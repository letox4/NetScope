# -*- coding: utf-8 -*-
"""Memoria sobre un proceso x86 (32 bits) real: SysWOW64\\ping.exe.

Ejecutar:  py -3 tests\\test_memory_x86.py
Se omite (exit 0) si el sistema no tiene SysWOW64.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import frida

from core.memory.backends.frida_memory import FridaMemoryBackend
from core.memory.engine import MemoryEngine
from core.memory.models import MemoryError

AGENT = os.path.join(os.path.dirname(__file__), '..', 'agent', 'memory.js')
TARGET = r'C:\Windows\SysWOW64\ping.exe'


def main():
    if not os.path.exists(TARGET):
        print('[SKIP] sin SysWOW64')
        return
    child = subprocess.Popen([TARGET, '-t', '127.0.0.1'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    session = None
    try:
        time.sleep(1.0)
        session = frida.attach(child.pid)
        with open(AGENT, encoding='utf-8') as f:
            script = session.create_script(f.read())
        script.load()
        backend = FridaMemoryBackend(script, read_only=False)
        eng = MemoryEngine(backend, audit_path=os.path.join(
            os.environ.get('TEMP', '.'), 'netscope_mem_audit_x86.jsonl'))

        assert backend.arch == 'ia32' and backend.pointer_size == 4, \
            (backend.arch, backend.pointer_size)
        regs = eng.regions('r')
        assert len(regs) >= 50 and all(r.addr + r.size <= 1 << 32 for r in regs)
        print(f'[OK] x86: arch=ia32 ptr=4, {len(regs)} regiones < 4 GiB')

        scratch = eng.alloc(32)
        # los 4 bytes siguientes al puntero son DISTINTOS de cero a propósito
        eng.write(scratch.addr, bytes.fromhex('78563412efbeadde') + b'cstr-ok\x00')
        assert eng.pointer_size == 4 and eng.scalar_size('ptr') == 4
        assert eng.read_value(scratch.addr, 'ptr') == 0x12345678, \
            hex(eng.read_value(scratch.addr, 'ptr'))
        assert eng.read_value(scratch.addr, 'u32') == 0x12345678
        assert eng.read_value(scratch.addr, 'u64') == 0xDEADBEEF12345678
        assert eng.read_value(scratch.addr, 'u16') == 0x5678
        assert eng.read_value(scratch.addr, 'u8') == 0x78
        assert eng.read_value(scratch.addr + 4, 'ptr') == 0xDEADBEEF
        assert eng.read_value(scratch.addr + 8, 'cstr') == b'cstr-ok'
        print('[OK] x86: ptr=4 bytes con vecino no nulo (0x12345678, no 0xdeadbeef12345678); '
              'u8/u16/u32/u64/cstr correctos')

        # escritura de un puntero desde el motor: 4 bytes exactos, sin pisar al vecino
        eng.write(scratch.addr, (0xCAFEBABE).to_bytes(eng.pointer_size, 'little'))
        assert eng.read_value(scratch.addr, 'ptr') == 0xCAFEBABE
        assert eng.read_value(scratch.addr + 4, 'ptr') == 0xDEADBEEF
        print('[OK] x86: escribir un ptr de 4 bytes no altera el vecino')

        # conversiones de dirección ia32
        for bad in (1 << 32, (1 << 32) - 2):
            try:
                eng.read_value(bad, 'u32')
                raise AssertionError('debió rechazar la dirección')
            except MemoryError as e:
                assert e.reason == 'E_BAD_ADDRESS'
        print('[OK] x86: direcciones fuera de 32 bits rechazadas (E_BAD_ADDRESS)')

        # VirtualQuery con la estructura MBI de 32 bits: coherente con la enumeración
        checked = 0
        for r in regs[:60]:
            q = script.exports_sync.query_region(hex(r.addr))
            assert q['ok'], q
            base, end = int(q['base'], 16), int(q['end'], 16)
            assert base <= r.addr < end <= 1 << 32, (hex(r.addr), q)
            assert (not r.w) or q['protect'] & 0xCC, (hex(r.addr), r.protections, q)
            checked += 1
        print(f'[OK] x86: VirtualQuery (MBI de 32 bits) coherente en {checked} regiones')

        # hueco real entre regiones: lectura parcial rápida y sin crash
        allr = sorted(regs, key=lambda r: r.addr)
        gap = next((a for a, n in zip(allr, allr[1:]) if a.end < n.addr), None)
        assert gap is not None
        t = time.time()
        rd = eng.read_detail(gap.end - 8, 32)
        elapsed = time.time() - t
        assert rd.valid == 8 and rd.error in ('E_NO_MAP', 'E_NO_ACCESS', 'E_NOT_COMMITTED'), rd
        assert rd.data[8:] == b'\x00' * 24 and elapsed < 1.0, elapsed
        print(f'[OK] x86: lectura parcial al cruzar un hueco ({rd.error}) en {elapsed:.3f}s')
        assert child.poll() is None
        print('ALL X86 MEMORY TESTS PASSED')
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        child.terminate()


def test_memory_x86():
    main()


if __name__ == '__main__':
    main()
