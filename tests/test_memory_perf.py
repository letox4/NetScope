# -*- coding: utf-8 -*-
"""Etapa 4 — rendimiento de lecturas (Frida real, proceso de laboratorio).

Ejecutar:  py -3.11 tests\\test_memory_perf.py
Antes: 64 KB sobre memoria no mapeada tardaba 6,7-7,2 s (5 excepciones por byte).
Ahora el agente salta tramos ilegibles con VirtualQuery y respeta un plazo.
"""
import json
import os
import subprocess
import sys
import time

import frida

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.memory.backends.frida_memory import FridaMemoryBackend
from core.memory.engine import MemoryEngine

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, '..', 'agent', 'memory.js')
MB = 1 << 20
UNMAPPED_BUDGET_S = 1.0       # antes: ~7 s
THROUGHPUT_BUDGET_S = 5.0     # 4 MB mapeados


def timed(fn):
    t = time.time()
    r = fn()
    return r, time.time() - t


def main():
    lab = subprocess.Popen([sys.executable, os.path.join(HERE, 'lab_target.py')],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    A = json.loads(lab.stdout.readline())
    session = frida.attach(A['pid'])
    script = session.create_script(open(AGENT, encoding='utf-8').read())
    script.load()
    backend = FridaMemoryBackend(script, read_only=False)
    eng = MemoryEngine(backend)

    # ---- lecturas sobre memoria no mapeada ----
    (d, err), t = timed(lambda: eng.read_range(0x10000, MB))
    assert err == 'E_NO_MAP' and d == b'\x00' * len(d) and len(d) == eng.chunk, (err, len(d))
    assert t < UNMAPPED_BUDGET_S, f'1 MB sin mapear tardó {t:.2f}s'
    print(f'[OK] read_range 1 MB sin mapear: {t:.3f}s (antes ~7,15s), err={err}, '
          f'devuelve {len(d)} B con ceros')

    rd, t = timed(lambda: backend.read_detail(0x10000, MB))
    assert rd.valid == 0 and rd.error == 'E_NO_MAP' and len(rd.data) == MB
    assert rd.holes == [(0, MB, 'E_NO_MAP')], rd.holes[:2]
    assert t < UNMAPPED_BUDGET_S
    print(f'[OK] read_detail 1 MB sin mapear: {t:.3f}s, un único hueco (0, {MB}, E_NO_MAP)')

    lab.stdin.write('free\n')
    lab.stdin.flush()
    lab.stdout.readline()
    (d, err), t = timed(lambda: eng.read_range(A['freeme'], 64 * 1024))
    assert t < UNMAPPED_BUDGET_S and err is not None
    print(f'[OK] 64 KB recién liberados: {t:.3f}s, err={err}')

    # ---- la detección de lecturas parciales se mantiene ----
    regs = sorted(eng.regions('r'), key=lambda r: r.addr)
    gap = next(a for a, n in zip(regs, regs[1:]) if a.end < n.addr)
    rd, t = timed(lambda: eng.read_detail(gap.end - 16, 64))
    assert rd.valid == 16 and rd.holes == [(16, 48, rd.error)] and rd.error is not None, rd
    assert rd.data[16:] == b'\x00' * 48 and t < UNMAPPED_BUDGET_S
    print(f'[OK] lectura que cruza a un hueco: valid=16, hueco=(16,48,{rd.error}) en {t:.3f}s')

    # ---- plazo: el agente no se queda colgado ----
    big = backend.alloc(4 * MB)
    for off in range(0, 4 * MB, MB):
        eng.write(big.addr + off, bytes([(off // MB) + 1]) * MB, note='patrón')
    rd = backend.read_detail(big.addr, 2 * MB, deadline_ms=0)
    assert rd.error == 'E_TIMEOUT' and rd.valid == 0, (rd.error, rd.valid)
    print('[OK] plazo agotado (deadline 0): E_TIMEOUT explícito, sin bloquear')

    # ---- rendimiento sobre memoria mapeada + integridad de datos ----
    (d, err), t = timed(lambda: eng.read_range(big.addr, 4 * MB))
    assert err is None and len(d) == 4 * MB
    for i in range(4):
        assert d[i * MB:(i + 1) * MB] == bytes([i + 1]) * MB, f'bloque {i} corrupto'
    assert t < THROUGHPUT_BUDGET_S, f'4 MB mapeados tardaron {t:.2f}s'
    print(f'[OK] 4 MB mapeados leídos íntegros en {t:.2f}s ({4 / t:.1f} MB/s)')

    assert lab.poll() is None
    session.detach()
    lab.kill()
    print('ALL MEMORY PERF TESTS PASSED')


def test_memory_perf():
    main()


if __name__ == '__main__':
    main()
