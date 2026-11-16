# -*- coding: utf-8 -*-
"""Etapa 2 — seguridad de memoria (Frida real sobre un proceso de laboratorio).

Ejecutar:  py -3.11 tests\\test_memory_safety.py
Demuestra que las lecturas no alteran el proceso (PAGE_GUARD intacta), que las
escrituras validan TODO el rango y que las regiones obsoletas no se escriben.
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
from core.memory.models import CapabilityError, MemoryError

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, '..', 'agent', 'memory.js')
P = 4096
PAGE_GUARD_RW = 0x104       # PAGE_READWRITE | PAGE_GUARD


class Lab:
    def __init__(self):
        self.p = subprocess.Popen([sys.executable, os.path.join(HERE, 'lab_target.py')],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.A = json.loads(self.p.stdout.readline())

    def cmd(self, c):
        self.p.stdin.write(c + '\n')
        self.p.stdin.flush()
        return self.p.stdout.readline().strip()

    def query(self):
        return json.loads(self.cmd('query'))

    def close(self):
        self.p.kill()


def attach(pid, agent_src=None):
    session = frida.attach(pid)
    src = agent_src or open(AGENT, encoding='utf-8').read()
    script = session.create_script(src)
    script.load()
    return session, script


def raises(reason, fn):
    try:
        fn()
    except MemoryError as e:
        assert e.reason == reason, f'esperaba {reason}, obtuvo {e.reason}: {e}'
        return e
    raise AssertionError(f'esperaba MemoryError({reason}) y no lanzó')


def main():
    lab = Lab()
    A = lab.A
    session, script = attach(A['pid'])
    backend = FridaMemoryBackend(script, read_only=False)
    eng = MemoryEngine(backend)
    assert backend.safe_read and eng.caps.read

    # ---------------- PAGE_GUARD: leer no debe consumir la guarda ----------------
    q0 = lab.query()
    assert q0['guard'][0] == PAGE_GUARD_RW and q0['edge_guard'][0] == PAGE_GUARD_RW, q0
    d, err = eng.read_range(A['guard'], 16)
    assert err == 'E_PAGE_GUARD' and d == b'\x00' * 16, (err, d)
    assert lab.query()['guard'][0] == PAGE_GUARD_RW, 'la lectura consumió PAGE_GUARD'
    rd = eng.read_detail(A['guard'], 16)
    assert rd.valid == 0 and rd.holes == [(0, 16, 'E_PAGE_GUARD')], rd
    raises('E_PARTIAL_READ', lambda: eng.read_value(A['guard'], 'u32'))
    raises('E_PARTIAL_READ', lambda: eng.read_value(A['guard'], 'ptr'))
    assert lab.query()['guard'][0] == PAGE_GUARD_RW
    print('[OK] PAGE_GUARD: la lectura devuelve E_PAGE_GUARD y la protección queda '
          f'intacta ({hex(PAGE_GUARD_RW)})')

    # lectura que cruza de memoria normal hacia la página guard
    rd = eng.read_detail(A['edge'] + P - 8, 16)
    assert rd.data[:8] == b'EDGE-END' and rd.valid == 8, rd
    assert rd.holes == [(8, 8, 'E_PAGE_GUARD')] and rd.error == 'E_PAGE_GUARD'
    d, err = eng.read_range(A['edge'] + P - 8, 16)
    assert d[:8] == b'EDGE-END' and err == 'E_PAGE_GUARD' and len(d) == 16
    assert lab.query()['edge_guard'][0] == PAGE_GUARD_RW
    print('[OK] lectura parcial hacia una guard: 8 bytes válidos + hueco E_PAGE_GUARD, guarda intacta')

    snap = eng.snapshot('seg', per_region_limit=4096, total_budget=4 << 20, prot_filter='rw')
    assert snap.entries and lab.query()['guard'][0] == PAGE_GUARD_RW
    print(f'[OK] snapshot de {len(snap.entries)} regiones: ninguna guard consumida')

    # ---------------- escritura: validar el rango completo ----------------
    tail_before = lab.query()['two_tail']
    assert tail_before == '41414141'
    spy = []
    real_write = backend.write
    backend.write = lambda a, b: (spy.append((a, bytes(b))), real_write(a, b))[1]
    e = raises('E_NON_WRITABLE',
               lambda: eng.write(A['two'] + P - 4, b'ZZZZZZZZ', note='cruce RW|RO'))
    assert not spy, 'el motor llegó a llamar al backend con un rango parcialmente no escribible'
    assert lab.query()['two_tail'] == tail_before
    print('[OK] escritura que cruza RW->RO rechazada por el MOTOR antes de tocar el backend '
          '(E_NON_WRITABLE), memoria intacta')

    backend.write = real_write
    e = raises('E_NON_WRITABLE',
               lambda: backend.write(A['two'] + P - 4, b'ZZZZZZZZ'))      # sin motor
    assert lab.query()['two_tail'] == tail_before
    print('[OK] el AGENTE también valida el rango completo: escritura directa cruzada '
          'rechazada de forma atómica (0 bytes escritos)')

    e = raises('E_PAGE_GUARD', lambda: backend.write(A['guard'], b'X'))
    assert lab.query()['guard'][0] == PAGE_GUARD_RW
    raises('E_NO_MAP', lambda: eng.write(A['guard'], b'X'))
    print('[OK] escribir en una página guard: agente E_PAGE_GUARD / motor E_NO_MAP, guarda intacta')

    # ---------------- regiones obsoletas ----------------
    assert eng.write(A['flip'], b'NEW', note='ok').applied
    stale_region_ok = eng._check_write_range                       # validación del motor
    lab.cmd('ro')                                                  # el proceso cambia permisos
    eng._check_write_range = lambda a, n: None                     # simula validación OBSOLETA
    raises('E_NON_WRITABLE', lambda: eng.write(A['flip'], b'STALE'))
    eng._check_write_range = stale_region_ok
    assert lab.query()['flip_data'].startswith('NEW'), 'se escribió sobre una región obsoleta'
    print('[OK] región obsoleta (cambió a RO tras la validación): el agente la rechaza, datos intactos')

    raises('E_NON_WRITABLE', lambda: eng.write(A['flip'], b'NOPE'))
    lab.cmd('rw')
    rec = eng.write(A['flip'], b'ROLL', note='para rollback')
    lab.cmd('ro')
    raises('E_NON_WRITABLE', lambda: eng.rollback(rec))
    assert lab.query()['flip_data'].startswith('ROLL')
    lab.cmd('rw')
    eng.rollback(rec)
    assert lab.query()['flip_data'].startswith('NEW')
    print('[OK] rollback rechazado mientras la región es RO y completado al volver a RW')

    lab.cmd('free')
    raises('E_NO_MAP', lambda: eng.write(A['freeme'], b'X'))
    d, err = eng.read_range(A['freeme'], 64)
    assert err in ('E_NO_MAP', 'E_NOT_COMMITTED') and d == b'\x00' * 64, err
    print(f'[OK] región liberada: escritura E_NO_MAP, lectura {err} sin excepción')

    # ---------------- direcciones fuera del espacio de direcciones ----------------
    raises('E_BAD_ADDRESS', lambda: eng.read_range(1 << 64, 4))
    raises('E_BAD_ADDRESS', lambda: eng.write(-1, b'X'))
    raises('E_BAD_ADDRESS', lambda: eng.read_value((1 << 64) - 2, 'u32'))
    print('[OK] direcciones negativas o fuera de 64 bits rechazadas (E_BAD_ADDRESS)')

    # ---------------- sin VirtualQuery no se garantiza lectura segura: se rechaza ----------------
    src = open(AGENT, encoding='utf-8').read().replace("'VirtualQuery'", "'VirtualQueryNoExiste'")
    s2, sc2 = attach(A['pid'], src)
    b2 = FridaMemoryBackend(sc2, read_only=False)
    assert not b2.safe_read and not b2.capabilities.read
    rd2 = b2.read_detail(A['tail'], 8)
    assert rd2.error == 'E_UNSAFE_READ' and rd2.valid == 0, rd2
    e2 = MemoryEngine(b2)
    try:
        e2.read_range(A['tail'], 8)
        raise AssertionError('debió rechazar la lectura')
    except CapabilityError:
        pass
    s2.detach()
    print('[OK] sin VirtualQuery: lectura rechazada explícitamente (capacidad read=False, E_UNSAFE_READ)')

    assert lab.p.poll() is None
    session.detach()
    lab.close()
    print('ALL MEMORY SAFETY TESTS PASSED')


def test_memory_safety():
    main()


if __name__ == '__main__':
    main()
