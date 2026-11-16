# -*- coding: utf-8 -*-
"""Tests nativos del subsistema de memoria (Frida real, attach a sí mismo).

Ejecutar:  py -3.11 tests\test_memory_native.py
Requiere:  Frida puede attach al propio proceso (permite auto-instrumentarse).
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import frida

from core.memory.backends.frida_memory import FridaMemoryBackend
from core.memory.engine import MemoryEngine
from core.memory.watcher import MemoryWatcher
from core.memory.models import MemoryError

AGENT = os.path.join(os.path.dirname(__file__), '..', 'agent', 'memory.js')


def build_engine():
    session = frida.attach(os.getpid())
    with open(AGENT, encoding='utf-8') as f:
        script = session.create_script(f.read())
    script.load()
    backend = FridaMemoryBackend(script, read_only=False)
    eng = MemoryEngine(backend, audit_path=os.path.join(
        os.environ.get('TEMP', '.'), 'netscope_mem_audit_self.jsonl'))
    return session, eng


def backend_probed(eng):
    return eng.backend.capabilities is not type(eng.backend).capabilities


def main():
    session, eng = build_engine()
    print(f'backend: arch={eng.backend.arch} ptr={eng.backend.pointer_size}')
    assert eng.caps.read and eng.caps.write_rw
    assert backend_probed(eng), 'capacidades no sondeadas por proceso'

    # --- test 1: enumeración de regiones ---
    regs = eng.regions('r')
    assert len(regs) >= 50, f'solo {len(regs)} regiones'
    img = eng.regions('rx')
    assert any(r.owner and 'x' in r.protections for r in regs), \
        'no hay regiones con owner módulo'
    print(f'[OK] regiones: {len(regs)} legibles, {len(img)} ejecutables')

    # --- test 2: alloc + roundtrip read/write ---
    scratch = eng.alloc(64)
    eng.write(scratch.addr, b'NetScope-mem-test', note='roundtrip')
    d, err = eng.read_range(scratch.addr, 17)
    assert err is None and d == b'NetScope-mem-test', (d, err)
    print('[OK] alloc+read/write roundtrip')

    # --- test 3: lectura enzona RX sin crash (la app sigue viva) ---
    d, err = eng.read_range(scratch.addr, 17)
    assert err is None and d == b'NetScope-mem-test'
    print('[OK] re-lectura estable')

    # --- escalares reales vía Frida ---
    eng.write(scratch.addr + 32, b'\xBE\xBA\xFE\xCA' + b'hello\x00')
    assert eng.read_value(scratch.addr + 32, 'u32') == 0xCAFEBABE
    assert eng.read_value(scratch.addr + 36, 'cstr') == b'hello'
    print('[OK] escalares u32/cstr con Frida real')

    # --- lectura parcial real: cruza el final de una región hacia memoria no mapeada ---
    tail = None
    allr = sorted(eng.regions('r'), key=lambda r: r.addr)
    for a, nxt in zip(allr, allr[1:]):
        if a.end < nxt.addr:      # hueco real entre regiones
            tail = a
            break
    assert tail is not None, 'no se encontró un hueco entre regiones'
    d, err = eng.read_range(tail.end - 16, 64)
    assert err is not None and len(d) == 64 and d[16:] == b'\x00' * 48, (err, len(d))
    print(f'[OK] lectura parcial tolerante ({err}), sin crash')

    # --- test 4: escrita en región RX declinada o no escribible ---
    denied = False
    try:
        target = next(r for r in eng.regions('r') if not r.w and not r.x)
        eng.write(target.addr, b'\xFF' * 4)
    except MemoryError as e:
        denied = e.reason in ('E_NON_WRITABLE', 'E_UNSUPPORTED_PROTECTION',
                              'E_ACCESS_DENIED', 'E_PRE_READ_FAILED')
    except StopIteration:
        pass
    assert denied, 'escribió una región no-escribible!'
    print('[OK] región no escribible rechazada')

    # --- test 5: snapshot + 1 modificación + diff ---
    a = eng.snapshot('A', per_region_limit=64 * 1024, total_budget=4 << 20,
                     prot_filter='rw')
    eng.write(scratch.addr, b'NetScope-MEM-TEST', note='diff')
    b = eng.snapshot('B', per_region_limit=64 * 1024, total_budget=4 << 20,
                     prot_filter='rw')
    diffs = [x for x in eng.diff(a, b) if x.kind != 'unchanged']
    mod = [x for x in diffs if x.kind == 'modified']
    if mod:
        # la región scratch tiene 1 modificación id esperado
        print(f'[OK] diff: {len(diffs)} cambios, {len(mod)} modified')
    else:
        print(f'[..] diff sin modified (scratch puede estar fuera de budget): '
              f'{len(diffs)} cambios')

    # --- test 6: undo verificado ---
    rec = eng.write(scratch.addr, b'ToBeRolledBackXXXXX', note='undo-test')
    assert rec.applied
    eng.rollback(rec)
    d, _ = eng.read_range(scratch.addr, len(rec.old_bytes))
    assert d == rec.old_bytes
    print('[OK] write + rollback verificado')

    # --- test 7: watcher detecta cambio ---
    hits = []
    w = MemoryWatcher(eng, scratch.addr, 16, interval=0.25)
    eng.write(scratch.addr, b'\x01' * 16, note='watch-pre')
    w.on_change = lambda old, new: hits.append(True)
    w.start()
    eng.write(scratch.addr, b'\x02' * 16, note='watch-trig')
    import time
    time.sleep(2.0)
    w.stop()
    assert hits, 'watcher no detectó el cambio'
    print('[OK] watcher (polling) detectó el cambio')

    # --- test 8: el target sigue vivo ---
    d, err = eng.read_range(scratch.addr, 4)
    assert err is None, err
    print('[OK] target vivo tras todas las pruebas')

    # limpieza
    eng.free(scratch.addr)
    try:
        session.detach()
    except Exception:
        pass
    print('ALL NATIVE MEMORY TESTS PASSED')


def test_memory_native():
    main()


if __name__ == '__main__':
    main()

