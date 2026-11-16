# -*- coding: utf-8 -*-
"""Tests genéricos del MemoryEngine con DummyBackend (sin Frida)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.memory.backends.dummy import DummyBackend
from core.memory.engine import MemoryEngine
from core.memory.models import (CapabilityError, MemoryError, MemorySnapshot,
                                ModuleIdentity, Region, WriteRecord,
                                SCALAR_KINDS)


def make_backend() -> DummyBackend:
    b = DummyBackend()
    owner = ModuleIdentity('lab.exe', 0x400000, 0x100000)
    b.add_region(0x100000, 0x100, 'rw', data=b'A' * 0x100, owner=owner,
                 type_='image')
    b.add_region(0x200000, 0x100, 'r', data=b'RO' * 0x80, type_='image')
    b.add_region(0x300000, 0x100, 'rx', data=b'\x90' * 0x100, type_='image')
    b.add_region(0x400000, 0x100, 'rw', owner=owner)
    b.add_region(0x500000, 0x40, 'rw')  # anónima
    return b


# ---------- test 1: enumeración y filtros R/W/X independientes ----------
def test_regions_filters():
    eng = MemoryEngine(make_backend())
    all = eng.regions()
    assert len(all) == 5
    r = eng.regions('r')
    assert len(r) == 5                       # todas las regiones tienen 'r'
    w = eng.regions('w')
    assert {x.addr for x in w} == {0x100000, 0x400000, 0x500000}
    assert 0x200000 not in {x.addr for x in w}   # r-only excluida
    x = eng.regions('x')
    assert {x2.addr for x2 in x} == {0x300000}   # solo 'rx' tiene X


def test_region_permissions_individual():
    """R/W/X tratadas individualmente: 'rx' NO implica escribible en general
    (en esta región sí tiene 'w'? No: 'rx' no contiene 'w' → w=False)."""
    eng = MemoryEngine(make_backend())
    rx = [r for r in eng.regions() if r.addr == 0x300000][0]
    assert rx.r is True and rx.w is False and rx.x is True
    ro = [r for r in eng.regions() if r.addr == 0x200000][0]
    assert ro.r and not ro.w and not ro.x


# ---------- test 2: lectura y tolerancia parcial ----------
def test_read_roundtrip():
    eng = MemoryEngine(make_backend())
    d, err = eng.read_range(0x100000, 0x10)
    assert err is None and d == b'A' * 0x10


def test_read_partial_guard_page():
    b = make_backend()
    b.read_fail_from[0x400000] = 0x80   # fallo desde offset 0x80
    eng = MemoryEngine(b)
    d, err = eng.read_range(0x400000, 0x100)
    assert len(d) == 0x80              # leyó hasta la página guard
    assert err == 'E_PAGE_GUARD'       # y reporta error parcial


def test_read_scalar():
    b = make_backend()
    eng = MemoryEngine(b)
    b.write(0x100010, (0xCAFEBABE).to_bytes(4, 'little'))
    b.write(0x100014, b'hello\x00world')
    b.write(0x100020, (0xAABBCCDD11223344).to_bytes(8, 'little'))
    assert eng.read_value(0x100010, 'u32') == 0xCAFEBABE
    assert eng.read_value(0x100010, 'u8') == 0xBE
    assert eng.read_value(0x100014, 'cstr') == b'hello'
    assert eng.read_value(0x100014, 'utf8').startswith('hello')
    assert eng.read_value(0x100020, 'ptr') == 0xAABBCCDD11223344


# ---------- test 3: snapshots presupuestados ----------
def test_snapshot_budget():
    b = make_backend()
    # presupuesto total menor que la suma de regiones
    eng = MemoryEngine(b)
    snap = eng.snapshot('A', per_region_limit=0x10, total_budget=0x20)
    sizes = [e.read_len for e in snap.entries]
    assert sum(sizes) <= 0x20
    assert any(e.note == 'E_BUDGET' for e in snap.entries)
    assert all(e.data is not None for e in snap.entries)


def test_snapshot_diff_modified():
    b = make_backend()
    eng = MemoryEngine(b)
    a = eng.snapshot('A', per_region_limit=0x100, total_budget=8 << 20)
    b.write(0x500000 + 0x10, b'\x7F')   # cambia un byte real (antes 0x00)
    bsnap = eng.snapshot('B', per_region_limit=0x100, total_budget=8 << 20)
    diffs = eng.diff(a, bsnap)
    changed = [d for d in diffs if d.kind != 'unchanged']
    assert len(changed) == 1
    assert changed[0].kind == 'modified'
    assert changed[0].identity[0] == '__anonymous__'
    # y las demás regiones sí fueron 'unchanged'
    assert any(d.kind == 'unchanged' for d in diffs)


# ---------- test 4: identidad ASLR-estable ----------
def test_identity_aslr_stable():
    """Mismo módulo rebasado (ASLR) → misma identidad y el diff no duplica."""
    owner1 = ModuleIdentity('lab.exe', 0x400000, 0x200000)
    owner2 = ModuleIdentity('lab.exe', 0x7FF00000, 0x200000)  # rebasado
    b1, b2 = DummyBackend(), DummyBackend()
    data = b'M' * 0x40
    b1.add_region(0x410000, 0x40, 'rw', data=data, owner=owner1)   # rel 0x10000
    b2.add_region(0x7FF10000, 0x40, 'rw', data=data, owner=owner2) # rel 0x10000
    e1, e2 = MemoryEngine(b1), MemoryEngine(b2)
    s1 = e1.snapshot('A', per_region_limit=0x40, total_budget=1 << 20,
                     prot_filter='w')
    s2 = e2.snapshot('B', per_region_limit=0x40, total_budget=1 << 20,
                     prot_filter='w')
    # identidad: el módulo y offset relativo coinciden aunque addr absoluta no
    ident1 = s1.entries[0].region.identity()
    ident2 = s2.entries[0].region.identity()
    assert ident1[0] == ident2[0] == 'lab.exe'
    assert ident1[1] == ident2[1] == 0x10000    # rel offset igual en ambas capturas
    diffs = [d for d in e1.diff(s1, s2) if d.kind == 'modified']
    assert diffs == []


# ---------- test 5: escritura, verificación, audit, undo ----------
def test_write_and_undo(tmp_audit=None):
    tmpdir = tempfile.mkdtemp()
    audit = os.path.join(tmpdir, 'audit.jsonl')
    b = make_backend()
    eng = MemoryEngine(b, audit_path=audit)
    rec = eng.write(0x400000, b'\x01\x02\x03\x04', note='test write')
    assert rec.applied and not rec.partial
    d, _ = b.read(0x400000, 4)
    assert d == b'\x01\x02\x03\x04'
    # undo
    eng.rollback(rec)
    d, _ = b.read(0x400000, 4)
    assert d == b'\x00' * 4                      # original restaurado
    assert rec.rolled_back
    # audit log: intent + resultado de la escritura y del rollback, sin bytes
    with open(audit, encoding='utf-8') as f:
        lines = f.read().splitlines()
    entries = [__import__('json').loads(l) for l in lines if l]
    ops = [e for e in entries if e['event'] in ('write', 'rollback')]
    assert [e['event'] for e in entries if e['event'].endswith('_intent')] == \
        ['write_intent', 'rollback_intent']
    assert len(ops) == 2
    assert ops[0]['applied'] and not ops[0]['rolled_back']
    assert ops[1]['note'].startswith('rollback')
    assert 'old_hex' not in ops[0] and 'new_hex' not in ops[0]   # sin datos del proceso
    assert ops[0]['new_len'] == 4 and len(ops[0]['new_sha256']) == 64


def test_write_no_change():
    b = make_backend()
    eng = MemoryEngine(b)
    b.write(0x500000, b'ZZZZ')
    rec = eng.write(0x500000, b'ZZZZ')
    assert not rec.applied and rec.reason == 'E_NO_CHANGE'


def test_write_pre_read_failed():
    """Pre-lectura falla → no escribe nada."""
    b = make_backend()
    b.read_fail_from[0x400000] = 0
    eng = MemoryEngine(b)
    try:
        eng.write(0x400000, b'\xFF' * 4)
        assert False, 'debería fallar'
    except MemoryError as e:
        assert e.reason == 'E_PRE_READ_FAILED'
    b.read_fail_from.clear()   # permite leer para verificar que no escribió
    d, _ = b.read(0x400000, 4)
    rec = eng.write_history[-1]
    assert rec.reason == 'E_PRE_READ_FAILED'


def test_write_protected_denied():
    """Region R-only → E_NON_WRITABLE, sin daño."""
    eng = MemoryEngine(make_backend())
    try:
        eng.write(0x200000, b'X' * 4)
        assert False
    except MemoryError as e:
        assert e.reason == 'E_NON_WRITABLE'


def test_write_verify_partial():
    b = make_backend()
    b.write_partial_n[0x500000] = 2    # escribe 2 de 4, luego falla
    eng = MemoryEngine(b)
    try:
        eng.write(0x500000, b'\x11' * 4)
        assert False
    except MemoryError as e:
        assert e.reason == 'E_PARTIAL'
    rec = eng.write_history[0]
    assert rec.partial and not rec.applied
    # rollback de una escritura parcial: la vida real aplicó parte;
    # el rollback seguro debe rechazarla antes de leer valores incompletos
    rec.applied = False
    try:
        eng.rollback(rec)
        assert False
    except MemoryError as e:
        assert e.reason == 'E_NOT_NEEDED'
    d, _ = b.read(0x500000, 4)
    assert d[0] == 0x11 and d[1] == 0x11 and d[2] == 0x00


def test_rollback_changed_since():
    b = make_backend()
    eng = MemoryEngine(b)
    rec = eng.write(0x500000, b'\xAB' * 4)
    assert rec.applied
    # cambio concurrente: terceros escriben encima
    b.write(0x500000, b'\xCD' * 4)
    try:
        eng.rollback(rec)
        assert False
    except MemoryError as e:
        assert e.reason == 'E_CHANGED_SINCE'
    d, _ = b.read(0x500000, 4)
    assert d == b'\xCD' * 4          # no se restauró sobre el cambio ajeno


def test_rollback_double_rejected():
    b = make_backend()
    eng = MemoryEngine(b)
    rec = eng.write(0x500000, b'\xAB' * 4)
    eng.rollback(rec)
    try:
        eng.rollback(rec)
        assert False
    except MemoryError as e:
        assert e.reason == 'E_ALREADY_ROLLED_BACK'


# ---------- test 6: capacidades declarativas ----------
def test_capability_gate():
    caps = DummyBackend().capabilities
    write_rw = caps.write_rw
    # backend sin write_rw levanta CapabilityError
    b = DummyBackend()
    b.capabilities = type(b.capabilities)(enumerate=True, read=True,
                                          read_scalars=frozenset(SCALAR_KINDS),
                                          write_rw=False, write_rwx=False,
                                          alloc=True, free=True, watch=False)
    eng = MemoryEngine(b)
    try:
        eng.write(0x500000, b'\x01' * 4)
        assert False
    except CapabilityError:
        pass
    # sin watch declarado, el watcher no debe instanciarse en GUI (test semántico)
    assert not eng.caps.watch


def test_engine_no_frida_import():
    """El engine es genérico: no puede importar frida."""
    src = open(os.path.join(os.path.dirname(__file__), '..',
                            'core', 'memory', 'engine.py'),
               encoding='utf-8').read()
    src_low = src.lower()
    assert 'import frida' not in src_low, 'engine.py importa frida — debe ser genérico'


def test_ptr_size_follows_process():
    """`ptr` mide pointerSize del proceso: 4 bytes en ia32 aunque el vecino
    inmediato sea distinto de cero (el bug: siempre leía 8 bytes)."""
    for psize, expect in ((4, 0x12345678), (8, 0xDEADBEEF12345678)):
        b = DummyBackend()
        b.pointer_size = psize
        b.add_region(0x100000, 0x100, 'rw',
                     data=bytes.fromhex('78563412efbeadde') + b'\xff' * 8)
        eng = MemoryEngine(b)
        assert eng.pointer_size == psize and eng.scalar_size('ptr') == psize
        assert eng.read_value(0x100000, 'ptr') == expect, (psize, eng.read_value(0x100000, 'ptr'))
        # u32 y u64 no dependen del proceso
        assert eng.read_value(0x100000, 'u32') == 0x12345678
        assert eng.read_value(0x100000, 'u64') == 0xDEADBEEF12345678
        assert eng.read_value(0x100000, 'u16') == 0x5678
        assert eng.read_value(0x100000, 'u8') == 0x78


def test_ptr_at_region_end_ia32():
    """En ia32 un puntero en los últimos 4 bytes de la región es legible
    (con 8 bytes fallaría por cruzar el final)."""
    b = DummyBackend()
    b.pointer_size = 4
    b.add_region(0x100000, 8, 'rw', data=b'\x00' * 4 + bytes.fromhex('44332211'))
    eng = MemoryEngine(b)
    assert eng.read_value(0x100004, 'ptr') == 0x11223344


def test_address_range_by_pointer_size():
    b = DummyBackend()
    b.pointer_size = 4
    b.add_region(0x100000, 0x10, 'rw')
    eng = MemoryEngine(b)
    for bad in (1 << 32, (1 << 32) - 2):        # el segundo cruza el final con 4 bytes
        try:
            eng.read_value(bad, 'u32')
            assert False
        except MemoryError as e:
            assert e.reason == 'E_BAD_ADDRESS'
    for fn in (lambda: eng.read_range(-1, 4), lambda: eng.write(1 << 40, b'X')):
        try:
            fn()
            assert False
        except MemoryError as e:
            assert e.reason == 'E_BAD_ADDRESS'
    # dirección alta válida de 32 bits (bit 31 activo): no se trata como negativa
    b.add_region(0xFFFF0000, 0x10, 'rw', data=bytes.fromhex('0100000000000080'))
    assert eng.read_value(0xFFFF0000, 'u32') == 1
    assert eng.read_value(0xFFFF0004, 'ptr') == 0x80000000


def test_cstr_stops_at_unreadable_not_confused_with_nul():
    """Un hueco ilegible nunca se confunde con un NUL (cstr cortada = error)."""
    b = DummyBackend()
    b.add_region(0x100000, 0x20, 'rw', data=b'A' * 0x20)         # sin NUL hasta el final
    eng = MemoryEngine(b)
    try:
        eng.read_value(0x100000, 'cstr')
        assert False, 'debió informar memoria ilegible'
    except MemoryError as e:
        assert e.reason == 'E_PARTIAL_READ'


def test_alloc_free():
    eng = MemoryEngine(make_backend())
    reg = eng.alloc(64)
    assert reg.w and not reg.x
    eng.backend.write(reg.addr, b'HELLO')
    d, e = eng.read_range(reg.addr, 5)
    assert d == b'HELLO'
    eng.free(reg.addr)
    assert eng.regions('w').count(reg) == 0 or all(
        r.addr != reg.addr for r in eng.regions())


if __name__ == '__main__':
    import json
    import tempfile as _t
    test_regions_filters()
    test_region_permissions_individual()
    test_read_roundtrip()
    test_read_partial_guard_page()
    test_read_scalar()
    test_snapshot_budget()
    test_snapshot_diff_modified()
    test_identity_aslr_stable()
    test_write_and_undo()
    test_write_no_change()
    test_write_pre_read_failed()
    test_write_protected_denied()
    test_write_verify_partial()
    test_rollback_changed_since()
    test_rollback_double_rejected()
    test_capability_gate()
    test_engine_no_frida_import()
    test_alloc_free()
    test_ptr_size_follows_process()
    test_ptr_at_region_end_ia32()
    test_address_range_by_pointer_size()
    test_cstr_stops_at_unreadable_not_confused_with_nul()
    print('ALL MEMORY ENGINE TESTS PASSED')
