# -*- coding: utf-8 -*-
"""Etapa 1 — ciclo de vida de sesiones (Frida real, procesos de laboratorio).

Ejecutar:  py -3.11 tests\\test_memory_lifecycle.py
Demuestra: detached escuchado, caché de MemoryEngine invalidada, watcher
detenido solo, errores de sesión de dominio (SessionError, nunca excepciones
crudas de Frida), estado de sesión visible y sin advertencias en stop().
"""
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.interceptor import FridaInterceptor
from core.memory.models import MemoryError, SessionError
from core.memory.watcher import MemoryWatcher

HERE = os.path.dirname(os.path.abspath(__file__))


def start_lab():
    p = subprocess.Popen([sys.executable, os.path.join(HERE, 'lab_target.py')],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    return p, json.loads(p.stdout.readline())


def wait(cond, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def expect_session_error(label, fn):
    try:
        fn()
    except SessionError as e:
        assert e.reason in ('E_SESSION_LOST', 'E_SESSION_STOPPED', 'E_NO_SESSION'), e.reason
        return e
    except Exception as e:      # una excepción cruda de Frida o de otro tipo
        raise AssertionError(f'{label}: excepción no normalizada '
                             f'{type(e).__module__}.{type(e).__name__}: {e}')
    raise AssertionError(f'{label}: no lanzó SessionError')


def main():
    audit = os.path.join(tempfile.mkdtemp(), 'audit.jsonl')
    statuses, logs, detached = [], [], []
    ic = FridaInterceptor(on_event=lambda ev: None, on_status=statuses.append,
                          on_log=logs.append, audit_path=audit)
    ic.on_detached = lambda reason, crash: detached.append(reason)

    # ---- A. el proceso objetivo muere con motor y watcher activos ----
    lab, A = start_lab()
    ic.attach(pid=A['pid'])
    assert ic.session_state == 'active'
    eng = ic.memory_engine(read_only=False)
    assert ic.memory_engine(read_only=False) is eng, 'el motor debe cachearse mientras la sesión vive'
    snap_old = eng.snapshot('antes', per_region_limit=4096, total_budget=1 << 20,
                            prot_filter='rw')
    rec = eng.write(A['tail'] + 64, b'\x01\x02\x03\x04', note='lifecycle')
    assert rec.applied
    stopped = []
    w = MemoryWatcher(eng, A['tail'], 8, interval=0.2)
    w.on_stopped = stopped.append
    w.start()
    assert w.running

    lab.stdin.write('exit\n')
    lab.stdin.flush()
    t0 = time.time()
    assert wait(lambda: any(s.startswith('Sesión perdida') for s in statuses)), \
        f'no se actualizó el estado: {statuses[-3:]}'
    print(f'[OK] estado de sesión actualizado en {time.time() - t0:.2f}s: {statuses[-1]!r}')
    assert detached and detached[0] == 'process-terminated', detached
    assert ic.session_state == 'lost' and ic.detach_reason == 'process-terminated'
    print('[OK] detached escuchado: reason=process-terminated, session_state=lost')

    assert not eng.valid, 'la caché del motor debe quedar invalidada'
    assert wait(lambda: stopped, 3.0) and stopped[0], stopped
    assert wait(lambda: eng._invalid.detail == 'process-terminated', 3.0), eng._invalid.detail
    assert wait(lambda: not w.running, 2.0)
    print(f'[OK] MemoryWatcher detenido automáticamente ({stopped[0]!r}) en '
          f'{time.time() - t0:.2f}s; motivo del motor: {eng._invalid.detail}')

    for label, fn in (
            ('read_range', lambda: eng.read_range(A['tail'], 8)),
            ('read_value', lambda: eng.read_value(A['tail'], 'u32')),
            ('regions', lambda: eng.regions()),
            ('snapshot', lambda: eng.snapshot('x')),
            ('write', lambda: eng.write(A['tail'] + 64, b'Z')),
            ('alloc', lambda: eng.alloc(8)),
            ('rollback', lambda: eng.rollback(rec))):
        expect_session_error(label, fn)
    print('[OK] 7 operaciones tras la muerte -> SessionError de dominio (ninguna excepción cruda de Frida)')
    e2 = expect_session_error('memory_engine()', ic.memory_engine)
    assert e2.detail == 'process-terminated'
    print('[OK] memory_engine() no devuelve un motor muerto: SessionError(process-terminated)')

    n_warn = len(logs)
    ic.stop()
    assert statuses[-1] == 'Detenido', statuses[-1]
    assert not [l for l in logs[n_warn:] if 'No se pudo descargar' in l], logs[n_warn:]
    assert ic.session_state == 'none'
    print('[OK] stop() tras pérdida de sesión: "Detenido" sin advertencias')

    # ---- B. re-attach a otro proceso: nada del anterior es utilizable ----
    lab2, B = start_lab()
    ic.attach(pid=B['pid'])
    eng2 = ic.memory_engine(read_only=False)
    assert eng2 is not eng and eng2.valid
    assert eng2.read_value(B['tail'] + 8, 'cstr') == b'cstr-ok'
    try:
        eng2.rollback(rec)
        raise AssertionError('rollback de un registro de otro proceso debió rechazarse')
    except MemoryError as e:
        assert e.reason == 'E_STALE_RECORD', e.reason
    snap_new = eng2.snapshot('despues', per_region_limit=4096, total_budget=1 << 20,
                             prot_filter='rw')
    try:
        eng2.diff(snap_old, snap_new)
        raise AssertionError('diff entre procesos distintos debió rechazarse')
    except MemoryError as e:
        assert e.reason == 'E_STALE_SNAPSHOT', e.reason
    print('[OK] re-attach: motor nuevo; rollback y diff de la sesión anterior rechazados '
          '(E_STALE_RECORD / E_STALE_SNAPSHOT)')

    # ---- C. parada pedida por nosotros: no es "pérdida de sesión" ----
    w2 = MemoryWatcher(eng2, B['tail'], 8, interval=0.2)
    stopped2 = []
    w2.on_stopped = stopped2.append
    w2.start()
    before = len(statuses)
    ic.stop()
    assert wait(lambda: stopped2, 3.0), 'stop() debe detener el watcher'
    assert not any(s.startswith('Sesión perdida') for s in statuses[before:]), statuses[before:]
    assert not eng2.valid
    expect_session_error('read tras stop', lambda: eng2.read_range(B['tail'], 4))
    print(f'[OK] stop() pedido: watcher detenido ({stopped2[0]}), sin falso "Sesión perdida"')
    lab2.kill()

    # ---- D. auditoría de eventos de sesión ----
    events = [json.loads(l) for l in open(audit, encoding='utf-8') if l.strip()]
    kinds = [e['event'] for e in events]
    assert kinds.count('engine_start') == 2 and kinds.count('session_lost') == 2, kinds
    print('[OK] auditoría registra engine_start x2 y session_lost x2')
    print('ALL LIFECYCLE TESTS PASSED')


def test_memory_lifecycle():
    main()


if __name__ == '__main__':
    main()
