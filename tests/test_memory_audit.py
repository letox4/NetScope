# -*- coding: utf-8 -*-
"""Etapa 5 — auditoría JSONL en el flujo real (Frida real, procesos propios).

Ejecutar:  py -3.11 tests\\test_memory_audit.py
Demuestra: la auditoría se escribe sin configurar nada (NETSCOPE_AUDIT_DIR),
sobrevive a la caída del target y al cierre brusco del host, registra
operaciones, rechazos y errores, y no guarda bytes del proceso por defecto.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

import frida

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.interceptor import FridaInterceptor
from core.memory.audit import AuditLog
from core.memory.backends.frida_memory import FridaMemoryBackend
from core.memory.engine import MemoryEngine
from core.memory.models import MemoryError

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.abspath(os.path.join(HERE, '..'))
SECRET = b'SECRET-PASSWORD-123'


def start_lab():
    p = subprocess.Popen([sys.executable, os.path.join(HERE, 'lab_target.py')],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    return p, json.loads(p.stdout.readline())


def lab_cmd(p, c):
    p.stdin.write(c + '\n')
    p.stdin.flush()
    return p.stdout.readline().strip()


def load(path):
    with open(path, encoding='utf-8') as f:
        return [json.loads(l) for l in f if l.strip()]


def raises(reason, fn):
    try:
        fn()
    except MemoryError as e:
        assert e.reason == reason, (reason, e.reason)
        return
    raise AssertionError(f'esperaba {reason}')


HOST = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
from core.interceptor import FridaInterceptor
ic = FridaInterceptor(on_event=lambda e: None, on_status=lambda s: None, on_log=lambda l: None)
ic.attach(pid=int(sys.argv[2]))
eng = ic.memory_engine(read_only=False)
rec = eng.write(int(sys.argv[3], 16), b"HOSTWRITE", note="host")
print("DONE", rec.applied, flush=True)
sys.stdin.readline()
'''


def main():
    audit_dir = tempfile.mkdtemp(prefix='netscope_audit_')
    os.environ['NETSCOPE_AUDIT_DIR'] = audit_dir
    audit = os.path.join(audit_dir, 'memory_audit.jsonl')

    # ---- 1. flujo real: sin audit_path, la auditoría se crea sola ----
    lab, A = start_lab()
    logs = []
    ic = FridaInterceptor(on_event=lambda e: None, on_status=lambda s: None,
                          on_log=logs.append)
    ic.attach(pid=A['pid'])
    eng = ic.memory_engine(read_only=False)
    assert eng.audit is not None and eng.audit_path == os.path.abspath(audit), eng.audit_path
    assert os.path.exists(audit)
    print(f'[OK] flujo real: auditoría activa sin configurar -> {eng.audit_path}')

    addr = A['tail'] + 128
    rec = eng.write(addr, SECRET, note='credencial de laboratorio')
    assert rec.applied
    raises('E_NON_WRITABLE', lambda: eng.write(A['two'] + 4096, b'X', note='rechazo'))
    eng.rollback(rec)
    scratch = eng.alloc(32)
    eng.free(scratch.addr)

    ev = load(audit)
    kinds = [e['event'] for e in ev]
    for k in ('engine_start', 'write_intent', 'write', 'rollback_intent', 'rollback',
              'alloc', 'free'):
        assert k in kinds, (k, kinds)
    writes = [e for e in ev if e['event'] == 'write']
    ok_w = next(e for e in writes if e['applied'])
    bad_w = next(e for e in writes if e['reason'] == 'E_NON_WRITABLE')
    assert not bad_w['applied'] and bad_w['note'] == 'rechazo'
    print('[OK] registrados: engine_start, write(+intent), rechazo E_NON_WRITABLE, '
          'rollback(+intent), alloc, free')

    # sin datos sensibles: longitud + SHA-256, ni bytes ni hex del secreto
    raw = open(audit, encoding='utf-8').read()
    assert SECRET.decode() not in raw and SECRET.hex() not in raw
    assert ok_w['new_len'] == len(SECRET)
    assert ok_w['new_sha256'] == hashlib.sha256(SECRET).hexdigest()
    assert 'new_hex' not in ok_w and 'old_hex' not in ok_w
    assert ok_w['pid'] == A['pid'] and ok_w['session'] == eng.session_id
    print('[OK] sin datos del proceso: solo longitud + SHA-256 (el secreto no aparece en el fichero)')

    # ---- 2. sobrevive a la caída del target ----
    n_before = len(load(audit))
    lab_cmd(lab, 'exit')
    time.sleep(1.5)
    ev = load(audit)
    assert len(ev) > n_before and ev[-1]['event'] == 'session_lost', ev[-1]
    assert ev[-1]['detail'] == 'process-terminated', ev[-1]
    assert [e for e in ev[:n_before]] == load(audit)[:n_before]
    print('[OK] tras caer el target: los registros previos siguen y se añade session_lost(process-terminated)')
    ic.stop()

    # ---- 3. sobrevive al cierre BRUSCO del host (sin atexit ni flush manual) ----
    lab2, B = start_lab()
    host = subprocess.Popen([sys.executable, '-c', HOST, BASE, str(B['pid']), hex(B['tail'] + 200)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                            env=dict(os.environ))
    line = host.stdout.readline().strip()
    assert line == 'DONE True', line
    n_before = len(load(audit))
    host.kill()                      # TerminateProcess: sin cierre ordenado
    host.wait(timeout=5)
    ev = load(audit)
    mine = [e for e in ev if e.get('note') == 'host']
    assert [e['event'] for e in mine] == ['write_intent', 'write'], mine
    assert mine[1]['applied'] and mine[1]['pid'] == B['pid']
    print('[OK] cierre brusco del host: intent + resultado de la escritura ya estaban en disco (fsync)')

    # ---- 4. se acumula entre sesiones (append-only) ----
    ic2 = FridaInterceptor(on_event=lambda e: None, on_status=lambda s: None, on_log=lambda l: None)
    ic2.attach(pid=B['pid'])
    ic2.memory_engine()
    ev2 = load(audit)
    assert len(ev2) > len(ev) and ev2[:len(ev)] == ev
    ic2.stop()
    print('[OK] append-only: una sesión nueva añade sin tocar lo anterior')

    # ---- 5. sin rastro no se escribe ----
    session = frida.attach(B['pid'])
    script = session.create_script(open(os.path.join(BASE, 'agent', 'memory.js'),
                                        encoding='utf-8').read())
    script.load()
    backend = FridaMemoryBackend(script, read_only=False)
    log = AuditLog(os.path.join(audit_dir, 'b.jsonl'))
    e3 = MemoryEngine(backend, audit=log)
    target = B['tail'] + 300
    before = e3.read_range(target, 4)[0]

    def broken(*a, **k):
        raise OSError('disco lleno (simulado)')
    log.event = broken
    raises('E_AUDIT_FAILED', lambda: e3.write(target, b'ZZZZ'))
    assert e3.read_range(target, 4)[0] == before, 'se escribió sin poder auditar'
    print('[OK] si la auditoría falla, la escritura se rechaza (E_AUDIT_FAILED) y la memoria no cambia')

    # ---- 6. opt-in de bytes: prefijo acotado ----
    log2 = AuditLog(os.path.join(audit_dir, 'c.jsonl'), include_bytes=True)
    e4 = MemoryEngine(backend, audit=log2)
    e4.write(B['tail'] + 400, bytes(range(1, 65)), note='optin')
    w = next(e for e in load(log2.path) if e['event'] == 'write')
    assert w['new_hex'] == bytes(range(1, 33)).hex(), 'prefijo acotado a 32 bytes'
    print('[OK] include_bytes=True (opt-in): prefijo hex acotado a 32 bytes')

    session.detach()
    lab2.kill()
    print('ALL MEMORY AUDIT TESTS PASSED')


def test_memory_audit():
    main()


if __name__ == '__main__':
    main()
