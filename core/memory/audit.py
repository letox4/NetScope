# -*- coding: utf-8 -*-
"""Registro de auditoría JSONL del subsistema de memoria.

- Append-only, una línea JSON por evento, `flush` + `fsync` en cada línea: lo
  escrito sobrevive al cierre brusco de la aplicación o a la caída del target.
- Por defecto NO guarda bytes del proceso analizado: solo longitud y SHA-256.
  `include_bytes=True` añade un prefijo hexadecimal acotado (opt-in).
- Es independiente del motor y de la sesión Frida: sigue siendo escribible
  tras un detach, de modo que los eventos de desconexión también quedan.
"""
import hashlib
import json
import os
import threading
import time

PREFIX_BYTES = 32


def default_audit_path() -> str:
    """NETSCOPE_AUDIT_DIR, o %LOCALAPPDATA%\\NetScope\\audit, o ./logs."""
    base = os.environ.get('NETSCOPE_AUDIT_DIR')
    if not base:
        local = os.environ.get('LOCALAPPDATA')
        base = (os.path.join(local, 'NetScope', 'audit') if local
                else os.path.join(os.getcwd(), 'logs'))
    return os.path.join(base, 'memory_audit.jsonl')


def digest(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


class AuditLog:
    def __init__(self, path: str, include_bytes: bool = False):
        self.path = os.path.abspath(path)
        self.include_bytes = include_bytes
        self.context = {}
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        open(self.path, 'a', encoding='utf-8').close()

    def set_context(self, **fields) -> None:
        self.context.update(fields)

    def blob_fields(self, prefix: str, data: bytes) -> dict:
        """Campos para un bloque de datos: longitud + hash (+ prefijo opt-in)."""
        out = {f'{prefix}_len': len(data), f'{prefix}_sha256': digest(data)}
        if self.include_bytes:
            out[f'{prefix}_hex'] = bytes(data[:PREFIX_BYTES]).hex()
        return out

    def event(self, event: str, **fields) -> None:
        """Escribe un evento durable. Lanza OSError si no puede persistirlo."""
        entry = {'ts': time.time(),
                 'iso': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
                 'event': event}
        entry.update(self.context)
        entry.update(fields)
        line = json.dumps(entry, default=str) + '\n'
        with self._lock:
            with open(self.path, 'a', encoding='utf-8') as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
