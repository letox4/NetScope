# -*- coding: utf-8 -*-
"""MemoryWatcher — monitorización periódica por polling (genérica).

Uso:
    w = MemoryWatcher(engine, watch_addr, size, interval=1.0)
    w.on_change = lambda old, new: print('cambia:', old.hex(), '->', new.hex())
    w.start()
    ...
    w.stop()

No requiere watchpoints HW (limitación documentada): snapshots por polling.
Errores de lectura se reportan vía on_error (opcional) sin parar el watcher.
"""
import threading
import time

from .models import CapabilityError, MemoryError, SessionError

MAX_CONSECUTIVE_ERRORS = 20


class MemoryWatcher:
    def __init__(self, engine, addr: int, size: int, interval: float = 1.0,
                 max_errors: int = MAX_CONSECUTIVE_ERRORS):
        self.engine = engine
        self.addr = int(addr)
        self.size = int(size)
        self.interval = float(interval)
        self.max_errors = int(max_errors)
        self.on_change = None                    # cb(old_bytes, new_bytes)
        self.on_error = None                     # cb(reason: str)
        self.on_stopped = None                   # cb(reason: str) — parada automática
        self.stopped_reason = None               # None mientras corre
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._baseline: bytes | None = None
        self._stop_lock = threading.Lock()

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        if not self.engine.caps.watch:
            raise CapabilityError('watch')
        # baseline inicial (falla si no se puede leer → no arranca a ciegas)
        data, err = self.engine.read_range(self.addr, self.size)
        if err is not None:
            raise MemoryError('E_WATCH_BASELINE', err)
        self._baseline = data
        self._stop.clear()
        self.stopped_reason = None
        self.engine.add_invalidation_listener(self._on_invalidated)
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name='NetScope-MemoryWatcher')
        self._thread.start()

    def _auto_stop(self, reason: str):
        """Detiene el watcher desde dentro (sesión perdida / demasiados errores)
        y avisa una sola vez."""
        with self._stop_lock:
            if self.stopped_reason is not None:
                return
            self.stopped_reason = reason
        self._stop.set()
        cb = self.on_stopped
        if cb:
            try:
                cb(reason)
            except Exception:
                pass

    def _on_invalidated(self, err):
        self._auto_stop(err.detail or err.reason)

    def _loop(self):
        errors = 0
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break
            try:
                data, err = self.engine.read_range(self.addr, self.size)
            except SessionError as e:
                self._auto_stop(e.detail or e.reason)
                break
            except Exception as e:
                errors += 1
                if self.on_error:
                    self.on_error(str(e))
                if errors >= self.max_errors:
                    self._auto_stop('E_WATCH_ERRORS')
                    break
                continue
            if err is not None:
                errors += 1
                if self.on_error:
                    self.on_error(err)
                if errors >= self.max_errors:
                    self._auto_stop('E_WATCH_ERRORS')
                    break
                continue
            errors = 0
            if data != self._baseline:
                old, self._baseline = self._baseline, data
                if self.on_change:
                    try:
                        self.on_change(old, data)
                    except Exception:
                        pass

    def stop(self):
        self._stop.set()
        self.engine.remove_invalidation_listener(self._on_invalidated)
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout=max(2.0, self.interval * 2))
        self._thread = None

    @property
    def running(self) -> bool:
        t = self._thread
        return t is not None and t.is_alive() and not self._stop.is_set()
