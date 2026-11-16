# -*- coding: utf-8 -*-
"""Carga la sonda agent/antidebug_probe.js en una sesión Frida EXISTENTE.

  scan_imports()  PASIVO: imports de APIs anti-debug en módulos que no son de Windows.
  observe()       ACTIVO (opt-in): registra llamadas a IsDebuggerPresent /
                  CheckRemoteDebuggerPresent / NtQueryInformationProcess sin
                  alterar resultados. Parchea el prólogo de esas funciones.
"""
import os
from typing import Dict, List

PROBE_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'agent', 'antidebug_probe.js')


class ProbeSession:
    def __init__(self, session):
        self._session = session
        with open(PROBE_PATH, encoding='utf-8') as f:
            self._script = session.create_script(f.read())
        self._script.load()
        self._observing = False

    def scan_imports(self) -> List[dict]:
        r = self._script.exports_sync.scan_imports()
        if not r.get('ok'):
            raise RuntimeError(r.get('error', 'scan_imports falló'))
        return r['imports']

    def observe(self) -> List[str]:
        r = self._script.exports_sync.observe()
        self._observing = True
        return r.get('hooked', [])

    def collect(self) -> Dict[str, dict]:
        return self._script.exports_sync.collect()['calls']

    def close(self) -> None:
        try:
            if self._observing:
                self._script.exports_sync.stop()
            self._script.unload()
        except Exception:
            pass
