# -*- coding: utf-8 -*-
"""CLI del diagnóstico de protecciones.

  py -3.11 -m core.antidebug --pid 1234 [--deep] [--footprint] [--observe SEGUNDOS] [--json out.json]

Hace un attach SOLO con el agente de memoria (sin hooks) para el escaneo de
huella e imports; `--observe` activa el observador de APIs anti-debug (parchea
esas funciones durante N segundos: efecto del observador).
"""
import argparse
import json
import sys
import time

from . import AntiDebugDiagnostics
from .errors import AttachBlockedError


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog='python -m core.antidebug')
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--deep', action='store_true', help='consulta mitigaciones/EAF con PowerShell (lento)')
    ap.add_argument('--footprint', action='store_true', help='compara prólogos con el disco (requiere attach)')
    ap.add_argument('--observe', type=float, default=0.0, help='observa APIs anti-debug N segundos (opt-in)')
    ap.add_argument('--json')
    a = ap.parse_args(argv)

    diag = AntiDebugDiagnostics()
    diag.begin(a.pid, str(a.pid), 'attach')
    pre = diag.preflight(a.pid, deep=a.deep)
    session = None
    if pre.blocking:
        print(f'Preflight: attach evitado ({pre.reason}).')
    elif pre.info.accessible and (a.footprint or a.observe):
        import frida
        from .probe import ProbeSession
        from core.memory.backends.frida_memory import FridaMemoryBackend
        from core.memory.engine import MemoryEngine
        try:
            session = frida.attach(a.pid)
            diag.mark('attached')
            with open('agent/memory.js', encoding='utf-8') as f:
                script = session.create_script(f.read())
            script.load()
            backend = FridaMemoryBackend(script)
            engine = MemoryEngine(backend)
            diag.mark('memory-agent-loaded')
            probe = ProbeSession(session)
            diag.scan_static_imports(probe.scan_imports)
            if a.footprint:
                diag.scan_footprint(lambda ad, n: engine.read_range(ad, n), backend._modules(),
                                    wow64=backend.pointer_size == 4, pid=a.pid)
            if a.observe:
                probe.observe()
                time.sleep(a.observe)
                diag.ingest_api_observations(probe.collect())
            probe.close()
        except Exception as exc:     # noqa: BLE001
            diag.on_attach_failure(exc, a.pid)
        finally:
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass
    elif not pre.info.accessible:
        pass
    rep = diag.report()
    print(rep.render_text())
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump(rep.to_dict(), f, indent=1, default=str)
    return 0


if __name__ == '__main__':
    sys.exit(main())
