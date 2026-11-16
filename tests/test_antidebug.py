# -*- coding: utf-8 -*-
"""Motor de diagnóstico anti-debug: reglas de veredicto (sin Frida) + integración
real con los ejecutables de laboratorio.

Ejecutar:  py -3.11 tests\\test_antidebug.py
Requiere:  tests\\protection_lab\\build.ps1 ejecutado (bin\\*.exe).
Comprueba, entre otras cosas, que un fallo de attach / un cuelgue / una sesión
perdida NO se declaran anti-debug y que CONFIRMED solo se usa con medición directa.
"""
import os
import subprocess
import sys
import tempfile
import time

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, 'tests', 'protection_lab'))

from core.antidebug import AntiDebugDiagnostics, Verdict, Kind, Finding, Evidence  # noqa: E402
from core.antidebug.errors import AttachBlockedError, AttachTimeoutError  # noqa: E402


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeFridaError(Exception):
    pass


PermissionDeniedError = type('PermissionDeniedError', (FakeFridaError,), {})
ProcessNotFoundError = type('ProcessNotFoundError', (FakeFridaError,), {})


# ---------------------------------------------------------------- A. reglas (sin Frida)
def test_rules():
    # A1. un fallo de attach NUNCA es anti-debug
    d = AntiDebugDiagnostics()
    d.begin(None, 'x.exe')
    f = d.on_attach_failure(PermissionDeniedError('unable to access process with pid 4'))
    assert f.verdict == Verdict.UNKNOWN and f.kind == Kind.FAILURE, f
    assert 'NO es evidencia de anti-debug' in f.summary
    assert all(m in f.can_continue_note for m in ('protegido', 'elevado'))
    f2 = d.on_attach_failure(ProcessNotFoundError('no existe'))
    assert f2.verdict == Verdict.UNKNOWN
    assert not [x for x in d.findings if x.verdict == Verdict.CONFIRMED]
    print('[OK] A1 fallo de attach (PermissionDenied / ProcessNotFound) -> UNKNOWN, nunca anti-debug')

    # A2. cuelgue: UNKNOWN sin evidencia; INDICATION si hay guardas medidas
    d = AntiDebugDiagnostics()
    d.begin(None, 'x.exe')
    t = d.on_attach_timeout(12)
    assert t.verdict == Verdict.UNKNOWN and 'no se declara anti-debug' in t.summary
    d2 = AntiDebugDiagnostics()
    d2.begin(None, 'x.exe')
    d2._add(Finding('export-table-guard', Kind.PROTECTION, Verdict.CONFIRMED, 'guardas EAT',
                    [Evidence('windows-api', 'ntdll: 20/20', 'VirtualQueryEx')]))
    t2 = d2.on_attach_timeout(12)
    assert t2.verdict == Verdict.INDICATION and t2.evidence and 'EAT' in t2.summary
    print('[OK] A2 attach colgado: UNKNOWN sin evidencia; INDICATION (no CONFIRMED) si hay guardas EAT medidas')

    # A3. sesión perdida: correlación temporal = INDICATION; sin correlación = UNKNOWN
    clk = Clock()
    d = AntiDebugDiagnostics(clk)
    d.begin(1234, 'x.exe')
    clk.t += 1
    d.mark('attached')
    clk.t += 1
    d.mark('memory-agent-loaded')
    clk.t += 0.5
    f = d.on_session_lost('process-terminated', exit_code=0xC0000409)
    assert f.verdict == Verdict.INDICATION and f.mechanism == 'termination-after-instrumentation', f
    assert any('0xC0000409' in e.detail and 'fast-fail' in e.detail for e in f.evidence), f.evidence
    assert 'NO prueba anti-debug' in f.summary and f.can_continue is False
    assert not [x for x in d.findings if x.verdict == Verdict.CONFIRMED]
    clk2 = Clock()
    d = AntiDebugDiagnostics(clk2)
    d.begin(1234, 'x.exe')
    d.mark('attached')
    clk2.t += 60
    f = d.on_session_lost('process-terminated', exit_code=0)
    assert f.verdict == Verdict.UNKNOWN and f.mechanism == 'session-lost'
    assert d.on_session_lost('application-requested') is None
    print('[OK] A3 sesión perdida: <=2 s tras un paso = INDICATION; sin correlación = UNKNOWN; '
          'detach pedido por nosotros = ignorado')

    # A4. memoria protegida
    d = AntiDebugDiagnostics()
    d.begin(1, 'x')
    f = d.on_memory_error('read', 'E_PAGE_GUARD', 0x1000)
    assert f.verdict == Verdict.CONFIRMED and f.can_continue is True and f.memory_ops_affected == ['read']
    assert any('no hay lectura sin efectos laterales' in l for l in f.limitations)
    print('[OK] A4 E_PAGE_GUARD -> guard-page CONFIRMED, operación afectada y análisis continuable')

    # A5. imports = INDICATION; observación de API = CONFIRMED (uso, no reacción)
    d = AntiDebugDiagnostics()
    d.begin(1, 'x')
    fs = d.scan_static_imports(lambda: [{'module': 'a.exe', 'api': 'IsDebuggerPresent', 'from': 'KERNEL32.dll'}])
    assert fs[0].verdict == Verdict.INDICATION and 'NO prueba' in fs[0].summary
    fs = d.ingest_api_observations({'IsDebuggerPresent': {'count': 5, 'results': {'sin depurador': 5},
                                                          'callers': {'a.exe': 5}}})
    assert fs[0].verdict == Verdict.CONFIRMED and 'sin depurador' in fs[0].summary
    assert any('observador activo' in l for l in fs[0].limitations)
    fs = d.ingest_api_observations({'NtQueryInformationProcess:ProcessDebugFlags': {
        'count': 2, 'results': {'valor=0': 2}, 'callers': {'a.exe': 2}}})
    assert 'indica depurador' in fs[0].summary
    txt = d.report().render_text()
    for w in ('INDICIO', 'CONFIRMADO', 'evidencia', 'efecto sobre la sesión', 'limitación', 'momento'):
        assert w in txt, w
    print('[OK] A5 imports=INDICIO, uso de API=CONFIRMADO, informe con evidencia/momento/efecto/limitaciones')

    # A6. escritura en código = huella confirmada y marcada como destructiva
    f = d.on_exec_write(0x401000, 4)
    assert f.kind == Kind.FOOTPRINT and f.verdict == Verdict.CONFIRMED
    assert any('destructiva' in l for l in f.limitations)
    print('[OK] A6 escritura en memoria ejecutable -> huella CONFIRMED con aviso de operación destructiva')


# ---------------------------------------------------------------- B/C. real
def main():
    test_rules()

    import labrun
    from core.antidebug import preflight as pf
    from core.interceptor import FridaInterceptor
    from core.memory.backends.frida_memory import FridaMemoryBackend
    from core.memory.engine import MemoryEngine
    import frida

    # B1. preflight real
    d = AntiDebugDiagnostics()
    d.begin(None, 'x')
    r = d.preflight(4_000_000)
    assert [f.mechanism for f in r.findings] == ['target-not-found'] and not r.blocking
    print('[OK] B1 PID inexistente -> target-not-found (CONFIRMED como hecho, sin hablar de anti-debug)')

    base = labrun.LabProc('lab_baseline', 'x64', ['--net'])
    d = AntiDebugDiagnostics()
    d.begin(None, 'x')
    r = d.preflight(base.pid)
    assert not r.blocking and r.info.accessible and r.info.integrity == 'medium' and r.info.alive
    base.close()
    eaf = labrun.LabProc('lab_guard', 'x64', ['--eaf-emulate', '--interval-ms=2000'])
    d = AntiDebugDiagnostics()
    d.begin(None, 'x')
    t = time.perf_counter()
    r = d.preflight(eaf.pid)
    dt = time.perf_counter() - t
    g = [f for f in r.findings if f.mechanism == 'export-table-guard']
    assert r.blocking and g and g[0].verdict == Verdict.CONFIRMED and dt < 2.0, (r.blocking, dt)
    assert {e.data['module'].lower() for e in g[0].evidence} >= {'ntdll.dll', 'kernel32.dll', 'kernelbase.dll'}
    print(f'[OK] B2 preflight sobre EAT guardada: bloquea el attach en {dt * 1000:.0f} ms; CONFIRMED con '
          f'{len(g[0].evidence)} módulos (ntdll/kernel32/kernelbase)')

    # C1. el intérprete no se cuelga: AttachBlockedError rápido con informe
    logs = []
    ic = FridaInterceptor(on_event=lambda e: None, on_status=lambda s: None, on_log=logs.append,
                          audit_path=os.path.join(tempfile.gettempdir(), 'ad_audit.jsonl'))
    t = time.perf_counter()
    try:
        ic.attach(pid=eaf.pid)
        raise AssertionError('debió bloquearse')
    except AttachBlockedError as e:
        dt = time.perf_counter() - t
        assert dt < 3.0 and e.report.find('export-table-guard')
    assert eaf.alive() and ic.session_state == 'none'
    assert any('[diag] [confirmed] export-table-guard' in l for l in logs)
    eaf.close()
    print(f'[OK] C1 attach a objetivo con EAT guardada: AttachBlockedError en {dt:.2f}s (antes: cuelgue indefinido)')

    # C2. fallo de attach real (PID inexistente) -> UNKNOWN
    ic = FridaInterceptor(on_event=lambda e: None, on_status=lambda s: None, on_log=lambda l: None,
                          audit_path=os.path.join(tempfile.gettempdir(), 'ad_audit.jsonl'))
    try:
        ic.attach(pid=4_000_001)
        raise AssertionError('debió fallar')
    except frida.ProcessNotFoundError:
        pass
    rep = ic.diagnostics.report()
    assert rep.find('attach-failure:ProcessNotFoundError')[0].verdict == Verdict.UNKNOWN
    print('[OK] C2 attach real a PID inexistente -> attach-failure UNKNOWN')

    # C3. huella: agente de memoria solo vs agente de red
    for arch in ('x64', 'x86'):
        lab = labrun.LabProc('lab_baseline', arch, ['--net'])
        wow = arch == 'x86'
        ic = FridaInterceptor(on_event=lambda e: None, on_status=lambda s: None, on_log=lambda l: None,
                              audit_path=os.path.join(tempfile.gettempdir(), 'ad_audit.jsonl'))
        ic.attach(pid=lab.pid, network_agent=False)
        eng = ic.memory_engine()
        diag = AntiDebugDiagnostics()
        diag.begin(lab.pid, 'lab')
        diag.mark('attached')
        rd = lambda a, n: eng.read_range(a, n)       # noqa: E731
        fs = diag.scan_footprint(rd, eng.backend._modules(), wow64=wow, pid=lab.pid)
        assert not [f for f in fs if f.mechanism == 'inline-hook-footprint'], \
            'el agente de memoria no debe dejar hooks'
        assert [f for f in fs if f.mechanism == 'frida-visible-artifacts'], 'hilos/tuberías de Frida visibles'
        ic.stop()
        lab.close()

        lab = labrun.LabProc('lab_integrity', arch, ['--net', '--on-detect=report', '--interval-ms=50'])
        ic = FridaInterceptor(on_event=lambda e: None, on_status=lambda s: None, on_log=lambda l: None,
                              audit_path=os.path.join(tempfile.gettempdir(), 'ad_audit.jsonl'))
        ic.attach(pid=lab.pid, network_agent=True)
        eng = ic.memory_engine()
        time.sleep(1.0)
        eng.backend._mod_cache_ts = 0
        diag = AntiDebugDiagnostics()
        diag.begin(lab.pid, 'lab')
        fs = diag.scan_footprint(lambda a, n: eng.read_range(a, n), eng.backend._modules(), wow64=wow, pid=lab.pid)
        hook = [f for f in fs if f.mechanism == 'inline-hook-footprint']
        assert hook and hook[0].verdict == Verdict.CONFIRMED and hook[0].agents_affected == ['network']
        hits = {e.detail.split(' @ ')[0].split('!')[-1] for e in hook[0].evidence}
        # verdad de terreno: lo que detectó el propio objetivo
        mine = {d['function'] for d in lab.detects() if d['mech'] == 'inline-hook'}
        assert mine, 'lab_integrity debió detectar los hooks de red'
        from core.antidebug import footprint as fp
        all_hits = {h.function for h in fp.scan_inline_hooks(lambda a, n: eng.read_range(a, n),
                                                               eng.backend._modules(), wow64=wow)}
        assert mine <= all_hits, f'NetScope no vio hooks que el objetivo sí vio: {mine - all_hits}'
        print(f'[OK] C3 {arch}: solo-memoria 0 hooks; con agente de red NetScope ve {len(all_hits)} hooks y '
              f'cubre los {len(mine)} que detectó el propio objetivo ({", ".join(sorted(mine)[:4])}...)')
        ic.stop()
        lab.close()

    # C4. APIs anti-debug: sonda pasiva (imports) + observador activo (opt-in)
    from core.antidebug.probe import ProbeSession
    for name, expect_api in (('lab_isdebugger', 'IsDebuggerPresent'), ('lab_remotedbg', 'CheckRemoteDebuggerPresent'),
                             ('lab_ntquery', 'NtQueryInformationProcess')):
        lab = labrun.LabProc(name, 'x64', ['--on-detect=report'])
        sess = frida.attach(lab.pid)
        probe = ProbeSession(sess)
        diag = AntiDebugDiagnostics()
        diag.begin(lab.pid, name)
        diag.mark('attached')
        fs = diag.scan_static_imports(probe.scan_imports)
        assert any(f.mechanism == f'static-import:{expect_api}' and f.verdict == Verdict.INDICATION for f in fs), \
            [f.mechanism for f in fs]
        probe.observe()
        time.sleep(1.0)
        obs = diag.ingest_api_observations(probe.collect())
        assert any(expect_api in f.mechanism and f.verdict == Verdict.CONFIRMED for f in obs), [f.mechanism for f in obs]
        assert all('sin depurador' in f.summary for f in obs), [f.summary for f in obs]
        assert not lab.detects(), 'Frida no debe activar las banderas de depuración'
        probe.close()
        sess.detach()
        lab.close()
    print('[OK] C4 imports estáticos=INDICACIÓN; observador activo=CONFIRMADO (sin depurador) para IsDebuggerPresent, '
          'CheckRemoteDebuggerPresent y NtQueryInformationProcess; el objetivo no detecta depurador')

    # C5. sesión perdida real: el objetivo hace fast-fail tras el attach
    lab = labrun.LabProc('lab_terminator', 'x64', ['--die-after-ms=1800', '--die-mode=failfast', '--net'])
    ic = FridaInterceptor(on_event=lambda e: None, on_status=lambda s: None, on_log=lambda l: None,
                          audit_path=os.path.join(tempfile.gettempdir(), 'ad_audit.jsonl'))
    ic.attach(pid=lab.pid, network_agent=False)
    ic.memory_engine()
    assert lab.wait_event(lambda e: e['event'] == 'terminating', 6.0)
    time.sleep(0.8)
    rep = ic.diagnostics.report()
    lost = [f for f in rep.findings if f.mechanism in ('session-lost', 'termination-after-instrumentation')]
    assert lost and all(f.verdict != Verdict.CONFIRMED for f in lost), [(f.mechanism, f.verdict) for f in rep.findings]
    ev = ' '.join(e.detail for f in lost for e in f.evidence)
    assert 'process-terminated' in ev and '0xC0000409' in ev, ev
    assert ic.session_state == 'lost'
    lab.close()
    print(f'[OK] C5 terminación real (fast-fail): {lost[0].mechanism} / {lost[0].verdict.value}, evidencia '
          'incluye process-terminated y 0xC0000409; nunca CONFIRMED')

    # C6. attach colgado real (en subproceso: contamina al intérprete)
    code = ("import os,sys,time;sys.path.insert(0,r'%s');sys.path.insert(0,r'%s')\n"
            "import labrun\nfrom core.interceptor import FridaInterceptor\nfrom core.antidebug.errors import AttachTimeoutError\n"
            "lab=labrun.LabProc('lab_guard','x64',['--eaf-emulate','--interval-ms=2000'])\n"
            "ic=FridaInterceptor(on_event=lambda e:None,on_status=lambda s:None,on_log=lambda l:None,"
            "audit_path=os.path.join(os.environ['TEMP'],'ad_audit.jsonl'),attach_timeout=5,preflight=False)\n"
            "t=time.time()\n"
            "try:\n ic.attach(pid=lab.pid)\n print('NO-TIMEOUT')\n"
            "except AttachTimeoutError as e:\n"
            " f=ic.diagnostics.find('attach-timeout') if hasattr(ic.diagnostics,'find') else None\n"
            " fs=[x for x in ic.diagnostics.report().findings if x.mechanism=='attach-timeout']\n"
            " print('TIMEOUT',round(time.time()-t,1),fs[0].verdict.value)\n"
            "lab.close();os._exit(0)\n") % (os.path.join(BASE, 'tests', 'protection_lab'), BASE)
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=60,
                         stdin=subprocess.DEVNULL)
    line = [l for l in out.stdout.splitlines() if l.startswith(('TIMEOUT', 'NO-TIMEOUT'))]
    assert line and line[0].startswith('TIMEOUT') and line[0].endswith('unknown'), (out.stdout, out.stderr[-300:])
    print(f'[OK] C6 attach colgado (sin preflight): AttachTimeoutError tras {line[0].split()[1]}s con veredicto '
          f'UNKNOWN (sin evidencia, no se declara anti-debug)')

    print('ALL ANTIDEBUG TESTS PASSED')


if __name__ == '__main__':
    main()
