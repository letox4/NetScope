# -*- coding: utf-8 -*-
"""Matriz de escenarios: NetScope (agente de memoria / agente de red / ambos)
contra los ejecutables de laboratorio con protecciones REALES de Windows.

  py -3.11 tests\\protection_lab\\run_matrix.py [--scenarios a,b] [--arch x64] [--agents memory,network,both]
                                              [--modes attach,spawn] [--quick] [--out results\\matrix.json]
  py -3.11 tests\\protection_lab\\run_matrix.py --report results\\matrix.json --md docs\\FASE3_RESULTS.md
  py -3.11 tests\\protection_lab\\run_matrix.py --print-config        (configuración exacta de cada escenario)

Cada caso corre en su PROPIO subproceso: un attach colgado o un fallo de NetScope
no contamina al resto y queda medido como resultado.
Por caso se mide: estabilidad del objetivo y de NetScope, tiempo de attach, latencia
de lectura/escritura, pérdida de sesión, cambios involuntarios de protecciones,
integridad de los datos leídos y funcionamiento simultáneo memoria+red.
"""
import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, BASE)
sys.path.insert(0, HERE)

PAGE = 4096
PAGE_GUARD_RW = 0x104


def S(id, exe, args=(), mitigation=None, spawn=False, write_exec=False, dynamic=False, doc='', elevated_only=False,
      expect=''):
    return dict(id=id, exe=exe, args=list(args), mitigation=mitigation, spawn=spawn, write_exec=write_exec,
                dynamic=dynamic, doc=doc, elevated_only=elevated_only, expect=expect)


NET = ['--net']
SCENARIOS = [
    S('baseline', 'lab_baseline', NET, spawn=True, doc='Control: sin ninguna protección.',
      expect='todo OK en los tres modos'),
    S('isdebugger', 'lab_isdebugger', NET, spawn=True,
      doc='IsDebuggerPresent() cada 50 ms.', expect='Frida no activa BeingDebugged: sin detección'),
    S('remotedbg', 'lab_remotedbg', NET,
      doc='CheckRemoteDebuggerPresent(GetCurrentProcess()) cada 50 ms.', expect='sin detección'),
    S('ntquery', 'lab_ntquery', NET,
      doc='NtQueryInformationProcess(DebugPort 7, DebugObjectHandle 0x1E, DebugFlags 0x1F) + PEB.BeingDebugged.',
      expect='sin detección'),
    S('integrity_report', 'lab_integrity', NET + ['--on-detect=report'], spawn=True,
      doc='Compara prólogos de ws2_32/kernel32/ntdll con una línea base y hashea .text; solo informa.',
      expect='con agente de red: detecta hooks inline; solo memoria: nada'),
    S('integrity_exit', 'lab_integrity', NET + ['--on-detect=exit', '--grace-ms=200'], spawn=True,
      doc='Igual, pero ExitProcess(3) al detectar un hook.',
      expect='con agente de red el objetivo termina; solo memoria: sobrevive'),
    S('instrumentation_report', 'lab_instrumentation', NET + ['--on-detect=report', '--interval-ms=100'], spawn=True,
      doc='Busca artefactos de Frida: módulos, nombres de hilo, tuberías, cadenas en memoria; solo informa.',
      expect='detecta hilos gmain/gdbus/gum-js-loop y tubería frida-* con CUALQUIER agente'),
    S('instrumentation_exit', 'lab_instrumentation', NET + ['--on-detect=terminate', '--interval-ms=100'], spawn=True,
      doc='Igual, pero TerminateProcess al detectar un artefacto.',
      expect='el objetivo termina con cualquier agente'),
    S('execmem_report', 'lab_execmem', NET + ['--on-detect=report'], write_exec=True,
      doc='Hashea .text y sus regiones RX/RWX; solo informa. NetScope escribe 1 byte en la región RWX.',
      expect='detecta la escritura de NetScope en memoria ejecutable'),
    S('execmem_exit', 'lab_execmem', NET + ['--on-detect=exit', '--grace-ms=100'], write_exec=True,
      doc='Igual, pero ExitProcess al detectar el cambio.',
      expect='la escritura en RWX termina el objetivo'),
    S('guard', 'lab_guard', NET, doc='Páginas PAGE_GUARD + VEH que cuenta cada acceso.',
      expect='NetScope no consume ninguna guarda'),
    S('guard_rearm', 'lab_guard', NET + ['--rearm'],
      doc='Igual, con rearmado de guarda tras cada acceso (single-step).', expect='sin accesos de NetScope'),
    S('eaf_emulated_armed', 'lab_guard', NET + ['--eaf-emulate'],
      doc='Guardas PAGE_GUARD rearmadas sobre la EAT de kernel32/kernelbase/ntdll (emulación de EAF).',
      expect='preflight evita el attach (se colgaría)'),
    S('eaf_emulated_oneshot', 'lab_guard', NET + ['--eaf-emulate', '--oneshot', '--interval-ms=20'],
      doc='Guardas EAT de un solo disparo (el propio objetivo las consume al instante).',
      expect='attach posible'),
    S('terminator_timer', 'lab_terminator', NET + ['--die-after-ms=3000', '--die-mode=terminate'],
      doc='Control: TerminateProcess a los 3 s SIN detectar nada.',
      expect='sesión perdida sin detección; no debe llamarse anti-debug'),
    S('terminator_crash', 'lab_terminator', NET + ['--die-after-ms=3000', '--die-mode=crash'],
      doc='Control: violación de acceso (crash) a los 3 s.', expect='Frida informa crash'),
    S('terminator_failfast', 'lab_terminator', NET + ['--die-after-ms=3000', '--die-mode=failfast'],
      doc='Control: __fastfail a los 3 s.', expect='código de salida 0xC0000409'),
    S('terminator_debug', 'lab_terminator', NET + ['--detectors=debug', '--on-detect=exit'], spawn=True,
      doc='Termina si ve IsDebuggerPresent/CheckRemote/NtQuery*/PEB.', expect='sobrevive: Frida no es un depurador'),
    S('terminator_all', 'lab_terminator', NET + ['--detectors=all', '--on-detect=exit', '--grace-ms=50'], spawn=True,
      doc='Termina ante cualquier detector (depuración, integridad, instrumentación, ejecutable).',
      expect='termina con cualquier agente (artefactos de hilo/tubería de Frida)'),
    S('memdyn', 'lab_memdyn', NET + ['--churn-ms=15'], dynamic=True,
      doc='Cambia permisos RW<->RO, libera/reasigna regiones y rearma guardas cada 15 ms.',
      expect='errores limpios; sin caída; patrón íntegro'),
    S('mit_inproc_dyncode', 'lab_mitigated', NET + ['--policy=dyncode'], spawn=True,
      doc='SetProcessMitigationPolicy(ProcessDynamicCodePolicy) al arrancar.', expect='ver resultados'),
    S('mit_inproc_signature', 'lab_mitigated', NET + ['--policy=signature'],
      doc='SetProcessMitigationPolicy(ProcessSignaturePolicy: solo firmadas por Microsoft).', expect='ver resultados'),
    S('mit_inproc_all', 'lab_mitigated', NET + ['--policy=all'],
      doc='Todas las políticas aplicables en el propio proceso (dyncode, signature, imageload, extpoint, handle, cfg, childproc).',
      expect='ver resultados'),
    S('mit_create_no_dyncode', 'lab_mitigated', NET, mitigation='no_dyncode',
      doc='CreateProcess + PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: PROHIBIT_DYNAMIC_CODE_ALWAYS_ON.',
      expect='ver resultados'),
    S('mit_create_ms_signed', 'lab_mitigated', NET, mitigation='ms_signed_only',
      doc='BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON desde el arranque.', expect='ver resultados'),
    S('mit_create_no_remote', 'lab_mitigated', NET, mitigation='no_remote_images',
      doc='IMAGE_LOAD_NO_REMOTE + IMAGE_LOAD_PREFER_SYSTEM32.', expect='ver resultados'),
    S('mit_create_cet', 'lab_mitigated', NET, mitigation='cet_shadow_stack',
      doc='POLICY2 CET_USER_SHADOW_STACKS_ALWAYS_ON (pilas sombra).', expect='ver resultados'),
    S('mit_create_strict_cfg', 'lab_mitigated', NET, mitigation='strict_cfg',
      doc='CONTROL_FLOW_GUARD_ALWAYS_ON + POLICY2 STRICT_CONTROL_FLOW_GUARD.', expect='ver resultados'),
    S('mit_create_module_tamper', 'lab_mitigated', NET, mitigation='module_tampering',
      doc='POLICY2 MODULE_TAMPERING_PROTECTION_ALWAYS_ON.', expect='ver resultados'),
    S('mit_create_combo', 'lab_mitigated', NET, mitigation='combo',
      doc='dyncode + firmadas-MS + sin imágenes remotas + handles estrictos + sin extension points + CFG estricto + module tampering.',
      expect='ver resultados'),
    S('eaf_real', 'lab_guard', NET, elevated_only=True,
      doc='EAF REAL: Set-ProcessMitigation -Name lab_guard_<arch>.exe -Enable EnableExportAddressFilter '
          '(scripts\\eaf_enable.ps1, requiere elevación). Se omite si no está configurado.',
      expect='ver resultados (omitido sin configuración)'),
]
BY_ID = {s['id']: s for s in SCENARIOS}


def median_ms(xs):
    return round(statistics.median(xs) * 1000, 2) if xs else None


# =====================================================================
#  Un caso, en un proceso propio
# =====================================================================
def run_one(spec):
    import frida  # noqa: F401  (comprueba que está)
    import labrun
    from core.antidebug import preflight as pf
    from core.antidebug.errors import AttachBlockedError, AttachTimeoutError
    from core.interceptor import FridaInterceptor
    from core.memory.models import MemoryError, SessionError

    sc = BY_ID[spec['scenario']]
    arch, agents, mode, work_s = spec['arch'], spec['agents'], spec['mode'], spec.get('work_s', 2.5)
    r = dict(scenario=sc['id'], arch=arch, agents=agents, mode=mode, outcome='ok', notes=[], findings=[],
             unexpected=[])
    lab = None
    ic = None
    logs, statuses = [], []
    net = {'seen': 0}
    try:
        # ---- configuración especial ----
        if sc['elevated_only']:
            cfg = pf.mitigations_of_image(f"{sc['exe']}_{arch}.exe") or {}
            if cfg.get('eaf') != 'ON':
                r['outcome'] = 'skipped'
                r['notes'].append('EAF real no configurado (requiere elevación: scripts\\eaf_enable.ps1)')
                return r
        # ---- lanzar objetivo ----
        t0 = time.perf_counter()
        try:
            if mode == 'spawn':
                lab = labrun.SpawnedLab(sc['exe'], arch, sc['args'])
            else:
                mit = labrun.MIT[sc['mitigation']] if sc['mitigation'] else None
                lab = labrun.LabProc(sc['exe'], arch, sc['args'], mitigation=mit)
        except Exception as exc:     # noqa: BLE001
            r['outcome'] = 'launch_failed'
            r['notes'].append(str(exc)[:200])
            return r
        r['t_launch_s'] = round(time.perf_counter() - t0, 3)
        pid = lab.pid
        pre_prot = lab.prot() if mode == 'attach' else None
        if mode == 'attach':
            r['exec_regions_ok'] = lab.ready.get('exec_regions_ok')

        def on_event(ev):
            if ev.event in ('send', 'wsa_send') and b'NETSCOPE-LAB-PING' in ev.data:
                net['seen'] += 1

        ic = FridaInterceptor(on_event=on_event, on_status=statuses.append, on_log=logs.append,
                              audit_path=os.path.join(tempfile.gettempdir(), 'netscope_matrix_audit.jsonl'),
                              attach_timeout=12.0)
        # ---- attach ----
        t = time.perf_counter()
        try:
            ic.attach(pid=pid, network_agent=(agents != 'memory'))
            r['t_attach_s'] = round(time.perf_counter() - t, 3)
        except AttachBlockedError as exc:
            r['outcome'] = 'attach_blocked'
            r['t_attach_s'] = round(time.perf_counter() - t, 3)
            r['notes'].append(str(exc)[:160])
            return _finish(r, lab, ic, None, pre_prot, sc, net)
        except AttachTimeoutError as exc:
            r['outcome'] = 'attach_timeout'
            r['t_attach_s'] = round(time.perf_counter() - t, 3)
            r['notes'].append(str(exc)[:160])
            return _finish(r, lab, ic, None, pre_prot, sc, net)
        except Exception as exc:     # noqa: BLE001
            r['outcome'] = 'attach_failed'
            r['notes'].append(f'{type(exc).__name__}: {exc}'[:200])
            return _finish(r, lab, ic, None, pre_prot, sc, net)
        r['network_agent_ready'] = any('Hooks activos' in s for s in statuses) if agents != 'memory' else None
        if agents != 'memory':
            tag = [l for l in logs if 'Hooks activos:' in l]
            r['network_hooks'] = tag[0][:140] if tag else None
            r['network_agent_errors'] = ('ERRORES' in tag[0]) if tag else None

        # ---- agente de memoria ----
        eng = None
        if agents in ('memory', 'both'):
            t = time.perf_counter()
            try:
                eng = ic.memory_engine()
                r['t_memory_load_s'] = round(time.perf_counter() - t, 3)
                r['memory_caps'] = {k: bool(v) for k, v in vars(eng.caps).items() if isinstance(v, bool)}
            except SessionError as exc:
                r['outcome'] = 'session_lost'
                r['notes'].append(f'memory_engine: {exc.reason} {exc.detail}')
            except Exception as exc:     # noqa: BLE001
                r['outcome'] = 'agent_failed'
                r['notes'].append(f'memory_engine: {type(exc).__name__}: {exc}'[:200])
                ic.diagnostics.on_agent_failure('memory', exc)
        if mode == 'spawn':
            try:
                r['t_resume_to_ready_s'] = round(lab.resume(), 3)
                pre_prot = lab.prot()
                r['exec_regions_ok'] = lab.ready.get('exec_regions_ok')
            except Exception as exc:     # noqa: BLE001
                r['outcome'] = 'launch_failed'
                r['notes'].append(f'resume: {exc}'[:160])
                return _finish(r, lab, ic, eng, pre_prot, sc, net)

        # ---- carga de trabajo (memoria y red a la vez) ----
        mem = dict(ops=0, ok=0, domain={}, session=0, lat_read=[], lat_write=[], integ_n=0, integ_bad=0,
                   scalar_n=0, scalar_bad=0, guard_n=0, guard_ok=0)
        if eng is not None and r['outcome'] == 'ok':
            _memory_workload(eng, lab, arch, sc, work_s, mem, r, labrun, MemoryError, SessionError)
        else:
            time.sleep(work_s)
        r['mem'] = {k: (v if not k.startswith('lat_') else median_ms(v)) for k, v in mem.items()}
        return _finish(r, lab, ic, eng, pre_prot, sc, net)
    except Exception as exc:     # noqa: BLE001
        r['outcome'] = 'harness_error'
        r['notes'].append(f'{type(exc).__name__}: {exc}'[:300])
        return r
    finally:
        try:
            if ic is not None:
                ic.stop()
        except Exception:
            pass
        if lab is not None:
            lab.close()


def _memory_workload(eng, lab, arch, sc, work_s, mem, r, labrun, MemoryError, SessionError):
    R = lab.regions
    exp = labrun.pattern_bytes()
    exp_ptr = 0xDEADBEEF12345678 if arch == 'x64' else 0x12345678
    end = time.time() + work_s
    i = 0
    exec_done = False

    def op(name, fn):
        mem['ops'] += 1
        try:
            v = fn()
            mem['ok'] += 1
            return True, v
        except SessionError as e:
            mem['session'] += 1
            r['notes'].append(f'{name}: sesión perdida ({e.detail})')
            raise
        except MemoryError as e:
            mem['domain'][e.reason] = mem['domain'].get(e.reason, 0) + 1
            return False, e.reason
        except Exception as e:      # noqa: BLE001
            r['unexpected'].append(f'{name}: {type(e).__name__}: {e}'[:160])
            return False, None

    try:
        while time.time() < end:
            t = time.perf_counter()
            ok, v = op('read_pattern', lambda: eng.read_range(R['pattern'], 16 * PAGE))
            mem['lat_read'].append(time.perf_counter() - t)
            if ok:
                mem['integ_n'] += 1
                if v[1] is not None or v[0] != exp:
                    mem['integ_bad'] += 1
            ok, v = op('scalar_u32', lambda: eng.read_value(R['tail'], 'u32'))
            if ok:
                mem['scalar_n'] += 1
                mem['scalar_bad'] += v != 0x12345678
            ok, v = op('scalar_ptr', lambda: eng.read_value(R['tail'], 'ptr'))
            if ok:
                mem['scalar_n'] += 1
                mem['scalar_bad'] += v != exp_ptr
            addr = R['tail'] + 512 + (i % 32) * 8
            t = time.perf_counter()
            ok, rec = op('write', lambda: eng.write(addr, (i + 1).to_bytes(8, 'little'), note='matrix'))
            if ok and rec.applied:
                op('rollback', lambda: eng.rollback(rec))
                mem['lat_write'].append(time.perf_counter() - t)
            mem['guard_n'] += 1
            ok, v = op('read_guard', lambda: eng.read_range(R['guard'], 16))
            if ok and v[1] == 'E_PAGE_GUARD':
                mem['guard_ok'] += 1
            if sc['dynamic']:
                op('read_flip', lambda: eng.read_range(R['flip'], 16))
                op('write_flip', lambda: eng.write(R['flip'] + 64, b'MX'))
                op('read_freeme', lambda: eng.read_range(R['freeme'], 64))
            if sc['write_exec'] and not exec_done and time.time() > end - work_s * 0.6:
                exec_done = True
                ok, rec = op('write_exec', lambda: eng.write(R['rwx'] + 1, b'\x90', note='matrix-exec'))
                r['exec_write'] = 'applied' if (ok and rec.applied) else f'rejected:{rec if not ok else rec.reason}'
                time.sleep(0.4)
            i += 1
            time.sleep(0.02)
    except SessionError:
        pass


def _finish(r, lab, ic, eng, pre_prot, sc, net):
    from core.antidebug import preflight as pf
    time.sleep(0.2)
    alive = lab.alive()
    r['target_alive'] = alive
    r['session_state'] = ic.session_state if ic is not None else None
    r['detach_reason'] = ic.detach_reason if ic is not None else None
    if r['outcome'] == 'ok' and ic is not None and ic.session_state == 'lost':
        r['outcome'] = 'session_lost'
    if not alive:
        code = lab.wait_exit(1.0)
        r['exit_code'] = None if code is None else f'0x{code & 0xFFFFFFFF:08X}'
    detects = lab.detects() if lab is not None else []
    r['lab_detects'] = sorted({d['mech'] for d in detects})
    term = [e for e in (lab.events if lab is not None else []) if e.get('event') == 'terminating']
    r['lab_terminating'] = (term[0]['method'] + ' por ' + term[0]['reason']) if term else None
    if alive:
        try:
            st = lab.status()
            r['lab_status'] = {k: st.get(k) for k in ('checks', 'detections', 'net_sent', 'net_recv', 'guard_hits',
                                                        'cycles', 'frees', 'reallocs_fail') if k in st}
            if pre_prot is not None:
                post = lab.prot()
                skip = set()
                if sc['dynamic']:
                    skip = {k for k in pre_prot if k.split('.')[0] in ('flip', 'freeme', 'guard')}
                if sc['write_exec']:
                    skip |= {k for k in pre_prot if k.split('.')[0] in ('rwx',)}
                r['prot_changed'] = sorted(k for k in pre_prot if k not in skip and post.get(k) != pre_prot[k])
                r['guard_intact'] = post.get('guard.0', [0])[0] == PAGE_GUARD_RW if 'guard.0' in post else None
        except Exception as exc:     # noqa: BLE001
            r['notes'].append(f'estado final: {type(exc).__name__}')
    r['net_ping_seen'] = net['seen']
    if ic is not None:
        rep = ic.diagnostics.report()
        r['findings'] = sorted({(f.mechanism, f.verdict.value) for f in rep.findings})
        r['findings'] = [list(x) for x in r['findings']]
        tl = {t['step']: t['t'] for t in rep.timeline}
        lost = [f for f in rep.findings if f.mechanism in ('session-lost', 'termination-after-instrumentation')]
        if lost and 'attached' in tl:
            r['session_lost_after_s'] = round(lost[0].detected_at - tl['attached'], 2)
    return r


# =====================================================================
#  Orquestador
# =====================================================================
def run_matrix(args):
    scen = [s for s in SCENARIOS if not args.scenarios or s['id'] in args.scenarios.split(',')]
    archs = args.arch.split(',')
    agents_l = args.agents.split(',')
    modes = args.modes.split(',')
    cases = []
    for sc in scen:
        for arch in archs:
            for mode in modes:
                if mode == 'spawn' and not sc['spawn']:
                    continue
                if mode == 'spawn' and args.quick and sc['id'] not in ('baseline', 'integrity_exit', 'terminator_all'):
                    continue
                for ag in agents_l:
                    cases.append(dict(scenario=sc['id'], arch=arch, agents=ag, mode=mode, work_s=args.work))
    out = []
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    print(f'{len(cases)} casos', flush=True)
    for n, c in enumerate(cases, 1):
        t = time.time()
        # salida a fichero (no tubería): los labs heredan handles y mantendrían la tubería abierta
        with tempfile.TemporaryFile('w+', encoding='utf-8', errors='replace') as fo, \
                tempfile.TemporaryFile('w+', encoding='utf-8', errors='replace') as fe:
            try:
                p = subprocess.Popen([sys.executable, os.path.abspath(__file__), '--one', json.dumps(c)],
                                     stdout=fo, stderr=fe, stdin=subprocess.DEVNULL)
                try:
                    p.wait(timeout=args.case_timeout)
                    timed_out = False
                except subprocess.TimeoutExpired:
                    p.kill()
                    timed_out = True
                fo.seek(0)
                fe.seek(0)
                lines = [l for l in fo.read().splitlines() if l.startswith('{"scenario"')]
                err = fe.read()[-200:]
                if timed_out:
                    res = dict(c, outcome='harness_timeout', notes=['el caso superó el límite'], findings=[],
                               unexpected=[])
                elif lines:
                    res = json.loads(lines[-1])
                else:
                    res = dict(c, outcome='netscope_crashed', notes=[f'código {p.returncode}', err],
                               findings=[], unexpected=[])
            except Exception as exc:      # noqa: BLE001
                res = dict(c, outcome='harness_error', notes=[str(exc)[:200]], findings=[], unexpected=[])
        res['wall_s'] = round(time.time() - t, 1)
        out.append(res)
        print(f"[{n}/{len(cases)}] {c['scenario']:24s} {c['arch']} {c['agents']:7s} {c['mode']:6s} -> "
              f"{res['outcome']:15s} alive={res.get('target_alive')} {res.get('t_attach_s', '')}s", flush=True)
        with open(args.out, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=1)
    return out


def scenarios_markdown(path):
    """docs/FASE3_SCENARIOS.md generado desde la MISMA tabla que ejecuta la matriz."""
    import labrun
    L = ['# Fase 3 — Escenarios del laboratorio (configuración exacta)', '',
         '_Generado por `tests/protection_lab/run_matrix.py --scenarios-md`; es la misma tabla que ejecuta la matriz, '
         'así que no puede desincronizarse._', '',
         'Los ejecutables están en `tests/protection_lab/bin/<nombre>_<x64|x86>.exe` '
         '(`tests\\protection_lab\\build.ps1`). Todos aceptan además `--max-seconds=N` (vigilante, 300 por defecto) '
         'e `--interval-ms=N`.', '',
         '| Escenario | Ejecutable y argumentos | Mitigaciones de arranque (CreateProcess) | Qué reproduce | Esperado |',
         '|---|---|---|---|---|']
    for s in SCENARIOS:
        mit = '—'
        if s['mitigation']:
            p1, p2 = labrun.MIT[s['mitigation']]
            mit = (f'`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` = [`{p1:#018x}`, `{p2:#018x}`] '
                   f'(`MIT["{s["mitigation"]}"]`)')
        args = ' '.join(s['args'])
        spawn = ' (también spawn)' if s['spawn'] else ''
        L.append(f"| `{s['id']}`{spawn} | `{s['exe']}_<arch>.exe {args}` | {mit} | {s['doc']} | {s['expect']} |")
    L.append('')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(L))


def print_config():
    print('Configuración exacta de cada escenario (ejecutable + argumentos + mitigación):\n')
    import labrun
    for s in SCENARIOS:
        mit = ''
        if s['mitigation']:
            p1, p2 = labrun.MIT[s['mitigation']]
            mit = f"  CreateProcess PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = [{p1:#018x}, {p2:#018x}]"
        print(f"- {s['id']}: lab/bin/{s['exe']}_<x64|x86>.exe {' '.join(s['args'])}{mit}")
        print(f"    {s['doc']}")


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--one')
    ap.add_argument('--scenarios')
    ap.add_argument('--arch', default='x64,x86')
    ap.add_argument('--agents', default='memory,network,both')
    ap.add_argument('--modes', default='attach,spawn')
    ap.add_argument('--quick', action='store_true')
    ap.add_argument('--work', type=float, default=2.5)
    ap.add_argument('--case-timeout', type=float, default=90.0)
    ap.add_argument('--out', default=os.path.join(HERE, 'results', 'matrix.json'))
    ap.add_argument('--print-config', action='store_true')
    ap.add_argument('--scenarios-md')
    ap.add_argument('--report')
    ap.add_argument('--md')
    a = ap.parse_args()
    if a.one:
        res = run_one(json.loads(a.one))
        print(json.dumps(res, default=str), flush=True)
        os._exit(0)          # un attach colgado no debe impedir la salida
    elif a.print_config:
        print_config()
    elif a.scenarios_md:
        scenarios_markdown(a.scenarios_md)
    elif a.report:
        from report import build_markdown
        build_markdown(a.report, a.md)
    else:
        run_matrix(a)
