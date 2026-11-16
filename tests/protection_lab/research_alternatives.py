# -*- coding: utf-8 -*-
"""Evaluación comparada de alternativas de instrumentación / acceso a memoria.

  py -3.11 tests\\protection_lab\\research_alternatives.py [--json out.json]

Mide sobre los ejecutables de laboratorio (procesos propios):
  A  Frida attach vs spawn: tiempos y, con lab_instrumentation, qué ve el objetivo.
  B  APIs nativas (VirtualQueryEx / ReadProcessMemory / WriteProcessMemory): capacidades,
     tiempos, efecto sobre guardas, escritura sobre páginas de solo lectura y
     observabilidad por parte del objetivo (SIN inyectar nada).
  C  Depuración de Windows (DebugActiveProcess + WaitForDebugEvent): efecto sobre los
     mecanismos IsDebuggerPresent / CheckRemoteDebuggerPresent / NtQueryInformationProcess.
  D  ETW: qué se puede arrancar sin elevación y qué observabilidad ofrece.
Nada de esto oculta ni evade protecciones: solo mide qué ve cada técnica.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', '..')))

import labrun  # noqa: E402

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.POINTER(ctypes.c_size_t)]
k32.CloseHandle.argtypes = [wt.HANDLE]
PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_QUERY_INFORMATION = 0x10, 0x20, 0x8, 0x400


class MBI(ctypes.Structure):
    _fields_ = [('Base', ctypes.c_void_p), ('AllocBase', ctypes.c_void_p), ('AllocProt', wt.DWORD),
                ('Part', wt.WORD), ('Region', ctypes.c_size_t), ('State', wt.DWORD),
                ('Protect', wt.DWORD), ('Type', wt.DWORD)]


k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]


def med(xs):
    return round(statistics.median(xs) * 1000, 2) if xs else None


# ----------------------------------------------------------------- A: Frida attach/spawn
def exp_frida():
    import frida
    from core.interceptor import FridaInterceptor
    out = {}
    for mode in ('attach', 'spawn'):
        ts, tm = [], []
        for _ in range(3):
            if mode == 'attach':
                lab = labrun.LabProc('lab_baseline', 'x64', ['--net'])
                pid = lab.pid
            else:
                lab = labrun.SpawnedLab('lab_baseline', 'x64', ['--net'])
                pid = lab.pid
            ic = FridaInterceptor(on_event=lambda e: None, on_status=lambda s: None, on_log=lambda l: None,
                                  audit_path=os.path.join(os.environ.get('TEMP', '.'), 'alt_audit.jsonl'))
            t = time.perf_counter()
            ic.attach(pid=pid, network_agent=False)
            ts.append(time.perf_counter() - t)
            t = time.perf_counter()
            ic.memory_engine()
            tm.append(time.perf_counter() - t)
            if mode == 'spawn':
                lab.resume()
            ic.stop()
            lab.close()
        out[mode] = {'attach_ms': med(ts), 'memory_agent_ms': med(tm)}
    # ¿qué ve el objetivo? lab_instrumentation con attach SOLO memoria
    lab = labrun.LabProc('lab_instrumentation', 'x64', ['--on-detect=report', '--interval-ms=100'])
    time.sleep(0.5)
    before = {d['mech'] for d in lab.detects()}
    ic = FridaInterceptor(on_event=lambda e: None, on_status=lambda s: None, on_log=lambda l: None,
                          audit_path=os.path.join(os.environ.get('TEMP', '.'), 'alt_audit.jsonl'))
    ic.attach(pid=lab.pid, network_agent=False)
    time.sleep(1.5)
    after = {d['mech'] for d in lab.detects()}
    out['frida_visible_to_target'] = sorted(after - before)
    # módulos: confirmación de que el agente no figura con nombre propio
    ic.stop()
    lab.close()
    return out


# ----------------------------------------------------------------- B: APIs nativas
def exp_native():
    out = {}
    lab = labrun.LabProc('lab_baseline', 'x64', ['--net'])
    R = lab.regions
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                        False, lab.pid)
    # enumeración por VirtualQueryEx
    t = time.perf_counter()
    addr, n, guard_pages = 0, 0, 0
    m = MBI()
    while addr < 0x7FFFFFFF0000 and k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m)):
        if m.State == 0x1000:
            n += 1
            guard_pages += 1 if m.Protect & 0x100 else 0
        addr = (m.Base or 0) + m.Region
        if m.Region == 0:
            break
    out['VirtualQueryEx_enumerate'] = {'regions': n, 'ms': round((time.perf_counter() - t) * 1000, 1),
                                       'guard_regions_identified': guard_pages}
    # lectura de 64 KB con integridad
    exp = labrun.pattern_bytes()
    lat = []
    ok = True
    for _ in range(20):
        buf = ctypes.create_string_buffer(len(exp))
        got = ctypes.c_size_t(0)
        t = time.perf_counter()
        r = k32.ReadProcessMemory(h, ctypes.c_void_p(R['pattern']), buf, len(exp), ctypes.byref(got))
        lat.append(time.perf_counter() - t)
        ok &= bool(r) and buf.raw == exp
    out['ReadProcessMemory_64KB'] = {'median_ms': med(lat), 'integrity_ok': bool(ok)}
    # lectura sobre guard / liberada / RO / RX
    res = {}
    for name, a in (('guard', R['guard']), ('rx', R['rx']), ('two_ro_page', R['two'] + 4096)):
        buf = ctypes.create_string_buffer(8)
        got = ctypes.c_size_t(0)
        r = k32.ReadProcessMemory(h, ctypes.c_void_p(a), buf, 8, ctypes.byref(got))
        res[name] = f'ok={bool(r)} err={0 if r else ctypes.get_last_error()}'
    q0 = lab.prot()['guard.0'][0]
    res['guard_protect_before_after'] = f'{hex(q0)} -> {hex(lab.prot()["guard.0"][0])}'
    out['ReadProcessMemory_special_pages'] = res
    # escritura nativa: RW, RO, RX, guard
    wres = {}
    pre = lab.prot()
    for name, a, pg in (('rw (flip)', R['flip'], 'flip.0'), ('ro (two+4096)', R['two'] + 4096, 'two.1'),
                        ('rx', R['rx'], 'rx.0'), ('guard', R['guard'], 'guard.0')):
        wrote = ctypes.c_size_t(0)
        r = k32.WriteProcessMemory(h, ctypes.c_void_p(a), b'\x41', 1, ctypes.byref(wrote))
        err = 0 if r else ctypes.get_last_error()
        post = lab.prot()
        wres[name] = (f'ok={bool(r)} err={err} escrito={wrote.value} protección '
                      f'{hex(pre[pg][0])}->{hex(post[pg][0])}')
    out['WriteProcessMemory'] = wres
    # observabilidad: el objetivo (lab_instrumentation / lab_integrity) NO debe ver nada
    k32.CloseHandle(h)
    lab.close()
    seen = {}
    for name in ('lab_instrumentation', 'lab_integrity', 'lab_execmem'):
        l2 = labrun.LabProc(name, 'x64', ['--on-detect=report', '--interval-ms=50'])
        h2 = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, l2.pid)
        t_end = time.time() + 1.5
        buf = ctypes.create_string_buffer(65536)
        got = ctypes.c_size_t(0)
        while time.time() < t_end:
            k32.ReadProcessMemory(h2, ctypes.c_void_p(l2.regions['pattern']), buf, 65536, ctypes.byref(got))
            time.sleep(0.01)
        seen[name] = sorted({d['mech'] for d in l2.detects()})
        k32.CloseHandle(h2)
        l2.close()
    out['target_detections_during_native_reads'] = seen
    return out


# ----------------------------------------------------------------- C: depuración de Windows
class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [('dwDebugEventCode', wt.DWORD), ('dwProcessId', wt.DWORD), ('dwThreadId', wt.DWORD),
                ('u', ctypes.c_ubyte * 160)]


k32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wt.DWORD]
k32.ContinueDebugEvent.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD]
k32.DebugActiveProcess.argtypes = [wt.DWORD]
k32.DebugActiveProcessStop.argtypes = [wt.DWORD]
k32.DebugSetProcessKillOnExit.argtypes = [wt.BOOL]


def debug_session(pid, seconds):
    k32.DebugSetProcessKillOnExit(False)
    t = time.perf_counter()
    if not k32.DebugActiveProcess(pid):
        return {'error': ctypes.get_last_error()}
    t_attach = time.perf_counter() - t
    events, end = {}, time.time() + seconds
    ev = DEBUG_EVENT()
    while time.time() < end:
        if k32.WaitForDebugEvent(ctypes.byref(ev), 100):
            events[ev.dwDebugEventCode] = events.get(ev.dwDebugEventCode, 0) + 1
            # 0x80010001 DBG_EXCEPTION_NOT_HANDLED / 0x00010002 DBG_CONTINUE
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, 0x00010002)
    t = time.perf_counter()
    k32.DebugActiveProcessStop(pid)
    return {'attach_ms': round(t_attach * 1000, 1), 'detach_ms': round((time.perf_counter() - t) * 1000, 1),
            'debug_events': events}


def exp_debug():
    out = {}
    for name in ('lab_isdebugger', 'lab_remotedbg', 'lab_ntquery', 'lab_terminator'):
        args = ['--on-detect=report'] if name != 'lab_terminator' else ['--detectors=debug', '--on-detect=exit']
        lab = labrun.LabProc(name, 'x64', args)
        time.sleep(0.4)
        before = len(lab.detects())
        info = debug_session(lab.pid, 1.5)
        time.sleep(0.3)
        out[name] = dict(info, detecciones=sorted({d['mech'] for d in lab.detects()}),
                         objetivo_vivo_tras_depurar=lab.alive(), detecciones_previas=before)
        lab.close()
    return out


# ----------------------------------------------------------------- D: ETW
def run_ps(cmd, timeout=30):
    p = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', cmd], capture_output=True,
                       text=True, timeout=timeout)
    return (p.stdout + p.stderr).strip()


def exp_etw():
    out = {}
    out['en_grupo_Performance_Log_Users_o_admin'] = run_ps(
        "whoami /groups | Select-String 'Performance Log Users|Administrators' | ForEach-Object { $_.Line.Split(' ')[0] }")[:200] or 'no'
    out['logman_query_providers_count'] = run_ps("(logman query providers | Measure-Object -Line).Lines")
    out['kernel_process_provider_listed'] = 'Microsoft-Windows-Kernel-Process' in run_ps(
        "logman query providers | Select-String 'Kernel-Process'")
    s = run_ps("logman create trace nsprobe -p Microsoft-Windows-Kernel-Process -o $env:TEMP\\nsprobe.etl -ets 2>&1")
    out['logman_start_session_sin_elevar'] = s[:240]
    run_ps("logman stop nsprobe -ets 2>&1")
    out['Get_WinEvent_ListLog_Kernel_Process'] = run_ps(
        "(Get-WinEvent -ListLog 'Microsoft-Windows-Kernel-Process/Analytic' -ErrorAction SilentlyContinue | "
        "Select-Object -First 1 | ForEach-Object { 'IsEnabled=' + $_.IsEnabled }) 2>&1")[:160] or 'sin canal legible'
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json')
    a = ap.parse_args()
    res = {}
    for name, fn in (('A_frida', exp_frida), ('B_native', exp_native), ('C_debug_api', exp_debug), ('D_etw', exp_etw)):
        print(f'\n== {name} ==', flush=True)
        try:
            res[name] = fn()
        except Exception as exc:     # noqa: BLE001
            res[name] = {'error': f'{type(exc).__name__}: {exc}'}
        print(json.dumps(res[name], indent=1, ensure_ascii=False, default=str), flush=True)
    if a.json:
        json.dump(res, open(a.json, 'w', encoding='utf-8'), indent=1, ensure_ascii=False, default=str)


if __name__ == '__main__':
    main()
