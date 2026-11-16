# -*- coding: utf-8 -*-
"""Lanzador de los ejecutables de laboratorio (tests/protection_lab/bin).

  LabProc('lab_guard', 'x64', ['--rearm'])                     lanzamiento normal
  LabProc('lab_baseline', 'x64', mitigation=MIT['no_dyncode']) mitigaciones OFICIALES
      de arranque: CreateProcess + PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY.

Cada proceso habla el protocolo JSON de labkit.h (ver src/labkit.h).
"""
import ctypes
import ctypes.wintypes as wt
import json
import msvcrt
import os
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, 'bin')
PAGE = 4096

# Constantes oficiales de winbase.h (PROCESS_CREATION_MITIGATION_POLICY_*_ALWAYS_ON)
P1 = {
    'strict_handle': 1 << 24, 'extension_point_disable': 1 << 32, 'prohibit_dynamic_code': 1 << 36,
    'cfg': 1 << 40, 'block_non_microsoft_binaries': 1 << 44, 'image_load_no_remote': 1 << 52,
    'image_load_prefer_system32': 1 << 60,
}
P2 = {
    'strict_cfg': 1 << 8, 'module_tampering': 1 << 12, 'cet_user_shadow_stacks': 1 << 28,
    'block_non_cet_binaries': 1 << 36,
}
# nombre de escenario -> (policy1, policy2)
MIT: Dict[str, Tuple[int, int]] = {
    'no_dyncode': (P1['prohibit_dynamic_code'], 0),
    'ms_signed_only': (P1['block_non_microsoft_binaries'], 0),
    'no_remote_images': (P1['image_load_no_remote'] | P1['image_load_prefer_system32'], 0),
    'cet_shadow_stack': (0, P2['cet_user_shadow_stacks']),
    'strict_cfg': (P1['cfg'], P2['strict_cfg']),
    'module_tampering': (0, P2['module_tampering']),
    'combo': (P1['prohibit_dynamic_code'] | P1['block_non_microsoft_binaries'] | P1['image_load_no_remote'] |
              P1['strict_handle'] | P1['extension_point_disable'], P2['strict_cfg'] | P2['module_tampering']),
}

k32 = ctypes.WinDLL('kernel32', use_last_error=True)


def exe_path(name: str, arch: str) -> str:
    p = os.path.join(BIN, f'{name}_{arch}.exe')
    if not os.path.exists(p):
        raise FileNotFoundError(f'{p} — compila con tests\\protection_lab\\build.ps1')
    return p


# ---------------- CreateProcess con mitigaciones de arranque ----------------
class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('nLength', wt.DWORD), ('lpSecurityDescriptor', ctypes.c_void_p), ('bInheritHandle', wt.BOOL)]


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [('cb', wt.DWORD), ('lpReserved', wt.LPWSTR), ('lpDesktop', wt.LPWSTR), ('lpTitle', wt.LPWSTR),
                ('dwX', wt.DWORD), ('dwY', wt.DWORD), ('dwXSize', wt.DWORD), ('dwYSize', wt.DWORD),
                ('dwXCountChars', wt.DWORD), ('dwYCountChars', wt.DWORD), ('dwFillAttribute', wt.DWORD),
                ('dwFlags', wt.DWORD), ('wShowWindow', wt.WORD), ('cbReserved2', wt.WORD),
                ('lpReserved2', ctypes.c_void_p), ('hStdInput', wt.HANDLE), ('hStdOutput', wt.HANDLE),
                ('hStdError', wt.HANDLE)]


class _STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [('StartupInfo', _STARTUPINFOW), ('lpAttributeList', ctypes.c_void_p)]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [('hProcess', wt.HANDLE), ('hThread', wt.HANDLE), ('dwProcessId', wt.DWORD),
                ('dwThreadId', wt.DWORD)]


for _fn, _args in (('CreatePipe', [ctypes.POINTER(wt.HANDLE), ctypes.POINTER(wt.HANDLE),
                                   ctypes.POINTER(_SECURITY_ATTRIBUTES), wt.DWORD]),
                   ('SetHandleInformation', [wt.HANDLE, wt.DWORD, wt.DWORD]),
                   ('CloseHandle', [wt.HANDLE]),
                   ('TerminateProcess', [wt.HANDLE, wt.UINT]),
                   ('GetExitCodeProcess', [wt.HANDLE, ctypes.POINTER(wt.DWORD)]),
                   ('InitializeProcThreadAttributeList', [ctypes.c_void_p, wt.DWORD, wt.DWORD,
                                                          ctypes.POINTER(ctypes.c_size_t)]),
                   ('UpdateProcThreadAttribute', [ctypes.c_void_p, wt.DWORD, ctypes.c_size_t, ctypes.c_void_p,
                                                  ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]),
                   ('CreateProcessW', [wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wt.BOOL, wt.DWORD,
                                       ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(_STARTUPINFOEXW),
                                       ctypes.POINTER(_PROCESS_INFORMATION)])):
    getattr(k32, _fn).argtypes = _args


class WinProc:
    """Proceso creado con CreateProcessW; interfaz mínima tipo Popen."""

    def __init__(self, cmdline: str, policy1: int, policy2: int):
        sa = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), None, True)
        out_r, out_w, in_r, in_w = wt.HANDLE(), wt.HANDLE(), wt.HANDLE(), wt.HANDLE()
        k32.CreatePipe(ctypes.byref(out_r), ctypes.byref(out_w), ctypes.byref(sa), 0)
        k32.CreatePipe(ctypes.byref(in_r), ctypes.byref(in_w), ctypes.byref(sa), 0)
        k32.SetHandleInformation(out_r, 1, 0)
        k32.SetHandleInformation(in_w, 1, 0)
        size = ctypes.c_size_t(0)
        k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        self._attr = ctypes.create_string_buffer(size.value)
        k32.InitializeProcThreadAttributeList(self._attr, 1, 0, ctypes.byref(size))
        pol = (ctypes.c_uint64 * 2)(policy1, policy2)
        if not k32.UpdateProcThreadAttribute(self._attr, 0, 0x20007, pol, 16, None, None):
            raise OSError(ctypes.get_last_error(), 'UpdateProcThreadAttribute')
        si = _STARTUPINFOEXW()
        si.StartupInfo.cb = ctypes.sizeof(si)
        si.StartupInfo.dwFlags = 0x100
        si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput = in_r, out_w
        si.StartupInfo.hStdError = out_w
        si.lpAttributeList = ctypes.cast(self._attr, ctypes.c_void_p)
        pi = _PROCESS_INFORMATION()
        ok = k32.CreateProcessW(None, cmdline, None, None, True, 0x00080000 | 0x08000000, None, None,
                                ctypes.byref(si), ctypes.byref(pi))
        err = ctypes.get_last_error()
        k32.CloseHandle(out_w)
        k32.CloseHandle(in_r)
        if not ok:
            k32.CloseHandle(out_r)
            k32.CloseHandle(in_w)
            raise OSError(err, f'CreateProcessW falló (error {err}) con mitigaciones {policy1:#x}/{policy2:#x}')
        self._h = pi.hProcess
        k32.CloseHandle(pi.hThread)
        self.pid = pi.dwProcessId
        self.stdout = os.fdopen(msvcrt.open_osfhandle(out_r.value, os.O_RDONLY), 'r', encoding='utf-8', errors='replace')
        self.stdin = os.fdopen(msvcrt.open_osfhandle(in_w.value, os.O_WRONLY), 'w', encoding='utf-8')

    def poll(self) -> Optional[int]:
        code = wt.DWORD(0)
        k32.GetExitCodeProcess(self._h, ctypes.byref(code))
        return None if code.value == 259 else code.value

    returncode = property(poll)

    def kill(self) -> None:
        if self.poll() is None:
            k32.TerminateProcess(self._h, 1)

    def wait(self, timeout: float = 5.0) -> Optional[int]:
        end = time.time() + timeout
        while time.time() < end and self.poll() is None:
            time.sleep(0.02)
        return self.poll()


class LabProc:
    """Lab en ejecución + hilo lector del protocolo JSON."""

    def __init__(self, name: str, arch: str = 'x64', args=(), mitigation: Optional[Tuple[int, int]] = None,
                 max_seconds: int = 120, ready_timeout: float = 15.0):
        self.name, self.arch = name, arch
        self.args = ['--max-seconds=%d' % max_seconds, *args]
        path = exe_path(name, arch)
        if mitigation:
            self.p = WinProc(subprocess.list2cmdline([path, *self.args]), *mitigation)
        else:
            self.p = subprocess.Popen([path, *self.args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='replace')
        self.pid = self.p.pid
        self.events: List[dict] = []
        self._cv = threading.Condition()
        self.ready: dict = {}
        threading.Thread(target=self._read, daemon=True).start()
        end = time.time() + ready_timeout
        while time.time() < end and not self.ready:
            with self._cv:
                self._cv.wait(0.05)
            if self.p.poll() is not None and not self.ready:
                break
        if not self.ready:
            raise RuntimeError(f'{name}_{arch} no emitió "ready" (código {self.p.poll()})')
        self.regions: Dict[str, int] = self.ready['regions']

    def _read(self):
        try:
            for ln in self.p.stdout:
                try:
                    ev = json.loads(ln)
                except ValueError:
                    continue
                with self._cv:
                    if ev.get('event') == 'ready' and not self.ready:
                        self.ready = ev
                    self.events.append(ev)
                    self._cv.notify_all()
        except (OSError, ValueError):
            pass

    # ---- protocolo ----
    def wait_event(self, pred, timeout: float = 5.0, start: int = 0) -> Optional[dict]:
        end = time.time() + timeout
        with self._cv:
            while True:
                for ev in self.events[start:]:
                    if pred(ev):
                        return ev
                left = end - time.time()
                if left <= 0:
                    return None
                self._cv.wait(min(left, 0.1))

    def _send(self, line: str) -> None:
        self.p.stdin.write(line)
        self.p.stdin.flush()

    def cmd(self, c: str, want: str, timeout: float = 5.0) -> dict:
        with self._cv:
            n = len(self.events)
        self._send(c + '\n')
        ev = self.wait_event(lambda e: e.get('event') == want, timeout, n)
        if ev is None:
            raise TimeoutError(f'{c}: sin respuesta "{want}"')
        return ev

    def status(self) -> dict:
        return self.cmd('status', 'status')

    def prot(self) -> Dict[str, List[int]]:
        return self.cmd('query', 'query')['prot']

    def detects(self) -> List[dict]:
        with self._cv:
            return [e for e in self.events if e.get('event') == 'detect']

    def has(self, event: str) -> bool:
        with self._cv:
            return any(e.get('event') == event for e in self.events)

    def alive(self) -> bool:
        return self.p.poll() is None

    def wait_exit(self, timeout: float = 5.0) -> Optional[int]:
        try:
            return self.p.wait(timeout=timeout)
        except Exception:
            return self.p.poll()

    def close(self) -> None:
        try:
            self.p.kill()
        except Exception:
            pass


def pattern_bytes(n: int = 16 * PAGE) -> bytes:
    """Contenido de la región 'pattern' de los labs: byte i = (i*31+7) & 0xFF."""
    return bytes(((i * 31 + 7) & 0xFF) for i in range(n))


class SpawnedLab(LabProc):
    """Lab lanzado con frida spawn (suspendido): stdout/stdin vía el canal de
    entrada/salida del dispositivo. Se reanuda con resume() tras instrumentar."""

    def __init__(self, name: str, arch: str = 'x64', args=(), max_seconds: int = 120):
        import frida
        self.name, self.arch = name, arch
        self.args = ['--max-seconds=%d' % max_seconds, *args]
        self.events: List[dict] = []
        self._cv = threading.Condition()
        self.ready: dict = {}
        self.regions: Dict[str, int] = {}
        self._buf = ''
        self.dev = frida.get_local_device()
        self.dev.on('output', self._on_output)
        t = time.perf_counter()
        self.pid = self.dev.spawn([exe_path(name, arch), *self.args], stdio='pipe')
        self.t_spawn = time.perf_counter() - t
        self._dead = False

    def _on_output(self, pid, fd, data):
        if pid != self.pid or fd != 1:
            return
        self._buf += data.decode('utf-8', 'replace')
        while '\n' in self._buf:
            ln, self._buf = self._buf.split('\n', 1)
            try:
                ev = json.loads(ln)
            except ValueError:
                continue
            with self._cv:
                if ev.get('event') == 'ready' and not self.ready:
                    self.ready = ev
                    self.regions = ev['regions']
                self.events.append(ev)
                self._cv.notify_all()

    def resume(self, ready_timeout: float = 15.0) -> float:
        t = time.perf_counter()
        self.dev.resume(self.pid)
        end = time.time() + ready_timeout
        while time.time() < end and not self.ready:
            with self._cv:
                self._cv.wait(0.05)
        if not self.ready:
            raise RuntimeError(f'{self.name}_{self.arch} (spawn) no emitió "ready"')
        return time.perf_counter() - t

    def _send(self, line: str) -> None:
        self.dev.input(self.pid, line.encode())

    def alive(self) -> bool:
        from core.antidebug import preflight as pf
        info = pf.inspect_process(self.pid)
        return info.accessible and info.alive

    def wait_exit(self, timeout: float = 5.0) -> Optional[int]:
        end = time.time() + timeout
        while time.time() < end and self.alive():
            time.sleep(0.05)
        from core.antidebug import preflight as pf
        return pf.exit_code_of(self.pid)

    def close(self) -> None:
        try:
            self.dev.kill(self.pid)
        except Exception:
            pass
