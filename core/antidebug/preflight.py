# -*- coding: utf-8 -*-
"""Preflight no invasivo del objetivo con APIs nativas de Windows (ctypes).

Nada de esto inyecta ni modifica el proceso: solo consulta (OpenProcess con
derechos de consulta, NtQueryInformationProcess, VirtualQueryEx, lectura de
cabeceras PE con ReadProcessMemory). Sirve para explicar un fallo de attach
ANTES de achacarlo a nada y para detectar guardas sobre las tablas de
exportación (EAF) que hacen que la inyección de Frida se cuelgue.

Requiere un Python de 64 bits (los objetivos x86 se leen igualmente).
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PAGE_GUARD = 0x100
LIST_MODULES_ALL = 3
TOKEN_QUERY = 0x0008

_k32 = ctypes.WinDLL('kernel32', use_last_error=True)
_psapi = ctypes.WinDLL('psapi', use_last_error=True)
_adv = ctypes.WinDLL('advapi32', use_last_error=True)
_nt = ctypes.WinDLL('ntdll')

_k32.OpenProcess.restype = wt.HANDLE
_k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.CloseHandle.argtypes = [wt.HANDLE]
_k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.POINTER(ctypes.c_size_t)]
_k32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
_k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
_k32.IsWow64Process.argtypes = [wt.HANDLE, ctypes.POINTER(wt.BOOL)]
_psapi.EnumProcessModulesEx.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_void_p), wt.DWORD,
                                        ctypes.POINTER(wt.DWORD), wt.DWORD]
_psapi.GetModuleFileNameExW.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.LPWSTR, wt.DWORD]
_adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
_adv.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD,
                                     ctypes.POINTER(wt.DWORD)]


class _MBI(ctypes.Structure):
    _fields_ = [('Base', ctypes.c_void_p), ('AllocBase', ctypes.c_void_p), ('AllocProt', wt.DWORD),
                ('Part', wt.WORD), ('Region', ctypes.c_size_t), ('State', wt.DWORD),
                ('Protect', wt.DWORD), ('Type', wt.DWORD)]


_k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(_MBI), ctypes.c_size_t]

EAF_MODULES = ('ntdll.dll', 'kernel32.dll', 'kernelbase.dll')


@dataclass
class ProcessInfo:
    pid: int
    accessible: bool = False
    open_error: int = 0
    image_path: str = ''
    protection: Optional[str] = None      # None | 'PPL' | 'PP'
    elevated: Optional[bool] = None
    integrity_rid: Optional[int] = None
    wow64: Optional[bool] = None
    exit_code: Optional[int] = None       # STILL_ACTIVE=259 si sigue vivo

    @property
    def integrity(self) -> str:
        return {0x1000: 'low', 0x2000: 'medium', 0x3000: 'high', 0x4000: 'system'}.get(
            self.integrity_rid or 0, 'desconocida')

    @property
    def alive(self) -> bool:
        return self.exit_code in (None, 259)


def inspect_process(pid: int) -> ProcessInfo:
    info = ProcessInfo(pid=pid)
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        info.open_error = ctypes.get_last_error()
        return info
    try:
        info.accessible = True
        buf = ctypes.create_unicode_buffer(1024)
        n = wt.DWORD(1024)
        if _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
            info.image_path = buf.value
        prot = ctypes.c_ubyte(0)
        if _nt.NtQueryInformationProcess(h, 61, ctypes.byref(prot), 1, None) == 0:
            t = prot.value & 7
            info.protection = {1: 'PPL', 2: 'PP'}.get(t)
        w = wt.BOOL(0)
        if _k32.IsWow64Process(h, ctypes.byref(w)):
            info.wow64 = bool(w.value)
        code = wt.DWORD(0)
        if _k32.GetExitCodeProcess(h, ctypes.byref(code)):
            info.exit_code = code.value
        tok = wt.HANDLE()
        if _adv.OpenProcessToken(h, TOKEN_QUERY, ctypes.byref(tok)):
            el = wt.DWORD(0)
            n2 = wt.DWORD(0)
            if _adv.GetTokenInformation(tok, 20, ctypes.byref(el), 4, ctypes.byref(n2)):
                info.elevated = bool(el.value)
            size = wt.DWORD(0)
            _adv.GetTokenInformation(tok, 25, None, 0, ctypes.byref(size))
            if size.value:
                raw = ctypes.create_string_buffer(size.value)
                if _adv.GetTokenInformation(tok, 25, raw, size.value, ctypes.byref(size)):
                    psid = ctypes.c_void_p.from_buffer(raw).value
                    cnt = ctypes.cast(_adv.GetSidSubAuthorityCount(ctypes.c_void_p(psid)),
                                      ctypes.POINTER(ctypes.c_ubyte)).contents.value
                    rid = ctypes.cast(_adv.GetSidSubAuthority(ctypes.c_void_p(psid), cnt - 1),
                                      ctypes.POINTER(wt.DWORD)).contents.value
                    info.integrity_rid = rid & 0xF000
            _k32.CloseHandle(tok)
    finally:
        _k32.CloseHandle(h)
    return info


_adv.GetSidSubAuthorityCount.restype = ctypes.c_void_p
_adv.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
_adv.GetSidSubAuthority.restype = ctypes.c_void_p
_adv.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wt.DWORD]


def exit_code_of(pid: int) -> Optional[int]:
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        code = wt.DWORD(0)
        return code.value if _k32.GetExitCodeProcess(h, ctypes.byref(code)) else None
    finally:
        _k32.CloseHandle(h)


@dataclass
class ModuleGuard:
    module: str
    base: int
    eat_rva: int
    eat_size: int
    pages: int
    guarded_pages: int
    protects: List[int] = field(default_factory=list)

    @property
    def armed(self) -> bool:
        return self.guarded_pages > 0


def _read(h, addr: int, n: int) -> Optional[bytes]:
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    ok = _k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got))
    return buf.raw[:got.value] if ok and got.value == n else None


def scan_export_guards(pid: int, modules=EAF_MODULES) -> List[ModuleGuard]:
    """¿Tienen PAGE_GUARD las páginas de la tabla de exportación (EAT)? Solo
    consulta: VirtualQueryEx + lectura de las cabeceras PE (que no están
    protegidas). Si hay guardas armadas, ReadProcessMemory sobre la EAT FALLA
    (ERROR_PARTIAL_COPY) y la inyección de Frida no puede resolver
    exportaciones: el attach se cuelga."""
    h = _k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return []
    out: List[ModuleGuard] = []
    try:
        arr = (ctypes.c_void_p * 2048)()
        need = wt.DWORD(0)
        if not _psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(need), LIST_MODULES_ALL):
            return []
        wanted = {m.lower() for m in modules}
        for i in range(min(need.value // ctypes.sizeof(ctypes.c_void_p), 2048)):
            base = arr[i]
            nm = ctypes.create_unicode_buffer(512)
            if not _psapi.GetModuleFileNameExW(h, base, nm, 512):
                continue
            if os.path.basename(nm.value).lower() not in wanted:
                continue
            hdr = _read(h, base, 0x400)
            if not hdr or hdr[:2] != b'MZ':
                continue
            pe = struct.unpack_from('<I', hdr, 0x3C)[0]
            if pe + 0x90 > len(hdr):
                continue
            magic, = struct.unpack_from('<H', hdr, pe + 24)
            dd = pe + 24 + (112 if magic == 0x20B else 96)
            rva, size = struct.unpack_from('<II', hdr, dd)
            if not rva:
                continue
            first = (base + rva) & ~0xFFF
            last = base + rva + size
            protects, guarded = [], 0
            addr = first
            while addr < last:
                m = _MBI()
                if _k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m)):
                    protects.append(m.Protect)
                    guarded += 1 if m.Protect & PAGE_GUARD else 0
                addr += 0x1000
            out.append(ModuleGuard(os.path.basename(nm.value), base, rva, size,
                                   len(protects), guarded, protects[:6]))
    finally:
        _k32.CloseHandle(h)
    return out


# ---------------- configuración de Windows (PowerShell, solo lectura) ----------------
_PS_MIT = (
    "$m = {call}; [pscustomobject]@{{"
    "dyncode=[string]$m.DynamicCode.BlockDynamicCode; "
    "signature_ms_only=[string]$m.BinarySignature.MicrosoftSignedOnly; "
    "cfg=[string]$m.Cfg.Enable; cfg_strict=[string]$m.Cfg.StrictControlFlowGuard; "
    "image_remote=[string]$m.ImageLoad.BlockRemoteImageLoads; "
    "extpoint=[string]$m.ExtensionPoint.DisableExtensionPoints; "
    "child=[string]$m.ChildProcess.DisallowChildProcessCreation; "
    "user_shadow_stack=[string]$m.UserShadowStack.UserShadowStack; "
    "eaf=[string]$m.Payload.EnableExportAddressFilter; "
    "eaf_plus=[string]$m.Payload.EnableExportAddressFilterPlus; "
    "iaf=[string]$m.Payload.EnableImportAddressFilter; "
    "rop_caller=[string]$m.Payload.EnableRopCallerCheck"
    "}} | ConvertTo-Json -Compress")


def _ps_json(call: str, timeout: float) -> Optional[Dict[str, str]]:
    try:
        out = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                              _PS_MIT.format(call=call)],
                             capture_output=True, text=True, timeout=timeout)
        return json.loads(out.stdout.strip().splitlines()[-1]) if out.stdout.strip() else None
    except Exception:
        return None


def mitigations_of_process(pid: int, timeout: float = 20.0) -> Optional[Dict[str, str]]:
    """Mitigaciones EN VIGOR del proceso (Get-ProcessMitigation -Id): ON/OFF/NOTSET."""
    return _ps_json(f'Get-ProcessMitigation -Id {int(pid)}', timeout)


def mitigations_of_image(image_name: str, timeout: float = 20.0) -> Optional[Dict[str, str]]:
    """Configuración PERSISTENTE (IFEO / Exploit Protection) para una imagen; aquí
    es donde aparece EAF configurado. Solo lectura: no requiere elevación."""
    safe = image_name.replace("'", "''")
    return _ps_json(f"Get-ProcessMitigation -Name '{safe}'", timeout)


# ---------------- huella visible de Frida (lo que un objetivo podría ver) ----------------
_k32.OpenThread.restype = wt.HANDLE
_k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]


class _THREADENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('cntUsage', wt.DWORD), ('th32ThreadID', wt.DWORD),
                ('th32OwnerProcessID', wt.DWORD), ('tpBasePri', wt.LONG), ('tpDeltaPri', wt.LONG),
                ('dwFlags', wt.DWORD)]


FRIDA_THREAD_NAMES = ('gmain', 'gdbus', 'gum-js-loop', 'pool-frida', 'pool-spawner')


def thread_names(pid: int) -> List[str]:
    """Nombres (descripción) de los hilos del proceso vía GetThreadDescription."""
    try:
        gtd = _k32.GetThreadDescription
    except AttributeError:
        return []
    gtd.argtypes = [wt.HANDLE, ctypes.POINTER(wt.LPWSTR)]
    gtd.restype = ctypes.c_long
    snap = _k32.CreateToolhelp32Snapshot(0x4, 0)
    if snap in (None, -1, 0xFFFFFFFFFFFFFFFF):
        return []
    names: List[str] = []
    try:
        te = _THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        ok = _k32.Thread32First(wt.HANDLE(snap), ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID == pid:
                th = _k32.OpenThread(0x0800, False, te.th32ThreadID)   # THREAD_QUERY_LIMITED_INFORMATION
                if th:
                    p = wt.LPWSTR()
                    if gtd(th, ctypes.byref(p)) >= 0 and p.value:
                        names.append(p.value)
                        _k32.LocalFree(p)
                    _k32.CloseHandle(th)
            ok = _k32.Thread32Next(wt.HANDLE(snap), ctypes.byref(te))
    finally:
        _k32.CloseHandle(wt.HANDLE(snap))
    return names


_k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
_k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
_k32.Thread32First.argtypes = [wt.HANDLE, ctypes.POINTER(_THREADENTRY32)]
_k32.Thread32Next.argtypes = [wt.HANDLE, ctypes.POINTER(_THREADENTRY32)]
_k32.LocalFree.argtypes = [ctypes.c_void_p]


def frida_pipes() -> List[str]:
    """Tuberías con nombre 'frida-*' visibles en el sistema."""
    try:
        return [n for n in os.listdir('\\\\.\\pipe\\') if 'frida' in n.lower()]
    except OSError:
        return []


def frida_thread_footprint(pid: int) -> List[str]:
    return sorted({n for n in thread_names(pid) if n.lower() in FRIDA_THREAD_NAMES})
