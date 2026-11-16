# -*- coding: utf-8 -*-
"""Huella de la instrumentación: qué cambios en el objetivo podría ver un
mecanismo de integridad (y qué ve NetScope de sí mismo).

Compara memoria con el fichero PE en disco (máscara de relocaciones) leyendo
SOLO páginas de código mediante la ruta segura del motor (VirtualQuery,
sin tocar guardas). No usa la tabla de exportación del objetivo: las
direcciones salen del fichero en disco + la base del módulo.
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from . import pe as peparse

ReadFn = Callable[[int, int], Tuple[bytes, Optional[str]]]

# Funciones que enganchan los agentes de NetScope + las que vigilan los labs.
CURATED: Dict[str, List[str]] = {
    'ws2_32.dll': ['send', 'recv', 'connect', 'WSASend', 'WSARecv', 'sendto', 'recvfrom',
                   'socket', 'closesocket', 'WSASendTo', 'WSARecvFrom'],
    'winhttp.dll': ['WinHttpConnect', 'WinHttpOpenRequest', 'WinHttpSendRequest',
                    'WinHttpWriteData', 'WinHttpReadData', 'WinHttpCloseHandle'],
    'wininet.dll': ['InternetConnectA', 'InternetConnectW', 'HttpOpenRequestA', 'HttpOpenRequestW',
                    'HttpSendRequestA', 'HttpSendRequestW', 'InternetReadFile', 'InternetWriteFile'],
    'sspicli.dll': ['EncryptMessage', 'DecryptMessage'],
    'secur32.dll': ['EncryptMessage', 'DecryptMessage'],
    'kernel32.dll': ['LoadLibraryW', 'LoadLibraryA', 'CreateFileW', 'IsDebuggerPresent',
                     'CheckRemoteDebuggerPresent', 'VirtualProtect', 'VirtualAlloc'],
    'kernelbase.dll': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'VirtualProtect',
                       'VirtualAlloc', 'LoadLibraryExW'],
    'ntdll.dll': ['NtQueryInformationProcess', 'NtProtectVirtualMemory', 'NtTerminateProcess',
                  'NtCreateThreadEx', 'NtSetInformationThread', 'LdrLoadDll'],
}


@dataclass
class HookHit:
    module: str
    function: str
    address: int
    first_diff: int
    memory: bytes
    disk: bytes
    trampoline: str

    def describe(self) -> str:
        return (f'{self.module}!{self.function} @ {hex(self.address)}: '
                f'{self.trampoline}; memoria={self.memory[:12].hex()} disco={self.disk[:12].hex()}')


def _resolve(img: 'peparse.PEImage', name: str, depth: int = 0):
    ent = img.exports().get(name)
    if not ent or ent[1]:
        return None            # inexistente o reenviada (la función real vive en otro módulo)
    return ent[0]


def _base(m: dict) -> int:
    b = m['base']
    return int(b, 16) if isinstance(b, str) else int(b)


def disk_path(path: str, wow64: bool) -> str:
    """Un proceso de 32 bits ve System32 redirigido a SysWOW64: el fichero que
    realmente cargó es el de 32 bits."""
    if wow64:
        low = path.lower()
        marker = '\\windows\\system32\\'
        i = low.find(marker)
        if i >= 0:
            return path[:i] + '\\Windows\\SysWOW64\\' + path[i + len(marker):]
    return path


def scan_inline_hooks(read: ReadFn, modules: Iterable[dict], curated: Optional[Dict[str, List[str]]] = None,
                      nbytes: int = 32, wow64: bool = False) -> List[HookHit]:
    """modules: dicts con name, path, base. Devuelve los prólogos que difieren del disco."""
    curated = curated or CURATED
    hits: List[HookHit] = []
    for m in modules:
        base_name = m['name'].lower()
        funcs = curated.get(base_name)
        if not funcs:
            continue
        try:
            img = peparse.load_cached(disk_path(m['path'], wow64))
        except (OSError, ValueError):
            continue
        mask = img.reloc_mask()
        for fn in funcs:
            rva = _resolve(img, fn)
            if rva is None:
                continue
            disk = img.read_rva(rva, nbytes)
            mem, err = read(_base(m) + rva, nbytes)
            if err is not None or len(mem) < nbytes or len(disk) < nbytes:
                continue
            diff = [i for i in range(nbytes) if mem[i] != disk[i] and (rva + i) not in mask]
            if diff:
                hits.append(HookHit(m['name'], fn, _base(m) + rva, diff[0], bytes(mem), bytes(disk),
                                    peparse.classify_trampoline(bytes(mem[diff[0]:]))))
    return hits


@dataclass
class CodeDiff:
    module: str
    bytes_compared: int
    ranges: List[Tuple[int, int]] = field(default_factory=list)       # (rva, longitud)

    @property
    def modified_bytes(self) -> int:
        return sum(n for _, n in self.ranges)


def scan_module_code(read: ReadFn, module: dict, max_bytes: int = 4 << 20, chunk: int = 64 * 1024,
                     wow64: bool = False) -> CodeDiff:
    """Compara las secciones ejecutables de un módulo con el disco."""
    img = peparse.load_cached(disk_path(module['path'], wow64))
    mask = img.reloc_mask()
    out = CodeDiff(module['name'], 0)
    budget = max_bytes
    for sec in img.sections:
        if not sec.executable:
            continue
        size = min(sec.vsize, sec.raw_size, budget)
        pos = 0
        while pos < size:
            n = min(chunk, size - pos)
            mem, err = read(_base(module) + sec.rva + pos, n)
            if err is not None or len(mem) < n:
                pos += n
                continue
            disk = img.read_rva(sec.rva + pos, n)
            if mem != disk:
                run_start = None
                for i in range(n):
                    differs = mem[i] != disk[i] and (sec.rva + pos + i) not in mask
                    if differs and run_start is None:
                        run_start = i
                    elif not differs and run_start is not None:
                        out.ranges.append((sec.rva + pos + run_start, i - run_start))
                        run_start = None
                if run_start is not None:
                    out.ranges.append((sec.rva + pos + run_start, n - run_start))
            out.bytes_compared += n
            pos += n
        budget -= size
        if budget <= 0:
            break
    # unir tramos cercanos (un parche suele ocupar 5-14 bytes con huecos)
    merged: List[Tuple[int, int]] = []
    for rva, n in sorted(out.ranges):
        if merged and rva - (merged[-1][0] + merged[-1][1]) <= 16:
            s, ln = merged[-1]
            merged[-1] = (s, rva + n - s)
        else:
            merged.append((rva, n))
    out.ranges = merged
    return out
