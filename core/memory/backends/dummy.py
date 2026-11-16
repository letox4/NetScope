# -*- coding: utf-8 -*-
"""Contrato de backends de memoria + DummyBackend de laboratorio.

El ABC define la superficie que el MemoryEngine (y la GUI) pueden usar.
Cada backend declara sus capacidades INDIVIDUALES; nada se asume.
DummyBackend permite testear el motor genérico en procesos puro-Python
sin dependencia de Frida ni del SO.
"""
import time
from typing import Callable, Dict, List, Optional, Tuple

from ..models import (BackendCapabilities, MemoryError, ModuleIdentity,
                      ReadDetail, Region, SCALAR_KINDS, SCALAR_SIZES,
                      CapabilityError)


class MemoryBackend:
    """Contrato genérico de acceso a memoria (instalación/región/leer/escribir)."""
    capabilities: BackendCapabilities = BackendCapabilities()
    pointer_size: int = 8          # 4 (ia32) u 8 (x64); los backends reales lo fijan
    session_id: str = ''           # identifica proceso+sesión (staleness de snapshots)

    def invalidate(self, reason: str = '') -> None:
        """La sesión subyacente terminó: el backend debe rechazar todo uso."""

    def read_detail(self, addr: int, size: int) -> ReadDetail:
        """Lectura con detalle de huecos. Por defecto deriva de read(): se
        asume que `data` contiene solo bytes realmente leídos."""
        data, err = self.read(addr, size)
        holes = [] if err is None else [(len(data), max(size - len(data), 0), err)]
        return ReadDetail(data=data, error=err, valid=len(data), holes=holes)

    def regions(self) -> List[Region]:
        raise NotImplementedError

    def read(self, addr: int, size: int) -> Tuple[bytes, Optional[str]]:
        """Devuelve (datos, error). En lectura parcial: datos con lo obtenido
        y error NO None. Cero bytes + error también es válido."""
        raise NotImplementedError

    def read_scalar(self, addr: int, kind: str) -> object:
        """Implementación por defecto sobre read(); los backends pueden
        optimizarla. Solo para kinds declarados en capabilities.read_scalars."""
        if kind not in SCALAR_KINDS:
            raise MemoryError('E_BAD_KIND', f'kind inválido: {kind}')
        if kind == 'cstr':
            out = bytearray()
            step = 1
            for i in range(256):
                data, err = self.read(addr + i, step)
                if err is not None:
                    raise MemoryError('E_READ', err)
                if not data:
                    break
                if data[0] == 0:
                    break
                out += data
            return bytes(out)
        if kind == 'utf8':
            data, err = self.read(addr, 256)
            if err is not None and not data:
                raise MemoryError('E_READ', err)
            return data.decode('utf-8', 'replace')
        n = self.pointer_size if kind == 'ptr' else SCALAR_SIZES.get(kind, 0)
        if not n:
            raise MemoryError('E_BAD_KIND', kind)
        data, err = self.read(addr, n)
        if len(data) < n:
            raise MemoryError('E_PARTIAL_READ', err or 'lectura corta')
        import struct
        fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}[n]
        return struct.unpack(fmt, data)[0]

    def write(self, addr: int, data: bytes) -> None:
        """Escribe data en addr. Debe lanzar MemoryError('E_*') si no puede.
        El ENGINE valida permisos y guarda old_bytes; el backend solo ejecuta."""
        raise NotImplementedError

    def alloc(self, size: int) -> Region:
        raise NotImplementedError

    def free(self, addr: int) -> None:
        raise NotImplementedError


class DummyBackend(MemoryBackend):
    """Backend de laboratorio configurable para tests del engine.

    Uso:
        b = DummyBackend()
        b.add_region(0x1000, 32, 'rw', data=b'...', owner=ModuleIdentity('mod.exe', 0x40000, 0x10000))

    Modos de fallo inyectables (scriptables):
        - b.read_fail_from[addr] = off  → lecturas a partir del offset off de esa
          región fallan (simula PAGE_GUARD / página inaccesible).
        - b.write_partial_n[addr] = n   → simulate escritura parcial de n bytes y
          excepción posterior (simula WriteProcessMemory truncado).
        - b.write_fail[addr] = 'E_X'    → la escritura en esa región falla siempre.
    """

    def __init__(self, capabilities: Optional[BackendCapabilities] = None):
        super().__init__()
        self.capabilities = capabilities or BackendCapabilities(
            enumerate=True, read=True,
            read_scalars=frozenset(SCALAR_KINDS),
            write_rw=True, write_rwx=True,
            alloc=True, free=True, watch=True)
        self._regions: List[Region] = []
        self._mem: Dict[int, bytearray] = {}
        self.read_fail_from: Dict[int, int] = {}   # region.addr → offset desde que falla
        self.write_fail: Dict[int, str] = {}       # region.addr → reason
        self.write_partial_n: Dict[int, int] = {}  # region.addr → nbytes aplicados
        self._alloc_cursor = 0x7000_0000

    # ---------- construcción de memoria de laboratorio ----------
    def add_region(self, addr: int, size: int, prot: str,
                   data: bytes = b'', owner: Optional[ModuleIdentity] = None,
                   state: str = 'committed', type_: str = 'private') -> Region:
        prot = prot  # se mantiene tal cual (ya canónico)
        r = Region(addr=addr, size=size, protections=prot,
                   state=state, type=type_, owner=owner)
        self._regions.append(r)
        self._mem[addr] = bytearray(data.ljust(size, b'\x00') if size >= len(data) else data[:size])
        return r

    # ---------- MemoryBackend ----------
    def regions(self) -> List[Region]:
        return list(self._regions)

    def _find(self, addr: int) -> Optional[Region]:
        for r in self._regions:
            if r.contains(addr):
                return r
        return None

    def read(self, addr: int, size: int) -> Tuple[bytes, Optional[str]]:
        if addr < 0 or size < 0:
            return b'', 'E_BAD_ARGS'
        r = self._find(addr)
        if r is None:
            return b'', 'E_NO_MAP'
        off = addr - r.addr
        lim = min(size, r.size - off)
        fail_from = self.read_fail_from.get(r.addr)
        hit_guard = False
        if fail_from is not None:
            # trunca en la frontera de fallo (como una página guard real)
            if off >= fail_from:
                return b'', 'E_PAGE_GUARD'
            if off + lim > fail_from:
                lim = fail_from - off
                hit_guard = True
        data = bytes(self._mem[r.addr][off:off + lim])
        if hit_guard:
            return data, 'E_PAGE_GUARD'
        if lim < size:
            return data, 'E_END_OF_REGION'
        return data, None

    def write(self, addr: int, data: bytes) -> None:
        r = self._find(addr)
        if r is None:
            raise MemoryError('E_NO_MAP')
        if r.addr in self.write_fail:
            raise MemoryError(self.write_fail[r.addr])
        if 'w' not in r.protections:
            raise MemoryError('E_ACCESS_DENIED', 'región no escribible')
        off = addr - r.addr
        avail = r.size - off
        if len(data) > avail:
            raise MemoryError('E_END_OF_REGION')
        pn = self.write_partial_n.get(r.addr)
        if pn is not None:
            self._mem[r.addr][off:off + pn] = data[:pn]
            raise MemoryError('E_PARTIAL', f'escritura parcial ({pn}/{len(data)})')
        self._mem[r.addr][off:off + len(data)] = data

    def alloc(self, size: int) -> Region:
        addr = self._alloc_cursor
        self._alloc_cursor += (size + 0xFFF) & ~0xFFF
        r = self.add_region(addr, size, 'rw', type_='scratch')
        return r

    def free(self, addr: int) -> None:
        self._regions = [r for r in self._regions if r.addr != addr]
        self._mem.pop(addr, None)
