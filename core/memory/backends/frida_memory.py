# -*- coding: utf-8 -*-
"""FridaMemoryBackend â€” adaptador del MemoryEngine hacia la sesiÃ³n Frida
EXISTENTE (script memory.js cargado en la misma sesiÃ³n; nunca un attach doble).

Contrato sobre el MemoryBackend ABC. Capacidades declaradas segÃºn lo que el
agente implementa de verdad; limitaciones documentadas en LIMITATIONS.
"""
import dataclasses
import threading
import time
from typing import List, Optional, Tuple

try:
    import frida
except ImportError:          # el backend sin Frida instalado solo falla al usarse
    frida = None

from ..models import (BackendCapabilities, CapabilityError, MemoryError,
                      ModuleIdentity, ReadDetail, Region, SCALAR_KINDS,
                      SessionError)
from .dummy import MemoryBackend

LIMITATIONS = {
    'write_protected': 'No se escriben regiones sin permiso W '
                       '(requerirÃ­a VirtualProtectEx explÃ­cito; v1 no lo hace).',
    'free': 'Solo se libera memoria asignada por el propio backend '
            '(registro de allocaciones propio).',
    'watch': 'MonitorizaciÃ³n por polling (MemoryWatcher); sin watchpoints HW.',
    'kernel': 'No hay acceso a memoria kernel.',
}


class FridaMemoryBackend(MemoryBackend):
    """script: Script de Frida que ya cargÃ³ agent/memory.js (misma sesiÃ³n)."""

    capabilities = BackendCapabilities(
        enumerate=True,
        read=True,
        read_scalars=frozenset(SCALAR_KINDS),
        write_rw=True,          # solo regiones ya escribibles (con permiso W)
        write_rwx=True,         # RWX: tiene W igualmente
        alloc=True,
        free=True,              # SOLO allocaciones propias (LIMITATIONS['free'])
        watch=True,             # vÃ­a MemoryWatcher (polling)
    )

    def __init__(self, script, read_only: bool = True):
        self.script = script
        self.read_only = bool(read_only)
        self.exports = script.exports_sync
        self._lock = threading.RLock()
        self._mod_cache: Optional[List[dict]] = None
        self._mod_cache_ts = 0.0
        self._allocs: set = set()
        self._alloc_size: dict = {}
        self._invalid_reason: Optional[str] = None
        ret = self._rpc('process_info')
        if not isinstance(ret, dict) or not ret.get('ok'):
            raise MemoryError('E_AGENT_BROKEN', 'processInfo falló')
        self.arch = ret.get('arch', '?')
        self.pointer_size = int(ret.get('pointerSize', 8))
        self.is64 = self.pointer_size == 8
        self.pid = int(ret.get('pid', 0))
        self.safe_read = bool(ret.get('safeRead', False))
        self.session_id = f'{self.pid}:{int(time.time() * 1000)}'
        self.capabilities = self._probe_capabilities()

    # ---------- sesión ----------
    def invalidate(self, reason: str = '') -> None:
        """Marca la sesión como perdida: cualquier uso posterior lanza
        SessionError sin tocar Frida."""
        if self._invalid_reason is None:
            self._invalid_reason = reason or 'E_SESSION_LOST'

    def _rpc(self, name: str, *args):
        """ÚNICO punto de llamada al agente. Traduce los errores de Frida
        (script destruido, transporte caído, proceso muerto) a SessionError y
        el resto de fallos de transporte a MemoryError de dominio."""
        if self._invalid_reason is not None:
            raise SessionError('E_SESSION_LOST', detail=self._invalid_reason)
        if getattr(self.script, 'is_destroyed', False):
            self.invalidate('script-destroyed')
            raise SessionError('E_SESSION_LOST', detail='script-destroyed')
        try:
            return getattr(self.exports, name)(*args)
        except Exception as e:
            if frida is not None and isinstance(e, (
                    frida.InvalidOperationError, frida.TransportError,
                    frida.ServerNotRunningError, frida.ProcessNotFoundError)):
                self.invalidate(str(e))
                raise SessionError('E_SESSION_LOST', detail=str(e)) from e
            if isinstance(e, MemoryError):
                raise
            raise MemoryError('E_BACKEND', f'{type(e).__name__}: {e}') from e

    def _probe_capabilities(self) -> BackendCapabilities:
        """Prueba real en el proceso destino; lo que falla se declara como no
        soportado. En modo read_only=True (por defecto en v1) no reserva ni
        escribe memoria y declara capacidades de solo lectura."""
        declared = type(self).capabilities
        can = {'enumerate': False, 'read': False, 'write_rw': False,
               'alloc': False, 'free': False}
        ranges_ret = None
        try:
            ranges_ret = self._rpc('list_ranges', 'r')
            can['enumerate'] = bool(ranges_ret.get('ok'))
        except SessionError:
            raise
        except Exception:
            pass

        if self.read_only:
            try:
                candidates = []
                if isinstance(ranges_ret, dict):
                    for reg in ranges_ret.get('regions', ())[:16]:
                        candidates.append(self._int(reg['addr']))
                if not candidates:
                    for mod in self._modules()[:4]:
                        candidates.append(self._int(mod['base']))
                for caddr in candidates:
                    _, err = self.read(caddr, 4)
                    if self.safe_read and err is None:
                        can['read'] = True
                        break
                    if self.safe_read and err not in ('E_UNSAFE_READ',):
                        can['read'] = True
            except SessionError:
                raise
            except Exception:
                pass
            return dataclasses.replace(
                declared,
                enumerate=declared.enumerate and can['enumerate'],
                read=declared.read and can['read'],
                read_scalars=declared.read_scalars if can['read'] else frozenset(),
                write_rw=False,
                write_rwx=False,
                alloc=False,
                free=False,
                watch=declared.watch and can['read'],
            )

        probe = b'\xA5\x5A\xC3\x3C'
        addr = None
        try:
            addr = self._int(self._call(self._rpc('alloc', 16))['addr'])
            can['alloc'] = True
            hexb = probe.hex()
            can['write_rw'] = bool(self._rpc('write_range', hex(addr), hexb).get('ok'))
            data, err = self.read(addr, len(probe))
            can['read'] = (self.safe_read and err is None
                           and (data == probe or not can['write_rw']))
            can['free'] = bool(self._rpc('free', hex(addr)).get('ok'))
        except SessionError:
            raise
        except Exception:
            pass
        return dataclasses.replace(
            declared,
            enumerate=declared.enumerate and can['enumerate'],
            read=declared.read and can['read'],
            read_scalars=declared.read_scalars if can['read'] else frozenset(),
            write_rw=declared.write_rw and can['write_rw'],
            write_rwx=declared.write_rwx and can['write_rw'],
            alloc=declared.alloc and can['alloc'],
            free=declared.free and can['free'],
            watch=declared.watch and can['read'],
        )

    # ---------- infraestructura ----------
    @staticmethod
    def _call(ret) -> dict:
        """Normaliza retorno RPC: dict con ok/error; lanza MemoryError."""
        if not isinstance(ret, dict):
            raise MemoryError('E_AGENT_BROKEN', f'respuesta invÃ¡lida: {ret!r}')
        if not ret.get('ok', False):
            raise MemoryError(str(ret.get('error') or 'E_AGENT'),
                              str(ret.get('detail', '')))
        return ret

    def _modules(self) -> List[dict]:
        """Lista de módulos con caché corta (2 s): un módulo cargado o
        descargado después no puede dejar owners obsoletos indefinidamente."""
        with self._lock:
            now = time.time()
            if self._mod_cache is None or now - self._mod_cache_ts > 2.0:
                self._mod_cache = self._call(self._rpc('list_modules'))['modules']
                self._mod_cache_ts = now
            return self._mod_cache

    @staticmethod
    def _int(v) -> int:
        return int(v, 16) if isinstance(v, str) else int(v)

    # ---------- MemoryBackend ABC ----------
    def regions(self) -> List[Region]:
        with self._lock:
            ret = self._call(self._rpc('list_ranges', 'r'))
            mods = [(m['name'], self._int(m['base']), int(m['size']))
                    for m in self._modules()]
            regs = []
            for r in ret['regions']:
                addr = self._int(r['addr'])
                size = int(r['size'])
                owner = None
                for (name, base, msize) in mods:
                    if base <= addr < base + msize:
                        owner = ModuleIdentity(name, base, msize)
                        break
                regs.append(Region(addr=addr, size=size,
                                   protections=r.get('prot', ''),
                                   state='committed', type='unknown',
                                   owner=owner))
            return regs

    def read_detail(self, addr: int, size: int, deadline_ms: Optional[int] = None
                    ) -> ReadDetail:
        """Lectura con huecos exactos. Los huecos se rellenan con ceros en
        `data` (longitud = size); `valid` es el prefijo realmente leído."""
        with self._lock:
            args = (hex(addr), int(size))
            if deadline_ms is not None:
                args += (int(deadline_ms),)
            ret = self._rpc('read_range', *args)
            if not isinstance(ret, dict) or not ret.get('ok'):
                err = ret.get('error', 'E_AGENT') if isinstance(ret, dict) else 'E_AGENT'
                return ReadDetail(data=b'', error=err, valid=0,
                                  holes=[(0, int(size), err)])
            data = bytes.fromhex(ret.get('hex', '') or '')
            holes = [tuple(h) for h in ret.get('holes') or []]
            valid = int(ret.get('valid', len(data)))
            err = ret.get('error')
            if err is None and len(data) < size:
                err = f'E_SHORT_READ({len(data)}/{size})'
                valid = len(data)
            return ReadDetail(data=data, error=err, valid=valid, holes=holes)

    def read(self, addr: int, size: int) -> Tuple[bytes, Optional[str]]:
        rd = self.read_detail(addr, size)
        return rd.data, rd.error

    def region_for(self, addr: int):
        """Región contenedora. Las allocaciones propias (rwx protegidas, no
        siempre visibles a enumerateRanges) se devuelven directamente."""
        with self._lock:
            for a in self._allocs:
                size = self._alloc_size.get(a, 0)
                if a <= addr < a + max(size, 1):
                    return Region(addr=a, size=size,
                                  protections='rw', state='committed',
                                  type='scratch', owner=None)
        return None

    def write(self, addr: int, data: bytes) -> None:
        if self.read_only:
            raise CapabilityError('write_rw')
        with self._lock:
            hexb = bytes(data).hex()
            self._call(self._rpc('write_range', hex(addr), hexb))

    def alloc(self, size: int) -> Region:
        if self.read_only:
            raise CapabilityError('alloc')
        with self._lock:
            ret = self._call(self._rpc('alloc', int(size)))
            addr = self._int(ret['addr'])
            self._allocs.add(addr)
            self._alloc_size[addr] = int(size)
            return Region(addr=addr, size=int(size), protections='rw',
                          state='committed', type='scratch', owner=None)

    def free(self, addr: int) -> None:
        if self.read_only:
            raise CapabilityError('free')
        with self._lock:
            if addr not in self._allocs:
                raise MemoryError('E_NOT_OWNED',
                                  'solo se libera memoria asignada por el backend')
            self._call(self._rpc('free', hex(addr)))
            self._allocs.discard(addr)
            self._alloc_size.pop(addr, None)

