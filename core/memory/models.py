# -*- coding: utf-8 -*-
"""Modelos genéricos del subsistema de memoria (independientes de Frida).

Puntos de diseño exigidos en la revisión:
- Permisos R/W/X independientes (nunca 'rwx' como sinónimo de 'writable').
- Identidad de región estable ante ASLR: módulo dueño + offset relativo,
  además de la dirección virtual absoluta.
- Metadatos de región completos en snapshots y diffs.
"""
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple


def parse_protections(protections: str) -> str:
    """Normaliza una cadena de protecciones a 'r','w','x' (o vacío).

    Acepta 'rwx', 'r--', '--w', 'rx', etc. Señales no reconocidas se
    ignoran; si la cadena está vacía devuelve '' (sin acceso).
    """
    out = []
    for c in 'rwx':
        if c in protections.lower():
            out.append(c)
    return ''.join(out)


@dataclass(frozen=True)
class ModuleIdentity:
    """Módulo dueño de una región. Su base durante una captura específica
    puede cambiar con ASLR: la identidad del módulo es su nombre, y el
    offset relativo es lo estable entre snapshots."""
    name: str
    base_addr: int
    size: int


@dataclass
class Region:
    """Región de memoria virtual con permisos R/W/X separados."""
    addr: int
    size: int
    protections: str          # canónico: subcadena ordenada de 'rwx' (ej. 'rx')
    state: str = 'committed'   # 'committed' | 'reserved' | 'free'
    type: str = 'private'      # 'private' | 'image' | 'mapped' | 'scratch'
    owner: Optional[ModuleIdentity] = None

    @property
    def r(self) -> bool:
        return 'r' in self.protections

    @property
    def w(self) -> bool:
        return 'w' in self.protections

    @property
    def x(self) -> bool:
        return 'x' in self.protections

    @property
    def end(self) -> int:
        return self.addr + self.size

    @property
    def rel_offset(self) -> Optional[int]:
        if self.owner is not None:
            return self.addr - self.owner.base_addr
        return None

    def contains(self, addr: int) -> bool:
        return self.addr <= addr < self.end

    def identity(self) -> tuple:
        """Clave estable para snapshots/diffs:
        - Si la región pertenece a un módulo: (module, offset relativo, addr).
        - Si es anónima: ('__anonymous__', addr, addr).
        """
        if self.owner is not None:
            return (self.owner.name, self.rel_offset, self.addr)
        return ('__anonymous__', self.addr, self.addr)

    def metadata(self) -> dict:
        """Metadatos completos para snapshots y diffs."""
        return {
            'addr': self.addr,
            'size': self.size,
            'protections': self.protections,
            'r': self.r, 'w': self.w, 'x': self.x,
            'state': self.state,
            'type': self.type,
            'module': self.owner.name if self.owner else None,
            'module_base': self.owner.base_addr if self.owner else None,
            'rel_offset': self.rel_offset,
        }


@dataclass
class RegionRead:
    """Resultado de leer una región (toma parcial tolerante a fallos)."""
    region: Region
    data: bytes = b''
    error: Optional[str] = None       # primer error encontrado (lectura parcial)
    truncated: bool = False           # no se leyó la región completa por budget/limit
    read_len: int = 0
    note: str = ''                    # ej. 'E_BUDGET' cuando se recorta por presupuesto

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class ReadDetail:
    """Lectura con detalle de huecos. `data` siempre tiene la longitud pedida
    si el backend rellena con ceros; `valid` es el prefijo contiguo realmente
    leído y `holes` lista (offset, longitud, motivo) de cada tramo no leído."""
    data: bytes = b''
    error: Optional[str] = None
    valid: int = 0
    holes: list = field(default_factory=list)


@dataclass
class MemorySnapshot:
    """Captura presupuestada de regiones (NO del proceso entero)."""
    ts: float
    label: str
    entries: list = field(default_factory=list)   # list[RegionRead]
    session_id: str = ''      # sesión/proceso de origen (evita diffs entre procesos)

    def by_identity(self) -> dict:
        return {e.region.identity(): e for e in self.entries}

    def get(self, addr: int) -> Optional[RegionRead]:
        for e in self.entries:
            if e.region.contains(addr):
                return e
        return None


@dataclass
class DiffEntry:
    """Diferencia entre dos snapshots. Incluye identidad ASLR-estable."""
    kind: str                 # 'added' | 'removed' | 'modified' | 'unchanged'
    identity: tuple           # Region.identity()
    metadata: dict
    old_data: Optional[bytes]
    new_data: Optional[bytes]


@dataclass
class WriteRecord:
    """Registro auditable de una operación de escritura."""
    ts: float
    addr: int
    length: int
    old_bytes: bytes
    new_bytes: bytes
    note: str = ''
    applied: bool = False
    partial: bool = False
    rolled_back: bool = False
    reason: str = ''          # '', 'E_PRE_READ_FAILED', 'E_NO_CHANGE', ...
    previous: Optional['WriteRecord'] = field(default=None, repr=False)
    session_id: str = ''      # sesión en la que se aplicó (rollback solo en la misma)


SCALAR_KINDS = ('u8', 'u16', 'u32', 'u64', 'ptr', 'cstr', 'utf8')

SCALAR_SIZES = {'u8': 1, 'u16': 2, 'u32': 4, 'u64': 8, 'ptr': 8}


@dataclass
class BackendCapabilities:
    """Capacidades declaradas POR OPERACIÓN. Un backend debe declarar cada
    capacidad individualmente y la GUI no ofrecerá lo no declarado.

    - enumerate: listar regiones virtuales.
    - read: lectura de rangos.
    - read_scalars: tipos escalares soportados (u8..u64/ptr/cstr/utf8).
    - write_rw: escribir en regiones legible-escribibles (sin X).
    - write_rwx: escribir además en regiones con X (ejecutable+escritible).
    - alloc / free: asignar y liberar memoria scratch en el target.
    - watch: monitorización de cambios (polling en v1).
    """
    enumerate: bool = False
    read: bool = False
    read_scalars: frozenset = frozenset()
    write_rw: bool = False
    write_rwx: bool = False
    alloc: bool = False
    free: bool = False
    watch: bool = False


class MemoryError(Exception):
    """Errores del subsistema de memoria. `reason` es un código estable."""
    def __init__(self, reason: str, message: str = ''):
        super().__init__(message or reason)
        self.reason = reason


class SessionError(MemoryError):
    """La sesión/proceso objetivo ya no está disponible (detach, proceso
    terminado, transporte caído) o nunca existió. `detail` conserva el motivo
    original (p. ej. 'process-terminated')."""
    def __init__(self, reason: str = 'E_SESSION_LOST', message: str = '',
                 detail: str = ''):
        super().__init__(reason, message or detail or reason)
        self.detail = detail


class CapabilityError(MemoryError):
    def __init__(self, feature: str):
        super().__init__('E_CAPABILITY', f'Backend sin capacidad: {feature}')
        self.feature = feature
