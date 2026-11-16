# -*- coding: utf-8 -*-
"""Parser PE mínimo (PE32 y PE32+) para comparar memoria con el fichero en disco.

Sirve para dos cosas SIN tocar la tabla de exportación del proceso objetivo
(las páginas de EAT pueden estar protegidas con PAGE_GUARD):
  - resolver direcciones de exportación a partir del fichero en disco;
  - saber qué bytes de las secciones ejecutables son "legítimos" (máscara de
    relocaciones) para detectar parches inline (hooks) y otras modificaciones.
"""
import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

IMAGE_SCN_MEM_EXECUTE = 0x20000000
REL_ABSOLUTE, REL_HIGH, REL_LOW, REL_HIGHLOW, REL_DIR64 = 0, 1, 2, 3, 10


@dataclass
class Section:
    name: str
    rva: int
    vsize: int
    raw_off: int
    raw_size: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & IMAGE_SCN_MEM_EXECUTE)


@dataclass
class PEImage:
    path: str
    is64: bool = False
    image_base: int = 0
    size_of_image: int = 0
    sections: List[Section] = field(default_factory=list)
    export_dir: Tuple[int, int] = (0, 0)           # (rva, size)
    reloc_dir: Tuple[int, int] = (0, 0)
    _data: bytes = b''
    _exports: Optional[Dict[str, Tuple[int, Optional[str]]]] = None
    _relocs: Optional[Set[int]] = None

    @classmethod
    def load(cls, path: str) -> 'PEImage':
        with open(path, 'rb') as f:
            data = f.read()
        if data[:2] != b'MZ':
            raise ValueError('no es un PE')
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b'PE\0\0':
            raise ValueError('firma PE inválida')
        nsec, = struct.unpack_from('<H', data, pe_off + 6)
        opt_size, = struct.unpack_from('<H', data, pe_off + 20)
        opt = pe_off + 24
        magic, = struct.unpack_from('<H', data, opt)
        is64 = magic == 0x20B
        img = cls(path=path, is64=is64, _data=data)
        if is64:
            img.image_base, = struct.unpack_from('<Q', data, opt + 24)
            dd = opt + 112
        else:
            img.image_base, = struct.unpack_from('<I', data, opt + 28)
            dd = opt + 96
        img.size_of_image, = struct.unpack_from('<I', data, opt + 56)
        img.export_dir = struct.unpack_from('<II', data, dd)
        img.reloc_dir = struct.unpack_from('<II', data, dd + 5 * 8)
        sec = opt + opt_size
        for i in range(nsec):
            name, vsize, rva, rsize, roff = struct.unpack_from('<8sIIII', data, sec + i * 40)
            flags, = struct.unpack_from('<I', data, sec + i * 40 + 36)
            img.sections.append(Section(name.rstrip(b'\0').decode('latin1'), rva, vsize, roff, rsize, flags))
        return img

    # ---- acceso por RVA ----
    def section_for_rva(self, rva: int) -> Optional[Section]:
        for s in self.sections:
            if s.rva <= rva < s.rva + max(s.vsize, s.raw_size):
                return s
        return None

    def read_rva(self, rva: int, n: int) -> bytes:
        """Bytes del fichero tal como quedarían en memoria (ceros fuera de la parte física)."""
        s = self.section_for_rva(rva)
        if s is None:
            if self.sections and rva < self.sections[0].rva:
                return self._data[rva:rva + n]
            return b''
        off = rva - s.rva
        raw = self._data[s.raw_off + off:s.raw_off + min(off + n, s.raw_size)] if off < s.raw_size else b''
        return raw + b'\0' * (n - len(raw))

    # ---- exportaciones ----
    def exports(self) -> Dict[str, Tuple[int, Optional[str]]]:
        """nombre -> (rva, forwarder 'DLL.Func' o None)."""
        if self._exports is not None:
            return self._exports
        out: Dict[str, Tuple[int, Optional[str]]] = {}
        rva, size = self.export_dir
        if rva:
            hdr = self.read_rva(rva, 40)
            (_, _, _, _, _, _, nfunc, nnames, aof, aon, aoo) = struct.unpack_from('<IIHHIIIIIII', hdr)
            funcs = struct.unpack('<%dI' % nfunc, self.read_rva(aof, nfunc * 4))
            names = struct.unpack('<%dI' % nnames, self.read_rva(aon, nnames * 4))
            ords = struct.unpack('<%dH' % nnames, self.read_rva(aoo, nnames * 2))
            for i in range(nnames):
                raw = self.read_rva(names[i], 128)
                nm = raw.split(b'\0')[0].decode('latin1')
                frva = funcs[ords[i]]
                fwd = None
                if rva <= frva < rva + size:           # forwarder: la "función" apunta a una cadena
                    fwd = self.read_rva(frva, 128).split(b'\0')[0].decode('latin1')
                out[nm] = (frva, fwd)
        self._exports = out
        return out

    # ---- relocaciones ----
    def reloc_mask(self) -> Set[int]:
        """RVAs de bytes que Windows modifica al cargar (aplicar relocaciones)."""
        if self._relocs is not None:
            return self._relocs
        mask: Set[int] = set()
        rva, size = self.reloc_dir
        if rva and size:
            blob = self.read_rva(rva, size)
            pos = 0
            while pos + 8 <= len(blob):
                page, bsize = struct.unpack_from('<II', blob, pos)
                if bsize < 8:
                    break
                for i in range((bsize - 8) // 2):
                    e, = struct.unpack_from('<H', blob, pos + 8 + i * 2)
                    t, off = e >> 12, e & 0xFFF
                    width = {REL_HIGHLOW: 4, REL_DIR64: 8, REL_HIGH: 2, REL_LOW: 2}.get(t, 0)
                    for k in range(width):
                        mask.add(page + off + k)
                pos += bsize
        self._relocs = mask
        return mask


_CACHE: Dict[str, PEImage] = {}


def load_cached(path: str) -> PEImage:
    key = os.path.normcase(path)
    if key not in _CACHE:
        _CACHE[key] = PEImage.load(path)
    return _CACHE[key]


def classify_trampoline(code: bytes) -> str:
    """Patrón típico de un parche inline al inicio de una función."""
    if not code:
        return 'desconocido'
    b = code
    if b[0] == 0xE9:
        return 'jmp rel32'
    if b[0] == 0xEB:
        return 'jmp short'
    if b[0] == 0xE8:
        return 'call rel32'
    if b[:2] == b'\xFF\x25':
        return 'jmp [mem]'
    if b[0] == 0x68 and len(b) >= 6 and b[5] == 0xC3:
        return 'push+ret'
    if b[:2] in (b'\x48\xB8', b'\x49\xBB') and len(b) >= 12 and b[10:12] in (b'\xFF\xE0', b'\x41\xFF'):
        return 'mov rax,imm64; jmp rax'
    if b[0] == 0xCC:
        return 'int3'
    return 'bytes modificados (patrón no reconocido)'
