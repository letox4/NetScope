# -*- coding: utf-8 -*-
"""MemoryEngine — infraestructura GENÉRICA del subsistema de memoria.

No importa Frida: opera sobre la interfaz abstracta MemoryBackend
(DummyBackend en tests, FridaMemoryBackend en producción).

Responsabilidades:
- Enumeración/filtrado de regiones por permisos R/W/X individuales.
- Snapshots presupuestados (chunking + tolerancia a lecturas parciales).
- Diff entre snapshots con identidad ASLR-estable (módulo + rel offset).
- Escrituras controladas con pre-lectura, verificación y auditoría JSONL.
- Rollback (undo) seguro: valida que no hubo cambios concurrentes.
- Lectura de escalares (solo kinds declarados por el backend).
"""
import json
import os
import struct
import threading
import time
from typing import Callable, List, Optional, Tuple

from .audit import AuditLog
from .models import (BackendCapabilities, CapabilityError, DiffEntry,
                     MemoryError, MemorySnapshot, ModuleIdentity, ReadDetail,
                     Region, RegionRead, SessionError, WriteRecord,
                     SCALAR_KINDS, SCALAR_SIZES)

DEFAULT_CHUNK = 64 * 1024          # chunk de lectura
DEFAULT_PER_REGION = 256 * 1024    # tope por región en snapshots
DEFAULT_TOTAL_BUDGET = 8 * 1024 * 1024  # tope global del snapshot
CSTR_MAX = 1024
PAGE = 4096


class MemoryEngine:
    """Motor genérico. Construir con backend = DummyBackend() en tests."""

    def __init__(self, backend, audit_path: Optional[str] = None,
                 chunk: int = DEFAULT_CHUNK,
                 audit: Optional[AuditLog] = None,
                 audit_include_bytes: bool = False,
                 audit_reads: bool = False):
        self.backend = backend
        self.caps: BackendCapabilities = backend.capabilities
        self.chunk = chunk
        self.write_history: List[WriteRecord] = []
        self.audit: Optional[AuditLog] = audit
        if self.audit is None and audit_path:
            self.audit = AuditLog(audit_path, include_bytes=audit_include_bytes)
        self.audit_path = self.audit.path if self.audit else None
        self.audit_reads = audit_reads
        self.session_id: str = getattr(backend, 'session_id', '') or ''
        self.pointer_size: int = int(getattr(backend, 'pointer_size', 8) or 8)
        self._invalid: Optional[SessionError] = None
        self._listeners: List[Callable[[SessionError], None]] = []
        self._llock = threading.Lock()
        # observadores de operaciones (diagnóstico): cb(op: str, **detalles)
        self.observers: List[Callable[..., None]] = []

    def _notify(self, op: str, **detail) -> None:
        for cb in list(self.observers):
            try:
                cb(op, **detail)
            except Exception:
                pass

    # ---------------- estado de sesión ----------------
    @property
    def valid(self) -> bool:
        return self._invalid is None

    def add_invalidation_listener(self, cb: Callable[[SessionError], None]) -> None:
        with self._llock:
            self._listeners.append(cb)
            err = self._invalid
        if err is not None:      # ya invalidado: avisa de inmediato
            try:
                cb(err)
            except Exception:
                pass

    def remove_invalidation_listener(self, cb) -> None:
        with self._llock:
            if cb in self._listeners:
                self._listeners.remove(cb)

    def invalidate(self, reason: str = 'E_SESSION_LOST', detail: str = '',
                   authoritative: bool = False) -> None:
        """Marca el motor como inservible (sesión perdida) y avisa a los
        watchers. Idempotente; el primer motivo se conserva, salvo que quien
        llama sea la fuente autoritativa (el evento detached de Frida), que
        puede precisar el detalle (p. ej. 'process-terminated') si otro hilo
        llegó antes con un error genérico de transporte."""
        with self._llock:
            if self._invalid is not None:
                if authoritative and detail:
                    self._invalid.detail = detail
                return
            self._invalid = SessionError(reason, detail=detail)
            err = self._invalid
            listeners = list(self._listeners)
        try:
            self.backend.invalidate(detail or reason)
        except Exception:
            pass
        self._audit_event('session_lost', reason=reason, detail=detail)
        for cb in listeners:
            try:
                cb(err)
            except Exception:
                pass

    def _ensure_valid(self) -> None:
        if self._invalid is not None:
            raise SessionError(self._invalid.reason, str(self._invalid),
                               self._invalid.detail)

    def _guard(self, fn, *args):
        """Llama al backend; un SessionError invalida el motor y se propaga."""
        self._ensure_valid()
        try:
            return fn(*args)
        except SessionError as e:
            self.invalidate(e.reason, e.detail or str(e))
            raise

    def _check_addr(self, addr: int, size: int = 1) -> None:
        limit = 1 << (8 * self.pointer_size)
        if not isinstance(addr, int) or addr < 0 or size < 0 or addr + size > limit:
            raise MemoryError(
                'E_BAD_ADDRESS',
                f'dirección/rango fuera del espacio de {8 * self.pointer_size} bits: '
                f'{addr!r}+{size!r}')

    # ---------------- auditoría ----------------
    def _audit_event(self, event: str, **fields) -> None:
        """Eventos informativos: un fallo de disco no rompe la operación."""
        if self.audit is None:
            return
        try:
            self.audit.event(event, session=self.session_id, **fields)
        except OSError:
            pass

    # ---------------- regiones ----------------
    def regions(self, prot_filter: str = '') -> List[Region]:
        """Lista regiones commit. prot_filter subcadena de 'rwx': devuelve
        regiones que tengan AL MENOS esos permisos (R, W, X independientes)."""
        if not self.caps.enumerate:
            raise CapabilityError('enumerate')
        req = set(prot_filter.lower()) & set('rwx')
        out = []
        for r in self._guard(self.backend.regions):
            if r.state != 'committed':
                continue
            have = set(r.protections)
            if req and not req.issubset(have):
                continue
            out.append(r)
        return out

    # ---------------- lectura ----------------
    def read_range(self, addr: int, size: int) -> Tuple[bytes, Optional[str]]:
        """Lectura tolereante: divide en chunks; devuelve lo leído + error
        parcial si hubo. Nunca lanza por fallo de página del target; sí lanza
        SessionError si la sesión se perdió."""
        if not self.caps.read:
            raise CapabilityError('read')
        self._check_addr(addr, size)
        data = bytearray()
        error = None
        cur = addr
        rest = size
        while rest > 0 and error is None:
            n = min(self.chunk, rest)
            d, err = self._guard(self.backend.read, cur, n)
            data += d
            if err is not None:
                error = err
            cur += n
            rest -= n
        if self.audit_reads:
            self._audit_event('read', addr=addr, len=size, got=len(data),
                              error=error)
        if error in ('E_PAGE_GUARD', 'E_NO_ACCESS'):
            self._notify('read_error', addr=addr, size=size, error=error)
        return bytes(data), error

    def read_detail(self, addr: int, size: int) -> ReadDetail:
        """Como read_range pero con el prefijo válido y los huecos exactos
        (un solo bloque; size <= chunk)."""
        if not self.caps.read:
            raise CapabilityError('read')
        self._check_addr(addr, size)
        if size > self.chunk:
            raise MemoryError('E_TOO_LARGE', f'read_detail admite <= {self.chunk} bytes')
        return self._guard(self.backend.read_detail, addr, size)

    # ---------------- escalares ----------------
    def check_scalars(self, kinds) -> None:
        have = set(self.caps.read_scalars)
        for k in kinds:
            if k not in SCALAR_KINDS:
                raise MemoryError('E_BAD_KIND', f'kind inválido: {k}')
            if k not in have:
                raise CapabilityError(f'read_scalar:{k}')

    def scalar_size(self, kind: str) -> int:
        """Tamaño en bytes de un escalar; `ptr` depende del proceso objetivo."""
        return self.pointer_size if kind == 'ptr' else SCALAR_SIZES[kind]

    def read_value(self, addr: int, kind: str):
        """Lee un escalar (u8..u64/ptr/cstr/utf8) según capacidad declarada."""
        self.check_scalars([kind])
        if kind in SCALAR_SIZES:
            n = self.scalar_size(kind)
            self._check_addr(addr, n)
            rd = self.read_detail(addr, n)
            if rd.valid < n:
                raise MemoryError('E_PARTIAL_READ', rd.error or 'lectura corta')
            fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}[n]
            return struct.unpack(fmt, rd.data[:n])[0]
        if kind == 'cstr':
            return self._read_cstr(addr)
        if kind == 'utf8':
            rd = self.read_detail(addr, 256)
            if rd.valid == 0:
                raise MemoryError('E_READ', rd.error or 'sin datos')
            return rd.data[:rd.valid].decode('utf-8', 'replace')
        raise MemoryError('E_BAD_KIND', kind)

    def _read_cstr(self, addr: int) -> bytes:
        """Lee hasta NUL por bloques que no cruzan límites de página (un
        bloque ilegible nunca se confunde con un NUL)."""
        out = bytearray()
        cur = addr
        while len(out) < CSTR_MAX:
            n = min(256, PAGE - (cur % PAGE), CSTR_MAX - len(out))
            self._check_addr(cur, n)
            rd = self.read_detail(cur, n)
            chunk = rd.data[:rd.valid]
            nul = chunk.find(b'\x00')
            if nul >= 0:
                return bytes(out + chunk[:nul])
            out += chunk
            if rd.valid < n:
                if not out:
                    raise MemoryError('E_READ', rd.error or 'sin datos')
                raise MemoryError(
                    'E_PARTIAL_READ',
                    f'cadena cortada por memoria ilegible ({rd.error}) tras {len(out)} bytes')
            cur += n
        return bytes(out)

    # ---------------- snapshots / diff ----------------
    def snapshot(self, label: str = '',
                 per_region_limit: int = DEFAULT_PER_REGION,
                 total_budget: int = DEFAULT_TOTAL_BUDGET,
                 prot_filter: str = 'r') -> MemorySnapshot:
        """Captura presupuestada de regiones legibles. Cada región se lee
        hasta per_region_limit; si el presupuesto total se agota, el resto
        queda marcado con note='E_BUDGET' (snapshot incompleto pero válido)."""
        if not self.caps.read:
            raise CapabilityError('read')
        snap = MemorySnapshot(ts=time.time(), label=label,
                              session_id=self.session_id)
        used = 0
        for r in self.regions(prot_filter):
            limit = min(per_region_limit, total_budget - used)
            if limit <= 0:
                snap.entries.append(RegionRead(region=r, data=b'',
                                               error='E_BUDGET',
                                               truncated=True, note='E_BUDGET'))
                continue
            n = min(r.size, limit)
            d, err = self._guard(self.backend.read, r.addr, n)
            if len(d) >= n:
                # si pedimos menos que la región completa → truncado
                truncated = n < r.size
            else:
                truncated = True
            note = ''
            if truncated and err is None:
                note = 'E_BUDGET' if limit < r.size else 'E_PARTIAL'
            snap.entries.append(RegionRead(region=r, data=d, error=err,
                                           truncated=truncated, read_len=len(d),
                                           note=note))
            used += len(d)
        self._audit_event('snapshot', label=label, regions=len(snap.entries),
                          bytes=used)
        return snap

    @staticmethod
    def diff(a: MemorySnapshot, b: MemorySnapshot) -> List[DiffEntry]:
        """Diff por identidad ASLR-estable (módulo + offset rel). Rechaza
        snapshots de sesiones/procesos distintos (direcciones no comparables)."""
        if a.session_id and b.session_id and a.session_id != b.session_id:
            raise MemoryError(
                'E_STALE_SNAPSHOT',
                'los snapshots pertenecen a sesiones/procesos distintos')
        ia = a.by_identity()
        ib = b.by_identity()
        out = []
        for ident in sorted(set(ia) | set(ib), key=str):
            ea = ia.get(ident)
            eb = ib.get(ident)
            if ea is None:
                out.append(DiffEntry('added', ident,
                                     eb.region.metadata(), None, eb.data))
            elif eb is None:
                out.append(DiffEntry('removed', ident,
                                     ea.region.metadata(), ea.data, None))
            elif ea.data != eb.data:
                out.append(DiffEntry('modified', ident,
                                     eb.region.metadata(), ea.data, eb.data))
            else:
                out.append(DiffEntry('unchanged', ident,
                                     ea.region.metadata(), ea.data, eb.data))
        return out

    # ---------------- escritura ----------------
    def _region_at(self, addr: int, regs: Optional[list]):
        """Región que contiene addr: primero las asignaciones propias del
        backend (scratch), luego la enumeración fresca."""
        region_for = getattr(self.backend, 'region_for', None)
        r = region_for(addr) if callable(region_for) else None
        if r is not None:
            return r, regs
        if regs is None:
            regs = list(self._guard(self.backend.regions))
        for reg in regs:
            if reg.contains(addr):
                return reg, regs
        return None, regs

    def _check_write_range(self, addr: int, length: int) -> bool:
        """Valida TODO el rango [addr, addr+length): cada byte debe caer en
        una región commit, escribible y (si es ejecutable) permitida por el
        backend. La enumeración es fresca en cada llamada (sin caché).
        Devuelve True si el rango toca memoria ejecutable."""
        if length <= 0:
            raise MemoryError('E_BAD_ARGS', 'longitud de escritura inválida')
        self._check_addr(addr, length)
        end = addr + length
        cursor = addr
        regs = None
        touches_exec = False
        while cursor < end:
            r, regs = self._region_at(cursor, regs)
            if r is None:
                raise MemoryError(
                    'E_NO_MAP',
                    f'{hex(cursor)} no mapeada (rango {hex(addr)}+{length})')
            if r.state != 'committed':
                raise MemoryError('E_NO_MAP', f'{hex(cursor)} no está commit')
            if not r.w:
                raise MemoryError(
                    'E_NON_WRITABLE',
                    f'región en {hex(cursor)} no es escribible '
                    f'(protecciones: {r.protections or "ninguna"}; '
                    f'rango {hex(addr)}+{length})')
            if r.x and not self.caps.write_rwx:
                raise MemoryError(
                    'E_UNSUPPORTED_PROTECTION',
                    'el backend no escribe en regiones con X')
            touches_exec = touches_exec or r.x
            cursor = max(r.end, cursor + 1)
        return touches_exec

    def _check_write_region(self, addr: int) -> Region:
        """Compatibilidad: valida una sola dirección (1 byte)."""
        self._check_write_range(addr, 1)
        r, _ = self._region_at(addr, None)
        return r

    def _audit(self, record: WriteRecord, event: str = 'write') -> None:
        if self.audit is None:
            return
        entry = {
            'op': event,
            'session': self.session_id,
            'addr': record.addr,
            'addr_hex': hex(record.addr),
            'len': record.length,
            'note': record.note,
            'applied': record.applied,
            'partial': record.partial,
            'reason': record.reason,
            'rolled_back': record.rolled_back,
        }
        entry.update(self.audit.blob_fields('old', record.old_bytes))
        entry.update(self.audit.blob_fields('new', record.new_bytes))
        try:
            self.audit.event(event, **entry)
        except OSError:
            pass    # el resultado ya se aplicó; el intento sí quedó registrado

    def _audit_intent(self, op: str, addr: int, length: int, note: str) -> None:
        """Registro previo obligatorio: sin él no se escribe (nunca hay una
        escritura sin rastro). Solo si hay auditoría configurada."""
        if self.audit is None:
            return
        try:
            self.audit.event(f'{op}_intent', session=self.session_id,
                             addr=addr, addr_hex=hex(addr), len=length, note=note)
        except OSError as e:
            raise MemoryError('E_AUDIT_FAILED',
                              f'no se pudo registrar la auditoría: {e}')

    def _reject(self, rec: WriteRecord, reason: str, event: str = 'write') -> None:
        rec.reason = reason
        rec.applied = False
        self.write_history.append(rec)
        self._audit(rec, event)

    def write(self, addr: int, data: bytes, note: str = '') -> WriteRecord:
        """Escritura controlada:
        1. valida capacidad, sesión y TODO el rango (permisos por región);
        2. registra la intención en la auditoría (si falla, no escribe);
        3. pre-lectura exacta de old_bytes (falla si no puede leer el rango
           completo — nunca escribe a ciegas);
        4. no escribe si no hay cambio real (E_NO_CHANGE);
        5. escribe + read-back; si el read-back no coincide → partial;
        6. registra WriteRecord + auditoría."""
        if not self.caps.write_rw:
            raise CapabilityError('write_rw')
        self._ensure_valid()
        data = bytes(data)
        rec = WriteRecord(ts=time.time(), addr=addr, length=len(data),
                          old_bytes=b'', new_bytes=data, note=note,
                          session_id=self.session_id)
        try:
            touches_exec = self._check_write_range(addr, len(data))
        except SessionError as e:
            self.invalidate(e.reason, e.detail or str(e))
            raise
        except MemoryError as e:
            self._reject(rec, e.reason)
            raise
        self._audit_intent('write', addr, len(data), note)
        # pre-lectura exacta (fuera de read_range: si falla, fracaso completo)
        old, err = self._guard(self.backend.read, addr, len(data))
        rec.old_bytes = bytes(old)
        if err is not None or len(old) < len(data):
            self._reject(rec, 'E_PRE_READ_FAILED')
            raise MemoryError('E_PRE_READ_FAILED',
                              f'no se pudo pre-leer el rango: {err or "corto"}')
        if old == data:
            rec.reason = 'E_NO_CHANGE'
            self.write_history.append(rec)
            return rec
        try:
            self._guard(self.backend.write, addr, data)
        except SessionError:
            self._reject(rec, 'E_SESSION_LOST')
            raise
        except MemoryError as e:
            rec.reason = e.reason
            rec.applied = False
            # ¿se aplicó algo? (escritura parcial interrumpida)
            try:
                back, berr = self.backend.read(addr, len(data))
                rec.partial = (back != bytes(old)) and bool(back)
            except Exception:
                rec.partial = False
            self.write_history.append(rec)
            self._audit(rec)
            raise
        # verificación (read-back)
        back, berr = self._guard(self.backend.read, addr, len(data))
        rec.applied = (back == data)
        rec.partial = (not rec.applied) and bool(back)
        if not rec.applied:
            rec.reason = berr or 'E_VERIFY_FAILED'
        self.write_history.append(rec)
        self._audit(rec)
        self._notify('write', addr=addr, length=len(data), applied=rec.applied,
                     reason=rec.reason, exec=touches_exec)
        return rec

    def rollback(self, record: WriteRecord) -> WriteRecord:
        """Restauración segura: reescribe old_bytes SOLO si
        1. el backend puede escribir;
        2. los bytes actuales son EXACTAMENTE new_bytes (sin cambio
           concurrente) — si no: E_CHANGED_SINCE, no se restaura;
        3. la región sigue siendo escribible.
        Devuelve el WriteRecord de la restauración."""
        if record.rolled_back:
            raise MemoryError('E_ALREADY_ROLLED_BACK',
                              'esta escritura ya fue restaurada')
        if not record.applied:
            raise MemoryError('E_NOT_NEEDED',
                              f'no hay nada que restaurar ({record.reason})')
        self._ensure_valid()
        if record.session_id and record.session_id != self.session_id:
            raise MemoryError(
                'E_STALE_RECORD',
                'la escritura pertenece a otra sesión/proceso: '
                'sus direcciones no son válidas aquí')
        undo = WriteRecord(ts=time.time(), addr=record.addr,
                           length=record.length, old_bytes=record.new_bytes,
                           new_bytes=record.old_bytes,
                           note=f'rollback: {record.note}',
                           session_id=self.session_id)
        try:
            self._check_write_range(record.addr, record.length)
        except SessionError as e:
            self.invalidate(e.reason, e.detail or str(e))
            raise
        except MemoryError as e:
            self._reject(undo, e.reason, 'rollback')
            raise
        self._audit_intent('rollback', record.addr, record.length, record.note)
        cur, err = self._guard(self.backend.read, record.addr, record.length)
        if err is not None or len(cur) < record.length:
            self._reject(undo, 'E_UNSAFE', 'rollback')
            raise MemoryError('E_UNSAFE',
                              f'no se pudo re-verificar el estado: {err or "corto"}')
        if bytes(cur) != record.new_bytes:
            self._reject(undo, 'E_CHANGED_SINCE', 'rollback')
            raise MemoryError('E_CHANGED_SINCE',
                              'la memoria cambió desde la escritura: '
                              'restauración rechazada por seguridad')
        try:
            self._guard(self.backend.write, record.addr, record.old_bytes)
        except SessionError:
            self._reject(undo, 'E_SESSION_LOST', 'rollback')
            raise
        except MemoryError as e:
            undo.reason = e.reason
            self.write_history.append(undo)
            self._audit(undo, 'rollback')
            raise
        back, berr = self._guard(self.backend.read, record.addr, record.length)
        undo.applied = (back == record.old_bytes)
        undo.partial = (not undo.applied) and bool(back)
        if not undo.applied:
            undo.reason = berr or 'E_VERIFY_FAILED'
            self.write_history.append(undo)
            self._audit(undo, 'rollback')
            raise MemoryError('E_VERIFY_FAILED',
                              'rollback no verificado: ' + undo.reason)
        record.rolled_back = True  # marca en el registro original
        self.write_history.append(undo)
        self._audit(undo, 'rollback')
        return undo

    # ---------------- alloc / free ----------------
    def alloc(self, size: int) -> Region:
        if not self.caps.alloc:
            raise CapabilityError('alloc')
        reg = self._guard(self.backend.alloc, size)
        self._audit_event('alloc', addr=reg.addr, addr_hex=hex(reg.addr),
                          len=size)
        return reg

    def free(self, addr: int) -> None:
        if not self.caps.free:
            raise CapabilityError('free')
        self._guard(self.backend.free, addr)
        self._audit_event('free', addr=addr, addr_hex=hex(addr))
