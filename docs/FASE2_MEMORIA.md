# NetScope · Fase 2 — Subsistema de Acceso a Memoria de Procesos

Estado: **IMPLEMENTADO (v1)**. No modifica la Fase 1
(observabilidad de red por Frida): es un subsistema independiente que se
apoya en la misma infraestructura de procesos y GUI y reutiliza la misma
sesión Frida (`FridaInterceptor.memory_engine()` carga `agent/memory.js` como
script adicional; no hay segundo attach).

### Estado de implementación y verificación

| Requisito | Estado | Verificado con |
|---|---|---|
| Regiones y permisos R/W/X | ✔ | `test_memory_native`, `test_memory_ui` |
| Lectura, escalares (u8..u64, ptr, cstr, utf8) | ✔ | `test_memory_engine` (Dummy), `test_memory_native` (Frida real) |
| Lecturas parciales / regiones inaccesibles | ✔ (relleno con 0 + error `E_ACCESS_DENIED`) | `test_memory_native` |
| Snapshots y diff | ✔ | `test_memory_engine`, `test_memory_native` |
| Auditoría JSONL y rollback verificado | ✔ | `test_memory_engine`, `test_memory_native` |
| Evitar escrituras accidentales | ✔ (solo regiones con W; el resto se rechaza) | `test_memory_native` |
| x86 y x64 | ✔ (`arch`/`pointerSize` del proceso) | `test_memory_x86` (SysWOW64\ping.exe, ia32) |
| Capacidades reales | ✔ sondeadas por proceso (alloc/write/read/free/enumerate) | `test_memory_native` |
| Watcher (polling) | ✔ | `test_memory_native` |
| GUI integrada (pestaña Memoria) | ✔ misma sesión, captura TCP/UDP coexiste | `test_memory_ui` (offscreen, PySide6 → `py -3.11`) |

Los tests son scripts (no `pytest`): `py -3 tests\test_memory_native.py`, etc.
`test_memory_ui.py` requiere PySide6.

### Limitaciones conocidas

- Sin escritura en regiones sin permiso W (no se usa `VirtualProtectEx`).
- Una lectura parcial rellena los bytes inaccesibles con `0` y devuelve el error;
  no distingue en los datos cuáles son huecos.
- Procesos protegidos (PPL/anti-debug) pueden denegar el attach; el error se propaga.
- Watch por polling (sin watchpoints hardware). Sin memoria de kernel.
- La GUI sin cerrar la ventana provoca un fallo de salida de Qt preexistente
  (`QThread` activo al destruirse); `closeEvent` lo evita.

---


## 1. Objetivo y alcance

Inspección y (bajo control) modificación de la memoria de procesos de
laboratorio / autorizados, con el mismo principio de NetScope: el usuario
no debe adivinar backend ni límites; la herramienta declara qué puede y
qué no puede en cada proceso.

**No incluye:** evasión de anti-cheat/anti-debug, dumping de propiedad
intelectual, ni accesso a procesos del sistema sin configuración explícita
(`MEMORY_ALLOW_SYSTEM=false` por defecto).

---

## 2. Mecanismos documentados del SO (Windows)

| Necesidad | API documentada | Cómo la cubrimos |
|---|---|---|
| Enumerar regiones virtuales | `VirtualQueryEx` (`MEMORY_BASIC_INFORMATION`: BaseAddress, RegionSize, State, Protect, Type) | Frida `Process.enumerateRanges(promises)` ya lo abstrae; handlers para `MEM_COMMIT`, `MEM_PRIVATE`, `MEM_IMAGE` |
| Lectura | `ReadProcessMemory` | Frida `Memory.readByteArray/ptr()/...` |
| Escritura | `WriteProcessMemory` (requiere `PAGE_*` escribible o cambia protección temporalmente) | Frida `Memory.write*`; para `PAGE_EXECUTE_READ` se documenta que requiere `VirtualProtectEx` externo — **no** implementado en v1 |
| Protecciones | `PAGE_NOACCESS/READONLY/READWRITE/EXECUTE_READ/...` | Se mapean a la tupla `(r, w, x)` y filtran consultas |
| Páginas guardianas / reserved | `PAGE_GUARD`, `MEM_RESERVE` | Lectura parcial tolerante a fallos por región |

Límites declarados (no ocultos):
- Frida **no** cambia protecciones por nosotros: escribir en regiones
  `R/X` falla en v1 y queda registrado como `E_UNSUPPORTED_PROTECTION`.
- Procesos protegidos (TLS callbacks, anti-debug, PPL) pueden denegar
  attach: el error se propaga tal cual, no se simulaología de éxito.

---

## 3. Arquitectura

```
agent/memory.js   (backend Frida: RPC puro, sin lógica de negocio)
        ▲ rpc.exports
core/memory/engine.py          ← infraestructura GENÉRICA (sin frida)
core/memory/backends/__init__.py (MemoryBackend, capacidades declarativas)
core/memory/backends/frida_memory.py (adaptador Frida → engine)
ui/memory_panel.py  + pestaña en main_window.py (reusa cola de eventos)
```

### 3.1 Interfaz del backend (`MemoryBackend`) — lo único que la GUI conoce

```python
class MemoryBackend(ABC):
    CAPABILITIES: dict   # declarativas, consultables por la GUI

    def enumerate_regions(self, min_prot='r') -> list[Region]
    def read(self, addr: int, size: int) -> tuple[bytes, int]   # (data, errc)
    def read_scalar(self, addr: int, kind: str)                 # u8..u64, ptr, cstr, utf8
    def write(self, addr: int, data: bytes) -> WriteResult       # auditado
    def alloc(self, size: int, near: int | None = None) -> int
    def free(self, addr: int) -> bool
    def snapshot_regions(self, filter: RegionFilter) -> MemorySnapshot
```

`CAPABILITIES` (por backend; la GUI las muestra y no offers opcionales
si el backend no las declara):

```python
CAPABILITIES = {
  'frida': {
    'enumerate_ranges': True,
    'read': True,
    'read_scalars': ['u8','u16','u32','u64','ptr','cstr','utf8'],
    'write_rwx': True,          # solo RW(e) ya escribibles
    'write_protected': False,   # R/X sin VirtualProtectEx → False (explícito)
    'alloc_free': True,
    'watch_changed_regions': 'polling',  # no exclusivo; sin callbacks de SO
    'kernel_memory': False,
  }
}
```

### 3.2 Modelos genéricos (independientes de Frida)

```python
@dataclass Region:    base:int; size:int; prot:'rwx'; state:str; type:str; owner_module:str|None
@dataclass RegionRead: region:Region; data:bytes; error:str|None     # lectura parcial tolerante
@dataclass MemorySnapshot: ts:float; regions:list[Region]; label:str
   # internamente guarda SOLO rangos solicitados (no GB del proceso entero)
@dataclass WriteRecord: ts, addr, old_bytes, new_bytes, source='gui'|'api', applied:bool, rolled_back:bool
```

### 3.3 Motor genérico (`MemoryEngine`) — sin frida como dependencia

- **Regiones**: normaliza ranges del backend, filtra (RW/RX/commit-only),
  agrupa contiguas, asocia `owner_module` por rango de base de módulos.
- **Read**: divide lecturas grandes en chunks (default 64 KB); en error
  parcial devuelve lo leído + `error:str` de la región fallida (nunca cansela
  el snapshot completo).
- **Snapshots y diff**: diff por dirección anclada a región (NO por índice,
  para tolerar ASLR entre capturas):
  `diff(s1, s2) -> list[DiffEntry(kind: added|removed|modified|unchanged, region, old, new)]`
- **Audit log**: `data:append` JSONL `{ts, pid, addr, len, old_hex_prefix, new_hex_prefix, user_note}`.
- **Undo**: por escritura guarda `old_bytes`; `rollback(record)` revalida que
  `read(addr) == new_bytes` (o descarta con `E_CHANGED_SINCE`) y reescribe el
  original. Solo se restaura si es técnicamente seguro (región sigue existiendo
  y con misma protección).

### 3.4 Backend Frida (`agent/memory.js`)

RPC puro (sin reglas de negocio), con llamadas idempotentes y timeouts:
`listRanges(promises)`, `readRange(addr, size)` (chunk interno 64 KB),
`readScalar(addr, kind)`, `writeRange(addr, hexBytes)`, `alloc/free`,
`moduleRanges(name)`. Toda excepción nativa → `{error, code}` en el retorno
(los crashes del target deben ser imposibles desde aquí; se testea).

### 3.5 Integración con la GUI existente (sin reconstruir NetScope)

- Nueva pestaña **Memoria** en `main_window`: reusa `proc_combo` y attach ya existente
  (misma sesión Frida; NO abre segundo attach).
- Reusa `EventQueue`/`FridaEventWorker` para eventos → nunca bloquea la GUI.
- Botón **Desactivar memoria** (inline) en caso de apps sensibles — el subsistema
  es explícito: no se engancha la memoria si el usuário no lo pide.

---

## 4. Qué es genérico y qué es específico (resumen)

| Componente | ¿Genérico? |
|---|---|
| Regiones/snapshots/diff/audit/undo | **Sí** — puro Python, testeable sin frida vía DummyBackend |
| Modelos `Region/RegionRead/MemorySnapshot/WriteRecord` | **Sí** |
| Filtrado RWX/commit, chunking de lectura parcial | **Sí** (semántica Windows, agnóstica de backend) |
| `VirtualQueryEx/ReadProcessMemory/WriteProcessMemory` vía Frida | **Específico Windows** (backend frida_memory) |
| Escritura en regiones `R/X` | **Específico y NO soportado en v1** (requiere VirtualProtectEx explícito, documentado como limitación) |
| Watch de cambios | **Genérico por polling** en v1 (watchpoints HW: documentado como futuro, requiere backend propio) |

---

## 5. Pruebas (todasattached self-process, sin network)

1. `test_memory_regions` — ≥50 regiones commit; todas con prot válida; ≥1 `MEM_IMAGE` (python.exe).
2. `test_read_roundtrip` — `Memory.alloc` del backend con patrón → read == patrón.
3. `test_read_partial` — lectura que cruza una página inaccesible → `data` parcial + `error` en la cola, sin exception.
4. `test_read_scalars` — write u32 0xCAFEBABE → readScalar('u32') igual; cstr igual.
5. `test_snapshot_diff` — cambiar 4 bytes entre snapshots → diff reporta exactamente 1 región modified + tamaños correctos.
6. `test_write_undo` — write en buffer scratch → read-back OK → rollback → old_bytes restaurados; audit log JSONL contiene ambas entradas.
7. `test_write_protected_denied` — write a región RX → `E_UNSUPPORTED_PROTECTION`, sin crash del target (target sigue vivo después del test).
8. `test_capability_declared` — la GUI muestra/oculta botones según `CAPABILITIES` del backend activo.
9. `test_engine_no_frida_import` — `core/memory/engine.py` no importa frida (DummyBackend).

## 6. Orden de implementación sugerido

1. Modelos + engine genéricos + DummyBackend + tests (1,2,5,9) — sin frida.
2. `agent/memory.js` + `frida_memory.py` + tests (3,4,6,7) — attach self.
3. Pestaña GUI Memoria (lista regiones/search hex/read+write con undo) + test 8.
4. (Opcional después) módulo watch de polling y export PCAPNG de registros.
