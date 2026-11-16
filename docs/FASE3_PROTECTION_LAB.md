# Fase 3 — Laboratorio de protecciones reales

Batería de **ejecutables independientes** (C, MSVC) que reproducen mecanismos reales de protección con APIs reales de
Windows, más el arnés que mide el comportamiento de NetScope contra ellos. **Todos los programas se inspeccionan solo
a sí mismos**: no tocan procesos de terceros y no implementan evasión de nada.

## 1. Construir y ejecutar

```powershell
# Compila 11 ejecutables × (x64, x86) en tests\protection_lab\bin\  (MSVC 2022/2019 + Windows SDK)
powershell -ExecutionPolicy Bypass -File tests\protection_lab\build.ps1

# Matriz completa (escenario × arquitectura × agentes × modo): ~15 min
py -3.11 tests\protection_lab\run_matrix.py
py -3.11 tests\protection_lab\run_matrix.py --report tests\protection_lab\results\matrix.json --md docs\FASE3_RESULTS.md

# Un subconjunto
py -3.11 tests\protection_lab\run_matrix.py --scenarios baseline,integrity_exit --arch x64 --agents memory,network

# Configuración exacta de cada escenario (misma tabla que se ejecuta)
py -3.11 tests\protection_lab\run_matrix.py --scenarios-md docs\FASE3_SCENARIOS.md
```

Los ejecutables compilados son `lab_<mecanismo>_<x64|x86>.exe` (CRT estático: no necesitan nada instalado).

## 2. Mecanismos y ejecutables

| Requisito | Ejecutable | API real de Windows | Cómo se configura |
|---|---|---|---|
| IsDebuggerPresent | `lab_isdebugger` | `IsDebuggerPresent()` cada 50 ms | `--on-detect=…` |
| CheckRemoteDebuggerPresent | `lab_remotedbg` | `CheckRemoteDebuggerPresent(GetCurrentProcess())` | ídem |
| Estado de depuración por NtQueryInformationProcess | `lab_ntquery` | `NtQueryInformationProcess` clases `7` (DebugPort), `0x1E` (DebugObjectHandle), `0x1F` (DebugFlags) + lectura directa de `PEB.BeingDebugged` | ídem |
| Detección de instrumentación | `lab_instrumentation` | módulos (`EnumProcessModules`), nombres de hilo (`GetThreadDescription`), tuberías (`\\.\pipe\*`), cadenas en memoria ejecutable privada (patrones ofuscados, no hay texto en claro) | `--on-detect=…` |
| Modificaciones de integridad | `lab_integrity` | prólogos de `ws2_32`/`kernel32`/`ntdll` frente a una línea base tomada al arrancar (hooks inline) + hash FNV-1a de las secciones ejecutables de la imagen | ídem |
| Cambios en memoria ejecutable | `lab_execmem` | hash de regiones `PAGE_EXECUTE_READ` y `PAGE_EXECUTE_READWRITE` propias + `.text`; comando `selfmod rwx\|rx` | ídem |
| Uso de `PAGE_GUARD` | `lab_guard` | `VirtualProtect(PAGE_GUARD)` + **VEH** (`AddVectoredExceptionHandler`) que registra cada `STATUS_GUARD_PAGE_VIOLATION` (tipo de acceso, dirección, RIP y módulo) | `--rearm`, `--oneshot` |
| EAF (emulado) | `lab_guard --eaf-emulate` | `PAGE_GUARD` sobre las páginas de la **tabla de exportación** de kernel32/kernelbase/ntdll con rearmado por single-step; viola el acceso desde módulos que no son de sistema | `--eaf-lazy` (armar bajo demanda) |
| EAF (real) | `lab_guard` + `scripts\eaf_enable.ps1` | Exploit Protection oficial: `Set-ProcessMitigation -Name lab_guard_<arch>.exe -Enable EnableExportAddressFilter` (**requiere elevación**: escribe IFEO en HKLM) | `run_matrix.py --scenarios eaf_real` (se omite si no está configurado) |
| Mitigaciones de Windows | `lab_mitigated` | **dentro del proceso**: `SetProcessMitigationPolicy` (`ProcessDynamicCodePolicy`, `ProcessSignaturePolicy`, `ProcessImageLoadPolicy`, `ProcessExtensionPointDisablePolicy`, `ProcessStrictHandleCheckPolicy`, `ProcessControlFlowGuardPolicy`, `ProcessChildProcessPolicy`); **al arrancar**: `CreateProcess` + `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` | `--policy=…`; `labrun.MIT[...]` |
| Terminación deliberada | `lab_terminator` | `ExitProcess`, `TerminateProcess`, violación de acceso, `__fastfail`; por detección (`--detectors=…`) o por temporizador (control sin detección) | `--on-detect`, `--die-after-ms`, `--die-mode` |
| Cambios dinámicos de permisos / liberación | `lab_memdyn` | hilo que alterna `PAGE_READWRITE`↔`PAGE_READONLY`, `VirtualFree`/`VirtualAlloc` en la **misma dirección** y rearma `PAGE_GUARD` cada N ms | `--churn-ms` |
| Control | `lab_baseline` | ninguna protección | — |

Opciones comunes (`src/labkit.h`): `--net` (tráfico TCP loopback propio con `send`/`recv` de ws2_32 para probar el
agente de red), `--on-detect=report|exit|terminate|crash|failfast`, `--grace-ms`, `--interval-ms`,
`--max-seconds`. Protocolo: una línea JSON por evento en stdout (`ready`, `detect`, `terminating`, `guard-hit`, …);
comandos por stdin (`status`, `query`, `free`, `realloc`, `ro`, `rw`, `exit`, …).

**Regiones de prueba** (todas dentro del propio proceso): `two` (RW|RO), `freeme` (64 KB liberables), `flip`
(RW↔RO), `guard` (`PAGE_GUARD`), `edge` (RW seguida de guard), `tail` (escalares), `pattern` (64 KB con
contenido conocido `(i*31+7)&0xFF` para verificar la integridad de las lecturas), `rx` y `rwx`.

## 3. Mitigaciones de arranque (constantes oficiales de `winbase.h`)

| Nombre (`labrun.MIT`) | policy1 | policy2 |
|---|---|---|
| `no_dyncode` | `PROHIBIT_DYNAMIC_CODE_ALWAYS_ON` = `1<<36` | — |
| `ms_signed_only` | `BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` = `1<<44` | — |
| `no_remote_images` | `IMAGE_LOAD_NO_REMOTE` (`1<<52`) + `IMAGE_LOAD_PREFER_SYSTEM32` (`1<<60`) | — |
| `cet_shadow_stack` | — | `CET_USER_SHADOW_STACKS_ALWAYS_ON` = `1<<28` |
| `strict_cfg` | `CONTROL_FLOW_GUARD_ALWAYS_ON` = `1<<40` | `STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON` = `1<<8` |
| `module_tampering` | — | `MODULE_TAMPERING_PROTECTION_ALWAYS_ON` = `1<<12` |
| `combo` | dyncode + firmadas-MS + sin imágenes remotas + handles estrictos (`1<<24`) + sin extension points (`1<<32`) | CFG estricto + module tampering |

`lab_mitigated` se enlaza con `/guard:cf /CETCOMPAT /DYNAMICBASE`. Cada mitigación se **verifica** con
`GetProcessMitigationPolicy` desde dentro del proceso (evento `mitigations`) y con `Get-ProcessMitigation -Id`
desde fuera. Cuando `ProhibitDynamicCode` impide crear memoria ejecutable, el laboratorio lo informa
(`exec_regions_ok=0`) en lugar de caer.

La lista completa de escenarios con sus argumentos exactos está en `docs/FASE3_SCENARIOS.md` (generada).
