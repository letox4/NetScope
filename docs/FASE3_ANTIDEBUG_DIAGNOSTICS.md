# Fase 3 — Motor de diagnóstico de protecciones (anti-debug)

Subsistema **independiente** (`core/antidebug/`) que informa de qué mecanismo de protección se detecta, con qué
evidencia y qué implica para la sesión Frida y para las operaciones de memoria. **No implementa evasión ni
ocultación**: solo mide e informa.

## 1. Veredictos (criterio explícito)

| Veredicto | Cuándo se usa | Ejemplo |
|---|---|---|
| **CONFIRMED** (detección confirmada) | Hay una **medición directa y falsable** de ese mecanismo en el objetivo/SO | `PAGE_GUARD` visto con `VirtualQueryEx` sobre la tabla de exportación; prólogo distinto del disco; mitigación activa según `Get-ProcessMitigation`; una API anti-debug **observada** invocándose |
| **INDICATION** (indicio) | Compatible con el mecanismo pero **no exclusivo** | Imports de `IsDebuggerPresent`; terminación ≤ 2 s después de un paso de instrumentación; attach colgado **con** guardas EAT medidas |
| **UNKNOWN** (desconocido) | No se puede atribuir causa | Fallo de attach, cuelgue sin evidencia, sesión perdida sin correlación |

Regla dura: **un fallo de attach, un cuelgue o una sesión perdida nunca se declaran anti-debug por sí solos**. Se
informa `UNKNOWN` con la lista de causas posibles (proceso protegido/PPL, elevación, política de Windows,
protección del programa —no demostrada—, proceso terminado).

`Finding.kind` separa **qué** se afirma: `protection` (mecanismo presente en el objetivo), `footprint` (huella que deja
**nuestra** instrumentación), `environment` (política de Windows), `failure` (resultado de una operación).

## 2. Campos de cada hallazgo (los pedidos)

`mechanism` · `evidence[]` (tipo, detalle, fuente/API) · `detected_at` y `t_since_attach` (momento) · `session_effect`
(efecto sobre la sesión Frida) · `memory_ops_affected[]` · `agents_affected[]` (memoria/red) · `can_continue` +
`can_continue_note` (posibilidad de continuar) · `limitations[]` (limitaciones del método de instrumentación).
`DiagnosticReport.render_text()` los imprime; `to_dict()` los serializa a JSON.

## 3. Fuentes de evidencia y qué pueden/no pueden demostrar

| Fuente | Módulo | Invasividad | Veredicto máximo | Limitación principal |
|---|---|---|---|---|
| `OpenProcess` / `NtQueryInformationProcess(61)` / token | `preflight.inspect_process` | ninguna | CONFIRMED (entorno) | no dice *por qué* un proceso ajeno está denegado |
| `VirtualQueryEx` sobre la EAT de ntdll/kernel32/kernelbase | `preflight.scan_export_guards` | ninguna | CONFIRMED (guarda armada) | confirma la guarda, no quién la puso (EAF real, otra herramienta, el programa) |
| `Get-ProcessMitigation -Id / -Name` | `preflight.mitigations_of_*` | ninguna | CONFIRMED (política) | PowerShell: ~0,3 s; solo lectura |
| Prólogos/código en memoria vs. fichero PE (máscara de relocaciones) | `footprint.scan_inline_hooks / scan_module_code` | lee código con la ruta segura | CONFIRMED (huella) | no identifica al autor del parche; solo funciones/módulos examinados |
| Hilos con nombre y tuberías `frida-*` | `preflight.frida_thread_footprint / frida_pipes` | ninguna | CONFIRMED (huella) | que un objetivo los **busque** no se demuestra |
| Imports anti-debug de módulos no-Windows | `probe.scan_imports` (JS pasivo) | ninguna | INDICATION | no prueba que se use; `GetProcAddress`/syscalls no aparecen |
| Observador de APIs (`Interceptor`, solo lectura) | `probe.observe/collect` (opt-in) | **parchea prólogos** (efecto del observador) | CONFIRMED (uso del mecanismo) | no demuestra reacción; es detectable por integridad |
| `detached` + línea temporal + `GetExitCodeProcess` | `on_session_lost` | ninguna | INDICATION | correlación ≠ causalidad |
| Errores del motor de memoria (`E_PAGE_GUARD`, …) | `on_memory_error` | ninguna | CONFIRMED (página protegida) | la lectura se **rechaza**, no se evade |

## 4. Integración

* `FridaInterceptor.diagnostics` (instancia por interceptor). `attach()` ejecuta el **preflight** (rápido, sin
  PowerShell) y, si detecta guardas armadas sobre la EAT, lanza `AttachBlockedError` con el informe **en vez de
  colgarse** (ver `docs/FASE3_PAGE_GUARD_EAF.md`). `attach_timeout` (20 s) es la red de seguridad
  (`AttachTimeoutError`).
* `detached` de Frida → `on_session_lost`; el motor de memoria notifica escrituras en código y lecturas rechazadas.
* `attach(network_agent=False)` carga solo el agente de memoria (sin hooks) para evaluar los agentes por separado.
* GUI: pestaña **Protecciones**. CLI: `py -3.11 -m core.antidebug --pid N [--deep] [--footprint] [--observe 5]`.

## 5. Limitaciones conocidas

* **EAF real sin elevación**: el EAF real requiere configurar IFEO en HKLM (admin). El comportamiento se verificó con
  una **emulación** equivalente (`lab_guard --eaf-emulate`); `scripts\eaf_enable.ps1` + `--scenarios eaf_real` lo
  prueba con el mecanismo oficial cuando se ejecuta elevado.
* Un attach colgado **contamina** los siguientes attach del mismo proceso Python (limitación de Frida): por eso el
  preflight evita el intento y el timeout es solo respaldo.
* PPL / procesos protegidos / otros usuarios: se **informa**, no se supera.
* La huella no se oculta: ocultarla sería evasión (fuera de alcance).
