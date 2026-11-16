# Fase 3 — Resultados medidos de la matriz de protecciones

_Generado automáticamente por `tests/protection_lab/run_matrix.py --report` el 2026-11-09 19:34 a partir de `matrix.json` (240 casos)._

Cada caso = escenario × arquitectura (x64/x86) × agentes (**memoria**: solo `memory.js`, sin hooks; **red**: solo `agent.js`; **ambos**) × modo (attach/spawn). Cada caso corre en un proceso Python propio. Los tiempos son de esta máquina y orientativos.

## 1. Resumen de resultados

| Resultado | Casos |
|---|---|
| ok | 173 |
| session_lost | 39 |
| attach_blocked | 12 |
| attach_timeout | 7 |
| skipped | 6 |
| attach_failed | 2 |
| agent_failed | 1 |

- **NetScope**: 0 caídas/errores del arnés, 0 casos con excepciones no normalizadas (fuera de `MemoryError`/`SessionError`).
- **Integridad de lecturas**: 5991 lecturas de 64 KB comparadas con el patrón, 0 casos con discrepancias; escalares incorrectos en 0 casos.
- **Cambios involuntarios de protecciones** (VirtualQuery antes/después): 0 casos.

## 2a. Resultado por escenario — modo attach

### x64

| Escenario | Agente de memoria | Agente de red | Ambos | Objetivo vivo (mem/red/ambos) | Detecciones del objetivo |
|---|---|---|---|---|---|
| baseline | ok 0.22s | ok 0.24s | ok 0.24s | sí/sí/sí | — |
| isdebugger | ok 0.22s | ok 0.26s | ok 0.24s | sí/sí/sí | — |
| remotedbg | ok 0.24s | ok 0.24s | ok 0.24s | sí/sí/sí | — |
| ntquery | ok 0.22s | ok 0.25s | ok 0.27s | sí/sí/sí | — |
| integrity_report | ok 0.22s | ok 0.23s (detecta) | ok 0.24s (detecta) | sí/sí/sí | inline-hook |
| integrity_exit | ok 0.22s | sesión perdida 0.23s | sesión perdida 0.23s | sí/no/no | inline-hook |
| instrumentation_report | ok 0.23s (detecta) | ok 0.23s (detecta) | ok 0.24s (detecta) | sí/sí/sí | instrumentation:named-pipe, instrumentation:thread-name |
| instrumentation_exit | agente falló 0.25s | attach falló | attach falló | no/no/no | instrumentation:named-pipe |
| execmem_report | ok 0.22s (detecta) | ok 0.24s | ok 0.23s (detecta) | sí/sí/sí | executable-memory-change |
| execmem_exit | sesión perdida 0.22s | ok 0.22s | sesión perdida 0.23s | no/sí/no | executable-memory-change |
| guard | ok 0.23s | ok 0.23s | ok 0.23s | sí/sí/sí | — |
| guard_rearm | ok 0.22s | ok 0.22s | ok 0.23s | sí/sí/sí | — |
| eaf_emulated_armed | attach evitado 0.02s | attach evitado 0.02s | attach evitado 0.02s | sí/sí/sí | — |
| eaf_emulated_oneshot | attach evitado 0.02s | attach evitado 0.02s | attach evitado 0.02s | sí/sí/sí | — |
| terminator_timer | ok 0.23s | ok 0.23s | ok 0.23s | sí/sí/sí | — |
| terminator_crash | ok 0.23s | ok 0.23s | ok 0.25s | sí/sí/sí | — |
| terminator_failfast | ok 0.23s | ok 0.24s | ok 0.22s | sí/sí/sí | — |
| terminator_debug | ok 0.21s | ok 0.23s | ok 0.23s | sí/sí/sí | — |
| terminator_all | sesión perdida 0.23s | sesión perdida 0.23s | attach colgado 12.03s | no/no/no | instrumentation:named-pipe |
| memdyn | ok 0.22s | ok 0.22s | ok 0.22s | sí/sí/sí | — |
| mit_inproc_dyncode | ok 0.22s | ok 0.23s | ok 0.23s | sí/sí/sí | — |
| mit_inproc_signature | ok 0.22s | ok 0.22s | ok 0.24s | sí/sí/sí | — |
| mit_inproc_all | ok 0.23s | ok 0.27s | ok 0.23s | sí/sí/sí | — |
| mit_create_no_dyncode | ok 0.23s | ok 0.26s | ok 0.25s | sí/sí/sí | — |
| mit_create_ms_signed | ok 0.22s | ok 0.23s | ok 0.23s | sí/sí/sí | — |
| mit_create_no_remote | ok 0.22s | ok 0.23s | ok 0.23s | sí/sí/sí | — |
| mit_create_cet | ok 0.22s | ok 0.24s | ok 0.23s | sí/sí/sí | — |
| mit_create_strict_cfg | ok 0.22s | ok 0.24s | ok 0.23s | sí/sí/sí | — |
| mit_create_module_tamper | ok 0.23s | ok 0.23s | ok 0.23s | sí/sí/sí | — |
| mit_create_combo | ok 0.22s | ok 0.24s | ok 0.24s | sí/sí/sí | — |
| eaf_real | omitido | omitido | omitido | —/—/— | — |

### x86

| Escenario | Agente de memoria | Agente de red | Ambos | Objetivo vivo (mem/red/ambos) | Detecciones del objetivo |
|---|---|---|---|---|---|
| baseline | ok 0.51s | ok 0.64s | ok 0.53s | sí/sí/sí | — |
| isdebugger | ok 0.53s | ok 0.55s | ok 0.54s | sí/sí/sí | — |
| remotedbg | ok 0.59s | ok 0.62s | ok 0.59s | sí/sí/sí | — |
| ntquery | ok 0.61s | ok 0.55s | ok 0.57s | sí/sí/sí | — |
| integrity_report | ok 0.56s | ok 0.52s (detecta) | ok 0.56s (detecta) | sí/sí/sí | inline-hook |
| integrity_exit | ok 0.52s | sesión perdida 0.53s | sesión perdida 0.52s | sí/no/no | inline-hook |
| instrumentation_report | ok 0.69s (detecta) | ok 0.66s (detecta) | ok 0.57s (detecta) | sí/sí/sí | instrumentation:named-pipe, instrumentation:thread-name |
| instrumentation_exit | attach colgado 12.03s | attach colgado 12.03s | attach colgado 12.04s | no/no/no | instrumentation:named-pipe |
| execmem_report | ok 0.53s (detecta) | ok 0.53s | ok 0.53s (detecta) | sí/sí/sí | executable-memory-change |
| execmem_exit | sesión perdida 0.51s | ok 0.51s | sesión perdida 0.56s | no/sí/no | executable-memory-change |
| guard | ok 0.53s | ok 0.53s | ok 0.52s | sí/sí/sí | — |
| guard_rearm | ok 0.51s | ok 0.51s | ok 0.53s | sí/sí/sí | — |
| eaf_emulated_armed | attach evitado 0.03s | attach evitado 0.02s | attach evitado 0.02s | sí/sí/sí | — |
| eaf_emulated_oneshot | attach evitado 0.02s | attach evitado 0.03s | attach evitado 0.02s | sí/sí/sí | — |
| terminator_timer | sesión perdida 0.52s | sesión perdida 0.53s | sesión perdida 0.52s | no/no/no | — |
| terminator_crash | ok 0.52s | ok 0.52s | sesión perdida 0.53s | sí/sí/no | — |
| terminator_failfast | sesión perdida 0.51s | sesión perdida 0.66s | sesión perdida 0.53s | no/no/no | — |
| terminator_debug | ok 0.53s | ok 0.51s | ok 0.54s | sí/sí/sí | — |
| terminator_all | attach colgado 12.03s | attach colgado 12.03s | attach colgado 12.03s | no/no/no | instrumentation:named-pipe |
| memdyn | ok 0.52s | ok 0.51s | ok 0.53s | sí/sí/sí | — |
| mit_inproc_dyncode | ok 0.51s | ok 0.54s | ok 0.53s | sí/sí/sí | — |
| mit_inproc_signature | ok 0.56s | ok 0.53s | ok 0.70s | sí/sí/sí | — |
| mit_inproc_all | ok 0.52s | ok 0.54s | ok 0.54s | sí/sí/sí | — |
| mit_create_no_dyncode | ok 0.55s | ok 0.53s | ok 0.57s | sí/sí/sí | — |
| mit_create_ms_signed | ok 0.58s | ok 0.52s | ok 0.54s | sí/sí/sí | — |
| mit_create_no_remote | ok 0.58s | ok 0.63s | ok 0.55s | sí/sí/sí | — |
| mit_create_cet | ok 0.53s | ok 0.55s | ok 0.62s | sí/sí/sí | — |
| mit_create_strict_cfg | ok 0.52s | ok 0.52s | ok 0.55s | sí/sí/sí | — |
| mit_create_module_tamper | ok 0.60s | ok 0.52s | ok 0.53s | sí/sí/sí | — |
| mit_create_combo | ok 0.52s | ok 0.53s | ok 0.55s | sí/sí/sí | — |
| eaf_real | omitido | omitido | omitido | —/—/— | — |

## 2b. Resultado por escenario — modo spawn

### x64

| Escenario | Agente de memoria | Agente de red | Ambos | Objetivo vivo (mem/red/ambos) | Detecciones del objetivo |
|---|---|---|---|---|---|
| baseline | ok 0.17s | ok 0.21s | ok 0.20s | sí/sí/sí | — |
| isdebugger | ok 0.18s | ok 0.18s | ok 0.17s | sí/sí/sí | — |
| integrity_report | ok 0.17s | ok 0.20s | ok 0.17s | sí/sí/sí | — |
| integrity_exit | ok 0.16s | ok 0.19s | ok 0.19s | sí/sí/sí | — |
| instrumentation_report | ok 0.17s (detecta) | ok 0.17s (detecta) | ok 0.17s (detecta) | sí/sí/sí | instrumentation:named-pipe, instrumentation:thread-name |
| instrumentation_exit | sesión perdida 0.16s | sesión perdida 0.17s | sesión perdida 0.17s | no/no/no | instrumentation:thread-name |
| terminator_debug | sesión perdida 0.16s | sesión perdida 0.17s | sesión perdida 0.17s | no/no/no | NtQueryInformationProcess.DebugFlags |
| terminator_all | sesión perdida 0.17s | sesión perdida 0.18s | sesión perdida 0.17s | no/no/no | NtQueryInformationProcess.DebugFlags |
| mit_inproc_dyncode | sesión perdida 0.17s | ok 0.17s | sesión perdida 0.17s | no/sí/no | — |

### x86

| Escenario | Agente de memoria | Agente de red | Ambos | Objetivo vivo (mem/red/ambos) | Detecciones del objetivo |
|---|---|---|---|---|---|
| baseline | ok 0.46s | ok 0.48s | ok 0.48s | sí/sí/sí | — |
| isdebugger | ok 0.46s | ok 0.50s | ok 0.52s | sí/sí/sí | — |
| integrity_report | ok 0.56s | ok 0.50s | ok 0.47s | sí/sí/sí | — |
| integrity_exit | ok 0.45s | ok 0.48s | ok 0.50s | sí/sí/sí | — |
| instrumentation_report | ok 0.49s (detecta) | ok 0.52s (detecta) | ok 0.49s (detecta) | sí/sí/sí | instrumentation:named-pipe, instrumentation:thread-name |
| instrumentation_exit | sesión perdida 0.46s | sesión perdida 0.47s | sesión perdida 0.47s | no/no/no | instrumentation:thread-name |
| terminator_debug | sesión perdida 0.46s | sesión perdida 0.47s | sesión perdida 0.47s | no/no/no | NtQueryInformationProcess.DebugFlags |
| terminator_all | sesión perdida 0.48s | sesión perdida 0.47s | sesión perdida 0.49s | no/no/no | NtQueryInformationProcess.DebugFlags |
| mit_inproc_dyncode | sesión perdida 0.45s | ok 0.46s | sesión perdida 0.48s | no/sí/no | — |

## 3. Rendimiento medido (mediana sobre casos con sesión estable)

| Agentes | attach (s) | carga agente memoria (s) | lectura 64 KB (ms) | escritura+rollback (ms) | casos |
|---|---|---|---|---|---|
| memory | 0.24 | 0.02 | 10.17 | 17.03 | 48 |
| network | 0.27 | None | None | None | 48 |
| both | 0.25 | 0.01 | 10.13 | 16.86 | 45 |

Spawn (objetivo suspendido, instrumentación antes del primer código): attach mediana 0.33 s, spawn→ready 0.0 s.

## 4. Funcionamiento simultáneo memoria + red

- Casos “ambos” con sesión estable: 55; con operaciones de memoria **y** tráfico de red capturado a la vez: 55.
- Mensajes del objetivo observados por el agente de red durante el trabajo de memoria: mediana 52 (el objetivo envió 28).

## 5. Verdad de terreno del objetivo vs diagnóstico de NetScope

| Escenario | Arq | Agentes | Qué hizo el objetivo | Hallazgos de NetScope (mecanismo: veredicto) |
|---|---|---|---|---|
| integrity_report | x64 | network | detectó: inline-hook | — |
| integrity_report | x64 | both | detectó: inline-hook | guard-page: confirmed |
| integrity_report | x86 | network | detectó: inline-hook | — |
| integrity_report | x86 | both | detectó: inline-hook | guard-page: confirmed |
| integrity_exit | x64 | network | detectó: inline-hook; terminó: ExitProcess por inline-hook; código 0x00000003 | termination-after-instrumentation: indication |
| integrity_exit | x64 | both | detectó: inline-hook; terminó: ExitProcess por inline-hook; código 0x00000003 | guard-page: confirmed; termination-after-instrumentation: indication |
| integrity_exit | x86 | network | detectó: inline-hook; terminó: ExitProcess por inline-hook; código 0x00000003 | termination-after-instrumentation: indication |
| integrity_exit | x86 | both | detectó: inline-hook; terminó: ExitProcess por inline-hook; código 0x00000003 | guard-page: confirmed; termination-after-instrumentation: indication |
| instrumentation_report | x64 | memory | detectó: instrumentation:named-pipe, instrumentation:thread-name | guard-page: confirmed |
| instrumentation_report | x64 | network | detectó: instrumentation:named-pipe, instrumentation:thread-name | — |
| instrumentation_report | x64 | both | detectó: instrumentation:named-pipe, instrumentation:thread-name | guard-page: confirmed |
| instrumentation_report | x86 | memory | detectó: instrumentation:named-pipe, instrumentation:thread-name | guard-page: confirmed |
| instrumentation_report | x86 | network | detectó: instrumentation:named-pipe, instrumentation:thread-name | — |
| instrumentation_report | x86 | both | detectó: instrumentation:named-pipe, instrumentation:thread-name | guard-page: confirmed |
| instrumentation_exit | x64 | memory | detectó: instrumentation:named-pipe; terminó: TerminateProcess por instrumentation:named-pipe; código 0x00000004 | agent-failure:memory: unknown; termination-after-instrumentation: indication |
| instrumentation_exit | x64 | network | detectó: instrumentation:named-pipe; terminó: TerminateProcess por instrumentation:named-pipe; código 0x00000004 | attach-failure:ProcessNotRespondingError: unknown |
| instrumentation_exit | x64 | both | detectó: instrumentation:named-pipe; terminó: TerminateProcess por instrumentation:named-pipe; código 0x00000004 | agent-failure:network: unknown; termination-after-instrumentation: indication |
| instrumentation_exit | x86 | memory | detectó: instrumentation:named-pipe; terminó: TerminateProcess por instrumentation:named-pipe; código 0x00000004 | attach-timeout: unknown |
| instrumentation_exit | x86 | network | detectó: instrumentation:named-pipe; terminó: TerminateProcess por instrumentation:named-pipe; código 0x00000004 | attach-timeout: unknown |
| instrumentation_exit | x86 | both | detectó: instrumentation:named-pipe; terminó: TerminateProcess por instrumentation:named-pipe; código 0x00000004 | attach-timeout: unknown |
| execmem_report | x64 | memory | detectó: executable-memory-change | exec-memory-write: confirmed; guard-page: confirmed |
| execmem_report | x64 | both | detectó: executable-memory-change | exec-memory-write: confirmed; guard-page: confirmed |
| execmem_report | x86 | memory | detectó: executable-memory-change | exec-memory-write: confirmed; guard-page: confirmed |
| execmem_report | x86 | both | detectó: executable-memory-change | exec-memory-write: confirmed; guard-page: confirmed |
| execmem_exit | x64 | memory | detectó: executable-memory-change; terminó: ExitProcess por executable-memory-change; código 0x00000003 | exec-memory-write: confirmed; guard-page: confirmed; termination-after-instrumentation: indication |
| execmem_exit | x64 | both | detectó: executable-memory-change; terminó: ExitProcess por executable-memory-change; código 0x00000003 | exec-memory-write: confirmed; guard-page: confirmed; termination-after-instrumentation: indication |
| execmem_exit | x86 | memory | detectó: executable-memory-change; terminó: ExitProcess por executable-memory-change; código 0x00000003 | exec-memory-write: confirmed; guard-page: confirmed; termination-after-instrumentation: indication |
| execmem_exit | x86 | both | detectó: executable-memory-change; terminó: ExitProcess por executable-memory-change; código 0x00000003 | exec-memory-write: confirmed; guard-page: confirmed; termination-after-instrumentation: indication |
| eaf_emulated_armed | x64 | memory | attach_blocked | export-table-guard: confirmed |
| eaf_emulated_armed | x64 | network | attach_blocked | export-table-guard: confirmed |
| eaf_emulated_armed | x64 | both | attach_blocked | export-table-guard: confirmed |
| eaf_emulated_armed | x86 | memory | attach_blocked | export-table-guard: confirmed |
| eaf_emulated_armed | x86 | network | attach_blocked | export-table-guard: confirmed |
| eaf_emulated_armed | x86 | both | attach_blocked | export-table-guard: confirmed |
| eaf_emulated_oneshot | x64 | memory | attach_blocked | export-table-guard: confirmed |
| eaf_emulated_oneshot | x64 | network | attach_blocked | export-table-guard: confirmed |
| eaf_emulated_oneshot | x64 | both | attach_blocked | export-table-guard: confirmed |
| eaf_emulated_oneshot | x86 | memory | attach_blocked | export-table-guard: confirmed |
| eaf_emulated_oneshot | x86 | network | attach_blocked | export-table-guard: confirmed |
| eaf_emulated_oneshot | x86 | both | attach_blocked | export-table-guard: confirmed |
| terminator_timer | x86 | memory | terminó: TerminateProcess por timer; código 0x00000004 | guard-page: confirmed; termination-after-instrumentation: indication |
| terminator_timer | x86 | network | terminó: TerminateProcess por timer; código 0x00000004 | session-lost: unknown |
| terminator_timer | x86 | both | terminó: TerminateProcess por timer; código 0x00000004 | guard-page: confirmed; termination-after-instrumentation: indication |
| terminator_crash | x64 | both | terminó: AccessViolation por timer | guard-page: confirmed |
| terminator_crash | x86 | memory | terminó: AccessViolation por timer | guard-page: confirmed |
| terminator_crash | x86 | network | terminó: AccessViolation por timer | — |
| terminator_crash | x86 | both | terminó: AccessViolation por timer; código 0xC0000005 | guard-page: confirmed; session-lost: unknown |
| terminator_failfast | x86 | memory | terminó: FastFail por timer; código 0xC0000409 | guard-page: confirmed; termination-after-instrumentation: indication |
| terminator_failfast | x86 | network | terminó: FastFail por timer; código 0xC0000409 | session-lost: unknown |
| terminator_failfast | x86 | both | terminó: FastFail por timer; código 0xC0000409 | guard-page: confirmed; termination-after-instrumentation: indication |
| terminator_all | x64 | memory | detectó: instrumentation:named-pipe; terminó: ExitProcess por instrumentation:named-pipe; código 0x00000003 | termination-after-instrumentation: indication |
| terminator_all | x64 | network | detectó: instrumentation:named-pipe; terminó: ExitProcess por instrumentation:named-pipe; código 0x00000003 | termination-after-instrumentation: indication |
| terminator_all | x64 | both | detectó: instrumentation:named-pipe; terminó: ExitProcess por instrumentation:named-pipe; código 0x00000003 | attach-timeout: unknown |
| terminator_all | x86 | memory | detectó: instrumentation:named-pipe; terminó: ExitProcess por instrumentation:named-pipe; código 0x00000003 | attach-timeout: unknown |
| terminator_all | x86 | network | detectó: instrumentation:named-pipe; terminó: ExitProcess por instrumentation:named-pipe; código 0x00000003 | attach-timeout: unknown |
| terminator_all | x86 | both | detectó: instrumentation:named-pipe; terminó: ExitProcess por instrumentation:named-pipe; código 0x00000003 | attach-timeout: unknown |

## 6. Mitigaciones de Windows (agentes por separado)

| Mitigación | Arq | Memoria | Red | ¿Hooks de red con errores? | Ping capturados (red/ambos) |
|---|---|---|---|---|---|
| mit_inproc_dyncode | x64 | ok 0.22s | ok 0.23s | False | 48/52 |
| mit_inproc_dyncode | x86 | ok 0.51s | ok 0.54s | False | 50/52 |
| mit_inproc_signature | x64 | ok 0.22s | ok 0.22s | False | 50/52 |
| mit_inproc_signature | x86 | ok 0.56s | ok 0.53s | False | 50/50 |
| mit_inproc_all | x64 | ok 0.23s | ok 0.27s | False | 50/52 |
| mit_inproc_all | x86 | ok 0.52s | ok 0.54s | False | 50/52 |
| mit_create_no_dyncode | x64 | ok 0.23s | ok 0.26s | False | 50/50 |
| mit_create_no_dyncode | x86 | ok 0.55s | ok 0.53s | False | 50/50 |
| mit_create_ms_signed | x64 | ok 0.22s | ok 0.23s | False | 52/52 |
| mit_create_ms_signed | x86 | ok 0.58s | ok 0.52s | False | 50/52 |
| mit_create_no_remote | x64 | ok 0.22s | ok 0.23s | False | 50/52 |
| mit_create_no_remote | x86 | ok 0.58s | ok 0.63s | False | 50/52 |
| mit_create_cet | x64 | ok 0.22s | ok 0.24s | False | 50/52 |
| mit_create_cet | x86 | ok 0.53s | ok 0.55s | False | 50/52 |
| mit_create_strict_cfg | x64 | ok 0.22s | ok 0.24s | False | 50/50 |
| mit_create_strict_cfg | x86 | ok 0.52s | ok 0.52s | False | 50/52 |
| mit_create_module_tamper | x64 | ok 0.23s | ok 0.23s | False | 50/50 |
| mit_create_module_tamper | x86 | ok 0.60s | ok 0.52s | False | 50/50 |
| mit_create_combo | x64 | ok 0.22s | ok 0.24s | False | 50/50 |
| mit_create_combo | x86 | ok 0.52s | ok 0.53s | False | 50/52 |

## 7. Anomalías y notas por caso

- `integrity_exit` x64/both/attach: read_pattern: sesión perdida (script has been destroyed)
- `integrity_exit` x86/both/attach: rollback: sesión perdida (script has been destroyed)
- `instrumentation_exit` x64/memory/attach: memory_engine: TransportError: the connection is closed
- `instrumentation_exit` x64/network/attach: ProcessNotRespondingError: process with pid 28928 either refused to load frida-agent, or terminated during injection
- `instrumentation_exit` x64/both/attach: TransportError: the connection is closed
- `instrumentation_exit` x64/memory/spawn: read_pattern: sesión perdida (script has been destroyed)
- `instrumentation_exit` x64/both/spawn: read_pattern: sesión perdida (script has been destroyed)
- `instrumentation_exit` x86/memory/attach: El attach no respondió en el tiempo límite. Sin otra evidencia, la causa es desconocida (no se declara anti-debug).
- `instrumentation_exit` x86/network/attach: El attach no respondió en el tiempo límite. Sin otra evidencia, la causa es desconocida (no se declara anti-debug).
- `instrumentation_exit` x86/both/attach: El attach no respondió en el tiempo límite. Sin otra evidencia, la causa es desconocida (no se declara anti-debug).
- `instrumentation_exit` x86/both/spawn: scalar_u32: sesión perdida (script has been destroyed)
- `execmem_exit` x64/memory/attach: read_pattern: sesión perdida (process-terminated)
- `execmem_exit` x64/both/attach: read_pattern: sesión perdida (process-terminated)
- `eaf_emulated_armed` x64/memory/attach: Attach evitado: guardas armadas sobre la tabla de exportación. Intentarlo dejaría Frida colgado.
- `eaf_emulated_armed` x64/network/attach: Attach evitado: guardas armadas sobre la tabla de exportación. Intentarlo dejaría Frida colgado.
- `eaf_emulated_armed` x64/both/attach: Attach evitado: guardas armadas sobre la tabla de exportación. Intentarlo dejaría Frida colgado.
- `eaf_emulated_oneshot` x64/memory/attach: Attach evitado: guardas armadas sobre la tabla de exportación. Intentarlo dejaría Frida colgado.
- `eaf_emulated_oneshot` x64/network/attach: Attach evitado: guardas armadas sobre la tabla de exportación. Intentarlo dejaría Frida colgado.
- `eaf_emulated_oneshot` x64/both/attach: Attach evitado: guardas armadas sobre la tabla de exportación. Intentarlo dejaría Frida colgado.
- `terminator_timer` x86/memory/attach: write: sesión perdida (script has been destroyed)
- `terminator_timer` x86/both/attach: read_guard: sesión perdida (script has been destroyed)
- `terminator_crash` x86/both/attach: write: sesión perdida (script has been destroyed)
- `terminator_failfast` x86/memory/attach: read_guard: sesión perdida (script has been destroyed)
- `terminator_failfast` x86/both/attach: read_pattern: sesión perdida (script has been destroyed)
- `terminator_debug` x64/memory/spawn: read_pattern: sesión perdida (script has been destroyed)
- `terminator_debug` x64/both/spawn: read_pattern: sesión perdida (script has been destroyed)
- `terminator_all` x64/memory/attach: write: sesión perdida (script has been destroyed)
- `terminator_all` x64/both/attach: El attach no respondió en el tiempo límite. Sin otra evidencia, la causa es desconocida (no se declara anti-debug).
- `terminator_all` x64/memory/spawn: scalar_u32: sesión perdida (script has been destroyed)
- `terminator_all` x64/both/spawn: scalar_u32: sesión perdida (script has been destroyed)
- `terminator_all` x86/memory/attach: El attach no respondió en el tiempo límite. Sin otra evidencia, la causa es desconocida (no se declara anti-debug).
- `terminator_all` x86/network/attach: El attach no respondió en el tiempo límite. Sin otra evidencia, la causa es desconocida (no se declara anti-debug).
- `terminator_all` x86/memory/spawn: read_pattern: sesión perdida (process-terminated)
- `terminator_all` x86/both/spawn: read_pattern: sesión perdida (script has been destroyed)
- `mit_inproc_dyncode` x64/memory/spawn: write: sesión perdida (script has been destroyed)
- `mit_inproc_dyncode` x64/both/spawn: write: sesión perdida (script has been destroyed)
- `eaf_real` x64/memory/attach: EAF real no configurado (requiere elevación: scripts\eaf_enable.ps1)
- `eaf_real` x64/network/attach: EAF real no configurado (requiere elevación: scripts\eaf_enable.ps1)
- `eaf_real` x64/both/attach: EAF real no configurado (requiere elevación: scripts\eaf_enable.ps1)
