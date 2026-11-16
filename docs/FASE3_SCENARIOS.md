# Fase 3 — Escenarios del laboratorio (configuración exacta)

_Generado por `tests/protection_lab/run_matrix.py --scenarios-md`; es la misma tabla que ejecuta la matriz, así que no puede desincronizarse._

Los ejecutables están en `tests/protection_lab/bin/<nombre>_<x64|x86>.exe` (`tests\protection_lab\build.ps1`). Todos aceptan además `--max-seconds=N` (vigilante, 300 por defecto) e `--interval-ms=N`.

| Escenario | Ejecutable y argumentos | Mitigaciones de arranque (CreateProcess) | Qué reproduce | Esperado |
|---|---|---|---|---|
| `baseline` (también spawn) | `lab_baseline_<arch>.exe --net` | — | Control: sin ninguna protección. | todo OK en los tres modos |
| `isdebugger` (también spawn) | `lab_isdebugger_<arch>.exe --net` | — | IsDebuggerPresent() cada 50 ms. | Frida no activa BeingDebugged: sin detección |
| `remotedbg` | `lab_remotedbg_<arch>.exe --net` | — | CheckRemoteDebuggerPresent(GetCurrentProcess()) cada 50 ms. | sin detección |
| `ntquery` | `lab_ntquery_<arch>.exe --net` | — | NtQueryInformationProcess(DebugPort 7, DebugObjectHandle 0x1E, DebugFlags 0x1F) + PEB.BeingDebugged. | sin detección |
| `integrity_report` (también spawn) | `lab_integrity_<arch>.exe --net --on-detect=report` | — | Compara prólogos de ws2_32/kernel32/ntdll con una línea base y hashea .text; solo informa. | con agente de red: detecta hooks inline; solo memoria: nada |
| `integrity_exit` (también spawn) | `lab_integrity_<arch>.exe --net --on-detect=exit --grace-ms=200` | — | Igual, pero ExitProcess(3) al detectar un hook. | con agente de red el objetivo termina; solo memoria: sobrevive |
| `instrumentation_report` (también spawn) | `lab_instrumentation_<arch>.exe --net --on-detect=report --interval-ms=100` | — | Busca artefactos de Frida: módulos, nombres de hilo, tuberías, cadenas en memoria; solo informa. | detecta hilos gmain/gdbus/gum-js-loop y tubería frida-* con CUALQUIER agente |
| `instrumentation_exit` (también spawn) | `lab_instrumentation_<arch>.exe --net --on-detect=terminate --interval-ms=100` | — | Igual, pero TerminateProcess al detectar un artefacto. | el objetivo termina con cualquier agente |
| `execmem_report` | `lab_execmem_<arch>.exe --net --on-detect=report` | — | Hashea .text y sus regiones RX/RWX; solo informa. NetScope escribe 1 byte en la región RWX. | detecta la escritura de NetScope en memoria ejecutable |
| `execmem_exit` | `lab_execmem_<arch>.exe --net --on-detect=exit --grace-ms=100` | — | Igual, pero ExitProcess al detectar el cambio. | la escritura en RWX termina el objetivo |
| `guard` | `lab_guard_<arch>.exe --net` | — | Páginas PAGE_GUARD + VEH que cuenta cada acceso. | NetScope no consume ninguna guarda |
| `guard_rearm` | `lab_guard_<arch>.exe --net --rearm` | — | Igual, con rearmado de guarda tras cada acceso (single-step). | sin accesos de NetScope |
| `eaf_emulated_armed` | `lab_guard_<arch>.exe --net --eaf-emulate` | — | Guardas PAGE_GUARD rearmadas sobre la EAT de kernel32/kernelbase/ntdll (emulación de EAF). | preflight evita el attach (se colgaría) |
| `eaf_emulated_oneshot` | `lab_guard_<arch>.exe --net --eaf-emulate --oneshot --interval-ms=20` | — | Guardas EAT de un solo disparo (el propio objetivo las consume al instante). | attach posible |
| `terminator_timer` | `lab_terminator_<arch>.exe --net --die-after-ms=3000 --die-mode=terminate` | — | Control: TerminateProcess a los 3 s SIN detectar nada. | sesión perdida sin detección; no debe llamarse anti-debug |
| `terminator_crash` | `lab_terminator_<arch>.exe --net --die-after-ms=3000 --die-mode=crash` | — | Control: violación de acceso (crash) a los 3 s. | Frida informa crash |
| `terminator_failfast` | `lab_terminator_<arch>.exe --net --die-after-ms=3000 --die-mode=failfast` | — | Control: __fastfail a los 3 s. | código de salida 0xC0000409 |
| `terminator_debug` (también spawn) | `lab_terminator_<arch>.exe --net --detectors=debug --on-detect=exit` | — | Termina si ve IsDebuggerPresent/CheckRemote/NtQuery*/PEB. | sobrevive: Frida no es un depurador |
| `terminator_all` (también spawn) | `lab_terminator_<arch>.exe --net --detectors=all --on-detect=exit --grace-ms=50` | — | Termina ante cualquier detector (depuración, integridad, instrumentación, ejecutable). | termina con cualquier agente (artefactos de hilo/tubería de Frida) |
| `memdyn` | `lab_memdyn_<arch>.exe --net --churn-ms=15` | — | Cambia permisos RW<->RO, libera/reasigna regiones y rearma guardas cada 15 ms. | errores limpios; sin caída; patrón íntegro |
| `mit_inproc_dyncode` (también spawn) | `lab_mitigated_<arch>.exe --net --policy=dyncode` | — | SetProcessMitigationPolicy(ProcessDynamicCodePolicy) al arrancar. | ver resultados |
| `mit_inproc_signature` | `lab_mitigated_<arch>.exe --net --policy=signature` | — | SetProcessMitigationPolicy(ProcessSignaturePolicy: solo firmadas por Microsoft). | ver resultados |
| `mit_inproc_all` | `lab_mitigated_<arch>.exe --net --policy=all` | — | Todas las políticas aplicables en el propio proceso (dyncode, signature, imageload, extpoint, handle, cfg, childproc). | ver resultados |
| `mit_create_no_dyncode` | `lab_mitigated_<arch>.exe --net` | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` = [`0x0000001000000000`, `0x0000000000000000`] (`MIT["no_dyncode"]`) | CreateProcess + PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: PROHIBIT_DYNAMIC_CODE_ALWAYS_ON. | ver resultados |
| `mit_create_ms_signed` | `lab_mitigated_<arch>.exe --net` | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` = [`0x0000100000000000`, `0x0000000000000000`] (`MIT["ms_signed_only"]`) | BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON desde el arranque. | ver resultados |
| `mit_create_no_remote` | `lab_mitigated_<arch>.exe --net` | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` = [`0x1010000000000000`, `0x0000000000000000`] (`MIT["no_remote_images"]`) | IMAGE_LOAD_NO_REMOTE + IMAGE_LOAD_PREFER_SYSTEM32. | ver resultados |
| `mit_create_cet` | `lab_mitigated_<arch>.exe --net` | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` = [`0x0000000000000000`, `0x0000000010000000`] (`MIT["cet_shadow_stack"]`) | POLICY2 CET_USER_SHADOW_STACKS_ALWAYS_ON (pilas sombra). | ver resultados |
| `mit_create_strict_cfg` | `lab_mitigated_<arch>.exe --net` | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` = [`0x0000010000000000`, `0x0000000000000100`] (`MIT["strict_cfg"]`) | CONTROL_FLOW_GUARD_ALWAYS_ON + POLICY2 STRICT_CONTROL_FLOW_GUARD. | ver resultados |
| `mit_create_module_tamper` | `lab_mitigated_<arch>.exe --net` | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` = [`0x0000000000000000`, `0x0000000000001000`] (`MIT["module_tampering"]`) | POLICY2 MODULE_TAMPERING_PROTECTION_ALWAYS_ON. | ver resultados |
| `mit_create_combo` | `lab_mitigated_<arch>.exe --net` | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` = [`0x0010101101000000`, `0x0000000000001100`] (`MIT["combo"]`) | dyncode + firmadas-MS + sin imágenes remotas + handles estrictos + sin extension points + CFG estricto + module tampering. | ver resultados |
| `eaf_real` | `lab_guard_<arch>.exe --net` | — | EAF REAL: Set-ProcessMitigation -Name lab_guard_<arch>.exe -Enable EnableExportAddressFilter (scripts\eaf_enable.ps1, requiere elevación). Se omite si no está configurado. | ver resultados (omitido sin configuración) |
