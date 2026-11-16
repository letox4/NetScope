# -*- coding: utf-8 -*-
"""Motor de diagnóstico de protecciones / anti-debug.

Es INDEPENDIENTE del motor de memoria y de la captura de red: recibe eventos
(preflight, fallos de attach, desconexiones, errores de memoria, escaneos) y los
convierte en `Finding`s con tres niveles de veredicto (ver models.py). Principios:

  - Un fallo de attach, un cuelgue o una sesión perdida NO se declaran anti-debug
    por sí solos: salen como UNKNOWN con las causas posibles.
  - Solo se marca CONFIRMED lo que se midió directamente en el objetivo/OS.
  - La correlación temporal (terminó N s después de nuestro paso X) es INDICATION.
  - No hay ninguna rutina de evasión ni de ocultación de la instrumentación.
"""
import os
import threading
import time
from typing import Callable, Dict, List, Optional

from . import footprint as fp
from . import preflight as pf
from .models import (DiagnosticReport, Evidence, Finding, Kind, Verdict)

CORRELATION_WINDOW_S = 2.0

# Hooks que instala el agente de red de NetScope (para atribuir la huella).
NETSCOPE_HOOK_MODULES = {'ws2_32.dll', 'winhttp.dll', 'wininet.dll', 'sspicli.dll', 'secur32.dll'}

EXIT_CODES = {
    0xC0000409: 'STATUS_STACK_BUFFER_OVERRUN (fast-fail: __fastfail/RaiseFailFastException)',
    0xC0000005: 'STATUS_ACCESS_VIOLATION (fallo de acceso a memoria)',
    0xC0000374: 'STATUS_HEAP_CORRUPTION',
    0xC0000602: 'STATUS_FAIL_FAST_EXCEPTION',
    0x80000003: 'STATUS_BREAKPOINT',
}

ALL_MEMORY_OPS = ['read', 'write', 'snapshot', 'watch', 'alloc', 'free', 'rollback']

POSSIBLE_ATTACH_CAUSES = [
    'proceso protegido (PP/PPL) o de otro usuario/sesión',
    'proceso elevado mientras NetScope no lo está',
    'política de Windows (mitigaciones, AppContainer, antivirus/EDR)',
    'protección del propio programa (anti-debug/anti-instrumentación) — no demostrada',
    'el proceso terminó o cambió de imagen durante el attach',
]


class PreflightResult:
    def __init__(self, info, findings: List[Finding], blocking: bool, reason: str = ''):
        self.info = info
        self.findings = findings
        self.blocking = blocking
        self.reason = reason


class AntiDebugDiagnostics:
    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._lock = threading.RLock()
        self.pid: Optional[int] = None
        self.target = ''
        self.mode = 'attach'
        self.t_attach: Optional[float] = None
        self.timeline: List[Dict] = []
        self.findings: List[Finding] = []
        self._keys = set()

    # ------------------------------------------------------------- sesión
    def begin(self, pid: Optional[int], target: str = '', mode: str = 'attach') -> None:
        with self._lock:
            self.pid, self.target, self.mode = pid, target, mode
            self.t_attach = None
            self.timeline = []
            self.findings = []
            self._keys = set()
            self.mark('begin', mode=mode)

    def mark(self, step: str, **detail) -> None:
        """Paso de instrumentación (attach, carga de agente, escritura...). Sirve
        para correlacionar una terminación posterior."""
        with self._lock:
            now = self._clock()
            if step == 'attached' and self.t_attach is None:
                self.t_attach = now
            self.timeline.append({'t': now, 'step': step, **detail})

    def _since_attach(self, now: Optional[float] = None) -> Optional[float]:
        if self.t_attach is None:
            return None
        return (now if now is not None else self._clock()) - self.t_attach

    def _add(self, f: Finding, key: Optional[str] = None) -> Finding:
        with self._lock:
            k = key or f'{f.mechanism}|{f.verdict.value}|{f.summary}'
            if k in self._keys:
                for old in self.findings:
                    if f'{old.mechanism}|{old.verdict.value}|{old.summary}' == k or old.mechanism == f.mechanism:
                        return old
            self._keys.add(k)
            if f.t_since_attach is None:
                f.t_since_attach = self._since_attach(f.detected_at)
            self.findings.append(f)
            return f

    def report(self) -> DiagnosticReport:
        with self._lock:
            return DiagnosticReport(pid=self.pid, target=self.target, findings=list(self.findings),
                                    timeline=[dict(t) for t in self.timeline])

    # ------------------------------------------------------------- preflight
    def preflight(self, pid: int, deep: bool = False) -> PreflightResult:
        """Consulta no invasiva ANTES del attach. `blocking` solo se activa cuando
        intentar el attach se colgaría (guardas armadas sobre la EAT)."""
        findings: List[Finding] = []
        blocking, reason = False, ''
        info = pf.inspect_process(pid)
        if info.image_path:
            self.target = os.path.basename(info.image_path)
        if not info.accessible:
            if info.open_error == 87:
                findings.append(self._add(Finding(
                    'target-not-found', Kind.FAILURE, Verdict.CONFIRMED,
                    f'El PID {pid} no existe (OpenProcess: ERROR_INVALID_PARAMETER).',
                    [Evidence('windows-api', f'OpenProcess error {info.open_error}', 'OpenProcess')],
                    can_continue=False, can_continue_note='no hay proceso al que adjuntarse')))
            else:
                findings.append(self._add(Finding(
                    'os-access-denied', Kind.ENVIRONMENT, Verdict.CONFIRMED,
                    'Windows deniega incluso la consulta limitada del proceso: otro usuario, '
                    'proceso protegido o política de seguridad. No indica anti-debug.',
                    [Evidence('windows-api', f'OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) error {info.open_error}',
                              'OpenProcess')],
                    session_effect='el attach será denegado', can_continue=False,
                    can_continue_note='sin elevación/privilegios no es posible',
                    limitations=['la causa concreta (usuario, PPL, sandbox) no puede distinguirse sin más privilegios'])))
            return PreflightResult(info, findings, False, 'inaccesible')

        if info.protection:
            findings.append(self._add(Finding(
                f'protected-process:{info.protection}', Kind.ENVIRONMENT, Verdict.CONFIRMED,
                f'Proceso protegido por Windows ({info.protection}): ningún proceso normal puede abrirlo '
                'con derechos de escritura/hilos, ni siquiera elevado. Es una política del SO, no anti-debug.',
                [Evidence('windows-api', f'NtQueryInformationProcess(ProcessProtectionInformation) = {info.protection}',
                          'NtQueryInformationProcess')],
                session_effect='el attach de Frida será rechazado', can_continue=False,
                can_continue_note='fuera del alcance de una herramienta en modo usuario sin evasión')))
        me = pf.inspect_process(os.getpid())
        if info.elevated and not me.elevated:
            findings.append(self._add(Finding(
                'elevated-target', Kind.ENVIRONMENT, Verdict.CONFIRMED,
                'El objetivo está elevado y NetScope no: Windows impide el attach (integridad superior).',
                [Evidence('windows-api', f'token del objetivo elevado; integridad {info.integrity}; '
                                         f'NetScope elevado={me.elevated}', 'GetTokenInformation')],
                session_effect='el attach de Frida será rechazado (PermissionDenied)',
                can_continue=None, can_continue_note='ejecutando NetScope elevado debería poder continuar (no verificado)')))

        guards = pf.scan_export_guards(pid)
        armed = [g for g in guards if g.armed]
        if armed:
            blocking = True
            reason = 'guardas armadas sobre la tabla de exportación'
            findings.append(self._add(Finding(
                'export-table-guard', Kind.PROTECTION, Verdict.CONFIRMED,
                'Las páginas de la tabla de exportación (EAT) de módulos del sistema tienen PAGE_GUARD armado: '
                'es el mecanismo de EAF (o una guarda equivalente). Mientras esté armado, ReadProcessMemory '
                'sobre la EAT falla y la inyección de Frida no puede resolver exportaciones: el attach se cuelga.',
                [Evidence('windows-api',
                          f'{g.module}: {g.guarded_pages}/{g.pages} páginas EAT con PAGE_GUARD (protect={[hex(p) for p in g.protects[:3]]})',
                          'VirtualQueryEx', {'module': g.module, 'guarded': g.guarded_pages, 'pages': g.pages})
                 for g in armed],
                session_effect='attach colgado (sin error) — NetScope lo evita con el preflight',
                memory_ops_affected=['attach', 'read', 'write'], agents_affected=['memory', 'network'],
                can_continue=False, can_continue_note='no se puede adjuntar mientras la guarda esté armada',
                limitations=['la medición confirma la guarda, no quién la puso (EAF real, otra herramienta o el propio programa)',
                             'un EAF real no pudo probarse sin elevación; el comportamiento se verificó con una emulación equivalente'])))

        if deep:
            findings.extend(self._deep_findings(pid, info))
        return PreflightResult(info, findings, blocking, reason)

    def _deep_findings(self, pid: int, info) -> List[Finding]:
        out: List[Finding] = []
        mit = pf.mitigations_of_process(pid)
        if mit:
            effects = {
                'dyncode': 'el agente de red (Interceptor) puede no poder instalar hooks',
                'signature_ms_only': 'la inyección de DLL no firmadas por Microsoft puede fallar',
                'image_remote': 'carga de imágenes remotas bloqueada',
                'user_shadow_stack': 'CET: la inyección/hooks pueden provocar fallos de pila',
                'child': 'no se pueden crear procesos hijos',
                'extpoint': 'puntos de extensión deshabilitados',
            }
            for name in ('dyncode', 'signature_ms_only', 'image_remote', 'user_shadow_stack', 'child', 'extpoint'):
                if mit.get(name) == 'ON':
                    out.append(self._add(Finding(
                        f'mitigation:{name}', Kind.ENVIRONMENT, Verdict.CONFIRMED,
                        f'Mitigación de Windows activa en el proceso: {name}.',
                        [Evidence('powershell', f'Get-ProcessMitigation -Id {pid}: {name}=ON', 'Get-ProcessMitigation')],
                        session_effect='ver efecto', can_continue=True,
                        can_continue_note=effects.get(name, ''),
                        limitations=['el efecto real sobre Frida depende de la versión; ver docs/FASE3_RESULTS.md'])))
        if info.image_path:
            cfg = pf.mitigations_of_image(os.path.basename(info.image_path))
            if cfg:
                for name in ('eaf', 'eaf_plus', 'iaf', 'rop_caller'):
                    if cfg.get(name) == 'ON':
                        out.append(self._add(Finding(
                            f'exploit-protection:{name}', Kind.ENVIRONMENT, Verdict.CONFIRMED,
                            f'Exploit Protection configurado para esta imagen: {name}=ON.',
                            [Evidence('powershell', f'Get-ProcessMitigation -Name {os.path.basename(info.image_path)}: {name}=ON',
                                      'Get-ProcessMitigation')],
                            session_effect='puede impedir o colgar el attach', agents_affected=['memory', 'network'],
                            can_continue=False if name.startswith('eaf') else None)))
        return out

    # ------------------------------------------------------------- fallos
    def on_attach_failure(self, exc: BaseException, pid: Optional[int] = None) -> Finding:
        cls = type(exc).__name__
        ev = [Evidence('frida', f'{cls}: {exc}', 'frida.attach')]
        summary = {
            'PermissionDeniedError': 'Frida no pudo adjuntarse: acceso denegado.',
            'ProcessNotFoundError': 'Frida no encontró el proceso.',
        }.get(cls, f'Frida no pudo adjuntarse ({cls}).')
        if pid:
            info = pf.inspect_process(pid)
            ev.append(Evidence('windows-api', f'accesible={info.accessible} protección={info.protection} '
                                              f'elevado={info.elevated} integridad={info.integrity} '
                                              f'viva={info.alive}', 'inspect_process'))
        return self._add(Finding(
            f'attach-failure:{cls}', Kind.FAILURE, Verdict.UNKNOWN,
            summary + ' Un fallo de attach NO es evidencia de anti-debug.', ev,
            session_effect='sin sesión', can_continue=False,
            can_continue_note='causas posibles: ' + '; '.join(POSSIBLE_ATTACH_CAUSES),
            limitations=['Frida no distingue el motivo del rechazo; el preflight de Windows aporta el contexto']))

    def on_attach_timeout(self, seconds: float, pid: Optional[int] = None) -> Finding:
        guard = [f for f in self.findings if f.mechanism == 'export-table-guard']
        ev = [Evidence('session', f'frida.attach sin respuesta tras {seconds:.0f}s', 'attach_with_timeout')]
        if guard:
            ev.extend(guard[0].evidence)
            return self._add(Finding(
                'attach-timeout', Kind.FAILURE, Verdict.INDICATION,
                'El attach no volvió y hay guardas armadas sobre la EAT: la causa más probable es esa guarda '
                '(la inyección no puede leer exportaciones). Es un indicio fuerte, no una confirmación del mecanismo.',
                ev, session_effect='attach colgado', can_continue=False,
                limitations=['un attach colgado puede dejar bloqueados los siguientes attach del mismo proceso Python']))
        return self._add(Finding(
            'attach-timeout', Kind.FAILURE, Verdict.UNKNOWN,
            'El attach no respondió en el tiempo límite. Sin otra evidencia, la causa es desconocida '
            '(no se declara anti-debug).', ev, session_effect='attach colgado', can_continue=False,
            can_continue_note='causas posibles: ' + '; '.join(POSSIBLE_ATTACH_CAUSES)))

    def on_agent_failure(self, agent: str, exc: BaseException) -> Finding:
        return self._add(Finding(
            f'agent-failure:{agent}', Kind.FAILURE, Verdict.UNKNOWN,
            f'El agente {agent} no pudo cargarse o inicializarse ({type(exc).__name__}). '
            'Compatibilidad parcial: el otro agente puede seguir funcionando.',
            [Evidence('frida', f'{type(exc).__name__}: {exc}', f'load {agent}')],
            session_effect='agente no disponible', agents_affected=[agent], can_continue=True,
            can_continue_note='evaluar el resto de agentes por separado'))

    def on_session_lost(self, reason: str, crash=None, pid: Optional[int] = None,
                        exit_code: Optional[int] = None) -> Optional[Finding]:
        if reason == 'application-requested':
            return None
        now = self._clock()
        pid = pid or self.pid
        if exit_code is None and pid:
            exit_code = pf.exit_code_of(pid)
        ev = [Evidence('session', f'detached: {reason}', 'frida session.detached')]
        meaning = EXIT_CODES.get(exit_code or -1)
        if exit_code is not None and exit_code != 259:
            ev.append(Evidence('windows-api', f'código de salida 0x{exit_code:08X}'
                               + (f' = {meaning}' if meaning else ''), 'GetExitCodeProcess'))
        if crash is not None:
            ev.append(Evidence('frida', f'crash: {getattr(crash, "summary", crash)}', 'detached(crash)'))
        last = None
        for t in reversed(self.timeline):
            if t['step'] != 'begin':
                last = t
                break
        dt = (now - last['t']) if last else None
        common = dict(session_effect=f'sesión perdida: {reason}', memory_ops_affected=list(ALL_MEMORY_OPS),
                      agents_affected=['memory', 'network'], can_continue=False,
                      can_continue_note='hay que volver a adjuntarse (si el proceso sigue vivo)')
        if dt is not None and dt <= CORRELATION_WINDOW_S and reason in ('process-terminated', 'process-replaced'):
            ev.append(Evidence('session', f'terminó {dt:.2f}s después del paso "{last["step"]}"', 'timeline'))
            return self._add(Finding(
                'termination-after-instrumentation', Kind.PROTECTION, Verdict.INDICATION,
                f'El proceso terminó {dt:.2f}s después de "{last["step"]}". Es compatible con una '
                'detección de instrumentación, pero también con un fallo causado por la instrumentación o con '
                'una salida normal: NO prueba anti-debug.',
                ev, limitations=['la correlación temporal no demuestra causalidad',
                                 'un objetivo que termina sin que lo hayamos instrumentado recientemente quedaría como desconocido'],
                **common))
        return self._add(Finding(
            'session-lost', Kind.FAILURE, Verdict.UNKNOWN,
            f'La sesión se perdió ({reason}) sin correlación con un paso de instrumentación: causa desconocida.',
            ev, limitations=['posibles causas: salida normal, fallo del objetivo, fallo de Frida, protección'], **common))

    def on_memory_error(self, op: str, code: str, addr: Optional[int] = None) -> Optional[Finding]:
        """Errores del motor de memoria que revelan una protección de memoria."""
        where = f' en {hex(addr)}' if addr is not None else ''
        if code == 'E_PAGE_GUARD':
            return self._add(Finding(
                'guard-page', Kind.PROTECTION, Verdict.CONFIRMED,
                f'La región{where} tiene PAGE_GUARD (VirtualQuery dentro del objetivo). La operación "{op}" se '
                'rechazó para NO consumir la guarda ni alterar el comportamiento del programa.',
                [Evidence('frida', f'{op}{where}: E_PAGE_GUARD', 'agent VirtualQuery')],
                session_effect='ninguno (sesión intacta)', memory_ops_affected=[op], agents_affected=['memory'],
                can_continue=True, can_continue_note='el resto de regiones siguen accesibles',
                limitations=['no hay lectura sin efectos laterales de una página guard: se rechaza, no se evade',
                             'ReadProcessMemory desde fuera tampoco la lee (falla) pero tampoco la consume']),
                key=f'guard-page|{hex(addr) if addr is not None else ""}')
        if code == 'E_NO_ACCESS':
            return self._add(Finding(
                'no-access-page', Kind.PROTECTION, Verdict.CONFIRMED,
                f'La región{where} es PAGE_NOACCESS: "{op}" rechazada.', 
                [Evidence('frida', f'{op}{where}: E_NO_ACCESS', 'agent VirtualQuery')],
                memory_ops_affected=[op], agents_affected=['memory'], can_continue=True),
                key=f'no-access|{hex(addr) if addr is not None else ""}')
        return None

    def on_exec_write(self, addr: int, length: int) -> Finding:
        return self._add(Finding(
            'exec-memory-write', Kind.FOOTPRINT, Verdict.CONFIRMED,
            f'NetScope escribió {length} bytes en memoria ejecutable ({hex(addr)}). Un mecanismo de integridad '
            'que vigile esa región podría detectarlo.',
            [Evidence('session', f'write {hex(addr)} len={length} en región con permiso X', 'MemoryEngine.write')],
            memory_ops_affected=['write'], agents_affected=['memory'], can_continue=True,
            limitations=['la escritura en código es una operación destructiva: solo bajo petición explícita']),
            key=f'exec-write|{hex(addr)}')

    # ------------------------------------------------------------- huella / estático
    def scan_footprint(self, read, modules: List[dict], wow64: bool = False,
                       pid: Optional[int] = None) -> List[Finding]:
        """Qué podría ver un objetivo de nuestra instrumentación (y de otras)."""
        out: List[Finding] = []
        hits = fp.scan_inline_hooks(read, modules, wow64=wow64)
        ours = [h for h in hits if h.module.lower() in NETSCOPE_HOOK_MODULES]
        other = [h for h in hits if h.module.lower() not in NETSCOPE_HOOK_MODULES]
        if ours:
            out.append(self._add(Finding(
                'inline-hook-footprint', Kind.FOOTPRINT, Verdict.CONFIRMED,
                f'{len(ours)} funciones tienen el prólogo modificado respecto al disco (hooks inline). '
                'Corresponden al agente de red de NetScope. Un mecanismo de integridad de prólogos lo vería.',
                [Evidence('windows-api', h.describe(), 'scan_inline_hooks') for h in ours[:8]],
                session_effect='ninguno', memory_ops_affected=[], agents_affected=['network'],
                can_continue=True,
                limitations=['el agente de memoria NO instala hooks: sin agente de red esta huella no existe',
                             'comparación contra el disco con máscara de relocaciones; los parches fuera de los '
                             'módulos curados no se examinan'])))
        if other:
            out.append(self._add(Finding(
                'third-party-inline-hook', Kind.FOOTPRINT, Verdict.CONFIRMED,
                f'{len(other)} funciones con prólogo modificado NO atribuible a NetScope (otra herramienta/EDR/el propio programa).',
                [Evidence('windows-api', h.describe(), 'scan_inline_hooks') for h in other[:8]],
                can_continue=True,
                limitations=['no se identifica quién instaló el parche'])))
        if pid:
            threads = pf.frida_thread_footprint(pid)
            pipes = pf.frida_pipes()
            if threads or pipes:
                out.append(self._add(Finding(
                    'frida-visible-artifacts', Kind.FOOTPRINT, Verdict.CONFIRMED,
                    'La instrumentación deja artefactos observables desde el propio objetivo: hilos con nombre '
                    f'({", ".join(threads) or "—"}) y tuberías con nombre ({len(pipes)}).',
                    [Evidence('windows-api', f'hilos del objetivo: {threads}', 'GetThreadDescription'),
                     Evidence('windows-api', f'tuberías: {pipes[:3]}', 'listado de \\\\.\\pipe\\')],
                    session_effect='ninguno', agents_affected=['memory', 'network'], can_continue=True,
                    limitations=['no se oculta nada: es información para el analista (ocultarlo es evasión)',
                                 'que un objetivo los busque no está demostrado por esta medición'])))
        return out

    def scan_static_imports(self, probe) -> List[Finding]:
        """probe: objeto con scan_imports() -> lista de {module, api, from} (sonda pasiva)."""
        res = probe()
        grouped: Dict[str, List[str]] = {}
        for i in res:
            grouped.setdefault(i['api'], []).append(i['module'])
        out = []
        for api, mods in grouped.items():
            out.append(self._add(Finding(
                f'static-import:{api}', Kind.PROTECTION, Verdict.INDICATION,
                f'Módulos del programa importan {api}. Es una API típica de anti-debug, pero también tiene usos '
                'legítimos: NO prueba que se use para detectar depuración.',
                [Evidence('static', f'{m} importa {api}', 'Module.enumerateImports') for m in sorted(set(mods))[:6]],
                can_continue=True,
                limitations=['análisis estático: no demuestra que la ruta se ejecute',
                             'las llamadas por GetProcAddress/syscall directo no aparecen en los imports'])))
        return out

    @staticmethod
    def _positive(key: str, results: Dict[str, int]) -> bool:
        """¿Algún resultado observado indica "depurado"?"""
        for r in results:
            if key.startswith(('IsDebuggerPresent', 'CheckRemoteDebuggerPresent')):
                if r == 'depurador':
                    return True
            elif key.endswith('ProcessDebugPort') or key.endswith('ProcessDebugObjectHandle'):
                if r.startswith('valor=') and r not in ('valor=0x0', 'valor=0', 'valor=null'):
                    return True
            elif key.endswith('ProcessDebugFlags'):
                if r == 'valor=0':
                    return True
        return False

    def ingest_api_observations(self, calls: Dict[str, dict]) -> List[Finding]:
        """Resultado del observador activo (opt-in): el objetivo invocó el mecanismo."""
        out = []
        for key, c in calls.items():
            positive = self._positive(key, c['results'])
            out.append(self._add(Finding(
                f'api-call:{key}', Kind.PROTECTION, Verdict.CONFIRMED,
                f'El objetivo invocó {key} {c["count"]} veces durante la observación. '
                + ('Resultado indica depurador.' if positive else
                   'Resultado: sin depurador (Frida no activa las banderas de depuración de Windows).'),
                [Evidence('frida', f'resultados={c["results"]} llamantes={c["callers"]}', 'Interceptor.attach (solo lectura)')],
                can_continue=True,
                limitations=['observador activo: parchea el prólogo de la API (efecto del observador, detectable por integridad)',
                             'solo verifica que el mecanismo SE USA, no que su resultado provoque una reacción'])))
        return out
