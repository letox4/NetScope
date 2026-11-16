# -*- coding: utf-8 -*-
"""NetScope - interceptor de tráfico TCP/UDP/TLS/HTTP orquestado con Frida."""
import json
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, List, Optional

import frida

from core.antidebug import AntiDebugDiagnostics
from core.antidebug.errors import AttachBlockedError, AttachTimeoutError
from core.dns_resolver import DnsResolver
from core.har_exporter import export_har_file
from core.threat_intel import IOCExtractor, YaraScanner

AGENT_PATH = os.path.join(os.path.dirname(__file__), "..", "agent", "agent.js")
MEMORY_AGENT_PATH = os.path.join(os.path.dirname(__file__), "..", "agent", "memory.js")
MAX_PATCH_RULES = 64


@dataclass
class NetEvent:
    ts: float
    event: str          # connect/send/recv/udp_send/...
    proto: str          # TCP/UDP/TLS/HTTP/STEAM
    fd: int
    direction: str      # out/in
    peer_ip: Optional[str]
    peer_port: Optional[int]
    data: bytes
    truncated: bool
    tag: str
    capture_id: int = 0
    sample_id: int = -1
    stack: List[str] = field(default_factory=list)
    pid: Optional[int] = None


@dataclass
class SocketStream:
    """Stream reensamblado de un socket (fd).

    MAX_DIR_BYTES: tope de memoria por dirección. Cuando el buffer supera el
    tope se descarta la mitad más antigua, para que un proceso con tráfico
    masivo (GB) no colapse la RAM de la GUI.
    """
    MAX_DIR_BYTES = 4 * 1024 * 1024   # 4 MB por dirección
    MAX_STACKS = 16

    fd: int
    proto: str
    peer: str = "?"
    opened_ts: float = field(default_factory=time.time)
    closed: bool = False
    out_data: bytearray = field(default_factory=bytearray)
    in_data: bytearray = field(default_factory=bytearray)
    event_count: int = 0
    byte_out: int = 0
    byte_in: int = 0
    out_generation: int = 0
    in_generation: int = 0
    peer_ip: Optional[str] = None
    peer_port: Optional[int] = None
    peer_host: Optional[str] = None
    pid: Optional[int] = None
    call_stacks: List[List[str]] = field(default_factory=list)

    def _append_capped(self, buf: bytearray, data: bytes, total_attr: str):
        buf += data
        setattr(self, total_attr, getattr(self, total_attr) + len(data))
        if len(buf) > self.MAX_DIR_BYTES:
            del buf[:len(buf) - self.MAX_DIR_BYTES // 2]
            generation_attr = 'out_generation' if total_attr == 'byte_out' else 'in_generation'
            setattr(self, generation_attr, getattr(self, generation_attr) + 1)

    def append_out(self, data: bytes):
        self._append_capped(self.out_data, data, 'byte_out')

    def append_in(self, data: bytes):
        self._append_capped(self.in_data, data, 'byte_in')

    def add_call_stack(self, stack: List[str]):
        if not stack:
            return
        sig = tuple(stack[:4])
        for existing in self.call_stacks:
            if tuple(existing[:4]) == sig:
                return
        if len(self.call_stacks) < self.MAX_STACKS:
            self.call_stacks.append(list(stack))


class FridaInterceptor:
    """Gestiona sesión Frida contra un proceso Windows y reconstruye streams."""

    MAX_SCAN_SAMPLE_BYTES = 16 * 1024 * 1024
    MAX_SCAN_SAMPLE_COUNT = 50000
    MAX_PLAINTEXT_SAMPLE_BYTES = MAX_SCAN_SAMPLE_BYTES
    MAX_PLAINTEXT_SAMPLE_COUNT = MAX_SCAN_SAMPLE_COUNT
    PLAINTEXT_EVENTS = {
        ('HTTP', 'http_out'), ('HTTP', 'http_in'),
        ('TLS', 'tls_out'), ('TLS', 'tls_in'),
        ('STEAM', 'steam_out'), ('STEAM', 'steam_in'),
    }
    RAW_SOCKET_EVENTS = {
        ('TCP', 'send'), ('TCP', 'recv'),
        ('TCP', 'wsa_send'), ('TCP', 'wsa_recv'),
        ('TCP', 'udp_send'), ('TCP', 'udp_recv'),
        ('UDP', 'udp_send'), ('UDP', 'udp_recv'),
        ('UDP', 'send'), ('UDP', 'recv'),
        ('UDP', 'wsa_send'), ('UDP', 'wsa_recv'),
    }
    SCAN_EVENTS = PLAINTEXT_EVENTS | RAW_SOCKET_EVENTS

    def __init__(self, on_event: Callable[[NetEvent], None],
                 on_status: Callable[[str], None],
                 on_log: Callable[[str], None],
                 audit_path: Optional[str] = None,
                 attach_timeout: float = 20.0,
                 preflight: bool = True):
        self.on_event = on_event
        self.on_status = on_status
        self.on_log = on_log
        self.attach_timeout = attach_timeout
        self.preflight = preflight
        self.diagnostics = AntiDebugDiagnostics()
        self.dns_resolver = DnsResolver(enable_rdns=True)
        # cb(reason: str, crash) cuando la sesión se pierde de forma inesperada
        self.on_detached: Optional[Callable] = None
        self._device: Optional[frida.core.Device] = None
        self._script = None
        self._session = None
        self._detach_reason: Optional[str] = None
        self._mem_script = None
        self._mem_backend = None
        self._mem_engine = None
        self._audit_path = audit_path
        self._audit = None
        self.spawned_pid: Optional[int] = None
        self._root_pid: Optional[int] = None
        self.follow_children: bool = False
        self._child_gating_cb = None
        self._child_sessions: dict[int, tuple] = {}
        self._attached_child_pids: set[int] = set()
        self.child_pids: List[int] = []
        self._agent_source: Optional[str] = None
        self._lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()
        self._capture_id = 0
        self._capturing = False
        # fd -> SocketStream
        self.streams: dict[int, SocketStream] = {}
        self.tls_keylog: List[str] = []
        self._tls_keylog_set: set[str] = set()
        self._scan_events = deque()
        self._scan_sample_bytes = 0
        self._scan_sample_drops = 0
        self._plaintext_sample_drops = 0
        self._next_scan_sample_id = 0

    # ---------- enumeración ----------
    @staticmethod
    def list_processes() -> List[dict]:
        device = frida.get_local_device()
        out = []
        for p in device.enumerate_processes(scope="full"):
            out.append({"pid": p.pid, "name": p.name})
        return sorted(out, key=lambda d: d["name"].lower())

    # ---------- attach ----------
    def _resolve_pid(self, pid: Optional[int], name: Optional[str]) -> Optional[int]:
        if pid:
            return pid
        if name:
            try:
                for p in self._device.enumerate_processes():
                    if p.name.lower() == name.lower():
                        return p.pid
            except Exception:
                pass
        return None

    def _log_findings(self, findings):
        for f in findings or []:
            self.on_log(f"[diag] [{f.verdict.value}] {f.mechanism}: {f.summary}")

    def _attach_with_timeout(self, target, pid):
        result = {}

        def work():
            try:
                result['s'] = self._device.attach(target)
            except BaseException as exc:      # noqa: BLE001 — se re-lanza abajo
                result['e'] = exc

        th = threading.Thread(target=work, daemon=True, name='NetScope-attach')
        th.start()
        th.join(self.attach_timeout)
        if th.is_alive():
            def late():
                th.join()
                s = result.get('s')
                if s is not None:
                    try:
                        s.detach()
                    except Exception:
                        pass
            threading.Thread(target=late, daemon=True).start()
            finding = self.diagnostics.on_attach_timeout(self.attach_timeout, pid)
            self._log_findings([finding])
            raise AttachTimeoutError(finding.summary, self.attach_timeout, self.diagnostics.report())
        if 'e' in result:
            raise result['e']
        return result['s']

    def attach(self, pid: Optional[int] = None, name: Optional[str] = None,
               spawn: bool = False, network_agent: bool = True,
               follow_children: bool = False):
        """network_agent=False: solo sesión (para usar únicamente el agente de
        memoria, sin ningún hook de red)."""
        with self._lifecycle_lock:
            self.stop()
            self.clear_capture_data()
            self.follow_children = bool(follow_children)
            self.on_status("Iniciando Frida…")
            self._device = frida.get_local_device()
            target_pid = self._resolve_pid(pid, name) if not spawn else None
            self.diagnostics.begin(target_pid, name or str(pid), 'spawn' if spawn else 'attach')
            try:
                if self.preflight and target_pid:
                    pre = self.diagnostics.preflight(target_pid)
                    self._log_findings(pre.findings)
                    if pre.blocking:
                        raise AttachBlockedError(
                            f'Attach evitado: {pre.reason}. Intentarlo dejaría Frida colgado.',
                            self.diagnostics.report())

                if spawn and name:
                    self.on_status(f"Spawneando {name}…")
                    self.spawned_pid = self._device.spawn([name])
                    pid = self.spawned_pid
                    self._session = self._attach_with_timeout(pid, pid)
                    self.on_log(f"[i] Proceso spawneado PID={pid}")
                elif pid is not None:
                    self._session = self._attach_with_timeout(pid, target_pid or pid)
                elif target_pid is not None:
                    self._session = self._attach_with_timeout(target_pid, target_pid)
                else:
                    self._session = self._attach_with_timeout(name, target_pid)
            except (AttachBlockedError, AttachTimeoutError):
                self._session = None
                raise
            except Exception as exc:
                self._log_findings([self.diagnostics.on_attach_failure(exc, target_pid or pid)])
                self._session = None
                raise

            self._root_pid = pid or target_pid
            self._detach_reason = None
            self.diagnostics.mark('attached', pid=self._root_pid)
            self._session.on('detached', self._make_detached_cb(self._session))

            if self.follow_children:
                self._enable_child_gating()

            if not network_agent:
                self.on_status("Sesión activa (solo agente de memoria)")
                if spawn and self.spawned_pid:
                    self._device.resume(self.spawned_pid)
                    self.on_log("[i] Proceso resumido")
                return

            with open(AGENT_PATH, "r", encoding="utf-8") as f:
                src = f.read()
            self._agent_source = src

            self.on_status("Creando script…")
            self._script = self._session.create_script(src)
            capture_id = self._capture_id
            root_pid = self._root_pid
            self._script.on(
                "message",
                lambda message, data, event_capture_id=capture_id, spid=root_pid:
                    self._on_message(message, data, event_capture_id, spid),
            )
            self.on_status("Cargando script…")
            with self._lock:
                self._capturing = True
            try:
                self._script.load()
            except Exception as exc:
                self.deactivate_capture()
                self._log_findings([self.diagnostics.on_agent_failure('network', exc)])
                raise
            self.diagnostics.mark('network-agent-loaded')
            self.on_status("Hooks activos")

            if spawn and self.spawned_pid:
                self._device.resume(self.spawned_pid)
                self.on_log("[i] Proceso resumido")

    def _enable_child_gating(self):
        if self._device is None or self._session is None:
            return
        try:
            def on_child(child):
                self._on_child(child)
            self._child_gating_cb = on_child
            self._device.on('child-added', on_child)
            self._session.enable_child_gating()
            self.on_log("[i] Seguimiento de procesos hijo (child gating) habilitado")
        except Exception as exc:
            self.on_log(f"[i] Child gating nativo no disponible ({exc}); usando respaldo CreateProcess")

    def _on_child(self, child):
        cpid = getattr(child, 'pid', None)
        if not cpid:
            return
        self.on_log(f"[i] Child spawned (gating): PID={cpid}")
        with self._lock:
            if cpid not in self.child_pids:
                self.child_pids.append(cpid)
        if self.follow_children:
            self._attach_child_pid(cpid, resume_after=True)
        else:
            try:
                self._device.resume(cpid)
            except Exception:
                pass

    def _attach_child_pid(self, child_pid: int, resume_after: bool = False):
        if not child_pid or child_pid == self._root_pid:
            return
        with self._lock:
            if not self._capturing or child_pid in self._attached_child_pids:
                return
            self._attached_child_pids.add(child_pid)
            if child_pid not in self.child_pids:
                self.child_pids.append(child_pid)
            capture_id = self._capture_id
            src = self._agent_source

        def _worker():
            try:
                if not src or self._device is None:
                    return
                sess = self._device.attach(child_pid)
                if self.follow_children:
                    try:
                        sess.enable_child_gating()
                    except Exception:
                        pass
                scr = sess.create_script(src)
                scr.on(
                    "message",
                    lambda message, data, cid=capture_id, spid=child_pid:
                        self._on_message(message, data, cid, spid),
                )
                scr.load()
                with self._lock:
                    if not self._capturing or capture_id != self._capture_id:
                        try:
                            scr.unload()
                        except Exception:
                            pass
                        try:
                            sess.detach()
                        except Exception:
                            pass
                        return
                    self._child_sessions[child_pid] = (sess, scr)
                self.on_log(f"[i] Hooks activos en proceso hijo PID={child_pid}")
            except Exception as exc:
                self.on_log(f"[!] No se pudo adjuntar al hijo PID={child_pid}: {exc}")
            finally:
                if resume_after and self._device is not None:
                    try:
                        self._device.resume(child_pid)
                    except Exception:
                        pass

        threading.Thread(target=_worker, daemon=True, name=f'NetScope-child-{child_pid}').start()

    # ---------- ciclo de vida de la sesión ----------
    @property
    def session_state(self) -> str:
        """'none' | 'active' | 'lost' (detach inesperado o proceso terminado)."""
        if self._detach_reason is not None:
            return 'lost'
        s = self._session
        if s is None:
            return 'none'
        return 'lost' if getattr(s, 'is_detached', False) else 'active'

    @property
    def detach_reason(self) -> Optional[str]:
        return self._detach_reason

    def _make_detached_cb(self, session):
        def cb(reason, crash):
            self._on_session_detached(session, reason, crash)
        return cb

    def _on_session_detached(self, session, reason, crash):
        with self._lock:
            if session is not self._session:
                return
            if reason == 'application-requested':
                return
            self._detach_reason = str(reason)
            self._capturing = False
            engine = self._mem_engine
            self._mem_engine = None
            self._mem_backend = None
            self._mem_script = None
        if engine is not None:
            engine.invalidate('E_SESSION_LOST', str(reason), authoritative=True)
        detail = f' (crash: {crash.summary})' if crash is not None else ''
        self.on_log(f"[!] Sesión Frida perdida: {reason}{detail}")
        finding = self.diagnostics.on_session_lost(str(reason), crash, self.diagnostics.pid)
        self._log_findings([finding] if finding else [])
        self.on_status(f"Sesión perdida: {reason}")
        cb = self.on_detached
        if cb is not None:
            try:
                cb(str(reason), crash)
            except Exception as exc:
                self.on_log(f"[!] on_detached falló: {exc}")

    # ---------- mensajes de frida ----------
    def _stream_fd(self, raw_fd: int, source_pid: Optional[int]) -> int:
        if source_pid is None or source_pid == self._root_pid:
            return raw_fd
        if raw_fd >= 0:
            return (source_pid * 100000) + raw_fd
        return -((source_pid * 100000) + abs(raw_fd))

    def _update_peer_dns(self, ip: str, host: str):
        recorded = self.dns_resolver.record(ip, host)
        if not recorded:
            return
        with self._lock:
            for st in self.streams.values():
                if st.peer_ip == ip:
                    st.peer_host = recorded
                    st.peer = self.dns_resolver.format_peer(st.peer_ip, st.peer_port, recorded)

    def _on_message(self, message, data, capture_id=None, source_pid=None):
        if capture_id is None:
            with self._lock:
                capture_id = self._capture_id
        with self._lock:
            if not self._capturing or capture_id != self._capture_id:
                return

        t = message.get("type")
        if t == "send":
            pl = message.get("payload", {})
            event = pl.get("event")
            if event in ("ready", "api_activity"):
                prefix = "Hooks activos" if event == "ready" else "API observada"
                self.on_log(f"[i] {prefix}: {pl.get('tag', '')}")
                return
            if event == "dns":
                peer_obj = pl.get("peer") or {}
                ip = peer_obj.get("ip")
                host = pl.get("tag", "")
                if ip and host:
                    self._update_peer_dns(ip, host)
                return
            if event == "tls_keylog":
                line = (pl.get("tag") or "").strip()
                if line:
                    with self._lock:
                        if line not in self._tls_keylog_set:
                            self._tls_keylog_set.add(line)
                            self.tls_keylog.append(line)
                    self.on_log(f"[i] TLS keylog: {line[:64]}…")
                return
            if event == "child_spawned":
                child_pid = int(pl.get("fd", 0) or 0)
                cmd = pl.get("tag", "")
                if child_pid > 0:
                    self.on_log(f"[i] Proceso hijo detectado PID={child_pid}: {cmd}")
                    with self._lock:
                        if child_pid not in self.child_pids:
                            self.child_pids.append(child_pid)
                    if self.follow_children:
                        self._attach_child_pid(child_pid, resume_after=False)
                return

            ev = NetEvent(
                ts=time.time(),
                event=pl.get("event", "?"),
                proto=pl.get("proto", "?"),
                fd=pl.get("fd", -1),
                direction=pl.get("dir", ""),
                peer_ip=(pl.get("peer") or {}).get("ip"),
                peer_port=(pl.get("peer") or {}).get("port"),
                data=bytes.fromhex(pl.get("hex", "")),
                truncated=bool(pl.get("truncated")),
                tag=pl.get("tag", ""),
                capture_id=capture_id,
                stack=list(pl.get("stack") or []),
                pid=source_pid or self._root_pid,
            )
            self._feed(ev)
        elif t == "error":
            self.on_log(f"[!] Frida error: {message.get('description', '')}")
        else:
            self.on_log(f"[i] {message}")

    def _feed(self, ev: NetEvent):
        if ev.event in ('ready', 'error'):
            return
        with self._lock:
            if not self._capturing or ev.capture_id != self._capture_id:
                return
            stream_fd = self._stream_fd(ev.fd, ev.pid)
            if ev.event == "socket":
                self.streams[stream_fd] = SocketStream(
                    fd=stream_fd, proto=ev.proto, pid=ev.pid)
                return
            if ev.event == "close":
                st = self.streams.get(stream_fd)
                if st:
                    st.closed = True
                return
            st = self.streams.get(stream_fd)
            if st is None:
                st = SocketStream(fd=stream_fd, proto=ev.proto, pid=ev.pid)
                self.streams[stream_fd] = st
            elif st.proto == '?' and ev.proto in ('TCP', 'UDP'):
                st.proto = ev.proto

            if ev.peer_ip:
                st.peer_ip = ev.peer_ip
                st.peer_port = ev.peer_port
            if ev.data:
                discovered_host = self.dns_resolver.inspect_payload(
                    st.peer_ip, ev.data, st.peer_port)
                if discovered_host and not st.peer_host:
                    st.peer_host = discovered_host
            if st.peer_ip and not st.peer_host:
                st.peer_host = self.dns_resolver.resolve(
                    st.peer_ip,
                    async_lookup=True,
                    on_resolved=self._update_peer_dns,
                )
            if st.peer_ip or st.peer_host:
                st.peer = self.dns_resolver.format_peer(
                    st.peer_ip, st.peer_port, st.peer_host)

            st.event_count += 1
            if ev.direction == "out":
                st.append_out(ev.data)
            else:
                st.append_in(ev.data)
            if ev.stack:
                st.add_call_stack(ev.stack)
            if (ev.proto.upper(), ev.event) in self.SCAN_EVENTS and ev.data:
                self._record_scan_event(ev)
        self.on_event(ev)

    def _record_scan_event(self, ev: NetEvent):
        if len(ev.data) > self.MAX_SCAN_SAMPLE_BYTES:
            self._scan_sample_drops += 1
            if (ev.proto.upper(), ev.event) in self.PLAINTEXT_EVENTS:
                self._plaintext_sample_drops += 1
            return
        ev.sample_id = self._next_scan_sample_id
        self._next_scan_sample_id += 1
        self._scan_events.append(ev)
        self._scan_sample_bytes += len(ev.data)
        while (
            self._scan_sample_bytes > self.MAX_SCAN_SAMPLE_BYTES
            or len(self._scan_events) > self.MAX_SCAN_SAMPLE_COUNT
        ):
            expired = self._scan_events.popleft()
            self._scan_sample_bytes -= len(expired.data)
            self._scan_sample_drops += 1
            if (expired.proto.upper(), expired.event) in self.PLAINTEXT_EVENTS:
                self._plaintext_sample_drops += 1

    # ---------- patch en vivo y opciones del agente ----------
    def set_patch_rules(self, rules):
        script = self._script
        if script is None:
            raise RuntimeError('No hay agente cargado (attach primero)')
        rules = list(rules or [])
        if len(rules) > MAX_PATCH_RULES:
            raise ValueError(
                f'Se permiten como máximo {MAX_PATCH_RULES} reglas')
        payload = []
        for rule in rules:
            try:
                match = bytes.fromhex(str(rule.get('hex_match', '')))
                replacement = bytes.fromhex(
                    str(rule.get('hex_replace', '')))
            except (AttributeError, TypeError, ValueError) as exc:
                raise ValueError(
                    'Las reglas deben contener valores hexadecimales válidos'
                ) from exc
            if not match:
                raise ValueError('Las reglas no pueden estar vacías')
            if len(match) != len(replacement):
                raise ValueError(
                    f'Regla inválida: match/replace deben tener la misma '
                    f'longitud en bytes ({len(match)} vs '
                    f'{len(replacement)})')
            payload.append({
                'hex_match': match.hex(),
                'hex_replace': replacement.hex(),
            })
        return script.exports_sync.set_rules(payload)

    def clear_patch_rules(self):
        return self.set_patch_rules([])

    def set_rewrite_enabled(self, onoff: bool):
        script = self._script
        if script is None:
            raise RuntimeError('No hay agente cargado (attach primero)')
        return script.exports_sync.set_rewrite(onoff)

    def set_capture_stacks(self, enabled: bool) -> bool:
        script = self._script
        if script is None:
            return bool(enabled)
        return bool(script.exports_sync.set_capture_stacks(bool(enabled)))

    def patch_ping(self):
        script = self._script
        if script is None:
            return {'rules': 0, 'enabled': False}
        return script.exports_sync.ping()

    # ---------- exportaciones y threat intel ----------
    def export_pcapng(self, path: str, include_secrets: bool = True,
                      include_dns: bool = True):
        """Vuelca los streams reensamblados a .pcapng (con DSB/NRB opcionales)."""
        from core.pcapng import build_pcapng
        streams = self.snapshot_streams()
        keys = self.snapshot_tls_keylog() if include_secrets else None
        dns_map = self.dns_resolver.snapshot() if include_dns else None
        blob = build_pcapng(streams, tls_keylog=keys, dns_map=dns_map)
        with open(path, 'wb') as f:
            f.write(blob)
        self.on_log(f'[i] PCAPNG exportado: {path} '
                    f'({len(streams)} streams, {len(blob)} bytes)')
        return path

    def export_tls_keylog(self, path: str) -> str:
        """Exporta las claves TLS capturadas en formato NSS/SSLKEYLOGFILE."""
        keys = self.snapshot_tls_keylog()
        with open(path, 'w', encoding='utf-8') as f:
            if keys:
                f.write('\n'.join(keys) + '\n')
        self.on_log(f'[i] TLS Keylog exportado: {path} ({len(keys)} líneas)')
        return path

    def export_har(self, path: str) -> str:
        """Exporta los intercambios HTTP reconstruidos a formato HAR 1.2."""
        streams = self.snapshot_streams()
        export_har_file(streams, path)
        self.on_log(f'[i] HAR exportado: {path} ({len(streams)} streams revisados)')
        return path

    def extract_iocs(self):
        """Extrae indicadores de compromiso (IOCs) de la captura actual."""
        streams = self.snapshot_streams()
        dns_map = self.dns_resolver.snapshot()
        return IOCExtractor().extract_from_streams(streams, dns_map=dns_map)

    def scan_yara(self, rules_text: Optional[str] = None,
                  rules_path: Optional[str] = None,
                  include_builtin: bool = True):
        """Escanea los streams capturados con reglas YARA."""
        if rules_path:
            scanner = YaraScanner.from_file(rules_path, include_builtin=include_builtin)
        else:
            scanner = YaraScanner(rules_text=rules_text, include_builtin=include_builtin)
        return scanner.scan_streams(self.snapshot_streams())

    # ---------- consultas ----------
    def snapshot_streams(self) -> List[SocketStream]:
        with self._lock:
            return [s for s in self.streams.values()
                    if s.out_data or s.in_data or s.event_count]

    def snapshot_tls_keylog(self) -> List[str]:
        with self._lock:
            return list(self.tls_keylog)

    def snapshot_plaintext_events(self, after_sample_id=-1):
        with self._lock:
            return tuple(
                ev for ev in self._scan_events
                if ev.sample_id > after_sample_id
                and (ev.proto.upper(), ev.event) in self.PLAINTEXT_EVENTS
            )

    def plaintext_sample_stats(self):
        with self._lock:
            events = tuple(
                ev for ev in self._scan_events
                if (ev.proto.upper(), ev.event) in self.PLAINTEXT_EVENTS
            )
            return (
                len(events),
                sum(len(ev.data) for ev in events),
                self._plaintext_sample_drops,
            )

    def snapshot_scan_events(self, after_sample_id=-1):
        with self._lock:
            return tuple(
                ev for ev in self._scan_events
                if ev.sample_id > after_sample_id
            )

    def scan_sample_stats(self):
        with self._lock:
            return (
                len(self._scan_events),
                self._scan_sample_bytes,
                self._scan_sample_drops,
            )

    def clear_capture_data(self):
        with self._lock:
            self.streams.clear()
            self.tls_keylog.clear()
            self._tls_keylog_set.clear()
            self.child_pids.clear()
            self._attached_child_pids.clear()
            self._scan_events.clear()
            self._scan_sample_bytes = 0
            self._scan_sample_drops = 0
            self._plaintext_sample_drops = 0
            self._next_scan_sample_id = 0
            self.dns_resolver.clear()

    def deactivate_capture(self, clear_streams=False):
        """Invalidate callbacks, optionally clearing the retained capture."""
        with self._lock:
            self._capturing = False
            self._capture_id += 1
            if clear_streams:
                self.clear_capture_data()

    def stop(self):
        with self._lifecycle_lock:
            self.deactivate_capture()
            errors = []
            script = self._script
            session = self._session
            mem_script = self._mem_script
            engine = self._mem_engine
            child_sessions = dict(self._child_sessions)
            self._child_sessions.clear()
            self._mem_script = None
            self._mem_backend = None
            self._mem_engine = None

            if self._device is not None and self._child_gating_cb is not None:
                try:
                    self._device.off('child-added', self._child_gating_cb)
                except Exception:
                    pass
                self._child_gating_cb = None

            if engine is not None:
                engine.invalidate('E_SESSION_STOPPED', 'application-requested')

            for label, scr in (("de memoria", mem_script), ("Frida", script)):
                if scr is None or getattr(scr, 'is_destroyed', False):
                    continue
                try:
                    scr.unload()
                except Exception as exc:
                    errors.append(f"No se pudo descargar el script {label}: {exc}")
            if script is not None:
                self._script = None

            for cpid, (csess, cscr) in child_sessions.items():
                try:
                    if cscr and not getattr(cscr, 'is_destroyed', False):
                        cscr.unload()
                except Exception:
                    pass
                try:
                    if csess and not getattr(csess, 'is_detached', False):
                        csess.detach()
                except Exception:
                    pass

            if session:
                try:
                    session.detach()
                    self._session = None
                    self._script = None
                except Exception as exc:
                    errors.append(f"No se pudo desconectar la sesión Frida: {exc}")

            if self.spawned_pid:
                try:
                    self._device.kill(self.spawned_pid)
                    self.spawned_pid = None
                    self._script = None
                    self._session = None
                except Exception as exc:
                    errors.append(f"No se pudo cerrar el proceso iniciado por NetScope: {exc}")

            self._root_pid = None
            self._detach_reason = None
            for error in errors:
                self.on_log(f"[!] {error}")
            self.on_status("Detenido" if not errors else "Detenido con advertencias")

    def _on_memory_op(self, op, **d):
        if op == 'write':
            self.diagnostics.mark('memory-write', addr=d.get('addr'), length=d.get('length'))
            if d.get('exec') and d.get('applied'):
                self._log_findings([self.diagnostics.on_exec_write(d['addr'], d['length'])])
        elif op == 'read_error':
            f = self.diagnostics.on_memory_error('read', d['error'], d.get('addr'))
            if f:
                self._log_findings([f])

    # ---------- Fase 2: subsistema de memoria ----------
    def _get_audit(self):
        if self._audit is None:
            from core.memory.audit import AuditLog, default_audit_path
            self._audit = AuditLog(self._audit_path or default_audit_path())
        return self._audit

    def memory_engine(self, read_only: bool = True):
        """Devuelve el MemoryEngine reusando la sesión Frida ACTUAL.

        Por defecto en v1 usa `read_only=True` (solo inspección de memoria).
        """
        from core.memory.models import SessionError
        with self._lifecycle_lock:
            if self.session_state == 'lost':
                self._mem_engine = None
                raise SessionError(
                    'E_SESSION_LOST',
                    'la sesión Frida se perdió: vuelve a hacer attach',
                    detail=self._detach_reason or 'detached')
            if self._session is None:
                raise SessionError(
                    'E_NO_SESSION',
                    'No hay una sesión Frida activa: haz attach a un proceso primero')
            if (self._mem_engine is not None and self._mem_engine.valid
                    and getattr(self._mem_backend, 'read_only', True) == bool(read_only)):
                return self._mem_engine
            with open(MEMORY_AGENT_PATH, 'r', encoding='utf-8') as f:
                src = f.read()
            self._mem_script = self._session.create_script(src)
            self._mem_script.load()
            from core.memory.backends.frida_memory import FridaMemoryBackend
            from core.memory.engine import MemoryEngine
            try:
                backend = FridaMemoryBackend(self._mem_script, read_only=read_only)
            except Exception:
                try:
                    self._mem_script.unload()
                except Exception:
                    pass
                self._mem_script = None
                raise
            self._mem_backend = backend
            audit = self._get_audit()
            audit.set_context(pid=backend.pid, arch=backend.arch)
            self._mem_engine = MemoryEngine(backend, audit=audit)
            self._mem_engine.observers.append(self._on_memory_op)
            self.diagnostics.mark('memory-agent-loaded')
            self._mem_engine._audit_event('engine_start',
                                          pointer_size=backend.pointer_size,
                                          read_only=bool(read_only))
            self.on_log(
                f"[i] Motor de memoria listo: arch={backend.arch} "
                f"({backend.pointer_size} bytes puntero, read_only={bool(read_only)}); "
                f"auditoría: {audit.path}")
            return self._mem_engine
