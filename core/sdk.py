# -*- coding: utf-8 -*-
"""NetScope SDK — API pública de alto nivel para scripts propios."""
import json
import threading
import time
from typing import Callable, Dict, List, Optional

from core.game_analysis import analyze_game_streams
from core.har_exporter import build_har
from core.http_parser import parse_http_stream
from core.interceptor import FridaInterceptor, NetEvent, SocketStream


class NetScopeSession:
    """Interfaz de scripting programática y context manager sobre FridaInterceptor."""

    def __init__(self,
                 pid: Optional[int] = None,
                 process: Optional[str] = None,
                 spawn: bool = False,
                 follow_children: bool = False,
                 network_agent: bool = True,
                 capture_stacks: bool = True,
                 preflight: bool = True,
                 attach_timeout: float = 20.0):
        self.pid = pid
        self.process = process
        self.spawn = bool(spawn)
        self.follow_children = bool(follow_children)
        self.network_agent = bool(network_agent)
        self.capture_stacks = bool(capture_stacks)

        self._lock = threading.RLock()
        self._attached = False
        self._events: List[NetEvent] = []
        self._event_cbs: List[Callable[[NetEvent], None]] = []
        self._http_cbs: List[Callable[[NetEvent, dict], None]] = []
        self._dns_cbs: List[Callable[[str, str], None]] = []
        self._tls_key_cbs: List[Callable[[str], None]] = []
        self._child_cbs: List[Callable[[int], None]] = []
        self._status_cbs: List[Callable[[str], None]] = []
        self._log_cbs: List[Callable[[str], None]] = []
        self._seen_dns: set = set()
        self._seen_keys: int = 0
        self._seen_children: set = set()

        self.interceptor = FridaInterceptor(
            on_event=self._handle_event,
            on_status=self._handle_status,
            on_log=self._handle_log,
            attach_timeout=attach_timeout,
            preflight=preflight,
        )

    # ---------- decoradores de eventos ----------
    def on_event(self, fn: Callable[[NetEvent], None]):
        self._event_cbs.append(fn)
        return fn

    def on_http(self, fn: Callable[[NetEvent, dict], None]):
        self._http_cbs.append(fn)
        return fn

    def on_dns(self, fn: Callable[[str, str], None]):
        self._dns_cbs.append(fn)
        return fn

    def on_tls_key(self, fn: Callable[[str], None]):
        self._tls_key_cbs.append(fn)
        return fn

    def on_child(self, fn: Callable[[int], None]):
        self._child_cbs.append(fn)
        return fn

    def on_status(self, fn: Callable[[str], None]):
        self._status_cbs.append(fn)
        return fn

    def on_log(self, fn: Callable[[str], None]):
        self._log_cbs.append(fn)
        return fn

    # ---------- dispatch interno ----------
    def _handle_event(self, ev: NetEvent):
        with self._lock:
            self._events.append(ev)
        for cb in list(self._event_cbs):
            try:
                cb(ev)
            except Exception:
                pass
        if self._http_cbs and ev.data and ev.proto in ('TCP', 'HTTP', 'TLS'):
            for msg in parse_http_stream(ev.data):
                for cb in list(self._http_cbs):
                    try:
                        cb(ev, msg)
                    except Exception:
                        pass
        if self._dns_cbs:
            for ip, host in self.interceptor.dns_resolver.snapshot().items():
                if (ip, host) not in self._seen_dns:
                    self._seen_dns.add((ip, host))
                    for cb in list(self._dns_cbs):
                        try:
                            cb(ip, host)
                        except Exception:
                            pass
        if self._tls_key_cbs:
            keys = self.interceptor.snapshot_tls_keylog()
            if len(keys) > self._seen_keys:
                new_keys = keys[self._seen_keys:]
                self._seen_keys = len(keys)
                for line in new_keys:
                    for cb in list(self._tls_key_cbs):
                        try:
                            cb(line)
                        except Exception:
                            pass
        if self._child_cbs:
            for cpid in list(self.interceptor.child_pids):
                if cpid not in self._seen_children:
                    self._seen_children.add(cpid)
                    for cb in list(self._child_cbs):
                        try:
                            cb(cpid)
                        except Exception:
                            pass

    def _handle_status(self, msg: str):
        for cb in list(self._status_cbs):
            try:
                cb(msg)
            except Exception:
                pass

    def _handle_log(self, msg: str):
        if self._child_cbs:
            for cpid in list(self.interceptor.child_pids):
                if cpid not in self._seen_children:
                    self._seen_children.add(cpid)
                    for cb in list(self._child_cbs):
                        try:
                            cb(cpid)
                        except Exception:
                            pass
        if self._tls_key_cbs:
            keys = self.interceptor.snapshot_tls_keylog()
            if len(keys) > self._seen_keys:
                new_keys = keys[self._seen_keys:]
                self._seen_keys = len(keys)
                for line in new_keys:
                    for cb in list(self._tls_key_cbs):
                        try:
                            cb(line)
                        except Exception:
                            pass
        for cb in list(self._log_cbs):
            try:
                cb(msg)
            except Exception:
                pass

    # ---------- ciclo de vida ----------
    @staticmethod
    def list_processes() -> List[dict]:
        return FridaInterceptor.list_processes()

    def attach(self, pid: Optional[int] = None, process: Optional[str] = None,
               spawn: Optional[bool] = None, follow_children: Optional[bool] = None) -> 'NetScopeSession':
        use_pid = pid if pid is not None else self.pid
        use_proc = process if process is not None else self.process
        use_spawn = self.spawn if spawn is None else bool(spawn)
        use_children = self.follow_children if follow_children is None else bool(follow_children)
        if use_pid is None and not use_proc:
            raise ValueError('Debes especificar pid o process para adjuntar.')
        self.interceptor.attach(
            pid=use_pid,
            name=use_proc,
            spawn=use_spawn,
            network_agent=self.network_agent,
            follow_children=use_children,
        )
        self._attached = True
        if self.network_agent:
            self.interceptor.set_capture_stacks(self.capture_stacks)
        return self

    def capture(self, duration: float = 5.0) -> List[SocketStream]:
        if not self._attached:
            self.attach()
        end = time.time() + max(0.0, float(duration))
        try:
            while time.time() < end:
                time.sleep(min(0.1, max(0.01, end - time.time())))
        except KeyboardInterrupt:
            pass
        return self.streams()

    def stop(self):
        self._attached = False
        self.interceptor.stop()

    def __enter__(self) -> 'NetScopeSession':
        if self.pid is not None or self.process:
            self.attach()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    # ---------- configuración en vivo ----------
    def set_patch_rules(self, rules):
        return self.interceptor.set_patch_rules(rules)

    def clear_patch_rules(self):
        return self.interceptor.clear_patch_rules()

    def set_rewrite_enabled(self, enabled: bool):
        return self.interceptor.set_rewrite_enabled(enabled)

    def set_capture_stacks(self, enabled: bool) -> bool:
        self.capture_stacks = bool(enabled)
        return self.interceptor.set_capture_stacks(enabled)

    # ---------- inspección y análisis ----------
    def streams(self, localhost_only: bool = False) -> List[SocketStream]:
        snaps = self.interceptor.snapshot_streams()
        if localhost_only:
            snaps = [s for s in snaps if '127.0.0.1' in (s.peer or '')]
        return snaps

    def events(self) -> List[NetEvent]:
        with self._lock:
            return list(self._events)

    def http_messages(self) -> List[dict]:
        return build_har(self.streams())['log']['entries']

    def dns_table(self) -> Dict[str, str]:
        return self.interceptor.dns_resolver.snapshot()

    def tls_keys(self) -> List[str]:
        return self.interceptor.snapshot_tls_keylog()

    def child_pids(self) -> List[int]:
        return list(self.interceptor.child_pids)

    def extract_iocs(self):
        return self.interceptor.extract_iocs()

    def scan_yara(self, rules_text: Optional[str] = None,
                  rules_path: Optional[str] = None,
                  include_builtin: bool = True):
        return self.interceptor.scan_yara(
            rules_text=rules_text,
            rules_path=rules_path,
            include_builtin=include_builtin,
        )

    def analyze_games(self):
        return analyze_game_streams(self.streams())

    @property
    def memory(self):
        """Motor de memoria en modo solo lectura (v1)."""
        return self.interceptor.memory_engine(read_only=True)

    # ---------- exportación ----------
    def export_pcapng(self, path: str, include_secrets: bool = True,
                      include_dns: bool = True) -> str:
        return self.interceptor.export_pcapng(
            path, include_secrets=include_secrets, include_dns=include_dns)

    def export_har(self, path: str) -> str:
        return self.interceptor.export_har(path)

    def export_keylog(self, path: str) -> str:
        return self.interceptor.export_tls_keylog(path)

    def export_json(self, path: str) -> str:
        streams = self.streams()
        iocs = self.extract_iocs()
        yara_matches = self.scan_yara()
        payload = {
            'captured_at': time.time(),
            'root_pid': self.interceptor._root_pid,
            'child_pids': self.child_pids(),
            'dns_map': self.dns_table(),
            'tls_keylog_count': len(self.tls_keys()),
            'streams': [
                {
                    'fd': s.fd,
                    'pid': s.pid,
                    'proto': s.proto,
                    'peer': s.peer,
                    'peer_ip': s.peer_ip,
                    'peer_port': s.peer_port,
                    'peer_host': s.peer_host,
                    'closed': s.closed,
                    'byte_out': s.byte_out,
                    'byte_in': s.byte_in,
                    'event_count': s.event_count,
                    'call_stacks': s.call_stacks,
                    'out_preview': bytes(s.out_data[:512]).decode('utf-8', 'replace'),
                    'in_preview': bytes(s.in_data[:512]).decode('utf-8', 'replace'),
                }
                for s in streams
            ],
            'iocs': iocs.to_dict(),
            'yara_matches': [m.to_dict() for m in yara_matches],
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return path
