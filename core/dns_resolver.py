# -*- coding: utf-8 -*-
"""NetScope - Resolución y correlación IP ↔ Nombre de dominio.

Combina múltiples fuentes para traducir direcciones IP a nombres de dominio:
  1. Hooks en vivo del agente Frida (getaddrinfo / GetAddrInfoW / DnsQuery).
  2. Inspección pasiva de tráfico: cabecera HTTP Host, SNI en TLS ClientHello
     y respuestas DNS sobre UDP/53.
  3. Resolución inversa (rDNS) asíncrona opcional vía socket.gethostbyaddr.
"""
import ipaddress
import re
import socket
import struct
import threading
from typing import Dict, List, Optional, Set


_HTTP_HOST_RE = re.compile(rb'(?im)^Host:\s*([^\r\n:\s]+)(?::\d+)?\s*\r?$')
_DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$|^localhost$')


def _is_valid_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    clean = value.strip()
    if clean.startswith('ipv6[') and clean.endswith(']'):
        return True
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def _clean_host(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    h = host.split('\x00', 1)[0].strip().rstrip('.').lower()
    if not h or _is_valid_ip(h):
        return None
    if len(h) > 253:
        return None
    # Rechazar caracteres de control, espacios o basura Unicode fuera de nombres DNS válidos
    if not re.match(r'^[a-z0-9._-]+$', h):
        return None
    return h


def extract_http_host(data: bytes) -> Optional[str]:
    """Extrae el nombre de dominio de una cabecera HTTP Host:."""
    if not data or len(data) < 8:
        return None
    head = data[:4096]
    m = _HTTP_HOST_RE.search(head)
    if not m:
        return None
    try:
        raw = m.group(1).decode('ascii', errors='ignore')
    except Exception:
        return None
    return _clean_host(raw)


def extract_tls_sni(data: bytes) -> Optional[str]:
    """Extrae el Server Name Indication (SNI) de un TLS ClientHello."""
    if not data or len(data) < 43:
        return None
    # TLS Record: ContentType=22 (Handshake), Version 0x0300..0x0304
    if data[0] != 0x16 or data[1] != 0x03:
        return None
    rec_len = struct.unpack_from('!H', data, 3)[0]
    if 5 + rec_len > len(data) and len(data) < 60:
        return None
    # Handshake type = 1 (ClientHello)
    if data[5] != 0x01:
        return None
    pos = 5 + 4  # skip handshake type(1) + length(3)
    if pos + 2 + 32 + 1 > len(data):
        return None
    pos += 2 + 32  # client_version(2) + random(32)
    sess_len = data[pos]
    pos += 1 + sess_len
    if pos + 2 > len(data):
        return None
    cs_len = struct.unpack_from('!H', data, pos)[0]
    pos += 2 + cs_len
    if pos + 1 > len(data):
        return None
    comp_len = data[pos]
    pos += 1 + comp_len
    if pos + 2 > len(data):
        return None
    ext_total = struct.unpack_from('!H', data, pos)[0]
    pos += 2
    end_ext = min(len(data), pos + ext_total)
    while pos + 4 <= end_ext:
        ext_type, ext_len = struct.unpack_from('!HH', data, pos)
        pos += 4
        if pos + ext_len > end_ext:
            break
        if ext_type == 0x0000 and ext_len >= 5:
            # server_name extension
            list_len = struct.unpack_from('!H', data, pos)[0]
            spos = pos + 2
            send = min(pos + ext_len, spos + list_len)
            while spos + 3 <= send:
                name_type = data[spos]
                name_len = struct.unpack_from('!H', data, spos + 1)[0]
                spos += 3
                if spos + name_len > send:
                    break
                if name_type == 0x00:
                    raw = data[spos:spos + name_len].decode('ascii', errors='ignore')
                    return _clean_host(raw)
                spos += name_len
        pos += ext_len
    return None


def _read_dns_name(buf: bytes, offset: int, depth: int = 0) -> tuple[Optional[str], int]:
    """Decodifica un nombre DNS con soporte de punteros de compresión (RFC 1035)."""
    if depth > 8 or offset >= len(buf):
        return None, offset
    labels = []
    cur = offset
    jumped = False
    next_off = offset
    while cur < len(buf):
        length = buf[cur]
        if length == 0:
            if not jumped:
                next_off = cur + 1
            break
        if (length & 0xC0) == 0xC0:
            if cur + 1 >= len(buf):
                return None, cur + 1
            ptr = ((length & 0x3F) << 8) | buf[cur + 1]
            if not jumped:
                next_off = cur + 2
            jumped = True
            cur = ptr
            depth += 1
            if depth > 12:
                return None, next_off
            continue
        cur += 1
        if cur + length > len(buf):
            return None, len(buf)
        labels.append(buf[cur:cur + length].decode('ascii', errors='replace'))
        cur += length
        if not jumped:
            next_off = cur
    name = '.'.join(labels)
    return name or None, next_off


def parse_dns_response(data: bytes) -> Dict[str, List[str]]:
    """Extrae pares {dominio: [ips]} desde un datagrama de respuesta DNS."""
    out: Dict[str, List[str]] = {}
    if not data or len(data) < 12:
        return out
    _txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack_from('!HHHHHH', data, 0)
    is_response = bool(flags & 0x8000)
    if not is_response or qdcount == 0 or ancount == 0 or qdcount > 16 or ancount > 64:
        return out
    pos = 12
    qnames: List[str] = []
    for _ in range(qdcount):
        qname, pos = _read_dns_name(data, pos)
        if pos + 4 > len(data):
            return out
        pos += 4  # qtype + qclass
        if qname:
            qnames.append(qname)
    for _ in range(ancount):
        if pos >= len(data):
            break
        aname, pos = _read_dns_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack_from('!HHIH', data, pos)
        pos += 10
        if pos + rdlen > len(data):
            break
        rdata = data[pos:pos + rdlen]
        pos += rdlen
        host = _clean_host(aname or (qnames[0] if qnames else None))
        if not host:
            continue
        if rtype == 1 and rdlen == 4:  # A
            ip = socket.inet_ntop(socket.AF_INET, rdata)
            out.setdefault(host, []).append(ip)
        elif rtype == 28 and rdlen == 16:  # AAAA
            ip = socket.inet_ntop(socket.AF_INET6, rdata)
            out.setdefault(host, []).append(ip)
    return out


class DnsResolver:
    """Caché thread-safe para correlacionar direcciones IP con nombres DNS."""

    def __init__(self, enable_rdns: bool = True):
        self._lock = threading.RLock()
        self._ip_to_host: Dict[str, str] = {}
        self._host_to_ips: Dict[str, Set[str]] = {}
        self._rdns_seen: Set[str] = set()
        self._rdns_sem = threading.Semaphore(4)
        self.enable_rdns = bool(enable_rdns)

    def record(self, ip: Optional[str], host: Optional[str]) -> Optional[str]:
        if not _is_valid_ip(ip):
            return None
        clean = _clean_host(host)
        if not clean:
            return None
        ip_norm = ip.strip()
        with self._lock:
            self._ip_to_host[ip_norm] = clean
            self._host_to_ips.setdefault(clean, set()).add(ip_norm)
        return clean

    def get_host(self, ip: Optional[str]) -> Optional[str]:
        if not ip:
            return None
        with self._lock:
            return self._ip_to_host.get(ip.strip())

    def resolve(self, ip: Optional[str], async_lookup: bool = True,
                on_resolved=None) -> Optional[str]:
        """Devuelve el dominio conocido para `ip`, lanzando rDNS en background si aplica."""
        if not ip:
            return None
        ip_norm = ip.strip()
        existing = self.get_host(ip_norm)
        if existing:
            return existing
        if not self.enable_rdns or not async_lookup or not _is_valid_ip(ip_norm):
            return None
        if ip_norm.startswith('ipv6['):
            return None
        if ip_norm in ('127.0.0.1', '::1', '0.0.0.0'):
            return None
        with self._lock:
            if ip_norm in self._rdns_seen:
                return None
            self._rdns_seen.add(ip_norm)

        def _worker():
            with self._rdns_sem:
                try:
                    host, _, _ = socket.gethostbyaddr(ip_norm)
                except Exception:
                    return
                recorded = self.record(ip_norm, host)
                if recorded and callable(on_resolved):
                    try:
                        on_resolved(ip_norm, recorded)
                    except Exception:
                        pass

        threading.Thread(target=_worker, daemon=True, name='NetScope-rDNS').start()
        return None

    def inspect_payload(self, peer_ip: Optional[str], data: bytes,
                        peer_port: Optional[int] = None) -> Optional[str]:
        """Inspecciona HTTP Host, TLS SNI y respuestas DNS UDP/53."""
        if not data:
            return None
        if peer_port == 53:
            dns_map = parse_dns_response(data)
            for host, ips in dns_map.items():
                for ip in ips:
                    self.record(ip, host)
        host = extract_http_host(data) or extract_tls_sni(data)
        if host and peer_ip:
            self.record(peer_ip, host)
        return host

    def format_peer(self, ip: Optional[str], port: Optional[int],
                    host: Optional[str] = None) -> str:
        """Formatea peer conservando IP:puerto y anteponiendo dominio si existe."""
        resolved = _clean_host(host) or self.get_host(ip)
        if ip:
            addr = f'{ip}:{port}' if port is not None else str(ip)
            if resolved and resolved.lower() != str(ip).lower():
                return f'{resolved} ({addr})'
            return addr
        if resolved:
            return f'{resolved}:{port}' if port is not None else resolved
        return '?'

    def snapshot(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._ip_to_host)

    def host_map(self) -> Dict[str, List[str]]:
        with self._lock:
            return {h: sorted(ips) for h, ips in self._host_to_ips.items()}

    def clear(self) -> None:
        with self._lock:
            self._ip_to_host.clear()
            self._host_to_ips.clear()
            self._rdns_seen.clear()
