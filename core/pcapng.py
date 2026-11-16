# -*- coding: utf-8 -*-
"""NetScope - exportación PCAPNG.

Empaqueta los SocketStream reensamblados como frames Ethernet+IPv4+TCP/UDP
(linktype Ethernet) para abrirlos directamente en Wireshark.

Si el stream dispone de IPv4/puerto reales observados en el peer, los usa en las
cabeceras IPv4/TCP/UDP (con fallback determinista a 10.200.0.x y pseudo_ports).
Cuando se proporcionan claves TLS (`tls_keylog`) o resoluciones DNS (`dns_map`),
embebe bloques estándar DSB (Decryption Secrets Block, 0x0000000A) y NRB
(Name Resolution Block, 0x00000004) para que Wireshark descifre TLS y muestre
nombres de dominio automáticamente.

Formato PCAPNG:
  SHB  (Section Header Block)        type 0x0A0D0D0A, BOM 0x1A2B3C4D
  IDB  (Interface Description)       type 0x00000001, linktype 1, snaplen 65535
  NRB  (Name Resolution Block)       type 0x00000004 (opcional, si hay dns_map)
  DSB  (Decryption Secrets Block)    type 0x0000000A (opcional, si hay tls_keylog)
  EPB  (Enhanced Packet Block)       type 0x00000006, uno por dirección/stream
"""
import ipaddress
import re
import socket
import struct
import time
from typing import Dict, Iterable, Optional, Tuple

_SHB_TYPES = 0x0A0D0D0A
_IDB_TYPE = 0x00000001
_NRB_TYPE = 0x00000004
_EPB_TYPE = 0x00000006
_DSB_TYPE = 0x0000000A
_SHP_EOF = 0x00000000

_DSB_TLS_KEY_LOG = 0x544C534B  # "TLSK" little-endian

LINKTYPE_ETHERNET = 0x0001
SNAPLEN = 65535

_MAC_SRC = b"\x02\x00\x5e\x00\x53\x11"   # Rango RFC: no confundir con tráfico real
_MAC_DST = b"\x02\x00\x5e\x00\x53\x12"
_IP_A = bytes((10, 200, 0, 2))
_IP_B = bytes((10, 200, 0, 1))
_IPV4_PORT_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})')


def _pad4(data: bytes) -> bytes:
    rest = len(data) % 4
    return data + b"\x00" * ((4 - rest) % 4)


def _block(kind: int, body: bytes) -> bytes:
    """Bloque PCAPNG: type(4) + total_len(4) + body + pad + total_len(4)."""
    padded = _pad4(body)
    total = 12 + len(padded)
    return (struct.pack("<II", kind, total) + padded
            + struct.pack("<I", total))


def _opt(code: int, data: bytes = b"") -> bytes:
    """Opción PCAPNG: code(2) + length(2) + valor(padded). code=0 → terminador."""
    if code == 0:
        return struct.pack("<HH", 0, 0)
    return struct.pack("<HH", code, len(data)) + _pad4(data)


def shb_block() -> bytes:
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)  # bom, v.major, v.minor, seclen(-1)
    body += _opt(2, b"NetScope")            # shb_userappl
    body += _opt(3, b"es")                  # UTF-8 comment: opcional
    body += _opt(0)
    return _block(_SHB_TYPES, body)


def idb_block() -> bytes:
    body = struct.pack("<HHI", LINKTYPE_ETHERNET, 0, SNAPLEN)  # linktype, reservado, snaplen
    body += _opt(9, struct.pack("<B", 6))   # if_tsresol = 6 → microsegundos
    body += _opt(0)
    return _block(_IDB_TYPE, body)


def dsb_block(keylog_lines: Iterable[str]) -> Optional[bytes]:
    """Decryption Secrets Block (TLS Key Log) para Wireshark."""
    lines = [ln.strip() for ln in keylog_lines if ln and ln.strip()]
    if not lines:
        return None
    secrets = ("\n".join(lines) + "\n").encode("utf-8")
    body = struct.pack("<II", _DSB_TLS_KEY_LOG, len(secrets)) + _pad4(secrets)
    return _block(_DSB_TYPE, body)


def nrb_block(dns_map: Dict[str, str]) -> Optional[bytes]:
    """Name Resolution Block (mapeo IPv4 -> dominio) para Wireshark."""
    if not dns_map:
        return None
    records = bytearray()
    count = 0
    for ip_str, host in dns_map.items():
        if not ip_str or not host:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            continue
        name_bytes = host.strip().encode("utf-8", errors="ignore") + b"\x00"
        if ip_obj.version == 4:
            rec_val = ip_obj.packed + name_bytes
            records += struct.pack("<HH", 0x0001, len(rec_val)) + _pad4(rec_val)
            count += 1
        elif ip_obj.version == 6:
            rec_val = ip_obj.packed + name_bytes
            records += struct.pack("<HH", 0x0002, len(rec_val)) + _pad4(rec_val)
            count += 1
    if count == 0:
        return None
    records += struct.pack("<HH", 0x0000, 0)  # nrb_record_end
    return _block(_NRB_TYPE, bytes(records))


def eof_block() -> bytes:
    return _block(_SHP_EOF, b"")


def ip_checksum(hdr_wo: bytes) -> int:
    if len(hdr_wo) & 1:
        hdr_wo += b"\x00"
    s = 0
    for i in range(0, len(hdr_wo), 2):
        s += (hdr_wo[i] << 8) | hdr_wo[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip_header(payload_len: int, proto: int, src: bytes, dst: bytes) -> bytes:
    total = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH4s4s",
                      0x45, 0, total & 0xFFFF, 0, 0x4000,   # ver=4, IHL=5, DF
                      64, proto, 0, src, dst)
    return hdr[:10] + struct.pack("!H", ip_checksum(hdr)) + hdr[12:]


def tcp_header(sport: int, dport: int, seq: int) -> bytes:
    return struct.pack("!HHIIBBHHH",
                       sport, dport, seq & 0xFFFFFFFF, 1,   # seq, ack
                       (5 << 4), 0x18,                      # data off 5, PSH|ACK
                       0xFFFF, 0, 0)                        # window, cksum=0, urgent ptr


def udp_header(sport: int, dport: int, payload_len: int) -> bytes:
    return struct.pack("!HHHH", sport, dport, (8 + payload_len) & 0xFFFF, 0)


def pseudo_ports(fd: int) -> Tuple[int, int]:
    """Puertos TCP/UDP sintéticos ESTABLES por fd (falsos, no colisionan con
    puertos reales de la app)."""
    sport = 18000 + (abs(fd) * 7919) % 44000   # 18000..61999
    dport = 18000 + (abs(fd) * 104729) % 44000
    return sport, dport


def _resolve_stream_endpoints(st) -> Tuple[bytes, bytes, int, int]:
    """Obtiene IPs y puertos (usa IPv4/puerto reales si están disponibles)."""
    sport, dport = pseudo_ports(st.fd)
    ip_a, ip_b = _IP_A, _IP_B
    peer_ip = getattr(st, "peer_ip", None)
    peer_port = getattr(st, "peer_port", None)
    if not peer_ip and getattr(st, "peer", None):
        m = _IPV4_PORT_RE.search(st.peer)
        if m:
            peer_ip = m.group(1)
            try:
                peer_port = int(m.group(2))
            except ValueError:
                peer_port = None
    if peer_ip:
        try:
            packed = socket.inet_aton(peer_ip)
            ip_b = packed
            ip_a = bytes((127, 0, 0, 1)) if packed == b"\x7f\x00\x00\x01" else _IP_A
        except OSError:
            pass
    if peer_port and 1 <= int(peer_port) <= 65535:
        dport = int(peer_port)
    return ip_a, ip_b, sport, dport


def stream_frames(st):
    """Frames Ethernet (out e in) de un SocketStream. st: SocketStream."""
    proto = (st.proto or 'TCP').upper()
    ip_proto = 17 if proto.startswith('UDP') else 6   # TCP (TLS se tramita sobre TCP)
    ip_a, ip_b, sport, dport = _resolve_stream_endpoints(st)
    frames = []
    for direction, ip_src, ip_dst, p_src, p_dst in (
        ('out', ip_a, ip_b, sport, dport),
        ('in', ip_b, ip_a, dport, sport),
    ):
        payload = bytes(getattr(st, 'out_data' if direction == 'out' else 'in_data'))
        if not payload:
            continue
        eth = _MAC_SRC + _MAC_DST + b"\x08\x00"
        if ip_proto == 17:
            l4 = udp_header(p_src, p_dst, len(payload))
        else:
            l4 = tcp_header(p_src, p_dst, len(payload))
        ip = ip_header(len(l4) + len(payload), ip_proto, ip_src, ip_dst)
        frames.append(eth + ip + l4 + payload)
    return frames


def build_pcapng(streams, tls_keylog: Optional[Iterable[str]] = None,
                 dns_map: Optional[Dict[str, str]] = None) -> bytes:
    """streams: iterable de SocketStream (core/interceptor.py). → bytes .pcapng."""
    out = bytearray()
    out += shb_block()
    out += idb_block()
    if dns_map:
        nrb = nrb_block(dns_map)
        if nrb:
            out += nrb
    if tls_keylog:
        dsb = dsb_block(tls_keylog)
        if dsb:
            out += dsb
    for st in streams:
        ts = int((st.opened_ts or time.time()) * 1_000_000)   # usec
        for frame in stream_frames(st):
            cap = min(len(frame), SNAPLEN)
            body = struct.pack("<IIIII", 0,  # interface_id
                               ts >> 32, ts & 0xFFFFFFFF,
                               cap, len(frame))
            body += frame[:cap]
            body += _opt(0)
            out += _block(_EPB_TYPE, body)
    out += eof_block()
    return bytes(out)
