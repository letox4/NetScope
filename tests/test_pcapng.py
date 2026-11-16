# -*- coding: utf-8 -*-
"""Test PCAPNG: estructura de bloques válida + contenido de frames esperado."""
import os
import struct
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core.pcapng import build_pcapng, pseudo_ports
from core.interceptor import SocketStream


def test_pcapng_blocks_and_frames():
    st1 = SocketStream(fd=123, proto='TCP', peer='93.184.216.34:443')
    st1.opened_ts = time.time() - 10
    st1.out_data += b'GET / HTTP/1.1\r\nHost: ej.com\r\n\r\n'
    st1.in_data += b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nHola\r\n'
    st2 = SocketStream(fd=777, proto='UDP', peer='1.1.1.1:53')
    st2.opened_ts = time.time() - 5
    st2.out_data += b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'

    blob = build_pcapng([st1, st2])

    off = 0
    SHB, IDB, EPB, EOF = 0x0A0D0D0A, 0x00000001, 0x00000006, 0x00000000
    counts = {SHB: 0, IDB: 0, EPB: 0, EOF: 0}
    frames = []
    while off + 12 <= len(blob):
        kind, total = struct.unpack_from('<II', blob, off)
        if kind == SHB:
            bom = struct.unpack_from('<I', blob, off + 8)[0]
            assert bom == 0x1A2B3C4D
            counts[kind] += 1
            off += total
            continue
        body = blob[off + 8:off + 8 + total - 12]
        counts[kind] = counts.get(kind, 0) + 1
        if kind == IDB:
            linktype, _res, snap = struct.unpack_from('<HHI', body, 0)
            assert linktype == 1
        if kind == EPB:
            iface, tsh, tsl, cap, olen = struct.unpack_from('<IIIII', body, 0)
            frame = body[20:20 + cap]
            frames.append(frame)
        off += total

    assert counts[SHB] == 1 and counts[IDB] == 1
    assert counts[EPB] == 3, 'esperados 3 frames: 2 dirs TCP (TX+RX) + 1 dir UDP (TX)'
    assert counts[EOF] == 1

    eth_len = 14
    for fr, want_ipproto in [(frames[0], 6), (frames[1], 6), (frames[2], 17)]:
        proto_ip = fr[eth_len + 9]
        assert proto_ip == want_ipproto, f'ip proto {proto_ip} != {want_ipproto}'
    assert b'GET / HTTP/1.1' in frames[0] or b'GET / HTTP/1.1' in frames[1]
    assert b'HTTP/1.1 200 OK' in frames[0] or b'HTTP/1.1 200 OK' in frames[1]

    assert pseudo_ports(123) == pseudo_ports(123)
    assert pseudo_ports(123) != pseudo_ports(777)


if __name__ == '__main__':
    test_pcapng_blocks_and_frames()
    print('PCAPNG OK')
