# -*- coding: utf-8 -*-
"""Genera un .pcapng sintético de prueba y un .txt de resumen para Wireshark."""
import os
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core.pcapng import build_pcapng
from core.interceptor import SocketStream

st1 = SocketStream(fd=123, proto='TCP', peer='93.184.216.34:443')
st1.out_data += b'GET / HTTP/1.1\r\nHost: netscope.local\r\nUser-Agent: netscope\r\n\r\n'
st1.in_data += b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHola mundo!\r\n'
st2 = SocketStream(fd=777, proto='UDP', peer='1.1.1.1:53')
st2.out_data += b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
st2.in_data += b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\xc0...AAA'
st3 = SocketStream(fd=-17, proto='TLS', peer='pseudo')   # stream plano Schannel
st3.out_data += b'POST /api/login HTTP/1.1\r\nHost: ej.com\r\nContent-Length: 7\r\n\r\nsecret1'

out_path = os.path.join(BASE, 'samples', 'netscope_demo.pcapng')
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, 'wb') as f:
    f.write(build_pcapng([st1, st2, st3]))
print('PCAPNG demo generado en:', out_path)
