# -*- coding: utf-8 -*-
"""Proceso de prueba: genera HTTP (loopback) + UDP de eco en bucle."""
import http.client
import http.server
import socket
import sys
import threading
import time


class _S(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<html><body>NetScope OK</body></html>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = http.server.HTTPServer(('127.0.0.1', 18765), _S)
threading.Thread(target=srv.serve_forever, daemon=True).start()

r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
r.bind(('127.0.0.1', 17654))
r.settimeout(1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

end = time.time() + 8
while time.time() < end:
    try:
        c = http.client.HTTPConnection('127.0.0.1', 18765, timeout=3)
        c.request('GET', '/', headers={'User-Agent': 'netscope-test'})
        resp = c.getresponse()
        resp.read()
        c.close()
    except Exception as e:
        print('[tcp] err', e, flush=True)
    s.sendto(b'UDP-PEEK-NETSCOPE', ('127.0.0.1', 17654))
    try:
        r.recvfrom(4096)
    except socket.timeout:
        pass
    time.sleep(0.3)
