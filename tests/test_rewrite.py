# -*- coding: utf-8 -*-
"""Test de reescritura en vivo (patch en onEnter de send)."""
import http.client
import http.server
import os
import sys
import threading
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core.interceptor import FridaInterceptor


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


def test_live_rewrite_send():
    ic = FridaInterceptor(
        on_event=lambda ev: None,
        on_status=lambda s: None,
        on_log=lambda s: None,
    )
    srv = http.server.HTTPServer(('127.0.0.1', 0), _S)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ic.attach(pid=os.getpid())

        rejected = False
        try:
            ic.set_patch_rules([{
                'hex_match': '4e657453636f7065204f4b',
                'hex_replace': '4e657453636f70653220474f01',
            }])
        except ValueError:
            rejected = True
        assert rejected, 'La regla de longitud desigual debió rechazarse'
        ic.clear_patch_rules()

        ok_rule = {
            'hex_match': 'NetScope OK'.encode().hex(),
            'hex_replace': 'NetScope GO'.encode().hex(),
        }
        n = ic.set_patch_rules([ok_rule])
        assert n == 1
        time.sleep(0.1)

        c = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        c.request('GET', '/')
        resp = c.getresponse()
        body = resp.read()
        c.close()
        assert b'NetScope GO' in body, f'Regla no aplicada: {body!r}'
    finally:
        ic.stop()
        srv.shutdown()
        srv.server_close()


if __name__ == '__main__':
    test_live_rewrite_send()
    print('REWRITE TEST OK')
