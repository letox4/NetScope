"""Verifica captura de texto claro en las APIs de WinHTTP."""
import http.server
import os
import subprocess
import sys
import threading
import time
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core.interceptor import FridaInterceptor


RESPONSE = b'netscope-winhttp-response'
REQUEST = b'netscope-winhttp-request'


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header('Content-Length', str(len(RESPONSE)))
        self.end_headers()
        self.wfile.write(RESPONSE)

    def log_message(self, *_args):
        pass


class WinHttpCaptureTest(unittest.TestCase):
    def test_request_and_response_are_captured_in_plaintext(self):
        server = http.server.HTTPServer(('127.0.0.1', 0), _Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        ps_script = (
            "$r = New-Object -ComObject WinHttp.WinHttpRequest.5.1; "
            "Start-Sleep -Seconds 2; "
            f"$r.Open('POST', 'http://127.0.0.1:{port}/audit', $false); "
            "$r.SetRequestHeader('X-NetScope-Test', 'winhttp'); "
            f"$r.Send('{REQUEST.decode()}'); "
            "$null = $r.ResponseText"
        )
        child = subprocess.Popen(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        events = []
        ic = FridaInterceptor(
            on_event=events.append,
            on_status=lambda _status: None,
            on_log=lambda _message: None,
        )
        try:
            time.sleep(0.5)
            ic.attach(pid=child.pid)
            deadline = time.time() + 15
            while time.time() < deadline and child.poll() is None:
                if (any(ev.event == 'http_out' and REQUEST in ev.data for ev in events)
                        and any(ev.event == 'http_in' and RESPONSE in ev.data
                                for ev in events)):
                    break
                time.sleep(0.05)

            self.assertTrue(
                any(ev.event == 'http_out' and REQUEST in ev.data for ev in events),
                'WinHTTP request body was not observed')
            self.assertTrue(
                any(ev.event == 'http_in' and RESPONSE in ev.data for ev in events),
                'WinHTTP response body was not observed')
            self.assertTrue(
                any(ev.event == 'http_out' and b'POST /audit' in ev.data
                    and ev.peer_ip == '127.0.0.1' and ev.peer_port == port
                    for ev in events),
                'WinHTTP method, path and peer were not associated with the request')
        finally:
            ic.stop()
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
