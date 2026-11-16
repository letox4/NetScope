# -*- coding: utf-8 -*-
"""NetScope Demo Target Lab — aplicación de demostración propia (sin terceros).

Genera tráfico local real en 127.0.0.1 para probar y demostrar todas las
capacidades de NetScope sin usar software de terceros:
  1. HTTP/1.1 sobre TCP clásico (send/recv)
  2. TCP asíncrono con Winsock Overlapped I/O + IOCP (WSASend/WSARecv + GetQueuedCompletionStatus)
  3. UDP comprimido (zlib) + JSON
  4. Resolución DNS (getaddrinfo)
  5. TLS local con OpenSSL (SSL_write / SSL_read + SSLKEYLOGFILE)
  6. Payloads benignos de prueba para extracción de IOCs y reglas YARA
  7. Creación opcional de un proceso hijo trabajador (--spawn-child)

Modos de uso:
  py -3.11 demo_app.py                 # Abre ventana interactiva PySide6
  py -3.11 demo_app.py --once          # Ejecuta un ciclo completo y termina
  py -3.11 demo_app.py --headless      # Ejecuta ciclos en consola
"""
import argparse
import ctypes
from ctypes import wintypes
import http.client
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import zlib


# ---------- Generación de certificado efímero para servidor TLS local ----------

def create_ephemeral_cert(tmpdir: str):
    """Genera cert.pem y key.pem temporales en disco (sin claves fijas en el repo)."""
    cert_path = os.path.join(tmpdir, 'cert.pem')
    key_path = os.path.join(tmpdir, 'key.pem')
    cfg_path = os.path.join(tmpdir, 'openssl.cnf')
    with open(cfg_path, 'w', encoding='ascii') as f:
        f.write('[req]\ndistinguished_name=dn\n[dn]\nCN=localhost\n')

    openssl_bin = shutil.which('openssl')
    if openssl_bin:
        res = subprocess.run(
            [
                openssl_bin, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-config', cfg_path,
                '-keyout', key_path, '-out', cert_path,
                '-days', '1', '-subj', '/CN=localhost',
            ],
            capture_output=True, text=True, timeout=15,
        )
        if res.returncode == 0 and os.path.exists(cert_path) and os.path.exists(key_path):
            return cert_path, key_path
    return None, None


# ---------- Cliente Winsock Overlapped + IOCP vía ctypes ----------

def run_winsock_iocp_roundtrip(port: int, payload: bytes = b'IOCP-HELLO-NETSCOPE\n') -> bytes:
    """Ejecuta un cliente TCP usando WSASocketW + WSASend + WSARecv + IOCP."""
    if os.name != 'nt':
        with socket.create_connection(('127.0.0.1', port), timeout=3) as s:
            s.sendall(payload)
            return s.recv(1024)

    ws2 = ctypes.WinDLL('ws2_32', use_last_error=True)
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)

    class WSAData(ctypes.Structure):
        _fields_ = [('raw', ctypes.c_ubyte * 408)]

    class WSABUF(ctypes.Structure):
        _fields_ = [('len', ctypes.c_ulong), ('buf', ctypes.c_void_p)]

    class SOCKADDR_IN(ctypes.Structure):
        _fields_ = [
            ('sin_family', ctypes.c_ushort),
            ('sin_port', ctypes.c_ushort),
            ('sin_addr', ctypes.c_ubyte * 4),
            ('sin_zero', ctypes.c_ubyte * 8),
        ]

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ('Internal', ctypes.c_size_t),
            ('InternalHigh', ctypes.c_size_t),
            ('Offset', ctypes.c_ulong),
            ('OffsetHigh', ctypes.c_ulong),
            ('hEvent', wintypes.HANDLE),
        ]

    ws2.WSAStartup.argtypes = [ctypes.c_ushort, ctypes.POINTER(WSAData)]
    ws2.WSAStartup.restype = ctypes.c_int
    ws2.WSASocketW.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
    ws2.WSASocketW.restype = ctypes.c_size_t
    ws2.connect.argtypes = [ctypes.c_size_t, ctypes.POINTER(SOCKADDR_IN), ctypes.c_int]
    ws2.connect.restype = ctypes.c_int
    ws2.WSASend.argtypes = [ctypes.c_size_t, ctypes.POINTER(WSABUF), ctypes.c_ulong,
                            ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong,
                            ctypes.POINTER(OVERLAPPED), ctypes.c_void_p]
    ws2.WSASend.restype = ctypes.c_int
    ws2.WSARecv.argtypes = [ctypes.c_size_t, ctypes.POINTER(WSABUF), ctypes.c_ulong,
                            ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong),
                            ctypes.POINTER(OVERLAPPED), ctypes.c_void_p]
    ws2.WSARecv.restype = ctypes.c_int
    ws2.WSAGetLastError.argtypes = []
    ws2.WSAGetLastError.restype = ctypes.c_int
    ws2.closesocket.argtypes = [ctypes.c_size_t]
    ws2.closesocket.restype = ctypes.c_int

    k32.CreateIoCompletionPort.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                                           ctypes.c_size_t, ctypes.c_ulong]
    k32.CreateIoCompletionPort.restype = wintypes.HANDLE
    k32.GetQueuedCompletionStatus.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.POINTER(OVERLAPPED)),
        ctypes.c_ulong,
    ]
    k32.GetQueuedCompletionStatus.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL

    wsa = WSAData()
    ws2.WSAStartup(0x0202, ctypes.byref(wsa))
    sock = ws2.WSASocketW(2, 1, 6, None, 0, 0x01)  # AF_INET, SOCK_STREAM, TCP, WSA_FLAG_OVERLAPPED
    if sock == ctypes.c_size_t(-1).value:
        raise OSError('WSASocketW failed')

    iocp = None
    try:
        iocp = k32.CreateIoCompletionPort(wintypes.HANDLE(sock), None, 0x1337, 1)
        sa = SOCKADDR_IN()
        sa.sin_family = 2
        sa.sin_port = socket.htons(port)
        sa.sin_addr = (ctypes.c_ubyte * 4)(127, 0, 0, 1)
        if ws2.connect(sock, ctypes.byref(sa), ctypes.sizeof(sa)) != 0:
            raise OSError(f'connect failed: {ws2.WSAGetLastError()}')

        def wait_iocp(target_ovl):
            target_addr = ctypes.addressof(target_ovl)
            deadline = time.time() + 5.0
            while time.time() < deadline:
                tr = ctypes.c_ulong(0)
                key = ctypes.c_size_t(0)
                ovl_p = ctypes.POINTER(OVERLAPPED)()
                ok = k32.GetQueuedCompletionStatus(
                    iocp, ctypes.byref(tr), ctypes.byref(key),
                    ctypes.byref(ovl_p), 2000,
                )
                if not ok and not ovl_p:
                    continue
                if ovl_p and ctypes.addressof(ovl_p.contents) == target_addr:
                    return tr.value
            return 0

        # WSASend overlapped
        out_buf = ctypes.create_string_buffer(payload, len(payload))
        wbuf_out = WSABUF(len(payload), ctypes.addressof(out_buf))
        ovl_send = OVERLAPPED()
        sent = ctypes.c_ulong(0)
        rc = ws2.WSASend(sock, ctypes.byref(wbuf_out), 1, ctypes.byref(sent), 0,
                         ctypes.byref(ovl_send), None)
        if rc == 0 or ws2.WSAGetLastError() == 997:
            if iocp:
                wait_iocp(ovl_send)

        # WSARecv overlapped (el servidor tarda ~120ms para forzar WSA_IO_PENDING)
        in_raw = ctypes.create_string_buffer(1024)
        wbuf_in = WSABUF(1024, ctypes.addressof(in_raw))
        ovl_recv = OVERLAPPED()
        recvd = ctypes.c_ulong(0)
        flags = ctypes.c_ulong(0)
        rc = ws2.WSARecv(sock, ctypes.byref(wbuf_in), 1, ctypes.byref(recvd),
                         ctypes.byref(flags), ctypes.byref(ovl_recv), None)
        total = recvd.value
        if rc == 0 or ws2.WSAGetLastError() == 997:
            if iocp:
                n = wait_iocp(ovl_recv)
                if n > 0:
                    total = n

        return in_raw.raw[:total]
    finally:
        ws2.closesocket(sock)
        if iocp:
            k32.CloseHandle(iocp)


# ---------- Servidores locales de la app de demo ----------

class _DemoHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/api/v1/status'):
            body = json.dumps({
                'service': 'netscope-demo',
                'status': 'healthy',
                'version': '1.0',
            }).encode('utf-8')
        elif self.path.startswith('/ioc-probe'):
            # Payload benigno para demostrar extracción de IOCs + YARA
            body = (
                b'{"probe":"ok","callback":"http://c2-sim.netscope.local/beacon",'
                b'"eicar":"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"}'
            )
        else:
            body = b'{"tls":"ok","engine":"openssl"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get('Content-Length', '0') or '0')
        req_body = self.rfile.read(n) if n > 0 else b''
        resp = json.dumps({'received_bytes': len(req_body), 'ok': True}).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *args):
        pass


class DemoTrafficLab:
    """Orquesta servidores locales y genera todos los patrones de tráfico de prueba."""

    def __init__(self, log_fn=None):
        self.log_fn = log_fn or (lambda msg: None)
        self._tmpdir = tempfile.mkdtemp(prefix='netscope_demo_')
        self._stop_ev = threading.Event()

        # 1. HTTP servidor
        self.http_srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _DemoHTTPHandler)
        self.http_port = self.http_srv.server_address[1]
        threading.Thread(target=self.http_srv.serve_forever, daemon=True).start()

        # 2. TCP IOCP echo servidor (con retraso intencional de 120 ms en respuesta)
        self._iocp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._iocp_srv.bind(('127.0.0.1', 0))
        self._iocp_srv.listen(8)
        self.iocp_port = self._iocp_srv.getsockname()[1]
        threading.Thread(target=self._serve_iocp, daemon=True).start()

        # 3. UDP servidor
        self._udp_srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_srv.bind(('127.0.0.1', 0))
        self.udp_port = self._udp_srv.getsockname()[1]
        threading.Thread(target=self._serve_udp, daemon=True).start()

        # 4. TLS servidor (OpenSSL)
        self.tls_port = None
        self._tls_srv = None
        cert_path, key_path = create_ephemeral_cert(self._tmpdir)
        if cert_path and key_path:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
                self._tls_srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _DemoHTTPHandler)
                self._tls_srv.socket = ctx.wrap_socket(self._tls_srv.socket, server_side=True)
                self.tls_port = self._tls_srv.server_address[1]
                threading.Thread(target=self._tls_srv.serve_forever, daemon=True).start()
            except Exception as exc:
                self.log_fn(f'[!] Servidor TLS no disponible: {exc}')

    def _serve_iocp(self):
        self._iocp_srv.settimeout(0.5)
        while not self._stop_ev.is_set():
            try:
                conn, _ = self._iocp_srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                _ = conn.recv(1024)
                time.sleep(0.12)  # fuerza WSA_IO_PENDING en el WSARecv del cliente
                conn.sendall(b'IOCP-REPLY:ASYNC-OK\n')
            except OSError:
                pass
            finally:
                conn.close()

    def _serve_udp(self):
        self._udp_srv.settimeout(0.5)
        while not self._stop_ev.is_set():
            try:
                data, addr = self._udp_srv.recvfrom(4096)
                self._udp_srv.sendto(b'UDP-ACK:' + data[:32], addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def trigger_dns(self):
        try:
            socket.getaddrinfo('localhost', self.http_port)
            self.log_fn('[DNS] getaddrinfo("localhost") ejecutado')
        except OSError as exc:
            self.log_fn(f'[DNS] error: {exc}')

    def trigger_http(self):
        c = http.client.HTTPConnection('127.0.0.1', self.http_port, timeout=3)
        c.request('GET', '/api/v1/status', headers={'Host': 'demo.netscope.local'})
        r1 = c.getresponse()
        b1 = r1.read()
        c.request(
            'POST', '/api/v1/telemetry',
            body=json.dumps({'player': 'demo', 'score': 42}).encode('utf-8'),
            headers={'Host': 'demo.netscope.local', 'Content-Type': 'application/json'},
        )
        r2 = c.getresponse()
        _ = r2.read()
        c.close()
        self.log_fn(f'[HTTP] GET/POST 200 OK ({len(b1)} B)')

    def trigger_iocp(self):
        reply = run_winsock_iocp_roundtrip(self.iocp_port, b'IOCP-HELLO-NETSCOPE\n')
        self.log_fn(f'[IOCP] WSASend/WSARecv Overlapped -> {reply!r}')

    def trigger_udp(self):
        payload = zlib.compress(json.dumps({'kind': 'udp_demo', 'ts': time.time()}).encode('utf-8'))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(payload, ('127.0.0.1', self.udp_port))
            ack, _ = s.recvfrom(1024)
        self.log_fn(f'[UDP] zlib enviado ({len(payload)} B), ack ({len(ack)} B)')

    def trigger_tls(self):
        if not self.tls_port:
            self.log_fn('[TLS] servidor TLS omitido (sin OpenSSL CLI)')
            return
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection('127.0.0.1', self.tls_port, context=ctx, timeout=4)
        conn.request('GET', '/tls-demo', headers={'Host': 'tls.netscope.local'})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.log_fn(f'[TLS] OpenSSL HTTPS -> {body.decode("utf-8", "replace")}')

    def trigger_threat_probe(self):
        c = http.client.HTTPConnection('127.0.0.1', self.http_port, timeout=3)
        c.request(
            'GET', '/ioc-probe',
            headers={
                'Host': 'c2-sim.netscope.local',
                'Authorization': 'Basic bmV0c2NvcGU6ZGVtbw==',
            },
        )
        r = c.getresponse()
        body = r.read()
        c.close()
        self.log_fn(f'[IOC/YARA] sonda benigna enviada ({len(body)} B)')

    def trigger_child(self):
        proc = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), '--child-worker', str(self.http_port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        out, _ = proc.communicate(timeout=10)
        self.log_fn(f'[CHILD] PID={proc.pid} rc={proc.returncode} {out.strip()}')

    def run_all(self, spawn_child: bool = False):
        self.trigger_dns()
        self.trigger_http()
        self.trigger_iocp()
        self.trigger_udp()
        self.trigger_tls()
        self.trigger_threat_probe()
        if spawn_child:
            self.trigger_child()

    def close(self):
        self._stop_ev.set()
        for srv in (self.http_srv, self._tls_srv):
            if srv is not None:
                try:
                    srv.shutdown()
                    srv.server_close()
                except Exception:
                    pass
        for sock in (self._iocp_srv, self._udp_srv):
            try:
                sock.close()
            except Exception:
                pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)


def _run_child_worker(port: int):
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
    c.request('GET', '/api/v1/status', headers={'Host': 'child.netscope.local'})
    resp = c.getresponse()
    body = resp.read()
    c.close()
    print(f'CHILD-HTTP-OK:{len(body)}', flush=True)


def _launch_gui(spawn_child: bool = False):
    from PySide6 import QtCore, QtWidgets

    app = QtWidgets.QApplication(sys.argv)
    win = QtWidgets.QWidget()
    win.setWindowTitle('NetScope Demo Target Lab')
    win.resize(580, 420)
    lay = QtWidgets.QVBoxLayout(win)

    log = QtWidgets.QPlainTextEdit()
    log.setReadOnly(True)
    lab = DemoTrafficLab(log_fn=log.appendPlainText)

    info = QtWidgets.QLabel(
        f'<b>App de Demo propia de NetScope (PID {os.getpid()})</b><br>'
        f'HTTP: 127.0.0.1:{lab.http_port} · IOCP: {lab.iocp_port} · '
        f'UDP: {lab.udp_port} · TLS: {lab.tls_port or "N/A"}'
    )
    info.setWordWrap(True)
    lay.addWidget(info)

    grid = QtWidgets.QGridLayout()
    buttons = [
        ('Ejecutar Todo', lambda: threading.Thread(target=lambda: lab.run_all(spawn_child=spawn_child), daemon=True).start()),
        ('HTTP / TCP', lambda: threading.Thread(target=lab.trigger_http, daemon=True).start()),
        ('Winsock IOCP', lambda: threading.Thread(target=lab.trigger_iocp, daemon=True).start()),
        ('TLS OpenSSL', lambda: threading.Thread(target=lab.trigger_tls, daemon=True).start()),
        ('UDP Zlib', lambda: threading.Thread(target=lab.trigger_udp, daemon=True).start()),
        ('IOCs / YARA Demo', lambda: threading.Thread(target=lab.trigger_threat_probe, daemon=True).start()),
        ('Proceso Hijo', lambda: threading.Thread(target=lab.trigger_child, daemon=True).start()),
    ]
    for idx, (label, cb) in enumerate(buttons):
        btn = QtWidgets.QPushButton(label)
        btn.clicked.connect(cb)
        grid.addWidget(btn, idx // 3, idx % 3)
    lay.addLayout(grid)

    auto_chk = QtWidgets.QCheckBox('Generar ciclo automático cada 3 s')
    lay.addWidget(auto_chk)
    lay.addWidget(log, 1)

    timer = QtCore.QTimer(win)
    timer.setInterval(3000)
    timer.timeout.connect(lambda: threading.Thread(target=lambda: lab.run_all(spawn_child=False), daemon=True).start())
    auto_chk.toggled.connect(lambda on: timer.start() if on else timer.stop())

    def on_close(_ev):
        timer.stop()
        lab.close()

    win.closeEvent = on_close
    win.show()
    sys.exit(app.exec())


def main():
    parser = argparse.ArgumentParser(description='NetScope Demo Target Lab')
    parser.add_argument('--once', action='store_true', help='Ejecuta un ciclo de tráfico y termina')
    parser.add_argument('--headless', action='store_true', help='Ejecuta sin ventana GUI')
    parser.add_argument('--duration', type=float, default=0.0, help='Segundos a correr en --headless')
    parser.add_argument('--delay', type=float, default=0.0, help='Espera inicial antes de generar tráfico')
    parser.add_argument('--spawn-child', action='store_true', help='Lanza también un proceso hijo')
    parser.add_argument('--child-worker', type=int, default=0, help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.child_worker:
        _run_child_worker(args.child_worker)
        return 0

    if args.once or args.headless:
        lab = DemoTrafficLab(log_fn=lambda m: print(m, flush=True))
        try:
            if args.delay > 0:
                time.sleep(args.delay)
            if args.once:
                lab.run_all(spawn_child=args.spawn_child)
                return 0
            end = time.time() + args.duration if args.duration > 0 else None
            while end is None or time.time() < end:
                lab.run_all(spawn_child=args.spawn_child)
                time.sleep(1.5)
        except KeyboardInterrupt:
            pass
        finally:
            lab.close()
        return 0

    _launch_gui(spawn_child=args.spawn_child)
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
