# -*- coding: utf-8 -*-
"""Suite de tests para todas las nuevas capacidades de NetScope."""
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core.dns_resolver import DnsResolver, extract_http_host, extract_tls_sni, parse_dns_response
from core.har_exporter import build_har, export_har_file
from core.interceptor import FridaInterceptor, SocketStream
from core.pcapng import build_pcapng
from core.sdk import NetScopeSession
from core.threat_intel import IOCExtractor, YaraScanner
import cli


def test_dns_resolver_http_sni_and_udp53():
    resolver = DnsResolver(enable_rdns=False)
    http_req = b'GET /index.html HTTP/1.1\r\nHost: api.example.org:8443\r\n\r\n'
    assert extract_http_host(http_req) == 'api.example.org'

    # Construir TLS ClientHello mínimo con extensión SNI = "secure.demo.local"
    sni_host = b'secure.demo.local'
    sni_entry = b'\x00' + struct.pack('!H', len(sni_host)) + sni_host
    sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
    ext_sni = struct.pack('!HH', 0x0000, len(sni_list)) + sni_list
    ext_block = struct.pack('!H', len(ext_sni)) + ext_sni
    ch_body = (
        b'\x03\x03' + (b'\x11' * 32)
        + b'\x00'  # session_id len
        + struct.pack('!HH', 2, 0x1301)  # cipher suites
        + b'\x01\x00'  # compression methods
        + ext_block
    )
    hs = b'\x01' + len(ch_body).to_bytes(3, 'big') + ch_body
    rec = b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs
    assert extract_tls_sni(rec) == 'secure.demo.local'

    # Construir respuesta DNS UDP/53 para example.net -> 93.184.216.34
    qname = b'\x07example\x03net\x00'
    dns_pkt = (
        struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)
        + qname + struct.pack('!HH', 1, 1)
        + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + bytes((93, 184, 216, 34))
    )
    parsed = parse_dns_response(dns_pkt)
    assert parsed == {'example.net': ['93.184.216.34']}

    resolver.inspect_payload('93.184.216.34', dns_pkt, peer_port=53)
    assert resolver.get_host('93.184.216.34') == 'example.net'
    assert resolver.format_peer('93.184.216.34', 443) == 'example.net (93.184.216.34:443)'


def test_pcapng_dsb_and_nrb_and_har_export():
    st = SocketStream(
        fd=42, proto='TCP', peer='api.demo.local (93.184.216.34:8080)',
        peer_ip='93.184.216.34', peer_port=8080, peer_host='api.demo.local',
        call_stacks=[['app.exe!send_req', 'ws2_32.dll!send']],
    )
    st.opened_ts = time.time() - 2
    st.append_out(b'POST /v1/login HTTP/1.1\r\nHost: api.demo.local\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{"user":"ok"}')
    st.append_in(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{"ok":123}')

    blob = build_pcapng(
        [st],
        tls_keylog=['CLIENT_RANDOM 00112233 44556677'],
        dns_map={'93.184.216.34': 'api.demo.local'},
    )
    off = 0
    kinds = []
    while off + 12 <= len(blob):
        kind, total = struct.unpack_from('<II', blob, off)
        kinds.append(kind)
        off += total
    assert 0x0A0D0D0A in kinds  # SHB
    assert 0x00000001 in kinds  # IDB
    assert 0x00000004 in kinds  # NRB
    assert 0x0000000A in kinds  # DSB
    assert 0x00000006 in kinds  # EPB
    assert b'CLIENT_RANDOM 00112233 44556677' in blob
    assert b'api.demo.local' in blob

    with tempfile.TemporaryDirectory() as tmp:
        har_path = os.path.join(tmp, 'cap.har')
        export_har_file([st], har_path)
        har = json.load(open(har_path, encoding='utf-8'))
        assert har['log']['version'] == '1.2'
        assert len(har['log']['entries']) == 1
        ent = har['log']['entries'][0]
        assert ent['request']['method'] == 'POST'
        assert ent['request']['url'] == 'http://api.demo.local/v1/login'
        assert ent['response']['status'] == 200
        assert ent['response']['content']['text'] == '{"ok":123}'
        assert ent['_netscope']['call_stacks'][0][0] == 'app.exe!send_req'


def test_ioc_extractor_and_yara_scanner():
    st = SocketStream(
        fd=11, proto='TCP', peer='c2-sim.netscope.local (198.51.100.25:80)',
        peer_ip='198.51.100.25', peer_port=80, peer_host='c2-sim.netscope.local',
    )
    st.append_out(
        b'GET /beacon HTTP/1.1\r\n'
        b'Host: c2-sim.netscope.local\r\n'
        b'Authorization: Basic dXNlcjpwYXNz\r\n\r\n'
        b'callback=http://198.51.100.25/gate.php email=ops@example.com'
    )
    st.append_in(
        b'MZ' + b'\x90' * 10 + b'This program cannot be run in DOS mode'
        b' X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    )

    rep = IOCExtractor().extract_from_streams([st], dns_map={'198.51.100.25': 'c2-sim.netscope.local'})
    assert '198.51.100.25' in rep.unique_values('ipv4')
    assert 'c2-sim.netscope.local' in rep.unique_values('domain')
    assert 'http://198.51.100.25/gate.php' in rep.unique_values('url')
    assert 'ops@example.com' in rep.unique_values('email')
    assert any('Authorization: Basic' in v for v in rep.unique_values('header'))

    custom_rule = '''
    rule Custom_Hex_Pattern : test {
        meta:
            severity = "low"
        strings:
            $h = { 4D 5A [1-16] 54 68 69 73 }
            $txt = "gate.php" nocase
        condition:
            $h or $txt
    }
    '''
    scanner = YaraScanner(rules_text=custom_rule, include_builtin=True)
    matches = scanner.scan_streams([st])
    rule_names = {m.rule for m in matches}
    assert 'Suspicious_C2_Beacon' in rule_names
    assert 'Cleartext_Auth_Credentials' in rule_names
    assert 'Suspicious_PE_Transfer' in rule_names
    assert 'EICAR_Test_Signature' in rule_names
    assert 'Custom_Hex_Pattern' in rule_names


def test_live_iocp_openssl_keylog_stacks_dns_and_children_with_demo_app():
    demo_path = os.path.join(BASE, 'demo_app.py')
    proc = subprocess.Popen(
        [sys.executable, demo_path, '--headless', '--delay', '1.8', '--duration', '7', '--spawn-child'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    events = []
    try:
        time.sleep(0.5)
        with NetScopeSession(pid=proc.pid, follow_children=True, capture_stacks=True) as ns:
            @ns.on_event
            def _on_ev(ev):
                events.append(ev)

            ns.capture(duration=4.5)
            streams = ns.streams()
            assert streams, 'No se capturaron streams de demo_app.py'

            # 1. Winsock Overlapped + IOCP
            all_in = b''.join(bytes(s.in_data) for s in streams)
            all_out = b''.join(bytes(s.out_data) for s in streams)
            assert b'IOCP-HELLO-NETSCOPE' in all_out, 'Falta payload WSASend IOCP'
            assert b'IOCP-REPLY:ASYNC-OK' in all_in, 'Falta payload WSARecv IOCP asíncrono'
            assert any('iocp:GQCS' in (ev.tag or '') for ev in events), 'No se registró completado IOCP GQCS'

            # 2. OpenSSL plaintext + TLS Keylog
            tls_streams = [s for s in streams if s.proto == 'TLS']
            assert tls_streams, 'No se capturó flujo TLS OpenSSL en claro'
            tls_blob = b''.join(bytes(s.out_data) + bytes(s.in_data) for s in tls_streams)
            assert b'/tls-demo' in tls_blob and b'"engine":"openssl"' in tls_blob
            assert len(ns.tls_keys()) >= 1, 'No se capturaron claves TLS (SSLKEYLOGFILE)'

            # 3. Call stack attribution
            assert any(s.call_stacks for s in streams), 'No se capturaron call stacks'

            # 4. DNS -> dominio
            assert ns.dns_table(), 'Tabla DNS vacía'
            assert any(s.peer_host for s in streams), 'Ningún stream asoció peer_host'

            # 5. Seguimiento de procesos hijo
            assert ns.child_pids(), 'No se detectaron procesos hijo'
            assert any(s.pid and s.pid != proc.pid for s in streams), 'No se capturó tráfico desde el proceso hijo'

            # 6. Exportaciones SDK
            with tempfile.TemporaryDirectory() as tmp:
                p_pcap = ns.export_pcapng(os.path.join(tmp, 'demo.pcapng'))
                p_har = ns.export_har(os.path.join(tmp, 'demo.har'))
                p_key = ns.export_keylog(os.path.join(tmp, 'demo.keylog'))
                p_json = ns.export_json(os.path.join(tmp, 'demo.json'))
                assert os.path.getsize(p_pcap) > 100
                assert os.path.getsize(p_har) > 100
                assert os.path.getsize(p_key) > 20
                assert os.path.getsize(p_json) > 100
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)


def test_cli_ps_and_scan_commands():
    with tempfile.TemporaryDirectory() as tmp:
        sample_bin = os.path.join(tmp, 'payload.bin')
        out_json = os.path.join(tmp, 'scan.json')
        with open(sample_bin, 'wb') as f:
            f.write(b'POST /checkin HTTP/1.1\r\nAuthorization: Basic dGVzdA==\r\n\r\nhttp://evil.example.org/p')
        assert cli.main(['ps', '--filter', 'python']) == 0
        assert cli.main(['scan', sample_bin, '--json', out_json]) == 0
        res = json.load(open(out_json, encoding='utf-8'))
        assert len(res) == 1
        assert any(m['rule'] == 'Suspicious_C2_Beacon' for m in res[0]['yara_matches'])
        assert any(i['value'] == 'http://evil.example.org/p' for i in res[0]['iocs'])
