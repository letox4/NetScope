#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NetScope — Ejemplos de uso de la API pública y análisis offline."""
import argparse
import json
import sys
import zlib
from pathlib import Path

BASE = Path(__file__).resolve().parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from core.binary_decoder import BinaryDecoder, StreamBinaryAnalyzer
from core.game_analysis import analyze_game_streams, format_game_analysis_report
from core.interceptor import SocketStream
from core.protocol_registry import BinaryForensics, ProtocolRegistry, register_custom_protocol
from core.sdk import NetScopeSession
from core.threat_intel import IOCExtractor, YaraScanner
from core.unity_hooks import UnityMessagePatterns, UnityNetworkAnalyzer


def print_header(title: str) -> None:
    print(f'\n{"=" * 70}')
    print(f'  {title}')
    print(f'{"=" * 70}\n')


def example_binary_and_compression() -> None:
    print_header('1. Análisis binario, compresión y entropía (API pública)')
    decoder = BinaryDecoder()
    raw = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>'
    analysis = decoder.analyze(raw)
    print(f'Formato={analysis.likely_format}, entropía={analysis.entropy:.2f}, compresión={analysis.compression_type}')

    original = b'Player spawned at position (10, 20, 30). ' * 40
    compressed = zlib.compress(original)
    comp_analysis = decoder.analyze(compressed)
    decompressed = decoder.try_decompress(compressed)
    print(
        f'Comprimido ({len(compressed)} B): tipo={comp_analysis.compression_type}, '
        f'descompresión OK={decompressed == original}'
    )


def example_xor_and_unity() -> None:
    print_header('2. Descifrado XOR, frameworks Unity/Photon y UnityNetworkAnalyzer')
    decoder = BinaryDecoder()
    original = b'secret_token_98765'
    encrypted = bytes(b ^ 0x42 for b in original)
    hits = [a for a in decoder.try_decrypt_xor(encrypted, key_size=1) if b'secret_token' in a]
    print(f'Candidatos XOR válidos: {hits}')

    samples = {
        'Photon TCP ping': b'\xf0\x00\x04\xc5\x89',
        'Photon TCP frame': b'\xfb\x00\x00\x00\x79\x00\x01\xf3\x84',
        'PlayFab JSON': b'{"TitleId":"1234"}',
        'Mirror': UnityMessagePatterns.MIRROR_SPAWN + b'player',
    }
    for label, payload in samples.items():
        print(f'  {label}: framework={UnityMessagePatterns.detect_framework(payload)}')

    analyzer = UnityNetworkAnalyzer()
    msg = analyzer.analyze_message(b'\x08\x96\x01\x12\x05Hello', 'send', '127.0.0.1:7777')
    print(f'UnityNetworkAnalyzer protobuf: encoding={msg.encoding_type}, parsed={msg.parsed}')


def example_forensics_and_custom_protocol() -> None:
    print_header('3. Análisis forense, IOCs, YARA y protocolo personalizado')
    stream = SocketStream(fd=42, proto='TCP', peer='198.51.100.10:8080', peer_host='api.ejemplo.local')
    stream.append_out(b'POST /login HTTP/1.1\r\nHost: api.ejemplo.local\r\n\r\nuser=admin&password=123')
    stream.append_in(zlib.compress(json.dumps({'status': 'ok', 'token': 'demo'}).encode()))

    report = IOCExtractor().extract_from_streams([stream])
    print(f'IOCs detectados: {len(report.items)}')
    matches = YaraScanner(include_builtin=True).scan_streams([stream])
    print(f'Coincidencias YARA: {[m.rule for m in matches]}')

    forensics = BinaryForensics()
    carved = forensics.carve_known_formats(b'\x89PNG\r\n\x1a\nhello\x00PK\x03\x04zip')
    print(f'Formatos encontrados (carving): {carved}')

    def parse_myproto(data: bytes):
        if len(data) < 7:
            return None
        return {
            'type': data[0],
            'length': int.from_bytes(data[1:3], 'little'),
            'id': int.from_bytes(data[3:7], 'little'),
            'payload': data[7:].decode('utf-8', 'ignore'),
        }

    register_custom_protocol('MyProto', [b'MYPR'], parse_myproto, 'Protocolo demo', priority=10)
    registry = ProtocolRegistry()
    pkt = b'MYPR\x42\x0c\x00\x01\x00\x00\x00Hola'
    print(f'ProtocolRegistry detectó={registry.detect_protocol(pkt)} -> {registry.parse_protocol("MyProto", pkt)}')


def example_game_stream_and_sdk() -> None:
    print_header('4. Resumen de juego y uso de NetScopeSession (SDK)')
    stream = SocketStream(fd=5020, proto='TCP', peer='188.241.71.66:4531')
    stream.append_out(b'\xf0\x00\x04\xd0\xdc')
    stream.append_in(b'\xf0\xdb\xa0\xae\x25\x00\x04\xd0\xdc\xfb\x00\x00\x00\x10payload')
    results = analyze_game_streams([stream])
    print(format_game_analysis_report(results))

    analyzer = StreamBinaryAnalyzer()
    print('\nHexdump resumido:', analyzer.format_analysis_report(stream).splitlines()[0])

    procs = NetScopeSession.list_processes()
    print(f'Procesos activos visibles desde NetScopeSession: {len(procs)}')


def main() -> int:
    parser = argparse.ArgumentParser(description='NetScope — Ejemplos de análisis y SDK')
    parser.add_argument('--interactive', action='store_true', help='Pausar tras cada ejemplo')
    args = parser.parse_args()

    examples = [
        example_binary_and_compression,
        example_xor_and_unity,
        example_forensics_and_custom_protocol,
        example_game_stream_and_sdk,
    ]
    for fn in examples:
        fn()
        if args.interactive:
            input('\nPresiona Enter para continuar...')
    return 0


if __name__ == '__main__':
    sys.exit(main())
