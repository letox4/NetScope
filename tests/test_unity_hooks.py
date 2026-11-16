# -*- coding: utf-8 -*-
"""Tests para análisis de juegos Unity."""
import sys
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core.unity_hooks import (
    UnityNetworkAnalyzer, UnityMessagePatterns, UnityGameNetworkSniffer,
    UnityNetworkMessage
)
from core.interceptor import SocketStream
import json


def test_json_detection():
    """Test de detección de JSON (formato común en Unity)."""
    analyzer = UnityNetworkAnalyzer()

    # JSON message
    data = json.dumps({
        'player_id': 123,
        'position': {'x': 10.5, 'y': 20.5},
        'action': 'move'
    }).encode()

    encoding = analyzer._detect_encoding(data)
    assert encoding == 'json', f"Debería detectar JSON, got {encoding}"
    print(f"  JSON detectado: {data[:50]}")

    parsed = analyzer._parse_message(data, encoding)
    assert parsed is not None, "Parsing JSON fallo"
    assert parsed['player_id'] == 123
    print(f"  Parsed JSON: player_id={parsed['player_id']}")


def test_protobuf_detection():
    """Test de detección de Protobuf."""
    analyzer = UnityNetworkAnalyzer()

    # Protobuf simple: field 1, type 0 (varint), value 150
    data = b'\x08\x96\x01'  # tag=1, wire_type=0, varint=150

    encoding = analyzer._detect_encoding(data)
    assert encoding == 'protobuf', f"Debería detectar protobuf, got {encoding}"
    print(f"  Protobuf detectado")

    parsed = analyzer._parse_message(data, encoding)
    assert parsed is not None, "Parsing protobuf fallo"
    assert len(parsed['fields']) > 0, "No se parsearon campos"
    print(f"  Parsed Protobuf: {parsed['fields']}")


def test_mirror_detection():
    """Test de detección de Mirror Network."""
    data = UnityMessagePatterns.MIRROR_SPAWN + b'\x00\x01\x02'

    framework = UnityMessagePatterns.detect_framework(data)
    assert framework == 'Mirror', f"Debería detectar Mirror, got {framework}"
    print(f"  Mirror framework detectado")


def test_netcode_detection():
    """Test de detección de Netcode for GameObjects."""
    data = UnityMessagePatterns.NETCODE_SPAWN + b'\x00\x01\x02'

    framework = UnityMessagePatterns.detect_framework(data)
    assert framework == 'Netcode', f"Debería detectar Netcode, got {framework}"
    print(f"  Netcode framework detectado")


def test_compressed_detection():
    """Test de detección de datos comprimidos."""
    import zlib

    original = b"Player data: " * 100
    compressed = zlib.compress(original)

    framework = UnityMessagePatterns.detect_framework(compressed)
    assert framework == 'Compressed (zlib/gzip)', f"Debería detectar compresion, got {framework}"
    print(f"  Compresion detectada: {len(original)} -> {len(compressed)} bytes")


def test_unity_stream_analysis():
    """Test de análisis de stream completo."""
    sniffer = UnityGameNetworkSniffer()

    # Crear stream simulado
    stream = SocketStream(fd=1, proto='TCP', peer='127.0.0.1:12345')

    # Agregar datos JSON (típico de juegos Unity)
    msg_out = json.dumps({
        'type': 'player_spawn',
        'id': 1,
        'pos': [0, 0, 0]
    }).encode()

    msg_in = json.dumps({
        'type': 'ack',
        'status': 'ok'
    }).encode()

    stream.append_out(msg_out)
    stream.append_in(msg_in)

    # Procesar
    result = sniffer.process_stream(stream)

    assert result['framework'] == 'JSON (custom)', f"Framework incorrecto: {result['framework']}"
    assert result['statistics']['tx_bytes'] == len(msg_out)
    assert result['statistics']['rx_bytes'] == len(msg_in)
    print(f"  Stream analizado: {result['framework']}")
    print(f"  TX: {result['statistics']['tx_bytes']} bytes")
    print(f"  RX: {result['statistics']['rx_bytes']} bytes")


def test_varint_parsing():
    """Test de parsing de varint (Protobuf)."""
    analyzer = UnityNetworkAnalyzer()

    # Varint 150 (dos bytes: 0x96 0x01)
    data = b'\x96\x01' + b'extra'
    value, pos = analyzer._read_varint(data, 0)

    assert value == 150, f"Varint incorrecto: {value}"
    assert pos == 2, f"Posición incorrecta: {pos}"
    print(f"  Varint parsing: 150 (correcto)")


def test_text_encoding_detection():
    """Test de detección de texto."""
    analyzer = UnityNetworkAnalyzer()

    data = b'Hello World! This is a game message'
    encoding = analyzer._detect_encoding(data)

    assert encoding == 'text', f"Debería detectar text, got {encoding}"
    print(f"  Text encoding detectado")


def test_binary_protocol_detection():
    """Test de detección de protocolo binario."""
    analyzer = UnityNetworkAnalyzer()

    # Datos binarios random (sin patrón conocido)
    data = b'\xFF\x00\x12\x34\x56\x78\x9A\xBC'
    encoding = analyzer._detect_encoding(data)

    assert encoding == 'binary', f"Debería detectar binary, got {encoding}"
    print(f"  Binary protocol detectado")


def run_all_tests():
    """Ejecuta todos los tests."""
    tests = [
        ("JSON detection", test_json_detection),
        ("Protobuf detection", test_protobuf_detection),
        ("Mirror framework", test_mirror_detection),
        ("Netcode framework", test_netcode_detection),
        ("Compressed data", test_compressed_detection),
        ("Unity stream analysis", test_unity_stream_analysis),
        ("Varint parsing", test_varint_parsing),
        ("Text encoding", test_text_encoding_detection),
        ("Binary protocol", test_binary_protocol_detection),
    ]

    print("=" * 70)
    print("NetScope - Unity Game Network Analysis Tests")
    print("=" * 70)

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            print(f"\n[TEST] {test_name}...", end=" ", flush=True)
            test_func()
            print("PASSED [OK]")
            passed += 1
        except AssertionError as e:
            print(f"FAILED [FAIL]\n  Error: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR [ERR]\n  Exception: {e}")
            failed += 1

    print("\n" + "=" * 70)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70)

    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
