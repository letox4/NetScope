# -*- coding: utf-8 -*-
"""Tests para el módulo de decodificación binaria."""
import sys
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core.binary_decoder import BinaryDecoder, StreamBinaryAnalyzer
from core.protocol_registry import ProtocolRegistry, BinaryForensics, AdvancedBinaryPattern
import zlib
import gzip


def test_entropy():
    """Test de cálculo de entropía."""
    decoder = BinaryDecoder()
    
    # Datos con baja entropía (muy repetitivos)
    low_entropy = b'AAAAAAAAAA'
    ent_low = decoder._calculate_entropy(low_entropy)
    assert ent_low < 1.0, f"Baja entropía debería ser < 1.0, got {ent_low}"
    print(f"✓ Baja entropía: {ent_low:.2f}")
    
    # Datos con alta entropía (random)
    high_entropy = bytes(range(256)) * 4
    ent_high = decoder._calculate_entropy(high_entropy)
    assert ent_high > 7.0, f"Alta entropía debería ser > 7.0, got {ent_high}"
    print(f"✓ Alta entropía: {ent_high:.2f}")


def test_compression_detection():
    """Test de detección de compresión."""
    decoder = BinaryDecoder()
    
    # Datos sin comprimir
    original = b"Hello World! " * 100
    
    # Comprimir con zlib
    compressed_zlib = zlib.compress(original)
    detected = decoder._detect_compression(compressed_zlib)
    assert detected == 'zlib', f"Debería detectar zlib, got {detected}"
    print(f"✓ Zlib detectado correctamente")
    
    # Comprimir con gzip
    compressed_gzip = gzip.compress(original)
    detected = decoder._detect_compression(compressed_gzip)
    assert detected == 'gzip', f"Debería detectar gzip, got {detected}"
    print(f"✓ Gzip detectado correctamente")


def test_decompression():
    """Test de descompresión."""
    decoder = BinaryDecoder()
    
    original = b"Test data for compression" * 50
    
    # Zlib
    compressed = zlib.compress(original)
    decompressed = decoder.try_decompress(compressed)
    assert decompressed == original, "Decompresión zlib fallida"
    print(f"✓ Zlib descompresión: {len(compressed)} → {len(decompressed)} bytes")
    
    # Gzip
    compressed = gzip.compress(original)
    decompressed = decoder.try_decompress(compressed)
    assert decompressed == original, "Decompresión gzip fallida"
    print(f"✓ Gzip descompresión: {len(compressed)} → {len(decompressed)} bytes")


def test_xor_decryption():
    """Test de descifrado XOR."""
    decoder = BinaryDecoder()
    
    original = b"Hello World! This is a secret message."
    key = 0x42
    encrypted = bytes(b ^ key for b in original)
    
    attempts = decoder.try_decrypt_xor(encrypted, key_size=1)
    assert len(attempts) > 0, "No se encontraron descifrados XOR"
    assert original in attempts, "Original no está en los intentos"
    print(f"✓ Descifrado XOR: {len(attempts)} intentos válidos")


def test_pattern_detection():
    """Test de detección de patrones."""
    decoder = BinaryDecoder()
    
    # Patrón repetitivo
    data = b"ABCD" * 50
    pattern, freq = decoder._find_repeating_pattern(data) or (None, 0)
    assert pattern == b"ABCD", f"Patrón incorrecto: {pattern}"
    assert freq == 50, f"Frecuencia incorrecta: {freq}"
    print(f"✓ Patrón repetitivo detectado: {pattern} ({freq}x)")


def test_binary_analysis():
    """Test de análisis binario completo."""
    decoder = BinaryDecoder()
    
    data = b"HTTP/1.1 200 OK\r\n" + b"Content-Type: text/html\r\n" * 10
    analysis = decoder.analyze(data)
    
    print(f"✓ Análisis binario:")
    print(f"  - Entropía: {analysis.entropy:.2f}")
    print(f"  - Formato: {analysis.likely_format}")
    print(f"  - Ratio ASCII: {analysis.ascii_ratio*100:.1f}%")
    print(f"  - Null bytes: {analysis.null_bytes}")


def test_forensics_strings():
    """Test de extracción de strings."""
    forensics = BinaryForensics()
    
    data = b"\x00\x00Hello\x00World\x00\xFF\xFE"
    strings = forensics.find_possible_strings(data)
    
    assert "Hello" in strings, "String 'Hello' no encontrado"
    assert "World" in strings, "String 'World' no encontrado"
    print(f"✓ Strings extraídos: {strings}")
    
    null_term = forensics.find_null_terminated_strings(data)
    assert b"Hello" in null_term, "Null-terminated 'Hello' no encontrado"
    print(f"✓ Null-terminated strings: {null_term}")


def test_format_carving():
    """Test de carving de formatos conocidos."""
    forensics = BinaryForensics()
    
    # Crear datos con header PNG
    data = b"\x89PNG\r\n\x1a\n" + b"fake png data"
    formats = forensics.carve_known_formats(data)
    
    assert "PNG" in formats, "PNG no detectado"
    assert 0 in formats["PNG"], "Offset PNG incorrecto"
    print(f"✓ Formatos encontrados: {list(formats.keys())}")


def test_statistics():
    """Test de estadísticas binarias."""
    forensics = BinaryForensics()
    
    data = b"\x00" * 10 + b"\xFF" * 5 + b"ABC" * 3
    stats = forensics.calculate_statistics(data)
    
    assert stats['length'] == 24, "Longitud incorrecta"
    assert stats['unique_bytes'] == 5, f"Bytes únicos incorrecto: {stats['unique_bytes']}"
    print(f"✓ Estadísticas: {stats['unique_bytes']} bytes únicos, longitud {stats['length']}")


def test_protocol_detection():
    """Test de detección de protocolos."""
    from core.protocol_registry import register_custom_protocol
    
    def simple_parser(data):
        return {'magic': data[:4].hex(), 'rest': data[4:].hex()}
    
    register_custom_protocol(
        name='TestProto',
        signatures=[b'TEST'],
        parser=simple_parser,
        priority=10
    )
    
    registry = ProtocolRegistry()
    protocol = registry.detect_protocol(b'TEST\x00\x01\x02')
    assert protocol == 'TestProto', f"Protocolo detectado incorrecto: {protocol}"
    print(f"✓ Protocolo detectado: {protocol}")
    
    result = registry.parse_protocol('TestProto', b'TEST\x00\x01\x02')
    assert result is not None, "Parsing falló"
    print(f"✓ Parsed result: {result}")


def test_hex_dump():
    """Test de hexdump anotado."""
    decoder = BinaryDecoder()
    
    data = b"Hello World!\x00Test"
    annotations = {0: "inicio", 13: "null terminator"}
    
    dump = decoder.hex_dump_annotated(data, width=8, annotations=annotations)
    assert "|Hello Wo|" in dump, "Hexdump no contiene los datos"
    assert "inicio" in dump, "Anotación no aparece"
    assert "null terminator" in dump, "Anotación fuera de línea no aparece"
    print(f"✓ Hexdump anotado generado correctamente")


def test_stream_analyzer():
    """Test del analizador de streams."""
    from core.interceptor import SocketStream
    
    stream = SocketStream(fd=1, proto='TCP', peer='127.0.0.1:8080')
    
    # Agregar datos comprimidos
    original = b"Stream data test " * 100
    compressed = zlib.compress(original)
    stream.append_out(compressed)
    stream.append_in(b"Response data\r\nMore info")
    
    analyzer = StreamBinaryAnalyzer()
    analysis = analyzer.analyze_stream(stream)
    
    assert analysis['fd'] == 1, "FD incorrecto"
    assert analysis['out']['analysis'].compression_type == 'zlib', "Compresión no detectada"
    print(f"✓ Stream analyzer: {len(analysis['out']['decompressed'])} bytes descomprimidos")


def run_all_tests():
    """Ejecuta todos los tests."""
    tests = [
        ("Entropia", test_entropy),
        ("Deteccion de compresion", test_compression_detection),
        ("Descompresion", test_decompression),
        ("Descifrado XOR", test_xor_decryption),
        ("Deteccion de patrones", test_pattern_detection),
        ("Analisis binario", test_binary_analysis),
        ("Extraccion de strings", test_forensics_strings),
        ("Carving de formatos", test_format_carving),
        ("Estadisticas", test_statistics),
        ("Deteccion de protocolos", test_protocol_detection),
        ("Hexdump", test_hex_dump),
        ("Stream analyzer", test_stream_analyzer),
    ]
    
    print("=" * 70)
    print("NetScope Binary Decoder - Test Suite")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            print(f"\n[TEST] {test_name}...", end=" ")
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
