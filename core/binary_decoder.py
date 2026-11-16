# -*- coding: utf-8 -*-
"""NetScope - Decodificación de datos binarios propietarios.

Módulo flexible para descodificar, analizar y parsear datos binarios
arbitrarios sin documentación. Soporta:
  - Detección automática de patrones (headers fijos, longitudes, null-terminators)
  - Descompresión (zlib, gzip, deflate)
  - Descifrado simple (XOR, ROT13 en binario)
  - Parsers personalizados registrables por protocolo
  - Análisis de entropía y estructura
  - Visualización hexadecimal con anotaciones
"""
import struct
import zlib
import gzip
import io
from dataclasses import dataclass
from typing import Optional, Dict, Callable, List, Any, Tuple
from collections import Counter
import re


@dataclass
class BinaryAnalysis:
    """Resultado del análisis de datos binarios."""
    raw: bytes
    length: int
    entropy: float
    null_bytes: int
    ascii_ratio: float
    repeating_pattern: Optional[bytes]
    pattern_frequency: int
    likely_format: str  # 'text', 'compressed', 'encrypted', 'structured', 'unknown'
    compression_type: Optional[str]  # 'zlib', 'gzip', 'deflate', None
    potential_header: Optional[bytes]
    potential_lengths: List[int]
    null_terminated: bool
    max_byte_value: int
    min_byte_value: int


class BinaryDecoder:
    """Decodificador agnóstico para datos binarios propietarios."""

    def __init__(self):
        self.parsers: Dict[str, Callable] = {}
        self.protocols: Dict[str, Dict[str, Any]] = {}
        self._register_common_parsers()

    def _register_common_parsers(self):
        """Registra parsers para formatos comunes."""
        # Placeholder para parsers personalizados
        pass

    def register_parser(self, protocol_name: str,
                       parser: Callable[[bytes], Dict[str, Any]]):
        """Registra un parser personalizado para un protocolo.

        Args:
            protocol_name: Nombre único del protocolo
            parser: Función que recibe bytes y retorna dict con datos decodificados
        """
        self.parsers[protocol_name] = parser

    def analyze(self, data: bytes) -> BinaryAnalysis:
        """Analiza datos binarios y detecta patrones.

        Returns:
            BinaryAnalysis con detalles de estructura, formato, etc.
        """
        if not data:
            return BinaryAnalysis(
                raw=b'', length=0, entropy=0, null_bytes=0, ascii_ratio=0,
                repeating_pattern=None, pattern_frequency=0,
                likely_format='empty', compression_type=None,
                potential_header=None, potential_lengths=[],
                null_terminated=False, max_byte_value=0, min_byte_value=0
            )

        entropy = self._calculate_entropy(data)
        null_bytes = data.count(b'\x00')
        ascii_count = sum(1 for b in data if 32 <= b <= 126)
        ascii_ratio = ascii_count / len(data) if data else 0
        null_terminated = data.endswith(b'\x00')
        max_byte = max(data) if data else 0
        min_byte = min(data) if data else 0

        # Detectar patrones repetitivos
        repeating = self._find_repeating_pattern(data)
        pattern, freq = repeating or (None, 0)

        # Detectar headers conocidos
        header = self._detect_header(data)

        # Detectar longitudes potenciales
        lengths = self._detect_potential_lengths(data)

        # Detectar compresión
        compression = self._detect_compression(data)

        # Clasificar formato
        likely_format = self._classify_format(
            data, entropy, ascii_ratio, null_bytes, compression
        )

        return BinaryAnalysis(
            raw=data,
            length=len(data),
            entropy=entropy,
            null_bytes=null_bytes,
            ascii_ratio=ascii_ratio,
            repeating_pattern=pattern,
            pattern_frequency=freq,
            likely_format=likely_format,
            compression_type=compression,
            potential_header=header,
            potential_lengths=lengths,
            null_terminated=null_terminated,
            max_byte_value=max_byte,
            min_byte_value=min_byte,
        )

    def try_decompress(self, data: bytes) -> Optional[bytes]:
        """Intenta descomprimir datos con múltiples métodos.

        Returns:
            Datos descomprimidos o None si falla todo.
        """
        # Intentar zlib
        try:
            return zlib.decompress(data)
        except (zlib.error, Exception):
            pass

        # Intentar gzip
        try:
            return gzip.decompress(data)
        except (OSError, Exception):
            pass

        # Intentar deflate sin header
        try:
            return zlib.decompress(data, -zlib.MAX_WBITS)
        except (zlib.error, Exception):
            pass

        return None

    def try_decrypt_xor(self, data: bytes, key_size: int = 1) -> List[bytes]:
        """Intenta descifrado XOR con claves de diferentes tamaños.

        Args:
            data: Datos a descifrar
            key_size: Tamaño de clave XOR a probar (1-16)

        Returns:
            Lista de posibles datos descifrados
        """
        results = []
        for ks in range(1, min(key_size + 1, 16)):
            if ks > len(data):
                continue
            # Probar todas las claves de 1 byte
            if ks == 1:
                for key in range(256):
                    decrypted = bytes(b ^ key for b in data)
                    if self._looks_like_valid_data(decrypted):
                        results.append(decrypted)
            else:
                # Para claves mayores, heurística de byte común
                for key_byte in range(256):
                    key = bytes([key_byte] * ks)
                    try:
                        decrypted = bytes(
                            data[i] ^ key[i % ks] for i in range(len(data))
                        )
                        if self._looks_like_valid_data(decrypted):
                            results.append(decrypted)
                    except Exception:
                        pass
        # Mejores candidatos primero (más texto imprimible); sort estable
        results.sort(key=self._printable_ratio, reverse=True)
        return results[:10]  # Limitar resultados

    @staticmethod
    def _printable_ratio(data: bytes) -> float:
        if not data:
            return 0.0
        return sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13)) / len(data)

    def try_decrypt_rot(self, data: bytes) -> List[bytes]:
        """Intenta descifrado ROT simple (0-25).

        Returns:
            Lista de posibles datos descifrados (solo ROT que resulte válido).
        """
        results = []
        for rot in range(1, 26):
            try:
                decrypted = bytes(
                    ((b - 97 + rot) % 26 + 97) if 97 <= b <= 122
                    else ((b - 65 + rot) % 26 + 65) if 65 <= b <= 90
                    else b
                    for b in data
                )
                if self._looks_like_valid_data(decrypted):
                    results.append(decrypted)
            except Exception:
                pass
        return results

    def parse_with_pattern(self, data: bytes, pattern: str) -> Optional[Dict[str, Any]]:
        """Parsea datos binarios usando un patrón struct.

        Patrón: '<' (little-endian), '>' (big-endian), seguido de:
          I (uint32), H (uint16), B (uint8), i (int32), etc.

        Ejemplo: '<IH4sB' → parsea uint32 + uint16 + 4 bytes + uint8

        Returns:
            Dict con valores nombrados o None si falla.
        """
        try:
            size = struct.calcsize(pattern)
            if len(data) < size:
                return None
            values = struct.unpack(pattern, data[:size])
            return {'data': values, 'parsed_bytes': size}
        except struct.error:
            return None

    def hex_dump_annotated(self, data: bytes, width: int = 16,
                          annotations: Optional[Dict[int, str]] = None) -> str:
        """Genera volcado hexadecimal con anotaciones opcional.

        Args:
            data: Bytes a mostrar
            width: Bytes por línea
            annotations: Dict {offset: anotación}

        Returns:
            String formateado.
        """
        lines = []
        annotations = annotations or {}

        for offset in range(0, len(data), width):
            chunk = data[offset:offset + width]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(
                chr(b) if 32 <= b < 127 else '.' for b in chunk
            )
            line = f'{offset:08x}  {hex_part:<{width * 3 - 1}}  |{ascii_part}|'

            notes = [annotations[o] for o in range(offset, offset + len(chunk))
                     if o in annotations]
            if notes:
                line += '  # ' + '; '.join(notes)

            lines.append(line)

        return '\n'.join(lines)

    def _calculate_entropy(self, data: bytes) -> float:
        """Calcula entropía de Shannon: media de -p(x)*log2(p(x))."""
        if not data:
            return 0
        import math
        counts = Counter(data)
        entropy = sum(
            -(count / len(data)) * math.log2(count / len(data))
            for count in counts.values()
        )
        return entropy

    def _find_repeating_pattern(self, data: bytes, max_pattern_size: int = 8
                               ) -> Optional[Tuple[bytes, int]]:
        """Detecta patrones repetitivos.

        Returns:
            (patrón, frecuencia) o None.
        """
        for pattern_size in range(1, min(max_pattern_size + 1, len(data) // 2)):
            pattern = data[:pattern_size]
            if len(data) % pattern_size != 0:
                continue
            if all(
                data[i:i + pattern_size] == pattern
                for i in range(0, len(data), pattern_size)
            ):
                return pattern, len(data) // pattern_size
        return None

    def _detect_header(self, data: bytes) -> Optional[bytes]:
        """Detecta posibles headers (4 bytes iniciales si son raros).

        Returns:
            Primeros 4 bytes si parecen ser un header mágico.
        """
        if len(data) < 4:
            return None

        header = data[:4]
        # Heurística: bytes bajos/altos, patrón poco común
        if any(b < 32 or b > 126 for b in header):
            return header

        return None

    def _detect_potential_lengths(self, data: bytes) -> List[int]:
        """Detecta campos de longitud potenciales.

        Busca valores uint32/uint16 que coincidan con longitudes reales.

        Returns:
            Lista de posibles longitudes encontradas.
        """
        lengths = []
        if len(data) < 8:
            return lengths

        # Buscar uint32 little-endian
        for offset in range(0, min(len(data) - 3, 16)):
            val_le = struct.unpack('<I', data[offset:offset + 4])[0]
            val_be = struct.unpack('>I', data[offset:offset + 4])[0]

            if val_le == len(data) - offset - 4:
                lengths.append(val_le)
            if val_be == len(data) - offset - 4:
                lengths.append(val_be)

        return list(set(lengths))[:5]  # Top 5 únicos

    def _detect_compression(self, data: bytes) -> Optional[str]:
        """Detecta si los datos están comprimidos.

        Returns:
            'zlib', 'gzip', 'deflate' o None.
        """
        if len(data) < 2:
            return None

        # Zlib: 78 9C / 78 DA / 78 01
        if data[0] == 0x78 and data[1] in (0x9C, 0xDA, 0x01):
            return 'zlib'

        # Gzip: 1F 8B
        if data[0] == 0x1F and data[1] == 0x8B:
            return 'gzip'

        # Deflate (sin header, difícil de detectar)
        try:
            zlib.decompress(data, -zlib.MAX_WBITS)
            return 'deflate'
        except Exception:
            pass

        return None

    def _classify_format(self, data: bytes, entropy: float, ascii_ratio: float,
                        null_bytes: int, compression: Optional[str]) -> str:
        """Clasifica el formato de los datos.

        Returns:
            Clasificación: 'text', 'compressed', 'encrypted', 'structured', 'unknown'.
        """
        if compression:
            return 'compressed'

        if ascii_ratio > 0.8 and null_bytes < len(data) * 0.05:
            return 'text'

        # Entropía alta sugiere encriptación
        if entropy > 7.0:
            return 'encrypted'

        # Muchos nulls o valores bajos sugieren estructura binaria
        if null_bytes > len(data) * 0.1 or entropy < 4.0:
            return 'structured'

        return 'unknown'

    def _looks_like_valid_data(self, data: bytes) -> bool:
        """Heurística: ¿parece datos válidos después de transformación?"""
        if not data:
            return False
        # Ratio ASCII decente, o patrón repetitivo conocido
        ascii_count = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
        ascii_ratio = ascii_count / len(data) if data else 0
        null_ratio = data.count(b'\x00') / len(data) if data else 0
        entropy = self._calculate_entropy(data)
        return (ascii_ratio > 0.5 or entropy < 3.0) and null_ratio < 0.5


class StreamBinaryAnalyzer:
    """Analiza streams TCP/UDP y aplica decodificadores."""

    def __init__(self):
        self.decoder = BinaryDecoder()
        self.stream_cache: Dict[int, Dict[str, Any]] = {}

    def analyze_stream(self, stream) -> Dict[str, Any]:
        """Analiza un SocketStream completo (TX + RX).

        Args:
            stream: SocketStream desde core/interceptor.py

        Returns:
            Dict con análisis de ambas direcciones.
        """
        fd = stream.fd
        if fd in self.stream_cache:
            return self.stream_cache[fd]

        out_data = bytes(stream.out_data)
        in_data = bytes(stream.in_data)

        result = {
            'fd': fd,
            'proto': stream.proto,
            'peer': stream.peer,
            'out': {
                'raw': out_data,
                'analysis': self.decoder.analyze(out_data),
                'decompressed': self.decoder.try_decompress(out_data),
                'xor_attempts': self.decoder.try_decrypt_xor(out_data),
                'rot_attempts': self.decoder.try_decrypt_rot(out_data),
            },
            'in': {
                'raw': in_data,
                'analysis': self.decoder.analyze(in_data),
                'decompressed': self.decoder.try_decompress(in_data),
                'xor_attempts': self.decoder.try_decrypt_xor(in_data),
                'rot_attempts': self.decoder.try_decrypt_rot(in_data),
            },
        }

        self.stream_cache[fd] = result
        return result

    def format_analysis_report(self, stream) -> str:
        """Genera un reporte legible del análisis.

        Returns:
            String con análisis detallado.
        """
        analysis = self.analyze_stream(stream)
        lines = []

        lines.append(f"\n{'='*70}")
        lines.append(f"Stream FD={analysis['fd']} | {analysis['proto']} | {analysis['peer']}")
        lines.append(f"{'='*70}")

        for direction in ('out', 'in'):
            lines.append(f"\n{direction.upper()} (TX {'→' if direction == 'out' else '←'} RX):")
            lines.append('-' * 70)

            dir_data = analysis[direction]
            raw = dir_data['raw']
            ana = dir_data['analysis']

            if not raw:
                lines.append("(sin datos)")
                continue

            lines.append(
                f"Length: {ana.length} bytes | Entropy: {ana.entropy:.2f} | "
                f"ASCII: {ana.ascii_ratio*100:.1f}% | Nulls: {ana.null_bytes}"
            )
            lines.append(
                f"Format: {ana.likely_format} | "
                f"Min/Max byte: 0x{ana.min_byte_value:02x}/0x{ana.max_byte_value:02x}"
            )

            if ana.compression_type:
                lines.append(f"⚠️  Compresión detectada: {ana.compression_type}")
                decompressed = dir_data.get('decompressed')
                if decompressed:
                    lines.append(f"   Descomprimido: {len(decompressed)} bytes")
                    lines.append(f"   Preview: {decompressed[:80]}")

            if ana.repeating_pattern:
                lines.append(
                    f"🔁 Patrón repetitivo: {ana.repeating_pattern.hex()} "
                    f"({ana.pattern_frequency}x)"
                )

            if ana.potential_header:
                lines.append(f"📋 Posible header: {ana.potential_header.hex()}")

            if ana.potential_lengths:
                lines.append(f"📏 Longitudes detectadas: {ana.potential_lengths}")

            # Mostrar intentos de descifrado
            if dir_data.get('xor_attempts'):
                lines.append(
                    f"🔐 {len(dir_data['xor_attempts'])} posibles descifrados XOR detectados"
                )

            # Hexdump pequeño
            if len(raw) <= 256:
                lines.append("\nHex dump:")
                lines.append(self.decoder.hex_dump_annotated(raw))
            else:
                lines.append("\nHex dump (primeros 128 bytes):")
                lines.append(self.decoder.hex_dump_annotated(raw[:128]))
                lines.append("\nHex dump (últimos 128 bytes):")
                lines.append(self.decoder.hex_dump_annotated(raw[-128:], width=16,
                                                             annotations={
                                                                 0: "fin del stream"
                                                             }))

        return '\n'.join(lines)
