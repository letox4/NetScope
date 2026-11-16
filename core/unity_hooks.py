# -*- coding: utf-8 -*-
"""NetScope - Hooks especializados para juegos Unity.

Proporciona helpers para capturar y parsear tráfico de juegos basados en
Unity, que típicamente usan:
  - LLAPI (Low Level API) de Winsock
  - NetworkTransform, NetworkManager (Mirror/Netcode)
  - Custom protocols (JSON, MessagePack, Protobuf, binario propietario)
  - Compresión (zlib en payloads)
  - Cifrado simple (XOR, AES)
"""

import struct
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass


@dataclass
class UnityNetworkMessage:
    """Mensaje de red en juego Unity."""
    timestamp: float
    direction: str  # 'send' o 'recv'
    peer: str
    raw_data: bytes
    parsed: Optional[Dict[str, Any]] = None
    encoding_type: str = 'unknown'  # 'json', 'binary', 'protobuf', etc.
    compressed: bool = False
    encrypted: bool = False


class UnityNetworkAnalyzer:
    """Analiza tráfico de redes de Unity."""

    def __init__(self):
        self.messages: List[UnityNetworkMessage] = []
        self.custom_parsers: Dict[str, Callable] = {}

    def register_message_parser(self, msg_type: str, parser: Callable[[bytes], Dict]):
        """Registra un parser para un tipo específico de mensaje."""
        self.custom_parsers[msg_type] = parser

    def analyze_message(self, data: bytes, direction: str, peer: str) -> UnityNetworkMessage:
        """Analiza un mensaje de red Unity."""
        import time
        from core.binary_decoder import BinaryDecoder

        decoder = BinaryDecoder()
        analysis = decoder.analyze(data)

        msg = UnityNetworkMessage(
            timestamp=time.time(),
            direction=direction,
            peer=peer,
            raw_data=data,
            encoding_type=self._detect_encoding(data),
            compressed=analysis.compression_type is not None,
            encrypted=analysis.likely_format == 'encrypted'
        )

        # Intentar parsear según el tipo
        msg.parsed = self._parse_message(data, msg.encoding_type)

        self.messages.append(msg)
        return msg

    def _detect_encoding(self, data: bytes) -> str:
        """Detecta el tipo de encoding del mensaje."""
        if not data:
            return 'empty'

        # JSON
        if data.startswith(b'{') or data.startswith(b'['):
            try:
                import json
                json.loads(data)
                return 'json'
            except Exception:
                pass

        # MessagePack
        if len(data) > 0 and data[0] in (0xdc, 0xdd, 0xde, 0xdf, 0x80, 0x90):
            return 'msgpack'

        # UTF-8 text (antes de protobuf para evitar falsos positivos)
        try:
            decoded = data.decode('utf-8')
            # Verificar que sea mayormente imprimible
            if sum(1 for c in decoded if ord(c) >= 32 or c in '\n\r\t') / len(decoded) > 0.9:
                return 'text'
        except UnicodeDecodeError:
            pass

        # Protobuf (difícil de detectar, pero buscar varint tags)
        if len(data) > 1 and (data[0] & 0x07) in (0, 1, 2, 5):
            return 'protobuf'

        return 'binary'

    def _parse_message(self, data: bytes, encoding: str) -> Optional[Dict]:
        """Parsea el mensaje según su tipo."""
        if encoding == 'json':
            try:
                import json
                return json.loads(data)
            except Exception:
                return None

        if encoding == 'text':
            try:
                return {'text': data.decode('utf-8', 'ignore')}
            except Exception:
                return None

        if encoding == 'msgpack':
            try:
                import msgpack
                return msgpack.unpackb(data, raw=False)
            except Exception:
                return None

        if encoding == 'protobuf':
            return self._parse_protobuf_simple(data)

        return None

    def _parse_protobuf_simple(self, data: bytes) -> Dict:
        """Parser simplificado de Protobuf (sin .proto file)."""
        result = {'fields': []}

        i = 0
        while i < len(data):
            if i >= len(data):
                break

            # Leer tag (varint)
            tag_byte = data[i]
            field_number = tag_byte >> 3
            wire_type = tag_byte & 0x07
            i += 1

            # Parsear según wire type
            if wire_type == 0:  # Varint
                value, i = self._read_varint(data, i)
                result['fields'].append({
                    'field': field_number,
                    'type': 'varint',
                    'value': value
                })
            elif wire_type == 1:  # Fixed64
                if i + 8 <= len(data):
                    value = struct.unpack('<Q', data[i:i+8])[0]
                    result['fields'].append({
                        'field': field_number,
                        'type': 'fixed64',
                        'value': value
                    })
                    i += 8
            elif wire_type == 2:  # Length-delimited (string, bytes, submessage)
                length, i = self._read_varint(data, i)
                if i + length <= len(data):
                    value = data[i:i+length]
                    result['fields'].append({
                        'field': field_number,
                        'type': 'bytes/string',
                        'length': length,
                        'value': value[:50].hex() if len(value) > 50 else value.hex(),
                        'text': value.decode('utf-8', 'ignore')[:50]
                    })
                    i += length
            elif wire_type == 5:  # Fixed32
                if i + 4 <= len(data):
                    value = struct.unpack('<I', data[i:i+4])[0]
                    result['fields'].append({
                        'field': field_number,
                        'type': 'fixed32',
                        'value': value
                    })
                    i += 4

        return result

    def _read_varint(self, data: bytes, pos: int) -> tuple:
        """Lee un varint desde posición."""
        result = 0
        shift = 0
        while pos < len(data):
            byte = data[pos]
            result |= (byte & 0x7F) << shift
            pos += 1
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result, pos

    def get_message_summary(self, msg: UnityNetworkMessage) -> str:
        """Genera un resumen del mensaje."""
        lines = []
        lines.append(f"[{msg.direction.upper()}] {msg.peer} | {msg.encoding_type}")
        lines.append(f"  Size: {len(msg.raw_data)} bytes")

        if msg.compressed:
            lines.append(f"  Compressed: YES")
        if msg.encrypted:
            lines.append(f"  Encrypted: YES (probable)")

        if msg.parsed:
            lines.append(f"  Parsed: {str(msg.parsed)[:100]}...")
        else:
            hex_preview = msg.raw_data[:32].hex()
            lines.append(f"  Hex: {hex_preview}{'...' if len(msg.raw_data) > 32 else ''}")

        return '\n'.join(lines)

    def export_pcap_lua(self, output_file: str):
        """Exporta mensajes en formato Lua/Wireshark dissector."""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('-- Unity Game Network Dissector\n')
            f.write('-- Auto-generated by NetScope\n\n')

            for i, msg in enumerate(self.messages):
                f.write(f'-- Message {i+1}\n')
                f.write(f'-- Time: {msg.timestamp}\n')
                f.write(f'-- Direction: {msg.direction}\n')
                f.write(f'-- Peer: {msg.peer}\n')
                f.write(f'-- Type: {msg.encoding_type}\n')
                f.write(f'-- Data: {msg.raw_data.hex()}\n')
                f.write(f'-- Parsed: {msg.parsed}\n')
                f.write('\n')


class UnityMessagePatterns:
    """Patrones conocidos de mensajes Unity."""

    # Mirror Network Library
    MIRROR_SPAWN = b'MirrorSpawn'
    MIRROR_DESTROY = b'MirrorDestroy'
    MIRROR_RPC = b'MirrorRPC'

    # Netcode for GameObjects (Netcode)
    NETCODE_SPAWN = b'NetcodeSpawn'
    NETCODE_RPC = b'NetcodeRPC'

    # Photon
    PHOTON_EVENT = b'\xBD'  # Photon event code
    PHOTON_OPERATION = b'\xBE'

    # PlayFab
    PLAYFAB_REQUEST = b'{"TitleId"'
    PLAYFAB_RESPONSE = b'"code"'

    # Firebase Realtime DB
    FIREBASE_PUT = b'PUT\r\n'
    FIREBASE_GET = b'GET\r\n'

    @staticmethod
    def detect_framework(data: bytes) -> Optional[str]:
        """Detecta qué framework de red usa el juego."""
        if data.startswith(UnityMessagePatterns.MIRROR_SPAWN):
            return 'Mirror'
        if data.startswith(UnityMessagePatterns.NETCODE_SPAWN):
            return 'Netcode'
        if (data.startswith(UnityMessagePatterns.PHOTON_EVENT)
                or (data.startswith(b'\xf0') and len(data) >= 5)
                or data.startswith(b'\xfb\x00\x00')):
            return 'Photon'
        if UnityMessagePatterns.PLAYFAB_REQUEST in data:
            return 'PlayFab'
        if UnityMessagePatterns.FIREBASE_PUT in data or UnityMessagePatterns.FIREBASE_GET in data:
            return 'Firebase'
        if data.startswith(b'{'):
            return 'JSON (custom)'
        if data.startswith(b'\x78\x9c') or data.startswith(b'\x1f\x8b'):
            return 'Compressed (zlib/gzip)'

        return None


class UnityGameNetworkSniffer:
    """Sniffer de alto nivel para juegos Unity."""

    def __init__(self):
        self.analyzer = UnityNetworkAnalyzer()
        self.sessions: Dict[str, List[UnityNetworkMessage]] = {}

    def process_stream(self, stream) -> Dict[str, Any]:
        """Procesa un stream TCP/UDP capturado."""
        from core.binary_decoder import BinaryDecoder

        out_data = bytes(stream.out_data)
        in_data = bytes(stream.in_data)

        session_id = f"{stream.fd}_{stream.peer}"
        self.sessions[session_id] = []

        result = {
            'session': session_id,
            'peer': stream.peer,
            'proto': stream.proto,
            'framework': None,
            'messages': [],
            'statistics': {}
        }

        # Analizar salida (client -> server)
        if out_data:
            framework = UnityMessagePatterns.detect_framework(out_data)
            if framework:
                result['framework'] = framework

            msg = self.analyzer.analyze_message(out_data, 'send', stream.peer)
            result['messages'].append({
                'direction': 'send',
                'size': len(out_data),
                'encoding': msg.encoding_type,
                'compressed': msg.compressed,
                'encrypted': msg.encrypted,
                'preview': out_data[:100].hex()
            })
            self.sessions[session_id].append(msg)

        # Analizar entrada (server -> client)
        if in_data:
            framework = UnityMessagePatterns.detect_framework(in_data)
            if framework and not result['framework']:
                result['framework'] = framework

            msg = self.analyzer.analyze_message(in_data, 'recv', stream.peer)
            result['messages'].append({
                'direction': 'recv',
                'size': len(in_data),
                'encoding': msg.encoding_type,
                'compressed': msg.compressed,
                'encrypted': msg.encrypted,
                'preview': in_data[:100].hex()
            })
            self.sessions[session_id].append(msg)

        # Estadísticas
        decoder = BinaryDecoder()
        result['statistics'] = {
            'total_bytes': len(out_data) + len(in_data),
            'tx_bytes': len(out_data),
            'rx_bytes': len(in_data),
            'entropy_out': decoder._calculate_entropy(out_data) if out_data else 0,
            'entropy_in': decoder._calculate_entropy(in_data) if in_data else 0
        }

        return result

    def generate_report(self) -> str:
        """Genera un reporte de todas las sesiones."""
        lines = []
        lines.append("=" * 80)
        lines.append("Unity Game Network Analysis Report")
        lines.append("=" * 80)

        for session_id, messages in self.sessions.items():
            lines.append(f"\nSession: {session_id}")
            lines.append("-" * 80)

            for i, msg in enumerate(messages):
                lines.append(f"Message {i+1}:")
                lines.append(self.analyzer.get_message_summary(msg))
                lines.append("")

        return '\n'.join(lines)
