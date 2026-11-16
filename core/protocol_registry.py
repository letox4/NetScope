# -*- coding: utf-8 -*-
"""NetScope - Gestión de protocolos personalizados y extensiones.

Permite registrar parsers, descifrados, y reglas de formateo para
protocolos específicos sin modificar el core.
"""
from typing import Callable, Dict, Any, List, Optional
from dataclasses import dataclass
import re


@dataclass
class ProtocolRule:
    """Regla para identificar y parsear un protocolo."""
    name: str
    signatures: List[bytes]  # Headers o patrones que identifican este protocolo
    parser: Optional[Callable[[bytes], Dict[str, Any]]]
    description: str
    priority: int = 0  # Mayor = se prueba primero


class ProtocolRegistry:
    """Registro global de protocolos y parsers personalizados."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_registry()
        return cls._instance

    def _init_registry(self):
        self.protocols: Dict[str, ProtocolRule] = {}
        self._load_built_in_protocols()

    def _load_built_in_protocols(self):
        """Carga protocolos comunes built-in."""
        # Auto-load game engine analyzers
        self._load_game_engines()
    
    def _load_game_engines(self):
        """Load all game engine analyzers."""
        try:
            from .unity_hooks import UnityNetworkAnalyzer
            self.unity_analyzer = UnityNetworkAnalyzer()
        except:
            self.unity_analyzer = None
        
        try:
            from .unreal_hooks import UnrealNetworkAnalyzer
            self.unreal_analyzer = UnrealNetworkAnalyzer()
        except:
            self.unreal_analyzer = None
        
        try:
            from .godot_hooks import GodotNetworkAnalyzer
            self.godot_analyzer = GodotNetworkAnalyzer()
        except:
            self.godot_analyzer = None
        
        try:
            from .java_hooks import JavaGameAnalyzer
            self.java_analyzer = JavaGameAnalyzer()
        except:
            self.java_analyzer = None
        
        try:
            from .advanced_decoders import AdvancedDecoderExtension
            self.advanced_decoder = AdvancedDecoderExtension()
        except:
            self.advanced_decoder = None

    def register_protocol(self, rule: ProtocolRule):
        """Registra un protocolo nuevo."""
        self.protocols[rule.name] = rule

    def detect_protocol(self, data: bytes) -> Optional[str]:
        """Detecta el protocolo basado en signatures.

        Returns:
            Nombre del protocolo o None.
        """
        if not data:
            return None

        # Ordenar por prioridad
        sorted_protocols = sorted(
            self.protocols.values(),
            key=lambda r: r.priority,
            reverse=True
        )

        for rule in sorted_protocols:
            for sig in rule.signatures:
                if data.startswith(sig):
                    return rule.name

        return None

    def parse_protocol(self, protocol_name: str, data: bytes) -> Optional[Dict[str, Any]]:
        """Parsea datos con el parser de un protocolo.

        Returns:
            Dict con datos parseados o None si falla.
        """
        rule = self.protocols.get(protocol_name)
        if not rule or not rule.parser:
            return None

        try:
            return rule.parser(data)
        except Exception as e:
            return {'error': str(e), 'raw': data.hex()}


def register_custom_protocol(
    name: str,
    signatures: List[bytes],
    parser: Callable[[bytes], Dict[str, Any]],
    description: str = "",
    priority: int = 0
):
    """Función de conveniencia para registrar protocolos.

    Ejemplo:
        def parse_myproto(data: bytes) -> Dict:
            return {
                'header': data[:4].hex(),
                'payload': data[4:].decode('utf-8', 'ignore')
            }

        register_custom_protocol(
            name='MyProtocol',
            signatures=[b'MYPRO'],
            parser=parse_myproto,
            description='Mi protocolo personalizado',
            priority=10
        )
    """
    registry = ProtocolRegistry()
    rule = ProtocolRule(
        name=name,
        signatures=signatures,
        parser=parser,
        description=description,
        priority=priority
    )
    registry.register_protocol(rule)


# Ejemplos de protocolos que se pueden registrar:

def _parse_json_like(data: bytes) -> Dict[str, Any]:
    """Parser para datos tipo JSON (usa regex simple)."""
    try:
        text = data.decode('utf-8', 'ignore')
        # Detectar estructura JSON básica
        if text.startswith('{') and text.endswith('}'):
            return {'type': 'json_like', 'text': text, 'length': len(text)}
        return None
    except Exception:
        return None


def _parse_msgpack_like(data: bytes) -> Dict[str, Any]:
    """Parser para datos tipo MessagePack."""
    # Implementaríamos msgpack parsing aquí
    if len(data) > 0 and data[0] in (0xdc, 0xdd, 0xde, 0xdf):
        return {'type': 'msgpack_like', 'first_byte': hex(data[0])}
    return None


def _parse_protobuf_like(data: bytes) -> Dict[str, Any]:
    """Parser simple para datos tipo Protobuf."""
    # Protobuf tiene tags varint al inicio
    if len(data) > 0:
        first_byte = data[0]
        wire_type = first_byte & 0x07
        field_number = first_byte >> 3
        return {
            'type': 'protobuf_like',
            'field_number': field_number,
            'wire_type': wire_type,
            'data_length': len(data)
        }
    return None


# Registro de protocolos built-in
_BUILTIN_PROTOCOLS = {
    'json': ProtocolRule(
        name='JSON',
        signatures=[b'{', b'['],
        parser=_parse_json_like,
        description='JavaScript Object Notation',
        priority=5
    ),
}


class AdvancedBinaryPattern:
    """Patrón binario avanzado para búsqueda y análisis."""

    def __init__(self, pattern: str, name: str = ""):
        """
        Pattern syntax:
          'FF' → byte exacto 0xFF
          '??' → cualquier byte
          'FF 00 FF' → secuencia exacta (espacios ignorados)
          'FF{3}' → FF repetido 3 veces
          '[48-5A]' → rango de bytes
          '...' → ceros acolchados automáticamente

        Ejemplo:
          'FF ?? FF' → FF, cualquier byte, FF
          'FF{4}' → FFFFFFFF
        """
        self.name = name
        self.pattern_text = pattern
        self.regex = self._compile_pattern(pattern)

    def _compile_pattern(self, pattern: str) -> bytes:
        """Compila patrón a bytes o regex."""
        # Implementación simplificada
        pattern = pattern.replace(' ', '')

        # Expandir FF{N}
        def expand_repeat(m):
            byte_val = m.group(1)
            count = int(m.group(2))
            return byte_val * count

        pattern = re.sub(r'([0-9A-Fa-f]{2})\{(\d+)\}', expand_repeat, pattern)

        # Convertir a bytes
        try:
            result = bytes.fromhex(pattern)
            return result
        except ValueError:
            return b''

    def matches(self, data: bytes) -> List[int]:
        """Encuentra todas las coincidencias en data.

        Returns:
            Lista de offsets donde coincide el patrón.
        """
        offsets = []
        if not self.regex:
            return offsets

        for i in range(len(data) - len(self.regex) + 1):
            if data[i:i + len(self.regex)] == self.regex:
                offsets.append(i)

        return offsets


class BinaryForensics:
    """Análisis forense de datos binarios (carving, recovery, etc.)."""

    @staticmethod
    def find_possible_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extrae strings legibles de datos binarios.

        Returns:
            Lista de strings encontrados.
        """
        strings = []
        current = []

        for byte in data:
            if 32 <= byte <= 126:  # ASCII printable
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []

        if len(current) >= min_length:
            strings.append(''.join(current))

        return strings

    @staticmethod
    def find_null_terminated_strings(data: bytes) -> List[bytes]:
        """Extrae strings terminados en null."""
        strings = []
        parts = data.split(b'\x00')
        for part in parts:
            if part and all(32 <= b <= 126 for b in part):
                strings.append(part)
        return strings

    @staticmethod
    def carve_known_formats(data: bytes) -> Dict[str, List[int]]:
        """Busca headers de formatos conocidos.

        Returns:
            Dict {formato: [offsets]}
        """
        formats = {
            'PNG': [b'\x89PNG\r\n\x1a\n'],
            'JPEG': [b'\xff\xd8\xff'],
            'ZIP': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
            'PDF': [b'%PDF'],
            'ELF': [b'\x7fELF'],
            'PE': [b'MZ'],
            'GZIP': [b'\x1f\x8b'],
            'ZLIB': [b'\x78\x9c', b'\x78\xda'],
        }

        found = {}
        for fmt, sigs in formats.items():
            offsets = []
            for sig in sigs:
                pos = 0
                while True:
                    pos = data.find(sig, pos)
                    if pos == -1:
                        break
                    offsets.append(pos)
                    pos += 1
            if offsets:
                found[fmt] = sorted(set(offsets))

        return found

    @staticmethod
    def calculate_statistics(data: bytes) -> Dict[str, Any]:
        """Calcula estadísticas de datos binarios.

        Returns:
            Dict con count, frecuencias, etc.
        """
        from collections import Counter

        if not data:
            return {'length': 0}

        counter = Counter(data)
        total = len(data)

        return {
            'length': total,
            'unique_bytes': len(counter),
            'most_common': counter.most_common(10),
            'byte_distribution': {b: count for b, count in counter.items()},
            'average_byte_value': sum(data) / total if total else 0,
            'contains_all_bytes': len(counter) == 256,
        }
