# NetScope - Guía de Extensibilidad

## Objetivo

NetScope está diseñado para funcionar con **cualquier motor gráfico, framework de networking, 
y tipo de aplicación** - no solo juegos Unity.

## Arquitectura Base (Extensible)

```
┌─────────────────────────────────────────────┐
│  BinaryDecoder (Generic - Todos usan esto)  │
│  - Compresión/Descompresión                 │
│  - XOR/ROT13                                │
│  - Entropia, Strings, Carving               │
└─────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────┐
│  ProtocolRegistry (Extensible)              │
│  - Registro dinámico de protocolos          │
│  - Detección de firmas                      │
│  - Binary Forensics genérico                │
└─────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────┐
│  Framework-Specific Analyzers (Pluggable)   │
│  - UnityNetworkAnalyzer                     │
│  - UnrealNetworkAnalyzer (por añadir)       │
│  - GodotNetworkAnalyzer (por añadir)        │
│  - CustomEngineAnalyzer (patrón para crear) │
└─────────────────────────────────────────────┘
```

## Cómo Agregar Soporte a Nuevos Motores

### 1. Crear un Analizador Específico del Motor

```python
# core/unreal_hooks.py (ejemplo)

from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class UnrealMessagePattern:
    """Patrones de identificación para Unreal Engine"""
    
    REPLICATION_GRAPH = b'\x00\x00\x00\x00'  # Header típico
    STEAM_NETWORKING = b'FOnlineSubsystemSteam'
    PIXEL_STREAMING = b'PixelStreaming'
    
    @staticmethod
    def detect_replication_message(data: bytes) -> bool:
        """Detecta mensajes de Replication Graph"""
        if len(data) < 4:
            return False
        # Lógica de detección específica de Unreal
        return data[:4] == UnrealMessagePattern.REPLICATION_GRAPH
    
    @staticmethod
    def detect_steam_networking(data: bytes) -> bool:
        """Detecta Steam Networking API"""
        return UnrealMessagePattern.STEAM_NETWORKING in data[:50]


class UnrealNetworkAnalyzer:
    """Analizador para aplicaciones de Unreal Engine"""
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        """Analiza datos de red de Unreal"""
        result = {
            'engine': 'Unreal',
            'framework': None,
            'encoding': 'binary',
            'format_type': 'unknown'
        }
        
        if UnrealMessagePattern.detect_replication_message(data):
            result['framework'] = 'Replication Graph'
            result['format_type'] = 'replication'
        elif UnrealMessagePattern.detect_steam_networking(data):
            result['framework'] = 'Steam Networking'
            result['format_type'] = 'steam_p2p'
        
        return result
```

### 2. Registrar el Analizador en ProtocolRegistry

```python
# En main.py o al inicializar

from core.protocol_registry import ProtocolRegistry
from core.unreal_hooks import UnrealNetworkAnalyzer

registry = ProtocolRegistry()
registry.register_analyzer('unreal', UnrealNetworkAnalyzer())
```

### 3. Integrar en StreamAnalyzer

```python
# core/stream_analyzer.py

# Modificar analyze_framework() para incluir Unreal
def analyze_framework(self, data: bytes) -> Dict[str, Any]:
    """Detecta framework de juego/app"""
    
    # Intentar todos los analizadores registrados
    registry = ProtocolRegistry()
    
    for engine_name, analyzer in registry.analyzers.items():
        result = analyzer.analyze(data)
        if result['framework']:
            return result
    
    return {'engine': 'unknown', 'framework': None}
```

## Motores Soportados / Por Soportar

### ✓ Unity (Completamente implementado)

**Frameworks:**
- ✓ Mirror
- ✓ Netcode for GameObjects
- ✓ Photon 2 (PUN2)
- ✓ PlayFab
- ✓ Firebase

**Detección:** Por clase de red y headers conocidos
**Parsing:** JSON, Protobuf, MessagePack

---

### 🟡 Unreal Engine (Plantilla disponible)

**Frameworks soportados típicamente:**
- Replication Graph (motor nativo)
- Steam Networking (P2P)
- Epic Online Services (EOS)
- Custom FSocket networking
- Pixel Streaming

**Qué detectar:**
```python
# Replication Graph: headers específicos de Actor replication
# Steam: magic bytes de la API de Steam
# EOS: headers de autenticación de Epic
# FSocket: tamaño de paquete en los primeros bytes
```

**Ejemplo de firma:**
```
Replication Graph: [4 bytes header] + [Actor GUID] + [Property delta]
Steam P2P:        [SteamNetworkingMessage header] + [payload]
EOS:              [EOS header magic] + [encrypted data]
```

---

### 🟡 Godot Engine (Por implementar)

**Frameworks soportados:**
- MultiplayerSynchronizer (nativo)
- Netcode for Godot
- WebSocket directo
- Custom RPC

**Firmas:**
```python
# MultiplayerSynchronizer: "MultiplayerSynchronizer" en paths
# Netcode: "\x00\x00\x00\x00[RPC]" pattern
# WebSocket: estándar WS
# Custom RPC: varint + method_id + args
```

---

### 🟡 Minecraft / Java (Por implementar)

**Protocolos:**
- Minecraft Protocol (estándar)
- Custom mods networking
- Fabric/Forge APIs

**Firmas:**
```
Minecraft: [length varint] + [packet_id varint] + [data]
Fabric: Fabric-specific packet headers
Forge: FML handshake messages
```

---

### 🟡 Otros Motores

- **Defold** (HTML5/Mobile)
- **Cocos2d** (China-popular)
- **LibGDX** (Java)
- **Phaser** (Web)
- **Custom Engines** (patrón genérico)

---

## Cómo Crear un Analizador Genérico

Si el motor no está listado, puedes crear uno genérico:

```python
# core/custom_analyzer.py

from typing import Dict, Any
from dataclasses import dataclass

@dataclass
class CustomEngineSignatures:
    """Define firmas para detectar tu motor personalizado"""
    
    # Bytes característicos al inicio
    magic_bytes: bytes = None
    
    # Strings identificables
    id_strings: list = None
    
    # Patrón de estructura
    structure_pattern: str = None


class CustomEngineAnalyzer:
    """Analizador personalizado para tu motor"""
    
    def __init__(self, name: str, signatures: CustomEngineSignatures):
        self.name = name
        self.signatures = signatures
    
    def analyze(self, data: bytes) -> Dict[str, Any]:
        """Analiza datos del motor personalizado"""
        
        # 1. Buscar magic bytes
        if self.signatures.magic_bytes and data.startswith(self.signatures.magic_bytes):
            return {
                'engine': self.name,
                'framework': 'native_protocol',
                'format_type': 'binary',
                'encoding': 'binary'
            }
        
        # 2. Buscar strings identificables
        if self.signatures.id_strings:
            data_str = data[:100].decode('utf-8', errors='ignore')
            for sig_str in self.signatures.id_strings:
                if sig_str in data_str:
                    return {
                        'engine': self.name,
                        'framework': f'detected_by_string_{sig_str}',
                        'format_type': 'binary',
                        'encoding': 'binary'
                    }
        
        # 3. Validar estructura conocida
        if self.signatures.structure_pattern:
            if self._matches_structure(data):
                return {
                    'engine': self.name,
                    'framework': 'pattern_matched',
                    'format_type': 'structured',
                    'encoding': 'binary'
                }
        
        return {'engine': self.name, 'framework': None}
    
    def _matches_structure(self, data: bytes) -> bool:
        """Valida si los datos coinciden con el patrón"""
        # Implementar lógica específica
        return False


# USO:

# Para un motor personalizado llamado "MyGame"
my_engine = CustomEngineAnalyzer(
    name='MyGame',
    signatures=CustomEngineSignatures(
        magic_bytes=b'\x4D\x59',  # "MY"
        id_strings=['MyGame', 'CustomProto'],
        structure_pattern='varint+string+varint'
    )
)

registry = ProtocolRegistry()
registry.register_analyzer('my_game', my_engine)
```

## Cómo Manejar Nuevos Formatos de Compresión

Si encuentras compresión desconocida:

```python
# core/binary_decoder.py

def try_decompress(self, data: bytes) -> Optional[bytes]:
    """Extensible para nuevas compresiones"""
    
    # Formatos soportados
    decompressors = {
        'zlib': self._decompress_zlib,
        'gzip': self._decompress_gzip,
        'deflate': self._decompress_deflate,
        'brotli': self._decompress_brotli,  # Nuevo
        'zstd': self._decompress_zstd,      # Nuevo
        'lz4': self._decompress_lz4,        # Nuevo
    }
    
    for format_name, decompressor in decompressors.items():
        try:
            result = decompressor(data)
            if result:
                self.analysis.compression_type = format_name
                return result
        except:
            continue
    
    return None

def _decompress_brotli(self, data: bytes) -> Optional[bytes]:
    """Nuevo formato: Brotli (usado por navegadores)"""
    try:
        import brotli
        return brotli.decompress(data)
    except:
        return None

def _decompress_zstd(self, data: bytes) -> Optional[bytes]:
    """Nuevo formato: Zstandard (más eficiente)"""
    try:
        import zstandard as zstd
        ctx = zstd.ZstdDecompressor()
        return ctx.decompress(data)
    except:
        return None

def _decompress_lz4(self, data: bytes) -> Optional[bytes]:
    """Nuevo formato: LZ4 (baja latencia)"""
    try:
        import lz4.frame
        return lz4.frame.decompress(data)
    except:
        return None
```

## Cómo Manejar Nuevos Cifrados

```python
# core/binary_decoder.py

def try_decrypt(self, data: bytes) -> Optional[Dict[str, Any]]:
    """Extensible para nuevos cifrados"""
    
    decryptors = {
        'xor_1': lambda d: self._try_xor_1byte(d),
        'xor_multi': lambda d: self._try_xor_multibyte(d),
        'rot13': lambda d: self._try_rot13(d),
        'base64': lambda d: self._try_base64(d),       # Nuevo
        'simple_substitution': lambda d: self._try_substitution(d),  # Nuevo
    }
    
    for cipher_name, decryptor in decryptors.items():
        result = decryptor(data)
        if result:
            return {'cipher': cipher_name, 'decrypted': result}
    
    return None

def _try_base64(self, data: bytes) -> Optional[bytes]:
    """Base64 (usado a veces como ofuscación)"""
    try:
        import base64
        decoded = base64.b64decode(data)
        # Validar si parece texto
        if self._is_valid_text(decoded):
            return decoded
    except:
        pass
    return None

def _try_substitution(self, data: bytes) -> Optional[bytes]:
    """Cifrado por sustitución simple"""
    # Intenta descifrar usando análisis de frecuencia
    # Solo si datos cortos y parecer ser texto
    if len(data) < 100:
        return None
    try:
        # Lógica simple: buscar patrón conocido
        common_patterns = [b'the ', b'hello', b'test']
        for pattern in common_patterns:
            offset = self._find_substitution_key(data, pattern)
            if offset:
                return self._apply_substitution_key(data, offset)
    except:
        pass
    return None
```

## Patrón de Extensión Rápida

Para agregar soporte a un nuevo motor en **15 minutos**:

```python
# PASO 1: Crear archivo core/XX_hooks.py
# PASO 2: Definir clase XXXAnalyzer con método analyze()
# PASO 3: Registrar en main.py o en ProtocolRegistry
# PASO 4: Agregar test en tests/test_XX_hooks.py
# PASO 5: Actualizar IMPLEMENTATION_CHECKLIST.md
```

## Librerías de Compresión Recomendadas

Para expandir soporte:

```bash
pip install brotli          # Google Brotli (navegadores)
pip install zstandard       # Facebook Zstandard (eficiente)
pip install lz4             # LZ4 (baja latencia)
pip install lzma            # LZMA (libre de patentes)
pip install snappy          # Google Snappy
pip install lzope           # LZ77
```

## Librerías de Criptografía Recomendadas

Para descifrado avanzado:

```bash
pip install cryptography    # General (AES, RSA, etc.)
pip install pycryptodome    # AES, DES, cifrados clásicos
pip install tlslite-ng      # Protocolos TLS customizados
```

## Estructura Final (Roadmap)

```
core/
├── binary_decoder.py           ✓ Genérico para todos
├── protocol_registry.py        ✓ Registro extensible
│
├── unity_hooks.py              ✓ Unity (completado)
├── unreal_hooks.py             🟡 Unreal (plantilla)
├── godot_hooks.py              🟡 Godot (por hacer)
├── minecraft_hooks.py          🟡 Minecraft (por hacer)
│
└── custom_analyzer_template.py ✓ Patrón para crear nuevos
```

## Verificación de Extensibilidad

```python
# Este código verifica que puedas agregar nuevos motores

from core.protocol_registry import ProtocolRegistry
from core.binary_decoder import BinaryDecoder

def test_extensibility():
    """Verifica que sea fácil agregar nuevos motores"""
    
    # 1. ProtocolRegistry debe aceptar nuevos analizadores
    registry = ProtocolRegistry()
    
    class DummyAnalyzer:
        def analyze(self, data):
            return {'framework': 'test'}
    
    registry.register_analyzer('test_engine', DummyAnalyzer())
    assert 'test_engine' in registry.analyzers
    
    # 2. BinaryDecoder debe ser agnostico del motor
    decoder = BinaryDecoder()
    data = b'\x78\x9c\x63\x64'  # zlib
    result = decoder.analyze(data)
    assert result.compression_type == 'zlib'
    
    # 3. Debería funcionar sin cambios en BinaryDecoder
    print("✓ Extensibilidad verificada")

test_extensibility()
```

## Resumen de Capacidades Extensibles

| Aspecto | Estado | Cómo Extender |
|---------|--------|----------------|
| **Motores Gráficos** | Unity ✓ | Crear core/XX_hooks.py |
| **Compresión** | zlib, gzip, deflate ✓ | Agregar decompressor en binary_decoder.py |
| **Cifrado** | XOR, ROT13 ✓ | Agregar decryptor en binary_decoder.py |
| **Formatos** | JSON, Protobuf, MessagePack ✓ | Extender encoding detection |
| **Plataformas** | Windows, Frida ✓ | Agregar agent hooks en agent/agent.js |

---

**Conclusión:** NetScope es diseñado para **escalar con nuevos motores, frameworks y 
tecnologías sin cambiar el código base**. Sigue los patrones anteriores y podrás 
agregar soporte a cualquier cosa en minutos.
