# NetScope Binary Decoder - Guía de Uso

## 📋 Descripción General

El módulo `binary_decoder.py` proporciona un framework agnóstico para analizar, descodificar y parsear datos binarios arbitrarios capturados por Frida, sin necesidad de documentación de protocolos.

**Características principales:**
- ✅ Detección automática de compresión (zlib, gzip, deflate)
- ✅ Descifrado simple (XOR, ROT13)
- ✅ Extracción de strings y formatos conocidos (PNG, ZIP, PDF, ELF, etc.)
- ✅ Análisis de entropía y estructura binaria
- ✅ Parsers personalizados registrables
- ✅ Hexdump anotado con offsets
- ✅ Estadísticas detalladas de bytes

---

## 🚀 Uso Básico

### 1. Analizar datos binarios directamente

```python
from core.binary_decoder import BinaryDecoder

decoder = BinaryDecoder()

# Datos binarios arbitrarios
data = b'\x78\x9c\x63\x64\x60...'  # Zlib comprimido

# Análisis automático
analysis = decoder.analyze(data)
print(f"Formato detectado: {analysis.likely_format}")
print(f"Compresión: {analysis.compression_type}")
print(f"Entropía: {analysis.entropy:.2f}")
print(f"Ratio ASCII: {analysis.ascii_ratio*100:.1f}%")
```

### 2. Descomprimir datos automáticamente

```python
# Intenta múltiples métodos de descompresión
decompressed = decoder.try_decompress(data)

if decompressed:
    print(f"Descomprimido: {len(data)} → {len(decompressed)} bytes")
    print(decompressed[:100])
```

### 3. Descifrar datos cifrados

```python
# Intenta descifrado XOR con diferentes tamaños de clave
attempts = decoder.try_decrypt_xor(data, key_size=4)

for i, attempt in enumerate(attempts):
    print(f"Intento {i+1}: {attempt[:80]}")

# Intenta ROT13
rot_attempts = decoder.try_decrypt_rot(data)
```

### 4. Extraer información de datos binarios

```python
from core.protocol_registry import BinaryForensics

forensics = BinaryForensics()

# Buscar strings legibles
strings = forensics.find_possible_strings(data, min_length=4)
print(f"Strings encontrados: {strings}")

# Extraer strings terminados en null
null_terms = forensics.find_null_terminated_strings(data)
print(f"Null-terminated: {null_terms}")

# Buscar headers de formatos conocidos
formats = forensics.carve_known_formats(data)
print(f"Formatos: {formats}")  # {'PNG': [0], 'ZIP': [100, 200]}

# Estadísticas detalladas
stats = forensics.calculate_statistics(data)
print(f"Bytes únicos: {stats['unique_bytes']}")
print(f"Distribución: {stats['most_common']}")
```

---

## 🔧 Integración con Streams Capturados

### Analizar un SocketStream completo

```python
from core.stream_analyzer import StreamBinaryAnalyzer
from core.interceptor import FridaInterceptor

# Después de capturar con Frida
interceptor = FridaInterceptor(...)
interceptor.attach(pid=1234)

# Analizar un stream
analyzer = StreamBinaryAnalyzer()
analysis = analyzer.analyze_stream(stream)

# Reporte completo
report = analyzer.format_analysis_report(stream)
print(report)

# Exportar
with open("stream_analysis.txt", "w") as f:
    f.write(report)
```

---

## 🎯 Protocolos Personalizados

### Registrar un parser personalizado

```python
from core.protocol_registry import register_custom_protocol

def parse_myproto(data: bytes) -> dict:
    """Parser para mi protocolo personalizado."""
    if len(data) < 8:
        return {'error': 'datos insuficientes'}
    
    header = data[:4]
    length = int.from_bytes(data[4:8], 'little')
    payload = data[8:8+length]
    
    return {
        'header': header.hex(),
        'length': length,
        'payload': payload.hex(),
        'payload_text': payload.decode('utf-8', 'ignore')
    }

# Registrar el protocolo
register_custom_protocol(
    name='MyProtocol',
    signatures=[b'MYPR', b'MPR\x00'],
    parser=parse_myproto,
    description='Mi protocolo personalizado v1.0',
    priority=10  # Se prueba primero
)

# Usar
from core.protocol_registry import ProtocolRegistry
registry = ProtocolRegistry()

data = b'MYPR\x20\x00\x00\x00payload_data'
protocol = registry.detect_protocol(data)  # 'MyProtocol'
result = registry.parse_protocol('MyProtocol', data)
print(result)
```

---

## 🔍 Patrones Binarios Avanzados

```python
from core.protocol_registry import AdvancedBinaryPattern

# Definir un patrón de búsqueda
pattern = AdvancedBinaryPattern('FF ?? FF ?? FF', name='Patrón especial')

# Buscar en datos
data = b'\xFF\x00\xFF\x11\xFF\x22\xFF\x33'
offsets = pattern.matches(data)
print(f"Coincidencias en offsets: {offsets}")
```

---

## 📊 Casos de Uso Comunes

### 1. Datos Comprimidos
```python
# Captura datos y NO puedes leer:
data = b'\x78\x9c...'  # ¿Qué es esto?

decoder = BinaryDecoder()
analysis = decoder.analyze(data)

if analysis.compression_type == 'zlib':
    decompressed = decoder.try_decompress(data)
    print(decompressed)  # ¡Ahora legible!
```

### 2. Datos Encriptados (Cifrado simple)
```python
# Datos que parecen random:
data = b'\xAB\xCD\xEF\x12...'

attempts = decoder.try_decrypt_xor(data, key_size=1)
rot_attempts = decoder.try_decrypt_rot(data)

for attempt in attempts:
    if b'HTTP' in attempt or b'GET' in attempt:
        print("¡Encontrado!", attempt)
```

### 3. Formatos Mixtos
```python
data = captura_binaria_desconocida

forensics = BinaryForensics()

# Extrae todo lo posible
strings = forensics.find_possible_strings(data)
formats = forensics.carve_known_formats(data)
stats = forensics.calculate_statistics(data)

print(f"Strings: {strings}")
print(f"Formatos: {formats}")
print(f"Bytes únicos: {stats['unique_bytes']}")
```

---

## 🧪 Tests

Ejecutar la suite de tests:

```bash
py -3.11 tests/test_binary_decoder.py
```

Tests incluidos:
- Cálculo de entropía
- Detección de compresión (zlib, gzip, deflate)
- Descompresión
- Descifrado XOR
- Detección de patrones repetitivos
- Análisis binario completo
- Extracción de strings
- Carving de formatos
- Estadísticas
- Detección de protocolos
- Hexdump anotado
- Análisis de streams

---

## 📈 Flujo de Trabajo Recomendado

```
1. Capturar tráfico con Frida
   ↓
2. Identificar datos "extraños" o ilegibles
   ↓
3. Usar BinaryDecoder.analyze() → conocer el formato
   ↓
4. Si está comprimido → try_decompress()
   ↓
5. Si está cifrado → try_decrypt_xor() / try_decrypt_rot()
   ↓
6. Extraer información → BinaryForensics
   ↓
7. (Opcional) Crear parser personalizado → register_protocol()
   ↓
8. Exportar análisis → format_analysis_report()
```

---

## 🛠️ API Rápida

### BinaryDecoder

| Método | Propósito |
|--------|-----------|
| `analyze(data)` | Análisis completo y detección de formato |
| `try_decompress(data)` | Intenta descomprimir automáticamente |
| `try_decrypt_xor(data, key_size)` | Descifrado XOR |
| `try_decrypt_rot(data)` | Descifrado ROT |
| `parse_with_pattern(data, pattern)` | Parsear con struct pattern |
| `hex_dump_annotated(data, width, annotations)` | Hexdump legible |

### BinaryForensics

| Método | Propósito |
|--------|-----------|
| `find_possible_strings(data, min_length)` | Extrae strings ASCII |
| `find_null_terminated_strings(data)` | Extrae strings null-terminated |
| `carve_known_formats(data)` | Detecta PNG, ZIP, PDF, ELF, PE, etc. |
| `calculate_statistics(data)` | Estadísticas de bytes |

### StreamBinaryAnalyzer

| Método | Propósito |
|--------|-----------|
| `analyze_stream(stream)` | Analiza SocketStream completo (TX+RX) |
| `format_analysis_report(stream)` | Genera reporte legible |

---

## 📝 Ejemplo Completo

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.interceptor import FridaInterceptor
from core.stream_analyzer import StreamBinaryAnalyzer
from core.protocol_registry import BinaryForensics, register_custom_protocol

# 1. Capturar tráfico
interceptor = FridaInterceptor(
    on_event=lambda ev: None,
    on_status=print,
    on_log=print
)
interceptor.attach(name="target.exe", spawn=True)

# 2. Dejar que se ejecute
import time
time.sleep(30)

# 3. Analizar todos los streams
analyzer = StreamBinaryAnalyzer()
forensics = BinaryForensics()

for stream in interceptor.snapshot_streams():
    print(f"\n{'='*70}")
    print(f"Stream: {stream.fd} | {stream.proto} | {stream.peer}")
    print('='*70)
    
    # Reporte general
    report = analyzer.format_analysis_report(stream)
    print(report)
    
    # Forensics
    out_data = bytes(stream.out_data)
    in_data = bytes(stream.in_data)
    
    for direction, data in [('TX', out_data), ('RX', in_data)]:
        if data:
            strings = forensics.find_possible_strings(data)
            formats = forensics.carve_known_formats(data)
            
            if strings:
                print(f"\n{direction} Strings: {strings[:5]}")
            if formats:
                print(f"{direction} Formats: {formats}")

# 4. Exportar
interceptor.export_pcapng("capture.pcapng")
analyzer.export_full_report("analysis_report.txt")

interceptor.stop()
print("\nHecho!")
```

---

## ⚠️ Limitaciones y Notas

1. **XOR**: Funciona bien para cifrado simple de 1-16 bytes. Claves más grandes necesitan análisis específico.
2. **ROT**: Solo para texto ASCII.
3. **Compresión**: Detecta zlib, gzip, deflate. Otros formatos necesitan análisis personalizado.
4. **Formatos**: Busca headers conocidos, pero datos truncados pueden no detectarse.
5. **Entropía**: Es una heurística. Datos pueden tener alta entropía sin estar "encriptados".

---

## 🔗 Integración con UI

La UI de NetScope (`ui/main_window.py`) mostrará automáticamente en la pestaña de **Hex/ASCII**:
- Análisis de formato automático
- Botón "Descomprimir" si detecta compresión
- Botón "Descifrar" si detecta posible cifrado
- Strings extraídos
- Formatos conocidos

---

**¡Ahora NetScope puede manejar cualquier formato binario! 🎉**
