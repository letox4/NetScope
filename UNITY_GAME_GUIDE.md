# NetScope para Juegos Unity - Guía Completa

## 🎮 Introducción

Esta guía te muestra cómo usar NetScope para interceptar, analizar y modificar en vivo el tráfico de red de un juego basado en Unity.

**NetScope puede:**
- ✅ Capturar TODOS los sockets TCP/UDP del juego (sin modificar el código)
- ✅ Descomprimir datos automáticamente (zlib, gzip)
- ✅ Descifrar cifrado simple (XOR)
- ✅ Parsear JSON, Protobuf, MessagePack, binario
- ✅ Detectar frameworks (Mirror, Netcode, Photon, PlayFab, Firebase)
- ✅ Modificar payloads en tiempo real
- ✅ Exportar análisis completo

---

## 📋 Requisitos

```bash
py -3.11 -m pip install -r requirements.txt
```

**Importante:** Ejecutar como **Administrador** (Frida requiere permisos elevados)

---

## 🚀 Uso Básico

### 1. Capturar tráfico del juego

```bash
py -3.11 main.py
```

Luego en la GUI:
1. Pulsa **⟳ Refrescar** procesos
2. Selecciona tu juego (ej: "Game.exe")
3. Marca **Spawn** si quieres lanzarlo hookeado
4. Pulsa **● Attach**
5. Genera tráfico en el juego (login, movimiento, ataque, etc.)
6. Observa los **Streams** en la tabla

### 2. Analizar un stream

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.interceptor import FridaInterceptor
from core.unity_hooks import UnityGameNetworkSniffer

# 1. Capturar
interceptor = FridaInterceptor(
    on_event=lambda ev: print(f"Event: {ev.event}"),
    on_status=print,
    on_log=print
)

# Attach al juego
interceptor.attach(name="Game.exe", spawn=False)

# 2. Dejar que capture tráfico
import time
time.sleep(30)

# 3. Analizar todos los streams
sniffer = UnityGameNetworkSniffer()

for stream in interceptor.snapshot_streams():
    result = sniffer.process_stream(stream)
    print(f"\nStream: {stream.fd}")
    print(f"Framework detectado: {result['framework']}")
    print(f"Mensajes: {len(result['messages'])}")
    print(f"Bytes TX/RX: {result['statistics']['tx_bytes']}/{result['statistics']['rx_bytes']}")

# 4. Generar reporte
report = sniffer.generate_report()
with open("unity_analysis.txt", "w") as f:
    f.write(report)

interceptor.stop()
```

---

## 🔍 Análisis Detallado

### Detectar framework de networking

```python
from core.unity_hooks import UnityMessagePatterns

# Ejemplo con Mirror (Framework de red muy popular)
data = stream_data  # Datos capturados

framework = UnityMessagePatterns.detect_framework(data)
print(f"Framework: {framework}")

# Posibles resultados:
# - "Mirror" → Usando Mirror (muy común)
# - "Netcode" → Netcode for GameObjects (recomendado por Unity)
# - "Photon" → Photon Cloud
# - "PlayFab" → Backend PlayFab
# - "Firebase" → Firebase Realtime DB
# - "JSON (custom)" → JSON personalizado
# - "Compressed" → Datos comprimidos
```

### Parsear mensajes JSON

```python
from core.unity_hooks import UnityNetworkAnalyzer
import json

analyzer = UnityNetworkAnalyzer()

# Datos capturados (típicamente JSON)
data = b'{"type":"player_move","pos":{"x":10,"y":20,"z":5},"playerId":123}'

encoding = analyzer._detect_encoding(data)
print(f"Encoding: {encoding}")  # "json"

parsed = analyzer._parse_message(data, encoding)
print(f"Parsed: {parsed}")
# Output: {'type': 'player_move', 'pos': {'x': 10, 'y': 20, 'z': 5}, 'playerId': 123}
```

### Parsear Protobuf (sin .proto file)

```python
# Datos Protobuf capturados
data = b'\x08\x96\x01\x12\x04test\x1d\x00\x00\xa0\x3f'

analyzer = UnityNetworkAnalyzer()
parsed = analyzer._parse_message(data, 'protobuf')

print(parsed)
# Output: {'fields': [
#     {'field': 1, 'type': 'varint', 'value': 150},
#     {'field': 2, 'type': 'bytes/string', 'length': 4, 'value': '...', 'text': 'test'},
#     {'field': 3, 'type': 'fixed32', 'value': 1.25}
# ]}
```

### Descomprimir datos

```python
from core.binary_decoder import BinaryDecoder

decoder = BinaryDecoder()

# Si los datos están comprimidos
compressed_data = stream.out_data  # Datos capturados

decompressed = decoder.try_decompress(compressed_data)
if decompressed:
    print(f"Decomprimido: {decompressed[:100]}")
else:
    print("No es zlib/gzip/deflate")
```

---

## 🎯 Casos de Uso Comunes

### Caso 1: Juego con JSON

```python
import json
from core.unity_hooks import UnityGameNetworkSniffer
from core.interceptor import FridaInterceptor

interceptor = FridaInterceptor(...)
interceptor.attach(name="Game.exe")

# ... capturar tráfico ...

sniffer = UnityGameNetworkSniffer()
for stream in interceptor.snapshot_streams():
    result = sniffer.process_stream(stream)
    
    # Buscar mensajes de login
    for msg in result['messages']:
        if 'login' in str(msg).lower():
            print(f"Login detected: {msg}")
```

### Caso 2: Juego con compresión

```python
from core.binary_decoder import BinaryDecoder

decoder = BinaryDecoder()

for stream in interceptor.snapshot_streams():
    out_data = bytes(stream.out_data)
    
    # Analizar
    analysis = decoder.analyze(out_data)
    
    if analysis.compression_type:
        print(f"Datos comprimidos ({analysis.compression_type})")
        decompressed = decoder.try_decompress(out_data)
        print(f"Contenido: {decompressed}")
```

### Caso 3: Juego con cifrado simple

```python
from core.binary_decoder import BinaryDecoder

decoder = BinaryDecoder()

data = stream.out_data

# Intentar XOR
xor_attempts = decoder.try_decrypt_xor(data, key_size=1)

for attempt in xor_attempts:
    if b'player' in attempt or b'login' in attempt:
        print(f"¡Encontrado descifrado!\n{attempt}")
        break
```

### Caso 4: Modificar datos en tiempo real

```python
# Ejemplo: Cambiar nombre de jugador antes de enviar

interceptor.set_patch_rules([{
    'hex_match': 'player_name'.encode().hex(),
    'hex_replace': 'hacker_name'.encode().hex(),  # ¡MISMO TAMAÑO!
}])

# El patch se aplica ANTES de que Winsock envíe
```

---

## 📊 Formato de Salida

### Reporte de Análisis

```
================================================================================
Unity Game Network Analysis Report
================================================================================

Session: 1_127.0.0.1:12345
--------------------------------------------------------------------------------
Message 1:
[SEND] 127.0.0.1:12345 | json
  Size: 51 bytes
  Parsed: {'type': 'player_spawn', 'id': 1, 'pos': [0, 0, 0]}...

Message 2:
[RECV] 127.0.0.1:12345 | json
  Size: 31 bytes
  Parsed: {'type': 'ack', 'status': 'ok'}...
```

---

## 🔐 Consideraciones de Seguridad

1. **No modificar datos críticos** (auth tokens, checksums)
2. **El juego puede detectar cambios** y desconectar
3. **Algunos juegos tienen anti-cheat** que detectarán Frida
4. **Usar solo con permisos explícitos** (tu propio servidor, debugging, etc.)

---

## 🛠️ API Rápida

### UnityGameNetworkSniffer

```python
sniffer = UnityGameNetworkSniffer()

# Procesar un stream capturado
result = sniffer.process_stream(stream)
# result = {
#     'session': str,
#     'peer': str,
#     'proto': 'TCP'|'UDP',
#     'framework': str (detectado),
#     'messages': [List of messages],
#     'statistics': {
#         'total_bytes': int,
#         'tx_bytes': int,
#         'rx_bytes': int,
#         'entropy_out': float,
#         'entropy_in': float
#     }
# }

# Generar reporte
report = sniffer.generate_report()
```

### UnityNetworkAnalyzer

```python
analyzer = UnityNetworkAnalyzer()

# Analizar un mensaje
msg = analyzer.analyze_message(data, direction, peer)
# msg.encoding_type: 'json', 'protobuf', 'msgpack', 'text', 'binary', etc.
# msg.parsed: dict con datos parseados
# msg.compressed: bool
# msg.encrypted: bool

# Resumen del mensaje
summary = analyzer.get_message_summary(msg)
print(summary)
```

### UnityMessagePatterns

```python
# Detectar framework de networking
framework = UnityMessagePatterns.detect_framework(data)

# Posibles valores:
# 'Mirror', 'Netcode', 'Photon', 'PlayFab', 'Firebase', 
# 'JSON (custom)', 'Compressed (zlib/gzip)'
```

---

## 📝 Ejemplo Completo: Sniffing de Juego

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sniffer de juego Unity."""

import sys
import time
from core.interceptor import FridaInterceptor
from core.unity_hooks import UnityGameNetworkSniffer
from core.stream_analyzer import StreamBinaryAnalyzer

def main():
    # 1. Iniciar captura
    print("[*] Iniciando captura de tráfico...")
    
    interceptor = FridaInterceptor(
        on_event=lambda ev: None,  # Silencioso
        on_status=lambda s: print(f"[status] {s}"),
        on_log=lambda s: print(f"[log] {s}")
    )
    
    # Buscar el juego
    print("[*] Buscando procesos...")
    processes = interceptor.list_processes()
    game = next((p for p in processes if 'game' in p['name'].lower()), None)
    
    if not game:
        print("[-] Juego no encontrado")
        return
    
    print(f"[+] Juego encontrado: {game['name']} (PID={game['pid']})")
    
    # 2. Attach
    interceptor.attach(pid=game['pid'])
    print("[+] Attach exitoso, capturando tráfico...")
    
    # 3. Capturar durante 60 segundos
    time.sleep(60)
    
    # 4. Analizar
    print("\n[*] Analizando streams capturados...")
    
    sniffer = UnityGameNetworkSniffer()
    binary_analyzer = StreamBinaryAnalyzer()
    
    for stream in interceptor.snapshot_streams():
        print(f"\n{'='*70}")
        print(f"Stream FD={stream.fd} | {stream.proto} | {stream.peer}")
        print('='*70)
        
        # Análisis binario
        report = binary_analyzer.format_analysis_report(stream)
        print(report[:500] + "...")
        
        # Análisis Unity
        result = sniffer.process_stream(stream)
        print(f"\nFramework: {result['framework']}")
        print(f"Mensajes: {len(result['messages'])}")
        print(f"Estadísticas: {result['statistics']}")
    
    # 5. Exportar
    print("\n[*] Exportando reportes...")
    with open("unity_analysis.txt", "w") as f:
        f.write(sniffer.generate_report())
    
    interceptor.export_pcapng("capture.pcapng")
    
    interceptor.stop()
    print("\n[+] Análisis completado. Ver:")
    print("  - unity_analysis.txt")
    print("  - capture.pcapng (abrir en Wireshark)")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Cancelado por usuario")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
```

---

## 🧪 Tests

Ejecutar tests de Unity:

```bash
py -3.11 tests\test_unity_hooks.py
```

Ejecutar todos los tests:

```bash
py -3.11 tests\test_binary_decoder.py
py -3.11 tests\test_unity_hooks.py
py -3.11 tests\test_interceptor.py
```

---

## ⚠️ Troubleshooting

| Problema | Solución |
|----------|----------|
| "Permission denied" | Ejecutar como Administrador |
| "Frida not found" | `pip install frida frida-tools` |
| "No streams capturados" | Generar tráfico en el juego (login, move, etc.) |
| "Datos ilegibles" | Ver si está comprimido o cifrado |
| "Juego se desconecta" | Reducir modificaciones, el anti-cheat detectó cambios |

---

## 📚 Lecturas Recomendadas

- [Frida Documentation](https://frida.re/)
- [Mirror Networking](https://mirror-networking.com/)
- [Netcode for GameObjects](https://docs.unity.com/netcode/current/intro/)
- [Protocol Buffers](https://developers.google.com/protocol-buffers)
- [Wireshark](https://www.wireshark.org/)

---

**¡Ahora estás listo para analizar juegos Unity! 🎮**
