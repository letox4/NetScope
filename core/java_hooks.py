"""
Java/Minecraft Network Analysis Module

Supports:
- Minecraft protocol (Java Edition)
- Custom Java serialization
- RMI protocol patterns
- Generic Java networking
"""

import struct
from typing import Dict, Any, Optional, List


class JavaNetworkPatterns:
    """Java and Minecraft network traffic signatures."""
    
    # Minecraft Java protocol packets
    MINECRAFT_PACKETS = {
        b'\x00': 'Disconnect',
        b'\x01': 'Encryption Request',
        b'\x02': 'Login Success',
        b'\x03': 'Set Compression',
        b'\x04': 'Login Plugin Request',
        b'\x05': 'Spawn Player',
        b'\x06': 'Spawn Entity',
        b'\x07': 'Block Update',
        b'\x08': 'Player Position',
        b'\x09': 'Player Rotation',
        b'\x0a': 'Player Movement',
    }
    
    # Java serialization magic bytes
    JAVA_SERIAL_MAGIC = b'\xac\xed'  # Java serialization magic
    RMI_MAGIC = b'\x4a\x52\x4d\x49'  # JRMI (Java RMI)
    
    # Minecraft handshake
    MINECRAFT_HANDSHAKE = b'Minecraft'
    
    # Common Java class names
    JAVA_CLASSES = {
        b'java/lang/String': 'Java String',
        b'java/util/HashMap': 'HashMap',
        b'java/util/ArrayList': 'ArrayList',
        b'java/io/Serializable': 'Serializable',
        b'net/minecraft': 'Minecraft Class',
        b'com/mojang': 'Mojang Class',
    }
    
    # Protocol signatures
    PROTOCOL_SIGS = {
        b'QUERY': 'Query Protocol',
        b'STATUS': 'Status Protocol',
        b'LOGIN': 'Login Protocol',
        b'PLAY': 'Play State',
    }


class JavaGameAnalyzer:
    """Analyzes Java and Minecraft network traffic."""
    
    def __init__(self):
        self.patterns = JavaNetworkPatterns()
        self.detected_packets: List[Dict[str, Any]] = []
        self.detected_classes: List[Dict[str, Any]] = []
    
    def detect_minecraft_protocol(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Detect Minecraft Java protocol."""
        if len(data) < 5:
            return None
        
        result = None
        
        # Check Minecraft handshake
        if self.patterns.MINECRAFT_HANDSHAKE in data[:20]:
            result = {
                'type': 'Minecraft Java',
                'protocol': 'Minecraft Handshake',
                'version': 'Java Edition',
                'game': 'Minecraft'
            }
        
        # Check for protocol state
        for sig, description in self.patterns.PROTOCOL_SIGS.items():
            if sig in data[:50]:
                if result is None:
                    result = {'protocol_state': description}
                else:
                    result['protocol_state'] = description
                break
        
        return result
    
    def detect_java_serialization(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Detect Java object serialization."""
        if len(data) < 2:
            return None
        
        # Check Java serialization magic
        if data[:2] == self.patterns.JAVA_SERIAL_MAGIC:
            version = struct.unpack('>H', data[2:4])[0] if len(data) >= 4 else 0
            return {
                'type': 'Java Serialization',
                'magic': data[:2].hex(),
                'stream_version': version
            }
        
        # Check RMI
        if data[:4] == self.patterns.RMI_MAGIC:
            return {
                'type': 'Java RMI',
                'magic': data[:4].hex()
            }
        
        return None
    
    def extract_java_classes(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract Java class references."""
        classes = []
        
        for pattern, description in self.patterns.JAVA_CLASSES.items():
            if pattern in data:
                offset = 0
                while True:
                    idx = data.find(pattern, offset)
                    if idx == -1:
                        break
                    
                    classes.append({
                        'class': pattern.decode('utf-8', errors='ignore'),
                        'description': description,
                        'offset': idx,
                    })
                    
                    offset = idx + 1
        
        self.detected_classes.extend(classes)
        return classes
    
    def parse_varint(self, data: bytes, offset: int = 0) -> tuple[int, int]:
        """Parse Minecraft varint (variable-length integer)."""
        result = 0
        shift = 0
        
        while offset < len(data):
            byte = data[offset]
            result |= (byte & 0x7F) << shift
            offset += 1
            
            if (byte & 0x80) == 0:
                return result, offset
            
            shift += 7
            if shift > 35:  # Max 5 bytes
                return 0, offset
        
        return result, offset
    
    def extract_minecraft_packets(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract Minecraft packet types."""
        packets = []
        
        # Try to parse as Minecraft protocol
        try:
            offset = 0
            packet_count = 0
            
            while offset < len(data) and packet_count < 10:
                # Try to read packet ID (varint)
                if offset >= len(data):
                    break
                
                packet_id, next_offset = self.parse_varint(data, offset)
                
                # Look up packet type
                packet_type = 'Unknown'
                for sig, desc in self.patterns.MINECRAFT_PACKETS.items():
                    if sig[0] == packet_id:
                        packet_type = desc
                        break
                
                packets.append({
                    'packet_id': f'0x{packet_id:02x}',
                    'type': packet_type,
                    'offset': offset,
                    'size': next_offset - offset
                })
                
                offset = next_offset + min(32, len(data) - next_offset)  # Skip ahead
                packet_count += 1
        except:
            pass
        
        self.detected_packets.extend(packets)
        return packets
    
    def analyze_stream(self, data: bytes) -> Dict[str, Any]:
        """Complete analysis of Java/Minecraft network stream."""
        result = {
            'engine': 'Java',
            'game': 'Unknown',
            'is_minecraft': False,
            'is_java_serialized': False,
            'packets': [],
            'classes': [],
            'protocol_info': {},
            'summary': ''
        }
        
        # Check for Minecraft
        minecraft_proto = self.detect_minecraft_protocol(data)
        if minecraft_proto:
            result['is_minecraft'] = True
            result['game'] = 'Minecraft'
            result['protocol_info'].update(minecraft_proto)
        
        # Check for Java serialization
        java_serial = self.detect_java_serialization(data)
        if java_serial:
            result['is_java_serialized'] = True
            result['protocol_info'].update(java_serial)
        
        # Extract classes
        classes = self.extract_java_classes(data)
        if classes:
            result['classes'] = classes[:5]
        
        # Extract packets if Minecraft
        if result['is_minecraft']:
            packets = self.extract_minecraft_packets(data)
            if packets:
                result['packets'] = packets
        
        # Build summary
        parts = []
        if result['is_minecraft']:
            parts.append('Minecraft (Java)')
        elif result['is_java_serialized']:
            parts.append('Java Serialized')
        
        if result['classes']:
            parts.append(f"{len(result['classes'])} Class(es)")
        if result['packets']:
            parts.append(f"{len(result['packets'])} Packet(s)")
        
        result['summary'] = ' | '.join(parts) if parts else 'Unknown Java traffic'
        
        return result


def detect_java_game(data: bytes) -> bool:
    """Quick detection for Java game traffic."""
    if len(data) < 5:
        return False
    
    # Check Minecraft
    if JavaNetworkPatterns.MINECRAFT_HANDSHAKE in data[:20]:
        return True
    
    # Check Java serialization
    if data[:2] == JavaNetworkPatterns.JAVA_SERIAL_MAGIC:
        return True
    
    # Check RMI
    if data[:4] == JavaNetworkPatterns.RMI_MAGIC:
        return True
    
    # Check for Java class patterns
    for pattern in JavaNetworkPatterns.JAVA_CLASSES.keys():
        if pattern in data[:500]:
            return True
    
    return False
