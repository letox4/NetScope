"""
Unreal Engine Network Analysis Module

Supports:
- Unreal Replication Graph
- UE4/UE5 Network serialization
- Custom RPC detection
- Actor spawn/destroy patterns
"""

import re
import struct
from typing import Dict, Any, Optional, List, Tuple


class UnrealNetworkPatterns:
    """Unreal Engine network traffic signatures."""
    
    # Common Unreal RPC names
    RPC_PATTERNS = {
        b'ServerRPC': 'Server RPC Call',
        b'ClientRPC': 'Client RPC Call',
        b'MulticastRPC': 'Multicast RPC',
        b'ReliableRPC': 'Reliable RPC',
        b'UnreliableRPC': 'Unreliable RPC',
        b'ACK': 'Acknowledgment',
        b'Hello': 'Connection Handshake',
        b'Challenge': 'Challenge/Response',
    }
    
    # UE4/UE5 specific headers
    UE_HEADER_MAGIC = [
        b'\x00\x14',  # UE4 packet magic
        b'\x00\x15',  # UE5 packet magic
    ]
    
    # Actor class names
    ACTOR_PATTERNS = {
        b'APawn': 'Pawn Actor',
        b'ACharacter': 'Character Actor',
        b'AActor': 'Base Actor',
        b'APlayerController': 'Player Controller',
        b'AGameState': 'Game State',
        b'APlayerState': 'Player State',
        b'AWorldSettings': 'World Settings',
    }
    
    # Network serialization markers
    SERIALIZATION_MARKERS = {
        0x00: 'End of data',
        0x01: 'Delta serialization',
        0x02: 'Full replication',
        0x03: 'Property update',
        0x04: 'Function call',
        0x05: 'Actor spawn',
        0x06: 'Actor destroy',
    }


class UnrealNetworkAnalyzer:
    """Analyzes Unreal Engine network traffic."""
    
    def __init__(self):
        self.patterns = UnrealNetworkPatterns()
        self.detected_rpcs: List[Dict[str, Any]] = []
        self.detected_actors: List[Dict[str, Any]] = []
        
    def detect_ue_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Detect if data is UE4/UE5 network packet."""
        if len(data) < 4:
            return None
            
        # Check magic bytes
        for magic in self.patterns.UE_HEADER_MAGIC:
            if data.startswith(magic):
                return {
                    'type': 'UE Network Packet',
                    'version': 'UE5' if magic == b'\x00\x15' else 'UE4',
                    'magic': magic.hex(),
                    'size': len(data)
                }
        
        return None
    
    def extract_rpcs(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract RPC calls from packet data."""
        rpcs = []
        
        for pattern, description in self.patterns.RPC_PATTERNS.items():
            if pattern in data:
                # Find all occurrences
                offset = 0
                while True:
                    idx = data.find(pattern, offset)
                    if idx == -1:
                        break
                    
                    # Extract context
                    start = max(0, idx - 10)
                    end = min(len(data), idx + len(pattern) + 10)
                    context = data[start:end]
                    
                    rpcs.append({
                        'rpc': pattern.decode('utf-8', errors='ignore'),
                        'description': description,
                        'offset': idx,
                        'context': context.hex()[:40] + '...'
                    })
                    
                    offset = idx + 1
        
        self.detected_rpcs.extend(rpcs)
        return rpcs
    
    def extract_actors(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract actor class references."""
        actors = []
        
        for pattern, description in self.patterns.ACTOR_PATTERNS.items():
            if pattern in data:
                offset = 0
                while True:
                    idx = data.find(pattern, offset)
                    if idx == -1:
                        break
                    
                    # Extract context
                    start = max(0, idx - 5)
                    end = min(len(data), idx + len(pattern) + 5)
                    context = data[start:end]
                    
                    actors.append({
                        'actor_class': pattern.decode('utf-8', errors='ignore'),
                        'description': description,
                        'offset': idx,
                        'context': context.hex()[:40] + '...'
                    })
                    
                    offset = idx + 1
        
        self.detected_actors.extend(actors)
        return actors
    
    def parse_serialization(self, data: bytes) -> Dict[str, Any]:
        """Parse UE network serialization format."""
        if len(data) < 2:
            return {}
        
        result = {
            'serialization_type': 'Unknown',
            'fields': []
        }
        
        # Check first byte
        if len(data) > 0 and data[0] in self.patterns.SERIALIZATION_MARKERS:
            result['serialization_type'] = self.patterns.SERIALIZATION_MARKERS[data[0]]
        
        # Simple field extraction (UE uses variable-length encoding)
        offset = 1
        field_count = 0
        while offset < len(data) and field_count < 10:
            # Try to read a field marker
            if offset >= len(data):
                break
            
            marker = data[offset]
            if marker < 0x80:  # Likely a field marker
                result['fields'].append({
                    'index': field_count,
                    'marker': f'0x{marker:02x}',
                    'offset': offset
                })
            offset += 1
            field_count += 1
        
        return result
    
    def analyze_stream(self, data: bytes) -> Dict[str, Any]:
        """Complete analysis of Unreal network stream."""
        result = {
            'engine': 'Unreal',
            'is_ue_packet': False,
            'rpcs': [],
            'actors': [],
            'serialization': {},
            'summary': ''
        }
        
        # Check for UE packet
        ue_packet = self.detect_ue_packet(data)
        if ue_packet:
            result['is_ue_packet'] = True
            result['packet_info'] = ue_packet
        
        # Extract RPCs
        rpcs = self.extract_rpcs(data)
        if rpcs:
            result['rpcs'] = rpcs[:5]  # Limit to 5 for summary
        
        # Extract actors
        actors = self.extract_actors(data)
        if actors:
            result['actors'] = actors[:5]  # Limit to 5 for summary
        
        # Parse serialization
        if len(data) > 10:
            result['serialization'] = self.parse_serialization(data)
        
        # Build summary
        parts = []
        if result['is_ue_packet']:
            parts.append(f"UE Packet ({result['packet_info']['version']})")
        if rpcs:
            parts.append(f"{len(rpcs)} RPC(s)")
        if actors:
            parts.append(f"{len(actors)} Actor(s)")
        
        result['summary'] = ' | '.join(parts) if parts else 'Unknown Unreal traffic'
        
        return result


def detect_unreal_engine(data: bytes) -> bool:
    """Quick detection for Unreal Engine traffic."""
    if len(data) < 2:
        return False
    
    # Check for UE magic bytes
    if data[:2] in UnrealNetworkPatterns.UE_HEADER_MAGIC:
        return True
    
    # Check for common RPC patterns (lower threshold)
    for pattern in UnrealNetworkPatterns.RPC_PATTERNS.keys():
        if pattern in data:
            return True
    
    # Check for actor patterns
    for pattern in UnrealNetworkPatterns.ACTOR_PATTERNS.keys():
        if pattern in data:
            return True
    
    return False
