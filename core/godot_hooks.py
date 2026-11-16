"""
Godot Engine Network Analysis Module

Supports:
- Godot MultiplayerAPI
- Godot RPC system
- Godot packet serialization
- Custom protocol detection
"""

import struct
from typing import Dict, Any, Optional, List


class GodotNetworkPatterns:
    """Godot Engine network traffic signatures."""
    
    # Godot RPC prefixes
    RPC_PATTERNS = {
        b'_rpc_': 'RPC Function',
        b'_rpc_unreliable_': 'Unreliable RPC',
        b'_rpc_reliable_': 'Reliable RPC',
        b'_rpc_multicast_': 'Multicast RPC',
        b'_rpc_master_': 'Master RPC',
        b'_rpc_puppet_': 'Puppet RPC',
    }
    
    # Godot node types
    NODE_PATTERNS = {
        b'Node': 'Base Node',
        b'Node2D': '2D Node',
        b'Node3D': '3D Node',
        b'CharacterBody': 'Character Body',
        b'RigidBody': 'Rigid Body',
        b'MultiplayerSynchronizer': 'Multiplayer Synchronizer',
        b'MultiplayerSpawner': 'Multiplayer Spawner',
    }
    
    # Godot packet markers
    PACKET_TYPES = {
        0x00: 'Handshake',
        0x01: 'Player List',
        0x02: 'RPC Call',
        0x03: 'Sync',
        0x04: 'Node Spawn',
        0x05: 'Node Delete',
        0x06: 'Node Configuration',
        0x07: 'Peer Disconnect',
    }
    
    # Godot protocol magic
    GODOT_MAGIC = b'GODOT'


class GodotNetworkAnalyzer:
    """Analyzes Godot Engine network traffic."""
    
    def __init__(self):
        self.patterns = GodotNetworkPatterns()
        self.detected_rpcs: List[Dict[str, Any]] = []
        self.detected_nodes: List[Dict[str, Any]] = []
    
    def detect_godot_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Detect if data is Godot network packet."""
        if len(data) < 10:
            return None
        
        # Check for Godot magic
        if self.patterns.GODOT_MAGIC in data[:20]:
            magic_idx = data.find(self.patterns.GODOT_MAGIC)
            return {
                'type': 'Godot Packet',
                'magic_offset': magic_idx,
                'size': len(data),
                'version_byte': f'0x{data[magic_idx + 5]:02x}' if magic_idx + 5 < len(data) else 'N/A'
            }
        
        return None
    
    def extract_rpcs(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract RPC calls from Godot packets."""
        rpcs = []
        
        for pattern, description in self.patterns.RPC_PATTERNS.items():
            if pattern in data:
                offset = 0
                while True:
                    idx = data.find(pattern, offset)
                    if idx == -1:
                        break
                    
                    # Extract function name after _rpc_ prefix
                    end_idx = idx + len(pattern)
                    func_end = data.find(b'\x00', end_idx)
                    if func_end == -1:
                        func_end = min(end_idx + 32, len(data))
                    
                    func_name = data[end_idx:func_end]
                    try:
                        func_name_str = func_name.decode('utf-8', errors='ignore').strip('\x00')
                    except:
                        func_name_str = func_name.hex()
                    
                    rpcs.append({
                        'rpc': pattern.decode('utf-8', errors='ignore'),
                        'description': description,
                        'function': func_name_str,
                        'offset': idx,
                    })
                    
                    offset = idx + 1
        
        self.detected_rpcs.extend(rpcs)
        return rpcs
    
    def extract_nodes(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract node types from Godot packets."""
        nodes = []
        
        # Sort by pattern length (longest first) to match more specific patterns first
        sorted_patterns = sorted(self.patterns.NODE_PATTERNS.items(), 
                                key=lambda x: len(x[0]), reverse=True)
        
        for pattern, description in sorted_patterns:
            if pattern in data:
                offset = 0
                while True:
                    idx = data.find(pattern, offset)
                    if idx == -1:
                        break
                    
                    nodes.append({
                        'node_type': pattern.decode('utf-8', errors='ignore'),
                        'description': description,
                        'offset': idx,
                    })
                    
                    offset = idx + 1
        
        self.detected_nodes.extend(nodes)
        return nodes
    
    def parse_packet_type(self, data: bytes) -> Dict[str, Any]:
        """Parse Godot packet type and structure."""
        if len(data) < 1:
            return {'packet_type': 'Unknown'}
        
        result = {'packet_type': 'Unknown'}
        
        # Try to extract packet type (usually in first few bytes)
        for i in range(min(4, len(data))):
            byte_val = data[i]
            if byte_val in self.patterns.PACKET_TYPES:
                result['packet_type'] = self.patterns.PACKET_TYPES[byte_val]
                result['packet_type_byte'] = f'0x{byte_val:02x}'
                result['packet_type_offset'] = i
                break
        
        # Look for embedded strings (node paths)
        strings = []
        current_str = b''
        for byte in data:
            if 32 <= byte < 127:  # Printable ASCII
                current_str += bytes([byte])
            else:
                if len(current_str) > 3:
                    try:
                        strings.append(current_str.decode('utf-8'))
                    except:
                        pass
                current_str = b''
        
        if strings:
            result['embedded_strings'] = strings[:5]  # First 5 strings
        
        return result
    
    def analyze_stream(self, data: bytes) -> Dict[str, Any]:
        """Complete analysis of Godot network stream."""
        result = {
            'engine': 'Godot',
            'is_godot_packet': False,
            'rpcs': [],
            'nodes': [],
            'packet_info': {},
            'summary': ''
        }
        
        # Check for Godot packet
        godot_packet = self.detect_godot_packet(data)
        if godot_packet:
            result['is_godot_packet'] = True
            result['packet_info'] = godot_packet
        
        # Extract RPCs
        rpcs = self.extract_rpcs(data)
        if rpcs:
            result['rpcs'] = rpcs[:5]
        
        # Extract nodes
        nodes = self.extract_nodes(data)
        if nodes:
            result['nodes'] = nodes[:5]
        
        # Parse packet type
        result['packet_info'].update(self.parse_packet_type(data))
        
        # Build summary
        parts = []
        if result['is_godot_packet']:
            parts.append("Godot Packet")
        if rpcs:
            parts.append(f"{len(rpcs)} RPC(s)")
        if nodes:
            parts.append(f"{len(nodes)} Node(s)")
        if 'packet_type' in result['packet_info']:
            parts.append(result['packet_info']['packet_type'])
        
        result['summary'] = ' | '.join(parts) if parts else 'Unknown Godot traffic'
        
        return result


def detect_godot_engine(data: bytes) -> bool:
    """Quick detection for Godot Engine traffic."""
    if len(data) < 10:
        return False
    
    # Check for Godot magic
    if GodotNetworkPatterns.GODOT_MAGIC in data:
        return True
    
    # Check for RPC patterns
    for pattern in GodotNetworkPatterns.RPC_PATTERNS.keys():
        if pattern in data[:200]:
            return True
    
    # Check for node patterns
    for pattern in GodotNetworkPatterns.NODE_PATTERNS.keys():
        if pattern in data[:300]:
            return True
    
    return False
