"""
Tests para motores adicionales: Unreal, Godot, Java/Minecraft
"""

import unittest
from core.unreal_hooks import UnrealNetworkAnalyzer, detect_unreal_engine
from core.godot_hooks import GodotNetworkAnalyzer, detect_godot_engine
from core.java_hooks import JavaGameAnalyzer, detect_java_game
from core.advanced_decoders import AdvancedDecoderExtension, AdvancedCompressionFormats, AdvancedEncryption


class TestUnrealEngine(unittest.TestCase):
    """Test Unreal Engine network analysis."""
    
    def setUp(self):
        self.analyzer = UnrealNetworkAnalyzer()
    
    def test_detect_ue_packet(self):
        """Test UE packet detection."""
        # UE4 magic
        ue4_data = b'\x00\x14' + b'some data'
        result = self.analyzer.detect_ue_packet(ue4_data)
        self.assertIsNotNone(result)
        self.assertEqual(result['version'], 'UE4')
    
    def test_detect_rpc(self):
        """Test RPC extraction."""
        data = b'some prefix ServerRPC function call data'
        rpcs = self.analyzer.extract_rpcs(data)
        self.assertTrue(len(rpcs) > 0)
        self.assertEqual(rpcs[0]['rpc'], 'ServerRPC')
    
    def test_detect_actor(self):
        """Test actor class detection."""
        data = b'APawn actor class data'
        actors = self.analyzer.extract_actors(data)
        self.assertTrue(len(actors) > 0)
        self.assertEqual(actors[0]['actor_class'], 'APawn')
    
    def test_full_analysis(self):
        """Test complete stream analysis."""
        data = b'\x00\x14ServerRPCAPawn'
        result = self.analyzer.analyze_stream(data)
        self.assertTrue(result['is_ue_packet'])
        self.assertTrue(len(result['summary']) > 0)
    
    def test_quick_detection(self):
        """Test quick Unreal detection."""
        ue_data = b'\x00\x14' + b'data'
        self.assertTrue(detect_unreal_engine(ue_data))
        
        non_ue = b'random data'
        self.assertFalse(detect_unreal_engine(non_ue))


class TestGodotEngine(unittest.TestCase):
    """Test Godot Engine network analysis."""
    
    def setUp(self):
        self.analyzer = GodotNetworkAnalyzer()
    
    def test_detect_godot_packet(self):
        """Test Godot packet detection."""
        godot_data = b'GODOT' + b'\x01' + b'some data'
        result = self.analyzer.detect_godot_packet(godot_data)
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'Godot Packet')
    
    def test_extract_rpc(self):
        """Test Godot RPC extraction."""
        data = b'prefix _rpc_ function call'
        rpcs = self.analyzer.extract_rpcs(data)
        self.assertTrue(len(rpcs) > 0)
    
    def test_extract_node(self):
        """Test node type extraction."""
        data = b'Node2D actor node data'
        nodes = self.analyzer.extract_nodes(data)
        self.assertTrue(len(nodes) > 0)
        self.assertEqual(nodes[0]['node_type'], 'Node2D')
    
    def test_full_analysis(self):
        """Test complete Godot stream analysis."""
        data = b'GODOT_rpc_Node2D'
        result = self.analyzer.analyze_stream(data)
        self.assertIsNotNone(result)
        self.assertTrue(len(result['summary']) > 0)
    
    def test_quick_detection(self):
        """Test quick Godot detection."""
        godot_data = b'GODOT data'
        self.assertTrue(detect_godot_engine(godot_data))


class TestJavaGames(unittest.TestCase):
    """Test Java/Minecraft network analysis."""
    
    def setUp(self):
        self.analyzer = JavaGameAnalyzer()
    
    def test_detect_minecraft(self):
        """Test Minecraft protocol detection."""
        mc_data = b'Minecraft protocol data'
        result = self.analyzer.detect_minecraft_protocol(mc_data)
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'Minecraft Java')
    
    def test_detect_java_serialization(self):
        """Test Java serialization detection."""
        java_data = b'\xac\xed' + b'\x00\x05' + b'data'
        result = self.analyzer.detect_java_serialization(java_data)
        self.assertIsNotNone(result)
        self.assertIn('Java Serialization', result['type'])
    
    def test_extract_java_classes(self):
        """Test Java class extraction."""
        data = b'java/lang/String data'
        classes = self.analyzer.extract_java_classes(data)
        self.assertTrue(len(classes) > 0)
    
    def test_varint_parsing(self):
        """Test Minecraft varint parsing."""
        # Encode 300 as varint: 0xAC, 0x02
        varint_data = b'\xAC\x02'
        result, offset = self.analyzer.parse_varint(varint_data)
        self.assertEqual(result, 300)
        self.assertEqual(offset, 2)
    
    def test_full_analysis(self):
        """Test complete Java stream analysis."""
        data = b'Minecraft java/lang/String'
        result = self.analyzer.analyze_stream(data)
        self.assertIsNotNone(result)
        self.assertTrue(len(result['summary']) > 0)
    
    def test_quick_detection(self):
        """Test quick Java detection."""
        java_data = b'Minecraft protocol'
        self.assertTrue(detect_java_game(java_data))


class TestAdvancedCompression(unittest.TestCase):
    """Test advanced compression format detection."""
    
    def test_detect_zstandard(self):
        """Test Zstandard magic detection."""
        zstd_data = b'\x28\xB5\x2F\xFD' + b'data'
        self.assertTrue(AdvancedCompressionFormats.detect_zstandard(zstd_data))
    
    def test_detect_lz4(self):
        """Test LZ4 magic detection."""
        lz4_data = b'\x04\x22\x4D\x18' + b'data'
        self.assertTrue(AdvancedCompressionFormats.detect_lz4(lz4_data))
    
    def test_brotli_detection(self):
        """Test Brotli detection."""
        # Brotli patterns
        brotli_data = b'\xCE\xB2' + b'data'
        self.assertTrue(AdvancedCompressionFormats.detect_brotli(brotli_data))


class TestAdvancedEncryption(unittest.TestCase):
    """Test advanced encryption format detection."""
    
    def test_base64_detection(self):
        """Test Base64 detection."""
        b64_data = b'SGVsbG8gV29ybGQhIFRoaXMgaXMgQmFzZTY0IGVuY29kaW5n'
        self.assertTrue(AdvancedEncryption.looks_like_base64(b64_data))
    
    def test_base64_decode(self):
        """Test Base64 decoding."""
        b64_data = b'SGVsbG8gV29ybGQ='  # "Hello World"
        result = AdvancedEncryption.try_decode_base64(b64_data)
        self.assertIsNotNone(result)
        self.assertEqual(result, b'Hello World')
    
    def test_caesar_detection(self):
        """Test Caesar cipher detection."""
        # Shift by 3: ABC -> DEF
        caesar_data = bytes([i + 3 for i in b'Hello World'])
        results = AdvancedEncryption.try_decrypt_caesar_advanced(caesar_data)
        self.assertTrue(len(results) > 0)


class TestAdvancedDecoderExtension(unittest.TestCase):
    """Test advanced decoder extension."""
    
    def setUp(self):
        self.decoder = AdvancedDecoderExtension()
    
    def test_analyze_advanced(self):
        """Test advanced analysis."""
        # Test with Zstandard magic
        zstd_data = b'\x28\xB5\x2F\xFD' + b'data'
        result = self.decoder.analyze_advanced(zstd_data)
        self.assertIsNotNone(result)
    
    def test_multiple_format_detection(self):
        """Test detection of multiple formats."""
        # Base64 encoded data
        b64_data = b'SGVsbG8gV29ybGQhIFRoaXMgaXMgQmFzZTY0IGVuY29kaW5n'
        result = self.decoder.analyze_advanced(b64_data)
        self.assertIn('Base64', result['additional_formats'])


if __name__ == '__main__':
    unittest.main(argv=[''], verbosity=2, exit=False)
