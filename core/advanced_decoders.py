"""
Advanced Compression and Encryption Module

Extends binary_decoder with:
- Brotli compression
- Zstandard (Zstd) compression
- LZ4 compression
- Base64 encoding
- Caesar cipher variations
- Vigenere cipher
"""

import base64
import string
from typing import Optional, Tuple, Dict, Any


class AdvancedCompressionFormats:
    """Support for advanced compression formats."""
    
    @staticmethod
    def try_decompress_brotli(data: bytes) -> Optional[bytes]:
        """Try to decompress Brotli data."""
        try:
            import brotli
            return brotli.decompress(data)
        except ImportError:
            # Brotli not installed - return None
            return None
        except Exception:
            return None
    
    @staticmethod
    def try_decompress_zstandard(data: bytes) -> Optional[bytes]:
        """Try to decompress Zstandard (Zstd) data."""
        try:
            import zstandard as zstd
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data)
        except ImportError:
            return None
        except Exception:
            return None
    
    @staticmethod
    def try_decompress_lz4(data: bytes) -> Optional[bytes]:
        """Try to decompress LZ4 data."""
        try:
            import lz4.frame
            return lz4.frame.decompress(data)
        except ImportError:
            return None
        except Exception:
            return None
    
    @staticmethod
    def detect_brotli(data: bytes) -> bool:
        """Detect if data might be Brotli compressed."""
        if len(data) < 4:
            return False
        
        # Brotli can have various headers, but common patterns:
        # Check for METABLOCK structure (0xCE, 0xB2, 0xCF, 0x81 for framed)
        if data[:2] in [b'\xCE\xB2', b'\xCF\x81']:
            return True
        
        return False
    
    @staticmethod
    def detect_zstandard(data: bytes) -> bool:
        """Detect Zstandard compressed data."""
        if len(data) < 4:
            return False
        
        # Zstd magic number
        if data[:4] == b'\x28\xB5\x2F\xFD':
            return True
        
        return False
    
    @staticmethod
    def detect_lz4(data: bytes) -> bool:
        """Detect LZ4 compressed data."""
        if len(data) < 4:
            return False
        
        # LZ4 magic number
        if data[:4] == b'\x04\x22\x4D\x18':
            return True
        
        return False


class AdvancedEncryption:
    """Support for additional encryption and encoding formats."""
    
    @staticmethod
    def try_decode_base64(data: bytes) -> Optional[bytes]:
        """Try to decode Base64 encoded data."""
        try:
            # Check if data looks like Base64
            if not AdvancedEncryption.looks_like_base64(data):
                return None
            
            return base64.b64decode(data, validate=True)
        except Exception:
            return None
    
    @staticmethod
    def looks_like_base64(data: bytes) -> bool:
        """Check if data looks like Base64 encoding."""
        # Base64 characters
        b64_chars = set(string.ascii_letters + string.digits + '+/=')
        
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            return False
        
        # At least 10 chars and mostly Base64
        if len(text) < 10:
            return False
        
        b64_text = set(text.replace('\n', '').replace('\r', '').replace('\t', ''))
        if b64_text - b64_chars:
            return False
        
        # Check length is multiple of 4 (with padding)
        clean_text = text.replace('\n', '').replace('\r', '')
        return len(clean_text) % 4 == 0
    
    @staticmethod
    def try_decrypt_caesar_advanced(data: bytes) -> Dict[int, bytes]:
        """Try all Caesar cipher variations."""
        results = {}
        
        for shift in range(256):
            decrypted = bytes([(b - shift) % 256 for b in data])
            
            # Check if result looks like text
            try:
                text = decrypted.decode('utf-8', errors='ignore')
                if sum(1 for c in text if c.isprintable()) > len(text) * 0.7:
                    results[shift] = decrypted
            except:
                pass
        
        return results
    
    @staticmethod
    def try_decrypt_vigenere(data: bytes, key_length: int = 8) -> Dict[str, Any]:
        """Try simple Vigenere cipher attack."""
        results = []
        
        # Try common key lengths
        for klen in range(2, min(key_length + 1, 16)):
            # Frequency analysis on first byte of each key position
            for key_start in range(256):
                try:
                    # Build key carefully to avoid overflow
                    key = bytes([((key_start + i) % 256) for i in range(klen)])
                    
                    decrypted = bytes([
                        (data[i] - key[i % klen]) % 256
                        for i in range(len(data))
                    ])
                    
                    # Check if looks like text
                    text = decrypted.decode('utf-8', errors='ignore')
                    printable_ratio = sum(1 for c in text if c.isprintable()) / len(text) if text else 0
                    
                    if printable_ratio > 0.7:
                        results.append({
                            'key_length': klen,
                            'key_sample': key.hex(),
                            'printable_ratio': printable_ratio,
                            'decrypted_sample': text[:50]
                        })
                except:
                    pass
        
        return {
            'algorithm': 'Vigenere',
            'attempts': len(results),
            'candidates': results[:3]  # Top 3
        }
    
    @staticmethod
    def try_decrypt_substitution(data: bytes) -> Optional[Dict[str, Any]]:
        """Detect potential substitution cipher."""
        if len(data) < 20:
            return None
        
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            text = data.decode('latin-1', errors='ignore')
        
        # Frequency analysis
        freq = {}
        for char in text.lower():
            if char.isalpha():
                freq[char] = freq.get(char, 0) + 1
        
        if not freq:
            return None
        
        # Check if frequency distribution suggests substitution
        sorted_freq = sorted(freq.values(), reverse=True)
        max_freq = sorted_freq[0] if sorted_freq else 0
        
        return {
            'algorithm': 'Substitution Cipher (suspected)',
            'unique_chars': len(freq),
            'top_frequencies': dict(sorted(freq.items(), key=lambda x: x[1], reverse=True)[:5]),
            'entropy': AdvancedEncryption.calculate_char_entropy(freq)
        }
    
    @staticmethod
    def calculate_char_entropy(freq_dict: Dict) -> float:
        """Calculate Shannon entropy of character frequencies."""
        import math
        total = sum(freq_dict.values())
        entropy = 0
        for count in freq_dict.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy


class AdvancedDecoderExtension:
    """Extension to BinaryDecoder for advanced formats."""
    
    def __init__(self):
        self.compression = AdvancedCompressionFormats()
        self.encryption = AdvancedEncryption()
    
    def analyze_advanced(self, data: bytes) -> Dict[str, Any]:
        """Analyze data for advanced compression/encryption."""
        result = {
            'advanced_compression': None,
            'advanced_encryption': None,
            'additional_formats': []
        }
        
        # Try advanced compression
        if self.compression.detect_brotli(data):
            decompressed = self.compression.try_decompress_brotli(data)
            if decompressed:
                result['advanced_compression'] = {
                    'format': 'Brotli',
                    'original_size': len(data),
                    'decompressed_size': len(decompressed),
                    'ratio': f"{(1 - len(decompressed)/len(data))*100:.1f}%"
                }
                result['additional_formats'].append('Brotli')
        
        if self.compression.detect_zstandard(data):
            decompressed = self.compression.try_decompress_zstandard(data)
            if decompressed:
                result['advanced_compression'] = {
                    'format': 'Zstandard',
                    'original_size': len(data),
                    'decompressed_size': len(decompressed),
                    'ratio': f"{(1 - len(decompressed)/len(data))*100:.1f}%"
                }
                result['additional_formats'].append('Zstandard')
        
        if self.compression.detect_lz4(data):
            decompressed = self.compression.try_decompress_lz4(data)
            if decompressed:
                result['advanced_compression'] = {
                    'format': 'LZ4',
                    'original_size': len(data),
                    'decompressed_size': len(decompressed),
                    'ratio': f"{(1 - len(decompressed)/len(data))*100:.1f}%"
                }
                result['additional_formats'].append('LZ4')
        
        # Try advanced encoding/encryption
        b64_decoded = self.encryption.try_decode_base64(data)
        if b64_decoded:
            result['advanced_encryption'] = {
                'format': 'Base64',
                'original_size': len(data),
                'decoded_size': len(b64_decoded)
            }
            result['additional_formats'].append('Base64')
        
        # Try Caesar advanced
        caesar_results = self.encryption.try_decrypt_caesar_advanced(data)
        if caesar_results:
            result['additional_formats'].append('Caesar (Advanced)')
        
        # Try Vigenere
        if len(data) > 30:
            vigenere_result = self.encryption.try_decrypt_vigenere(data)
            if vigenere_result['candidates']:
                result['additional_formats'].append('Vigenere')
        
        # Try substitution detection
        subst = self.encryption.try_decrypt_substitution(data)
        if subst:
            result['additional_formats'].append('Substitution')
        
        return result
