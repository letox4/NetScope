import unittest
from types import SimpleNamespace
import gzip
import zlib

from loopback_telemetry import (
    MAX_DECOMPRESSED_BYTES,
    LoopbackMonitor,
    PayloadTransitions,
    decode_payload,
    is_loopback_peer,
    matching_processes,
)


class LoopbackTelemetryTests(unittest.TestCase):
    def test_loopback_filter_accepts_ipv4_and_ipv6(self):
        self.assertTrue(is_loopback_peer({"ip": "127.0.0.1"}))
        self.assertTrue(is_loopback_peer({"ip": "::1"}))
        self.assertTrue(is_loopback_peer({"ip": "::ffff:127.0.0.1"}))
        self.assertFalse(is_loopback_peer({"ip": "192.168.1.10"}))
        self.assertFalse(is_loopback_peer({"ip": "unknown"}))

    def test_process_matching_is_exact_and_case_insensitive(self):
        processes = [
            SimpleNamespace(pid=1, name="App.exe"),
            SimpleNamespace(pid=2, name="app-helper.exe"),
        ]
        self.assertEqual(matching_processes(processes, "app.EXE"), [processes[0]])

    def test_duplicate_payloads_are_suppressed_until_state_changes(self):
        transitions = PayloadTransitions()
        first = transitions.changed(
            1, 10, "TCP", "in", "127.0.0.1", b"one")
        duplicate = transitions.changed(
            1, 10, "TCP", "in", "127.0.0.1", b"one")
        second = transitions.changed(
            1, 10, "TCP", "in", "127.0.0.1", b"two")

        self.assertIsNotNone(first)
        self.assertIsNone(duplicate)
        self.assertNotEqual(first, second)
        self.assertIsNotNone(transitions.changed(
            1, 10, "TCP", "in", "127.0.0.1", b"one"))

    def test_closing_socket_resets_transition_state(self):
        transitions = PayloadTransitions()
        transitions.changed(1, 10, "TCP", "in", "127.0.0.1", b"one")
        transitions.clear_fd(1, 10)
        self.assertIsNotNone(transitions.changed(
            1, 10, "TCP", "in", "127.0.0.1", b"one"))

    def test_decode_payload_handles_compression_and_json(self):
        payload = zlib.compress(b'{"ok":true}')
        decoded = decode_payload(payload)
        self.assertIn("Descomprimido (zlib", decoded)
        self.assertIn('"ok": true', decoded)
        gzip_decoded = decode_payload(gzip.compress(b'{"ok":true}'))
        self.assertIn("Descomprimido (gzip", gzip_decoded)

    def test_decode_payload_detects_raw_deflate(self):
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        payload = compressor.compress(b"hello") + compressor.flush()
        decoded = decode_payload(payload)
        self.assertIn("Descomprimido (deflate", decoded)
        self.assertIn("hello", decoded)

    def test_decode_payload_detects_packet_framing(self):
        length_prefixed = b"\x00\x03one\x00\x03two"
        self.assertIn(
            "16-bit big-endian length", decode_payload(length_prefixed))
        self.assertIn("Paquetes (NUL, 2)", decode_payload(b"one\x00two"))
        self.assertIn(
            "Paquetes (newline, 2)", decode_payload(b"one\ntwo\n"))

    def test_decode_payload_limits_decompression_and_display(self):
        compressed = zlib.compress(b"A" * (MAX_DECOMPRESSED_BYTES + 1))
        self.assertIn("supera el límite", decode_payload(compressed))
        self.assertIn("vista truncada", decode_payload(b"A" * 3000))

    def test_monitor_decodes_only_when_payload_hash_changes(self):
        monitor = LoopbackMonitor.__new__(LoopbackMonitor)
        monitor.transitions = PayloadTransitions()
        messages = []
        monitor._log = messages.append
        message = {
            "type": "send",
            "payload": {
                "event": "payload",
                "peer": {"ip": "127.0.0.1", "port": 1234},
                "proto": "TCP",
                "direction": "in",
                "fd": 10,
                "length": 11,
            },
        }

        monitor._on_message(1, message, b'{"ok":true}')
        monitor._on_message(1, message, b'{"ok":true}')

        self.assertEqual(len(messages), 1)
        self.assertIn("JSON:", messages[0])


if __name__ == "__main__":
    unittest.main()
