import unittest

from core.interceptor import NetEvent
from core.interceptor import FridaInterceptor
from core.value_scan import ValueScanner


def sample(sample_id, data, *, proto='TLS', event='tls_in', fd=7,
           direction='in', tag='DecryptMessage'):
    return NetEvent(
        ts=0,
        event=event,
        proto=proto,
        fd=fd,
        direction=direction,
        peer_ip=None,
        peer_port=None,
        data=data,
        truncated=False,
        tag=tag,
        capture_id=1,
        sample_id=sample_id,
    )


class ValueScannerTests(unittest.TestCase):
    def test_interceptor_retains_plaintext_and_raw_socket_payloads(self):
        interceptor = FridaInterceptor(
            on_event=lambda event: None,
            on_status=lambda status: None,
            on_log=lambda message: None,
        )
        interceptor._capturing = True
        interceptor._capture_id = 1
        interceptor._feed(sample(0, b'\x64\x00', proto='TCP', event='recv'))
        interceptor._feed(sample(1, b'\x64\x00', proto='TLS', event='tls_in'))

        captured = interceptor.snapshot_plaintext_events()
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].proto, 'TLS')
        self.assertEqual(interceptor.plaintext_sample_stats()[1], 2)
        scan_events = interceptor.snapshot_scan_events()
        self.assertEqual(len(scan_events), 2)
        self.assertEqual(interceptor.scan_sample_stats()[1], 4)

        interceptor.stop()
        self.assertEqual(interceptor.snapshot_scan_events(), scan_events)

    def test_scans_known_value_in_both_byte_orders(self):
        scanner = ValueScanner()
        candidates = scanner.scan(
            [sample(0, b'\x00\x2a\x00\x00\x00\x2a')],
            '42', 'uint16')
        self.assertEqual(
            {(item.offset, item.byte_order) for item in candidates},
            {(0, 'big-endian'), (1, 'little-endian'),
             (4, 'big-endian')},
        )

    def test_rescan_keeps_same_event_location_with_new_value(self):
        scanner = ValueScanner()
        first = sample(0, b'prefix\x64\x00suffix')
        candidates = scanner.scan([first], '100', 'uint16', 'little-endian')
        self.assertEqual([item.offset for item in candidates], [6])

        new_event = sample(1, b'prefix\xc8\x00suffix')
        candidates = scanner.rescan([new_event], '200')
        self.assertEqual([item.offset for item in candidates], [6])
        self.assertEqual(candidates[0].current_value, '200')

    def test_rescan_uses_only_new_payload_samples(self):
        scanner = ValueScanner()
        old = sample(0, b'\x64\x00')
        scanner.scan([old], '100', 'uint16', 'little-endian')

        candidates = scanner.rescan(
            [old, sample(1, b'\x64\x00')], '100')
        self.assertEqual(len(candidates), 1)
        self.assertEqual(scanner.last_rescan_sample_count, 1)

    def test_rescan_drops_when_new_value_is_not_at_candidate_offset(self):
        scanner = ValueScanner()
        scanner.scan(
            [sample(0, b'\x64\x00', tag='WinHttpSendRequest body')],
            '100', 'uint16', 'little-endian')
        candidates = scanner.rescan(
            [sample(1, b'\xc9\x00', tag='WinHttpSendRequest body')],
            '200')
        self.assertEqual(candidates, ())

    def test_scans_raw_socket_payloads_without_claiming_to_decrypt(self):
        scanner = ValueScanner()
        raw_socket = sample(0, b'\x64\x00', proto='TCP', event='recv')
        candidates = scanner.scan(
            [raw_socket], '100', 'uint16', 'little-endian')
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].proto, 'TCP')
        self.assertEqual(candidates[0].event, 'recv')

    def test_rescan_keeps_raw_socket_and_event_identity(self):
        scanner = ValueScanner()
        first = sample(
            0, b'\x64\x00', proto='TCP', event='recv', tag='')
        scanner.scan([first], '100', 'uint16', 'little-endian')
        updated = sample(
            1, b'\xc8\x00', proto='TCP', event='recv', tag='')
        candidates = scanner.rescan([updated], '200')
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].current_value, '200')

    def test_rejects_out_of_range_value(self):
        scanner = ValueScanner()
        with self.assertRaisesRegex(ValueError, 'no cabe'):
            scanner.scan(
                [sample(0, b'\x00\x00')],
                '70000', 'uint16', 'little-endian')

    def test_accepts_decimal_integer_with_leading_zero(self):
        scanner = ValueScanner()
        candidates = scanner.scan(
            [sample(0, b'\x0a\x00')],
            '010', 'uint16', 'little-endian')
        self.assertEqual(len(candidates), 1)

    def test_candidate_limit_marks_only_additional_matches_as_truncated(self):
        scanner = ValueScanner()
        scanner.MAX_CANDIDATES = 2
        candidates = scanner.scan(
            [sample(0, b'\x2a\x00\x2a\x00')],
            '42', 'uint16', 'little-endian')
        self.assertEqual(len(candidates), 2)
        self.assertFalse(scanner.candidates_truncated)

        candidates = scanner.scan(
            [sample(1, b'\x2a\x00\x2a\x00\x2a\x00')],
            '42', 'uint16', 'little-endian')
        self.assertEqual(len(candidates), 2)
        self.assertTrue(scanner.candidates_truncated)


if __name__ == '__main__':
    unittest.main()
