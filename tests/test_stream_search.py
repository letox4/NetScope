"""Pruebas de búsqueda incremental en streams."""
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core.interceptor import SocketStream
from core.stream_search import StreamSearchIndex


class StreamSearchTests(unittest.TestCase):
    def setUp(self):
        self.index = StreamSearchIndex()
        self.stream = SocketStream(fd=42, proto='TCP')

    def test_text_search_is_case_insensitive_and_crosses_events(self):
        self.stream.append_out(b'GET /Ne')
        self.assertEqual(self.index.update([self.stream], 'netscope'), set())
        self.stream.append_out(b'tScope HTTP/1.1')
        self.assertEqual(self.index.update([self.stream], 'netscope'), {42})

    def test_hex_search_matches_exact_bytes(self):
        self.stream.append_in(b'\x00\xAB\xff')
        self.assertEqual(self.index.update([self.stream], 'hex:00 AB FF'), {42})
        self.assertEqual(self.index.update([self.stream], 'hex:00 ab fe'), set())

    def test_numeric_value_is_searched_as_text(self):
        self.stream.append_in(b'value=12')
        self.assertEqual(self.index.update([self.stream], '12'), {42})

    def test_recomputes_when_old_data_is_discarded(self):
        self.stream.MAX_DIR_BYTES = 8
        self.stream.append_out(b'needle!')
        self.assertEqual(self.index.update([self.stream], 'needle'), {42})
        self.stream.append_out(b'12345678')
        self.assertEqual(self.index.update([self.stream], 'needle'), set())

    def test_fd_reuse_does_not_keep_previous_result(self):
        self.stream.append_out(b'needle')
        self.assertEqual(self.index.update([self.stream], 'needle'), {42})
        replacement = SocketStream(fd=42, proto='TCP')
        replacement.append_out(b'other')
        self.assertEqual(self.index.update([replacement], 'needle'), set())

    def test_empty_query_clears_index(self):
        self.stream.append_out(b'needle')
        self.assertEqual(self.index.update([self.stream], 'needle'), {42})
        self.assertEqual(self.index.update([self.stream], '  '), set())


if __name__ == '__main__':
    unittest.main()
