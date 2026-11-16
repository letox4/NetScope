import gzip
import unittest

from core.game_analysis import (
    analyze_game_streams,
    format_game_analysis_report,
)
from core.interceptor import SocketStream


class GameAnalysisTests(unittest.TestCase):
    def test_analyzes_framework_formats_and_report(self):
        stream = SocketStream(fd=12, proto='TCP', peer='127.0.0.1:8000')
        stream.append_out(b'{"TitleId":"TEST"}')
        stream.append_in(gzip.compress(b'game response'))

        results = analyze_game_streams([stream])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['framework'], 'PlayFab')
        self.assertEqual(results[0]['rx_compression'], 'gzip')
        self.assertGreater(results[0]['tx_bytes'], 0)

        report = format_game_analysis_report(results)
        self.assertIn('PlayFab', report)
        self.assertIn('Las detecciones', report)
        self.assertIn('compresión gzip', report)

    def test_empty_capture_has_helpful_report(self):
        self.assertIn(
            'No se capturaron streams',
            format_game_analysis_report([]),
        )


if __name__ == '__main__':
    unittest.main()
