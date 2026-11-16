import unittest

from core.interceptor import FridaInterceptor, NetEvent


class CaptureStopTests(unittest.TestCase):
    def setUp(self):
        self.logs = []
        self.interceptor = FridaInterceptor(
            on_event=lambda event: None,
            on_status=lambda status: None,
            on_log=self.logs.append,
        )

    @staticmethod
    def make_event(capture_id):
        return NetEvent(
            ts=0,
            event='recv',
            proto='TCP',
            fd=123,
            direction='in',
            peer_ip='127.0.0.1',
            peer_port=443,
            data=b'payload',
            truncated=False,
            tag='test',
            capture_id=capture_id,
        )

    def test_late_event_cannot_change_retained_stream_after_stop(self):
        self.interceptor._capturing = True
        event = self.make_event(self.interceptor._capture_id)
        self.interceptor._feed(event)
        self.assertEqual(len(self.interceptor.snapshot_streams()), 1)

        self.interceptor.stop()
        self.interceptor._feed(event)

        streams = self.interceptor.snapshot_streams()
        self.assertEqual(len(streams), 1)
        self.assertEqual(bytes(streams[0].in_data), b'payload')

    def test_event_from_previous_capture_is_ignored(self):
        self.interceptor._capturing = True
        old_event = self.make_event(self.interceptor._capture_id)
        self.interceptor.stop()

        with self.interceptor._lock:
            self.interceptor.streams.clear()
        self.interceptor._capturing = True
        self.interceptor._feed(old_event)

        self.assertEqual(self.interceptor.snapshot_streams(), [])

    def test_stop_reports_detach_failure(self):
        class FakeSession:
            def detach(self):
                raise RuntimeError('detach failed')

        self.interceptor._session = FakeSession()
        self.interceptor.stop()

        self.assertTrue(any('detach failed' in message for message in self.logs))
        self.assertEqual(self.interceptor.snapshot_streams(), [])


if __name__ == '__main__':
    unittest.main()
