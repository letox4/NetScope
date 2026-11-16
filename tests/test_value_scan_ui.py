import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6 import QtWidgets

from core.interceptor import NetEvent
from core.diagnostics import DiagnosticObservation
from ui.main_window import NetScopeGUI


class ValueScanUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    @staticmethod
    def _sample(sample_id, data, *, proto='TLS', event='tls_in',
                tag='DecryptMessage'):
        return NetEvent(
            ts=0,
            event=event,
            proto=proto,
            fd=7,
            direction='in',
            peer_ip=None,
            peer_port=None,
            data=data,
            truncated=False,
            tag=tag,
            capture_id=1,
            sample_id=sample_id,
        )

    def test_function_observation_history_tracks_changes_and_exports(self):
        with patch.object(NetScopeGUI, 'refresh_processes'):
            window = NetScopeGUI()
        try:
            window._handle_diagnostic_event(DiagnosticObservation(
                1.0, 'frida.function_observation', 'native_function', 4321,
                'sample.dll!Read', 'entry', {'arg0': 10}))
            window._handle_diagnostic_event(DiagnosticObservation(
                2.0, 'frida.function_observation', 'native_function', 4321,
                'sample.dll!Read', 'entry', {'arg0': 12}))

            self.assertEqual(window.probe_history_table.rowCount(), 2)
            self.assertEqual(
                window.observation_history.records[-1].changed_values,
                ('arg0',))
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'history.json'
                with patch(
                        'ui.main_window.QtWidgets.QFileDialog.getSaveFileName',
                        return_value=(str(path), 'JSON (*.json)')):
                    window._export_probe_history()
                payload = json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(len(payload['observations']), 2)
            self.assertEqual(
                payload['observations'][1]['changed_values'], ['arg0'])
        finally:
            window._frida_worker.stop()
            window._frida_thread.quit()
            window._frida_thread.wait(2000)

    def test_ui_scans_then_filters_new_raw_socket_sample(self):
        events = [self._sample(
            0, b'prefix\x64\x00suffix',
            proto='TCP', event='recv', tag='')]
        with patch.object(NetScopeGUI, 'refresh_processes'):
            window = NetScopeGUI()
        try:
            window.interceptor.snapshot_scan_events = (
                lambda after_sample_id=-1: tuple(
                    event for event in events
                    if event.sample_id > after_sample_id
                )
            )
            window.interceptor.scan_sample_stats = (
                lambda: (len(events), sum(len(event.data) for event in events), 0)
            )

            window.value_scan_input.setText('100')
            window._scan_initial_value()
            self.assertEqual(window.value_scan_table.rowCount(), 1)
            self.assertTrue(window.btn_value_rescan.isEnabled())

            events.append(self._sample(
                1, b'prefix\xc8\x00suffix',
                proto='TCP', event='recv', tag=''))
            window.value_scan_input.setText('200')
            window._rescan_value()
            self.assertEqual(window.value_scan_table.rowCount(), 1)
            self.assertEqual(window.value_scan_table.item(0, 3).text(), 'recv')
            self.assertEqual(window.value_scan_table.item(0, 7).text(), '200')
        finally:
            window._frida_worker.stop()
            window._frida_thread.quit()
            window._frida_thread.wait(2000)

    def test_patch_rule_ui_validates_equal_length_hex(self):
        with patch.object(NetScopeGUI, 'refresh_processes'):
            window = NetScopeGUI()
        try:
            window.patch_match_input.setText('AA bb')
            window.patch_replace_input.setText('cc DD')
            window._add_patch_rule()
            self.assertEqual(window.patch_rule_table.rowCount(), 1)
            self.assertEqual(window.patch_rule_table.item(0, 0).text(), 'AABB')
            self.assertEqual(window.patch_rule_table.item(0, 1).text(), 'CCDD')

            window.patch_match_input.setText('AA BB')
            window.patch_replace_input.setText('CC')
            window._add_patch_rule()
            self.assertEqual(window.patch_rule_table.rowCount(), 1)
            self.assertIn('misma longitud', window.patch_status.text())
        finally:
            window._frida_worker.stop()
            window._frida_thread.quit()
            window._frida_thread.wait(2000)

    def test_applying_rules_keeps_rewrite_off_until_requested(self):
        with patch.object(NetScopeGUI, 'refresh_processes'):
            window = NetScopeGUI()
        try:
            rules = ({'hex_match': 'aabb', 'hex_replace': 'ccdd'},)
            window._patch_rules = [dict(rules[0])]
            window._patch_attached = True
            with patch.object(
                    window.interceptor, 'set_rewrite_enabled') as set_enabled:
                with patch.object(
                        window.interceptor, 'set_patch_rules',
                        return_value=1) as set_rules:
                    window._install_patch_rules(rules, False)
                    self.app.processEvents()

            self.assertEqual(set_rules.call_args.args[0], rules)
            self.assertEqual(
                [call.args[0] for call in set_enabled.call_args_list],
                [False, False],
            )
            self.assertTrue(window._patch_ready)
            self.assertFalse(window.patch_enable_checkbox.isChecked())
        finally:
            window._frida_worker.stop()
            window._frida_thread.quit()
            window._frida_thread.wait(2000)

    def test_quick_analysis_runs_until_stop_then_shows_report(self):
        with patch.object(NetScopeGUI, 'refresh_processes'):
            window = NetScopeGUI()
        try:
            window._quick_analysis_pending = True
            window._quick_analysis_duration = 5
            with patch.object(
                    window.interceptor, 'set_rewrite_enabled'):
                with patch.object(
                        window.interceptor, 'set_patch_rules',
                        return_value=0):
                    with patch.object(
                            window, '_run_async',
                            side_effect=lambda fn, *args: fn(*args)):
                        window._handle_status('Hooks activos')
                        self.assertTrue(window._quick_analysis_running)
                        self.assertTrue(window._quick_analysis_timer.isActive())
                        window.stop()
                        self.app.processEvents()

            self.assertFalse(window._quick_analysis_running)
            self.assertFalse(window._quick_analysis_processing)
            self.assertIn('No se capturaron streams', window._quick_report_text)
            self.assertIn('Análisis completado', window.quick_progress.format())
        finally:
            window._quick_analysis_timer.stop()
            window._frida_worker.stop()
            window._frida_thread.quit()
            window._frida_thread.wait(2000)

    def test_closing_window_does_not_open_export_dialog(self):
        with patch.object(NetScopeGUI, 'refresh_processes'):
            window = NetScopeGUI()
        with patch.object(QtWidgets.QFileDialog, 'getSaveFileName') as dialog:
            window.close()
        dialog.assert_not_called()

    def test_quick_start_requires_an_explicit_process_selection(self):
        with patch.object(NetScopeGUI, 'refresh_processes'):
            window = NetScopeGUI()
        try:
            window._set_processes([])
            self.assertIn('No se encontraron', window.process_hint.text())
            window._set_processes([(1234, 'Game.exe')])
            self.assertIn('1 aplicación abierta', window.process_hint.text())
            self.assertFalse(window.btn_quick_start.isEnabled())
            window.proc_view.selectRow(0)
            self.assertTrue(window.btn_quick_start.isEnabled())
            self.assertIn('PID 1234', window.quick_target_label.text())
        finally:
            window._frida_worker.stop()
            window._frida_thread.quit()
            window._frida_thread.wait(2000)

    def test_stream_list_explains_empty_state_and_local_filter(self):
        with patch.object(NetScopeGUI, 'refresh_processes'):
            window = NetScopeGUI()
        try:
            window.interceptor.snapshot_streams = lambda: ()
            window._on_tick()
            self.assertIn('Inicia un análisis', window.stream_hint.text())

            window.localhost_chk.setChecked(True)
            window._on_tick()
            self.assertIn('no hay conexiones locales', window.stream_hint.text())
        finally:
            window._frida_worker.stop()
            window._frida_thread.quit()
            window._frida_thread.wait(2000)

    def test_numeric_probe_can_start_from_selected_process_in_gui(self):
        with patch.object(NetScopeGUI, 'refresh_processes'):
            window = NetScopeGUI()
        try:
            window._set_processes([(4321, 'Sample.exe')])
            window.proc_view.selectRow(0)
            window.probe_module_edit.setText('sample.dll')
            window.probe_export_edit.setText('ReadValue')

            class ImmediateThread:
                def __init__(self, target, daemon):
                    self.target = target

                def start(self):
                    self.target()

            with patch('ui.main_window.threading.Thread', ImmediateThread):
                with patch.object(window.numeric_probe, 'start') as start:
                    window._start_numeric_probe()

            self.assertEqual(start.call_args.args[0], 4321)
            self.assertEqual(start.call_args.args[1]['mode'], 'native')
            self.assertEqual(
                start.call_args.args[1]['native']['exportName'], 'ReadValue')
            self.assertEqual(start.call_args.args[3], None)
            self.assertIn('Sonda activa', window.numeric_probe_status.text())
        finally:
            window._frida_worker.stop()
            window._frida_thread.quit()
            window._frida_thread.wait(2000)

    def test_attach_error_restores_quick_analysis_controls(self):
        with patch.object(NetScopeGUI, 'refresh_processes'):
            window = NetScopeGUI()
        try:
            window._attach_in_progress = True
            window._quick_analysis_pending = True
            window.btn_attach.setEnabled(False)
            window.btn_stop.setEnabled(True)
            with patch.object(window, '_run_async'):
                window._handle_status('Error')
            self.assertTrue(window.btn_attach.isEnabled())
            self.assertFalse(window.btn_stop.isEnabled())
            self.assertFalse(window._quick_analysis_pending)
            self.assertIn('No se pudo adjuntar', window.quick_countdown.text())
        finally:
            window._frida_worker.stop()
            window._frida_thread.quit()
            window._frida_thread.wait(2000)


if __name__ == '__main__':
    unittest.main()
