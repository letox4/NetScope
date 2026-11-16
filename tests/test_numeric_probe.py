import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.numeric_probe import FridaNumericProbe


class FakeScript:
    def __init__(self, source):
        self.source = source
        self.loaded = False
        self.unloaded = False
        self.callback = None

    def on(self, _event, callback):
        self.callback = callback

    def load(self):
        self.loaded = True

    def unload(self):
        self.unloaded = True


class FakeSession:
    def __init__(self):
        self.scripts = []
        self.detached = False

    def create_script(self, source):
        script = FakeScript(source)
        self.scripts.append(script)
        return script

    def detach(self):
        self.detached = True


class NumericProbeTests(unittest.TestCase):
    def setUp(self):
        self.session = FakeSession()
        self.device = type('FakeDevice', (), {
            'attach': lambda _device, pid: self._attach(pid),
        })()
        self.attach_pids = []

    def _attach(self, pid):
        self.attach_pids.append(pid)
        return self.session

    def test_native_probe_injects_configuration_and_stops_cleanly(self):
        logs = []
        config = {
            'mode': 'native',
            'native': {
                'moduleName': 'sample.dll',
                'exportName': 'ReadValue',
                'argumentIndex': 1,
            },
        }
        source_path = (
            Path(__file__).resolve().parents[1]
            / 'agent'
            / 'observe_numeric.js'
        )
        probe = FridaNumericProbe(logs.append)

        with patch(
                'core.numeric_probe.frida.get_local_device',
                return_value=self.device):
            probe.start(4321, config, str(source_path))

            self.assertTrue(probe.is_running)
            self.assertEqual(self.attach_pids, [4321])
            self.assertIn(
                'globalThis.NETSCOPE_CONFIG = ' +
                '{"mode": "native", "native": {"moduleName": "sample.dll", '
                '"exportName": "ReadValue", "argumentIndex": 1}};',
                self.session.scripts[0].source,
            )
            self.assertTrue(self.session.scripts[0].loaded)
            self.session.scripts[0].callback({
                'type': 'log',
                'payload': '[NetScope sonda] onLeave: valor de retorno = 5',
            }, None)
            self.assertIn(
                '[NetScope sonda] onLeave: valor de retorno = 5', logs)

            probe.stop()

        self.assertFalse(probe.is_running)
        self.assertTrue(self.session.scripts[0].unloaded)
        self.assertTrue(self.session.detached)
        self.assertIn('[i] Sonda detenida y desconectada.', logs)

    def test_il2cpp_probe_loads_bridge_before_observer(self):
        logs = []
        config = {
            'mode': 'il2cpp',
            'il2cpp': {
                'assemblyName': 'Assembly-CSharp',
                'namespaceName': '',
                'className': 'DiceController',
                'methodName': 'GetResult',
                'argumentCount': 0,
                'argumentIndex': 0,
            },
        }
        source_path = (
            Path(__file__).resolve().parents[1]
            / 'agent'
            / 'observe_numeric.js'
        )
        probe = FridaNumericProbe(logs.append)
        with tempfile.TemporaryDirectory() as temp_dir:
            bridge_path = Path(temp_dir) / 'bridge.js'
            bridge_path.write_text('globalThis.Il2Cpp = {};', encoding='utf-8')
            with patch(
                    'core.numeric_probe.frida.get_local_device',
                    return_value=self.device):
                probe.start(
                    4321, config, str(source_path), str(bridge_path))
                # El bridge y la sonda se concatenan en UN script: los
                # realms de Frida son independientes por script, por lo
                # que globalThis.Il2Cpp del bridge debe ser visible aquí.
                self.assertEqual(len(self.session.scripts), 1)
                combined = self.session.scripts[0].source
                self.assertTrue(combined.startswith('globalThis.Il2Cpp'))
                self.assertIn('globalThis.NETSCOPE_CONFIG', combined)
                self.assertIn('attachIl2CppHook', combined)
                probe.stop()

        self.assertTrue(all(script.unloaded for script in self.session.scripts))

    def test_il2cpp_requires_bridge_before_attaching(self):
        probe = FridaNumericProbe(lambda _message: None)
        with patch('core.numeric_probe.frida.get_local_device') as get_device:
            with self.assertRaisesRegex(ValueError, 'Selecciona el bundle'):
                probe.start(4321, {'mode': 'il2cpp'}, 'probe.js')
        get_device.assert_not_called()

    def test_structured_diagnostic_events_are_forwarded(self):
        events = []
        logs = []
        probe = FridaNumericProbe(logs.append, events.append)

        probe._on_message({
            'type': 'send',
            'payload': {
                'event': 'function_observation',
                'domain': 'native_function',
                'subject': 'sample.dll!Read',
                'phase': 'entry',
                'values': {'arg0': 7},
            },
        }, None)
        probe._on_message({
            'type': 'send',
            'payload': {'event': 'ready', 'tag': 'existing log message'},
        }, None)

        self.assertEqual(events[0]['values'], {'arg0': 7})
        self.assertIn('existing log message', logs[0])


if __name__ == '__main__':
    unittest.main()
