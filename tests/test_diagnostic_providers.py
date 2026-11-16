import unittest
from unittest.mock import patch

from core.diagnostic_providers import FridaFunctionProvider
from core.diagnostics import (
    DiagnosticDomain,
    DiagnosticObservation,
    DiagnosticProfile,
    DiagnosticProviderRegistry,
    DiagnosticTarget,
)


class FakeProbe:
    def __init__(self):
        self.on_event = None
        self.started = None

    def start(self, *args):
        self.started = args

    def stop(self):
        pass


class DiagnosticProviderTests(unittest.TestCase):
    def test_frida_provider_declares_only_supported_capabilities(self):
        provider = FridaFunctionProvider(FakeProbe())
        availability = provider.availability(DiagnosticTarget(
            10, 'sample.exe', runtime_markers=('unity_il2cpp',)))
        capability_ids = {
            capability.capability_id
            for capability in availability.capabilities
        }
        self.assertIn('frida.native_function_values', capability_ids)
        self.assertIn('frida.process_profile', capability_ids)
        self.assertIn('frida.il2cpp_function_values', capability_ids)
        self.assertFalse(any(
            capability.domain in (
                DiagnosticDomain.NATIVE_MEMORY,
                DiagnosticDomain.MANAGED_MEMORY,
            )
            for capability in availability.capabilities
        ))
        self.assertFalse(availability.verified)

    def test_frida_provider_reuses_probe_and_normalizes_events(self):
        probe = FakeProbe()
        provider = FridaFunctionProvider(probe)
        target = DiagnosticTarget(10, 'sample.exe')
        request = {
            'config': {'mode': 'native'},
            'script_path': 'observe_numeric.js',
            'bridge_path': None,
        }
        events = []
        session = provider.start(target, request, events.append)

        self.assertIs(session, probe)
        self.assertEqual(
            probe.started,
            (10, {'mode': 'native'}, 'observe_numeric.js', None))
        probe.on_event({
            'event': 'diagnostic_profile',
            'architecture': 'x64',
            'pointer_size': 8,
            'runtime_markers': ['electron_or_node'],
        })
        probe.on_event({
            'event': 'function_observation',
            'domain': 'native_function',
            'subject': 'sample.dll!Read',
            'phase': 'entry',
            'values': {'arg0': 4},
        })

        self.assertIsInstance(events[0], DiagnosticProfile)
        self.assertEqual(events[0].architecture, 'x64')
        self.assertIsInstance(events[1], DiagnosticObservation)
        self.assertEqual(events[1].domain, DiagnosticDomain.NATIVE_FUNCTION)
        self.assertEqual(events[1].values, {'arg0': 4})

    def test_entry_points_register_external_providers(self):
        class EntryPoint:
            name = 'external'

            @staticmethod
            def load():
                return lambda: type('Provider', (), {
                    'provider_id': 'external.provider',
                    'availability': lambda _self, _target: None,
                    'start': lambda _self, _target, _request, _callback: None,
                })()

        registry = DiagnosticProviderRegistry()
        with patch(
                'core.diagnostics.entry_points',
                return_value=[EntryPoint()]) as load_entry_points:
            self.assertEqual(registry.load_entry_points(), ('external',))
        load_entry_points.assert_called_once_with(
            group='netscope.diagnostic_providers')
        self.assertEqual(
            registry.get('external.provider').provider_id,
            'external.provider')

    def test_entry_point_failures_are_reported(self):
        class BrokenEntryPoint:
            name = 'broken'

            @staticmethod
            def load():
                raise ImportError('missing adapter dependency')

        registry = DiagnosticProviderRegistry()
        with patch(
                'core.diagnostics.entry_points',
                return_value=[BrokenEntryPoint()]):
            self.assertEqual(registry.load_entry_points(), ())
        self.assertIn('missing adapter dependency', registry.load_errors[0])


if __name__ == '__main__':
    unittest.main()
