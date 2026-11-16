import json
import tempfile
import unittest
from pathlib import Path

from core.diagnostics import (
    DiagnosticCapability,
    DiagnosticObservation,
    DiagnosticProviderRegistry,
    DiagnosticTarget,
    ObservationHistory,
    ProviderAvailability,
)


class StubProvider:
    provider_id = 'test.provider'

    def availability(self, target):
        return ProviderAvailability(
            self.provider_id,
            True,
            (DiagnosticCapability(
                'function_values', 'native_function',
                frozenset({'observe_arguments', 'observe_return'}),
                'Observed scalar function values.',
            ),),
        )

    def start(self, target, request, on_observation):
        raise NotImplementedError


class DiagnosticTests(unittest.TestCase):
    def test_registry_reports_dynamic_provider_capabilities(self):
        registry = DiagnosticProviderRegistry()
        provider = StubProvider()
        registry.register(provider)

        self.assertIs(registry.get(provider.provider_id), provider)
        availability = registry.availability(
            DiagnosticTarget(100, 'sample.exe', architecture='x64'))
        self.assertTrue(availability[0].available)
        self.assertEqual(
            availability[0].capabilities[0].domain, 'native_function')

    def test_registry_rejects_duplicate_and_invalid_providers(self):
        registry = DiagnosticProviderRegistry()
        registry.register(StubProvider())
        with self.assertRaisesRegex(ValueError, 'duplicado'):
            registry.register(StubProvider())
        with self.assertRaisesRegex(ValueError, 'provider_id'):
            registry.register(object())
        with self.assertRaisesRegex(ValueError, 'operaciones'):
            DiagnosticCapability('empty', 'native_function', frozenset(), '')

    def test_history_marks_changed_fields_and_respects_bound(self):
        history = ObservationHistory(max_records=2)
        first = DiagnosticObservation(
            1.0, 'frida.functions', 'native_function', 100,
            'sample.dll!Read', 'entry', {'arg0': 3})
        unchanged = DiagnosticObservation(
            2.0, 'frida.functions', 'native_function', 100,
            'sample.dll!Read', 'entry', {'arg0': 3})
        changed = DiagnosticObservation(
            3.0, 'frida.functions', 'native_function', 100,
            'sample.dll!Read', 'entry', {'arg0': 4})

        self.assertEqual(history.add(first).changed_values, ())
        self.assertEqual(history.add(unchanged).changed_values, ())
        self.assertEqual(history.add(changed).changed_values, ('arg0',))
        self.assertEqual(len(history.records), 2)

    def test_history_exports_observations_as_json(self):
        history = ObservationHistory()
        history.add(DiagnosticObservation(
            1.0, 'frida.functions', 'native_function', 100,
            'sample.dll!Read', 'return', {'value': 9}))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'observations.json'
            self.assertEqual(history.export_json(path), str(path))
            payload = json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(payload['schema_version'], 1)
        self.assertEqual(payload['observations'][0]['values']['value'], 9)

    def test_history_preserves_structured_runtime_values(self):
        history = ObservationHistory()
        history.add(DiagnosticObservation(
            1.0, 'runtime.adapter', 'runtime_data', 100,
            'managed-state', 'snapshot',
            {'player': {'health': 75, 'position': [1.0, 2.0, 3.0]}},
        ))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'runtime.json'
            history.export_json(path)
            payload = json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(
            payload['observations'][0]['values']['player']['health'], 75)

    def test_history_rejects_unbounded_configuration(self):
        with self.assertRaisesRegex(ValueError, 'mayor que cero'):
            ObservationHistory(max_records=0)

    def test_comparison_baseline_can_reset_between_sessions(self):
        history = ObservationHistory()
        observation = DiagnosticObservation(
            1.0, 'frida.functions', 'native_function', 100,
            'sample.dll!Read', 'entry', {'arg0': 3})
        history.add(observation)
        history.reset_comparison_baseline()
        self.assertEqual(history.add(observation).changed_values, ())


if __name__ == '__main__':
    unittest.main()
