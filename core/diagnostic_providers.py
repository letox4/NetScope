"""Adapters that expose existing instrumentation through the provider API."""
import time

from core.diagnostics import (
    DiagnosticCapability,
    DiagnosticDomain,
    DiagnosticObservation,
    DiagnosticProfile,
    DiagnosticTarget,
    ProviderAvailability,
)


class FridaFunctionProvider:
    """Expose the existing read-only Frida function probe as a provider."""

    provider_id = 'frida.function_observation'

    def __init__(self, probe):
        self._probe = probe

    def availability(self, target: DiagnosticTarget) -> ProviderAvailability:
        capabilities = [
            DiagnosticCapability(
                'frida.native_function_values',
                DiagnosticDomain.NATIVE_FUNCTION,
                frozenset({'observe_scalar_argument', 'observe_scalar_return'}),
                'Observa valores escalares de una función nativa configurada.',
            ),
            DiagnosticCapability(
                'frida.process_profile',
                DiagnosticDomain.PROCESS_METADATA,
                frozenset({'detect_architecture', 'detect_runtime_markers'}),
                'Detecta arquitectura y marcadores de runtime por módulos.',
            ),
        ]
        if 'unity_il2cpp' in target.runtime_markers:
            capabilities.append(DiagnosticCapability(
                'frida.il2cpp_function_values',
                DiagnosticDomain.MANAGED_FUNCTION,
                frozenset({'observe_scalar_argument', 'observe_scalar_return'}),
                'Observa escalares de un método IL2CPP con bridge compatible.',
            ))
        return ProviderAvailability(
            provider_id=self.provider_id,
            available=target.pid > 0,
            capabilities=tuple(capabilities),
            reason=(
                'Capacidad declarada; el acceso real se confirma al adjuntar.'
                if target.pid > 0 else 'El PID debe ser positivo.'
            ),
            verified=False,
        )

    def start(self, target, request, on_observation):
        self._probe.on_event = lambda event: self._forward_event(
            target, event, on_observation)
        config = request['config']
        self._probe.start(
            target.pid,
            config,
            request['script_path'],
            request.get('bridge_path'),
        )
        return self._probe

    def _forward_event(self, target, event, on_observation):
        event_type = event.get('event')
        if event_type == 'diagnostic_profile':
            on_observation(DiagnosticProfile(
                pid=target.pid,
                name=target.name,
                architecture=str(event['architecture']),
                pointer_size=int(event['pointer_size']),
                runtime_markers=tuple(event.get('runtime_markers', ())),
            ))
        elif event_type == 'function_observation':
            on_observation(DiagnosticObservation(
                timestamp=time.time(),
                provider_id=self.provider_id,
                domain=str(event['domain']),
                pid=target.pid,
                subject=str(event['subject']),
                phase=str(event['phase']),
                values=dict(event['values']),
            ))
