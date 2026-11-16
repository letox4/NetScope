"""Extensible contracts and history for non-invasive diagnostics."""
import json
from dataclasses import asdict, dataclass
from importlib.metadata import entry_points
from pathlib import Path
from typing import Callable, Protocol


class DiagnosticDomain:
    PROCESS_METADATA = 'process_metadata'
    NATIVE_FUNCTION = 'native_function'
    MANAGED_FUNCTION = 'managed_function'
    NATIVE_MEMORY = 'native_memory'
    MANAGED_MEMORY = 'managed_memory'
    NETWORK_PAYLOAD = 'network_payload'
    RUNTIME_DATA = 'runtime_data'


@dataclass(frozen=True)
class DiagnosticTarget:
    pid: int
    name: str
    architecture: str | None = None
    pointer_size: int | None = None
    runtime_markers: tuple[str, ...] = ()


@dataclass(frozen=True)
class DiagnosticProfile:
    pid: int
    name: str
    architecture: str
    pointer_size: int
    runtime_markers: tuple[str, ...] = ()


@dataclass(frozen=True)
class DiagnosticCapability:
    capability_id: str
    domain: str
    operations: frozenset[str]
    description: str

    def __post_init__(self):
        if not self.capability_id or not self.domain or not self.operations:
            raise ValueError('La capacidad requiere id, dominio y operaciones.')


@dataclass(frozen=True)
class ProviderAvailability:
    provider_id: str
    available: bool
    capabilities: tuple[DiagnosticCapability, ...] = ()
    reason: str = ''
    verified: bool = False


@dataclass(frozen=True)
class DiagnosticObservation:
    timestamp: float
    provider_id: str
    domain: str
    pid: int
    subject: str
    phase: str
    values: dict[str, object]
    changed_values: tuple[str, ...] = ()


class DiagnosticSession(Protocol):
    def stop(self) -> None: ...


class DiagnosticProvider(Protocol):
    """Plugin contract: describe capabilities and emit typed observations."""

    provider_id: str

    def availability(self, target: DiagnosticTarget) -> ProviderAvailability: ...

    def start(
        self,
        target: DiagnosticTarget,
        request: dict,
        on_observation: Callable[
            [DiagnosticObservation | DiagnosticProfile], None],
    ) -> DiagnosticSession: ...


class DiagnosticProviderRegistry:
    """Registry for built-in providers and installed provider entry points."""

    ENTRY_POINT_GROUP = 'netscope.diagnostic_providers'

    def __init__(self):
        self._providers: dict[str, DiagnosticProvider] = {}
        self.load_errors: list[str] = []

    def register(self, provider: DiagnosticProvider) -> None:
        provider_id = getattr(provider, 'provider_id', None)
        if not isinstance(provider_id, str) or not provider_id.strip():
            raise ValueError('El proveedor debe declarar un provider_id válido.')
        if provider_id in self._providers:
            raise ValueError(f'Proveedor de diagnóstico duplicado: {provider_id}')
        self._providers[provider_id] = provider

    def load_entry_points(self) -> tuple[str, ...]:
        loaded = []
        for entry_point in entry_points(group=self.ENTRY_POINT_GROUP):
            try:
                provider_factory = entry_point.load()
                self.register(provider_factory())
            except Exception as error:
                self.load_errors.append(
                    f'{entry_point.name}: {type(error).__name__}: {error}')
                continue
            loaded.append(entry_point.name)
        return tuple(loaded)

    def get(self, provider_id: str) -> DiagnosticProvider:
        try:
            return self._providers[provider_id]
        except KeyError as exc:
            raise KeyError(f'Proveedor de diagnóstico no registrado: {provider_id}') from exc

    def availability(
        self, target: DiagnosticTarget,
    ) -> tuple[ProviderAvailability, ...]:
        return tuple(
            provider.availability(target)
            for provider in self._providers.values()
        )


class ObservationHistory:
    """Bounded event history with per-subject change detection."""

    def __init__(self, max_records: int = 10000):
        if max_records < 1:
            raise ValueError('max_records debe ser mayor que cero.')
        self.max_records = max_records
        self._records: list[DiagnosticObservation] = []
        self._latest: dict[tuple[int, str, str, str], dict] = {}

    @property
    def records(self) -> tuple[DiagnosticObservation, ...]:
        return tuple(self._records)

    def add(self, observation: DiagnosticObservation) -> DiagnosticObservation:
        key = (
            observation.pid, observation.provider_id,
            observation.subject, observation.phase,
        )
        previous = self._latest.get(key)
        changed = tuple(
            name for name, value in observation.values.items()
            if previous is not None
            and (name not in previous or previous[name] != value)
        )
        recorded = DiagnosticObservation(
            timestamp=observation.timestamp,
            provider_id=observation.provider_id,
            domain=observation.domain,
            pid=observation.pid,
            subject=observation.subject,
            phase=observation.phase,
            values=dict(observation.values),
            changed_values=changed,
        )
        self._latest[key] = dict(observation.values)
        self._records.append(recorded)
        if len(self._records) > self.max_records:
            del self._records[:len(self._records) - self.max_records]
        return recorded

    def clear(self) -> None:
        self._records.clear()
        self._latest.clear()

    def reset_comparison_baseline(self) -> None:
        self._latest.clear()

    def export_json(self, path: str | Path, metadata: dict | None = None) -> str:
        payload = {
            'schema_version': 1,
            'metadata': metadata or {},
            'observations': [asdict(record) for record in self._records],
        }
        output_path = Path(path)
        output_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding='utf-8',
        )
        return str(output_path)
