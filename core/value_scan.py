"""Passive staged searches for numeric values in captured network payloads."""

import struct
from dataclasses import dataclass, replace
from typing import Iterable


VALUE_FORMATS = {
    'uint16': 'H',
    'uint32': 'I',
    'uint64': 'Q',
    'int16': 'h',
    'int32': 'i',
    'int64': 'q',
    'float32': 'f',
    'float64': 'd',
}
BYTE_ORDERS = {
    'little-endian': '<',
    'big-endian': '>',
}
PLAINTEXT_EVENTS = {
    ('HTTP', 'http_out'), ('HTTP', 'http_in'),
    ('TLS', 'tls_out'), ('TLS', 'tls_in'),
    ('STEAM', 'steam_out'), ('STEAM', 'steam_in'),
}
RAW_SOCKET_EVENTS = {
    ('TCP', 'send'), ('TCP', 'recv'),
    ('TCP', 'wsa_send'), ('TCP', 'wsa_recv'),
    ('UDP', 'udp_send'), ('UDP', 'udp_recv'),
}
SCAN_EVENTS = PLAINTEXT_EVENTS | RAW_SOCKET_EVENTS


@dataclass(frozen=True)
class ValueCandidate:
    capture_id: int
    fd: int
    proto: str
    event: str
    direction: str
    tag: str
    offset: int
    value_type: str
    byte_order: str
    initial_value: str
    current_value: str
    sample_id: int


class ValueScanner:
    """Find a known value, then compare new matching payload events."""

    MAX_CANDIDATES = 5000

    def __init__(self):
        self._candidates = {}
        self._cursor = -1
        self._value_type = None
        self._byte_orders = ()
        self.last_rescan_sample_count = 0
        self.candidates_truncated = False

    @staticmethod
    def _encode(value, value_type, byte_order):
        if value_type not in VALUE_FORMATS:
            raise ValueError(f'Tipo numérico no compatible: {value_type}')
        if byte_order not in BYTE_ORDERS:
            raise ValueError(f'Orden de bytes no compatible: {byte_order}')
        try:
            if value_type.startswith(('int', 'uint')):
                try:
                    parsed = int(value, 0)
                except ValueError:
                    parsed = int(value, 10)
            else:
                parsed = float(value)
            return struct.pack(
                BYTE_ORDERS[byte_order] + VALUE_FORMATS[value_type], parsed)
        except (ValueError, TypeError, struct.error, OverflowError) as exc:
            raise ValueError(
                f'El valor {value!r} no cabe como {value_type} '
                f'({byte_order})') from exc

    @staticmethod
    def _sample_key(sample):
        return (
            sample.capture_id, sample.fd, sample.proto, sample.event,
            sample.direction, sample.tag,
        )

    @staticmethod
    def _is_scan_sample(sample):
        return (
            (sample.proto.upper(), sample.event) in SCAN_EVENTS
            and bool(sample.data)
        )

    @staticmethod
    def _candidate_key(candidate):
        return (
            candidate.capture_id, candidate.fd, candidate.proto,
            candidate.event, candidate.direction, candidate.tag, candidate.offset,
            candidate.value_type, candidate.byte_order,
        )

    def scan(self, samples: Iterable, value: str, value_type: str,
             byte_order: str = 'both'):
        if value_type not in VALUE_FORMATS:
            raise ValueError(f'Tipo numérico no compatible: {value_type}')
        orders = tuple(BYTE_ORDERS) if byte_order == 'both' else (byte_order,)
        patterns = {
            order: self._encode(value, value_type, order)
            for order in orders
        }
        sample_list = tuple(
            sample for sample in samples if self._is_scan_sample(sample)
        )
        if not sample_list:
            raise ValueError(
                'No hay payloads HTTP/TLS/Steam o TCP/UDP capturados. '
                'Genera tráfico después de adjuntar el proceso.')

        candidates = {}
        self.candidates_truncated = False
        for sample in sample_list:
            for order, pattern in patterns.items():
                offset = sample.data.find(pattern)
                while offset >= 0:
                    candidate = ValueCandidate(
                        capture_id=sample.capture_id,
                        fd=sample.fd,
                        proto=sample.proto,
                        event=sample.event,
                        direction=sample.direction,
                        tag=sample.tag,
                        offset=offset,
                        value_type=value_type,
                        byte_order=order,
                        initial_value=str(value),
                        current_value=str(value),
                        sample_id=sample.sample_id,
                    )
                    candidate_key = self._candidate_key(candidate)
                    if (candidate_key not in candidates
                            and len(candidates) >= self.MAX_CANDIDATES):
                        self.candidates_truncated = True
                        break
                    candidates[candidate_key] = candidate
                    offset = sample.data.find(pattern, offset + 1)
                if self.candidates_truncated:
                    break
            if self.candidates_truncated:
                break

        self._candidates = candidates
        self._value_type = value_type
        self._byte_orders = orders
        self._cursor = max(sample.sample_id for sample in sample_list)
        self.last_rescan_sample_count = 0
        return self.candidates

    def rescan(self, samples: Iterable, new_value: str):
        if not self._candidates:
            raise ValueError('Primero busca un valor inicial con candidatos')
        new_patterns = {
            order: self._encode(new_value, self._value_type, order)
            for order in self._byte_orders
        }
        new_samples = tuple(
            sample for sample in samples
            if sample.sample_id > self._cursor
            and self._is_scan_sample(sample)
        )
        self.last_rescan_sample_count = len(new_samples)
        if not new_samples:
            return self.candidates

        grouped = {}
        for candidate in self._candidates.values():
            grouped.setdefault(self._sample_key(candidate), []).append(candidate)

        retained = {}
        for sample in new_samples:
            for candidate in grouped.get(self._sample_key(sample), ()):
                pattern = new_patterns[candidate.byte_order]
                end = candidate.offset + len(pattern)
                if sample.data[candidate.offset:end] == pattern:
                    updated = replace(
                        candidate,
                        current_value=str(new_value),
                        sample_id=sample.sample_id,
                    )
                    retained[self._candidate_key(updated)] = updated

        self._cursor = max(sample.sample_id for sample in new_samples)
        self._candidates = retained
        return self.candidates

    @property
    def candidates(self):
        return tuple(sorted(
            self._candidates.values(),
            key=lambda item: (
                item.proto, item.fd, item.direction, item.event, item.tag,
                item.offset, item.value_type, item.byte_order,
            ),
        ))

    @property
    def has_candidates(self):
        return bool(self._candidates)

    def reset(self):
        self.__init__()
