"""Reusable, heuristic analysis for captured game-network streams."""

from core.binary_decoder import BinaryDecoder
from core.unity_hooks import UnityMessagePatterns


def analyze_game_streams(streams):
    decoder = BinaryDecoder()
    results = []
    for stream in sorted(streams, key=lambda item: item.fd):
        tx_data = bytes(stream.out_data)
        rx_data = bytes(stream.in_data)
        tx = decoder.analyze(tx_data)
        rx = decoder.analyze(rx_data)
        framework = (
            UnityMessagePatterns.detect_framework(tx_data)
            or UnityMessagePatterns.detect_framework(rx_data)
        )
        results.append({
            'fd': stream.fd,
            'proto': stream.proto,
            'peer': stream.peer,
            'tx_bytes': len(tx_data),
            'rx_bytes': len(rx_data),
            'framework': framework or 'No detectado',
            'tx_format': tx.likely_format,
            'rx_format': rx.likely_format,
            'tx_entropy': tx.entropy,
            'rx_entropy': rx.entropy,
            'tx_compression': tx.compression_type,
            'rx_compression': rx.compression_type,
        })
    return results


def format_game_analysis_report(results):
    lines = [
        'NetScope - Informe de análisis de juego',
        '=' * 48,
        f'Streams analizados: {len(results)}',
        f'TX total: {sum(item["tx_bytes"] for item in results)} bytes',
        f'RX total: {sum(item["rx_bytes"] for item in results)} bytes',
        '',
        'Las detecciones de formato/framework son heurísticas.',
    ]
    for item in results:
        lines.extend((
            '',
            f'FD={item["fd"]} | {item["proto"]} | {item["peer"]}',
            f'Framework/patrón: {item["framework"]}',
            f'TX: {item["tx_bytes"]} bytes | {item["tx_format"]} | '
            f'entropía {item["tx_entropy"]:.2f} | '
            f'compresión {item["tx_compression"] or "no detectada"}',
            f'RX: {item["rx_bytes"]} bytes | {item["rx_format"]} | '
            f'entropía {item["rx_entropy"]:.2f} | '
            f'compresión {item["rx_compression"] or "no detectada"}',
        ))
    if not results:
        lines.extend(('', 'No se capturaron streams durante el análisis.'))
    return '\n'.join(lines)
