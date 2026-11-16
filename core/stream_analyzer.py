# -*- coding: utf-8 -*-
"""NetScope - Herramientas de análisis interactivo de streams binarios."""
import sys
from typing import Optional
from core.interceptor import FridaInterceptor, SocketStream
from core.binary_decoder import StreamBinaryAnalyzer, BinaryDecoder
from core.protocol_registry import ProtocolRegistry, BinaryForensics


class StreamAnalyzerCLI:
    """CLI interactiva para analizar streams capturados."""

    def __init__(self, interceptor: FridaInterceptor):
        self.ic = interceptor
        self.analyzer = StreamBinaryAnalyzer()
        self.registry = ProtocolRegistry()

    def print_streams_summary(self):
        """Lista todos los streams con información resumida."""
        streams = self.ic.snapshot_streams()
        if not streams:
            print("No hay streams capturados.")
            return

        print("\n" + "=" * 100)
        print(f"{'FD':<6} {'Proto':<6} {'Peer':<30} {'TX Bytes':<12} {'RX Bytes':<12} {'Closed':<8}")
        print("=" * 100)

        for st in sorted(streams, key=lambda s: s.fd):
            closed = "✓ YES" if st.closed else ""
            print(f"{st.fd:<6} {st.proto:<6} {st.peer:<30} {st.byte_out:<12} {st.byte_in:<12} {closed:<8}")

        print("=" * 100)
        print(f"Total: {len(streams)} streams\n")

    def analyze_stream_interactive(self, fd: int):
        """Analiza un stream específico de forma interactiva."""
        streams = self.ic.snapshot_streams()
        stream = next((s for s in streams if s.fd == fd), None)

        if not stream:
            print(f"Stream FD={fd} no encontrado.")
            return

        # Generar reporte de análisis
        report = self.analyzer.format_analysis_report(stream)
        print(report)

        # Menú interactivo
        while True:
            print("\nOpciones:")
            print("  1 - Intentar descomprimir")
            print("  2 - Intentar descifrar (XOR)")
            print("  3 - Buscar strings")
            print("  4 - Buscar archivos conocidos")
            print("  5 - Estadísticas detalladas")
            print("  6 - Hexdump completo")
            print("  0 - Volver")

            choice = input("Opción: ").strip()

            if choice == "1":
                self._analyze_compression(stream)
            elif choice == "2":
                self._analyze_encryption(stream)
            elif choice == "3":
                self._find_strings(stream)
            elif choice == "4":
                self._carve_formats(stream)
            elif choice == "5":
                self._show_statistics(stream)
            elif choice == "6":
                self._show_full_hexdump(stream)
            elif choice == "0":
                break
            else:
                print("Opción no válida.")

    def _analyze_compression(self, stream: SocketStream):
        """Intenta descomprimir datos del stream."""
        decoder = BinaryDecoder()

        for direction in ('out', 'in'):
            data = bytes(getattr(stream, f'{direction}_data'))
            if not data:
                continue

            print(f"\n{direction.upper()}:")
            decompressed = decoder.try_decompress(data)

            if decompressed:
                print(f"✓ Descomprimido exitosamente ({len(data)} → {len(decompressed)} bytes)")
                print(f"  Preview: {decompressed[:200]}")
            else:
                print(f"✗ No se pudo descomprimir")

    def _analyze_encryption(self, stream: SocketStream):
        """Intenta descifrar con XOR."""
        decoder = BinaryDecoder()

        for direction in ('out', 'in'):
            data = bytes(getattr(stream, f'{direction}_data'))
            if not data:
                continue

            print(f"\n{direction.upper()}:")
            attempts = decoder.try_decrypt_xor(data, key_size=4)

            if attempts:
                print(f"✓ {len(attempts)} posibles descifrados XOR encontrados:")
                for i, attempt in enumerate(attempts[:3]):
                    preview = attempt[:80]
                    print(f"  [{i+1}] {preview}")
            else:
                print(f"✗ No se encontraron descifrados XOR válidos")

    def _find_strings(self, stream: SocketStream):
        """Extrae strings legibles."""
        forensics = BinaryForensics()

        for direction in ('out', 'in'):
            data = bytes(getattr(stream, f'{direction}_data'))
            if not data:
                continue

            print(f"\n{direction.upper()}:")
            strings = forensics.find_possible_strings(data, min_length=4)
            null_term = forensics.find_null_terminated_strings(data)

            if strings:
                print(f"  Strings encontrados ({len(strings)}):")
                for s in strings[:10]:
                    print(f"    - {repr(s)}")
                if len(strings) > 10:
                    print(f"    ... y {len(strings) - 10} más")

            if null_term:
                print(f"  Null-terminated strings ({len(null_term)}):")
                for s in null_term[:5]:
                    print(f"    - {s.decode('utf-8', 'ignore')}")

    def _carve_formats(self, stream: SocketStream):
        """Busca formatos conocidos (PNG, ZIP, etc.)."""
        forensics = BinaryForensics()

        for direction in ('out', 'in'):
            data = bytes(getattr(stream, f'{direction}_data'))
            if not data:
                continue

            print(f"\n{direction.upper()}:")
            formats = forensics.carve_known_formats(data)

            if formats:
                print("  Formatos encontrados:")
                for fmt, offsets in formats.items():
                    print(f"    {fmt}: {offsets}")
            else:
                print("  No se encontraron formatos conocidos")

    def _show_statistics(self, stream: SocketStream):
        """Muestra estadísticas detalladas."""
        forensics = BinaryForensics()

        for direction in ('out', 'in'):
            data = bytes(getattr(stream, f'{direction}_data'))
            if not data:
                continue

            print(f"\n{direction.upper()}:")
            stats = forensics.calculate_statistics(data)

            for key, value in stats.items():
                if key == 'most_common':
                    print(f"  {key}:")
                    for byte_val, count in value:
                        pct = (count / stats['length']) * 100
                        print(f"    0x{byte_val:02x}: {count} ({pct:.1f}%)")
                elif key == 'byte_distribution':
                    continue  # Muy largo
                else:
                    print(f"  {key}: {value}")

    def _show_full_hexdump(self, stream: SocketStream):
        """Muestra hexdump completo."""
        decoder = BinaryDecoder()

        for direction in ('out', 'in'):
            data = bytes(getattr(stream, f'{direction}_data'))
            if not data:
                continue

            print(f"\n{direction.upper()}:")
            print(decoder.hex_dump_annotated(data, width=32))

    def interactive_menu(self):
        """Menú interactivo principal."""
        while True:
            print("\n" + "=" * 70)
            print("NetScope - Stream Binary Analyzer")
            print("=" * 70)
            print("1 - Listar streams")
            print("2 - Analizar stream específico")
            print("3 - Exportar reporte completo")
            print("0 - Salir")

            choice = input("\nOpción: ").strip()

            if choice == "1":
                self.print_streams_summary()
            elif choice == "2":
                fd = input("Ingresa FD del stream: ").strip()
                try:
                    self.analyze_stream_interactive(int(fd))
                except ValueError:
                    print("FD inválido")
            elif choice == "3":
                self.export_full_report()
            elif choice == "0":
                break
            else:
                print("Opción no válida")

    def export_full_report(self, output_file: str = "binary_analysis_report.txt"):
        """Exporta un reporte completo de todos los streams."""
        streams = self.ic.snapshot_streams()
        with open(output_file, 'w', encoding='utf-8') as f:
            for stream in sorted(streams, key=lambda s: s.fd):
                report = self.analyzer.format_analysis_report(stream)
                f.write(report)
                f.write("\n\n")

        print(f"Reporte exportado a {output_file}")


def main_cli_demo():
    """Demo de análisis de streams (requiere una captura previa)."""
    print("NetScope - Stream Binary Analyzer CLI")
    print("Nota: Requiere un interceptor activo con streams capturados.\n")

    # Simulación: crear un stream dummy para demostración
    from core.interceptor import SocketStream
    import time

    # Crear un stream con datos de prueba
    stream = SocketStream(
        fd=1,
        proto='TCP',
        peer='192.168.1.1:8080'
    )

    # Datos de prueba: mezcla de formatos
    stream.append_out(b'\x78\x9c' + b'datos comprimidos')  # Fake zlib header
    stream.append_in(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n')

    analyzer = StreamBinaryAnalyzer()
    report = analyzer.format_analysis_report(stream)
    print(report)

    print("\n\nEsta es una demo. Para usar en producción:")
    print("1. Captura datos con Frida")
    print("2. Usa StreamAnalyzerCLI con FridaInterceptor")
    print("3. Accede al menú interactivo")


if __name__ == '__main__':
    main_cli_demo()
