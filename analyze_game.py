#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NetScope — Analizador rápido de tráfico para juegos Unity/multijugador.

Construido sobre el SDK público (``NetScopeSession``) para capturar TCP/UDP/IOCP/TLS,
detectar frameworks (Photon, PlayFab, Mirror, Netcode), mostrar call stacks,
DNS resueltos e IOCs, con limpieza automática al salir.

Uso:
  py -3.11 analyze_game.py MiJuego.exe -t 15
  py -3.11 analyze_game.py 5788 -t 10 --pcapng captura.pcapng
"""
import argparse
import sys
from pathlib import Path
from typing import Optional

BASE = Path(__file__).resolve().parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from core.game_analysis import analyze_game_streams, format_game_analysis_report
from core.sdk import NetScopeSession


def resolve_game_pid(target: str) -> Optional[int]:
    """Acepta PID numérico o subcadena del nombre del proceso."""
    if target.isdigit():
        return int(target)

    needle = target.casefold()
    matches = [p for p in NetScopeSession.list_processes() if needle in p['name'].casefold()]
    if not matches:
        print(f"[-] No se encontró ningún proceso que coincida con '{target}'.")
        return None
    if len(matches) == 1:
        print(f"[+] Proceso detectado: {matches[0]['name']} (PID={matches[0]['pid']})")
        return int(matches[0]['pid'])

    print('[*] Múltiples procesos encontrados:')
    for idx, proc in enumerate(matches, 1):
        print(f"  [{idx}] {proc['name']} (PID={proc['pid']})")
    choice = input('Selecciona [1]: ').strip() or '1'
    try:
        selected = matches[int(choice) - 1]
    except (ValueError, IndexError):
        selected = matches[0]
    print(f"[+] Seleccionado: {selected['name']} (PID={selected['pid']})")
    return int(selected['pid'])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description='NetScope — Analizador en vivo de tráfico de juegos Unity',
    )
    parser.add_argument('target', help='Nombre del proceso (ej. MiJuego.exe) o PID')
    parser.add_argument('-t', '--timeout', type=float, default=15.0,
                        help='Segundos de captura (default: 15)')
    parser.add_argument('--follow-children', action='store_true',
                        help='Seguir automáticamente procesos hijo')
    parser.add_argument('--pcapng', help='Guardar captura PCAPNG en esta ruta')
    parser.add_argument('--report', help='Guardar informe de texto en esta ruta')
    args = parser.parse_args(argv)

    pid = resolve_game_pid(args.target)
    if pid is None:
        return 1

    print(f"[*] Capturando PID={pid} durante {args.timeout:.1f}s (Ctrl+C para detener antes)...")
    with NetScopeSession(pid=pid, follow_children=bool(args.follow_children), capture_stacks=True) as ns:
        streams = ns.capture(duration=args.timeout)
        results = analyze_game_streams(streams)
        report_text = format_game_analysis_report(results)
        print('\n' + report_text)

        for st in streams:
            if st.call_stacks:
                print(f"  fd={st.fd} caller: {' <- '.join(st.call_stacks[0][:4])}")

        dns_map = ns.dns_table()
        if dns_map:
            print(f"\n[i] DNS observados: {len(dns_map)}")
            for ip, host in sorted(dns_map.items()):
                print(f"  {ip} -> {host}")

        ioc_report = ns.extract_iocs()
        if ioc_report.items or ioc_report.stream_hashes:
            print('\n' + ioc_report.summary_text())

        if args.report:
            Path(args.report).write_text(report_text, encoding='utf-8')
            print(f"[+] Reporte guardado en {args.report}")
        if args.pcapng:
            ns.export_pcapng(args.pcapng)
            print(f"[+] PCAPNG guardado en {args.pcapng}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
