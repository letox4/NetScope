# -*- coding: utf-8 -*-
"""NetScope CLI — Interfaz de línea de comandos completa."""
import argparse
import json
import os
import subprocess
import sys
import time
from typing import List, Optional

from core.binary_decoder import BinaryDecoder
from core.sdk import NetScopeSession
from core.threat_intel import IOCExtractor, YaraScanner


def _cmd_ps(args) -> int:
    procs = NetScopeSession.list_processes()
    if args.filter:
        q = args.filter.casefold()
        procs = [p for p in procs if q in p['name'].casefold() or q in str(p['pid'])]
    if args.json:
        print(json.dumps(procs, indent=2, ensure_ascii=False))
        return 0
    print(f'{"PID":>8}  {"Proceso"}')
    print('-' * 48)
    for p in procs:
        print(f'{p["pid"]:>8}  {p["name"]}')
    print(f'\nTotal: {len(procs)} procesos')
    return 0


def _parse_rewrite_rules(specs: Optional[List[str]]) -> List[dict]:
    rules = []
    for raw in specs or ():
        if ':' not in raw:
            raise ValueError(f'Formato --rewrite inválido ({raw!r}); usa HEX_MATCH:HEX_REPLACE')
        hm, hr = raw.split(':', 1)
        rules.append({'hex_match': hm.strip(), 'hex_replace': hr.strip()})
    return rules


def _print_capture_summary(ns: NetScopeSession, args) -> None:
    streams = ns.streams(localhost_only=getattr(args, 'localhost_only', False))
    print(f'\n=== Resumen de captura ({len(streams)} streams) ===')
    for st in streams:
        pid_info = f' pid={st.pid}' if st.pid else ''
        print(
            f'  fd={st.fd:<8} {st.proto:<5} peer={st.peer:<36} '
            f'tx={st.byte_out:<7}B rx={st.byte_in:<7}B ev={st.event_count}{pid_info}'
        )
        if st.call_stacks:
            print(f'    caller: {" <- ".join(st.call_stacks[0][:4])}')

    dns_map = ns.dns_table()
    if dns_map:
        print(f'\n=== DNS resueltos ({len(dns_map)}) ===')
        for ip, host in sorted(dns_map.items()):
            print(f'  {ip} -> {host}')

    keys = ns.tls_keys()
    if keys:
        print(f'\n=== Claves TLS capturadas ({len(keys)} líneas) ===')
        for ln in keys[:5]:
            print(f'  {ln[:88]}')

    if ns.child_pids():
        print(f'\n=== Procesos hijo observados: {ns.child_pids()} ===')

    if getattr(args, 'extract_iocs', False):
        report = ns.extract_iocs()
        print('\n' + report.summary_text())

    yara_arg = getattr(args, 'yara', None)
    if yara_arg is not None:
        rules_path = yara_arg if (isinstance(yara_arg, str) and yara_arg != '__BUILTIN__') else None
        matches = ns.scan_yara(rules_path=rules_path, include_builtin=True)
        print(f'\n=== Coincidencias YARA ({len(matches)}) ===')
        for m in matches:
            print(f'  [{m.rule}] fd={m.fd} dir={m.direction} tags={m.tags}')
            for sm in m.strings[:3]:
                print(f'    {sm.identifier} @ {sm.offset}: {sm.matched_ascii!r}')

    if getattr(args, 'pcapng', None):
        ns.export_pcapng(args.pcapng)
        print(f'[+] PCAPNG guardado en {args.pcapng}')
    if getattr(args, 'har', None):
        ns.export_har(args.har)
        print(f'[+] HAR guardado en {args.har}')
    if getattr(args, 'keylog', None):
        ns.export_keylog(args.keylog)
        print(f'[+] TLS Keylog guardado en {args.keylog}')
    if getattr(args, 'json', None):
        ns.export_json(args.json)
        print(f'[+] Reporte JSON guardado en {args.json}')


def _cmd_capture(args) -> int:
    if not (args.pid or args.process or args.spawn):
        print('Error: debes especificar --pid, --process o --spawn.', file=sys.stderr)
        return 2

    target_name = args.spawn or args.process
    ns = NetScopeSession(
        pid=args.pid,
        process=target_name,
        spawn=bool(args.spawn),
        follow_children=bool(args.follow_children),
        capture_stacks=not args.no_stacks,
    )

    if args.live:
        @ns.on_event
        def _on_ev(ev):
            if ev.data:
                caller = f' [{ev.stack[0]}]' if ev.stack else ''
                print(
                    f'[{ev.proto}] fd={ev.fd} {ev.direction.upper():<3} '
                    f'len={len(ev.data):<5} peer={ev.peer_ip}:{ev.peer_port}{caller}',
                    flush=True,
                )

    @ns.on_log
    def _on_log(msg):
        if args.verbose:
            print(msg, flush=True)

    ns.attach()
    try:
        if args.rewrite:
            rules = _parse_rewrite_rules(args.rewrite)
            n = ns.set_patch_rules(rules)
            ns.set_rewrite_enabled(True)
            print(f'[i] {n} reglas de reescritura activas')

        if args.duration > 0:
            print(f'[i] Capturando durante {args.duration}s (Ctrl+C para detener antes)...')
            ns.capture(args.duration)
        else:
            print('[i] Capturando indefinidamente (Ctrl+C para detener)...')
            try:
                while True:
                    time.sleep(0.25)
            except KeyboardInterrupt:
                pass
    finally:
        _print_capture_summary(ns, args)
        ns.stop()
    return 0


def _cmd_scan(args) -> int:
    extractor = IOCExtractor()
    decoder = BinaryDecoder()
    scanner = (
        YaraScanner.from_file(args.yara, include_builtin=not args.no_builtin_yara)
        if args.yara else YaraScanner(include_builtin=not args.no_builtin_yara)
    )
    summary = []
    for path in args.files:
        with open(path, 'rb') as f:
            data = f.read()
        analysis = decoder.analyze(data)
        iocs = extractor.extract_from_bytes(data, fd=-1, direction='file', peer=path)
        matches = scanner.scan_bytes(data, fd=-1, direction='file')
        item = {
            'file': path,
            'bytes': len(data),
            'format': analysis.likely_format,
            'entropy': round(analysis.entropy, 3),
            'compression': analysis.compression_type,
            'iocs': [i.to_dict() for i in iocs],
            'yara_matches': [m.to_dict() for m in matches],
        }
        summary.append(item)
        if not args.json_out:
            print(f'\n=== {path} ({len(data)} B · fmt={analysis.likely_format} · ent={analysis.entropy:.2f}) ===')
            print(f'  IOCs: {len(iocs)}')
            for i in iocs[:25]:
                print(f'    - [{i.kind}] {i.value} ({i.context})')
            print(f'  YARA ({scanner.engine_name}): {len(matches)} coincidencias')
            for m in matches:
                print(f'    - [{m.rule}] {m.meta.get("description", "")}')

    if args.json_out:
        with open(args.json_out, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        print(f'[+] Escaneo guardado en {args.json_out}')
    return 0


def _cmd_demo(args) -> int:
    demo_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'demo_app.py')
    cmd = [sys.executable, demo_script, '--headless', '--delay', '1.8', '--duration', '6']
    if args.spawn_child:
        cmd.append('--spawn-child')
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)
    ns = NetScopeSession(
        pid=proc.pid,
        follow_children=bool(args.spawn_child),
        capture_stacks=True,
    )
    args.extract_iocs = True
    args.yara = '__BUILTIN__'
    args.localhost_only = False
    try:
        ns.attach()
        ns.capture(duration=args.duration)
        _print_capture_summary(ns, args)
    finally:
        ns.stop()
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='netscope',
        description='NetScope CLI — Interceptor TCP/UDP/TLS/IOCP con Frida',
    )
    sub = parser.add_subparsers(dest='command', required=True)

    p_ps = sub.add_parser('ps', aliases=['list-procs'], help='Listar procesos activos')
    p_ps.add_argument('--filter', '-f', help='Filtrar por nombre o PID')
    p_ps.add_argument('--json', action='store_true', help='Salida en JSON')
    p_ps.set_defaults(func=_cmd_ps)

    p_cap = sub.add_parser('capture', help='Adjuntar o spawnear un proceso y capturar tráfico')
    tgt = p_cap.add_mutually_exclusive_group(required=True)
    tgt.add_argument('--pid', type=int, help='PID del proceso objetivo')
    tgt.add_argument('--process', '-p', help='Nombre del proceso objetivo (ej. app.exe)')
    tgt.add_argument('--spawn', help='Ruta del ejecutable a lanzar bajo Frida')
    p_cap.add_argument('--duration', '-d', type=float, default=15.0,
                       help='Segundos de captura (0 = hasta Ctrl+C)')
    p_cap.add_argument('--follow-children', action='store_true',
                       help='Seguir automáticamente procesos hijo')
    p_cap.add_argument('--localhost-only', action='store_true',
                       help='Mostrar/exportar solo tráfico 127.0.0.1')
    p_cap.add_argument('--no-stacks', action='store_true',
                       help='Desactivar captura de call stacks')
    p_cap.add_argument('--live', action='store_true',
                       help='Imprimir eventos de red en tiempo real')
    p_cap.add_argument('--verbose', '-v', action='store_true',
                       help='Imprimir logs internos de Frida y hooks')
    p_cap.add_argument('--extract-iocs', action='store_true',
                       help='Extraer IOCs al finalizar')
    p_cap.add_argument('--yara', nargs='?', const='__BUILTIN__', default=None,
                       help='Aplicar reglas YARA (built-in o ruta a .yar)')
    p_cap.add_argument('--rewrite', action='append',
                       help='Regla hex igual-longitud: HEX_MATCH:HEX_REPLACE')
    p_cap.add_argument('--pcapng', help='Exportar captura a archivo .pcapng')
    p_cap.add_argument('--har', help='Exportar HTTP a archivo .har')
    p_cap.add_argument('--keylog', help='Exportar claves TLS a archivo SSLKEYLOGFILE')
    p_cap.add_argument('--json', help='Exportar reporte completo a JSON')
    p_cap.set_defaults(func=_cmd_capture)

    p_scan = sub.add_parser('scan', help='Análisis offline de archivos/payloads (IOCs + YARA)')
    p_scan.add_argument('files', nargs='+', help='Archivos o volcados binarios a analizar')
    p_scan.add_argument('--yara', help='Archivo .yar de reglas adicionales')
    p_scan.add_argument('--no-builtin-yara', action='store_true',
                        help='No incluir reglas YARA built-in')
    p_scan.add_argument('--json', dest='json_out', help='Guardar salida en JSON')
    p_scan.set_defaults(func=_cmd_scan)

    p_demo = sub.add_parser('demo', help='Ejecutar demo end-to-end contra demo_app.py')
    p_demo.add_argument('--duration', '-d', type=float, default=5.0)
    p_demo.add_argument('--spawn-child', action='store_true')
    p_demo.add_argument('--pcapng', help='Exportar PCAPNG de la demo')
    p_demo.add_argument('--har', help='Exportar HAR de la demo')
    p_demo.add_argument('--keylog', help='Exportar TLS keylog de la demo')
    p_demo.add_argument('--json', help='Exportar JSON de la demo')
    p_demo.set_defaults(func=_cmd_demo)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == '__main__':
    sys.exit(main())
