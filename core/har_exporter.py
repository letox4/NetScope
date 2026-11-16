# -*- coding: utf-8 -*-
"""NetScope - Exportación a HAR 1.2 (HTTP Archive).

Reconstruye pares petición/respuesta HTTP desde los SocketStream capturados
(TCP, TLS en claro, HTTP WinHTTP/WinINet o SteamHTTP) y genera un JSON válido
según la especificación HAR 1.2.
"""
import base64
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from core.http_parser import parse_http_stream


def _iso_utc(ts: float) -> str:
    dt = datetime.fromtimestamp(ts or 0.0, tz=timezone.utc)
    return dt.isoformat().replace('+00:00', 'Z')


def _header_value(headers: List[Tuple[str, str]], name: str) -> Optional[str]:
    target = name.lower()
    for k, v in headers:
        if k.lower() == target:
            return v
    return None


def _headers_size(start_line: str, headers: List[Tuple[str, str]]) -> int:
    total = len(start_line.encode('latin-1', 'replace')) + 2
    for k, v in headers:
        total += len(f'{k}: {v}\r\n'.encode('latin-1', 'replace'))
    return total + 2


def _decode_body(body: bytes, mime: str) -> Tuple[str, Optional[str]]:
    if not body:
        return '', None
    is_text = (
        mime.startswith('text/')
        or 'json' in mime
        or 'xml' in mime
        or 'javascript' in mime
        or 'x-www-form-urlencoded' in mime
        or 'html' in mime
    )
    if is_text or all(b in (9, 10, 13) or 32 <= b < 127 for b in body[:256]):
        return body.decode('utf-8', errors='replace'), None
    return base64.b64encode(body).decode('ascii'), 'base64'


def _parse_cookies(headers: List[Tuple[str, str]], header_name: str) -> List[dict]:
    out = []
    target = header_name.lower()
    for k, v in headers:
        if k.lower() != target:
            continue
        for part in v.split(';'):
            part = part.strip()
            if '=' in part:
                ck, cv = part.split('=', 1)
                out.append({'name': ck.strip(), 'value': cv.strip()})
    return out


def _build_url(target_uri: str, headers: List[Tuple[str, str]], st: Any) -> str:
    if target_uri.startswith(('http://', 'https://')):
        return target_uri
    host = _header_value(headers, 'host')
    if not host:
        peer_host = getattr(st, 'peer_host', None)
        peer_ip = getattr(st, 'peer_ip', None)
        peer_port = getattr(st, 'peer_port', None)
        if peer_host:
            host = f'{peer_host}:{peer_port}' if peer_port and peer_port not in (80, 443) else peer_host
        elif peer_ip:
            host = f'{peer_ip}:{peer_port}' if peer_port and peer_port not in (80, 443) else peer_ip
        else:
            peer = getattr(st, 'peer', '') or 'unknown'
            host = peer.split('(')[-1].rstrip(')') if '(' in peer else peer
    proto = (getattr(st, 'proto', '') or '').upper()
    peer_port = getattr(st, 'peer_port', None)
    scheme = 'https' if (proto == 'TLS' or peer_port == 443) else 'http'
    path = target_uri if target_uri.startswith('/') else f'/{target_uri}'
    return f'{scheme}://{host}{path}'


def _parse_http_messages_tolerant(data: bytes) -> List[dict]:
    """Usa parse_http_stream y aplica fallback si los headers carecen de versión."""
    msgs = parse_http_stream(data)
    if msgs or not data:
        return msgs
    # Fallback para APIs de alto nivel (WinHTTP/WinINet) que emiten método + ruta + headers
    text = data.decode('latin-1', errors='replace')
    lines = text.split('\r\n')
    first = lines[0].strip()
    parts = first.split(' ')
    if len(parts) >= 2 and parts[0].upper() in (
        'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'
    ):
        headers = []
        idx = 1
        while idx < len(lines) and lines[idx]:
            if ':' in lines[idx]:
                k, v = lines[idx].split(':', 1)
                headers.append((k.strip(), v.strip()))
            idx += 1
        body_str = '\r\n'.join(lines[idx + 1:]) if idx + 1 < len(lines) else ''
        return [{
            'kind': 'request',
            'start_line': first + (' HTTP/1.1' if ' HTTP/' not in first else ''),
            'headers': headers,
            'body': body_str.encode('latin-1', errors='replace'),
        }]
    return []


def _format_request(req: Optional[dict], st: Any) -> dict:
    if not req:
        return {
            'method': 'GET',
            'url': _build_url('/', [], st),
            'httpVersion': 'HTTP/1.1',
            'cookies': [],
            'headers': [],
            'queryString': [],
            'headersSize': -1,
            'bodySize': 0,
        }
    parts = req['start_line'].split(' ')
    method = parts[0] if parts else 'GET'
    target = parts[1] if len(parts) > 1 else '/'
    version = parts[2] if len(parts) > 2 else 'HTTP/1.1'
    headers = req.get('headers', [])
    url = _build_url(target, headers, st)
    parsed = urlsplit(url)
    query = [{'name': k, 'value': v} for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    body = req.get('body', b'') or b''
    mime = (_header_value(headers, 'content-type') or 'application/octet-stream').split(';')[0].strip()

    har_req: Dict[str, Any] = {
        'method': method,
        'url': url,
        'httpVersion': version,
        'cookies': _parse_cookies(headers, 'cookie'),
        'headers': [{'name': k, 'value': v} for k, v in headers],
        'queryString': query,
        'headersSize': _headers_size(req['start_line'], headers),
        'bodySize': len(body),
    }
    if body:
        text, enc = _decode_body(body, mime)
        post_data: Dict[str, Any] = {'mimeType': mime, 'text': text}
        if enc:
            post_data['encoding'] = enc
        if 'x-www-form-urlencoded' in mime.lower():
            post_data['params'] = [
                {'name': k, 'value': v}
                for k, v in parse_qsl(text, keep_blank_values=True)
            ]
        har_req['postData'] = post_data
    return har_req


def _format_response(resp: Optional[dict]) -> dict:
    if not resp:
        return {
            'status': 0,
            'statusText': '',
            'httpVersion': 'HTTP/1.1',
            'cookies': [],
            'headers': [],
            'content': {'size': 0, 'mimeType': 'x-unknown'},
            'redirectURL': '',
            'headersSize': -1,
            'bodySize': -1,
        }
    parts = resp['start_line'].split(' ', 2)
    version = parts[0] if parts else 'HTTP/1.1'
    try:
        status = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        status = 0
    status_text = parts[2] if len(parts) > 2 else ''
    headers = resp.get('headers', [])
    body = resp.get('body', b'') or b''
    mime = (_header_value(headers, 'content-type') or 'application/octet-stream').split(';')[0].strip()
    text, enc = _decode_body(body, mime)
    content: Dict[str, Any] = {
        'size': len(body),
        'mimeType': mime,
        'text': text,
    }
    if enc:
        content['encoding'] = enc
    return {
        'status': status,
        'statusText': status_text,
        'httpVersion': version,
        'cookies': _parse_cookies(headers, 'set-cookie'),
        'headers': [{'name': k, 'value': v} for k, v in headers],
        'content': content,
        'redirectURL': _header_value(headers, 'location') or '',
        'headersSize': _headers_size(resp['start_line'], headers),
        'bodySize': len(body),
    }


def build_har(streams) -> Dict[str, Any]:
    """Construye un diccionario HAR 1.2 completo a partir de SocketStreams."""
    entries: List[dict] = []
    for st in streams:
        out_msgs = _parse_http_messages_tolerant(bytes(getattr(st, 'out_data', b'')))
        in_msgs = _parse_http_messages_tolerant(bytes(getattr(st, 'in_data', b'')))

        reqs = [m for m in out_msgs if m['kind'] == 'request']
        resps = [m for m in in_msgs if m['kind'] == 'response']
        # Si el proceso observado actuó como servidor, invertir dirección
        if not reqs and not resps:
            reqs = [m for m in in_msgs if m['kind'] == 'request']
            resps = [m for m in out_msgs if m['kind'] == 'response']

        pair_count = max(len(reqs), len(resps))
        if pair_count == 0:
            continue

        opened_ts = getattr(st, 'opened_ts', 0.0) or 0.0
        for idx in range(pair_count):
            req = reqs[idx] if idx < len(reqs) else None
            resp = resps[idx] if idx < len(resps) else None
            entry = {
                'startedDateTime': _iso_utc(opened_ts),
                'time': 0,
                'request': _format_request(req, st),
                'response': _format_response(resp),
                'cache': {},
                'timings': {'send': 0, 'wait': 0, 'receive': 0},
                '_netscope': {
                    'fd': getattr(st, 'fd', -1),
                    'proto': getattr(st, 'proto', '?'),
                    'peer': getattr(st, 'peer', '?'),
                    'peer_host': getattr(st, 'peer_host', None),
                    'pid': getattr(st, 'pid', None),
                    'call_stacks': list(getattr(st, 'call_stacks', []) or [])[:3],
                },
            }
            entries.append(entry)

    return {
        'log': {
            'version': '1.2',
            'creator': {'name': 'NetScope', 'version': '1.0'},
            'pages': [],
            'entries': entries,
        }
    }


def export_har_file(streams, path: str) -> str:
    """Serializa el HAR 1.2 a disco en UTF-8."""
    har_obj = build_har(streams)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(har_obj, f, indent=2, ensure_ascii=False)
    return path
