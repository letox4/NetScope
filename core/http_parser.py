# -*- coding: utf-8 -*-
"""Parser HTTP mínimo para streams TCP reensamblados."""


def parse_http_stream(data: bytes):
    """Devuelve lista de dicts: {kind, version, start_line, headers[], body}."""
    out = []
    i, n = 0, len(data)
    while i < n:
        chunk = data[i:]
        rest, req = _parse_http_message(chunk, request=True)
        if rest is None or req is None:
            rest, resp = _parse_http_message(chunk, request=False)
        if req:
            out.append(req)
            i = n - len(rest)
            continue
        if resp:
            out.append(resp)
            i = n - len(rest)
            continue
        # incompleto o no-http
        break
    return out


_HEADERS_END = b"\r\n\r\n"


def _parse_http_message(buf: bytes, request: bool):
    end = buf.find(_HEADERS_END)
    if end < 0:
        if len(buf) > 4 and (buf.startswith(b"GET ") or buf.startswith(b"POST ")
                             or buf.startswith(b"PUT ") or buf.startswith(b"HTTP/")):
            # aún incompleto
            return None, None
        return None, None
    head = buf[:end].decode("latin-1", "replace")
    lines = head.split("\r\n")
    start = lines[0]
    headers = []
    for ln in lines[1:]:
        if ':' in ln:
            k, v = ln.split(':', 1)
            headers.append((k.strip(), v.strip()))
    if request and ' HTTP/' not in start:
        return None, None
    if not request and not start.startswith("HTTP/"):
        return None, None

    body_len = 0
    chunked = False
    for k, v in headers:
        kl = k.lower()
        if kl == 'content-length':
            try:
                body_len = int(v)
            except ValueError:
                pass
        elif kl == 'transfer-encoding' and 'chunked' in v.lower():
            chunked = True
    body = buf[end + 4:]
    if not chunked:
        if body_len and len(body) < body_len:
            return None, None  # falta cuerpo
        body_frag = body[:body_len] if body_len else b''
        rest = body[body_len:] if body_len else b''
        return rest, _mk(start, headers, body_frag, request)
    # chunked: parse simple
    out, pos = bytearray(), 0
    while pos + 1 < len(body):
        crlf = body.find(b"\r\n", pos)
        if crlf < 0:
            return None, None
        try:
            sz = int(body[pos:crlf].split(b';')[0], 16)
        except ValueError:
            return None, None
        if sz == 0:
            # fin del cuerpo; trae trailers hasta el doble CRLF
            tt = body.find(b"\r\n\r\n", crlf)
            consumed = (tt + 2 if tt >= 0 else crlf + 2)
            return body[consumed:], _mk(start, headers, bytes(out), request)
        if crlf + 2 + sz > len(body):
            return None, None
        out += body[crlf + 2:crlf + 2 + sz]
        pos = crlf + 2 + sz + 2  # salta CRLF final del chunk
    return None, None


def _mk(start, headers, body, request):
    return {
        "kind": "request" if request else "response",
        "start_line": start,
        "headers": headers,
        "body": body,
    }
