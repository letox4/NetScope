# -*- coding: utf-8 -*-
"""NetScope - Extracción de IOCs y Motor de Reglas YARA para análisis forense.

Proporciona:
  - IOCExtractor: extracción automática de direcciones IPv4/IPv6, dominios, URLs,
    correos, hashes MD5/SHA-256 de payloads, credenciales/cabeceras sensibles e
    indicadores potenciales de C2 sobre streams capturados o buffers arbitrarios.
  - YaraScanner: evaluación de reglas YARA (usa yara-python si está instalado y
    dispone de un compilador/evaluador YARA puro en Python integrado para cero
    dependencias externas), junto con un conjunto de reglas built-in.
"""
import hashlib
import ipaddress
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from core.binary_decoder import BinaryDecoder

try:
    import yara as _yara_mod  # type: ignore
except ImportError:
    _yara_mod = None


BUILTIN_YARA_RULES = r'''
rule Suspicious_PE_Transfer : malware executable {
    meta:
        description = "Detecta transferencia de ejecutable Windows PE (MZ + DOS stub)"
        severity = "high"
    strings:
        $mz = "MZ"
        $dos = "This program cannot be run in DOS mode" ascii
        $pe = { 50 45 00 00 }
    condition:
        ($mz at 0 or uint16(0) == 0x5A4D) and ($dos or $pe)
}

rule Reverse_Shell_Indicator : malware shell {
    meta:
        description = "Indicadores comunes de shell inversa o ejecución remota"
        severity = "critical"
    strings:
        $cmd1 = "cmd.exe /c" ascii wide nocase
        $cmd2 = "/bin/sh" ascii
        $cmd3 = "/bin/bash" ascii
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "-EncodedCommand" ascii wide nocase
        $ps3 = "Invoke-Expression" ascii wide nocase
        $ps4 = "Net.Sockets.TCPClient" ascii wide nocase
    condition:
        any of ($cmd*) or ($ps1 and any of ($ps2, $ps3, $ps4)) or $ps4
}

rule Cleartext_Auth_Credentials : credential exposure {
    meta:
        description = "Detecta envío de credenciales o tokens en texto claro"
        severity = "medium"
    strings:
        $auth_basic = "Authorization: Basic " ascii nocase
        $auth_bearer = "Authorization: Bearer " ascii nocase
        $pwd1 = "password=" ascii nocase
        $pwd2 = "\"password\":" ascii nocase
        $apikey = "api_key=" ascii nocase
    condition:
        any of them
}

rule Suspicious_C2_Beacon : c2 network {
    meta:
        description = "Patrones típicos de check-in o beacon C2"
        severity = "high"
    strings:
        $b1 = "/beacon" ascii nocase
        $b2 = "/checkin" ascii nocase
        $b3 = "c2-" ascii nocase
        $b4 = "gate.php" ascii nocase
        $ua_ps = "User-Agent: WindowsPowerShell" ascii nocase
    condition:
        any of them
}

rule Private_Key_Exposure : crypto secret {
    meta:
        description = "Detecta exposición de clave privada PEM en tráfico"
        severity = "high"
    strings:
        $k1 = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $k2 = "-----BEGIN PRIVATE KEY-----" ascii
        $k3 = "-----BEGIN EC PRIVATE KEY-----" ascii
        $k4 = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
    condition:
        any of them
}

rule EICAR_Test_Signature : test signature {
    meta:
        description = "Firma estándar de prueba EICAR (benigna)"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar
}
'''


@dataclass
class IOCItem:
    kind: str         # ipv4 | ipv6 | domain | url | email | sha256 | md5 | header | c2
    value: str
    fd: int
    direction: str
    context: str = ''
    confidence: str = 'medium'

    def to_dict(self) -> Dict[str, Any]:
        return {
            'kind': self.kind,
            'value': self.value,
            'fd': self.fd,
            'direction': self.direction,
            'context': self.context,
            'confidence': self.confidence,
        }


@dataclass
class IOCReport:
    items: List[IOCItem] = field(default_factory=list)
    stream_hashes: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def by_kind(self) -> Dict[str, List[IOCItem]]:
        grouped: Dict[str, List[IOCItem]] = {}
        for item in self.items:
            grouped.setdefault(item.kind, []).append(item)
        return grouped

    def unique_values(self, kind: Optional[str] = None) -> List[str]:
        seen = []
        seen_set = set()
        for item in self.items:
            if kind and item.kind != kind:
                continue
            if item.value not in seen_set:
                seen_set.add(item.value)
                seen.append(item.value)
        return seen

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_iocs': len(self.items),
            'items': [item.to_dict() for item in self.items],
            'stream_hashes': self.stream_hashes,
        }

    def summary_text(self) -> str:
        if not self.items and not self.stream_hashes:
            return 'No se encontraron IOCs en los datos analizados.'
        lines = [f'=== Reporte de IOCs ({len(self.items)} hallazgos únicos) ===']
        grouped = self.by_kind()
        for kind in sorted(grouped):
            vals = grouped[kind]
            lines.append(f'\n[{kind.upper()}] ({len(vals)})')
            for it in vals[:50]:
                ctx = f' · {it.context}' if it.context else ''
                lines.append(f'  - {it.value} (fd={it.fd} {it.direction}, conf={it.confidence}{ctx})')
        if self.stream_hashes:
            lines.append(f'\n[PAYLOAD HASHES] ({len(self.stream_hashes)})')
            for key, info in list(self.stream_hashes.items())[:30]:
                lines.append(f'  - {key}: sha256={info["sha256"]} ({info["bytes"]} B)')
        return '\n'.join(lines)


class IOCExtractor:
    """Extrae indicadores de compromiso (IOCs) de streams o payloads."""

    _URL_RE = re.compile(r'https?://[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+')
    _IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
    _DOMAIN_RE = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(?:com|net|org|io|co|local|dev|app|xyz|ru|cn|info|biz|me|tv|cc|tk|uk|de|fr|es|cl|br|ar|mx|gov|edu)\b',
        re.IGNORECASE,
    )
    _EMAIL_RE = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}\b')
    _SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
    _MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
    _HEADER_RE = re.compile(
        r'(?im)^(Authorization|X-Api-Key|X-Auth-Token|User-Agent|Host):\s*([^\r\n]+?)\r?$'
    )
    _C2_HINTS = (
        re.compile(r'(?i)(?:powershell(?:\.exe)?\s+-(?:enc|encodedcommand|w\s+hidden))'),
        re.compile(r'(?i)(?:cmd\.exe\s+/c|/bin/(?:ba)?sh)'),
        re.compile(r'(?i)(?:/beacon|/checkin|/gate\.php|c2-[a-z0-9-]+)'),
        re.compile(r'X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*'),
    )

    def __init__(self):
        self._decoder = BinaryDecoder()

    def extract_from_bytes(self, data: bytes, fd: int = -1,
                           direction: str = 'raw',
                           peer: str = '') -> List[IOCItem]:
        if not data:
            return []
        candidates = [data]
        decompressed = self._decoder.try_decompress(data)
        if decompressed:
            candidates.append(decompressed)

        found: List[IOCItem] = []
        seen = set()

        def add(kind: str, value: str, context: str = '', confidence: str = 'medium'):
            val = value.strip()
            if not val:
                return
            key = (kind, val, fd, direction)
            if key in seen:
                return
            seen.add(key)
            found.append(IOCItem(
                kind=kind, value=val, fd=fd, direction=direction,
                context=context, confidence=confidence,
            ))

        for buf in candidates:
            text = buf.decode('utf-8', errors='ignore')
            for m in self._URL_RE.finditer(text):
                url = m.group(0).rstrip('.,;)\'"')
                add('url', url, context=peer or 'payload', confidence='high')

            for m in self._EMAIL_RE.finditer(text):
                add('email', m.group(0), context='payload', confidence='medium')

            for m in self._IPV4_RE.finditer(text):
                ip_s = m.group(0)
                try:
                    ip_obj = ipaddress.ip_address(ip_s)
                    scope = 'loopback' if ip_obj.is_loopback else ('private' if ip_obj.is_private else 'public')
                    conf = 'high' if scope == 'public' else 'low'
                    add('ipv4', ip_s, context=f'payload ({scope})', confidence=conf)
                except ValueError:
                    pass

            for m in self._DOMAIN_RE.finditer(text):
                dom = m.group(0).lower()
                add('domain', dom, context='payload', confidence='medium')

            for m in self._HEADER_RE.finditer(text):
                hname, hval = m.group(1), m.group(2).strip()
                if hname.lower() == 'host':
                    dom = hval.split(':')[0].lower()
                    if not dom.replace('.', '').isdigit():
                        add('domain', dom, context='HTTP Host', confidence='high')
                elif hname.lower() in ('authorization', 'x-api-key', 'x-auth-token'):
                    preview = hval[:24] + ('…' if len(hval) > 24 else '')
                    add('header', f'{hname}: {preview}', context='credential/token', confidence='high')
                elif hname.lower() == 'user-agent':
                    low_ua = hval.lower()
                    if any(tok in low_ua for tok in ('powershell', 'curl', 'python', 'wget', 'go-http')):
                        add('header', f'User-Agent: {hval[:80]}', context='scripted UA', confidence='medium')

            for pat in self._C2_HINTS:
                for m in pat.finditer(text):
                    add('c2', m.group(0)[:120], context='heuristic match', confidence='high')

            for m in self._SHA256_RE.finditer(text):
                add('sha256', m.group(0).lower(), context='string hash', confidence='low')

        return found

    def extract_from_streams(self, streams: Iterable[Any],
                             dns_map: Optional[Dict[str, str]] = None) -> IOCReport:
        all_items: List[IOCItem] = []
        seen_global = set()
        stream_hashes: Dict[str, Dict[str, Any]] = {}

        def append_unique(item: IOCItem):
            key = (item.kind, item.value, item.fd, item.direction)
            if key not in seen_global:
                seen_global.add(key)
                all_items.append(item)

        for st in streams:
            fd = getattr(st, 'fd', -1)
            peer = getattr(st, 'peer', '?')
            peer_ip = getattr(st, 'peer_ip', None)
            peer_host = getattr(st, 'peer_host', None)

            if peer_ip:
                try:
                    ip_obj = ipaddress.ip_address(peer_ip)
                    scope = 'loopback' if ip_obj.is_loopback else ('private' if ip_obj.is_private else 'public')
                    append_unique(IOCItem(
                        kind='ipv4' if ip_obj.version == 4 else 'ipv6',
                        value=peer_ip,
                        fd=fd,
                        direction='peer',
                        context=f'socket peer ({scope})',
                        confidence='high' if scope == 'public' else 'low',
                    ))
                except ValueError:
                    pass
            if peer_host:
                append_unique(IOCItem(
                    kind='domain',
                    value=peer_host,
                    fd=fd,
                    direction='peer',
                    context=f'resolved peer ({peer})',
                    confidence='high',
                ))

            for direction, attr in (('out', 'out_data'), ('in', 'in_data')):
                buf = bytes(getattr(st, attr, b'') or b'')
                if not buf:
                    continue
                sha256_hex = hashlib.sha256(buf).hexdigest()
                md5_hex = hashlib.md5(buf).hexdigest()
                stream_hashes[f'fd={fd}:{direction}'] = {
                    'fd': fd,
                    'direction': direction,
                    'bytes': len(buf),
                    'sha256': sha256_hex,
                    'md5': md5_hex,
                }
                for item in self.extract_from_bytes(buf, fd=fd, direction=direction, peer=peer):
                    append_unique(item)

        if dns_map:
            for ip, host in dns_map.items():
                append_unique(IOCItem(
                    kind='domain', value=host, fd=-1, direction='dns',
                    context=f'DNS -> {ip}', confidence='high',
                ))

        return IOCReport(items=all_items, stream_hashes=stream_hashes)


# ---------------- Motor YARA puro en Python + puente opcional yara-python ----------------

@dataclass
class YaraStringMatch:
    identifier: str
    offset: int
    matched_hex: str
    matched_ascii: str


@dataclass
class YaraMatch:
    rule: str
    tags: List[str]
    meta: Dict[str, Any]
    fd: int
    direction: str
    strings: List[YaraStringMatch] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule': self.rule,
            'tags': list(self.tags),
            'meta': dict(self.meta),
            'fd': self.fd,
            'direction': self.direction,
            'strings': [
                {
                    'identifier': s.identifier,
                    'offset': s.offset,
                    'hex': s.matched_hex,
                    'ascii': s.matched_ascii,
                }
                for s in self.strings
            ],
        }


@dataclass
class _CompiledString:
    ident: str
    patterns: List[re.Pattern]


@dataclass
class _CompiledRule:
    name: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: Dict[str, _CompiledString]
    condition: str


def _strip_yara_comments(text: str) -> str:
    out = []
    i = 0
    n = len(text)
    in_str = False
    in_regex = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == '\\' and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if in_regex:
            out.append(ch)
            if ch == '\\' and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '/':
                in_regex = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                i += 1
            continue
        if ch == '/' and i + 1 < n and text[i + 1] == '*':
            i += 2
            while i + 1 < n and not (text[i] == '*' and text[i + 1] == '/'):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def _split_rules(source: str) -> List[Tuple[str, List[str], str]]:
    clean = _strip_yara_comments(source)
    rules: List[Tuple[str, List[str], str]] = []
    header_re = re.compile(r'\brule\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*:\s*([^{]+))?\s*\{')
    pos = 0
    while True:
        m = header_re.search(clean, pos)
        if not m:
            break
        name = m.group(1)
        tags = [t.strip() for t in (m.group(2) or '').split() if t.strip()]
        brace_start = m.end() - 1
        depth = 0
        i = brace_start
        in_str = False
        while i < len(clean):
            c = clean[i]
            if in_str:
                if c == '\\':
                    i += 2
                    continue
                if c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        body = clean[brace_start + 1:i]
                        rules.append((name, tags, body))
                        pos = i + 1
                        break
            i += 1
        else:
            raise ValueError(f'Llave sin cerrar en regla YARA "{name}"')
    return rules


def _compile_hex_string(hex_body: str) -> re.Pattern:
    tokens = hex_body.strip().split()
    parts: List[bytes] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == '??':
            parts.append(b'.')
        elif tok.startswith('[') and tok.endswith(']'):
            inner = tok[1:-1].strip()
            if '-' in inner:
                lo, hi = inner.split('-', 1)
                lo_s = lo.strip() or '0'
                hi_s = hi.strip() or ''
                parts.append(f'.{{{lo_s},{hi_s}}}'.encode('ascii'))
            else:
                parts.append(f'.{{{int(inner)}}}'.encode('ascii'))
        elif len(tok) == 2 and all(c in '0123456789abcdefABCDEF' for c in tok):
            bval = bytes([int(tok, 16)])
            parts.append(re.escape(bval))
        elif len(tok) == 2 and '?' in tok:
            # Nibbles parciales (A? o ?A)
            hi = tok[0]
            lo = tok[1]
            opts = []
            for v in range(256):
                hv = f'{v:02X}'
                if (hi == '?' or hv[0] == hi.upper()) and (lo == '?' or hv[1] == lo.upper()):
                    opts.append(re.escape(bytes([v])))
            parts.append(b'(?:' + b'|'.join(opts) + b')')
        else:
            raise ValueError(f'Token hex YARA no soportado: {tok!r}')
        i += 1
    return re.compile(b''.join(parts), re.DOTALL)


def _unescape_yara_str(raw: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == '\\' and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt == 'n':
                out.append(10)
            elif nxt == 'r':
                out.append(13)
            elif nxt == 't':
                out.append(9)
            elif nxt == '\\':
                out.append(92)
            elif nxt == '"':
                out.append(34)
            elif nxt == 'x' and i + 3 < len(raw):
                out.append(int(raw[i + 2:i + 4], 16))
                i += 4
                continue
            else:
                out.extend(nxt.encode('latin-1'))
            i += 2
        else:
            out.extend(raw[i].encode('latin-1', errors='replace'))
            i += 1
    return bytes(out)


def _compile_text_string(raw: str, modifiers: List[str]) -> List[re.Pattern]:
    base = _unescape_yara_str(raw)
    flags = re.IGNORECASE if 'nocase' in modifiers else 0
    want_wide = 'wide' in modifiers
    want_ascii = 'ascii' in modifiers or not want_wide
    fullword = 'fullword' in modifiers
    patterns: List[re.Pattern] = []
    if want_ascii:
        pat = re.escape(base)
        if fullword:
            pat = rb'(?<![A-Za-z0-9_])' + pat + rb'(?![A-Za-z0-9_])'
        patterns.append(re.compile(pat, flags))
    if want_wide:
        wide_bytes = b''.join(bytes([b, 0]) for b in base)
        pat = re.escape(wide_bytes)
        patterns.append(re.compile(pat, flags))
    return patterns


def _parse_rule_sections(body: str) -> Tuple[Dict[str, Any], Dict[str, _CompiledString], str]:
    sec_re = re.compile(r'\b(meta|strings|condition)\s*:')
    matches = list(sec_re.finditer(body))
    sections: Dict[str, str] = {}
    for idx, m in enumerate(matches):
        sec_name = m.group(1)
        start = m.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(body)
        sections[sec_name] = body[start:end].strip()

    meta: Dict[str, Any] = {}
    if 'meta' in sections:
        for line in sections['meta'].splitlines():
            line = line.strip()
            if '=' not in line:
                continue
            k, v = line.split('=', 1)
            k = k.strip()
            v = v.strip()
            if v.startswith('"') and v.endswith('"'):
                meta[k] = v[1:-1]
            elif v.lower() in ('true', 'false'):
                meta[k] = v.lower() == 'true'
            else:
                try:
                    meta[k] = int(v, 0)
                except ValueError:
                    meta[k] = v

    compiled_strings: Dict[str, _CompiledString] = {}
    if 'strings' in sections:
        str_re = re.compile(
            r'(\$[A-Za-z0-9_]+)\s*=\s*'
            r'(?:"((?:\\.|[^"\\])*)"([^\r\n]*)|'
            r'\{([^}]*)\}|'
            r'/((?:\\.|[^/\\])*)/([a-zA-Z]*))'
        )
        for m in str_re.finditer(sections['strings']):
            ident = m.group(1)
            if m.group(2) is not None:
                mods = [w.strip().lower() for w in (m.group(3) or '').split() if w.strip()]
                pats = _compile_text_string(m.group(2), mods)
            elif m.group(4) is not None:
                pats = [_compile_hex_string(m.group(4))]
            else:
                rflags = 0
                mod_chars = (m.group(6) or '').lower()
                if 'i' in mod_chars:
                    rflags |= re.IGNORECASE
                if 's' in mod_chars:
                    rflags |= re.DOTALL
                if 'm' in mod_chars:
                    rflags |= re.MULTILINE
                pats = [re.compile(m.group(5).encode('latin-1'), rflags)]
            compiled_strings[ident] = _CompiledString(ident=ident, patterns=pats)

    condition = sections.get('condition', 'any of them')
    return meta, compiled_strings, condition


class _ConditionEvaluator:
    """Evaluador seguro de expresiones condition de YARA sin eval() arbitrario."""

    _TOK_RE = re.compile(
        r'\s*(?:(\d+|0x[0-9a-fA-F]+)|'
        r'([#$@!][A-Za-z0-9_*]+)|'
        r'(==|!=|<=|>=|<|>|\(|\)|,)|'
        r'([A-Za-z_][A-Za-z0-9_]*))'
    )

    def __init__(self, data: bytes, hits: Dict[str, List[Tuple[int, bytes]]], all_idents: List[str]):
        self.data = data
        self.hits = hits
        self.all_idents = all_idents
        self.tokens = self._tokenize_expr('')

    def evaluate(self, condition: str) -> bool:
        self.tokens = self._tokenize_expr(condition)
        self.pos = 0
        if not self.tokens:
            return False
        res = self._parse_or()
        return bool(res)

    def _tokenize_expr(self, expr: str) -> List[str]:
        tokens = []
        idx = 0
        while idx < len(expr):
            m = self._TOK_RE.match(expr, idx)
            if not m:
                idx += 1
                continue
            tok = m.group(1) or m.group(2) or m.group(3) or m.group(4)
            tokens.append(tok)
            idx = m.end()
        return tokens

    def _peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self) -> Optional[str]:
        tok = self._peek()
        if tok is not None:
            self.pos += 1
        return tok

    def _parse_or(self):
        left = self._parse_and()
        while self._peek() == 'or':
            self._consume()
            right = self._parse_and()
            left = bool(left) or bool(right)
        return left

    def _parse_and(self):
        left = self._parse_not()
        while self._peek() == 'and':
            self._consume()
            right = self._parse_not()
            left = bool(left) and bool(right)
        return left

    def _parse_not(self):
        if self._peek() == 'not':
            self._consume()
            return not bool(self._parse_not())
        return self._parse_cmp()

    def _parse_cmp(self):
        left = self._parse_primary()
        op = self._peek()
        if op in ('==', '!=', '<', '<=', '>', '>='):
            self._consume()
            right = self._parse_primary()
            if op == '==':
                return left == right
            if op == '!=':
                return left != right
            if op == '<':
                return left < right
            if op == '<=':
                return left <= right
            if op == '>':
                return left > right
            if op == '>=':
                return left >= right
        if op == 'at':
            self._consume()
            offset = int(self._parse_primary())
            if isinstance(left, str) and left.startswith('$'):
                return any(off == offset for off, _ in self.hits.get(left, ()))
            return False
        return left

    def _resolve_set(self) -> List[str]:
        if self._peek() == 'them':
            self._consume()
            return list(self.all_idents)
        if self._peek() == '(':
            self._consume()
            idents: List[str] = []
            while self._peek() and self._peek() != ')':
                tok = self._consume()
                if tok == ',':
                    continue
                if tok.endswith('*'):
                    prefix = tok[:-1]
                    idents.extend(i for i in self.all_idents if i.startswith(prefix))
                else:
                    idents.append(tok)
            if self._peek() == ')':
                self._consume()
            return idents
        return []

    def _parse_primary(self):
        tok = self._peek()
        if tok is None:
            return False
        if tok == '(':
            self._consume()
            val = self._parse_or()
            if self._peek() == ')':
                self._consume()
            return val
        if tok in ('true', 'false'):
            self._consume()
            return tok == 'true'
        if tok == 'filesize':
            self._consume()
            return len(self.data)
        if tok in ('uint8', 'uint16', 'uint32', 'uint16be', 'uint32be'):
            self._consume()
            if self._peek() == '(':
                self._consume()
            off = int(self._parse_or())
            if self._peek() == ')':
                self._consume()
            fmt_map = {
                'uint8': ('<B', 1),
                'uint16': ('<H', 2),
                'uint32': ('<I', 4),
                'uint16be': ('>H', 2),
                'uint32be': ('>I', 4),
            }
            fmt, sz = fmt_map[tok]
            if off < 0 or off + sz > len(self.data):
                return -1
            return struct.unpack_from(fmt, self.data, off)[0]
        if tok in ('any', 'all', 'none') and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1] == 'of':
            self._consume()
            self._consume()  # 'of'
            idents = self._resolve_set()
            matched = sum(1 for i in idents if self.hits.get(i))
            if tok == 'any':
                return matched >= 1
            if tok == 'all':
                return bool(idents) and matched == len(idents)
            return matched == 0
        if tok.isdigit() or tok.startswith('0x'):
            self._consume()
            val = int(tok, 0)
            if self._peek() == 'of':
                self._consume()
                idents = self._resolve_set()
                matched = sum(1 for i in idents if self.hits.get(i))
                return matched >= val
            return val
        if tok.startswith('#'):
            self._consume()
            ident = '$' + tok[1:]
            return len(self.hits.get(ident, ()))
        if tok.startswith('@'):
            self._consume()
            ident = '$' + tok[1:]
            matches = self.hits.get(ident, ())
            return matches[0][0] if matches else -1
        if tok.startswith('$'):
            self._consume()
            if self._peek() == 'at':
                # Defer 'at' handling to _parse_cmp
                return tok
            return bool(self.hits.get(tok))
        self._consume()
        return False


class YaraScanner:
    """Escáner de reglas YARA (con reglas built-in y soporte de reglas personalizadas)."""

    def __init__(self, rules_text: Optional[str] = None,
                 include_builtin: bool = True):
        sources: List[str] = []
        if include_builtin:
            sources.append(BUILTIN_YARA_RULES)
        if rules_text and rules_text.strip():
            sources.append(rules_text)
        self.source = '\n\n'.join(sources)
        self._compiled: List[_CompiledRule] = []
        self._yara_rules = None
        self.engine_name = 'python-builtin'
        self._compile(self.source)

    def _compile(self, source: str) -> None:
        if not source.strip():
            self._compiled = []
            return
        if _yara_mod is not None:
            try:
                self._yara_rules = _yara_mod.compile(source=source)
                self.engine_name = 'yara-python'
            except Exception:
                self._yara_rules = None
        parsed = _split_rules(source)
        compiled: List[_CompiledRule] = []
        for name, tags, body in parsed:
            meta, strings, condition = _parse_rule_sections(body)
            compiled.append(_CompiledRule(
                name=name, tags=tags, meta=meta, strings=strings, condition=condition,
            ))
        self._compiled = compiled

    @classmethod
    def from_file(cls, path: str, include_builtin: bool = True) -> 'YaraScanner':
        with open(path, 'r', encoding='utf-8') as f:
            return cls(rules_text=f.read(), include_builtin=include_builtin)

    def scan_bytes(self, data: bytes, fd: int = -1,
                   direction: str = 'raw') -> List[YaraMatch]:
        if not data:
            return []
        if self._yara_rules is not None:
            out: List[YaraMatch] = []
            for m in self._yara_rules.match(data=data):
                s_matches: List[YaraStringMatch] = []
                for sm in getattr(m, 'strings', ()):
                    ident = getattr(sm, 'identifier', '$s')
                    for inst in getattr(sm, 'instances', ()):
                        raw = bytes(getattr(inst, 'matched_data', b''))
                        s_matches.append(YaraStringMatch(
                            identifier=ident,
                            offset=int(getattr(inst, 'offset', 0)),
                            matched_hex=raw[:32].hex(),
                            matched_ascii=raw[:64].decode('latin-1', errors='replace'),
                        ))
                out.append(YaraMatch(
                    rule=m.rule, tags=list(m.tags), meta=dict(m.meta),
                    fd=fd, direction=direction, strings=s_matches,
                ))
            return out

        matches: List[YaraMatch] = []
        for rule in self._compiled:
            hits: Dict[str, List[Tuple[int, bytes]]] = {}
            for ident, cstr in rule.strings.items():
                ihits: List[Tuple[int, bytes]] = []
                for pat in cstr.patterns:
                    for pm in pat.finditer(data):
                        ihits.append((pm.start(), pm.group(0)))
                        if len(ihits) >= 32:
                            break
                if ihits:
                    ihits.sort(key=lambda x: x[0])
                    hits[ident] = ihits
            ev = _ConditionEvaluator(data, hits, list(rule.strings.keys()))
            if ev.evaluate(rule.condition):
                s_matches = []
                for ident, ihits in hits.items():
                    for off, matched in ihits[:8]:
                        s_matches.append(YaraStringMatch(
                            identifier=ident,
                            offset=off,
                            matched_hex=matched[:32].hex(),
                            matched_ascii=matched[:64].decode('latin-1', errors='replace'),
                        ))
                matches.append(YaraMatch(
                    rule=rule.name, tags=list(rule.tags), meta=dict(rule.meta),
                    fd=fd, direction=direction, strings=s_matches,
                ))
        return matches

    def scan_streams(self, streams: Iterable[Any]) -> List[YaraMatch]:
        decoder = BinaryDecoder()
        results: List[YaraMatch] = []
        for st in streams:
            fd = getattr(st, 'fd', -1)
            for direction, attr in (('out', 'out_data'), ('in', 'in_data')):
                buf = bytes(getattr(st, attr, b'') or b'')
                if not buf:
                    continue
                results.extend(self.scan_bytes(buf, fd=fd, direction=direction))
                dec = decoder.try_decompress(buf)
                if dec:
                    results.extend(self.scan_bytes(dec, fd=fd, direction=f'{direction}:decompressed'))
        return results
