"""Búsqueda incremental en los buffers retenidos de streams."""


class StreamSearchIndex:
    """Busca un patrón sin volver a escanear buffers que no cambiaron."""

    def __init__(self):
        self._query = None
        self._pattern = b''
        self._case_insensitive = True
        self._states = {}

    def update(self, streams, query):
        text = query.strip()
        if not text:
            self._query = None
            self._states.clear()
            return set()

        is_hex = text.casefold().startswith('hex:')
        pattern_text = text[4:].strip() if is_hex else text
        query_key = ('hex:' if is_hex else 'text:') + pattern_text.lower()
        if query_key != self._query:
            if is_hex:
                try:
                    self._pattern = bytes.fromhex(pattern_text)
                except ValueError as exc:
                    raise ValueError('usa hex: seguido de pares hexadecimales') from exc
                if not self._pattern:
                    raise ValueError('indica al menos un byte después de hex:')
                self._case_insensitive = False
            elif any(char.isspace() for char in text):
                try:
                    self._pattern = bytes.fromhex(text)
                    self._case_insensitive = False
                except ValueError:
                    self._pattern = text.encode('utf-8', 'ignore').lower()
                    self._case_insensitive = True
            else:
                self._pattern = text.encode('utf-8', 'ignore').lower()
                self._case_insensitive = True
            self._query = query_key
            self._states.clear()

        hits = set()
        active_fds = set()
        for stream in streams:
            fd = stream.fd
            active_fds.add(fd)
            state = self._states.get(fd)
            if state is None or state['stream'] is not stream:
                state = {
                    'stream': stream,
                    'out_generation': -1,
                    'in_generation': -1,
                    'byte_out': 0,
                    'byte_in': 0,
                    'out_tail': b'',
                    'in_tail': b'',
                    'out_match': False,
                    'in_match': False,
                }

            state['out_match'] = self._update_direction(
                stream.out_data, stream.byte_out, stream.out_generation,
                state, 'out')
            state['in_match'] = self._update_direction(
                stream.in_data, stream.byte_in, stream.in_generation,
                state, 'in')
            if state['out_match'] or state['in_match']:
                hits.add(fd)
            self._states[fd] = state

        for fd in self._states.keys() - active_fds:
            del self._states[fd]
        return hits

    def _update_direction(self, buffer, total, generation, state, direction):
        generation_key = f'{direction}_generation'
        total_key = f'byte_{direction}'
        tail_key = f'{direction}_tail'
        match_key = f'{direction}_match'
        previous_generation = state[generation_key]
        previous_total = state[total_key]

        if previous_generation == generation and total >= previous_total:
            added = total - previous_total
            start = max(0, len(buffer) - added)
            data = bytes(buffer[start:])
            data = self._normalize(data)
            searchable = state[tail_key] + data
            matched = state[match_key] or self._pattern in searchable
        else:
            data = self._normalize(bytes(buffer))
            searchable = data
            matched = self._pattern in searchable

        overlap = max(0, len(self._pattern) - 1)
        state[tail_key] = searchable[-overlap:] if overlap else b''
        state[generation_key] = generation
        state[total_key] = total
        return matched

    def _normalize(self, data):
        return data.lower() if self._case_insensitive else data
