"""Frida runner for the read-only numeric observation probe."""
import json
import threading
from pathlib import Path
from typing import Callable, Optional

import frida


CONFIG_MARKER = '/* NETSCOPE_CONFIG_INJECTION */'


class FridaNumericProbe:
    """Attaches a read-only probe to one process and reports its console output."""

    def __init__(self, on_log: Callable[[str], None],
                 on_event: Optional[Callable[[dict], None]] = None):
        self.on_log = on_log
        self.on_event = on_event or (lambda _event: None)
        self._lock = threading.RLock()
        self._session: Optional[frida.core.Session] = None
        self._scripts = []

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._session is not None

    def start(self, pid: int, config: dict, script_path: str,
              bridge_path: Optional[str] = None):
        mode = config.get('mode')
        valid_modes = ('native', 'il2cpp')
        if mode not in valid_modes:
            raise ValueError(
                'El modo de sonda debe ser: ' + ', '.join(valid_modes) + '.')
        if mode == 'il2cpp' and not bridge_path:
            raise ValueError(
                'Selecciona el bundle JavaScript de frida-il2cpp-bridge '
                'para usar el modo Unity/IL2CPP.'
            )

        source = Path(script_path).read_text(encoding='utf-8')
        if CONFIG_MARKER not in source:
            raise ValueError(
                'El script no contiene el marcador de configuración esperado.'
            )
        injected_config = (
            'globalThis.NETSCOPE_CONFIG = ' +
            json.dumps(config, ensure_ascii=True) + ';'
        )
        source = source.replace(CONFIG_MARKER, injected_config, 1)

        with self._lock:
            if self._session is not None:
                raise RuntimeError('La sonda ya está conectada a un proceso.')

            session = frida.get_local_device().attach(pid)
            scripts = []
            try:
                if bridge_path:
                    # Los scripts de Frida tienen realms JS aislados: el
                    # globalThis.Il2Cpp del bridge NO es visible desde otro
                    # script. La CLI de frida concatena los `-l` en un solo
                    # script; aquí reproducimos ese comportamiento cargando
                    # bridge + sonda como UN único script.
                    bridge_source = Path(bridge_path).read_text(encoding='utf-8')
                    combined = bridge_source + '\n;\n' + source
                    probe = session.create_script(combined)
                    probe.on('message', self._on_message)
                    probe.load()
                    scripts.append(probe)
                else:
                    probe = session.create_script(source)
                    probe.on('message', self._on_message)
                    probe.load()
                    scripts.append(probe)
            except Exception:
                for script in reversed(scripts):
                    try:
                        script.unload()
                    except Exception as cleanup_error:
                        self.on_log(
                            '[!] No se pudo limpiar un script de sonda: ' +
                            str(cleanup_error)
                        )
                try:
                    session.detach()
                except Exception as cleanup_error:
                    self.on_log(
                        '[!] No se pudo cerrar la conexión de la sonda: ' +
                        str(cleanup_error)
                    )
                raise

            self._session = session
            self._scripts = scripts
            self.on_log(f'[i] Sonda conectada al PID {pid}.')

    def stop(self):
        with self._lock:
            session = self._session
            scripts = self._scripts
            self._session = None
            self._scripts = []
            if session is None:
                return

            errors = []
            for script in reversed(scripts):
                try:
                    script.unload()
                except Exception as error:
                    errors.append(f'No se pudo descargar un script: {error}')
            try:
                session.detach()
            except Exception as error:
                errors.append(f'No se pudo cerrar la sesión de la sonda: {error}')

            if errors:
                raise RuntimeError('; '.join(errors))
            self.on_log('[i] Sonda detenida y desconectada.')

    def _on_message(self, message, _data):
        message_type = message.get('type')
        if message_type == 'log':
            self.on_log(str(message.get('payload', '')))
        elif message_type == 'error':
            description = message.get('description', 'Error Frida sin descripción.')
            stack = message.get('stack')
            self.on_log(
                '[!] ' + str(description) +
                (('\n' + str(stack)) if stack else '')
            )
        elif message_type == 'send':
            payload = message.get('payload', {})
            if isinstance(payload, dict) and payload.get('event') in (
                    'diagnostic_profile', 'function_observation'):
                self.on_event(payload)
            else:
                self.on_log('[i] ' + str(payload))
        else:
            self.on_log('[i] Mensaje Frida: ' + str(message))
