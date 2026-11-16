# -*- coding: utf-8 -*-
"""Monitorea cambios de payload Winsock sobre loopback en procesos Windows."""
import argparse
import hashlib
import ipaddress
import json
import sys
import threading
import time
import zlib


MAX_SAMPLE_BYTES = 4096
MAX_DECOMPRESSED_BYTES = 1024 * 1024
MAX_DISPLAY_CHARS = 2048
POLL_INTERVAL = 0.5
ATTACH_RETRY_INTERVAL = 3.0


def _try_decompress(data):
    for name, window_bits in (
        ("zlib", zlib.MAX_WBITS),
        ("gzip", zlib.MAX_WBITS | 16),
        ("deflate", -zlib.MAX_WBITS),
    ):
        decoder = zlib.decompressobj(window_bits)
        try:
            decoded = decoder.decompress(data, MAX_DECOMPRESSED_BYTES + 1)
        except zlib.error:
            continue
        if len(decoded) > MAX_DECOMPRESSED_BYTES:
            return name, None
        if decoder.eof and not decoder.unused_data:
            return name, decoded
    return None, None


def _length_prefixed_frames(data):
    for width in (4, 2):
        for byte_order in ("big", "little"):
            frames = []
            offset = 0
            while offset + width <= len(data):
                length = int.from_bytes(
                    data[offset:offset + width], byte_order)
                offset += width
                if length == 0 or offset + length > len(data):
                    break
                frames.append(data[offset:offset + length])
                offset += length
            if frames and offset == len(data):
                return f"{width * 8}-bit {byte_order}-endian length", frames
    return None, []


def _delimited_frames(data):
    for delimiter, name in ((b"\x00", "NUL"), (b"\n", "newline")):
        if delimiter not in data:
            continue
        frames = [part.rstrip(b"\r") for part in data.split(delimiter)]
        frames = [part for part in frames if part]
        if len(frames) > 1:
            return name, frames
    return None, []


def _format_frame(frame):
    try:
        text = frame.decode("utf-8")
    except UnicodeDecodeError:
        return frame[:64].hex(" ") + (" ..." if len(frame) > 64 else "")
    if all(char.isprintable() or char in "\r\n\t" for char in text):
        return text
    return frame[:64].hex(" ") + (" ..." if len(frame) > 64 else "")


def _format_payload(data):
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = None

    if text is not None:
        try:
            value = json.loads(text)
            formatted = json.dumps(value, ensure_ascii=False, indent=2)
        except (json.JSONDecodeError, RecursionError):
            pass
        else:
            return "JSON:\n" + formatted

    framing, frames = _length_prefixed_frames(data)
    if not frames:
        framing, frames = _delimited_frames(data)
    if frames:
        rendered = [f"[{index}] {_format_frame(frame)}"
                    for index, frame in enumerate(frames, 1)]
        return f"Paquetes ({framing}, {len(frames)}):\n" + "\n".join(rendered)

    if text is not None and all(
            char.isprintable() or char in "\r\n\t" for char in text):
        return text.rstrip("\x00") or "(texto vacío)"
    preview = data[:128].hex(" ")
    if len(data) > 128:
        preview += " ..."
    return f"Binario (hex): {preview}"


def decode_payload(data):
    """Descomprime y representa un bloque como JSON, texto o estructura básica."""
    compression, decoded = _try_decompress(data)
    if compression and decoded is None:
        return (
            f"Compresión {compression} detectada; "
            f"salida supera el límite de {MAX_DECOMPRESSED_BYTES} bytes."
        )
    if decoded is not None:
        data = decoded
        result = f"Descomprimido ({compression}, {len(data)} bytes):\n"
    else:
        result = ""
    formatted = _format_payload(data)
    if len(formatted) > MAX_DISPLAY_CHARS:
        formatted = formatted[:MAX_DISPLAY_CHARS] + "\n… (vista truncada)"
    return result + formatted


def is_loopback_peer(peer):
    if not isinstance(peer, dict):
        return False
    address = peer.get("ip")
    if not isinstance(address, str):
        return False
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped.is_loopback
    return parsed.is_loopback


def matching_processes(processes, name):
    target = name.casefold()
    return [process for process in processes
            if process.name.casefold() == target]


class PayloadTransitions:
    def __init__(self):
        self._last = {}
        self._lock = threading.Lock()

    def changed(self, pid, fd, proto, direction, peer, data):
        digest = hashlib.sha256(data).hexdigest()
        key = (pid, fd, proto, direction, peer)
        with self._lock:
            if self._last.get(key) == digest:
                return None
            self._last[key] = digest
        return digest

    def clear_fd(self, pid, fd):
        with self._lock:
            self._last = {
                key: value for key, value in self._last.items()
                if key[0] != pid or key[1] != fd
            }


FRIDA_AGENT = r"""
'use strict';

const MAX_SAMPLE_BYTES = __MAX_SAMPLE_BYTES__;
const MAX_WSA_BUFS = 64;
const peers = {};
const socketTypes = {};

function ws2(name) {
    try {
        return Process.getModuleByName('ws2_32.dll').getExportByName(name);
    } catch (e) {
        return Module.getGlobalExportByName('ws2_32.dll', name);
    }
}

function sockaddrToObj(sa) {
    if (!sa || sa.isNull()) return null;
    try {
        const family = sa.readU16();
        const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
        if (family === 2) {
            return { ip: new Uint8Array(sa.add(4).readByteArray(4)).join('.'),
                port: port };
        }
        if (family === 23) {
            const parts = [];
            for (let i = 0; i < 8; i++) {
                const offset = 8 + i * 2;
                parts.push(((sa.add(offset).readU8() << 8) |
                    sa.add(offset + 1).readU8()).toString(16));
            }
            return { ip: parts.join(':'), port: port };
        }
    } catch (e) {}
    return null;
}

function isLoopback(peer) {
    if (!peer || !peer.ip) return false;
    if (peer.ip.indexOf('127.') === 0) return true;
    const parts = peer.ip.toLowerCase().split(':');
    if (parts.length !== 8) return peer.ip === '::1';
    if (parts.slice(0, 7).every(part => part === '0') && parts[7] === '1') {
        return true;
    }
    return parts.slice(0, 5).every(part => part === '0') &&
        parts[5] === 'ffff' &&
        (parseInt(parts[6], 16) >> 8) === 127;
}

function lookupPeer(fd) {
    if (peers[fd]) return peers[fd];
    try {
        const address = Memory.alloc(32);
        const length = Memory.alloc(Process.pointerSize);
        length.writeULong(32);
        if (new NativeFunction(ws2('getpeername'), 'int',
            ['int', 'pointer', 'pointer'])(fd, address, length) === 0) {
            return sockaddrToObj(address);
        }
    } catch (e) {}
    return null;
}

function emitPayload(fd, proto, direction, peer, buffer, length) {
    if (length <= 0 || !isLoopback(peer)) return;
    const sampleLength = Math.min(length, MAX_SAMPLE_BYTES);
    try {
        send({
            event: 'payload', fd: fd, proto: proto || '?',
            direction: direction, peer: peer, length: length,
            truncated: length > sampleLength
        }, buffer.readByteArray(sampleLength));
    } catch (e) {
        send({ event: 'hook_error', detail: String(e) });
    }
}

function emitWsaBuffers(fd, proto, direction, peer, buffers, totalLength) {
    let remaining = totalLength;
    for (let i = 0; i < buffers.length && remaining > 0; i++) {
        const length = Math.min(buffers[i].length, remaining);
        emitPayload(fd, proto, direction, peer, buffers[i].buffer, length);
        remaining -= length;
    }
}

function readWsaBuffers(array, count) {
    const buffers = [];
    const n = Math.min(Math.max(count, 0), MAX_WSA_BUFS);
    for (let i = 0; i < n; i++) {
        const entry = array.add(i * Process.pointerSize * 2);
        buffers.push({
            length: entry.readU32(),
            buffer: entry.add(Process.pointerSize).readPointer()
        });
    }
    return buffers;
}

function attachHook(name, callbacks) {
    try {
        Interceptor.attach(ws2(name), callbacks);
    } catch (e) {
        send({ event: 'hook_error', detail: name + ': ' + String(e) });
    }
}

attachHook('socket', {
    onEnter(args) { this.type = args[1].toInt32() & 0xf; },
    onLeave(retval) {
        const fd = retval.toInt32();
        if (fd !== -1) socketTypes[fd] = this.type === 2 ? 'UDP' : 'TCP';
    }
});

attachHook('connect', {
    onEnter(args) {
        const fd = args[0].toInt32();
        const peer = sockaddrToObj(args[1]);
        if (peer) peers[fd] = peer;
    }
});

attachHook('accept', {
    onEnter(args) { this.address = args[1]; },
    onLeave(retval) {
        const fd = retval.toInt32();
        if (fd !== -1) {
            const peer = sockaddrToObj(this.address);
            if (peer) peers[fd] = peer;
            socketTypes[fd] = 'TCP';
        }
    }
});

attachHook('send', {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.buffer = args[1];
        this.peer = lookupPeer(this.fd);
        this.length = args[2].toInt32();
    },
    onLeave(retval) {
        emitPayload(this.fd, socketTypes[this.fd], 'out', this.peer,
            this.buffer, retval.toInt32());
    }
});

attachHook('recv', {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.buffer = args[1];
        this.peer = lookupPeer(this.fd);
    },
    onLeave(retval) {
        emitPayload(this.fd, socketTypes[this.fd], 'in', this.peer,
            this.buffer, retval.toInt32());
    }
});

attachHook('WSASend', {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.peer = lookupPeer(this.fd);
        this.buffers = readWsaBuffers(args[1], args[2].toInt32());
        this.bytes = args[3];
        this.overlapped = args[4];
    },
    onLeave(retval) {
        if (retval.toInt32() !== 0 ||
            (this.overlapped && !this.overlapped.isNull())) return;
        const total = this.bytes.isNull() ? 0 : this.bytes.readU32();
        emitWsaBuffers(this.fd, socketTypes[this.fd], 'out',
            this.peer, this.buffers, total);
    }
});

attachHook('WSARecv', {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.peer = lookupPeer(this.fd);
        this.buffers = readWsaBuffers(args[1], args[2].toInt32());
        this.bytes = args[3];
        this.overlapped = args[5];
    },
    onLeave(retval) {
        if (retval.toInt32() !== 0 ||
            (this.overlapped && !this.overlapped.isNull())) return;
        const total = this.bytes.isNull() ? 0 : this.bytes.readU32();
        emitWsaBuffers(this.fd, socketTypes[this.fd], 'in',
            this.peer, this.buffers, total);
    }
});

attachHook('sendto', {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.buffer = args[1];
        this.length = args[2].toInt32();
        this.peer = sockaddrToObj(args[4]) || lookupPeer(this.fd);
    },
    onLeave(retval) {
        emitPayload(this.fd, 'UDP', 'out', this.peer,
            this.buffer, retval.toInt32());
    }
});

attachHook('recvfrom', {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.buffer = args[1];
        this.address = args[4];
        this.peer = sockaddrToObj(this.address) || lookupPeer(this.fd);
    },
    onLeave(retval) {
        emitPayload(this.fd, 'UDP', 'in', this.peer,
            this.buffer, retval.toInt32());
    }
});

attachHook('closesocket', {
    onEnter(args) {
        const fd = args[0].toInt32();
        delete peers[fd];
        delete socketTypes[fd];
        send({ event: 'close', fd: fd });
    }
});

send({ event: 'ready' });
"""


class LoopbackMonitor:
    def __init__(self, process_name):
        try:
            import frida
        except ImportError as exc:
            raise RuntimeError(
                'Falta "frida". Instala con: py -m pip install frida'
            ) from exc

        self.frida = frida
        self.process_name = process_name
        self.device = frida.get_local_device()
        self.sessions = {}
        self.last_attach_attempt = {}
        self.transitions = PayloadTransitions()

    def _log(self, message):
        print(message, flush=True)

    def _on_message(self, pid, message, data):
        if message.get("type") == "error":
            self._log(f"[{pid}] Error Frida: {message.get('description', '')}")
            return
        if message.get("type") != "send":
            return

        event = message.get("payload", {})
        kind = event.get("event")
        if kind == "ready":
            self._log(f"[{pid}] Hooks Winsock activos; solo loopback.")
        elif kind == "hook_error":
            self._log(f"[{pid}] Error de hook: {event.get('detail', '')}")
        elif kind == "close":
            self.transitions.clear_fd(pid, event.get("fd"))
        elif kind == "payload":
            peer = event.get("peer") or {}
            if not is_loopback_peer(peer):
                return
            payload = bytes(data or b"")
            proto = str(event.get("proto", "?"))
            direction = str(event.get("direction", "?"))
            fd = event.get("fd", -1)
            digest = self.transitions.changed(
                pid, fd, proto, direction, peer.get("ip", ""), payload)
            if digest is None:
                return
            sample = "muestra" if event.get("truncated") else "completo"
            self._log(
                f"[{pid}] fd={fd} {proto} {direction} "
                f"{peer.get('ip')}:{peer.get('port')} "
                f"len={event.get('length', len(payload))} {sample} "
                f"sha256={digest} estado=cambiado\n"
                f"{decode_payload(payload)}"
            )

    def _attach(self, process):
        pid = process.pid
        session = None
        try:
            session = self.device.attach(pid)
            script = session.create_script(
                FRIDA_AGENT.replace(
                    "__MAX_SAMPLE_BYTES__", str(MAX_SAMPLE_BYTES)))
            script.on(
                "message",
                lambda message, data, target_pid=pid:
                    self._on_message(target_pid, message, data),
            )
            session.on(
                "detached",
                lambda reason, crash, target_pid=pid:
                    self._on_detached(target_pid, reason, crash),
            )
            script.load()
            self.sessions[pid] = (session, script)
            self._log(f"[+] Adjunto a {process.name} (PID {pid})")
        except Exception as exc:
            self._log(f"[!] No se pudo adjuntar a PID {pid}: {exc}")
            if session is not None:
                try:
                    session.detach()
                except Exception as detach_exc:
                    self._log(
                        f"[!] Error al limpiar la sesión de PID {pid}: "
                        f"{detach_exc}")

    def _on_detached(self, pid, reason, crash):
        self.sessions.pop(pid, None)
        detail = f"sesión Frida cerrada: {reason}"
        if crash:
            detail += f" ({crash})"
        self._log(f"[i] PID {pid}: {detail}")

    def run(self):
        self._log(
            f"Buscando procesos llamados exactamente "
            f'"{self.process_name}" (Ctrl+C para salir).'
        )
        try:
            while True:
                now = time.monotonic()
                try:
                    processes = matching_processes(
                        self.device.enumerate_processes(scope="full"),
                        self.process_name,
                    )
                except Exception as exc:
                    self._log(f"[!] No se pudieron enumerar procesos: {exc}")
                    time.sleep(POLL_INTERVAL)
                    continue

                current_pids = {process.pid for process in processes}
                for pid in list(self.sessions):
                    if pid not in current_pids:
                        session, _ = self.sessions.pop(pid)
                        try:
                            session.detach()
                        except Exception as exc:
                            self._log(
                                f"[!] Error al separar PID {pid}: {exc}")

                for process in processes:
                    if process.pid in self.sessions:
                        continue
                    last_attempt = self.last_attach_attempt.get(
                        process.pid, 0)
                    if now - last_attempt < ATTACH_RETRY_INTERVAL:
                        continue
                    self.last_attach_attempt[process.pid] = now
                    self._attach(process)

                for pid in list(self.last_attach_attempt):
                    if pid not in current_pids:
                        del self.last_attach_attempt[pid]
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            self._log("\n[i] Deteniendo monitor…")
        finally:
            for pid, (session, _) in list(self.sessions.items()):
                try:
                    session.detach()
                except Exception as exc:
                    self._log(f"[!] Error al separar PID {pid}: {exc}")
            self.sessions.clear()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Monitor de cambios de payload Winsock en loopback.")
    parser.add_argument(
        "--process", required=True,
        help="nombre exacto del proceso, por ejemplo app.exe")
    args = parser.parse_args(argv)
    if not args.process.strip() or "/" in args.process or "\\" in args.process:
        parser.error("--process debe ser un nombre de proceso, no una ruta")

    try:
        LoopbackMonitor(args.process.strip()).run()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error al iniciar el monitor: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
