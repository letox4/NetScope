/*
 * NetScope — agente Frida (ws2_32.dll + IOCP/Overlapped + TLS/OpenSSL + DNS + Stacks + ChildProcs)
 *
 * Captura y reensambla a nivel de API los flujos TCP/UDP/TLS/HTTP del proceso:
 *   - Winsock síncrono y asíncrono (Overlapped I/O + IOCP):
 *       connect, WSAConnect, ConnectEx (WSAIoctl), socket, closesocket,
 *       send/recv, sendto/recvfrom, WSASend/WSARecv, WSASendTo/WSARecvFrom,
 *       WSAGetOverlappedResult, GetOverlappedResult, GetOverlappedResultEx,
 *       GetQueuedCompletionStatus, GetQueuedCompletionStatusEx, lpCompletionRoutine
 *   - TLS en claro + claves TLS (SSLKEYLOG):
 *       Schannel/Secur32 (EncryptMessage / DecryptMessage)
 *       OpenSSL / BoringSSL (SSL_write / SSL_read / SSL_write_ex / SSL_read_ex + SSL_CTX_set_keylog_callback)
 *   - HTTP de alto nivel: WinHTTP, WinINet, SteamHTTP, SteamNetworking
 *   - DNS en vivo: getaddrinfo, GetAddrInfoW, gethostbyname
 *   - Atribución de código: Thread.backtrace + DebugSymbol (cacheado)
 *   - Procesos hijo: CreateProcessW / CreateProcessA
 *
 * Seguridad del proceso objetivo: TODOS los callbacks están blindados con
 * try/catch vía safe(); una excepción nunca se propaga a la app monitorizada.
 */

'use strict';

const PROTO = { 1: 'TCP', 2: 'UDP' };
const MAX_CHUNK = 8192;      // bytes máximos por evento (canal Frida)
const MAX_WSA_BUFS = 16;     // WSABUFs leídos por llamada WSASend/WSARecv
const MAX_RULES = 64;        // reglas de reescritura simultáneas
const MAX_PENDING_OVL = 4096;
const MAX_STACK_FRAMES = 8;
const WSA_IO_PENDING = 997;

var rewriteEnabled = true;   // se puede apagar en caliente vía RPC
var captureStacks = true;    // atribución de call stack por paquete
var rules = [];              // [{match: Uint8Array, replace: Uint8Array}]
var httpHandles = {};
var httpPeers = {};
var winHttpHosts = {};
var winInetHosts = {};
var nextHttpFd = 100000;
var hookedWinHttpCallbacks = {};
var observedHttpApis = {};

var socketPeers = {};        // fd -> {ip, port}
var socketProtos = {};       // fd -> 'TCP' | 'UDP'
var pendingOverlapped = {};  // ptrStr -> op descriptor
var pendingOvlOrder = [];    // FIFO para acotar memoria si hay cancelaciones
var hookedCompletionRoutines = {};
var hookedConnectEx = {};
var hookedSslModules = {};
var hookedSslCtxs = {};
var sslKeylogCallbacks = []; // mantiene referencias vivas contra GC
var symbolCache = {};
var symbolCacheCount = 0;

var _wsaGetLastError = null;
var _getpeername = null;
var _getsockopt = null;

var HEX = [];
for (var h = 0; h < 256; h++) HEX.push(('0' + h.toString(16)).slice(-2));

/* ---------- utilidades ---------- */

function ws2(name) {
    try {
        return Process.getModuleByName('ws2_32.dll').findExportByName(name);
    } catch (e) { }
    return Module.findGlobalExportByName ? Module.findGlobalExportByName(name) : null;
}

function findExport(moduleName, name) {
    try {
        var mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(name) : null;
    } catch (e) {
        return null;
    }
}

function findKernelExport(name) {
    return findExport('kernelbase.dll', name) || findExport('kernel32.dll', name);
}

function findKernelExports(name) {
    var out = [];
    var seen = {};
    ['kernelbase.dll', 'kernel32.dll'].forEach(function (mod) {
        var addr = findExport(mod, name);
        if (addr && !seen[addr.toString()]) {
            seen[addr.toString()] = true;
            out.push(addr);
        }
    });
    return out;
}

function getWsaLastError() {
    if (!_wsaGetLastError) {
        var addr = ws2('WSAGetLastError');
        if (addr) _wsaGetLastError = new NativeFunction(addr, 'int', []);
    }
    if (_wsaGetLastError) {
        try { return _wsaGetLastError(); } catch (e) { }
    }
    return 0;
}

function bytesToHex(u8) {
    var parts = new Array(u8.length);
    for (var i = 0; i < u8.length; i++) parts[i] = HEX[u8[i]];
    return parts.join('');
}

function captureStack(ctx) {
    if (!captureStacks || !ctx) return [];
    try {
        var addrs = Thread.backtrace(ctx, Backtracer.ACCURATE);
        if (!addrs || addrs.length === 0) {
            addrs = Thread.backtrace(ctx, Backtracer.FUZZY);
        }
        var limit = Math.min(addrs.length, MAX_STACK_FRAMES);
        var frames = [];
        for (var i = 0; i < limit; i++) {
            var a = addrs[i];
            var key = a.toString();
            var label = symbolCache[key];
            if (label === undefined) {
                try {
                    var sym = DebugSymbol.fromAddress(a);
                    var mod = Process.findModuleByAddress(a);
                    if (sym && sym.moduleName && sym.name) {
                        var validSym = Boolean(sym.fileName);
                        if (!validSym && mod) {
                            var exp = mod.findExportByName(sym.name);
                            if (exp && exp.compare(a) <= 0) {
                                var dist = parseInt(a.sub(exp).toString(), 16);
                                if (!isNaN(dist) && dist <= 0x4000) {
                                    validSym = true;
                                }
                            }
                        } else if (!mod) {
                            validSym = true;
                        }
                        if (validSym) {
                            label = sym.moduleName + '!' + sym.name;
                        } else if (mod) {
                            label = mod.name + '+0x' + a.sub(mod.base).toString(16);
                        } else {
                            label = sym.moduleName + '!' + sym.name;
                        }
                    } else if (sym && sym.name) {
                        label = sym.name;
                    } else {
                        label = mod ? (mod.name + '+0x' + a.sub(mod.base).toString(16)) : key;
                    }
                } catch (e) {
                    label = key;
                }
                if (symbolCacheCount > 4096) {
                    symbolCache = {};
                    symbolCacheCount = 0;
                }
                symbolCache[key] = label;
                symbolCacheCount++;
            }
            frames.push(label);
        }
        return frames;
    } catch (e) {
        return [];
    }
}

function resolvePeer(fd) {
    if (fd < 0) return null;
    try {
        if (!_getpeername) {
            var gp = ws2('getpeername');
            if (gp) _getpeername = new NativeFunction(gp, 'int', ['int', 'pointer', 'pointer']);
        }
        if (!_getpeername) return null;
        var buf = Memory.alloc(32);
        var lenBuf = Memory.alloc(4);
        lenBuf.writeS32(32);
        if (_getpeername(fd, buf, lenBuf) === 0) {
            var p = sockaddrToObj(buf);
            if (p && p.ip && p.ip !== '?') {
                socketPeers[fd] = p;
                return p;
            }
        }
    } catch (e) { }
    return null;
}

function getPeerForFd(fd) {
    if (fd < 0) return null;
    if (socketPeers[fd]) return socketPeers[fd];
    return resolvePeer(fd);
}

function resolveSocketProto(fd) {
    if (fd < 0) return null;
    try {
        if (!_getsockopt) {
            var gs = ws2('getsockopt');
            if (gs) _getsockopt = new NativeFunction(gs, 'int', ['int', 'int', 'int', 'pointer', 'pointer']);
        }
        if (!_getsockopt) return null;
        var valBuf = Memory.alloc(4);
        var lenBuf = Memory.alloc(4);
        lenBuf.writeS32(4);
        if (_getsockopt(fd, 0xFFFF, 0x1008, valBuf, lenBuf) === 0) {
            var proto = PROTO[valBuf.readS32()];
            if (proto) {
                socketProtos[fd] = proto;
                return proto;
            }
        }
    } catch (e) { }
    return null;
}

function protoForFd(fd, fallback) {
    if (socketProtos[fd]) return socketProtos[fd];
    return resolveSocketProto(fd) || fallback || 'TCP';
}

function httpFd(handle, api) {
    const key = api + ':' + handle.toString();
    if (httpHandles[key] === undefined) {
        httpHandles[key] = -nextHttpFd++;
    }
    return httpHandles[key];
}

function steamHttpFd(request) {
    const key = 'steamhttp:' + request;
    if (httpHandles[key] === undefined) {
        httpHandles[key] = -nextHttpFd++;
    }
    return httpHandles[key];
}

function steamNetFd(keyValue, api) {
    const key = api + ':' + keyValue;
    if (httpHandles[key] === undefined) {
        httpHandles[key] = -nextHttpFd++;
    }
    return httpHandles[key];
}

function steamIdentityFd(identity) {
    try {
        const bytes = new Uint8Array(identity.readByteArray(136));
        let hash = 2166136261;
        for (let i = 0; i < bytes.length; i++) {
            hash = Math.imul(hash ^ bytes[i], 16777619) >>> 0;
        }
        return steamNetFd(hash.toString(16), 'steamuser');
    } catch (e) {
        return steamNetFd(identity.toString(), 'steamuser');
    }
}

function steamMessagePayload(message, direction, api, fd) {
    if (message.isNull()) return;
    try {
        const length = message.add(Process.pointerSize).readS32();
        if (length <= 0) return;
        const data = message.readPointer();
        const messageFd = fd !== undefined ? fd
            : api === 'steamuser'
                ? steamIdentityFd(message.add(Process.pointerSize + 8))
                : steamNetFd(message.add(Process.pointerSize + 4).readU32(), api);
        emit(direction === 'out' ? 'steam_out' : 'steam_in',
            'STEAM', messageFd, direction, null, data, length, api);
    } catch (e) {
        send({
            event: 'hook_error', proto: 'STEAM', fd: -1, dir: direction,
            peer: null, hex: '', truncated: false, tag: api + ': ' + e
        });
    }
}

function readSteamMessages(array, count, direction, api, connection) {
    const n = Math.min(Math.max(count, 0), 128);
    for (let i = 0; i < n; i++) {
        const message = array.add(i * Process.pointerSize).readPointer();
        const fd = connection === undefined
            ? undefined : steamNetFd(connection, api);
        steamMessagePayload(message, direction, api, fd);
    }
}

function httpPeer(fd) {
    return httpPeers[fd] || null;
}

function markHttpApi(name) {
    if (observedHttpApis[name]) return;
    observedHttpApis[name] = true;
    send({
        event: 'api_activity', proto: 'HTTP', fd: -1, dir: '',
        peer: null, hex: '', truncated: false, tag: name
    });
}

function readWide(ptr, maxChars) {
    if (!ptr || ptr.isNull()) return '';
    const s = ptr.readUtf16String() || '';
    const clean = s.split('\x00')[0];
    return maxChars ? clean.slice(0, maxChars) : clean;
}

function emitHttpText(evt, fd, text, tag, stack) {
    if (!text) return;
    try {
        const data = Memory.allocUtf8String(text);
        const len = unescape(encodeURIComponent(text)).length;
        emit(evt, 'HTTP', fd, evt === 'http_out' ? 'out' : 'in',
            httpPeer(fd), data, len, tag, stack);
    } catch (e) {
        send({
            event: 'hook_error', proto: 'HTTP', fd: fd, dir: '',
            peer: null, hex: '', truncated: false, tag: String(e)
        });
    }
}

function emitHttpBuffer(evt, fd, buffer, length, tag, stack) {
    emit(evt, 'HTTP', fd, evt === 'http_out' ? 'out' : 'in',
        httpPeer(fd), buffer, length, tag, stack);
}

function readAnsiHeader(ptr, length) {
    if (!ptr || ptr.isNull()) return '';
    const n = length >>> 0;
    return n === 0xFFFFFFFF ? ptr.readCString(8192) : ptr.readCString(Math.min(n, 8192));
}

function readWideHeader(ptr, length, lengthIsBytes) {
    if (!ptr || ptr.isNull()) return '';
    const n = length >>> 0;
    if (n === 0xFFFFFFFF) return readWide(ptr, 4096);
    const bytes = lengthIsBytes ? n : n * 2;
    const raw = ptr.readUtf16String(Math.min(bytes, 8192)) || '';
    return raw.split('\x00')[0];
}

function hookHttpClose(moduleName, name, api) {
    const addr = findExport(moduleName, name);
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter: safe(function (args) {
            const key = api + ':' + args[0].toString();
            const fd = httpHandles[key];
            if (fd !== undefined) {
                send({
                    event: 'close', proto: 'HTTP', fd: fd, dir: 'out',
                    peer: httpPeer(fd), hex: '', truncated: false, tag: name
                });
                delete httpHandles[key];
                delete httpPeers[fd];
            }
            if (api === 'winhttp') delete winHttpHosts[args[0].toString()];
            if (api === 'wininet') delete winInetHosts[args[0].toString()];
        })
    });
    return true;
}

function hookWinHttp() {
    const hooked = [];
    let addr = findExport('winhttp.dll', 'WinHttpConnect');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('WinHttpConnect');
                this.host = readWide(args[1], 2048);
                this.port = args[2].toUInt32();
            }),
            onLeave: safe(function (retval) {
                if (!retval.isNull()) {
                    winHttpHosts[retval.toString()] = {
                        host: this.host, port: this.port
                    };
                }
            })
        });
        hooked.push('WinHttpConnect');
    }

    addr = findExport('winhttp.dll', 'WinHttpOpenRequest');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('WinHttpOpenRequest');
                this.parent = args[0].toString();
                this.method = readWide(args[1], 64) || 'GET';
                this.path = readWide(args[2], 4096) || '/';
                this.stack = captureStack(this.context);
            }),
            onLeave: safe(function (retval) {
                if (retval.isNull()) return;
                const fd = httpFd(retval, 'winhttp');
                const host = winHttpHosts[this.parent];
                if (host) {
                    httpPeers[fd] = { ip: host.host, port: host.port };
                }
                emitHttpText('http_out', fd, this.method + ' ' + this.path + '\r\n',
                    'WinHttpOpenRequest', this.stack);
            })
        });
        hooked.push('WinHttpOpenRequest');
    }

    addr = findExport('winhttp.dll', 'WinHttpSendRequest');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('WinHttpSendRequest');
                this.fd = httpFd(args[0], 'winhttp');
                this.headers = readWideHeader(args[1], args[2].toUInt32(), false);
                this.body = args[3];
                this.bodyLen = args[4].toUInt32();
                this.stack = captureStack(this.context);
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0) return;
                emitHttpText('http_out', this.fd, this.headers, 'WinHttpSendRequest headers', this.stack);
                if (this.bodyLen > 0) {
                    emitHttpBuffer('http_out', this.fd, this.body, this.bodyLen,
                        'WinHttpSendRequest body', this.stack);
                }
            })
        });
        hooked.push('WinHttpSendRequest');
    }

    addr = findExport('winhttp.dll', 'WinHttpWriteData');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('WinHttpWriteData');
                this.fd = httpFd(args[0], 'winhttp');
                this.buffer = args[1];
                this.requested = args[2].toUInt32();
                this.written = args[3];
                this.stack = captureStack(this.context);
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0) return;
                const n = this.written.isNull()
                    ? this.requested : this.written.readU32();
                if (n > 0) emitHttpBuffer('http_out', this.fd, this.buffer, n,
                    'WinHttpWriteData body', this.stack);
            })
        });
        hooked.push('WinHttpWriteData');
    }

    addr = findExport('winhttp.dll', 'WinHttpReadData');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('WinHttpReadData');
                this.fd = httpFd(args[0], 'winhttp');
                this.buffer = args[1];
                this.read = args[3];
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0 || this.read.isNull()) return;
                const n = this.read.readU32();
                if (n > 0) emitHttpBuffer('http_in', this.fd, this.buffer, n,
                    'WinHttpReadData response');
            })
        });
        hooked.push('WinHttpReadData');
    }

    addr = findExport('winhttp.dll', 'WinHttpSetStatusCallback');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('WinHttpSetStatusCallback');
                const callback = args[1];
                if (callback.isNull()) return;
                const key = callback.toString();
                if (hookedWinHttpCallbacks[key]) return;
                hookedWinHttpCallbacks[key] = true;
                Interceptor.attach(callback, {
                    onEnter: safe(function (cbArgs) {
                        const status = cbArgs[2].toUInt32();
                        if (status !== 0x14) return; // WINHTTP_CALLBACK_STATUS_READ_COMPLETE
                        markHttpApi('WinHTTP async read complete');
                        const length = cbArgs[4].toUInt32();
                        if (length > 0) {
                            emitHttpBuffer('http_in', httpFd(cbArgs[0], 'winhttp'),
                                cbArgs[3], length, 'WinHTTP async read complete');
                        }
                    })
                });
            })
        });
        hooked.push('WinHttpSetStatusCallback');
    }
    if (hookHttpClose('winhttp.dll', 'WinHttpCloseHandle', 'winhttp')) {
        hooked.push('WinHttpCloseHandle');
    }
    return hooked;
}

function hookWinInet() {
    const hooked = [];
    for (const suffix of ['A', 'W']) {
        const connectName = 'InternetConnect' + suffix;
        const connectAddr = findExport('wininet.dll', connectName);
        if (connectAddr) {
            Interceptor.attach(connectAddr, {
                onEnter: safe(function (args) {
                    markHttpApi(connectName);
                    this.host = suffix === 'W'
                        ? readWide(args[1], 2048) : readAnsiHeader(args[1], 0xFFFFFFFF);
                    this.port = args[2].toUInt32();
                }),
                onLeave: safe(function (retval) {
                    if (!retval.isNull()) {
                        winInetHosts[retval.toString()] = {
                            host: this.host, port: this.port
                        };
                    }
                })
            });
            hooked.push(connectName);
        }

        const openName = 'HttpOpenRequest' + suffix;
        const openAddr = findExport('wininet.dll', openName);
        if (openAddr) {
            Interceptor.attach(openAddr, {
                onEnter: safe(function (args) {
                    markHttpApi(openName);
                    this.parent = args[0].toString();
                    this.method = suffix === 'W'
                        ? readWide(args[1], 64) : readAnsiHeader(args[1], 64);
                    this.path = suffix === 'W'
                        ? readWide(args[2], 4096) : readAnsiHeader(args[2], 4096);
                    this.stack = captureStack(this.context);
                }),
                onLeave: safe(function (retval) {
                    if (retval.isNull()) return;
                    const fd = httpFd(retval, 'wininet');
                    const host = winInetHosts[this.parent];
                    if (host) httpPeers[fd] = { ip: host.host, port: host.port };
                    emitHttpText('http_out', fd,
                        (this.method || 'GET') + ' ' + (this.path || '/') + '\r\n',
                        openName, this.stack);
                })
            });
            hooked.push(openName);
        }
    }

    for (const suffix of ['A', 'W']) {
        const name = 'HttpSendRequest' + suffix;
        const addr = findExport('wininet.dll', name);
        if (!addr) continue;
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi(name);
                this.fd = httpFd(args[0], 'wininet');
                const length = args[2].toUInt32();
                this.headers = suffix === 'W'
                    ? readWideHeader(args[1], length, true)
                    : readAnsiHeader(args[1], length);
                this.body = args[3];
                this.bodyLen = args[4].toUInt32();
                this.stack = captureStack(this.context);
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0) return;
                emitHttpText('http_out', this.fd, this.headers, name + ' headers', this.stack);
                if (this.bodyLen > 0) {
                    emitHttpBuffer('http_out', this.fd, this.body, this.bodyLen,
                        name + ' body', this.stack);
                }
            })
        });
        hooked.push(name);
    }

    for (const name of ['InternetWriteFile', 'InternetReadFile']) {
        const addr = findExport('wininet.dll', name);
        if (!addr) continue;
        const outgoing = name === 'InternetWriteFile';
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi(name);
                this.fd = httpFd(args[0], 'wininet');
                this.buffer = args[1];
                this.requested = args[2].toUInt32();
                this.transferred = args[3];
                this.stack = outgoing ? captureStack(this.context) : [];
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0 || this.transferred.isNull()) return;
                const n = this.transferred.readU32();
                if (n > 0) emitHttpBuffer(outgoing ? 'http_out' : 'http_in',
                    this.fd, this.buffer, n, name + (outgoing ? ' body' : ' response'), this.stack);
            })
        });
        hooked.push(name);
    }
    if (hookHttpClose('wininet.dll', 'InternetCloseHandle', 'wininet')) {
        hooked.push('InternetCloseHandle');
    }
    return hooked;
}

function hookSteamHttp() {
    const hooked = [];
    const methodNames = {
        1: 'GET', 2: 'HEAD', 3: 'POST', 4: 'PUT',
        5: 'DELETE', 6: 'OPTIONS', 7: 'PATCH', 8: 'CUSTOM'
    };
    let addr = findExport('steam_api64.dll', 'SteamAPI_ISteamHTTP_CreateHTTPRequest');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('SteamHTTP CreateHTTPRequest');
                this.method = methodNames[args[1].toInt32()] || 'HTTP';
                this.url = readAnsiHeader(args[2], 0xFFFFFFFF);
            }),
            onLeave: safe(function (retval) {
                const request = retval.toUInt32();
                if (!request) return;
                const fd = steamHttpFd(request);
                const match = this.url.match(/^https?:\/\/([^/:?#]+)(?::([0-9]+))?/i);
                if (match) {
                    const secure = this.url.toLowerCase().startsWith('https://');
                    httpPeers[fd] = {
                        ip: match[1], port: match[2] ? parseInt(match[2], 10)
                            : (secure ? 443 : 80)
                    };
                }
                emitHttpText('http_out', fd, this.method + ' ' + this.url + '\r\n',
                    'SteamHTTP CreateHTTPRequest');
            })
        });
        hooked.push('SteamHTTP CreateHTTPRequest');
    }

    addr = findExport('steam_api64.dll', 'SteamAPI_ISteamHTTP_SetHTTPRequestHeaderValue');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('SteamHTTP SetHTTPRequestHeaderValue');
                this.fd = steamHttpFd(args[1].toUInt32());
                this.name = readAnsiHeader(args[2], 0xFFFFFFFF);
                this.value = readAnsiHeader(args[3], 0xFFFFFFFF);
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() !== 0) {
                    emitHttpText('http_out', this.fd, this.name + ': ' + this.value + '\r\n',
                        'SteamHTTP request header');
                }
            })
        });
        hooked.push('SteamHTTP SetHTTPRequestHeaderValue');
    }

    addr = findExport('steam_api64.dll', 'SteamAPI_ISteamHTTP_SetHTTPRequestGetOrPostParameter');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('SteamHTTP SetHTTPRequestGetOrPostParameter');
                this.fd = steamHttpFd(args[1].toUInt32());
                this.name = readAnsiHeader(args[2], 0xFFFFFFFF);
                this.value = readAnsiHeader(args[3], 0xFFFFFFFF);
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() !== 0) {
                    emitHttpText('http_out', this.fd, this.name + '=' + this.value + '&',
                        'SteamHTTP request parameter');
                }
            })
        });
        hooked.push('SteamHTTP SetHTTPRequestGetOrPostParameter');
    }

    addr = findExport('steam_api64.dll', 'SteamAPI_ISteamHTTP_SetHTTPRequestRawPostBody');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('SteamHTTP SetHTTPRequestRawPostBody');
                this.fd = steamHttpFd(args[1].toUInt32());
                this.contentType = readAnsiHeader(args[2], 0xFFFFFFFF);
                this.body = args[3];
                this.length = args[4].toUInt32();
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0) return;
                emitHttpText('http_out', this.fd, 'Content-Type: ' + this.contentType + '\r\n',
                    'SteamHTTP raw body content type');
                if (this.length > 0) {
                    emitHttpBuffer('http_out', this.fd, this.body, this.length,
                        'SteamHTTP request body');
                }
            })
        });
        hooked.push('SteamHTTP SetHTTPRequestRawPostBody');
    }

    addr = findExport('steam_api64.dll', 'SteamAPI_ISteamHTTP_SendHTTPRequest');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function () { markHttpApi('SteamHTTP SendHTTPRequest'); })
        });
        hooked.push('SteamHTTP SendHTTPRequest');
    }
    addr = findExport('steam_api64.dll', 'SteamAPI_ISteamHTTP_SendHTTPRequestAndStreamResponse');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function () { markHttpApi('SteamHTTP SendHTTPRequestAndStreamResponse'); })
        });
        hooked.push('SteamHTTP SendHTTPRequestAndStreamResponse');
    }

    addr = findExport('steam_api64.dll', 'SteamAPI_ISteamHTTP_GetHTTPResponseBodyData');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('SteamHTTP GetHTTPResponseBodyData');
                this.fd = steamHttpFd(args[1].toUInt32());
                this.body = args[2];
                this.length = args[3].toUInt32();
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() !== 0 && this.length > 0) {
                    emitHttpBuffer('http_in', this.fd, this.body, this.length,
                        'SteamHTTP response body');
                }
            })
        });
        hooked.push('SteamHTTP GetHTTPResponseBodyData');
    }

    addr = findExport('steam_api64.dll', 'SteamAPI_ISteamHTTP_GetHTTPResponseHeaderValue');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('SteamHTTP GetHTTPResponseHeaderValue');
                this.fd = steamHttpFd(args[1].toUInt32());
                this.name = readAnsiHeader(args[2], 0xFFFFFFFF);
                this.value = args[3];
                this.length = args[4].toUInt32();
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() !== 0 && !this.value.isNull() && this.length > 0) {
                    const value = this.value.readCString(Math.min(this.length, 8192));
                    emitHttpText('http_in', this.fd, this.name + ': ' + value + '\r\n',
                        'SteamHTTP response header');
                }
            })
        });
        hooked.push('SteamHTTP GetHTTPResponseHeaderValue');
    }

    addr = findExport('steam_api64.dll', 'SteamAPI_ISteamHTTP_ReleaseHTTPRequest');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                const key = 'steamhttp:' + args[1].toUInt32();
                const fd = httpHandles[key];
                if (fd !== undefined) {
                    send({
                        event: 'close', proto: 'HTTP', fd: fd, dir: 'out',
                        peer: httpPeer(fd), hex: '', truncated: false,
                        tag: 'SteamHTTP ReleaseHTTPRequest'
                    });
                    delete httpHandles[key];
                    delete httpPeers[fd];
                }
            })
        });
        hooked.push('SteamHTTP ReleaseHTTPRequest');
    }
    return hooked;
}

function hookSteamNetworking() {
    const hooked = [];
    let addr = findExport('steam_api64.dll',
        'SteamAPI_ISteamNetworking_SendP2PPacket');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('SteamNetworking SendP2PPacket');
                this.fd = steamNetFd(args[1].toString(), 'steamp2p');
                this.data = args[2];
                this.length = args[3].toUInt32();
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() !== 0 && this.length > 0) {
                    emit('steam_out', 'STEAM', this.fd, 'out', null,
                        this.data, this.length, 'SteamNetworking P2P send');
                }
            })
        });
        hooked.push('SteamNetworking SendP2PPacket');
    }

    addr = findExport('steam_api64.dll', 'SteamAPI_ISteamNetworking_ReadP2PPacket');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('SteamNetworking ReadP2PPacket');
                this.data = args[1];
                this.length = args[3];
                this.sender = args[4];
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0 || this.length.isNull()) return;
                const length = this.length.readU32();
                if (length <= 0) return;
                const sender = this.sender.isNull()
                    ? 'unknown' : this.sender.readU64().toString();
                emit('steam_in', 'STEAM', steamNetFd(sender, 'steamp2p'),
                    'in', null, this.data, length, 'SteamNetworking P2P receive');
            })
        });
        hooked.push('SteamNetworking ReadP2PPacket');
    }

    for (const name of [
        'SteamAPI_ISteamNetworking_SendDataOnSocket',
        'SteamAPI_ISteamNetworking_RetrieveDataFromSocket'
    ]) {
        addr = findExport('steam_api64.dll', name);
        if (!addr) continue;
        const outgoing = name.endsWith('SendDataOnSocket');
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi(name);
                this.fd = steamNetFd(args[1].toUInt32(), 'steamsocket');
                this.data = args[2];
                this.length = args[3].toUInt32();
                this.transferred = args[4];
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0) return;
                const length = outgoing || this.transferred.isNull()
                    ? this.length : this.transferred.readU32();
                if (length > 0) {
                    emit(outgoing ? 'steam_out' : 'steam_in', 'STEAM',
                        this.fd, outgoing ? 'out' : 'in', null,
                        this.data, length, name);
                }
            })
        });
        hooked.push(name.replace('SteamAPI_ISteamNetworking_', ''));
    }

    addr = findExport('steam_api64.dll',
        'SteamAPI_ISteamNetworkingSockets_SendMessageToConnection');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('SteamNetworking SendMessageToConnection');
                this.fd = steamNetFd(args[1].toUInt32(), 'steamconn');
                this.data = args[2];
                this.length = args[3].toUInt32();
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 1 && this.length > 0) {
                    emit('steam_out', 'STEAM', this.fd, 'out', null,
                        this.data, this.length, 'SteamNetworking send');
                }
            })
        });
        hooked.push('SteamNetworking SendMessageToConnection');
    }

    addr = findExport('steam_api64.dll',
        'SteamAPI_ISteamNetworkingSockets_SendMessages');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('SteamNetworking SendMessages');
                readSteamMessages(args[2], args[1].toInt32(), 'out', 'steamconn');
            })
        });
        hooked.push('SteamNetworking SendMessages');
    }

    for (const name of [
        'SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnConnection',
        'SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnPollGroup',
        'SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel'
    ]) {
        addr = findExport('steam_api64.dll', name);
        if (!addr) continue;
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi(name);
                this.connection = name.indexOf('OnConnection') >= 0
                    ? args[1].toUInt32() : undefined;
                this.messages = args[2];
            }),
            onLeave: safe(function (retval) {
                readSteamMessages(this.messages, retval.toInt32(), 'in',
                    name.indexOf('NetworkingMessages') >= 0 ? 'steamuser' : 'steamconn',
                    this.connection);
            })
        });
        hooked.push(name.replace('SteamAPI_ISteam', ''));
    }

    addr = findExport('steam_api64.dll',
        'SteamAPI_ISteamNetworkingMessages_SendMessageToUser');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                markHttpApi('SteamNetworkingMessages SendMessageToUser');
                this.fd = steamIdentityFd(args[1]);
                this.data = args[2];
                this.length = args[3].toUInt32();
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 1 && this.length > 0) {
                    emit('steam_out', 'STEAM', this.fd, 'out', null,
                        this.data, this.length, 'SteamNetworkingMessages send');
                }
            })
        });
        hooked.push('SteamNetworkingMessages SendMessageToUser');
    }
    return hooked;
}

function sockaddrToObj(sa) {
    if (!sa || sa.isNull()) return null;
    try {
        const family = sa.readU16();
        if (family === 2) { // AF_INET
            const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
            const ip = new Uint8Array(sa.add(4).readByteArray(4)).join('.');
            return { ip: ip, port: port };
        } else if (family === 23) { // AF_INET6
            const bytes = new Uint8Array(sa.add(8).readByteArray(16));
            // IPv4-mapped IPv6 (::ffff:a.b.c.d)
            var isV4Mapped = true;
            for (var j = 0; j < 10; j++) { if (bytes[j] !== 0) { isV4Mapped = false; break; } }
            if (isV4Mapped && bytes[10] === 0xff && bytes[11] === 0xff) {
                const port4 = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                return { ip: bytes[12] + '.' + bytes[13] + '.' + bytes[14] + '.' + bytes[15], port: port4 };
            }
            const parts = [];
            for (let i = 0; i < 16; i++) {
                parts.push(HEX[bytes[i]]);
            }
            return { ip: 'ipv6[' + parts.join('') + ']', port: (sa.add(2).readU8() << 8) | sa.add(3).readU8() };
        }
    } catch (e) { }
    return { ip: '?', port: 0 };
}

/* Envía el evento a Python. data puede ser NativePointer, Uint8Array o null. */
function emit(evt, proto, fd, dir, peer, data, len, tag, stack) {
    let hex = '';
    try {
        if (data && len > 0) {
            if (data instanceof Uint8Array) {
                const n = Math.min(len, data.length, MAX_CHUNK);
                hex = bytesToHex(data.subarray(0, n));
            } else if (!data.isNull()) {
                const n = Math.min(len, MAX_CHUNK);
                const bytes = new Uint8Array(data.readByteArray(n));
                hex = bytesToHex(bytes);
            }
        }
    } catch (e) {
        tag = 'read-err:' + e;
    }
    send({
        event: evt, proto: proto, fd: fd, dir: dir,
        peer: peer || null, hex: hex, truncated: len > MAX_CHUNK,
        tag: tag || '', stack: stack || []
    });
}

function emitHex(evt, proto, fd, dir, peer, hex, truncated, tag, stack) {
    send({
        event: evt, proto: proto, fd: fd, dir: dir,
        peer: peer || null, hex: hex || '', truncated: !!truncated,
        tag: tag || '', stack: stack || []
    });
}

/* Blindaje: ejecuta fn() atrapando cualquier excepción del callback. */
function safe(fn) {
    return function () {
        try { return fn.apply(this, arguments); }
        catch (e) { reportHookErr(e); }
    };
}

function reportHookErr(e) {
    send({
        event: 'hook_error', proto: '', fd: -1, dir: '', peer: null,
        hex: '', truncated: false, tag: String(e), stack: []
    });
}

/* ---------- reescritura en vivo (solo llamadas de SALIDA) ---------- */

function applyRules(buf, len) {
    if (!rewriteEnabled || rules.length === 0 || len <= 0 || !buf || buf.isNull()) return;
    for (let r = 0; r < rules.length; r++) {
        const m = rules[r].match;
        const rep = rules[r].replace;
        if (!m || !rep || m.length !== rep.length || m.length > len || m.length === 0) continue;
        const head = m[0];
        for (let i = 0; i + m.length <= len; i++) {
            if (buf.add(i).readU8() !== head) continue;
            let ok = true;
            for (let j = 1; j < m.length; j++) {
                if (buf.add(i + j).readU8() !== m[j]) { ok = false; break; }
            }
            if (ok) buf.add(i).writeByteArray(rep);
        }
    }
}

function hexToBytes(hx) {
    const out = new Uint8Array(hx.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hx.substr(i * 2, 2), 16);
    }
    return out;
}

rpc.exports = {
    setRules: safe(function (list) {
        const next = [];
        if (Array.isArray(list)) {
            for (let i = 0; i < list.length && next.length < MAX_RULES; i++) {
                const it = list[i] || {};
                const hm = String(it.hex_match || '').toLowerCase();
                const hr = String(it.hex_replace || '').toLowerCase();
                if (!/^[0-9a-f]+$/.test(hm) || !/^[0-9a-f]+$/.test(hr) ||
                    hm.length !== hr.length || hm.length % 2 !== 0) {
                    continue;
                }
                next.push({ match: hexToBytes(hm), replace: hexToBytes(hr) });
            }
        }
        rules = next;
        return rules.length;
    }),
    setRewrite: safe(function (onoff) {
        rewriteEnabled = !!onoff;
        return rewriteEnabled;
    }),
    setCaptureStacks: safe(function (onoff) {
        captureStacks = !!onoff;
        return captureStacks;
    }),
    ping: safe(function () {
        return { rules: rules.length, enabled: rewriteEnabled, stacks: captureStacks };
    })
};

/* ---------- helpers WSABUF / Overlapped / IOCP ---------- */

function wsabufAt(lpBuffers, i) {
    const wsb = lpBuffers.add(i * Process.pointerSize * 2);
    return { len: wsb.readU32(), buf: wsb.add(Process.pointerSize).readPointer() };
}

function snapshotWsabufs(lpBuffers, nbufs) {
    const bufs = [];
    if (!lpBuffers || lpBuffers.isNull() || nbufs <= 0) return bufs;
    const nb = Math.min(nbufs, MAX_WSA_BUFS);
    for (let i = 0; i < nb; i++) {
        const b = wsabufAt(lpBuffers, i);
        bufs.push(b);
    }
    return bufs;
}

function copyWsabufsBytes(bufs, maxBytes) {
    var totalAvail = 0;
    for (var i = 0; i < bufs.length; i++) totalAvail += (bufs[i].len | 0);
    var want = maxBytes !== undefined ? Math.min(totalAvail, maxBytes, MAX_CHUNK) : Math.min(totalAvail, MAX_CHUNK);
    if (want <= 0) return { bytes: new Uint8Array(0), total: totalAvail };
    var out = new Uint8Array(want);
    var off = 0;
    for (var i = 0; i < bufs.length && off < want; i++) {
        var b = bufs[i];
        var take = Math.min(b.len | 0, want - off);
        if (take > 0 && b.buf && !b.buf.isNull()) {
            var chunk = new Uint8Array(b.buf.readByteArray(take));
            out.set(chunk, off);
            off += take;
        }
    }
    return { bytes: off === want ? out : out.subarray(0, off), total: totalAvail };
}

function readOverlappedInternalHigh(ovl) {
    if (!ovl || ovl.isNull()) return 0;
    try {
        return ovl.add(Process.pointerSize).readPointer().toUInt32();
    } catch (e) {
        return 0;
    }
}

function isOverlappedPending(ovl, lastErr) {
    if (!ovl || ovl.isNull()) return false;
    if (lastErr === WSA_IO_PENDING) return true;
    try {
        return ovl.readPointer().toUInt32() === 0x103; // STATUS_PENDING
    } catch (e) {
        return false;
    }
}

function registerPendingOverlapped(ovlPtr, info) {
    if (!ovlPtr || ovlPtr.isNull()) return;
    const key = ovlPtr.toString();
    pendingOverlapped[key] = info;
    pendingOvlOrder.push(key);
    while (pendingOvlOrder.length > MAX_PENDING_OVL) {
        const oldKey = pendingOvlOrder.shift();
        if (oldKey !== key) delete pendingOverlapped[oldKey];
    }
}

function attachCompletionRoutine(routinePtr) {
    if (!routinePtr || routinePtr.isNull()) return;
    const key = routinePtr.toString();
    if (hookedCompletionRoutines[key]) return;
    hookedCompletionRoutines[key] = true;
    Interceptor.attach(routinePtr, {
        onEnter: safe(function (args) {
            // void CALLBACK CompletionROUTINE(dwError, cbTransferred, lpOverlapped, dwFlags)
            if (args[0].toUInt32() !== 0) return;
            const transferred = args[1].toUInt32();
            completeOverlapped(args[2], transferred, 'overlapped:APC');
        })
    });
}

function completeOverlapped(ovlPtr, bytesTransferred, sourceTag) {
    if (!ovlPtr || ovlPtr.isNull()) return;
    const key = ovlPtr.toString();
    const info = pendingOverlapped[key];
    if (!info) return;
    delete pendingOverlapped[key];
    var n = bytesTransferred;
    if (!n || n <= 0) {
        n = readOverlappedInternalHigh(ovlPtr);
    }
    if (info.evt === 'connect') {
        var peer = info.peer || getPeerForFd(info.fd);
        emit('connect', info.proto, info.fd, 'out', peer, null, 0, sourceTag, info.stack);
        if (info.outBytes && info.outBytes.length > 0 && n > 0) {
            emit('wsa_send', info.proto, info.fd, 'out', peer, info.outBytes, Math.min(n, info.outBytes.length), sourceTag, info.stack);
        }
        return;
    }
    if (n <= 0) return;
    var peer = info.peer;
    if (!peer && info.fromPtr && !info.fromPtr.isNull()) {
        peer = sockaddrToObj(info.fromPtr);
    }
    if (!peer) peer = getPeerForFd(info.fd);

    if (info.dir === 'out') {
        if (info.outBytes && info.outBytes.length > 0) {
            var count = Math.min(n, info.outBytes.length);
            emit(info.evt, info.proto, info.fd, 'out', peer, info.outBytes, count, sourceTag, info.stack);
        }
    } else {
        var readRes = copyWsabufsBytes(info.bufs || [], n);
        if (readRes.bytes.length > 0) {
            emitHex(info.evt, info.proto, info.fd, 'in', peer,
                bytesToHex(readRes.bytes), n > MAX_CHUNK, sourceTag, info.stack);
        }
    }
}

/* ---------- hooks: connect / WSAConnect / ConnectEx ---------- */

function hookConnect() {
    var addr = ws2('connect');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                const fd = args[0].toInt32();
                const peer = sockaddrToObj(args[1]);
                if (peer && peer.ip && peer.ip !== '?') socketPeers[fd] = peer;
                emit('connect', protoForFd(fd, 'TCP'), fd, 'out', peer, null, 0, 'connect', captureStack(this.context));
            })
        });
    }
    var wsaConn = ws2('WSAConnect');
    if (wsaConn) {
        Interceptor.attach(wsaConn, {
            onEnter: safe(function (args) {
                const fd = args[0].toInt32();
                const peer = sockaddrToObj(args[1]);
                if (peer && peer.ip && peer.ip !== '?') socketPeers[fd] = peer;
                emit('connect', protoForFd(fd, 'TCP'), fd, 'out', peer, null, 0, 'WSAConnect', captureStack(this.context));
            })
        });
    }
}

function attachConnectEx(fnPtr) {
    if (!fnPtr || fnPtr.isNull()) return;
    var key = fnPtr.toString();
    if (hookedConnectEx[key]) return;
    hookedConnectEx[key] = true;
    Interceptor.attach(fnPtr, {
        onEnter: safe(function (args) {
            this.fd = args[0].toInt32();
            this.peer = sockaddrToObj(args[1]);
            if (this.peer && this.peer.ip && this.peer.ip !== '?') socketPeers[this.fd] = this.peer;
            this.sendBuf = args[3];
            this.sendLen = args[4].toUInt32();
            this.lpSent = args[5];
            this.lpOvl = args[6];
            this.stack = captureStack(this.context);
            this.outBytes = null;
            if (this.sendLen > 0 && this.sendBuf && !this.sendBuf.isNull()) {
                try {
                    applyRules(this.sendBuf, this.sendLen);
                    this.outBytes = new Uint8Array(this.sendBuf.readByteArray(Math.min(this.sendLen, MAX_CHUNK)));
                } catch (e) { }
            }
        }),
        onLeave: safe(function (retval) {
            const ok = retval.toInt32() !== 0;
            const lastErr = ok ? 0 : (this.errno || getWsaLastError());
            const proto = protoForFd(this.fd, 'TCP');
            if (ok) {
                if (this.lpOvl && !this.lpOvl.isNull()) delete pendingOverlapped[this.lpOvl.toString()];
                emit('connect', proto, this.fd, 'out', this.peer, null, 0, 'ConnectEx', this.stack);
                if (this.outBytes && this.outBytes.length > 0) {
                    var sent = (!this.lpSent.isNull()) ? this.lpSent.readU32() : this.sendLen;
                    if (sent > 0) {
                        emit('wsa_send', proto, this.fd, 'out', this.peer, this.outBytes, Math.min(sent, this.outBytes.length), 'ConnectEx', this.stack);
                    }
                }
            } else if (isOverlappedPending(this.lpOvl, lastErr)) {
                registerPendingOverlapped(this.lpOvl, {
                    evt: 'connect', proto: proto, fd: this.fd, peer: this.peer,
                    outBytes: this.outBytes, stack: this.stack
                });
            }
        })
    });
}

function hookWSAIoctl() {
    var addr = ws2('WSAIoctl');
    if (!addr) return;
    // WSAID_CONNECTEX = {0x25a207b9, 0xddf3, 0x4660, {0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}}
    const CONNECTEX_GUID = [0xb9, 0x07, 0xa2, 0x25, 0xf3, 0xdd, 0x60, 0x46, 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e];
    Interceptor.attach(addr, {
        onEnter: safe(function (args) {
            this.isConnectExQuery = false;
            const code = args[1].toUInt32();
            if (code !== 0xC8000006) return; // SIO_GET_EXTENSION_FUNCTION_POINTER
            const inBuf = args[2];
            const inLen = args[3].toUInt32();
            if (!inBuf.isNull() && inLen >= 16) {
                var b = new Uint8Array(inBuf.readByteArray(16));
                var match = true;
                for (var i = 0; i < 16; i++) {
                    if (b[i] !== CONNECTEX_GUID[i]) { match = false; break; }
                }
                if (match) {
                    this.isConnectExQuery = true;
                    this.outBuf = args[4];
                }
            }
        }),
        onLeave: safe(function (retval) {
            if (!this.isConnectExQuery || retval.toInt32() !== 0) return;
            if (this.outBuf && !this.outBuf.isNull()) {
                attachConnectEx(this.outBuf.readPointer());
            }
        })
    });
}

/* ---------- hooks: send / recv ---------- */

function hookSend() {
    var addr = ws2('send');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: safe(function (args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            const len = args[2].toInt32();
            this.stack = captureStack(this.context);
            try { applyRules(this.buf, len); } catch (e) { }
        }),
        onLeave: safe(function (retval) {
            const n = retval.toInt32();
            if (n > 0) {
                emit('send', protoForFd(this.fd, 'TCP'), this.fd, 'out',
                    getPeerForFd(this.fd), this.buf, n, '', this.stack);
            }
        })
    });
}

function hookRecv() {
    var addr = ws2('recv');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: safe(function (args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.stack = captureStack(this.context);
        }),
        onLeave: safe(function (retval) {
            const n = retval.toInt32();
            if (n > 0) {
                emit('recv', protoForFd(this.fd, 'TCP'), this.fd, 'in',
                    getPeerForFd(this.fd), this.buf, n, '', this.stack);
            }
        })
    });
}

/* ---------- hooks: WSASend / WSARecv / WSASendTo / WSARecvFrom (síncrono + Overlapped/IOCP) ---------- */

function hookWSASend() {
    var addr = ws2('WSASend');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: safe(function (args) {
            this.fd = args[0].toInt32();
            this.bufs = snapshotWsabufs(args[1], args[2].toInt32());
            this.lpSent = args[3];
            this.lpOverlapped = args[5];
            this.lpCompletion = args[6];
            this.stack = captureStack(this.context);
            try {
                for (let i = 0; i < this.bufs.length; i++) {
                    applyRules(this.bufs[i].buf, this.bufs[i].len | 0);
                }
            } catch (e) { }
            this.snap = copyWsabufsBytes(this.bufs);
            if (this.lpCompletion && !this.lpCompletion.isNull()) {
                attachCompletionRoutine(this.lpCompletion);
            }
        }),
        onLeave: safe(function (retval) {
            const rc = retval.toInt32();
            const lastErr = rc === 0 ? 0 : (this.errno || getWsaLastError());
            const proto = protoForFd(this.fd, 'TCP');
            const peer = getPeerForFd(this.fd);
            if (rc === 0) {
                if (this.lpOverlapped && !this.lpOverlapped.isNull()) {
                    delete pendingOverlapped[this.lpOverlapped.toString()];
                }
                let sent = 0;
                if (this.lpSent && !this.lpSent.isNull()) {
                    sent = this.lpSent.readU32();
                } else {
                    sent = this.snap.total;
                }
                if (sent > 0 && this.snap.bytes.length > 0) {
                    emit('wsa_send', proto, this.fd, 'out', peer,
                        this.snap.bytes, Math.min(sent, this.snap.bytes.length), '', this.stack);
                }
            } else if (isOverlappedPending(this.lpOverlapped, lastErr)) {
                registerPendingOverlapped(this.lpOverlapped, {
                    dir: 'out', evt: 'wsa_send', proto: proto, fd: this.fd,
                    peer: peer, outBytes: this.snap.bytes, stack: this.stack
                });
            }
        })
    });
}

function hookWSARecv() {
    var addr = ws2('WSARecv');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: safe(function (args) {
            this.fd = args[0].toInt32();
            this.bufs = snapshotWsabufs(args[1], args[2].toInt32());
            this.lpRecvd = args[3];
            this.lpOverlapped = args[5];
            this.lpCompletion = args[6];
            this.stack = captureStack(this.context);
            if (this.lpCompletion && !this.lpCompletion.isNull()) {
                attachCompletionRoutine(this.lpCompletion);
            }
        }),
        onLeave: safe(function (retval) {
            const rc = retval.toInt32();
            const lastErr = rc === 0 ? 0 : (this.errno || getWsaLastError());
            const proto = protoForFd(this.fd, 'TCP');
            const peer = getPeerForFd(this.fd);
            if (rc === 0) {
                if (this.lpOverlapped && !this.lpOverlapped.isNull()) {
                    delete pendingOverlapped[this.lpOverlapped.toString()];
                }
                let recvd = 0;
                if (this.lpRecvd && !this.lpRecvd.isNull()) {
                    recvd = this.lpRecvd.readU32();
                } else if (this.lpOverlapped && !this.lpOverlapped.isNull()) {
                    recvd = readOverlappedInternalHigh(this.lpOverlapped);
                }
                if (recvd > 0) {
                    const res = copyWsabufsBytes(this.bufs, recvd);
                    if (res.bytes.length > 0) {
                        emitHex('wsa_recv', proto, this.fd, 'in', peer,
                            bytesToHex(res.bytes), recvd > MAX_CHUNK, '', this.stack);
                    }
                }
            } else if (isOverlappedPending(this.lpOverlapped, lastErr)) {
                registerPendingOverlapped(this.lpOverlapped, {
                    dir: 'in', evt: 'wsa_recv', proto: proto, fd: this.fd,
                    peer: peer, bufs: this.bufs, stack: this.stack
                });
            }
        })
    });
}

function hookWSASendTo() {
    var addr = ws2('WSASendTo');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: safe(function (args) {
            this.fd = args[0].toInt32();
            this.bufs = snapshotWsabufs(args[1], args[2].toInt32());
            this.lpSent = args[3];
            this.peer = sockaddrToObj(args[5]) || getPeerForFd(this.fd);
            this.lpOverlapped = args[7];
            this.lpCompletion = args[8];
            this.stack = captureStack(this.context);
            try {
                for (let i = 0; i < this.bufs.length; i++) {
                    applyRules(this.bufs[i].buf, this.bufs[i].len | 0);
                }
            } catch (e) { }
            this.snap = copyWsabufsBytes(this.bufs);
            if (this.lpCompletion && !this.lpCompletion.isNull()) {
                attachCompletionRoutine(this.lpCompletion);
            }
        }),
        onLeave: safe(function (retval) {
            const rc = retval.toInt32();
            const lastErr = rc === 0 ? 0 : (this.errno || getWsaLastError());
            const proto = protoForFd(this.fd, 'UDP');
            const evtName = proto === 'TCP' ? 'wsa_send' : 'udp_send';
            if (rc === 0) {
                if (this.lpOverlapped && !this.lpOverlapped.isNull()) {
                    delete pendingOverlapped[this.lpOverlapped.toString()];
                }
                const sent = (this.lpSent && !this.lpSent.isNull()) ? this.lpSent.readU32() : this.snap.total;
                if (sent > 0 && this.snap.bytes.length > 0) {
                    emit(evtName, proto, this.fd, 'out', this.peer,
                        this.snap.bytes, Math.min(sent, this.snap.bytes.length), 'WSASendTo', this.stack);
                }
            } else if (isOverlappedPending(this.lpOverlapped, lastErr)) {
                registerPendingOverlapped(this.lpOverlapped, {
                    dir: 'out', evt: evtName, proto: proto, fd: this.fd,
                    peer: this.peer, outBytes: this.snap.bytes, stack: this.stack
                });
            }
        })
    });
}

function hookWSARecvFrom() {
    var addr = ws2('WSARecvFrom');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: safe(function (args) {
            this.fd = args[0].toInt32();
            this.bufs = snapshotWsabufs(args[1], args[2].toInt32());
            this.lpRecvd = args[3];
            this.fromPtr = args[5];
            this.lpOverlapped = args[7];
            this.lpCompletion = args[8];
            this.stack = captureStack(this.context);
            if (this.lpCompletion && !this.lpCompletion.isNull()) {
                attachCompletionRoutine(this.lpCompletion);
            }
        }),
        onLeave: safe(function (retval) {
            const rc = retval.toInt32();
            const lastErr = rc === 0 ? 0 : (this.errno || getWsaLastError());
            const proto = protoForFd(this.fd, 'UDP');
            const evtName = proto === 'TCP' ? 'wsa_recv' : 'udp_recv';
            if (rc === 0) {
                if (this.lpOverlapped && !this.lpOverlapped.isNull()) {
                    delete pendingOverlapped[this.lpOverlapped.toString()];
                }
                const recvd = (this.lpRecvd && !this.lpRecvd.isNull())
                    ? this.lpRecvd.readU32()
                    : readOverlappedInternalHigh(this.lpOverlapped);
                const peer = sockaddrToObj(this.fromPtr) || getPeerForFd(this.fd);
                if (recvd > 0) {
                    const res = copyWsabufsBytes(this.bufs, recvd);
                    if (res.bytes.length > 0) {
                        emitHex(evtName, proto, this.fd, 'in', peer,
                            bytesToHex(res.bytes), recvd > MAX_CHUNK, 'WSARecvFrom', this.stack);
                    }
                }
            } else if (isOverlappedPending(this.lpOverlapped, lastErr)) {
                registerPendingOverlapped(this.lpOverlapped, {
                    dir: 'in', evt: evtName, proto: proto, fd: this.fd,
                    fromPtr: this.fromPtr, bufs: this.bufs, stack: this.stack
                });
            }
        })
    });
}

function hookOverlappedCompletions() {
    // 1. WSAGetOverlappedResult(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags)
    var wsaRes = ws2('WSAGetOverlappedResult');
    if (wsaRes) {
        Interceptor.attach(wsaRes, {
            onEnter: safe(function (args) {
                this.ovl = args[1];
                this.cbTransfer = args[2];
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0) return;
                const n = (this.cbTransfer && !this.cbTransfer.isNull()) ? this.cbTransfer.readU32() : 0;
                completeOverlapped(this.ovl, n, 'overlapped:WSAGetOverlappedResult');
            })
        });
    }

    // 2. GetOverlappedResult / GetOverlappedResultEx
    for (const name of ['GetOverlappedResult', 'GetOverlappedResultEx']) {
        findKernelExports(name).forEach(function (gor) {
            Interceptor.attach(gor, {
                onEnter: safe(function (args) {
                    this.ovl = args[1];
                    this.cbTransfer = args[2];
                }),
                onLeave: safe(function (retval) {
                    if (retval.toInt32() === 0) return;
                    const n = (this.cbTransfer && !this.cbTransfer.isNull()) ? this.cbTransfer.readU32() : 0;
                    completeOverlapped(this.ovl, n, 'overlapped:' + name);
                })
            });
        });
    }

    // 3. GetQueuedCompletionStatus(CompletionPort, lpNumberOfBytesTransferred, lpCompletionKey, lpOverlapped, dwMilliseconds)
    findKernelExports('GetQueuedCompletionStatus').forEach(function (gqcs) {
        Interceptor.attach(gqcs, {
            onEnter: safe(function (args) {
                this.lpBytes = args[1];
                this.lpOvlOut = args[3];
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0) return;
                if (!this.lpOvlOut || this.lpOvlOut.isNull()) return;
                const ovl = this.lpOvlOut.readPointer();
                if (!ovl || ovl.isNull()) return;
                const n = (this.lpBytes && !this.lpBytes.isNull()) ? this.lpBytes.readU32() : 0;
                completeOverlapped(ovl, n, 'iocp:GQCS');
            })
        });
    });

    // 4. GetQueuedCompletionStatusEx(CompletionPort, lpCompletionPortEntries, ulCount, ulNumEntriesRemoved, dwMilliseconds, fAlertable)
    const entryStride = 4 * Process.pointerSize;
    const ovlOffset = Process.pointerSize;
    const bytesOffset = 3 * Process.pointerSize;
    findKernelExports('GetQueuedCompletionStatusEx').forEach(function (gqcsex) {
        Interceptor.attach(gqcsex, {
            onEnter: safe(function (args) {
                this.entries = args[1];
                this.ulRemoved = args[3];
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0) return;
                if (!this.entries || this.entries.isNull() || !this.ulRemoved || this.ulRemoved.isNull()) return;
                const count = Math.min(this.ulRemoved.readU32(), 256);
                for (let i = 0; i < count; i++) {
                    const entry = this.entries.add(i * entryStride);
                    const ovl = entry.add(ovlOffset).readPointer();
                    const n = entry.add(bytesOffset).readU32();
                    if (ovl && !ovl.isNull()) {
                        completeOverlapped(ovl, n, 'iocp:GQCSEx');
                    }
                }
            })
        });
    });
}

/* ---------- hooks: UDP (sendto / recvfrom) ---------- */
function hookUDPSend() {
    var addr = ws2('sendto');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: safe(function (args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.peer = sockaddrToObj(args[4]) || getPeerForFd(this.fd);
            this.stack = captureStack(this.context);
            try { applyRules(this.buf, args[2].toInt32()); } catch (e) { }
        }),
        onLeave: safe(function (retval) {
            const n = retval.toInt32();
            if (n > 0) {
                const proto = protoForFd(this.fd, 'UDP');
                emit(proto === 'TCP' ? 'send' : 'udp_send', proto, this.fd, 'out', this.peer, this.buf, n, '', this.stack);
            }
        })
    });
}

function hookUDPRecv() {
    var addr = ws2('recvfrom');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: safe(function (args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.from = args[4];
            this.stack = captureStack(this.context);
        }),
        onLeave: safe(function (retval) {
            const n = retval.toInt32();
            if (n > 0) {
                const proto = protoForFd(this.fd, 'UDP');
                emit(proto === 'TCP' ? 'recv' : 'udp_recv', proto, this.fd, 'in', sockaddrToObj(this.from) || getPeerForFd(this.fd), this.buf, n, '', this.stack);
            }
        })
    });
}

/* ---------- hooks: ciclo de vida del socket ---------- */
function hookSocket() {
    var addr = ws2('socket');
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                this.af = args[0].toInt32();
                this.type = args[1].toInt32();
            }),
            onLeave: safe(function (retval) {
                const s = retval.toInt32();
                if (s >= 0) {
                    const proto = PROTO[this.type] || '?';
                    if (proto !== '?') socketProtos[s] = proto;
                    emit('socket', proto, s, 'out', null, null, 0,
                        'new socket af=' + this.af + ' type=' + this.type);
                }
            })
        });
    }
    ['WSASocketW', 'WSASocketA'].forEach(function (wname) {
        var waddr = ws2(wname);
        if (!waddr) return;
        Interceptor.attach(waddr, {
            onEnter: safe(function (args) {
                this.af = args[0].toInt32();
                this.type = args[1].toInt32();
            }),
            onLeave: safe(function (retval) {
                const s = retval.toInt32();
                if (s >= 0) {
                    const proto = PROTO[this.type] || '?';
                    if (proto !== '?') socketProtos[s] = proto;
                    emit('socket', proto, s, 'out', null, null, 0,
                        'new socket (' + wname + ') af=' + this.af + ' type=' + this.type);
                }
            })
        });
    });
}

function hookClosesocket() {
    var addr = ws2('closesocket');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: safe(function (args) {
            const fd = args[0].toInt32();
            const peer = socketPeers[fd] || null;
            delete socketPeers[fd];
            delete socketProtos[fd];
            emit('close', '?', fd, 'out', peer, null, 0, 'close');
        })
    });
}

/* ---------- hooks: DNS (getaddrinfo / GetAddrInfoW / gethostbyname) ---------- */

function emitAddrinfoList(host, headPtr) {
    if (!host || !headPtr || headPtr.isNull()) return;
    const addrOff = 16 + 2 * Process.pointerSize;
    const nextOff = 16 + 3 * Process.pointerSize;
    var cur = headPtr;
    var guard = 0;
    while (cur && !cur.isNull() && guard < 32) {
        guard++;
        try {
            const sa = cur.add(addrOff).readPointer();
            const peer = sockaddrToObj(sa);
            if (peer && peer.ip && peer.ip !== '?') {
                send({
                    event: 'dns', proto: 'DNS', fd: -1, dir: 'in',
                    peer: { ip: peer.ip, port: 0 }, hex: '', truncated: false,
                    tag: host, stack: []
                });
            }
            cur = cur.add(nextOff).readPointer();
        } catch (e) {
            break;
        }
    }
}

function hookDns() {
    var gai = ws2('getaddrinfo');
    if (gai) {
        Interceptor.attach(gai, {
            onEnter: safe(function (args) {
                this.host = args[0].isNull() ? '' : args[0].readCString(256);
                this.ppResult = args[3];
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() !== 0 || !this.host || !this.ppResult || this.ppResult.isNull()) return;
                emitAddrinfoList(this.host, this.ppResult.readPointer());
            })
        });
    }
    var gaiw = ws2('GetAddrInfoW');
    if (gaiw) {
        Interceptor.attach(gaiw, {
            onEnter: safe(function (args) {
                this.host = args[0].isNull() ? '' : readWide(args[0], 256);
                this.ppResult = args[3];
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() !== 0 || !this.host || !this.ppResult || this.ppResult.isNull()) return;
                emitAddrinfoList(this.host, this.ppResult.readPointer());
            })
        });
    }
}

/* ---------- hooks: Schannel / Secur32 ---------- */

const SECBUFFER_DATA = 1;
const SEC_LIT = Process.pointerSize === 8
    ? { secbuf: 16, typeOff: 4, ptrOff: 8 }
    : { secbuf: 12, typeOff: 4, ptrOff: 8 };

function pseudoFdFromCtx(ctx) {
    var hex = ctx.toString();
    if (hex.indexOf('0x') === 0) hex = hex.substring(2);
    var n = parseInt(hex, 16);
    if (isNaN(n)) n = 0;
    return -(1 + (n & 0xFFF));
}

function secBuffers(desc) {
    var out = [];
    var cBuffers = desc.add(4).readULong() | 0;
    var pBuffers = desc.add(8).readPointer();
    var total = cBuffers | 0;
    if (total > 32) total = 32;
    for (let i = 0; i < total; i++) {
        var sb = pBuffers.add(i * SEC_LIT.secbuf);
        var len = sb.readULong() | 0;
        var type = sb.add(SEC_LIT.typeOff).readULong() | 0;
        var buf = sb.add(SEC_LIT.ptrOff).readPointer();
        out.push({ len: len, type: type, buf: buf });
    }
    return out;
}

function emitPlain(evt, pseudoFd, bufs, tag, stack, peer) {
    for (let i = 0; i < bufs.length; i++) {
        var b = bufs[i];
        if (b.type === SECBUFFER_DATA && b.len > 0) {
            emit(evt, 'TLS', pseudoFd, evt === 'tls_out' ? 'out' : 'in', peer || null, b.buf, b.len, tag, stack);
        }
    }
}

function resolveSecHook(name) {
    var mods = ['Secur32.dll', 'sspicli.dll', 'schannel.dll'];
    for (let i = 0; i < mods.length; i++) {
        try {
            var mod = Process.findModuleByName(mods[i]);
            if (!mod) continue;
            var addr = mod.findExportByName(name);
            if (addr) return { addr: addr, mod: mods[i] };
        } catch (e) { }
    }
    return null;
}

function hookEncryptMessage() {
    var r = resolveSecHook('EncryptMessage');
    if (!r) return;
    Interceptor.attach(r.addr, {
        onEnter: safe(function (args) {
            var pseudoFd = pseudoFdFromCtx(args[0]);
            var inDesc = args[2];
            emitPlain('tls_out', pseudoFd, secBuffers(inDesc),
                'HTTPS plano saliendo (pre-cifrado) ' + r.mod, captureStack(this.context));
        })
    });
}

function hookDecryptMessage() {
    var r = resolveSecHook('DecryptMessage');
    if (!r) return;
    Interceptor.attach(r.addr, {
        onEnter: safe(function (args) {
            this.desc = args[1];
            this.pseudoFd = pseudoFdFromCtx(args[0]);
        }),
        onLeave: safe(function (retval) {
            var st = retval.toInt32();
            if (st < 0) return;
            emitPlain('tls_in', this.pseudoFd, secBuffers(this.desc),
                'HTTPS plano entrando (post-descifrado)');
        })
    });
}

/* ---------- hooks: OpenSSL / BoringSSL (texto en claro + SSLKEYLOGFILE) ---------- */

function hookOpenSSLModule(mod) {
    if (!mod) return false;
    var modKey = mod.name.toLowerCase();
    if (hookedSslModules[modKey]) return false;

    var sslWrite = mod.findExportByName('SSL_write');
    var sslRead = mod.findExportByName('SSL_read');
    var sslWriteEx = mod.findExportByName('SSL_write_ex');
    var sslReadEx = mod.findExportByName('SSL_read_ex');
    if (!sslWrite && !sslRead && !sslWriteEx && !sslReadEx) return false;

    hookedSslModules[modKey] = true;
    var sslGetFdAddr = mod.findExportByName('SSL_get_fd');
    var sslGetFd = sslGetFdAddr ? new NativeFunction(sslGetFdAddr, 'int', ['pointer']) : null;
    var sslSetKeylogAddr = mod.findExportByName('SSL_CTX_set_keylog_callback');
    var sslSetKeylog = sslSetKeylogAddr ? new NativeFunction(sslSetKeylogAddr, 'void', ['pointer', 'pointer']) : null;

    var keylogCb = new NativeCallback(function (ssl, linePtr) {
        try {
            if (linePtr && !linePtr.isNull()) {
                var line = linePtr.readCString(1024);
                if (line) {
                    send({
                        event: 'tls_keylog', proto: 'TLS', fd: -1, dir: '',
                        peer: null, hex: '', truncated: false, tag: line, stack: []
                    });
                }
            }
        } catch (e) { }
    }, 'void', ['pointer', 'pointer']);
    sslKeylogCallbacks.push(keylogCb);

    function registerCtxKeylog(ctxPtr) {
        if (!sslSetKeylog || !ctxPtr || ctxPtr.isNull()) return;
        var k = ctxPtr.toString();
        if (hookedSslCtxs[k]) return;
        hookedSslCtxs[k] = true;
        try { sslSetKeylog(ctxPtr, keylogCb); } catch (e) { }
    }

    function sslFdInfo(ssl) {
        var pfd = -((Math.abs(pseudoFdFromCtx(ssl)) + 20000));
        var peer = null;
        if (sslGetFd && ssl && !ssl.isNull()) {
            try {
                var realFd = sslGetFd(ssl);
                if (realFd >= 0) {
                    peer = getPeerForFd(realFd);
                    pfd = -(20000 + realFd);
                }
            } catch (e) { }
        }
        return { fd: pfd, peer: peer };
    }

    if (sslWrite) {
        Interceptor.attach(sslWrite, {
            onEnter: safe(function (args) {
                this.ssl = args[0];
                this.buf = args[1];
                this.num = args[2].toInt32();
                this.stack = captureStack(this.context);
            }),
            onLeave: safe(function (retval) {
                var n = retval.toInt32();
                if (n > 0) {
                    var info = sslFdInfo(this.ssl);
                    emit('tls_out', 'TLS', info.fd, 'out', info.peer, this.buf, n,
                        'OpenSSL SSL_write (' + mod.name + ')', this.stack);
                }
            })
        });
    }
    if (sslRead) {
        Interceptor.attach(sslRead, {
            onEnter: safe(function (args) {
                this.ssl = args[0];
                this.buf = args[1];
                this.stack = captureStack(this.context);
            }),
            onLeave: safe(function (retval) {
                var n = retval.toInt32();
                if (n > 0) {
                    var info = sslFdInfo(this.ssl);
                    emit('tls_in', 'TLS', info.fd, 'in', info.peer, this.buf, n,
                        'OpenSSL SSL_read (' + mod.name + ')', this.stack);
                }
            })
        });
    }
    if (sslWriteEx) {
        Interceptor.attach(sslWriteEx, {
            onEnter: safe(function (args) {
                this.ssl = args[0];
                this.buf = args[1];
                this.num = args[2].toUInt32();
                this.writtenPtr = args[3];
                this.stack = captureStack(this.context);
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() !== 1) return;
                var n = (this.writtenPtr && !this.writtenPtr.isNull()) ? this.writtenPtr.readPointer().toUInt32() : this.num;
                if (n > 0) {
                    var info = sslFdInfo(this.ssl);
                    emit('tls_out', 'TLS', info.fd, 'out', info.peer, this.buf, n,
                        'OpenSSL SSL_write_ex (' + mod.name + ')', this.stack);
                }
            })
        });
    }
    if (sslReadEx) {
        Interceptor.attach(sslReadEx, {
            onEnter: safe(function (args) {
                this.ssl = args[0];
                this.buf = args[1];
                this.readPtr = args[3];
                this.stack = captureStack(this.context);
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() !== 1 || !this.readPtr || this.readPtr.isNull()) return;
                var n = this.readPtr.readPointer().toUInt32();
                if (n > 0) {
                    var info = sslFdInfo(this.ssl);
                    emit('tls_in', 'TLS', info.fd, 'in', info.peer, this.buf, n,
                        'OpenSSL SSL_read_ex (' + mod.name + ')', this.stack);
                }
            })
        });
    }

    for (const ctxFnName of ['SSL_CTX_new', 'SSL_CTX_new_ex']) {
        var ctxFn = mod.findExportByName(ctxFnName);
        if (ctxFn && sslSetKeylog) {
            Interceptor.attach(ctxFn, {
                onLeave: safe(function (retval) {
                    if (!retval.isNull()) registerCtxKeylog(retval);
                })
            });
        }
    }

    var sslNewFn = mod.findExportByName('SSL_new');
    if (sslNewFn && sslSetKeylog) {
        Interceptor.attach(sslNewFn, {
            onEnter: safe(function (args) {
                if (!args[0].isNull()) registerCtxKeylog(args[0]);
            })
        });
    }

    send({
        event: 'api_activity', proto: 'TLS', fd: -1, dir: '',
        peer: null, hex: '', truncated: false,
        tag: 'OpenSSL hooked: ' + mod.name + (sslSetKeylog ? ' (+keylog)' : '')
    });
    return true;
}

function scanOpenSSLModules() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        var name = mods[i].name.toLowerCase();
        if (name.indexOf('ssl') >= 0 || name.indexOf('crypto') >= 0 ||
            name.indexOf('node') >= 0 || name.indexOf('boring') >= 0 ||
            name.indexOf('electron') >= 0 || name.indexOf('libcurl') >= 0) {
            try { hookOpenSSLModule(mods[i]); } catch (e) { }
        }
    }
}

/* ---------- hooks: procesos hijo (CreateProcessW / CreateProcessA) ---------- */

function hookChildProcesses() {
    for (const suffix of ['W', 'A']) {
        var addr = findKernelExport('CreateProcess' + suffix);
        if (!addr) continue;
        Interceptor.attach(addr, {
            onEnter: safe(function (args) {
                this.app = args[0].isNull() ? '' : (suffix === 'W' ? readWide(args[0], 512) : args[0].readCString(512));
                this.cmd = args[1].isNull() ? '' : (suffix === 'W' ? readWide(args[1], 512) : args[1].readCString(512));
                this.lpProcInfo = args[9];
            }),
            onLeave: safe(function (retval) {
                if (retval.toInt32() === 0 || !this.lpProcInfo || this.lpProcInfo.isNull()) return;
                const childPid = this.lpProcInfo.add(2 * Process.pointerSize).readU32();
                if (childPid > 0) {
                    send({
                        event: 'child_spawned', proto: 'PROC', fd: childPid, dir: 'out',
                        peer: null, hex: '', truncated: false,
                        tag: this.cmd || this.app || ('PID ' + childPid), stack: []
                    });
                }
            })
        });
    }
}

function bootStage(name, fn) {
    try { fn(); return null; }
    catch (e) { return name + ': ' + e; }
}

var deferredHooks = [];
function hookWhenLoaded(moduleName, hookFn) {
    if (Process.findModuleByName(moduleName)) return;
    deferredHooks.push({ mod: moduleName.toLowerCase(), fn: hookFn, done: false });
}

function installLoadLibraryWatcher() {
    var onLoaded = safe(function () {
        for (var i = 0; i < deferredHooks.length; i++) {
            var item = deferredHooks[i];
            if (!item.done && Process.findModuleByName(item.mod)) {
                item.done = true;
                var res = bootStage(item.mod, item.fn);
                send({
                    event: 'ready', proto: '', fd: -1, dir: '', peer: null,
                    hex: '', truncated: false,
                    tag: 'Hook diferido ' + item.mod + (res ? ' ERROR: ' + res : ' OK')
                });
            }
        }
        scanOpenSSLModules();
    });
    ['LoadLibraryW', 'LoadLibraryA', 'LoadLibraryExW', 'LoadLibraryExA'].forEach(
        function (fn) {
            var addr = findKernelExport(fn);
            if (addr) Interceptor.attach(addr, { onLeave: onLoaded });
        }
    );
}

(function () {
    var errors = [];
    var stages = [
        ['connect', hookConnect], ['WSAIoctl', hookWSAIoctl],
        ['send', hookSend], ['recv', hookRecv],
        ['WSASend', hookWSASend], ['WSARecv', hookWSARecv],
        ['WSASendTo', hookWSASendTo], ['WSARecvFrom', hookWSARecvFrom],
        ['overlapped', hookOverlappedCompletions],
        ['sendto', hookUDPSend], ['recvfrom', hookUDPRecv],
        ['socket', hookSocket], ['closesocket', hookClosesocket],
        ['dns', hookDns],
        ['OpenSSL', scanOpenSSLModules],
        ['ChildProcesses', hookChildProcesses],
        ['Secur32!EncryptMessage', hookEncryptMessage],
        ['Secur32!DecryptMessage', hookDecryptMessage],
    ];
    var plaintextHooks = [];
    var winHttp = bootStage('WinHTTP plaintext', function () {
        plaintextHooks = plaintextHooks.concat(hookWinHttp());
    });
    if (winHttp) errors.push(winHttp);
    var winInet = bootStage('WinINet plaintext', function () {
        plaintextHooks = plaintextHooks.concat(hookWinInet());
    });
    if (winInet) errors.push(winInet);
    var steamHttp = bootStage('SteamHTTP plaintext', function () {
        plaintextHooks = plaintextHooks.concat(hookSteamHttp());
    });
    if (steamHttp) errors.push(steamHttp);
    var steamNetworking = bootStage('SteamNetworking plaintext', function () {
        plaintextHooks = plaintextHooks.concat(hookSteamNetworking());
    });
    if (steamNetworking) errors.push(steamNetworking);
    hookWhenLoaded('winhttp.dll', hookWinHttp);
    hookWhenLoaded('wininet.dll', hookWinInet);
    installLoadLibraryWatcher();
    for (var i = 0; i < stages.length; i++) {
        var e = bootStage(stages[i][0], stages[i][1]);
        if (e) errors.push(e);
    }
    send({
        event: 'ready', proto: '', fd: -1, dir: '', peer: null,
        hex: '', truncated: false,
        tag: 'Hooks plaintext: ' +
            (plaintextHooks.length ? plaintextHooks.join(', ') : 'ninguna exportada') +
            (errors.length ? (' | ERRORES: ' + errors.join(' | ')) : ' | agent ready')
    });
})();
