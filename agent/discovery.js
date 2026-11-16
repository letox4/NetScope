/*
 * NetScope - Application Discovery (Frida)
 * Enumera módulos cargados en el proceso y detecta runtimes/bibliotecas
 * de red y criptografía para activar adaptadores de hooks automáticamente.
 *
 * Resultado: se envía vía send() como {event:'discovery', ...} con:
 *   - modules: lista de {name, path, base, size}
 *   - runtimes: {unity, mono, schannel, openssl, boringssl, mbedTLS, winhttp, wininet, winsock}
 *   - adapters: lista de adaptadores que se activarán
 */

'use strict';

const KNOWN_RUNTIMES = {
    // Unity / IL2CPP
    'UnityPlayer.dll': { kind: 'unity_player', adapter: 'unity' },
    'GameAssembly.dll': { kind: 'unity_il2cpp', adapter: 'unity' },
    'mono-2.0-bdwgc.dll': { kind: 'mono', adapter: 'mono' },
    'mono.dll': { kind: 'mono', adapter: 'mono' },
    // Schannel (TLS Windows)
    'schannel.dll': { kind: 'schannel', adapter: 'schannel' },
    'sspicli.dll': { kind: 'sspi', adapter: 'schannel' },
    'secur32.dll': { kind: 'secur32', adapter: 'schannel' },
    // OpenSSL / BoringSSL / mbedTLS
    'libssl.dll': { kind: 'openssl', adapter: 'openssl' },
    'libssl-1_1.dll': { kind: 'openssl', adapter: 'openssl' },
    'libssl-3.dll': { kind: 'openssl', adapter: 'openssl' },
    'ssl.dll': { kind: 'openssl', adapter: 'openssl' },
    'libcrypto.dll': { kind: 'openssl', adapter: 'openssl' },
    'boringssl.dll': { kind: 'boringssl', adapter: 'boringssl' },
    'libmbedcrypto.dll': { kind: 'mbedTLS', adapter: 'mbedTLS' },
    'mbedtls.dll': { kind: 'mbedTLS', adapter: 'mbedTLS' },
    // Windows HTTP stacks
    'winhttp.dll': { kind: 'winhttp', adapter: 'winhttp' },
    'wininet.dll': { kind: 'wininet', adapter: 'wininet' },
    'urlmon.dll': { kind: 'urlmon', adapter: 'winhttp' },
    // Winsock
    'ws2_32.dll': { kind: 'winsock', adapter: 'winsock' },
    'mswsock.dll': { kind: 'winsock', adapter: 'winsock' },
    'ws2help.dll': { kind: 'winsock', adapter: 'winsock' },
    // .NET
    'clr.dll': { kind: 'dotnet', adapter: 'dotnet' },
    'coreclr.dll': { kind: 'dotnet_core', adapter: 'dotnet' },
};

/* Exports conocidos de TLS/crypto que buscamos en los módulos. */
const KNOWN_EXPORTS = {
    // OpenSSL
    'SSL_write': { runtime: 'openssl', adapter: 'openssl' },
    'SSL_read': { runtime: 'openssl', adapter: 'openssl' },
    'SSL_do_handshake': { runtime: 'openssl', adapter: 'openssl' },
    // Schannel
    'EncryptMessage': { runtime: 'schannel', adapter: 'schannel' },
    'DecryptMessage': { runtime: 'schannel', adapter: 'schannel' },
    // WinHTTP
    'WinHttpSendRequest': { runtime: 'winhttp', adapter: 'winhttp' },
    'WinHttpReceiveResponse': { runtime: 'winhttp', adapter: 'winhttp' },
    // WinINet
    'HttpSendRequestW': { runtime: 'wininet', adapter: 'wininet' },
    'HttpSendRequestA': { runtime: 'wininet', adapter: 'wininet' },
    // Unity / IL2CPP (nombres típicos de UnityEngine.Networking)
    'UnityEngine_Networking_UnityWebRequest_SendWebRequest': { runtime: 'unity', adapter: 'unity' },
    'UnityEngine_Networking_UnityWebRequest_Get': { runtime: 'unity', adapter: 'unity' },
    'UnityEngine_Networking_UnityWebRequest_Post': { runtime: 'unity', adapter: 'unity' },
    'UnityEngine_Networking_DownloadHandler_GetText': { runtime: 'unity', adapter: 'unity' },
};

/* TLS fingerprint: bytes iniciales de un handshake TLS (0x16 0x03 0x01..0x03). */
function looksLikeTLS(bytes) {
    if (!bytes || bytes.length < 3) return false;
    return bytes[0] === 0x16 && bytes[1] === 0x03 &&
           (bytes[2] === 0x01 || bytes[2] === 0x02 || bytes[2] === 0x03);
}

function discover() {
    var modules = [];
    var runtimes = {};
    var adapters = new Set();
    var exportsFound = {};

    // 1. Enumerar módulos cargados
    Process.enumerateModules().forEach(function (m) {
        modules.push({
            name: m.name,
            path: m.path,
            base: m.base.toString(),
            size: m.size,
        });
        var low = m.name.toLowerCase();
        for (var kn in KNOWN_RUNTIMES) {
            if (kn.toLowerCase() === low) {
                var info = KNOWN_RUNTIMES[kn];
                runtimes[info.kind] = (runtimes[info.kind] || 0) + 1;
                adapters.add(info.adapter);
            }
        }
    });

    // 2. Buscar exports conocidos en cada módulo
    Process.enumerateModules().forEach(function (m) {
        for (var en in KNOWN_EXPORTS) {
            try {
                var addr = m.getExportByName(en);
                if (addr) {
                    var info = KNOWN_EXPORTS[en];
                    exportsFound[en] = { module: m.name, addr: addr.toString() };
                    runtimes[info.runtime] = (runtimes[info.runtime] || 0) + 1;
                    adapters.add(info.adapter);
                }
            } catch (e) { }
        }
    });

    // 3. Siempre Winsock (ya implementado)
    adapters.add('winsock');

    // 4. Enviar resultado
    send({
        event: 'discovery',
        proto: '', fd: -1, dir: '', peer: null, hex: '', truncated: false,
        tag: 'discovery',
        payload: {
            modules: modules,
            runtimes: runtimes,
            exports: exportsFound,
            adapters: Array.from(adapters),
            moduleCount: modules.length,
        }
    });

    return { modules: modules, runtimes: runtimes, adapters: Array.from(adapters) };
}

// Exponer para que Python pueda llamarlo vía RPC si necesita re-discovery
rpc.exports = rpc.exports || {};
rpc.exports.discover = function () { return discover(); };
rpc.exports.listModules = function () {
    return Process.enumerateModules().map(function (m) {
        return { name: m.name, path: m.path, base: m.base.toString(), size: m.size };
    });
};

// Auto-discovery al cargar el agente
try { discover(); } catch (e) {
    send({ event: 'discovery_error', proto: '', fd: -1, dir: '', peer: null,
           hex: '', truncated: false, tag: String(e) });
}
