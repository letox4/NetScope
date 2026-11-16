/*
 * NetScope — Memory Agent (RPC puro, sin lógica de negocio)
 * Se carga en la MISMA sesión Frida del interceptor (create_script adicional,
 * NO un segundo attach). Contrato: toda exportación devuelve
 *   {ok, ...} o {ok:false, error:'E_*'} — nunca lanza hacia Python.
 * Datos binarios como hex. Lecturas y escrituras consultan VirtualQuery:
 * nunca se tocan páginas guard/sin acceso/no mapeadas.
 */
'use strict';

function toAddr(v) {
    return ptr(String(v));
}

/* Registro de allocaciones propias: solo se libera lo asignado aquí. */
var allocated = {};

/* ---- Consulta de regiones (VirtualQuery) -------------------------------
 * Toda lectura/escritura consulta antes el estado REAL de la página: así no
 * se toca nunca una página PAGE_GUARD (leerla consume el flag y altera al
 * proceso), ni memoria libre/reservada/sin acceso, y los tramos ilegibles se
 * saltan de golpe en vez de provocar miles de excepciones. */
var PAGE_NOACCESS = 0x01, PAGE_GUARD = 0x100;
var READABLE = { 0x02: 1, 0x04: 1, 0x08: 1, 0x20: 1, 0x40: 1, 0x80: 1 };
var WRITABLE = { 0x04: 1, 0x08: 1, 0x40: 1, 0x80: 1 };
var MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000;
var MAX_READ = 16 * 1024 * 1024;
var MAX_WRITE = 1024 * 1024;
var DEFAULT_DEADLINE_MS = 2000;
var PAGE = 4096;

var vq = null;
var mbi = null;
var vqError = null;
(function initVirtualQuery() {
    try {
        var f = Process.getModuleByName('kernel32.dll').getExportByName('VirtualQuery');
        vq = new NativeFunction(f, 'pointer', ['pointer', 'pointer', 'pointer']);
        mbi = Memory.alloc(64);
    } catch (e) {
        vqError = String(e);
    }
})();

/* Devuelve {base, end, state, protect} o null si la dirección no es consultable. */
function queryRegion(p) {
    if (vq === null) return null;
    var psz = Process.pointerSize;
    var n = vq(p, mbi, ptr(psz === 8 ? 48 : 28));
    if (n.isNull()) return null;
    var off = psz === 8 ? { size: 24, state: 32, prot: 36 }
                        : { size: 12, state: 16, prot: 20 };
    var base = mbi.readPointer();
    var size = mbi.add(off.size).readPointer();
    return {
        base: base,
        end: base.add(size),
        state: mbi.add(off.state).readU32(),
        protect: mbi.add(off.prot).readU32(),
    };
}

/* Motivo por el que NO se puede leer esa región, o null si es legible. */
function unreadableReason(q) {
    if (q === null) return 'E_NO_MAP';
    if (q.state === MEM_COMMIT) {
        if (q.protect & PAGE_GUARD) return 'E_PAGE_GUARD';
        if (q.protect & PAGE_NOACCESS || q.protect === 0) return 'E_NO_ACCESS';
        if (!READABLE[q.protect & 0xFF]) return 'E_NO_ACCESS';
        return null;
    }
    return q.state === MEM_RESERVE ? 'E_NOT_COMMITTED' : 'E_NO_MAP';
}

/* Motivo por el que NO se puede escribir, o null si es escribible. */
function unwritableReason(q) {
    if (q === null) return 'E_NO_MAP';
    if (q.state !== MEM_COMMIT) return q.state === MEM_RESERVE ? 'E_NOT_COMMITTED' : 'E_NO_MAP';
    if (q.protect & PAGE_GUARD) return 'E_PAGE_GUARD';
    if (!WRITABLE[q.protect & 0xFF]) return 'E_NON_WRITABLE';
    return null;
}

/* Bytes disponibles desde cur hasta el final de la región (acotado a rem). */
function spanWithin(q, cur, rem) {
    var left = q.end.sub(cur);
    if (left.compare(ptr(rem)) >= 0) return rem;
    return left.toInt32();
}

var HEX = [];
for (var h = 0; h < 256; h++) HEX.push(('0' + h.toString(16)).slice(-2));

function toHex(u8) {
    var parts = new Array(u8.length);
    for (var i = 0; i < u8.length; i++) parts[i] = HEX[u8[i]];
    return parts.join('');
}

/* Lectura tolerante por regiones. Devuelve
 *   {hex, got, valid, holes:[[offset,len,motivo]...], error}
 * `hex` siempre tiene `size` bytes (huecos a 0); `valid` es el prefijo leído
 * sin huecos; `error` es el motivo del primer hueco. Nunca toca páginas guard
 * ni memoria no legible, y respeta un plazo (E_TIMEOUT). */
function readTolerant(base, size, deadlineMs) {
    var p = toAddr(base);
    var out = new Uint8Array(size);
    var holes = [];
    var pos = 0;
    var limit = Date.now() + (deadlineMs === undefined || deadlineMs === null
        ? DEFAULT_DEADLINE_MS : deadlineMs);

    function addHole(off, len, reason) {
        var last = holes.length ? holes[holes.length - 1] : null;
        if (last && last[2] === reason && last[0] + last[1] === off) last[1] += len;
        else holes.push([off, len, reason]);
    }

    while (pos < size) {
        if (Date.now() >= limit) { addHole(pos, size - pos, 'E_TIMEOUT'); break; }
        var cur = p.add(pos);
        var q = queryRegion(cur);
        var rem = size - pos;
        if (q === null) { addHole(pos, rem, 'E_NO_MAP'); break; }
        var span = spanWithin(q, cur, rem);
        if (span <= 0) span = 1;
        var why = unreadableReason(q);
        if (why !== null) { addHole(pos, span, why); pos += span; continue; }
        try {
            var buf = cur.readByteArray(span);
            if (buf === null) throw new Error('null');
            out.set(new Uint8Array(buf), pos);
        } catch (e) {
            /* La región cambió entre la consulta y la lectura (carrera):
             * se reintenta por páginas, sin tocar páginas ya conocidas. */
            var o = 0;
            while (o < span) {
                var n = Math.min(PAGE - ((pos + o) % PAGE), span - o);
                try {
                    var b2 = cur.add(o).readByteArray(n);
                    out.set(new Uint8Array(b2), pos + o);
                } catch (e2) { addHole(pos + o, n, 'E_ACCESS_DENIED'); }
                o += n;
            }
        }
        pos += span;
    }
    var valid = holes.length ? holes[0][0] : size;
    return { hex: toHex(out), got: size, valid: valid, holes: holes,
             error: holes.length ? holes[0][2] : null };
}

rpc.exports = {
    /* Enumerar rangos commit según permisos pedidos. Accepta 'r', 'w', 'x'
     * o combinaciones (p. ej. 'rw'). Devuelve regiones con prot normalizada
     * 'rw' etc. — permisos separados, no 'rwx' genérico. */
    listRanges: function (protSpec) {
        try {
            // Process.enumerateRanges acepta un gesto de protecciones; pedimos
            // 'rw-' y 'r--' y filtramos en la GUI por permisos individuales.
            var ranges = Process.enumerateRanges('rw-')
                .concat(Process.enumerateRanges('r--'))
                .concat(Process.enumerateRanges('r-x'));
            var seen = {};
            var regions = [];
            ranges.forEach(function (r) {
                var key = r.base.toString();
                if (seen[key]) return;
                seen[key] = true;
                var p = '';
                var prot = r.protection;
                if (prot.indexOf('r') >= 0) p += 'r';
                if (prot.indexOf('w') >= 0) p += 'w';
                if (prot.indexOf('x') >= 0) p += 'x';
                regions.push({ addr: key, size: r.size, prot: p });
            });
            return { ok: true, regions: regions };
        } catch (e) {
            return { ok: false, error: 'E_ENUM: ' + String(e) };
        }
    },

    listModules: function () {
        try {
            return {
                ok: true,
                modules: Process.enumerateModules().map(function (m) {
                    return { name: m.name, path: m.path,
                             base: m.base.toString(), size: m.size };
                }),
            };
        } catch (e) {
            return { ok: false, error: 'E_ENUM: ' + String(e) };
        }
    },

    /* Lectura tolerante sin efectos secundarios: devuelve lo obtenido, el
     * prefijo válido y los huecos. Si no hay VirtualQuery no se puede
     * garantizar que no se consuman páginas guard: se rechaza (E_UNSAFE_READ). */
    readRange: function (addrHex, size, deadlineMs) {
        try {
            if (vq === null)
                return { ok: false, hex: '', got: 0, valid: 0, holes: [],
                         error: 'E_UNSAFE_READ', detail: vqError };
            if (!(size >= 0) || size > MAX_READ)
                return { ok: false, hex: '', got: 0, valid: 0, holes: [],
                         error: 'E_TOO_LARGE' };
            var r = readTolerant(addrHex, size, deadlineMs);
            return { ok: true, hex: r.hex, got: r.got, valid: r.valid,
                     holes: r.holes, error: r.error };
        } catch (e) {
            return { ok: false, hex: '', got: 0, valid: 0, holes: [],
                     error: 'E_READ: ' + String(e) };
        }
    },

    /* Estado real de la página en una dirección (diagnóstico/tests). */
    queryRegion: function (addrHex) {
        try {
            var q = queryRegion(toAddr(addrHex));
            if (q === null) return { ok: false, error: 'E_NO_MAP' };
            return { ok: true, base: q.base.toString(), end: q.end.toString(),
                     state: q.state, protect: q.protect };
        } catch (e) {
            return { ok: false, error: 'E_QUERY: ' + String(e) };
        }
    },

    /* Escritura. hexBytes = cadena hex (longitud par). Valida TODO el rango
     * contra el estado real de cada página ANTES de escribir un solo byte:
     * o se escribe completo o no se toca nada. */
    writeRange: function (addrHex, hexBytes) {
        try {
            if (vq === null)
                return { ok: false, error: 'E_UNSAFE_WRITE', detail: vqError };
            var p = toAddr(addrHex);
            var len = hexBytes.length / 2;
            if (!(len > 0) || len !== Math.floor(len) || len > MAX_WRITE)
                return { ok: false, error: 'E_BAD_ARGS' };
            var pos = 0;
            while (pos < len) {
                var cur = p.add(pos);
                var q = queryRegion(cur);
                var why = unwritableReason(q);
                if (why !== null) return { ok: false, error: why,
                                           detail: 'offset ' + pos + ' de ' + len };
                pos += Math.max(spanWithin(q, cur, len - pos), 1);
            }
            var u8 = new Uint8Array(len);
            for (var i = 0; i < len; i++) {
                u8[i] = parseInt(hexBytes.substr(i * 2, 2), 16);
            }
            // sin Memory.protect: solo se escribe en regiones ya escribibles
            p.writeByteArray(u8);
            return { ok: true, wrote: len };
        } catch (e) {
            var m = String(e);
            if (m.indexOf('ccess') >= 0)
                return { ok: false, error: 'E_ACCESS_DENIED' };
            return { ok: false, error: 'E_WRITE_FAILED: ' + m };
        }
    },

    alloc: function (size) {
        try {
            var base = Memory.alloc(size);
            allocated[base.toString()] = base;  // referencia: evita GC/free
            return { ok: true, addr: base.toString() };
        } catch (e) {
            return { ok: false, error: 'E_ALLOC: ' + String(e) };
        }
    },

    free: function (addrHex) {
        try {
            var key = toAddr(addrHex).toString();
            if (!allocated[key]) {
                return { ok: false, error: 'E_NOT_OWNED',
                         detail: 'solo se libera memoria asignada por este agente' };
            }
            delete allocated[key];
            return { ok: true };
        } catch (e) {
            return { ok: false, error: 'E_FREE: ' + String(e) };
        }
    },

    processInfo: function () {
        return {
            ok: true,
            pid: Process.id,
            arch: Process.arch,      // 'x64' | 'ia32'
            pointerSize: Process.pointerSize,
            safeRead: vq !== null,   // VirtualQuery disponible: lecturas sin efectos laterales
        };
    },

    ping: function () { return { ok: true, ts: Date.now() }; },
};
