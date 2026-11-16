/*
 * NetScope — sonda de diagnóstico anti-debug (RPC puro, sin evasión).
 *
 * scanImports(): PASIVO. Recorre los módulos que NO son de Windows y lista los
 *   imports de APIs típicas de anti-debug. No modifica nada.
 * observe()/collect()/stop(): ACTIVO y opt-in. Registra (sin alterar valores de
 *   retorno ni argumentos) las llamadas del objetivo a IsDebuggerPresent,
 *   CheckRemoteDebuggerPresent y NtQueryInformationProcess(DebugPort/
 *   DebugObjectHandle/DebugFlags). Usa Interceptor, que parchea el inicio de
 *   esas funciones: un objetivo con comprobación de integridad lo puede ver
 *   (efecto del observador). Se informa como limitación.
 */
'use strict';

var APIS = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
            'NtSetInformationThread', 'OutputDebugStringA', 'OutputDebugStringW',
            'DebugActiveProcessStop', 'NtQuerySystemInformation', 'GetThreadContext',
            'NtQueryObject'];
var DEBUG_CLASSES = { 7: 'ProcessDebugPort', 30: 'ProcessDebugObjectHandle', 31: 'ProcessDebugFlags' };

var calls = {};
var listeners = [];

function isSystemPath(p) { return /^[a-z]:\\windows\\/i.test(p); }

function callerOf(ctx) {
    try {
        var m = Process.findModuleByAddress(ctx.returnAddress);
        return m ? m.name : '(memoria anónima)';
    } catch (e) { return '?'; }
}

function record(key, result, caller) {
    var c = calls[key] || (calls[key] = { count: 0, results: {}, callers: {} });
    c.count++;
    c.results[result] = (c.results[result] || 0) + 1;
    c.callers[caller] = (c.callers[caller] || 0) + 1;
}

function exportOf(modName, fn) {
    try { return Process.getModuleByName(modName).getExportByName(fn); } catch (e) { return null; }
}

rpc.exports = {
    scanImports: function () {
        var out = [];
        try {
            Process.enumerateModules().forEach(function (m) {
                if (isSystemPath(m.path)) return;
                try {
                    m.enumerateImports().forEach(function (i) {
                        if (APIS.indexOf(i.name) >= 0)
                            out.push({ module: m.name, api: i.name, from: i.module || '' });
                    });
                } catch (e) {}
            });
            return { ok: true, imports: out };
        } catch (e) {
            return { ok: false, error: String(e) };
        }
    },

    observe: function () {
        var hooked = [];
        function hook(mod, fn, onEnter, onLeave) {
            var a = exportOf(mod, fn);
            if (!a) return;
            listeners.push(Interceptor.attach(a, { onEnter: onEnter, onLeave: onLeave }));
            hooked.push(mod + '!' + fn);
        }
        hook('kernelbase.dll', 'IsDebuggerPresent', function (args) {
            this.who = callerOf(this);
        }, function (retval) {
            record('IsDebuggerPresent', retval.toInt32() ? 'depurador' : 'sin depurador', this.who);
        });
        hook('kernelbase.dll', 'CheckRemoteDebuggerPresent', function (args) {
            this.out = args[1]; this.who = callerOf(this);
        }, function (retval) {
            var v = 'desconocido';
            try { v = this.out.readU32() ? 'depurador' : 'sin depurador'; } catch (e) {}
            record('CheckRemoteDebuggerPresent', v, this.who);
        });
        hook('ntdll.dll', 'NtQueryInformationProcess', function (args) {
            this.cls = args[1].toInt32();
            this.out = args[2]; this.who = callerOf(this);
        }, function (retval) {
            var name = DEBUG_CLASSES[this.cls];
            if (!name) return;
            var res = 'status=0x' + (retval.toInt32() >>> 0).toString(16);
            if (retval.toInt32() === 0) {
                try {
                    var v = this.cls === 31 ? this.out.readU32() : this.out.readPointer().toString();
                    res = 'valor=' + v;
                } catch (e) {}
            }
            record('NtQueryInformationProcess:' + name, res, this.who);
        });
        return { ok: true, hooked: hooked };
    },

    collect: function () {
        return { ok: true, calls: calls };
    },

    stop: function () {
        listeners.forEach(function (l) { l.detach(); });
        listeners = [];
        return { ok: true };
    },
};
