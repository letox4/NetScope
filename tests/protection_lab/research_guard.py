# -*- coding: utf-8 -*-
"""Investigación PAGE_GUARD / EAF con lab_guard.exe (proceso propio).

Ejecutar:  py -3.11 tests\\protection_lab\\research_guard.py [--arch x64|x86] [--json out.json]

Para cada operación sobre una página PAGE_GUARD mide:
  - resultado / excepción,
  - protección real ANTES y DESPUÉS (VirtualQuery dentro del objetivo),
  - accesos que el VEH del propio objetivo vio (guard_hits),
  - si el proceso siguió vivo.
Las operaciones de Frida se ejecutan dentro del objetivo (misma ruta que los agentes
de NetScope); las "nativas" se ejecutan desde fuera con la API de Windows.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import threading
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.abspath(os.path.join(HERE, '..', '..'))
BIN = os.path.join(HERE, 'bin')
PAGE_GUARD = 0x100


class Lab:
    def __init__(self, arch, args=()):
        exe = os.path.join(BIN, f'lab_guard_{arch}.exe')
        self.p = subprocess.Popen([exe, '--max-seconds=120', *args], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)
        self.events = []
        self._cv = threading.Condition()
        self.ready = json.loads(self.p.stdout.readline())
        self.regions = self.ready['regions']
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for ln in self.p.stdout:
            try:
                ev = json.loads(ln)
            except ValueError:
                continue
            with self._cv:
                self.events.append(ev)
                self._cv.notify_all()

    def cmd(self, c, want, timeout=5.0):
        with self._cv:
            n = len(self.events)
        self.p.stdin.write(c + '\n')
        self.p.stdin.flush()
        end = time.time() + timeout
        with self._cv:
            while time.time() < end:
                for ev in self.events[n:]:
                    if ev['event'] == want:
                        return ev
                self._cv.wait(0.1)
        raise TimeoutError(c)

    def prot(self, region, page=0):
        return self.cmd('query', 'query')['prot'][f'{region}.{page}'][0]

    def hits(self):
        st = self.cmd('status', 'status')
        return sum(st.get('guard_hits', {}).values()), st

    def close(self):
        try:
            self.p.kill()
        except Exception:
            pass


# ---------------- operaciones nativas (fuera del objetivo) ----------------
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.POINTER(ctypes.c_size_t)]


class MBI64(ctypes.Structure):
    _fields_ = [('Base', ctypes.c_void_p), ('AllocBase', ctypes.c_void_p), ('AllocProt', wt.DWORD),
                ('Part', wt.WORD), ('Region', ctypes.c_size_t), ('State', wt.DWORD),
                ('Protect', wt.DWORD), ('Type', wt.DWORD)]


k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI64), ctypes.c_size_t]


def native_ops(pid, addr):
    h = k32.OpenProcess(0x1F0FFF if False else (0x0010 | 0x0020 | 0x0008 | 0x0400), False, pid)
    out = {}

    def rpm():
        buf = ctypes.create_string_buffer(16)
        n = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(h, addr, buf, 16, ctypes.byref(n))
        return f'ok={bool(ok)} err={ctypes.get_last_error() if not ok else 0} got={n.value}'

    def wpm():
        n = ctypes.c_size_t(0)
        ok = k32.WriteProcessMemory(h, addr, b'X', 1, ctypes.byref(n))
        return f'ok={bool(ok)} err={ctypes.get_last_error() if not ok else 0} wrote={n.value}'

    def vqx():
        m = MBI64()
        n = k32.VirtualQueryEx(h, addr, ctypes.byref(m), ctypes.sizeof(m))
        return f'bytes={n} protect={hex(m.Protect)} state={hex(m.State)}'

    out['ReadProcessMemory (desde fuera)'] = rpm
    out['WriteProcessMemory (desde fuera)'] = wpm
    out['VirtualQueryEx (desde fuera)'] = vqx
    return out, h


FRIDA_OPS_JS = r"""
var A = ptr(PAGE);
function guarded(fn) { try { return String(fn()); } catch (e) { return 'EXC: ' + String(e).slice(0, 90); } }
rpc.exports = {
  readByteArray: function () { return guarded(function () { var b = A.readByteArray(16); return b === null ? 'null' : 'ok len=' + b.byteLength; }); },
  readU8: function () { return guarded(function () { return 'ok ' + A.readU8(); }); },
  writeU8: function () { return guarded(function () { A.writeU8(0x41); return 'ok'; }); },
  writeByteArray: function () { return guarded(function () { A.writeByteArray([0x41, 0x42]); return 'ok'; }); },
  memoryScan: function () { return guarded(function () { var n = 0; Memory.scanSync(A, 4096, '41 42').forEach(function () { n++; }); return 'ok matches=' + n; }); },
  enumerateRanges: function () {
      return guarded(function () {
          var hit = null; Process.enumerateRanges('---').concat(Process.enumerateRanges('r--'), Process.enumerateRanges('rw-')).forEach(function (r) {
              if (A.compare(r.base) >= 0 && A.compare(r.base.add(r.size)) < 0) hit = r.protection + ' size=' + r.size; });
          return hit === null ? 'no listada' : 'listada ' + hit; });
  },
  findRangeByAddress: function () { return guarded(function () { var r = Process.findRangeByAddress(A); return r === null ? 'null' : r.protection; }); },
  virtualQuery: function () {
      return guarded(function () {
          var vq = new NativeFunction(Process.getModuleByName('kernel32.dll').getExportByName('VirtualQuery'), 'pointer', ['pointer', 'pointer', 'pointer']);
          var mbi = Memory.alloc(64); vq(A, mbi, ptr(Process.pointerSize === 8 ? 48 : 28));
          return 'protect=0x' + mbi.add(Process.pointerSize === 8 ? 36 : 20).readU32().toString(16); });
  },
  moduleExportLookup: function () { return guarded(function () { return 'ok ' + Process.getModuleByName('kernel32.dll').getExportByName('CreateFileW'); }); },
};
"""


def run(arch):
    rows = []
    lab = Lab(arch)
    pid = lab.p.pid
    guard = lab.regions['guard']
    session = frida.attach(pid)
    js = FRIDA_OPS_JS.replace('PAGE', json.dumps(hex(guard)))
    sc = session.create_script(js)
    sc.load()
    ex = sc.exports_sync
    native, h = native_ops(pid, guard)

    def trial(label, fn):
        lab.cmd('rearm', 'ack')
        before = lab.prot('guard')
        h0, _ = lab.hits()
        t = time.time()
        try:
            res = fn()
        except Exception as e:
            res = f'EXC {type(e).__name__}: {str(e)[:80]}'
        dt = (time.time() - t) * 1000
        time.sleep(0.15)
        try:
            after = lab.prot('guard')
            h1, _ = lab.hits()
            alive = lab.p.poll() is None
        except Exception:
            after, h1, alive = None, None, False
        rows.append(dict(op=label, result=res, guard_before=hex(before), guard_after=hex(after) if after is not None else None,
                         consumed=(after is not None and not (after & PAGE_GUARD)),
                         target_veh_hits=(None if h1 is None else h1 - h0), alive=alive, ms=round(dt, 2)))

    trial('Frida Memory: ptr.readByteArray', lambda: ex.read_byte_array())
    trial('Frida Memory: ptr.readU8', lambda: ex.read_u8())
    trial('Frida Memory: ptr.writeU8', lambda: ex.write_u8())
    trial('Frida Memory: ptr.writeByteArray', lambda: ex.write_byte_array())
    trial('Frida Memory.scanSync', lambda: ex.memory_scan())
    trial('Frida Process.enumerateRanges', lambda: ex.enumerate_ranges())
    trial('Frida Process.findRangeByAddress', lambda: ex.find_range_by_address())
    trial('Frida NativeFunction(VirtualQuery)', lambda: ex.virtual_query())
    for name, fn in native.items():
        trial(name, fn)

    # agente de memoria ANTERIOR (línea base) vs ACTUAL, misma ruta de lectura
    for label, path in (('agente memory.js ANTERIOR (línea base)', os.environ.get('BASELINE_AGENT')),
                        ('agente memory.js ACTUAL: readRange', os.path.join(BASE, 'agent', 'memory.js'))):
        if not path or not os.path.exists(path):
            continue
        s2 = session.create_script(open(path, encoding='utf-8').read())
        s2.load()
        trial(label, lambda: (lambda r: f"ok={r.get('ok')} err={r.get('error')} valid={r.get('valid')}")(
            s2.exports_sync.read_range(hex(guard), 16)))
        s2.unload()

    # EAF-like: ¿la inicialización y los agentes de NetScope tocan la tabla de exportación?
    sc.unload()
    session.detach()
    k32.CloseHandle(h)
    lab.close()
    return rows


def timed_attach(pid, timeout=8.0):
    """frida.attach con límite de tiempo (el attach de Frida puede no volver nunca)."""
    res = {}

    def go():
        t = time.time()
        try:
            res['s'] = frida.attach(pid)
            res['t'] = round(time.time() - t, 2)
        except Exception as e:
            res['err'] = f'{type(e).__name__}: {e}'

    th = threading.Thread(target=go, daemon=True)
    th.start()
    th.join(timeout)
    return res


def attach_check_subprocess(arch, lab_args, timeout=10.0):
    """Un attach por proceso Python limpio: un attach colgado contamina a los siguientes."""
    code = (
        "import os,sys,time,json,subprocess,threading,frida\n"
        f"exe=r'{os.path.join(BIN, f'lab_guard_{arch}.exe')}'\n"
        f"p=subprocess.Popen([exe,'--on-detect=report','--max-seconds=30',*{lab_args!r}],stdin=subprocess.PIPE,"
        "stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)\n"
        "p.stdout.readline();time.sleep(0.4);res={}\n"
        "def go():\n"
        " t=time.time()\n"
        " try: frida.attach(p.pid);res['t']=round(time.time()-t,2)\n"
        " except Exception as e: res['err']=repr(e)\n"
        f"th=threading.Thread(target=go,daemon=True);th.start();th.join({timeout})\n"
        "print(json.dumps(res or {'hang':True}),flush=True);p.kill();os._exit(0)\n")
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=timeout + 20)
    try:
        return json.loads(out.stdout.strip().splitlines()[-1])
    except Exception:
        return {'error': out.stdout[-200:] + out.stderr[-200:]}


def eaf_probe(arch):
    """lab_guard --eaf-emulate: ¿puede Frida adjuntarse? ¿qué toca las tablas de exportación?"""
    rows = []

    def fmt(r):
        if 't' in r:
            return f"adjuntado en {r['t']}s"
        return 'COLGADO > 10s (sin error)' if r.get('hang') else str(r)

    rows.append(dict(step='attach SIN guardas (control)', result=fmt(attach_check_subprocess(arch, []))))
    rows.append(dict(step='attach con guardas EAT ARMADAS y rearmadas (como EAF)',
                     result=fmt(attach_check_subprocess(arch, ['--eaf-emulate']))))
    rows.append(dict(step='attach con guardas EAT armadas pero consumidas al instante (--oneshot)',
                     result=fmt(attach_check_subprocess(arch, ['--eaf-emulate', '--oneshot', '--interval-ms=20']))))

    # guardas EAT armadas bajo demanda: attach primero, luego medir qué toca la EAT en cada paso
    lab = Lab(arch, ['--eaf-emulate', '--eaf-lazy', '--oneshot', '--on-detect=report', '--interval-ms=20'])
    res = timed_attach(lab.p.pid, 8.0)
    sess = {'s': res.get('s')}

    def delta(label, fn):
        lab.cmd('rearm', 'ack')
        n0 = len(lab.events)
        h0, _ = lab.hits()
        try:
            fn()
            err = ''
        except Exception as e:
            err = f' [{type(e).__name__}: {str(e)[:60]}]'
        time.sleep(0.5)
        h1, _ = lab.hits()
        new = [e for e in lab.events[n0:] if e['event'] == 'guard-hit' and e.get('page', '').startswith('eaf:')]
        outsiders = [e for e in new if not e.get('system_module') and not e.get('self')]
        rows.append(dict(step=label + err, eat_hits=h1 - h0, hits_from_non_system=len(outsiders),
                         accessor=sorted({os.path.basename(e['module']) for e in outsiders})[:4],
                         alive=lab.p.poll() is None))

    if sess['s'] is not None:
        agents = os.path.join(BASE, 'agent')
        keep = {}

        def load_mem():
            s = sess['s'].create_script(open(os.path.join(agents, 'memory.js'), encoding='utf-8').read())
            s.load()
            keep['m'] = s

        def mem_ops():
            r = keep['m'].exports_sync.read_range(hex(lab.regions['pattern']), 4096)
            assert r['ok']
            keep['m'].exports_sync.write_range(hex(lab.regions['tail'] + 512), '41')

        def load_net():
            s = sess['s'].create_script(open(os.path.join(agents, 'agent.js'), encoding='utf-8').read())
            s.on('message', lambda m, d: None)
            s.load()
            keep['n'] = s

        def lookup():
            s = sess['s'].create_script(
                "rpc.exports={f:function(){return String(Process.getModuleByName('kernel32.dll')"
                ".getExportByName('CreateFileW'));}}")
            s.load()
            s.exports_sync.f()
            s.unload()

        delta('cargar memory.js (resuelve VirtualQuery por export)', load_mem)
        delta('lecturas/escrituras del agente de memoria', mem_ops)
        delta('cargar agent.js (hooks de red: ~40 búsquedas de export)', load_net)
        delta('Module.getExportByName("CreateFileW") suelto', lookup)
        try:
            sess['s'].detach()
        except Exception:
            pass
    lab.close()
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--arch', default='x64')
    ap.add_argument('--json')
    a = ap.parse_args()
    ops = run(a.arch)
    print(f'\n== Operaciones sobre una página PAGE_GUARD ({a.arch}) ==')
    for r in ops:
        flag = 'CONSUME' if r['consumed'] else 'intacta'
        print(f"{r['op']:44s} guarda:{flag:8s} hits_VEH={r['target_veh_hits']} vivo={r['alive']} -> {r['result']}")
    eaf = eaf_probe(a.arch)
    print(f'\n== Accesos a tablas de exportación (EAF emulado, {a.arch}) ==')
    for r in eaf:
        if 'eat_hits' in r:
            print(f"{r['step']:62s} hits_EAT={r['eat_hits']:3d} desde_no_sistema={r['hits_from_non_system']} "
                  f"{r['accessor']} vivo={r['alive']}")
        else:
            print(f"{r['step']:70s} -> {r['result']}")
    if a.json:
        json.dump({'guard_ops': ops, 'eaf_probe': eaf}, open(a.json, 'w'), indent=1)


if __name__ == '__main__':
    main()
