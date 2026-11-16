# -*- coding: utf-8 -*-
"""GUI extremo a extremo (offscreen): pestaña Memoria en modo solo lectura (v1)
sobre un proceso separado, comprobando que la captura de red sigue funcionando
sobre la misma sesión Frida.

Ejecutar:  py -3.11 tests\\test_memory_ui.py   (requiere PySide6 y Frida)
"""
import json
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from PySide6 import QtCore, QtWidgets
from core.memory.models import CapabilityError
from ui.main_window import NetScopeGUI


def _pump(app, cond, timeout=20.0):
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.05)
    return False


def main():
    audit_dir = tempfile.mkdtemp(prefix='netscope_ui_audit_')
    os.environ['NETSCOPE_AUDIT_DIR'] = audit_dir
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])

    child = subprocess.Popen(
        [sys.executable, os.path.join(BASE, 'tests', 'dummy_target.py')],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    w = NetScopeGUI()
    mp = w.memory_panel
    try:
        time.sleep(1.0)
        w.interceptor.attach(pid=child.pid)
        assert w.interceptor._session is not None
        sessions_before = id(w.interceptor._session)

        # Panel de memoria en solo lectura para v1
        assert not hasattr(mp, 'btn_write'), 'btn_write no debe existir en v1 solo lectura'
        assert not hasattr(mp, 'btn_undo'), 'btn_undo no debe existir en v1 solo lectura'
        assert not hasattr(mp, 'write_edit'), 'write_edit no debe existir en v1 solo lectura'

        # motor de memoria sobre la MISMA sesión (sin segundo attach)
        mp.btn_init.click()
        assert _pump(app, lambda: mp.reg_table.rowCount() > 0), 'sin regiones en la tabla'
        assert id(w.interceptor._session) == sessions_before
        print(f'[OK] GUI: {mp.reg_table.rowCount()} regiones listadas')
        assert 'FridaMemoryBackend' in mp.lbl_caps.text(), mp.lbl_caps.text()
        assert 'solo-lectura' in mp.lbl_caps.text(), mp.lbl_caps.text()

        # lectura de una región desde la GUI
        mp.reg_table.selectRow(0)
        mp.kind_combo.setCurrentText('hex')
        mp.btn_read.click()
        assert _pump(app, lambda: mp.read_out.toPlainText().startswith('@ 0x')), \
            'lectura sin salida'
        print('[OK] GUI: lectura hex mostrada')

        # la captura de red sigue viva con el motor de memoria cargado
        assert _pump(app, lambda: len(w.interceptor.streams) > 0, 20.0), \
            'la captura de red dejó de funcionar con memoria activa'
        print('[OK] GUI: captura TCP/UDP coexiste con memoria')

        assert child.poll() is None, 'el target murió'
        print('[OK] target vivo')

        # el motor por defecto de la sesión es solo lectura
        gui_eng = w.interceptor.memory_engine()
        assert gui_eng.caps.read is True
        assert gui_eng.caps.write_rw is False
        assert gui_eng.caps.alloc is False
        assert gui_eng.caps.free is False
        try:
            gui_eng.alloc(32)
            raise AssertionError('alloc debió estar bloqueado en modo solo lectura')
        except CapabilityError:
            pass
        row0 = mp.reg_table.item(0, 0)
        addr0 = int(row0.data(QtCore.Qt.UserRole))
        try:
            gui_eng.write(addr0, b'NOPE')
            raise AssertionError('write debió estar bloqueado en modo solo lectura')
        except CapabilityError:
            pass

        # ---- pérdida de sesión: el target muere con el watcher activo ----
        mp.watch_addr.setText(hex(addr0))
        mp.watch_size.setText('8')
        mp.watch_interval.setText('0.2')
        mp.btn_watch.click()
        assert _pump(app, lambda: 'Detener' in mp.btn_watch.text()), 'el watch no arrancó'
        child.kill()
        child.wait(timeout=5)
        assert _pump(app, lambda: 'Sesión perdida' in w.statusBar().currentMessage(), 10.0), \
            f'barra de estado: {w.statusBar().currentMessage()!r}'
        assert _pump(app, lambda: 'Observar' in mp.btn_watch.text()), 'watch no se reseteó'
        assert not mp.btn_watch.isEnabled() and not mp.btn_read.isEnabled()
        assert not mp.btn_refresh.isEnabled() and mp._watcher is None
        assert 'no disponible' in mp.lbl_caps.text(), mp.lbl_caps.text()
        assert w.btn_attach.isEnabled()
        print('[OK] GUI: pérdida de sesión -> controles de memoria desactivados, watch detenido')
    finally:
        w.interceptor.stop()
        w.close()
        app.processEvents()
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=5)

    events = [json.loads(l) for l in open(os.path.join(audit_dir, 'memory_audit.jsonl'),
                                          encoding='utf-8') if l.strip()]
    kinds = [e['event'] for e in events]
    assert 'engine_start' in kinds and 'session_lost' in kinds, kinds
    print('ALL MEMORY UI TESTS PASSED')


def test_memory_ui_readonly():
    main()


if __name__ == '__main__':
    main()
