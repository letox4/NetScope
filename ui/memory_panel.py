# -*- coding: utf-8 -*-
"""Pestaña 'Memoria' de NetScope (solo lectura en v1).

Usa el MemoryEngine del interceptor (misma sesión Frida; sin attach doble).
Organizada en sub-pestañas amplias para evitar saturar la pantalla.
"""
import threading

from PySide6 import QtWidgets, QtCore

from core.memory.models import MemoryError
from ui.icons import get_icon


class MemoryPanel(QtWidgets.QWidget):
    """Constructor recibe la MainWindow (para interceptor, sLog y _make_text)."""

    def __init__(self, main):
        super().__init__()
        self.main = main
        self._snapshot_a = None
        self._snapshot_b = None
        self._watcher = None
        self._watch_lock = threading.Lock()
        self._build_ui()

    # ---------------- UI ----------------
    def _build_ui(self):
        lay = QtWidgets.QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)

        # --- cabecera ---
        top_card = QtWidgets.QFrame()
        top_card.setObjectName('metricCard')
        top = QtWidgets.QHBoxLayout(top_card)
        top.setContentsMargins(12, 10, 12, 10)
        self.btn_init = QtWidgets.QPushButton(
            get_icon('zap', color='#ffffff', active_color='#ffffff'),
            'Activar inspector de memoria')
        self.btn_init.setObjectName('primaryButton')
        self.btn_init.setToolTip(
            'Conecta el lector seguro de memoria usando la sesión actual (solo lectura).')
        self.btn_init.clicked.connect(self._init_engine)
        top.addWidget(self.btn_init)
        self.lbl_caps = QtWidgets.QLabel(
            'Primero conecta con una aplicación y pulsa «Activar inspector de memoria».')
        self.lbl_caps.setWordWrap(True)
        top.addWidget(self.lbl_caps, 1)
        lay.addWidget(top_card)

        # --- sub-pestañas amplias ---
        self.sub_tabs = QtWidgets.QTabWidget()
        self.sub_tabs.setIconSize(QtCore.QSize(15, 15))
        lay.addWidget(self.sub_tabs, 1)

        # 1. Explorar y leer regiones
        tab_read = QtWidgets.QWidget()
        rlay = QtWidgets.QVBoxLayout(tab_read)
        rlay.setContentsMargins(8, 8, 8, 8)
        rlay.setSpacing(8)

        row = QtWidgets.QHBoxLayout()
        self.prot_combo = QtWidgets.QComboBox()
        self.prot_combo.addItems(['r (legible)', 'rw (datos)',
                                  'x (código)', 'rx', 'wx'])
        self.prot_combo.currentIndexChanged.connect(self._reload_regions_safe)
        self.btn_refresh = QtWidgets.QPushButton(get_icon('refresh'), 'Actualizar lista')
        self.btn_refresh.setEnabled(False)
        self.btn_refresh.clicked.connect(self._reload_regions_safe)
        row.addWidget(QtWidgets.QLabel('Tipo de región:'))
        row.addWidget(self.prot_combo)
        row.addWidget(self.btn_refresh)
        row.addStretch(1)
        rlay.addLayout(row)

        self.reg_table = QtWidgets.QTableWidget(0, 4)
        self.reg_table.setHorizontalHeaderLabels(
            ['Dirección', 'Tamaño (bytes)', 'Permisos', 'Módulo / Origen'])
        self.reg_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.reg_table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.reg_table.horizontalHeader().setStretchLastSection(True)
        self.reg_table.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.reg_table.itemSelectionChanged.connect(self._region_selected)
        rlay.addWidget(self.reg_table, 3)

        io_group = QtWidgets.QGroupBox('Lectura segura de la región seleccionada (solo lectura v1)')
        io = QtWidgets.QGridLayout(io_group)
        io.addWidget(QtWidgets.QLabel('Formato:'), 0, 0)
        self.kind_combo = QtWidgets.QComboBox()
        self.kind_combo.addItems(['hex', 'utf8', 'cstr', 'u32', 'u64', 'u16', 'u8', 'ptr'])
        io.addWidget(self.kind_combo, 0, 1)
        io.addWidget(QtWidgets.QLabel('Longitud:'), 0, 2)
        self.len_edit = QtWidgets.QLineEdit('64')
        self.len_edit.setMaximumWidth(90)
        io.addWidget(self.len_edit, 0, 3)
        self.btn_read = QtWidgets.QPushButton(get_icon('eye'), 'Leer bytes')
        self.btn_read.setEnabled(False)
        self.btn_read.clicked.connect(self._do_read)
        io.addWidget(self.btn_read, 0, 4)
        io.setColumnStretch(5, 1)
        self.read_out = self.main._make_text()
        self.read_out.setPlaceholderText(
            'Selecciona una fila de la tabla superior y pulsa «Leer bytes».')
        io.addWidget(self.read_out, 1, 0, 1, 6)
        rlay.addWidget(io_group, 2)
        self.sub_tabs.addTab(tab_read, get_icon('book-open'), 'Explorar y Leer')

        # 2. Snapshots / diff
        tab_snap = QtWidgets.QWidget()
        slay = QtWidgets.QVBoxLayout(tab_snap)
        slay.setContentsMargins(8, 8, 8, 8)
        slay.setSpacing(8)
        slay.addWidget(QtWidgets.QLabel(
            'Toma una captura «A» antes de realizar una acción y una captura «B» '
            'después para ver exactamente qué regiones cambiaron.'))
        snap_bar = QtWidgets.QHBoxLayout()
        self.btn_snap_a = QtWidgets.QPushButton(get_icon('camera'), 'Captura A (antes)')
        self.btn_snap_b = QtWidgets.QPushButton(get_icon('camera'), 'Captura B (después)')
        self.btn_diff = QtWidgets.QPushButton(get_icon('git-compare'), 'Comparar A / B')
        for b in (self.btn_snap_a, self.btn_snap_b, self.btn_diff):
            b.setEnabled(False)
        self.btn_snap_a.clicked.connect(self._snap_a)
        self.btn_snap_b.clicked.connect(self._snap_b)
        self.btn_diff.clicked.connect(self._do_diff)
        snap_bar.addWidget(self.btn_snap_a)
        snap_bar.addWidget(self.btn_snap_b)
        snap_bar.addWidget(self.btn_diff)
        self.snap_lbl = QtWidgets.QLabel('Sin capturas todavía.')
        snap_bar.addWidget(self.snap_lbl, 1)
        slay.addLayout(snap_bar)

        self.diff_table = QtWidgets.QTableWidget(0, 4)
        self.diff_table.setHorizontalHeaderLabels(
            ['Cambio', 'Módulo + Offset', 'Tamaño', 'Primer byte distinto'])
        self.diff_table.horizontalHeader().setStretchLastSection(True)
        self.diff_table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        slay.addWidget(self.diff_table, 1)
        self.sub_tabs.addTab(tab_snap, get_icon('git-compare'), 'Comparar Capturas')

        # 3. Watch
        tab_watch = QtWidgets.QWidget()
        wlay = QtWidgets.QVBoxLayout(tab_watch)
        wlay.setContentsMargins(8, 8, 8, 8)
        wlay.setSpacing(8)
        wlay.addWidget(QtWidgets.QLabel(
            'Vigila una dirección hexadecimal de forma periódica para registrar cambios en tiempo real.'))
        watch_bar = QtWidgets.QHBoxLayout()
        watch_bar.addWidget(QtWidgets.QLabel('Dirección hex:'))
        self.watch_addr = QtWidgets.QLineEdit()
        self.watch_addr.setPlaceholderText('0x7ff...')
        self.watch_addr.setMaximumWidth(160)
        watch_bar.addWidget(self.watch_addr)
        watch_bar.addWidget(QtWidgets.QLabel('Bytes:'))
        self.watch_size = QtWidgets.QLineEdit('64')
        self.watch_size.setMaximumWidth(70)
        watch_bar.addWidget(self.watch_size)
        watch_bar.addWidget(QtWidgets.QLabel('Cada (s):'))
        self.watch_interval = QtWidgets.QLineEdit('1.0')
        self.watch_interval.setMaximumWidth(60)
        watch_bar.addWidget(self.watch_interval)
        self.btn_watch = QtWidgets.QPushButton(get_icon('play'), 'Observar')
        self.btn_watch.setEnabled(False)
        self.btn_watch.clicked.connect(self._toggle_watch)
        watch_bar.addWidget(self.btn_watch)
        watch_bar.addStretch(1)
        wlay.addLayout(watch_bar)

        self.watch_out = self.main._make_text()
        self.watch_out.setPlaceholderText('Los cambios detectados aparecerán aquí.')
        wlay.addWidget(self.watch_out, 1)
        self.sub_tabs.addTab(tab_watch, get_icon('eye'), 'Monitor en Vivo')

    # ---------------- helpers ----------------
    def _log(self, msg):
        self.main.sLog.emit(str(msg))

    def _engine(self):
        en = self.main.interceptor.memory_engine()
        self._update_caps(en)
        return en

    def _update_caps(self, en):
        c = en.caps
        arch = getattr(en.backend, 'arch', '?') if hasattr(en, 'backend') else '?'
        scals = ', '.join(sorted(c.read_scalars)) if c.read_scalars else '—'
        mode = 'solo-lectura (v1)' if not (c.write_rw or c.alloc) else 'lectura/escritura'
        self.lbl_caps.setText(
            f'Activo ({type(en.backend).__name__}) · {arch} · modo {mode} · '
            f'lectura={c.read} · monitor={c.watch}\n'
            f'Tipos soportados: {scals}')

    # ---------------- acciones ----------------
    def on_session_ended(self, reason: str):
        """Hilo GUI. La sesión Frida se perdió o se detuvo."""
        for b in (self.btn_refresh, self.btn_snap_a, self.btn_snap_b,
                  self.btn_diff, self.btn_watch, self.btn_read):
            b.setEnabled(False)
        with self._watch_lock:
            w, self._watcher = self._watcher, None
        if w is not None:
            w.stop()
        self.btn_watch.setIcon(get_icon('play'))
        self.btn_watch.setText('Observar')
        self._snapshot_a = None
        self._snapshot_b = None
        self.snap_lbl.setText('Sin capturas.')
        self.lbl_caps.setText(
            f'Inspector de memoria no disponible: {reason}. '
            'Conecta de nuevo y pulsa «Activar inspector de memoria».')

    def _init_engine(self):
        try:
            en = self._engine()
        except Exception as e:
            self._log(f'[!] Memoria: {e}')
            return
        self.btn_refresh.setEnabled(True)
        self.btn_snap_a.setEnabled(True)
        self.btn_snap_b.setEnabled(True)
        self.btn_diff.setEnabled(True)
        self.btn_watch.setEnabled(True)
        self._log('[i] Motor de memoria activo (solo lectura v1).')
        self._reload_regions()

    def _prot_filter(self):
        t = self.prot_combo.currentText()
        return t.split(' ')[0]

    def _reload_regions_safe(self):
        if self.btn_refresh.isEnabled():
            self._reload_regions()

    def _reload_regions(self):
        def work():
            en = self._engine()
            regs = en.regions(self._prot_filter())
            self.main.sMemRegions.emit(regs[:5000], len(regs))
        self._run(work)

    def _region_selected(self):
        has = bool(self.reg_table.selectedItems())
        self.btn_read.setEnabled(has)

    def _sel_addr(self):
        row = self.reg_table.currentRow()
        if row < 0:
            return None
        it = self.reg_table.item(row, 0)
        if not it:
            return None
        return int(it.data(QtCore.Qt.UserRole))

    def _run(self, work):
        threading.Thread(target=lambda: self._wrap(work), daemon=True).start()

    def _wrap(self, work):
        try:
            work()
        except MemoryError as e:
            self._log(f'[!] Memoria: {e.reason}: {e}')
        except Exception as e:
            self._log(f'[!] Memoria: {e}')

    def _do_read(self):
        addr = self._sel_addr()
        if addr is None:
            return
        kind = self.kind_combo.currentText()
        try:
            n = int(self.len_edit.text(), 0) if kind == 'hex' else None
        except ValueError:
            n = None

        def work():
            en = self._engine()
            if kind == 'hex':
                data, err = en.read_range(addr, min(n or 64, 4096))
                lines = [f'@ {hex(addr)} len={len(data)}'
                         + (f' (parcial: {err})' if err else '')]
                for off in range(0, len(data), 16):
                    chunk = data[off:off + 16]
                    hexs = ' '.join(f'{b:02X}' for b in chunk)
                    asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    lines.append(f'{off:06X}  {hexs:<48} |{asc}|')
                self.main.sMemText.emit(self.read_out, '\n'.join(lines))
                return
            val = en.read_value(addr, kind)
            self.main.sMemText.emit(self.read_out, f'{kind}@{hex(addr)} = {val!r}')
        self._run(work)

    # --- snapshots ---
    def _snap_a(self):
        self._take_snap('A')

    def _snap_b(self):
        self._take_snap('B')

    def _take_snap(self, which):
        def work():
            en = self._engine()
            snap = en.snapshot(
                f'{which}',
                per_region_limit=64 * 1024,
                total_budget=4 * 1024 * 1024,
                prot_filter=self._prot_filter(),
            )
            self.main.sMemSnap.emit(which, snap)
        self._run(work)

    def _do_diff(self):
        if self._snapshot_a is None or self._snapshot_b is None:
            self.snap_lbl.setText('Toma primero la captura A y la captura B.')
            return

        def work():
            en = self._engine()
            diffs = en.diff(self._snapshot_a, self._snapshot_b)
            chg = [d for d in diffs if d.kind != 'unchanged']
            self.main.sMemDiff.emit(chg, len(diffs))

        self._run(work)

    # --- watcher ---
    def _toggle_watch(self):
        with self._watch_lock:
            if self._watcher is not None:
                self._watcher.stop()
                self._watcher = None
                self.btn_watch.setIcon(get_icon('play'))
                self.btn_watch.setText('Observar')
                self._log('[watch] detenido')
                return
        try:
            addr = int(self.watch_addr.text().strip(), 16)
            size = int(self.watch_size.text(), 0)
            iv = float(self.watch_interval.text())
        except ValueError as e:
            self._log(f'[!] Watch: valores inválidos ({e})')
            return

        def work():
            en = self._engine()
            w = __import__(
                'core.memory.watcher', fromlist=['MemoryWatcher']
            ).MemoryWatcher(en, addr, size, interval=iv)
            w.on_error = lambda r: self.main.sMemWatch.emit(f'[watch] {r}')
            w.on_stopped = lambda r: self.main.sMemWatch.emit(
                f'[watch] detenido automáticamente: {r} @@STOPPED@@')
            w.start()
            w.on_change = lambda old, new: self.main.sMemWatch.emit(
                f'[watch {hex(addr)}] cambio:\n'
                f'  antes: {old[:32].hex()}\n  ahora: {new[:32].hex()}'[:400])
            with self._watch_lock:
                self._watcher = w
            self.main.sMemWatch.emit(
                f'[watch] activo @@STARTED@@ {hex(addr)} ({size} B cada {iv}s)')

        self._run(work)
