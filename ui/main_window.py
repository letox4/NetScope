# -*- coding: utf-8 -*-
"""Main window de NetScope (PySide6)."""
from pathlib import Path
import threading
from dataclasses import asdict
from datetime import datetime
import json
import os
import subprocess
import sys

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtGui import QAction

from core.interceptor import (
    MAX_PATCH_RULES, FridaInterceptor, NetEvent, SocketStream,
)
from core.numeric_probe import FridaNumericProbe
from core.diagnostics import (
    DiagnosticObservation,
    DiagnosticProfile,
    DiagnosticProviderRegistry,
    DiagnosticTarget,
    ObservationHistory,
)
from core.diagnostic_providers import FridaFunctionProvider
from core.http_parser import parse_http_stream
from core.event_queue import EventQueue, FridaEventWorker
from core.game_analysis import (
    analyze_game_streams,
    format_game_analysis_report,
)
from core.stream_search import StreamSearchIndex
from core.value_scan import ValueScanner
from ui.icons import (
    app_icon,
    get_icon,
    get_pixmap,
    icon_heading,
    logo_pixmap,
    pick_mono_font,
)

REFRESH_MS = 1000


def fmt_bytes(n: float) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == 'B' else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def hexdump(data: bytes, limit: int = 256 * 1024, pattern: bytes = b'') -> str:
    if not data:
        return '(sin datos)'
    data = data[:limit]
    lines = []
    pat = pattern.lower() if pattern else b''
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = ' '.join(f'{b:02X}' for b in chunk)
        hexs = hexs.ljust(48)
        ascii_ = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{off:06X}  {hexs} |{ascii_}|')
    if len(data) == limit:
        lines.append(f'… (mostrando primeros {limit // 1024} KB)')
    if pat:
        # marcar offset donde aparece el patrón
        idx = data.lower().find(pat)
        if idx >= 0:
            lines.append(f'>>> patrón encontrado en offset 0x{idx:06X} (línea {idx//16:04X})')
    return '\n'.join(lines)


class ProcessModel(QtCore.QAbstractTableModel):
    HEAD = ['PID', 'Nombre']

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: list = []

    def rowCount(self, p=QtCore.QModelIndex()) -> int:
        return len(self.rows)

    def columnCount(self, p=QtCore.QModelIndex()) -> int:
        return len(self.HEAD)

    def data(self, idx, role=QtCore.Qt.ItemDataRole.DisplayRole):
        if not idx.isValid():
            return None
        row = self.rows[idx.row()]
        if role == QtCore.Qt.ItemDataRole.DisplayRole:
            key = ('pid', 'name')[idx.column()]
            return str(row[key])
        return None

    def headerData(self, s, o, role):
        if role == QtCore.Qt.ItemDataRole.DisplayRole and o == QtCore.Qt.Orientation.Horizontal:
            return self.HEAD[s]
        return None

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def get(self, row):
        return self.rows[row]


class ProcessFilterProxyModel(QtCore.QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._query = ''

    def set_filter_text(self, text: str):
        q = (text or '').strip().casefold()
        if q == self._query:
            return
        self._query = q
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        if not self._query:
            return True
        row = self.sourceModel().rows[source_row]
        return self._query in row['name'].casefold() or self._query in str(row['pid'])


class StreamModel(QtCore.QAbstractTableModel):
    HEAD = ['ID', 'Protocolo', 'Destino / Dominio', 'Estado', 'Enviado ↑', 'Recibido ↓', 'Paquetes']
    KIND_ROLE = QtCore.Qt.ItemDataRole.UserRole

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: list = []

    def rowCount(self, p=QtCore.QModelIndex()) -> int:
        return len(self.rows)

    def columnCount(self, p=QtCore.QModelIndex()) -> int:
        return len(self.HEAD)

    def data(self, idx, role=QtCore.Qt.ItemDataRole.DisplayRole):
        if not idx.isValid():
            return None
        st = self.rows[idx.row()]
        c = idx.column()
        if role == QtCore.Qt.ItemDataRole.DisplayRole:
            vals = [str(st.fd), st.proto, st.peer,
                    'cerrado' if st.closed else 'abierto',
                    fmt_bytes(st.byte_out), fmt_bytes(st.byte_in),
                    str(st.event_count)]
            return vals[c]
        if role == QtCore.Qt.ItemDataRole.ForegroundRole:
            if c == 4 and st.closed:
                return QtGui.QColor('#B33')
            if c == 2 and st.proto == 'UDP':
                return QtGui.QColor('#2A7')
        if role == self.KIND_ROLE:
            return st
        return None

    def headerData(self, s, o, role):
        if role == QtCore.Qt.ItemDataRole.DisplayRole and o == QtCore.Qt.Orientation.Horizontal:
            return self.HEAD[s]
        return None

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class StreamFilterProxyModel(QtCore.QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._criteria = ()
        self._hits = ()
        self.setDynamicSortFilter(True)

    def set_search(self, criteria, hits):
        normalized = tuple(query.strip().casefold() for query in criteria)
        normalized_hits = tuple(frozenset(item) for item in hits)
        if normalized == self._criteria and normalized_hits == self._hits:
            return
        self._criteria = normalized
        self._hits = normalized_hits
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        if not self._criteria:
            return True
        stream = self.sourceModel().rows[source_row]
        metadata = (
            f'{stream.fd} {stream.proto} {stream.peer} '
            f'{"cerrado" if stream.closed else "abierto"} '
            f'{fmt_bytes(stream.byte_out)} {fmt_bytes(stream.byte_in)} '
            f'{stream.event_count}'
        ).casefold()
        return all(
            query in metadata or stream.fd in self._hits[index]
            for index, query in enumerate(self._criteria)
        )


class NetScopeGUI(QtWidgets.QMainWindow):
    # señales para pasar de threads Frida al hilo GUI
    sStatus = QtCore.Signal(str)
    sLog = QtCore.Signal(str)
    sProcesses = QtCore.Signal(object)
    sModelReset = QtCore.Signal()
    sPatchConfigured = QtCore.Signal(int, bool)
    sPatchToggled = QtCore.Signal(bool)
    sGameAnalysisReady = QtCore.Signal(object, str)
    sProbeLog = QtCore.Signal(str)
    sProbeState = QtCore.Signal(str, str)
    sDiagnosticEvent = QtCore.Signal(object)
    # Fase 2: memoria
    sMemRegions = QtCore.Signal(list, int)
    sMemSnap = QtCore.Signal(str, object)
    sMemDiff = QtCore.Signal(list, int)
    sMemText = QtCore.Signal(object, str)     # (widget destino, texto)
    sMemWatch = QtCore.Signal(str)
    sDiagRefresh = QtCore.Signal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle('NetScope · Observabilidad de red en vivo')
        self.setWindowIcon(app_icon())
        self.resize(1440, 900)
        self.setMinimumSize(1080, 700)
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background: #0b1220;
                color: #e5e7eb;
                font-family: "Bahnschrift", "Segoe UI", sans-serif;
                font-size: 10pt;
            }
            QToolBar {
                background: #111827;
                border: 0;
                border-bottom: 1px solid #263449;
                spacing: 8px;
                padding: 8px 10px;
            }
            QToolBar QToolButton {
                background: transparent;
                color: #e2e8f0;
                border: 1px solid transparent;
                border-radius: 6px;
                padding: 5px 10px;
                font-weight: 600;
            }
            QToolBar QToolButton:hover {
                background: #1e293b;
                border-color: #334155;
            }
            QToolBar QToolButton:disabled {
                color: #475569;
            }
            QTabWidget::pane {
                background: #0f172a;
                border: 1px solid #263449;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #111827;
                color: #94a3b8;
                padding: 9px 15px;
                margin-right: 3px;
                border-top-left-radius: 7px;
                border-top-right-radius: 7px;
                font-weight: 600;
            }
            QTabBar::tab:selected {
                background: #1e293b;
                color: #f8fafc;
                border-bottom: 2px solid #38bdf8;
            }
            QFrame#heroCard, QFrame#metricCard, QFrame#sidebarCard {
                background: #111c2f;
                border: 1px solid #263449;
                border-radius: 10px;
            }
            QLabel#sectionTitle {
                color: #f8fafc;
                font-size: 11pt;
                font-weight: 700;
                letter-spacing: 0.3px;
            }
            QLabel#mutedHint {
                color: #94a3b8;
                font-size: 9pt;
            }
            QLabel#detailBanner {
                background: #111c2f;
                border: 1px solid #263449;
                border-radius: 8px;
                padding: 8px 12px;
                color: #cbd5e1;
            }
            QGroupBox {
                border: 1px solid #263449;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: 600;
                color: #cbd5e1;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 6px;
            }
            QLabel#heroTitle {
                color: #f8fafc;
                font-size: 19pt;
                font-weight: 700;
                letter-spacing: 0.4px;
            }
            QLabel#heroSubtitle {
                color: #94a3b8;
            }
            QLabel#metricTitle {
                color: #94a3b8;
                font-size: 8.5pt;
                font-weight: 700;
                letter-spacing: 0.8px;
            }
            QLabel#metricValue {
                color: #7dd3fc;
                font-size: 17pt;
                font-weight: 700;
            }
            QPushButton, QToolButton#exportMenuBtn {
                background: #1e293b;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 7px;
                padding: 7px 12px;
            }
            QPushButton:hover, QToolButton#exportMenuBtn:hover { background: #29394f; }
            QPushButton:disabled { color: #64748b; background: #111827; }
            QPushButton#primaryButton {
                background: #0284c7;
                color: white;
                border: 0;
                font-weight: 600;
            }
            QPushButton#primaryButton:hover { background: #0ea5e9; }
            QMenu {
                background: #111827;
                color: #e2e8f0;
                border: 1px solid #334155;
            }
            QMenu::item:selected { background: #0369a1; }
            QLineEdit, QComboBox, QSpinBox, QTableWidget, QTableView,
            QTextEdit, QPlainTextEdit {
                background: #0b1220;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 6px;
                selection-background-color: #0369a1;
            }
            QHeaderView::section {
                background: #172337;
                color: #cbd5e1;
                border: 0;
                border-bottom: 1px solid #334155;
                padding: 7px;
            }
            QProgressBar {
                background: #111827;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 6px;
                text-align: center;
                min-height: 18px;
            }
            QProgressBar::chunk {
                background: #0284c7;
                border-radius: 5px;
            }
            QStatusBar {
                background: #111827;
                color: #94a3b8;
                border-top: 1px solid #263449;
            }
        """)

        self.event_queue = EventQueue()
        self._frida_thread = QtCore.QThread(self)
        self._frida_worker = FridaEventWorker(self.event_queue)
        self._frida_worker.moveToThread(self._frida_thread)
        self._frida_worker.batch_ready.connect(self._on_frida_batch)
        self._frida_thread.started.connect(self._frida_worker.run)
        self._frida_thread.start()

        self.interceptor = FridaInterceptor(
            on_event=lambda ev: None,
            on_status=lambda t: self.event_queue.put_status(t),
            on_log=lambda t: self.event_queue.put_log(t),
        )
        self.numeric_probe = FridaNumericProbe(
            on_log=lambda text: self.sProbeLog.emit(text),
            on_event=lambda event: self.sDiagnosticEvent.emit(event))
        self.diagnostic_providers = DiagnosticProviderRegistry()
        self.diagnostic_providers.register(
            FridaFunctionProvider(self.numeric_probe))
        self.diagnostic_providers.load_entry_points()
        for error in self.diagnostic_providers.load_errors:
            self.event_queue.put_log(
                '[!] No se pudo cargar un proveedor de diagnóstico: ' + error)
        self.observation_history = ObservationHistory()
        self._last_diagnostic_profile = None
        self._probe_busy = False
        self.value_scanner = ValueScanner()
        self._value_scan_drop_count = 0
        self._patch_rules = []
        self._patch_attached = False
        self._patch_ready = False
        self._patch_busy = False
        self._patch_dirty = False
        self._attach_in_progress = False
        self._quick_analysis_pending = False
        self._quick_analysis_running = False
        self._quick_analysis_processing = False
        self._quick_analysis_duration = 0
        self._quick_analysis_remaining = 0
        self._quick_report_text = ''
        self._detail_fd = None

        self.proc_model = ProcessModel(self)
        self.proc_proxy = ProcessFilterProxyModel(self)
        self.proc_proxy.setSourceModel(self.proc_model)
        self.stream_model = StreamModel(self)
        self.stream_proxy = StreamFilterProxyModel(self)
        self.stream_proxy.setSourceModel(self.stream_model)
        self._search_query = ''
        self._search_filters = []
        self._search_indexes = {}
        self._stream_by_fd = {}
        self._stream_revisions = {}

        self._build_ui()
        self._search_timer = QtCore.QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(180)
        self._search_timer.timeout.connect(self._apply_search)
        self._refresh_filter_toolbar()
        self._connect_signals()

        self._quick_analysis_timer = QtCore.QTimer(self)
        self._quick_analysis_timer.setInterval(1000)
        self._quick_analysis_timer.timeout.connect(
            self._tick_quick_analysis)

        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._on_tick)
        self._timer.start(REFRESH_MS)

        self.sStatus.emit('Refrescando lista de procesos…')
        self.refresh_processes()

    # -------------------- construcción UI --------------------
    def _build_ui(self):
        tb = QtWidgets.QToolBar('Controles')
        tb.setMovable(False)
        tb.setIconSize(QtCore.QSize(16, 16))
        tb.setToolButtonStyle(QtCore.Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.addToolBar(tb)

        self.btn_refresh = QAction(get_icon('refresh'), 'Actualizar', self)
        self.btn_refresh.setToolTip('Actualiza la lista de aplicaciones abiertas.')

        self.proc_combo = QtWidgets.QComboBox()
        self.proc_combo.setEditable(True)
        self.proc_combo.setInsertPolicy(QtWidgets.QComboBox.InsertPolicy.NoInsert)
        self.proc_combo.setVisible(False)

        self.btn_attach = QAction(get_icon('play', color='#38bdf8'), 'Conectar', self)
        self.btn_attach.setToolTip('Conecta con la aplicación elegida para observar su tráfico.')
        tb.addAction(self.btn_attach)

        self.btn_stop = QAction(get_icon('stop', color='#f87171'), 'Detener', self)
        self.btn_stop.setToolTip('Detiene la captura actual conservando los resultados.')
        self.btn_stop.setEnabled(False)
        tb.addAction(self.btn_stop)

        tb.addSeparator()

        self.spawn_chk = QtWidgets.QCheckBox('Abrir .exe nuevo')
        self.spawn_chk.setToolTip(
            'Marca esta opción si quieres abrir un programa desde cero ya conectado.')
        tb.addWidget(self.spawn_chk)

        self.follow_children_chk = QtWidgets.QCheckBox('Seguir subprocesos')
        self.follow_children_chk.setToolTip(
            'Captura también los procesos hijo que cree la app (Electron, Chromium, launchers).')
        self.follow_children_chk.setChecked(False)
        tb.addWidget(self.follow_children_chk)

        tb.addSeparator()

        self.btn_launch_demo = QAction(get_icon('flask'), 'Probar con App Demo', self)
        self.btn_launch_demo.setToolTip(
            'Abre la app de demostración propia de NetScope para probar todas las funciones.')
        tb.addAction(self.btn_launch_demo)

        spacer = QtWidgets.QWidget()
        spacer.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Preferred,
        )
        tb.addWidget(spacer)

        self.btn_export = QAction(get_icon('file-text'), 'Conexión seleccionada (.bin)', self)
        self.btn_export.setEnabled(False)
        self.btn_export_pcap = QAction(get_icon('file-code'), 'Captura para Wireshark (.pcapng)', self)
        self.btn_export_pcap.setEnabled(False)
        self.btn_export_har = QAction(get_icon('globe'), 'Tráfico Web (.har)', self)
        self.btn_export_har.setEnabled(False)
        self.btn_export_keylog = QAction(get_icon('key'), 'Claves TLS (.keylog)', self)
        self.btn_export_keylog.setEnabled(False)

        export_menu = QtWidgets.QMenu(self)
        export_menu.addAction(self.btn_export_pcap)
        export_menu.addAction(self.btn_export_har)
        export_menu.addAction(self.btn_export_keylog)
        export_menu.addSeparator()
        export_menu.addAction(self.btn_export)

        self.export_menu_btn = QtWidgets.QToolButton()
        self.export_menu_btn.setObjectName('exportMenuBtn')
        self.export_menu_btn.setIcon(get_icon('download'))
        self.export_menu_btn.setIconSize(QtCore.QSize(15, 15))
        self.export_menu_btn.setToolButtonStyle(
            QtCore.Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.export_menu_btn.setText('Exportar')
        self.export_menu_btn.setPopupMode(
            QtWidgets.QToolButton.ToolButtonPopupMode.InstantPopup)
        self.export_menu_btn.setMenu(export_menu)
        self.export_menu_btn.setToolTip('Guarda la captura en PCAPNG, HAR, Keylog o binario.')
        tb.addWidget(self.export_menu_btn)

        # --- splitter central ---
        split = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        self.setCentralWidget(split)

        # Panel izquierdo en 2 tarjetas limpias
        left = QtWidgets.QWidget()
        lv = QtWidgets.QVBoxLayout(left)
        lv.setContentsMargins(8, 8, 4, 8)
        lv.setSpacing(10)
        split.addWidget(left)

        # Tarjeta 1: Aplicaciones abiertas
        proc_card = QtWidgets.QFrame()
        proc_card.setObjectName('sidebarCard')
        pl = QtWidgets.QVBoxLayout(proc_card)
        pl.setContentsMargins(10, 10, 10, 10)
        pl.setSpacing(6)

        proc_hdr = QtWidgets.QHBoxLayout()
        proc_title = icon_heading('monitor', '1. Elige la aplicación')
        self.btn_refresh_inline = QtWidgets.QPushButton(get_icon('refresh'), 'Actualizar')
        self.btn_refresh_inline.setIconSize(QtCore.QSize(14, 14))
        self.btn_refresh_inline.setToolTip('Vuelve a listar las aplicaciones abiertas.')
        self.btn_refresh_inline.clicked.connect(self.btn_refresh.trigger)
        proc_hdr.addWidget(proc_title)
        proc_hdr.addStretch(1)
        proc_hdr.addWidget(self.btn_refresh_inline)
        pl.addLayout(proc_hdr)

        self.proc_filter_edit = QtWidgets.QLineEdit()
        self.proc_filter_edit.setPlaceholderText('Buscar app por nombre o PID…')
        self.proc_filter_edit.addAction(
            get_icon('search', color='#64748b', size=14),
            QtWidgets.QLineEdit.ActionPosition.LeadingPosition)
        self.proc_filter_edit.setClearButtonEnabled(True)
        pl.addWidget(self.proc_filter_edit)

        self.process_hint = QtWidgets.QLabel('Buscando aplicaciones abiertas…')
        self.process_hint.setWordWrap(True)
        self.process_hint.setObjectName('mutedHint')
        pl.addWidget(self.process_hint)

        self.proc_view = QtWidgets.QTableView()
        self.proc_view.setModel(self.proc_proxy)
        self._setup_view(self.proc_view)
        self.proc_view.setColumnWidth(0, 72)
        self.proc_view.setToolTip('Haz clic en una aplicación para seleccionarla.')
        pl.addWidget(self.proc_view, 1)
        lv.addWidget(proc_card, 5)

        # Tarjeta 2: Conexiones detectadas
        stream_card = QtWidgets.QFrame()
        stream_card.setObjectName('sidebarCard')
        sl = QtWidgets.QVBoxLayout(stream_card)
        sl.setContentsMargins(10, 10, 10, 10)
        sl.setSpacing(6)

        stream_hdr = QtWidgets.QHBoxLayout()
        stream_title = icon_heading('activity', '2. Conexiones detectadas')
        self.localhost_chk = QtWidgets.QCheckBox('Solo local')
        self.localhost_chk.setToolTip('Muestra solo conexiones hacia 127.0.0.1.')
        self.localhost_chk.setChecked(False)
        stream_hdr.addWidget(stream_title)
        stream_hdr.addStretch(1)
        stream_hdr.addWidget(self.localhost_chk)
        sl.addLayout(stream_hdr)

        search_row = QtWidgets.QHBoxLayout()
        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText('Filtrar por texto, dominio, IP o hex:…')
        self.search_edit.addAction(
            get_icon('search', color='#64748b', size=14),
            QtWidgets.QLineEdit.ActionPosition.LeadingPosition)
        self.search_edit.setClearButtonEnabled(True)
        self.btn_add_filter = QtWidgets.QPushButton('+ Filtro')
        self.btn_add_filter.setToolTip('Fija este filtro para combinarlo con otros.')
        search_row.addWidget(self.search_edit, 1)
        search_row.addWidget(self.btn_add_filter)
        sl.addLayout(search_row)

        self.filters_toolbar = QtWidgets.QToolBar('Filtros acumulados')
        self.filters_toolbar.setMovable(False)
        self.filters_toolbar.setVisible(False)
        sl.addWidget(self.filters_toolbar)

        self.stream_hint = QtWidgets.QLabel(
            'Aquí aparecerán las conexiones al iniciar la captura.')
        self.stream_hint.setWordWrap(True)
        self.stream_hint.setObjectName('mutedHint')
        sl.addWidget(self.stream_hint)

        self.stream_view = QtWidgets.QTableView()
        self.stream_view.setModel(self.stream_proxy)
        self._setup_view(self.stream_view)
        self.stream_view.setColumnWidth(0, 64)
        self.stream_view.setColumnWidth(1, 68)
        self.stream_view.setColumnWidth(2, 160)
        self.stream_view.setToolTip('Selecciona una conexión para ver su contenido a la derecha.')
        sl.addWidget(self.stream_view, 1)
        lv.addWidget(stream_card, 5)

        # Panel derecho (5 secciones principales limpias)
        right_wrap = QtWidgets.QWidget()
        rw = QtWidgets.QVBoxLayout(right_wrap)
        rw.setContentsMargins(4, 8, 8, 8)
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setIconSize(QtCore.QSize(16, 16))
        rw.addWidget(self.tabs)
        split.addWidget(right_wrap)
        split.setSizes([450, 950])

        # ==================== 1. RESUMEN ====================
        quick_page = QtWidgets.QWidget()
        quick_layout = QtWidgets.QVBoxLayout(quick_page)
        quick_layout.setContentsMargins(14, 14, 14, 14)
        quick_layout.setSpacing(10)

        hero = QtWidgets.QFrame()
        hero.setObjectName('heroCard')
        hero_row = QtWidgets.QHBoxLayout(hero)
        hero_row.setContentsMargins(16, 13, 16, 13)
        hero_row.setSpacing(14)
        hero_logo = QtWidgets.QLabel()
        hero_logo.setPixmap(logo_pixmap(40))
        hero_logo.setFixedSize(42, 42)
        hero_row.addWidget(hero_logo)
        hero_text_col = QtWidgets.QVBoxLayout()
        hero_text_col.setSpacing(2)
        hero_title = QtWidgets.QLabel('NetScope · Empieza en 3 pasos')
        hero_title.setObjectName('heroTitle')
        hero_subtitle = QtWidgets.QLabel(
            'Elige una aplicación a la izquierda, inicia la captura y úsala normalmente: '
            'NetScope resumirá automáticamente sus conexiones, protocolos y datos.')
        hero_subtitle.setObjectName('heroSubtitle')
        hero_subtitle.setWordWrap(True)
        hero_text_col.addWidget(hero_title)
        hero_text_col.addWidget(hero_subtitle)
        hero_row.addLayout(hero_text_col, 1)
        quick_layout.addWidget(hero)

        self.quick_target_label = QtWidgets.QLabel(
            'Paso 1 de 3 · Elige una aplicación en la lista de la izquierda.')
        self.quick_target_label.setObjectName('heroSubtitle')
        quick_layout.addWidget(self.quick_target_label)

        quick_controls = QtWidgets.QHBoxLayout()
        quick_controls.addWidget(QtWidgets.QLabel('Duración:'))
        self.quick_duration = QtWidgets.QSpinBox()
        self.quick_duration.setRange(5, 3600)
        self.quick_duration.setValue(60)
        self.quick_duration.setSuffix(' s')
        quick_controls.addWidget(self.quick_duration)
        self.btn_quick_start = QtWidgets.QPushButton(
            get_icon('play', color='#ffffff', active_color='#ffffff'), 'Iniciar análisis')
        self.btn_quick_start.setObjectName('primaryButton')
        self.btn_quick_stop = QtWidgets.QPushButton(get_icon('stop'), 'Detener y analizar')
        self.btn_quick_stop.setEnabled(False)
        self.btn_quick_export = QtWidgets.QPushButton(get_icon('save'), 'Guardar informe')
        self.btn_quick_export.setEnabled(False)
        quick_controls.addWidget(self.btn_quick_start)
        quick_controls.addWidget(self.btn_quick_stop)
        quick_controls.addWidget(self.btn_quick_export)
        quick_controls.addStretch(1)
        self.quick_countdown = QtWidgets.QLabel('Selecciona una aplicación para empezar.')
        quick_controls.addWidget(self.quick_countdown)
        quick_layout.addLayout(quick_controls)

        self.quick_progress = QtWidgets.QProgressBar()
        self.quick_progress.setRange(0, 100)
        self.quick_progress.setValue(0)
        self.quick_progress.setFormat('En espera')
        quick_layout.addWidget(self.quick_progress)

        metrics_layout = QtWidgets.QHBoxLayout()
        self.quick_metric_values = {}
        for key, icon_name, title, initial in (
                ('streams', 'activity', 'CONEXIONES', '0'),
                ('tx', 'arrow-up-right', 'ENVIADO', '0 B'),
                ('rx', 'arrow-down-left', 'RECIBIDO', '0 B'),
                ('frameworks', 'shield', 'DETECTADO', '—')):
            card = QtWidgets.QFrame()
            card.setObjectName('metricCard')
            card_layout = QtWidgets.QVBoxLayout(card)
            title_row = QtWidgets.QHBoxLayout()
            title_row.setContentsMargins(0, 0, 0, 0)
            title_row.setSpacing(5)
            icon_lbl = QtWidgets.QLabel()
            icon_lbl.setPixmap(get_pixmap(icon_name, color='#64748b', size=13))
            icon_lbl.setFixedSize(14, 14)
            label = QtWidgets.QLabel(title)
            label.setObjectName('metricTitle')
            title_row.addWidget(icon_lbl)
            title_row.addWidget(label, 1)
            value = QtWidgets.QLabel(initial)
            value.setObjectName('metricValue')
            card_layout.addLayout(title_row)
            card_layout.addWidget(value)
            metrics_layout.addWidget(card, 1)
            self.quick_metric_values[key] = value
        quick_layout.addLayout(metrics_layout)

        self.quick_results_table = QtWidgets.QTableWidget(0, 9)
        self.quick_results_table.setHorizontalHeaderLabels([
            'ID', 'Protocolo', 'Destino', 'Patrón / Motor',
            'Enviado', 'Recibido', 'Formato Env.', 'Formato Rec.', 'Entropía',
        ])
        self.quick_results_table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.quick_results_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.quick_results_table.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.quick_results_table.horizontalHeader().setStretchLastSection(True)
        quick_layout.addWidget(self.quick_results_table, 3)

        self.quick_report_view = self._make_text()
        self.quick_report_view.setMaximumHeight(150)
        self.quick_report_view.setPlaceholderText(
            'El resumen del análisis aparecerá aquí al finalizar la captura.')
        quick_layout.addWidget(self.quick_report_view, 1)
        self.tabs.addTab(quick_page, get_icon('home'), 'Resumen')

        # ==================== 2. TRÁFICO DE LA CONEXIÓN ====================
        traffic_page = QtWidgets.QWidget()
        tlay = QtWidgets.QVBoxLayout(traffic_page)
        tlay.setContentsMargins(10, 10, 10, 10)
        tlay.setSpacing(8)

        self.detail_banner_lbl = QtWidgets.QLabel(
            'Selecciona una conexión en «2. Conexiones detectadas» para ver sus datos.')
        self.detail_banner_lbl.setObjectName('detailBanner')
        tlay.addWidget(self.detail_banner_lbl)

        self.inspector_tabs = QtWidgets.QTabWidget()
        self.inspector_tabs.setIconSize(QtCore.QSize(15, 15))
        tlay.addWidget(self.inspector_tabs, 1)

        # Sub-tab: Texto legible (TX / RX)
        w_stream = QtWidgets.QWidget()
        v1 = QtWidgets.QVBoxLayout(w_stream)
        v1.setContentsMargins(4, 4, 4, 4)
        self.dir_tabs = QtWidgets.QTabWidget()
        self.dir_tabs.setIconSize(QtCore.QSize(14, 14))
        v1.addWidget(self.dir_tabs, 1)
        self.out_view = self._make_text()
        self.out_view.setPlaceholderText('Datos enviados por la aplicación.')
        self.in_view = self._make_text()
        self.in_view.setPlaceholderText('Datos recibidos por la aplicación.')
        self.dir_tabs.addTab(self.out_view, get_icon('arrow-up-right'), 'Enviado (TX)')
        self.dir_tabs.addTab(self.in_view, get_icon('arrow-down-left'), 'Recibido (RX)')
        self.inspector_tabs.addTab(w_stream, get_icon('file-text'), 'Texto Legible')

        # Sub-tab: Peticiones Web (HTTP)
        w_http = QtWidgets.QWidget()
        v3 = QtWidgets.QVBoxLayout(w_http)
        v3.setContentsMargins(4, 4, 4, 4)
        self.http_list = QtWidgets.QListWidget()
        self.http_body = self._make_text()
        self.http_body.setPlaceholderText('Selecciona una petición HTTP arriba para ver sus cabeceras y cuerpo.')
        v3.addWidget(self.http_list, 4)
        v3.addWidget(self.http_body, 6)
        self.inspector_tabs.addTab(w_http, get_icon('globe'), 'Peticiones Web')

        # Sub-tab: Técnico (Hex + Origen en código)
        w_hex = QtWidgets.QWidget()
        v2 = QtWidgets.QVBoxLayout(w_hex)
        v2.setContentsMargins(4, 4, 4, 4)
        self.hex_view = QtWidgets.QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(pick_mono_font(9))
        self.hex_view.setPlaceholderText('Vista hexadecimal y funciones de código que enviaron/recibieron el tráfico.')
        v2.addWidget(self.hex_view)
        self.inspector_tabs.addTab(w_hex, get_icon('code'), 'Técnico y Origen en Código')

        self.tabs.addTab(traffic_page, get_icon('message-square'), 'Conexión')

        # ==================== 3. SEGURIDAD Y AMENAZAS ====================
        security_page = QtWidgets.QWidget()
        seclay = QtWidgets.QVBoxLayout(security_page)
        seclay.setContentsMargins(10, 10, 10, 10)
        self.security_tabs = QtWidgets.QTabWidget()
        self.security_tabs.setIconSize(QtCore.QSize(15, 15))
        seclay.addWidget(self.security_tabs)

        # Sub-tab: Amenazas (IOCs / YARA)
        w_threat = QtWidgets.QWidget()
        threat_layout = QtWidgets.QVBoxLayout(w_threat)
        threat_layout.setContentsMargins(8, 8, 8, 8)
        threat_layout.setSpacing(8)
        threat_layout.addWidget(QtWidgets.QLabel(
            'Busca automáticamente IPs, dominios, URLs, credenciales o firmas sospechosas en el tráfico capturado.'
        ))
        threat_actions = QtWidgets.QHBoxLayout()
        self.btn_extract_iocs = QtWidgets.QPushButton(
            get_icon('search', color='#ffffff', active_color='#ffffff'),
            'Extraer indicadores (IOCs)')
        self.btn_extract_iocs.setObjectName('primaryButton')
        self.btn_scan_yara = QtWidgets.QPushButton(get_icon('shield'), 'Escanear con YARA')
        self.btn_load_yara = QtWidgets.QPushButton(get_icon('folder-open'), 'Cargar .yar…')
        self.btn_toggle_yara = QtWidgets.QPushButton(get_icon('sliders'), 'Reglas propias')
        self.btn_toggle_yara.setCheckable(True)
        self.btn_export_threats = QtWidgets.QPushButton(get_icon('save'), 'Exportar informe…')
        self.threat_status_lbl = QtWidgets.QLabel('Sin análisis todavía.')
        self.threat_status_lbl.setObjectName('mutedHint')
        threat_actions.addWidget(self.btn_extract_iocs)
        threat_actions.addWidget(self.btn_scan_yara)
        threat_actions.addWidget(self.btn_load_yara)
        threat_actions.addWidget(self.btn_toggle_yara)
        threat_actions.addWidget(self.btn_export_threats)
        threat_actions.addWidget(self.threat_status_lbl, 1)
        threat_layout.addLayout(threat_actions)

        self.yara_rules_edit = QtWidgets.QPlainTextEdit()
        self.yara_rules_edit.setMaximumHeight(110)
        self.yara_rules_edit.setFont(pick_mono_font(9))
        self.yara_rules_edit.setPlaceholderText(
            'Opcional: pega reglas YARA personalizadas aquí.\n'
            'Ejemplo: rule MiRegla { strings: $a = "secret" condition: $a }'
        )
        self.yara_rules_edit.setVisible(False)
        threat_layout.addWidget(self.yara_rules_edit)

        self.ioc_table = QtWidgets.QTableWidget(0, 6)
        self.ioc_table.setHorizontalHeaderLabels([
            'Tipo', 'Valor', 'Conexión', 'Dirección', 'Confianza', 'Contexto',
        ])
        self.ioc_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.ioc_table.horizontalHeader().setStretchLastSection(True)
        threat_layout.addWidget(self.ioc_table, 1)

        self.yara_table = QtWidgets.QTableWidget(0, 5)
        self.yara_table.setHorizontalHeaderLabels([
            'Regla YARA', 'Categoría / Severidad', 'Conexión', 'Dirección', 'Coincidencias',
        ])
        self.yara_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.yara_table.horizontalHeader().setStretchLastSection(True)
        threat_layout.addWidget(self.yara_table, 1)

        self.security_tabs.addTab(w_threat, get_icon('search'), 'Indicadores y YARA')

        # Sub-tab: Protecciones del proceso
        from ui.antidebug_panel import AntiDebugPanel
        self.antidebug_panel = AntiDebugPanel(self)
        self.security_tabs.addTab(self.antidebug_panel, get_icon('lock'), 'Diagnóstico de Protecciones')

        self.tabs.addTab(security_page, get_icon('shield'), 'Seguridad')

        # ==================== 4. LABORATORIO AVANZADO ====================
        lab_page = QtWidgets.QWidget()
        lab_layout = QtWidgets.QVBoxLayout(lab_page)
        lab_layout.setContentsMargins(10, 10, 10, 10)
        self.lab_tabs = QtWidgets.QTabWidget()
        self.lab_tabs.setIconSize(QtCore.QSize(15, 15))
        lab_layout.addWidget(self.lab_tabs)

        # Sub-tab: Buscar valores
        w_scan = QtWidgets.QWidget()
        scan_layout = QtWidgets.QVBoxLayout(w_scan)
        scan_layout.setContentsMargins(8, 8, 8, 8)
        scan_layout.addWidget(QtWidgets.QLabel(
            'Encuentra números (ej. vida, dinero, puntuación) dentro de los mensajes de red ya capturados.'
        ))

        scan_controls = QtWidgets.QHBoxLayout()
        self.value_scan_input = QtWidgets.QLineEdit()
        self.value_scan_input.setPlaceholderText('Valor a buscar (ej. 100 o 0x64)')
        self.value_scan_input.setMinimumWidth(200)
        self.value_type_combo = QtWidgets.QComboBox()
        for value_type in (
                'uint16', 'uint32', 'uint64',
                'int16', 'int32', 'int64', 'float32', 'float64'):
            self.value_type_combo.addItem(value_type, value_type)
        self.byte_order_combo = QtWidgets.QComboBox()
        self.byte_order_combo.addItem('Ambos endian', 'both')
        self.byte_order_combo.addItem('Little-endian', 'little-endian')
        self.byte_order_combo.addItem('Big-endian', 'big-endian')
        self.btn_value_scan = QtWidgets.QPushButton(get_icon('search'), 'Buscar inicial')
        self.btn_value_rescan = QtWidgets.QPushButton(get_icon('sliders'), 'Filtrar nuevo valor')
        self.btn_value_rescan.setEnabled(False)
        self.btn_value_reset = QtWidgets.QPushButton(get_icon('refresh'), 'Reiniciar')
        scan_controls.addWidget(self.value_scan_input, 2)
        scan_controls.addWidget(self.value_type_combo)
        scan_controls.addWidget(self.byte_order_combo)
        scan_controls.addWidget(self.btn_value_scan)
        scan_controls.addWidget(self.btn_value_rescan)
        scan_controls.addWidget(self.btn_value_reset)
        scan_layout.addLayout(scan_controls)

        self.value_scan_status = QtWidgets.QLabel(
            'Solo analiza mensajes capturados en la sesión actual.')
        self.value_scan_status.setObjectName('mutedHint')
        self.value_scan_status.setWordWrap(True)
        scan_layout.addWidget(self.value_scan_status)

        self.value_scan_table = QtWidgets.QTableWidget(0, 8)
        self.value_scan_table.setHorizontalHeaderLabels([
            'ID', 'Proto', 'Dirección', 'Origen', 'Offset', 'Tipo',
            'Orden', 'Valor',
        ])
        self.value_scan_table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.value_scan_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.value_scan_table.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.value_scan_table.horizontalHeader().setStretchLastSection(True)
        scan_layout.addWidget(self.value_scan_table, 1)
        self.lab_tabs.addTab(w_scan, get_icon('search'), 'Buscar Números')

        # Sub-tab: Modificar salida
        w_patch = QtWidgets.QWidget()
        patch_layout = QtWidgets.QVBoxLayout(w_patch)
        patch_layout.setContentsMargins(8, 8, 8, 8)
        patch_layout.addWidget(QtWidgets.QLabel(
            'Reemplaza bytes exactos antes de enviarse (ambos hexadecimales deben medir exactamente lo mismo).'
        ))

        patch_inputs = QtWidgets.QHBoxLayout()
        self.patch_match_input = QtWidgets.QLineEdit()
        self.patch_match_input.setPlaceholderText('Buscar bytes (hex)')
        self.patch_replace_input = QtWidgets.QLineEdit()
        self.patch_replace_input.setPlaceholderText('Reemplazar por (hex)')
        self.btn_patch_add = QtWidgets.QPushButton('Añadir regla')
        patch_inputs.addWidget(self.patch_match_input, 1)
        patch_inputs.addWidget(self.patch_replace_input, 1)
        patch_inputs.addWidget(self.btn_patch_add)
        patch_layout.addLayout(patch_inputs)

        self.patch_rule_table = QtWidgets.QTableWidget(0, 2)
        self.patch_rule_table.setHorizontalHeaderLabels([
            'Coincidencia hex', 'Reemplazo hex',
        ])
        self.patch_rule_table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.patch_rule_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.patch_rule_table.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.patch_rule_table.horizontalHeader().setStretchLastSection(True)
        patch_layout.addWidget(self.patch_rule_table, 1)

        patch_actions = QtWidgets.QHBoxLayout()
        self.btn_patch_remove = QtWidgets.QPushButton('Quitar regla')
        self.btn_patch_apply = QtWidgets.QPushButton('Aplicar al proceso')
        self.btn_patch_apply.setEnabled(False)
        self.patch_enable_checkbox = QtWidgets.QCheckBox('Activar reemplazo en vivo')
        self.patch_enable_checkbox.setEnabled(False)
        patch_actions.addWidget(self.btn_patch_remove)
        patch_actions.addWidget(self.btn_patch_apply)
        patch_actions.addStretch(1)
        patch_actions.addWidget(self.patch_enable_checkbox)
        patch_layout.addLayout(patch_actions)

        self.patch_status = QtWidgets.QLabel(
            f'Máximo {MAX_PATCH_RULES} reglas. Conecta con un proceso antes de aplicarlas.')
        self.patch_status.setObjectName('mutedHint')
        self.patch_status.setWordWrap(True)
        patch_layout.addWidget(self.patch_status)
        self.lab_tabs.addTab(w_patch, get_icon('edit'), 'Modificar Salida')

        # Sub-tab: Memoria (solo lectura)
        from ui.memory_panel import MemoryPanel
        self.memory_panel = MemoryPanel(self)
        self.lab_tabs.addTab(self.memory_panel, get_icon('cpu'), 'Memoria (Solo lectura)')

        # Sub-tab: Sonda de funciones
        w_probe = QtWidgets.QWidget()
        probe_layout = QtWidgets.QVBoxLayout(w_probe)
        probe_layout.setContentsMargins(8, 8, 8, 8)
        probe_layout.setSpacing(8)
        self.numeric_probe_path = Path(__file__).resolve().parents[1] / 'agent' / 'observe_numeric.js'

        probe_target_box = QtWidgets.QGroupBox('Aplicación seleccionada')
        probe_target_layout = QtWidgets.QVBoxLayout(probe_target_box)
        self.probe_target_label = QtWidgets.QLabel(
            'Elige una aplicación en la lista de la izquierda.')
        self.probe_target_label.setWordWrap(True)
        probe_target_layout.addWidget(self.probe_target_label)
        probe_layout.addWidget(probe_target_box)

        probe_form_box = QtWidgets.QGroupBox('Configuración de la sonda')
        probe_form = QtWidgets.QFormLayout(probe_form_box)
        self.probe_mode_combo = QtWidgets.QComboBox()
        self.probe_mode_combo.addItem('Función nativa exportada', 'native')
        self.probe_mode_combo.addItem('Unity / IL2CPP', 'il2cpp')
        probe_form.addRow('Modo:', self.probe_mode_combo)

        self.probe_config_stack = QtWidgets.QStackedWidget()
        native_page = QtWidgets.QWidget()
        native_form = QtWidgets.QFormLayout(native_page)
        self.probe_module_edit = QtWidgets.QLineEdit()
        self.probe_module_edit.setPlaceholderText('Ej.: GameAssembly.dll')
        self.probe_export_edit = QtWidgets.QLineEdit()
        self.probe_export_edit.setPlaceholderText('Ej.: MiFuncion')
        self.probe_native_arg_index = QtWidgets.QSpinBox()
        self.probe_native_arg_index.setRange(0, 32)
        self.probe_native_arg_type = QtWidgets.QComboBox()
        self.probe_return_type = QtWidgets.QComboBox()
        for value_type in ('int32', 'uint32', 'pointer'):
            self.probe_native_arg_type.addItem(value_type, value_type)
            self.probe_return_type.addItem(value_type, value_type)
        native_form.addRow('Módulo / DLL', self.probe_module_edit)
        native_form.addRow('Función exportada', self.probe_export_edit)
        native_form.addRow('Índice argumento', self.probe_native_arg_index)
        native_form.addRow('Tipo argumento', self.probe_native_arg_type)
        native_form.addRow('Tipo retorno', self.probe_return_type)
        self.probe_config_stack.addWidget(native_page)

        il2cpp_page = QtWidgets.QWidget()
        il2cpp_form = QtWidgets.QFormLayout(il2cpp_page)
        self.probe_assembly_edit = QtWidgets.QLineEdit()
        self.probe_assembly_edit.setPlaceholderText('Ej.: Assembly-CSharp')
        self.probe_namespace_edit = QtWidgets.QLineEdit()
        self.probe_namespace_edit.setPlaceholderText('Ej.: Game')
        self.probe_class_edit = QtWidgets.QLineEdit()
        self.probe_class_edit.setPlaceholderText('Ej.: PlayerController')
        self.probe_method_edit = QtWidgets.QLineEdit()
        self.probe_method_edit.setPlaceholderText('Ej.: UpdateScore')
        self.probe_il2cpp_arg_count = QtWidgets.QSpinBox()
        self.probe_il2cpp_arg_count.setRange(0, 32)
        self.probe_il2cpp_arg_index = QtWidgets.QSpinBox()
        self.probe_il2cpp_arg_index.setRange(0, 32)
        self.probe_il2cpp_arg_type = QtWidgets.QComboBox()
        self.probe_il2cpp_return_type = QtWidgets.QComboBox()
        for value_type in ('int32', 'uint32', 'pointer'):
            self.probe_il2cpp_arg_type.addItem(value_type, value_type)
            self.probe_il2cpp_return_type.addItem(value_type, value_type)
        il2cpp_form.addRow('Ensamblado', self.probe_assembly_edit)
        il2cpp_form.addRow('Namespace', self.probe_namespace_edit)
        il2cpp_form.addRow('Clase', self.probe_class_edit)
        il2cpp_form.addRow('Método', self.probe_method_edit)
        il2cpp_form.addRow('N.º parámetros', self.probe_il2cpp_arg_count)
        il2cpp_form.addRow('Índice argumento', self.probe_il2cpp_arg_index)
        il2cpp_form.addRow('Tipo argumento', self.probe_il2cpp_arg_type)
        il2cpp_form.addRow('Tipo retorno', self.probe_il2cpp_return_type)

        bridge_row = QtWidgets.QHBoxLayout()
        self.probe_bridge_edit = QtWidgets.QLineEdit()
        self.probe_bridge_edit.setPlaceholderText('Selecciona frida-il2cpp-bridge.js')
        default_bridge = Path(__file__).resolve().parents[1] / 'vendor' / 'frida-il2cpp-bridge.js'
        if default_bridge.is_file():
            self.probe_bridge_edit.setText(str(default_bridge))
        self.btn_probe_browse_bridge = QtWidgets.QPushButton('Buscar…')
        bridge_row.addWidget(self.probe_bridge_edit, 1)
        bridge_row.addWidget(self.btn_probe_browse_bridge)
        il2cpp_form.addRow('Bridge IL2CPP', bridge_row)

        self.probe_config_stack.addWidget(il2cpp_page)
        probe_form.addRow(self.probe_config_stack)
        probe_layout.addWidget(probe_form_box)

        probe_actions = QtWidgets.QHBoxLayout()
        self.btn_probe_start = QtWidgets.QPushButton(
            get_icon('play', color='#ffffff', active_color='#ffffff'), 'Iniciar sonda')
        self.btn_probe_start.setObjectName('primaryButton')
        self.btn_probe_stop = QtWidgets.QPushButton(get_icon('stop'), 'Detener sonda')
        self.btn_probe_stop.setEnabled(False)
        probe_actions.addWidget(self.btn_probe_start)
        probe_actions.addWidget(self.btn_probe_stop)
        probe_layout.addLayout(probe_actions)
        self.numeric_probe_status = QtWidgets.QLabel('Listo para observar funciones en modo solo lectura.')
        self.numeric_probe_status.setObjectName('mutedHint')
        self.numeric_probe_status.setWordWrap(True)
        probe_layout.addWidget(self.numeric_probe_status)
        self.probe_capabilities_label = QtWidgets.QLabel('')
        self.probe_capabilities_label.setObjectName('mutedHint')
        self.probe_capabilities_label.setWordWrap(True)
        probe_layout.addWidget(self.probe_capabilities_label)

        probe_history_actions = QtWidgets.QHBoxLayout()
        self.btn_probe_export_history = QtWidgets.QPushButton(get_icon('save'), 'Exportar historial…')
        self.btn_probe_clear_history = QtWidgets.QPushButton(get_icon('trash'), 'Limpiar')
        probe_history_actions.addWidget(self.btn_probe_export_history)
        probe_history_actions.addWidget(self.btn_probe_clear_history)
        probe_history_actions.addStretch(1)
        probe_layout.addLayout(probe_history_actions)
        self.probe_history_table = QtWidgets.QTableWidget(0, 5)
        self.probe_history_table.setHorizontalHeaderLabels([
            'Hora', 'Dominio', 'Función', 'Fase', 'Valores',
        ])
        self.probe_history_table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.probe_history_table.horizontalHeader().setStretchLastSection(True)
        probe_layout.addWidget(self.probe_history_table, 1)
        self.numeric_probe_log = self._make_text()
        self.numeric_probe_log.setMaximumHeight(110)
        probe_layout.addWidget(self.numeric_probe_log)
        self.lab_tabs.addTab(w_probe, get_icon('crosshair'), 'Sonda de Funciones')

        self.tabs.addTab(lab_page, get_icon('sliders'), 'Laboratorio')

        # ==================== 5. REGISTRO ====================
        w_log = QtWidgets.QWidget()
        v4 = QtWidgets.QVBoxLayout(w_log)
        v4.setContentsMargins(10, 10, 10, 10)
        v4.setSpacing(8)
        log_bar = QtWidgets.QHBoxLayout()
        log_bar.addWidget(QtWidgets.QLabel('Actividad interna y eventos de conexión'))
        log_bar.addStretch(1)
        self.btn_clear_log = QtWidgets.QPushButton(get_icon('trash'), 'Limpiar registro')
        self.btn_clear_log.clicked.connect(lambda: self.log_view.clear())
        log_bar.addWidget(self.btn_clear_log)
        v4.addLayout(log_bar)
        self.log_view = self._make_text()
        v4.addWidget(self.log_view, 1)
        self.tabs.addTab(w_log, get_icon('list'), 'Registro')

        self.statusBar().showMessage('Listo')

    def _make_text(self):
        t = QtWidgets.QPlainTextEdit()
        t.setReadOnly(True)
        t.setFont(pick_mono_font(9))
        return t

    def _setup_view(self, view: QtWidgets.QTableView):
        vh = view.verticalHeader()
        vh.setVisible(False)
        hh = view.horizontalHeader()
        hh.setStretchLastSection(True)
        view.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        view.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        view.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)

    def _connect_signals(self):
        self.sStatus.connect(self._handle_status)
        self.sLog.connect(self.log_view.appendPlainText)
        # Fase 2: memoria
        self.sMemRegions.connect(self._mem_fill_regions)
        self.sMemSnap.connect(self._mem_on_snap)
        self.sMemDiff.connect(self._mem_fill_diff)
        self.sMemText.connect(self._mem_set_text)
        self.sMemWatch.connect(self._mem_watch_log)
        self.sDiagRefresh.connect(lambda: self.antidebug_panel.refresh())
        self.sProcesses.connect(self._set_processes)
        self.sPatchConfigured.connect(self._on_patch_configured)
        self.sPatchToggled.connect(self._on_patch_toggled)
        self.sGameAnalysisReady.connect(self._on_quick_analysis_ready)
        self.btn_refresh.triggered.connect(self.refresh_processes)
        self.btn_attach.triggered.connect(self.attach_target)
        self.btn_stop.triggered.connect(self.stop)
        self.btn_export.triggered.connect(self.export_stream)
        self.btn_export_pcap.triggered.connect(self.export_pcapng)
        self.btn_export_har.triggered.connect(self.export_har)
        self.btn_export_keylog.triggered.connect(self.export_tls_keylog)
        self.btn_launch_demo.triggered.connect(self.launch_demo_app)
        self.btn_extract_iocs.clicked.connect(self._extract_iocs_ui)
        self.btn_scan_yara.clicked.connect(self._scan_yara_ui)
        self.btn_load_yara.clicked.connect(self._load_yara_file)
        self.btn_toggle_yara.toggled.connect(self.yara_rules_edit.setVisible)
        self.btn_export_threats.clicked.connect(self._export_threats_report)
        self.proc_filter_edit.textChanged.connect(self._on_proc_filter_changed)
        self.stream_view.selectionModel().currentRowChanged.connect(self._on_stream_sel)
        self.http_list.itemSelectionChanged.connect(self._on_http_sel)
        self.search_edit.textChanged.connect(self._schedule_search)
        self.search_edit.returnPressed.connect(self._add_search_filter)
        self.btn_add_filter.clicked.connect(self._add_search_filter)
        self.btn_patch_add.clicked.connect(self._add_patch_rule)
        self.btn_patch_remove.clicked.connect(self._remove_patch_rule)
        self.btn_patch_apply.clicked.connect(self._apply_patch_rules)
        self.patch_enable_checkbox.toggled.connect(self._toggle_patch_rewrite)
        self.patch_rule_table.itemSelectionChanged.connect(
            self._update_patch_controls)
        self.btn_quick_start.clicked.connect(self._start_quick_analysis)
        self.btn_quick_stop.clicked.connect(self.stop)
        self.btn_quick_export.clicked.connect(self._export_quick_report)
        self.proc_view.selectionModel().selectionChanged.connect(
            self._update_quick_target)
        self.proc_combo.currentTextChanged.connect(self._update_quick_target)
        self.spawn_chk.toggled.connect(self._update_quick_target)
        self._update_patch_controls()
        self._update_quick_target()
        self._update_quick_controls()
        self.btn_value_scan.clicked.connect(self._scan_initial_value)
        self.btn_value_rescan.clicked.connect(self._rescan_value)
        self.btn_value_reset.clicked.connect(self._reset_value_scan)
        self.sProbeLog.connect(self.numeric_probe_log.appendPlainText)
        self.sProbeState.connect(self._handle_numeric_probe_state)
        self.sDiagnosticEvent.connect(self._handle_diagnostic_event)
        self.probe_mode_combo.currentIndexChanged.connect(
            self._on_probe_mode_changed)
        self.btn_probe_browse_bridge.clicked.connect(
            self._browse_numeric_probe_bridge)
        self.btn_probe_start.clicked.connect(self._start_numeric_probe)
        self.btn_probe_stop.clicked.connect(self._stop_numeric_probe)
        self.btn_probe_export_history.clicked.connect(
            self._export_probe_history)
        self.btn_probe_clear_history.clicked.connect(
            self._clear_probe_history)
        self._on_probe_mode_changed()

    # -------------------- export --------------------
    def _browse_numeric_probe_bridge(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, 'Seleccionar bundle de frida-il2cpp-bridge', '',
            'JavaScript (*.js);;Todos los archivos (*)')
        if path:
            self.probe_bridge_edit.setText(path)

    def _on_proc_filter_changed(self, text):
        self.proc_proxy.set_filter_text(text)

    def _selected_process_dict(self):
        selected = self.proc_view.selectionModel().selectedRows()
        if not selected:
            return None
        idx = selected[0]
        if idx.model() is self.proc_proxy:
            idx = self.proc_proxy.mapToSource(idx)
        if not idx.isValid():
            return None
        return self.proc_model.get(idx.row())

    def _selected_probe_target(self):
        process = self._selected_process_dict()
        if process:
            return process['pid'], process['name']

        text = self.proc_combo.currentText().strip()
        if '(pid' in text:
            try:
                pid = int(text.rsplit('(pid', 1)[-1].rstrip(') '))
            except ValueError:
                return None
            return pid, text.split(' (pid', 1)[0]
        return None

    def _on_probe_mode_changed(self, _index=None):
        mode = self.probe_mode_combo.currentData()
        self.probe_config_stack.setCurrentIndex(0 if mode == 'native' else 1)

    def _update_probe_target(self):
        target = self._selected_probe_target()
        if target:
            profile = self._last_diagnostic_profile
            if profile and profile.pid != target[0]:
                self._last_diagnostic_profile = None
                profile = None
            diagnostic_target = DiagnosticTarget(
                pid=target[0],
                name=target[1],
                architecture=profile.architecture if profile else None,
                pointer_size=profile.pointer_size if profile else None,
                runtime_markers=profile.runtime_markers if profile else (),
            )
            capabilities = []
            for availability in self.diagnostic_providers.availability(
                    diagnostic_target):
                if availability.available:
                    capability_ids = ', '.join(
                        capability.capability_id
                        for capability in availability.capabilities)
                    verification = (
                        ' (declarado; pendiente de verificar al adjuntar)'
                        if not availability.verified else ''
                    )
                    reason = (
                        f' — {availability.reason}'
                        if availability.reason else ''
                    )
                    capabilities.append(
                        f'{availability.provider_id}: {capability_ids}'
                        f'{verification}{reason}')
                else:
                    capabilities.append(
                        f'{availability.provider_id}: {availability.reason}')
            profile_text = (
                f'{profile.architecture} · puntero de {profile.pointer_size} B'
                if profile else 'arquitectura pendiente de conectar'
            )
            markers = (
                ', '.join(profile.runtime_markers) or 'sin marcadores conocidos'
                if profile else 'runtime pendiente de detectar'
            )
            self.probe_target_label.setText(
                f'{target[1]} · PID {target[0]}')
            self.probe_capabilities_label.setText(
                f'Perfil: {profile_text}. Marcadores (heurísticos): {markers}. '
                f'Capacidades: {"; ".join(capabilities)}. '
                'Los marcadores no implican soporte del runtime.')
        else:
            self.probe_target_label.setText(
                'Selecciona una aplicación en la lista de la izquierda.')
            self.probe_capabilities_label.setText(
                'Selecciona un proceso para ver arquitectura, marcadores de '
                'runtime y capacidades declaradas.')
            self._last_diagnostic_profile = None

    def _start_numeric_probe(self):
        if self._probe_busy or self.numeric_probe.is_running:
            return
        target = self._selected_probe_target()
        if target is None:
            self.numeric_probe_status.setText(
                'Primero selecciona una aplicación de la lista de la izquierda.')
            return

        mode = self.probe_mode_combo.currentData()
        if mode == 'native':
            module_name = self.probe_module_edit.text().strip()
            export_name = self.probe_export_edit.text().strip()
            if not module_name or not export_name:
                self.numeric_probe_status.setText(
                    'Completa el módulo y el nombre de la función exportada.')
                return
            config = {
                'mode': 'native',
                'native': {
                    'moduleName': module_name,
                    'exportName': export_name,
                    'argumentIndex': self.probe_native_arg_index.value(),
                    'argumentType': self.probe_native_arg_type.currentData(),
                    'returnType': self.probe_return_type.currentData(),
                },
            }
            bridge_path = None
            script_path = str(self.numeric_probe_path)
        else:
            values = {
                'assemblyName': self.probe_assembly_edit.text().strip(),
                'namespaceName': self.probe_namespace_edit.text().strip(),
                'className': self.probe_class_edit.text().strip(),
                'methodName': self.probe_method_edit.text().strip(),
            }
            if not all(values[key] for key in (
                    'assemblyName', 'className', 'methodName')):
                self.numeric_probe_status.setText(
                    'Completa el ensamblado, espacio de nombres, clase y método.')
                return
            bridge_path = self.probe_bridge_edit.text().strip()
            if not bridge_path:
                self.numeric_probe_status.setText(
                    'Selecciona el bundle JavaScript de frida-il2cpp-bridge.')
                return
            config = {
                'mode': mode,
                'il2cpp': {
                    **values,
                    'argumentCount': self.probe_il2cpp_arg_count.value(),
                    'argumentIndex': self.probe_il2cpp_arg_index.value(),
                    'argumentType': self.probe_il2cpp_arg_type.currentData(),
                    'returnType': self.probe_il2cpp_return_type.currentData(),
                },
            }
            script_path = str(self.numeric_probe_path)

        pid, name = target
        self.observation_history.reset_comparison_baseline()
        self._probe_busy = True
        self.btn_probe_start.setEnabled(False)
        self.btn_probe_stop.setEnabled(False)
        self.numeric_probe_status.setText(f'Conectando con {name}…')

        def work():
            try:
                self.diagnostic_providers.get(
                    FridaFunctionProvider.provider_id).start(
                        DiagnosticTarget(pid=pid, name=name),
                        {
                            'config': config,
                            'script_path': script_path,
                            'bridge_path': bridge_path,
                        },
                        self.sDiagnosticEvent.emit,
                    )
            except Exception as error:
                self.sProbeState.emit('error', str(error))
            else:
                self.sProbeState.emit(
                    'running', f'Sonda activa en {name} · PID {pid}.')

        threading.Thread(target=work, daemon=True).start()

    def _stop_numeric_probe(self):
        if self._probe_busy or not self.numeric_probe.is_running:
            return
        self._probe_busy = True
        self.btn_probe_stop.setEnabled(False)
        self.numeric_probe_status.setText('Deteniendo la sonda…')

        def work():
            try:
                self.numeric_probe.stop()
            except Exception as error:
                self.sProbeState.emit('error', str(error))
            else:
                self.sProbeState.emit('stopped', 'Sonda detenida.')

        threading.Thread(target=work, daemon=True).start()

    @QtCore.Slot(str, str)
    def _handle_numeric_probe_state(self, state, message):
        self._probe_busy = False
        self.numeric_probe_status.setText(message)
        running = state == 'running' or self.numeric_probe.is_running
        self.btn_probe_start.setEnabled(not running)
        self.btn_probe_stop.setEnabled(running)
        if state == 'error':
            self.numeric_probe_log.appendPlainText('[!] ' + message)

    @QtCore.Slot(object)
    def _handle_diagnostic_event(self, event):
        if isinstance(event, DiagnosticProfile):
            self._last_diagnostic_profile = event
            self._update_probe_target()
            return
        if not isinstance(event, DiagnosticObservation):
            self.numeric_probe_log.appendPlainText(
                '[!] Evento de diagnóstico no reconocido: ' + repr(event))
            return

        record = self.observation_history.add(event)
        if (self.probe_history_table.rowCount()
                >= self.observation_history.max_records):
            self.probe_history_table.removeRow(0)
        row = self.probe_history_table.rowCount()
        self.probe_history_table.insertRow(row)
        values_json = json.dumps(record.values, ensure_ascii=False, sort_keys=True)
        display_values = values_json
        if record.changed_values:
            display_values += ' · cambió: ' + ', '.join(record.changed_values)
        cells = (
            datetime.fromtimestamp(record.timestamp).strftime('%H:%M:%S.%f')[:-3],
            record.domain,
            record.subject,
            record.phase,
            display_values,
        )
        for column, value in enumerate(cells):
            self.probe_history_table.setItem(
                row, column, QtWidgets.QTableWidgetItem(value))
        self.probe_history_table.scrollToBottom()

    def _export_probe_history(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 'Exportar historial de diagnóstico',
            'netscope_diagnostics.json', 'JSON (*.json)')
        if not path:
            return
        profile = (
            asdict(self._last_diagnostic_profile)
            if self._last_diagnostic_profile else None
        )
        try:
            saved_path = self.observation_history.export_json(
                path, metadata={'target_profile': profile})
        except OSError as error:
            self.numeric_probe_log.appendPlainText(
                '[!] No se pudo exportar el historial: ' + str(error))
            return
        self.numeric_probe_log.appendPlainText(
            '[i] Historial exportado: ' + saved_path)

    def _clear_probe_history(self):
        self.observation_history.clear()
        self.probe_history_table.setRowCount(0)

    def export_pcapng(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 'Exportar PCAPNG', 'netscope.pcapng', '*.pcapng')
        if not path:
            return
        self._run_async(self.interceptor.export_pcapng, path)

    def export_har(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 'Exportar HAR 1.2', 'netscope.har', 'HAR (*.har);;JSON (*.json)')
        if not path:
            return
        self._run_async(self.interceptor.export_har, path)

    def export_tls_keylog(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 'Exportar claves TLS (SSLKEYLOGFILE)', 'tls_keys.keylog',
            'Keylog (*.keylog *.log *.txt);;Todos (*)')
        if not path:
            return
        self._run_async(self.interceptor.export_tls_keylog, path)

    def launch_demo_app(self):
        demo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'demo_app.py')
        try:
            proc = subprocess.Popen([sys.executable, demo_path])
            self.sLog.emit(f'[i] App Demo propia iniciada (PID {proc.pid}). Pulsa Actualizar si no aparece aún.')
            QtCore.QTimer.singleShot(800, self.refresh_processes)
        except Exception as exc:
            self.sLog.emit(f'[!] No se pudo iniciar App Demo: {exc}')

    def _extract_iocs_ui(self):
        report = self.interceptor.extract_iocs()
        self.ioc_table.setRowCount(len(report.items))
        for row, item in enumerate(report.items):
            vals = (item.kind, item.value, str(item.fd), item.direction, item.confidence, item.context)
            for col, v in enumerate(vals):
                self.ioc_table.setItem(row, col, QtWidgets.QTableWidgetItem(v))
        self.threat_status_lbl.setText(
            f'{len(report.items)} IOCs extraídos · {len(report.stream_hashes)} hashes de payload.')

    def _scan_yara_ui(self):
        custom = self.yara_rules_edit.toPlainText().strip() or None
        try:
            matches = self.interceptor.scan_yara(rules_text=custom, include_builtin=True)
        except Exception as exc:
            self.threat_status_lbl.setText(f'Error en regla YARA: {exc}')
            self.sLog.emit(f'[!] Error YARA: {exc}')
            return
        self.yara_table.setRowCount(len(matches))
        for row, m in enumerate(matches):
            sev = m.meta.get('severity', '')
            tags = ', '.join(m.tags) + (f' ({sev})' if sev else '')
            strs = '; '.join(f'{s.identifier}@{s.offset}: {s.matched_ascii[:32]!r}' for s in m.strings[:3])
            vals = (m.rule, tags, str(m.fd), m.direction, strs)
            for col, v in enumerate(vals):
                self.yara_table.setItem(row, col, QtWidgets.QTableWidgetItem(v))
        self.threat_status_lbl.setText(f'{len(matches)} coincidencias YARA encontradas.')

    def _load_yara_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, 'Cargar archivo de reglas YARA', '', 'YARA (*.yar *.yara);;Todos (*)')
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                self.yara_rules_edit.setPlainText(f.read())
            self.threat_status_lbl.setText(f'Reglas cargadas: {os.path.basename(path)}')
        except OSError as exc:
            self.sLog.emit(f'[!] No se pudo leer el archivo YARA: {exc}')

    def _export_threats_report(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 'Exportar informe IOCs/YARA', 'netscope_threats.json', 'JSON (*.json)')
        if not path:
            return
        report = self.interceptor.extract_iocs()
        custom = self.yara_rules_edit.toPlainText().strip() or None
        matches = self.interceptor.scan_yara(rules_text=custom, include_builtin=True)
        data = {
            'iocs': report.to_dict(),
            'yara_matches': [m.to_dict() for m in matches],
        }
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.threat_status_lbl.setText(f'Informe exportado: {path}')
        except OSError as exc:
            self.sLog.emit(f'[!] No se pudo exportar informe de amenazas: {exc}')

    # -------------------- acciones --------------------
    def refresh_processes(self):
        def work():
            try:
                rows = FridaInterceptor.list_processes()   # [ {pid,name},…]
            except Exception as e:
                rows = []
                self.sLog.emit(f'[!] Error listando procesos: {e}')
            # filas = tuplas (pid, name)
            spooky = []
            for r in rows:
                spooky.append((r['pid'], r['name']))
            self.sProcesses.emit(spooky)
        threading.Thread(target=work, daemon=True).start()

    @QtCore.Slot(object)
    def _set_processes(self, rows):
        self.proc_model.set_rows([{'pid': p, 'name': n} for p, n in rows])
        self.proc_combo.clear()
        for p, n in rows:
            self.proc_combo.addItem(f'{n} (pid {p})')
        self.proc_combo.setCurrentIndex(-1)
        self.proc_combo.setEditText('')
        if rows:
            count = len(rows)
            noun = 'aplicación abierta' if count == 1 else 'aplicaciones abiertas'
            self.process_hint.setText(
                f'{count} {noun}. Haz clic en una para seleccionarla.'
            )
        else:
            self.process_hint.setText(
                'No se encontraron aplicaciones. Abre la que quieres analizar '
                'y pulsa «Actualizar aplicaciones». Si está elevada, inicia '
                'NetScope con permisos suficientes.'
            )
        self._update_quick_target()

    def attach_target(self):
        follow_children = self.follow_children_chk.isChecked()
        if self.spawn_chk.isChecked():
            exe, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, 'Ejecutable a spawnear', '',
                'Ejecutables (*.exe);;Todos (*)')
            if not exe:
                return
            self._attach_in_progress = True
            self._run_async(self.interceptor.attach, None, exe, True, True, follow_children)
        else:
            row = self._selected_process_dict()
            if row:
                pid, name = row['pid'], row['name']
                self.proc_combo.setEditText(f'{name} (pid {pid})')
            else:
                txt = self.proc_combo.currentText().strip()
                if not txt:
                    QtWidgets.QMessageBox.information(
                        self, 'Conectar', 'Selecciona una aplicación de la lista izquierda.')
                    return
                pid = int(txt.rsplit('(pid', 1)[-1].rstrip(') ')) if '(pid' in txt else None
                name = txt.split(' (pid')[0] if '(pid' in txt else txt
            self._attach_in_progress = True
            self._run_async(self.interceptor.attach, pid, name, False, True, follow_children)
        self.btn_stop.setEnabled(True)
        self.btn_attach.setEnabled(False)
        self._set_patch_session_inactive()
        self._reset_value_scan(show_status=False)
        self._update_quick_controls()

    def stop(self):
        self._attach_in_progress = False
        analyze_stopped_capture = self._quick_analysis_running
        self._quick_analysis_timer.stop()
        self._quick_analysis_pending = False
        self._quick_analysis_running = False
        if analyze_stopped_capture:
            self._quick_analysis_processing = True
        self.interceptor.deactivate_capture()
        streams = (
            self.interceptor.snapshot_streams()
            if analyze_stopped_capture else ()
        )
        self.event_queue.clear()
        self._run_async(self.interceptor.stop)
        self.btn_stop.setEnabled(False)
        self.btn_attach.setEnabled(True)
        self._set_patch_session_inactive()
        if analyze_stopped_capture:
            self.quick_countdown.setText('Captura detenida; analizando streams…')
            self.quick_progress.setFormat('Analizando…')
            self._run_async(self._analyze_quick_snapshot, streams)
        else:
            self.quick_countdown.setText('Captura detenida.')
        self._update_quick_controls()

    def _start_quick_analysis(self):
        if self._quick_analysis_pending or self._quick_analysis_running \
                or self._quick_analysis_processing:
            return
        if (not self.spawn_chk.isChecked()
                and not self.proc_view.selectionModel().selectedRows()
                and not self.proc_combo.currentText().strip()):
            self.quick_countdown.setText(
                'Selecciona un proceso en la lista de la izquierda.')
            return

        self._quick_analysis_duration = self.quick_duration.value()
        self._quick_analysis_pending = True
        self._quick_report_text = ''
        self.quick_report_view.clear()
        self.quick_results_table.setRowCount(0)
        self.btn_quick_export.setEnabled(False)
        self.quick_metric_values['streams'].setText('0')
        self.quick_metric_values['tx'].setText('0 B')
        self.quick_metric_values['rx'].setText('0 B')
        self.quick_metric_values['frameworks'].setText('—')
        self.quick_countdown.setText('Adjuntando al proceso…')
        self.quick_progress.setRange(0, self._quick_analysis_duration)
        self.quick_progress.setValue(0)
        self.quick_progress.setFormat('Preparando captura')
        self._update_quick_controls()
        self.attach_target()
        if self.btn_attach.isEnabled():
            self._quick_analysis_pending = False
            self.quick_countdown.setText('Análisis no iniciado.')
            self._update_quick_controls()

    def _begin_quick_capture(self):
        self._quick_analysis_pending = False
        self._quick_analysis_running = True
        self._quick_analysis_remaining = self._quick_analysis_duration
        self.quick_progress.setRange(0, self._quick_analysis_duration)
        self.quick_progress.setValue(0)
        self.quick_progress.setFormat('%p% · capturando')
        self.quick_countdown.setText(
            f'Capturando · quedan {self._quick_analysis_remaining} s')
        self._quick_analysis_timer.start()
        self._update_quick_controls()

    def _tick_quick_analysis(self):
        if not self._quick_analysis_running:
            self._quick_analysis_timer.stop()
            return
        self._quick_analysis_remaining -= 1
        elapsed = (
            self._quick_analysis_duration - self._quick_analysis_remaining
        )
        self.quick_progress.setValue(elapsed)
        self.quick_countdown.setText(
            f'Capturando · quedan {self._quick_analysis_remaining} s')
        if self._quick_analysis_remaining <= 0:
            self.stop()

    def _analyze_quick_snapshot(self, streams):
        results = analyze_game_streams(streams)
        report = format_game_analysis_report(results)
        self.sGameAnalysisReady.emit(results, report)

    @QtCore.Slot(object, str)
    def _on_quick_analysis_ready(self, results, report):
        self._quick_analysis_processing = False
        self._quick_report_text = report
        self.quick_report_view.setPlainText(report)
        self.quick_results_table.setRowCount(len(results))
        for row, result in enumerate(results):
            entropy = (
                f'{result["tx_entropy"]:.2f} / '
                f'{result["rx_entropy"]:.2f}'
            )
            values = (
                result['fd'],
                result['proto'],
                result['peer'],
                result['framework'],
                fmt_bytes(result['tx_bytes']),
                fmt_bytes(result['rx_bytes']),
                result['tx_format'],
                result['rx_format'],
                entropy,
            )
            for column, value in enumerate(values):
                self.quick_results_table.setItem(
                    row, column, QtWidgets.QTableWidgetItem(str(value)))

        self.quick_metric_values['streams'].setText(str(len(results)))
        self.quick_metric_values['tx'].setText(fmt_bytes(
            sum(item['tx_bytes'] for item in results)))
        self.quick_metric_values['rx'].setText(fmt_bytes(
            sum(item['rx_bytes'] for item in results)))
        frameworks = sorted({
            item['framework'] for item in results
            if item['framework'] != 'No detectado'
        })
        self.quick_metric_values['frameworks'].setText(
            ', '.join(frameworks) if frameworks else '—')
        self.quick_progress.setValue(self._quick_analysis_duration)
        self.quick_progress.setFormat('Análisis completado')
        self.quick_countdown.setText(
            f'Listo · {len(results)} streams analizados.')
        self.btn_quick_export.setEnabled(bool(report))
        self._update_quick_controls()

    def _export_quick_report(self):
        if not self._quick_report_text:
            self.quick_countdown.setText('Todavía no hay informe que guardar.')
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 'Guardar informe', 'game_analysis_report.txt',
            'Informe de texto (*.txt)')
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as report_file:
                report_file.write(self._quick_report_text)
        except OSError as exc:
            self.sLog.emit(f'[!] No se pudo guardar el informe: {exc}')
            self.quick_countdown.setText('Error al guardar el informe.')
            return
        self.quick_countdown.setText(f'Informe guardado: {path}')

    def _update_quick_controls(self, *_args):
        busy = (
            self._quick_analysis_pending
            or self._quick_analysis_running
            or self._quick_analysis_processing
        )
        has_target = (
            bool(self.proc_view.selectionModel().selectedRows())
            or bool(self.proc_combo.currentText().strip())
        )
        self.btn_quick_start.setEnabled(
            not busy and self.btn_attach.isEnabled()
            and (self.spawn_chk.isChecked() or has_target))
        self.btn_quick_stop.setEnabled(
            self._quick_analysis_pending or self._quick_analysis_running)
        self.quick_duration.setEnabled(not busy)

    def _update_quick_target(self, *_args):
        process = self._selected_process_dict()
        if process:
            self.quick_target_label.setText(
                f'Paso 1 de 3 · Elegida: {process["name"]} · PID '
                f'{process["pid"]}. Pulsa «Iniciar análisis» para continuar.')
        else:
            name = self.proc_combo.currentText().strip()
            if self.spawn_chk.isChecked():
                self.quick_target_label.setText(
                    'Paso 1 de 3 · Pulsa «Iniciar análisis» y elige el archivo '
                    'de la aplicación que quieres abrir.')
            elif name:
                self.quick_target_label.setText(
                    f'Paso 1 de 3 · Aplicación elegida: {name}. Pulsa '
                    '«Iniciar análisis» para continuar.')
            else:
                self.quick_target_label.setText(
                    'Paso 1 de 3 · Elige una aplicación en la lista de la '
                    'izquierda o escribe su nombre arriba.')
        self._update_probe_target()
        self._update_quick_controls()

    def _add_patch_rule(self):
        if self._patch_busy:
            return
        try:
            match = bytes.fromhex(self.patch_match_input.text())
            replacement = bytes.fromhex(self.patch_replace_input.text())
        except ValueError:
            self.patch_status.setText(
                'La coincidencia y el reemplazo deben ser hexadecimales válidos.')
            return
        if not match:
            self.patch_status.setText('La regla no puede estar vacía.')
            return
        if len(match) != len(replacement):
            self.patch_status.setText(
                'Coincidencia y reemplazo deben tener la misma longitud.')
            return
        if len(self._patch_rules) >= MAX_PATCH_RULES:
            self.patch_status.setText(
                f'Se alcanzó el límite de {MAX_PATCH_RULES} reglas.')
            return

        self._patch_rules.append({
            'hex_match': match.hex(),
            'hex_replace': replacement.hex(),
        })
        self._patch_dirty = True
        self._populate_patch_rules()
        self.patch_match_input.clear()
        self.patch_replace_input.clear()
        self.patch_status.setText(
            'Regla añadida localmente. Pulsa "Aplicar reglas" para actualizar '
            'el proceso adjunto.')
        self._update_patch_controls()

    def _remove_patch_rule(self):
        if self._patch_busy:
            return
        selected = self.patch_rule_table.selectionModel().selectedRows()
        if not selected:
            self.patch_status.setText('Selecciona una regla para quitarla.')
            return
        del self._patch_rules[selected[0].row()]
        self._patch_dirty = True
        self._populate_patch_rules()
        self.patch_status.setText(
            'Regla quitada localmente. Pulsa "Aplicar reglas" para actualizar '
            'el proceso adjunto.')
        self._update_patch_controls()

    def _populate_patch_rules(self):
        self.patch_rule_table.setRowCount(len(self._patch_rules))
        for row, rule in enumerate(self._patch_rules):
            self.patch_rule_table.setItem(
                row, 0,
                QtWidgets.QTableWidgetItem(rule['hex_match'].upper()))
            self.patch_rule_table.setItem(
                row, 1,
                QtWidgets.QTableWidgetItem(rule['hex_replace'].upper()))

    def _update_patch_controls(self):
        busy = self._patch_busy
        selected = bool(
            self.patch_rule_table.selectionModel().selectedRows())
        self.patch_match_input.setEnabled(not busy)
        self.patch_replace_input.setEnabled(not busy)
        self.btn_patch_add.setEnabled(
            not busy and len(self._patch_rules) < MAX_PATCH_RULES)
        self.patch_rule_table.setEnabled(not busy)
        self.btn_patch_remove.setEnabled(not busy and selected)
        self.btn_patch_apply.setEnabled(
            self._patch_ready and self._patch_dirty and not busy)
        self.patch_enable_checkbox.setEnabled(
            self._patch_ready and bool(self._patch_rules)
            and not self._patch_dirty and not busy)

    def _apply_patch_rules(self):
        if not self._patch_ready or self._patch_busy:
            self.patch_status.setText(
                'Adjúntate a un proceso para aplicar las reglas.')
            return
        rules = tuple(dict(rule) for rule in self._patch_rules)
        enabled = self.patch_enable_checkbox.isChecked()
        self._patch_busy = True
        self._update_patch_controls()
        self.patch_status.setText('Aplicando reglas al agente Frida…')
        self._run_async(self._install_patch_rules, rules, enabled)

    def _install_patch_rules(self, rules, enabled):
        self.interceptor.set_rewrite_enabled(False)
        installed = self.interceptor.set_patch_rules(rules)
        if installed != len(rules):
            raise RuntimeError(
                f'Frida instaló {installed} de {len(rules)} reglas')
        active = bool(enabled and rules)
        self.interceptor.set_rewrite_enabled(active)
        self.sPatchConfigured.emit(installed, active)

    @QtCore.Slot(int, bool)
    def _on_patch_configured(self, installed, enabled):
        self._patch_busy = False
        self._patch_ready = self._patch_attached
        active = bool(enabled and self._patch_attached)
        blocker = QtCore.QSignalBlocker(self.patch_enable_checkbox)
        self.patch_enable_checkbox.setChecked(active)
        del blocker
        self._patch_dirty = False
        self.patch_status.setText(
            f'{installed} reglas instaladas; reescritura '
            f'{"activa" if active else "inactiva"}.')
        self._update_patch_controls()

    def _toggle_patch_rewrite(self, enabled):
        if not self._patch_ready or self._patch_busy:
            return
        self._patch_busy = True
        self._update_patch_controls()
        self.patch_status.setText('Actualizando estado de reescritura…')
        self._run_async(
            self._set_patch_rewrite, bool(enabled and self._patch_rules))

    def _set_patch_rewrite(self, enabled):
        self.interceptor.set_rewrite_enabled(enabled)
        self.sPatchToggled.emit(enabled)

    @QtCore.Slot(bool)
    def _on_patch_toggled(self, enabled):
        self._patch_busy = False
        active = bool(enabled and self._patch_attached)
        self._patch_ready = self._patch_attached
        blocker = QtCore.QSignalBlocker(self.patch_enable_checkbox)
        self.patch_enable_checkbox.setChecked(active)
        del blocker
        self.patch_status.setText(
            f'Reescritura {"activa" if active else "inactiva"}.')
        self._update_patch_controls()

    def _set_patch_session_inactive(self):
        self._patch_attached = False
        self._patch_ready = False
        self._patch_busy = False
        blocker = QtCore.QSignalBlocker(self.patch_enable_checkbox)
        self.patch_enable_checkbox.setChecked(False)
        del blocker
        self._update_patch_controls()

    @QtCore.Slot(str)
    def _handle_status(self, text):
        self.statusBar().showMessage(text)
        panel = getattr(self, 'antidebug_panel', None)
        if panel is not None and (text.startswith('Sesión perdida') or text in ('Error', 'Hooks activos')
                                  or text.startswith('Sesión activa')):
            panel.refresh()
        if text == 'Hooks activos':
            self._attach_in_progress = False
            self._patch_attached = True
            self._patch_ready = False
            self._patch_busy = True
            blocker = QtCore.QSignalBlocker(self.patch_enable_checkbox)
            self.patch_enable_checkbox.setChecked(False)
            del blocker
            self._update_patch_controls()
            rules = tuple(dict(rule) for rule in self._patch_rules)
            self.patch_status.setText(
                'Preparando reescritura desactivada para esta sesión…')
            self._run_async(self._install_patch_rules, rules, False)
            if self._quick_analysis_pending:
                self._begin_quick_capture()
            self._update_quick_controls()
        elif text.startswith('Detenido'):
            self._set_patch_session_inactive()
            self._update_quick_controls()
            self._memory_session_ended(text)
        elif text.startswith('Sesión perdida'):
            # El proceso objetivo terminó o Frida se desconectó sin que lo
            # pidiéramos: la sesión ya no es utilizable.
            self._attach_in_progress = False
            self._quick_analysis_pending = False
            self.btn_attach.setEnabled(True)
            self.btn_stop.setEnabled(True)
            self._set_patch_session_inactive()
            self._update_quick_controls()
            self._memory_session_ended(text)
            self.quick_countdown.setText(
                'La sesión con el proceso se perdió; vuelve a hacer attach.')
        elif text == 'Error' and self._attach_in_progress:
            self._attach_in_progress = False
            self._quick_analysis_pending = False
            self.btn_attach.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self._set_patch_session_inactive()
            self._run_async(self.interceptor.stop)
            self.quick_countdown.setText(
                'No se pudo adjuntar al proceso; revisa la pestaña Registro.')
            self._update_quick_controls()
        elif text == 'Error' and self._patch_busy:
            self._set_patch_session_inactive()
            self.patch_status.setText(
                'No se pudo sincronizar la reescritura; revisa Registro.')
        if text == 'Error' and (
                self._quick_analysis_pending
                or self._quick_analysis_processing):
            self._quick_analysis_timer.stop()
            self._quick_analysis_pending = False
            self._quick_analysis_running = False
            self._quick_analysis_processing = False
            self.quick_countdown.setText(
                'El análisis no pudo completarse; revisa Registro.')
            self.quick_progress.setFormat('Error')
            self._update_quick_controls()

    def _scan_initial_value(self):
        value = self.value_scan_input.text().strip()
        if not value:
            self.value_scan_status.setText('Escribe el valor que quieres buscar.')
            return
        samples = self.interceptor.snapshot_scan_events()
        _, _, dropped = self.interceptor.scan_sample_stats()
        try:
            candidates = self.value_scanner.scan(
                samples,
                value,
                self.value_type_combo.currentData(),
                self.byte_order_combo.currentData(),
            )
        except ValueError as exc:
            self.value_scan_status.setText(str(exc))
            return

        self._value_scan_drop_count = dropped
        self.value_type_combo.setEnabled(False)
        self.byte_order_combo.setEnabled(False)
        self.btn_value_scan.setEnabled(False)
        self._populate_value_scan_results(candidates)
        self.value_scan_input.clear()
        self.value_scan_input.setPlaceholderText(
            'Introduce el nuevo valor después de cambiarlo en la aplicación')
        self.btn_value_rescan.setEnabled(bool(candidates))
        retained, _, _ = self.interceptor.scan_sample_stats()
        if candidates:
            status = (
                f'{len(candidates)} candidatos en {retained} payloads '
                'capturados. Cambia el valor en la aplicación y genera '
                'tráfico nuevo antes de filtrar.'
            )
        else:
            status = (
                f'No se encontraron candidatos en {retained} payloads '
                'capturados. Pulsa Reiniciar para probar otro valor, tipo o endian.'
            )
        if self.value_scanner.candidates_truncated:
            status += f' Se alcanzó el límite de {ValueScanner.MAX_CANDIDATES}.'
        if dropped:
            status += f' Historial limitado: {dropped} muestras antiguas descartadas.'
        self.value_scan_status.setText(status)

    def _rescan_value(self):
        value = self.value_scan_input.text().strip()
        if not value:
            self.value_scan_status.setText(
                'Escribe el nuevo valor observado en la aplicación.')
            return
        samples = self.interceptor.snapshot_scan_events()
        _, _, dropped = self.interceptor.scan_sample_stats()
        try:
            candidates = self.value_scanner.rescan(samples, value)
        except ValueError as exc:
            self.value_scan_status.setText(str(exc))
            return
        if not self.value_scanner.last_rescan_sample_count:
            self.value_scan_status.setText(
                'No hay payloads nuevos desde la última búsqueda. '
                'Genera tráfico y vuelve a intentarlo.')
            return

        self._populate_value_scan_results(candidates)
        self.btn_value_rescan.setEnabled(bool(candidates))
        self.value_scan_input.clear()
        newly_dropped = max(0, dropped - self._value_scan_drop_count)
        self._value_scan_drop_count = dropped
        status = (
            f'{len(candidates)} candidatos tras revisar '
            f'{self.value_scanner.last_rescan_sample_count} muestras nuevas.'
        )
        if newly_dropped:
            status += ' Se descartaron muestras por el límite del historial.'
        self.value_scan_status.setText(status)

    def _populate_value_scan_results(self, candidates):
        self.value_scan_table.setRowCount(len(candidates))
        for row, candidate in enumerate(candidates):
            values = (
                candidate.fd,
                candidate.proto,
                candidate.direction,
                candidate.tag or candidate.event,
                f'0x{candidate.offset:X}',
                candidate.value_type,
                candidate.byte_order,
                candidate.current_value,
            )
            for column, value in enumerate(values):
                self.value_scan_table.setItem(
                    row, column, QtWidgets.QTableWidgetItem(str(value)))
        self.value_scan_table.resizeColumnsToContents()

    def _reset_value_scan(self, show_status=True):
        self.value_scanner.reset()
        self.value_scan_table.setRowCount(0)
        self.value_scan_input.clear()
        self.value_scan_input.setPlaceholderText(
            'Valor decimal o hexadecimal (por ejemplo 100 o 0x64)')
        self.value_type_combo.setEnabled(True)
        self.byte_order_combo.setEnabled(True)
        self.btn_value_scan.setEnabled(True)
        self.btn_value_rescan.setEnabled(False)
        self._value_scan_drop_count = 0
        if show_status:
            self.value_scan_status.setText(
                'Búsqueda reiniciada. Solo se consideran payloads capturados '
                'en la captura actual.')

    def _run_async(self, fn, *args):
        def work():
            try:
                fn(*args)
            except Exception as e:
                self.sLog.emit(f'[!] {e}')
                self.sStatus.emit('Error')
        threading.Thread(target=work, daemon=True).start()

    # -------------------- slots de memoria (Fase 2, hilo GUI) --------------------
    def _mem_fill_regions(self, regs: list, total: int):
        t = self.memory_panel.reg_table
        t.setRowCount(0)
        for r in regs:
            row = t.rowCount()
            t.insertRow(row)
            mod = r.owner.name if getattr(r, 'owner', None) else ''
            items = (hex(r.addr), str(r.size), r.protections or '—', mod)
            for col, text in enumerate(items):
                it = QtWidgets.QTableWidgetItem(text)
                if col == 0:
                    it.setData(QtCore.Qt.UserRole, r.addr)
                t.setItem(row, col, it)
        self.memory_panel.lbl_caps.setToolTip(f'{len(regs)} de {total} regiones mostradas')

    def _mem_on_snap(self, which: str, snap):
        self.memory_panel._snapshot_a = snap if which == 'A' else self.memory_panel._snapshot_a
        self.memory_panel._snapshot_b = snap if which == 'B' else self.memory_panel._snapshot_b
        self.memory_panel.snap_lbl.setText(
            f'A: {len(self.memory_panel._snapshot_a.entries) if self.memory_panel._snapshot_a else 0} regiones · '
            f'B: {len(self.memory_panel._snapshot_b.entries) if self.memory_panel._snapshot_b else 0} regiones')

    def _mem_fill_diff(self, changed: list, total: int):
        t = self.memory_panel.diff_table
        t.setRowCount(0)
        for d in changed[:2000]:
            row = t.rowCount()
            t.insertRow(row)
            ident = d.identity
            desc = f'{ident[0]}+{ident[1]:#x}' if ident[1] is not None else str(ident)
            old, new = d.old_data or b'', d.new_data or b''
            resumen = ''
            common = min(len(old), len(new))
            for i in range(common):
                if old[i] != new[i]:
                    resumen = f'{old[i]:02X}→{new[i]:02X} @ +{i:#x}'
                    break
            if not resumen:
                resumen = f'{len(old)} B → {len(new)} B'
            items = (d.kind, desc, str(d.metadata.get('size', '?')), resumen)
            for col, text in enumerate(items):
                t.setItem(row, col, QtWidgets.QTableWidgetItem(text))
        self.memory_panel.snap_lbl.setText(
            f'{len(changed)} cambios · {total} identidades comparadas')

    def _mem_set_text(self, widget, text):
        widget.setPlainText(text)

    def _memory_session_ended(self, reason):
        panel = getattr(self, 'memory_panel', None)
        if panel is None:
            return
        # Los estados llegan por una cola asíncrona: un 'Detenido' del stop()
        # interno de attach() puede llegar con la sesión nueva ya activa.
        if (not reason.startswith('Sesión perdida')
                and self.interceptor.session_state == 'active'):
            return
        panel.on_session_ended(reason)

    def _mem_watch_log(self, text):
        if '@@STARTED@@' in text:
            self.memory_panel.btn_watch.setIcon(get_icon('stop', color='#f87171'))
            self.memory_panel.btn_watch.setText('Detener watch')
            text = text.replace(' @@STARTED@@', '')
        if '@@STOPPED@@' in text:
            self.memory_panel.btn_watch.setIcon(get_icon('play'))
            self.memory_panel.btn_watch.setText('Observar')
            with self.memory_panel._watch_lock:
                self.memory_panel._watcher = None
            text = text.replace(' @@STOPPED@@', '')
        self.memory_panel.watch_out.appendPlainText(text)

    # -------------------- ticks / detalle --------------------
    def _on_tick(self):
        snaps = self.interceptor.snapshot_streams()
        # Filtro localhost: solo streams cuyo peer contiene 127.0.0.1
        if self.localhost_chk.isChecked():
            snaps = [s for s in snaps if '127.0.0.1' in (s.peer or '')]
        if not snaps:
            hint = (
                'El filtro local está activo y no hay conexiones locales.'
                if self.localhost_chk.isChecked() else
                'Inicia un análisis y usa la aplicación; aquí aparecerán sus '
                'conexiones de red.'
            )
        else:
            if len(snaps) == 1:
                hint = (
                    '1 conexión detectada. Selecciónala para ver los datos '
                    'enviados y recibidos.'
                )
            else:
                hint = (
                    f'{len(snaps)} conexiones detectadas. Selecciona una para '
                    'ver los datos enviados y recibidos.'
                )
        if self.stream_hint.text() != hint:
            self.stream_hint.setText(hint)
        self._stream_by_fd = {st.fd: st for st in snaps}
        # Solo resetear el modelo si cambió el número de streams (evita
        # destruir la selección y re-renderizar en cada tick).
        if len(snaps) != len(self.stream_model.rows):
            self.stream_model.set_rows(snaps)
            self._stream_revisions = {
                st.fd: (st.fd, st.proto, st.peer, st.closed, st.byte_out,
                        st.byte_in, st.event_count)
                for st in snaps
            }
        else:
            revisions = {}
            for r, st in enumerate(snaps):
                revision = (st.fd, st.proto, st.peer, st.closed, st.byte_out,
                            st.byte_in, st.event_count)
                revisions[st.fd] = revision
                if self.stream_model.rows[r] is not st or self._stream_revisions.get(st.fd) != revision:
                    self.stream_model.rows[r] = st
                    self.stream_model.dataChanged.emit(
                        self.stream_model.index(r, 0),
                        self.stream_model.index(r, self.stream_model.columnCount() - 1))
            self._stream_revisions = revisions
        self.btn_export_pcap.setEnabled(bool(snaps))
        self.btn_export_har.setEnabled(bool(snaps))
        self.btn_export_keylog.setEnabled(
            bool(snaps) or bool(self.interceptor.snapshot_tls_keylog()))
        if self._detail_fd is not None:
            # Solo re-renderizar si el stream seleccionado cambió de tamaño.
            st = self._get_stream(self._detail_fd)
            if st is not None:
                cache = getattr(self, '_detail_cache', {})
                key = (st.byte_out, st.byte_in, st.closed, st.event_count)
                if cache.get(self._detail_fd) != key:
                    cache[self._detail_fd] = key
                    self._detail_cache = cache
                    self._render_detail(self._detail_fd)
        if self._search_query or self._search_filters:
            self._apply_search(snaps, report=False)

    def _on_stream_sel(self, current, previous):
        if not current.isValid():
            self._detail_fd = None
            self.btn_export.setEnabled(False)
            self.detail_banner_lbl.setText(
                'Selecciona una conexión en «2. Conexiones detectadas» para ver sus datos.')
            return
        st = current.siblingAtColumn(0).data(self.stream_model.KIND_ROLE)
        self._detail_fd = st.fd
        self.btn_export.setEnabled(True)
        self._render_detail(st.fd)

    def _get_stream(self, fd):
        return self._stream_by_fd.get(fd)

    def _render_detail(self, fd):
        st = self._get_stream(fd)
        if st is None:
            return
        state_lbl = 'cerrada' if st.closed else 'activa'
        pid_badge = f' · Proceso PID {st.pid}' if getattr(st, 'pid', None) else ''
        self.detail_banner_lbl.setText(
            f'<b>Conexión #{fd}</b> · {st.proto} · Destino: <b>{st.peer}</b> · '
            f'Estado: {state_lbl} · ↑ {fmt_bytes(st.byte_out)} / ↓ {fmt_bytes(st.byte_in)}{pid_badge}'
        )
        self.out_view.setPlainText(st.out_data.decode('utf-8', 'replace')[-256*1024:] if len(st.out_data) > 256*1024 else st.out_data.decode('utf-8', 'replace'))
        self.in_view.setPlainText(st.in_data.decode('utf-8', 'replace')[-256*1024:] if len(st.in_data) > 256*1024 else st.in_data.decode('utf-8', 'replace'))
        stack_lines = []
        if getattr(st, 'call_stacks', None):
            stack_lines.append('== Atribución de código (Call Stacks) ==')
            for idx, stk in enumerate(st.call_stacks[:5], 1):
                stack_lines.append(f'  #{idx}: ' + ' <- '.join(stk))
            stack_lines.append('')
        pid_txt = f' pid={st.pid}' if getattr(st, 'pid', None) else ''
        host_txt = f' dominio={st.peer_host}' if getattr(st, 'peer_host', None) else ''
        stack_block = '\n'.join(stack_lines)
        self.hex_view.setPlainText(
            f'# fd={fd} ({st.proto}) peer={st.peer}{pid_txt}{host_txt}\n\n'
            f'{stack_block}'
            f'== TX → (enviado, {fmt_bytes(st.byte_out)}) ==\n'
            f'{hexdump(bytes(st.out_data), limit=16*1024)}\n\n'
            f'== RX ← (recibido, {fmt_bytes(st.byte_in)}) ==\n'
            f'{hexdump(bytes(st.in_data), limit=16*1024)}')

        self.http_list.blockSignals(True)
        first = self.http_list.currentRow()
        self.http_list.clear()
        for direction, data in (('TX →', st.out_data), ('RX ←', st.in_data)):
            for m in parse_http_stream(bytes(data)):
                label = f'{direction}  {m["start_line"][:90]}'
                item = QtWidgets.QListWidgetItem(label)
                item.setData(QtCore.Qt.ItemDataRole.UserRole, (direction, m))
                self.http_list.addItem(item)
        if 0 <= first < self.http_list.count():
            self.http_list.setCurrentRow(first)
        self.http_list.blockSignals(False)

    def _on_http_sel(self):
        item = self.http_list.currentItem()
        if not item:
            return
        direction, m = item.data(QtCore.Qt.ItemDataRole.UserRole)
        body = m['body']
        txt = direction + '\n' + m['start_line'] + '\n\n'
        for k, v in m['headers']:
            txt += f'{k}: {v}\n'
        txt += '\n'
        bin_markers = (b'\xff\xd8\xff', b'\x89PNG', b'GIF8', b'%PDF', b'\x1f\x8b')
        if any(body.startswith(mk) for mk in bin_markers):
            self.http_body.setPlainText(
                txt + f'[cuerpo binario, {len(body)} bytes]\n\n{hexdump(body[:4096])}')
        else:
            self.http_body.setPlainText(txt + (body.decode('utf-8', 'replace') or ''))

    # -------------------- búsqueda --------------------
    def _schedule_search(self, _text):
        self._search_timer.start()

    def _add_search_filter(self):
        query = self.search_edit.text().strip()
        if not query:
            return
        try:
            StreamSearchIndex().update([], query)
        except ValueError as exc:
            self.statusBar().showMessage(f'Filtro inválido: {exc}')
            return
        if query.casefold() not in {item.casefold() for item in self._search_filters}:
            self._search_filters.append(query)
            self._refresh_filter_toolbar()
        self.search_edit.clear()
        self._search_timer.stop()
        self._apply_search()

    def _remove_search_filter(self, index):
        if 0 <= index < len(self._search_filters):
            del self._search_filters[index]
            self._refresh_filter_toolbar()
            self._apply_search()

    def _clear_search_filters(self):
        self._search_filters.clear()
        self.search_edit.clear()
        self._search_timer.stop()
        self._refresh_filter_toolbar()
        self._apply_search()

    def _refresh_filter_toolbar(self):
        self.filters_toolbar.clear()
        if not self._search_filters:
            self.filters_toolbar.setVisible(False)
            return
        self.filters_toolbar.setVisible(True)
        self.filters_toolbar.addWidget(QtWidgets.QLabel('Filtros AND:'))
        for index, query in enumerate(self._search_filters):
            action = QAction(f'× {query}', self)
            action.setToolTip(f'Quitar filtro: {query}')
            action.triggered.connect(
                lambda checked=False, i=index: self._remove_search_filter(i))
            self.filters_toolbar.addAction(action)
        clear_action = QAction('Limpiar filtros', self)
        clear_action.triggered.connect(self._clear_search_filters)
        self.filters_toolbar.addAction(clear_action)

    def _apply_search(self, snaps=None, report=True):
        self._search_query = self.search_edit.text().strip()
        if snaps is None:
            snaps = self.interceptor.snapshot_streams()
        if self.localhost_chk.isChecked():
            snaps = [s for s in snaps if '127.0.0.1' in (s.peer or '')]
        criteria = self._search_filters.copy()
        if self._search_query:
            criteria.append(self._search_query)
        hits = []
        try:
            for query in criteria:
                index = self._search_indexes.setdefault(
                    query.casefold(), StreamSearchIndex())
                hits.append(index.update(snaps, query))
        except ValueError as exc:
            self.statusBar().showMessage(f'Filtro inválido: {exc}')
            return
        active = set(criteria)
        self._search_indexes = {
            query: index for query, index in self._search_indexes.items()
            if query in {item.casefold() for item in active}
        }
        self.stream_proxy.set_search(criteria, hits)
        if report:
            matched = self.stream_proxy.rowCount()
            if criteria:
                self.statusBar().showMessage(
                    f'Filtro: {matched} de {len(snaps)} streams coinciden. '
                    'Selecciona una fila para ver TX/RX y HEX.')
            else:
                self.statusBar().showMessage(
                    f'{len(snaps)} streams disponibles.')

    @QtCore.Slot(list)
    def _on_frida_batch(self, batch):
        for kind, payload in batch:
            if kind == 'status':
                self._handle_status(payload)
            elif kind == 'log':
                self.log_view.appendPlainText(payload)

    def closeEvent(self, event):
        if self._probe_busy:
            self.statusBar().showMessage(
                'Espera a que termine la operación de la sonda antes de cerrar.')
            event.ignore()
            return
        self._quick_analysis_timer.stop()
        self._timer.stop()
        try:
            self.numeric_probe.stop()
        except Exception as error:
            QtWidgets.QMessageBox.warning(
                self, 'Sonda numérica',
                'No se pudo cerrar limpiamente la sonda: ' + str(error))
        self.interceptor.stop()
        self._frida_worker.stop()
        self._frida_thread.quit()
        self._frida_thread.wait(3000)
        super().closeEvent(event)

    def export_stream(self):
        if self._detail_fd is None:
            return
        st = self._get_stream(self._detail_fd)
        if not st:
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 'Exportar stream', f'fd{st.fd}_{st.proto}.bin', '*.bin')
        if not path:
            return
        with open(path, 'wb') as f:
            f.write(b'--NETSCOPE stream fd=%d proto=%s peer=%s\n' % (
                st.fd, st.proto.encode(), st.peer.encode()))
            f.write(b'-- TX ==' + b'\n')
            f.write(bytes(st.out_data))
            f.write(b'\n-- RX ==\n')
            f.write(bytes(st.in_data))
        self.sLog.emit(f'[i] Stream fd={st.fd} exportado a {path}')
