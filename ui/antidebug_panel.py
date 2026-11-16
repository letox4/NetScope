# -*- coding: utf-8 -*-
"""Pestaña "Protecciones": diagnóstico claro del comportamiento de la app objetivo.

Muestra los hallazgos con su nivel de certeza (confirmado / indicio / desconocido),
evidencia y efecto sobre la sesión. Es puramente informativo (solo observabilidad).
"""
import threading

from PySide6 import QtCore, QtWidgets

from ui.icons import get_icon


class AntiDebugPanel(QtWidgets.QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        lay = QtWidgets.QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)

        intro = QtWidgets.QLabel(
            '<b>Diagnóstico de estabilidad y protecciones</b><br>'
            '<span style="color:#94a3b8;">Te explica de forma clara por qué un programa '
            'bloqueó la conexión o se cerró, sin aplicar técnicas de evasión.</span>'
        )
        intro.setWordWrap(True)
        lay.addWidget(intro)

        row = QtWidgets.QHBoxLayout()
        self.btn_refresh = QtWidgets.QPushButton(get_icon('refresh'), ' Actualizar diagnóstico')
        self.btn_footprint = QtWidgets.QPushButton(get_icon('search'), ' Ver huella de hooks')
        self.btn_imports = QtWidgets.QPushButton(get_icon('package'), ' Ver librerías importadas')
        self.btn_observe = QtWidgets.QPushButton(get_icon('clock'), ' Observar llamadas (5 s)')
        for b in (self.btn_refresh, self.btn_footprint, self.btn_imports, self.btn_observe):
            b.setIconSize(QtCore.QSize(15, 15))
        self.btn_observe.setToolTip(
            'Observa durante 5 segundos si la app consulta APIs de diagnóstico '
            '(IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess).'
        )
        for b in (self.btn_refresh, self.btn_footprint, self.btn_imports, self.btn_observe):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)

        self.out = main._make_text()
        lay.addWidget(self.out, 1)

        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_footprint.clicked.connect(lambda: self._run(self._footprint))
        self.btn_imports.clicked.connect(lambda: self._run(self._imports))
        self.btn_observe.clicked.connect(lambda: self._run(self._observe))
        self.refresh()

    def refresh(self):
        rep = self.main.interceptor.diagnostics.report()
        self.out.setPlainText(
            rep.render_text() if rep.findings else
            'Todo limpio por ahora.\n\n'
            'Cuando conectes con una aplicación, aquí verás automáticamente si hubo '
            'bloqueos de acceso, protecciones de memoria o cierres inesperados.'
        )

    def _run(self, fn):
        def work():
            try:
                fn()
            except Exception as e:      # noqa: BLE001
                self.main.sLog.emit(f'[!] Diagnóstico: {e}')
            self.main.sDiagRefresh.emit()
        threading.Thread(target=work, daemon=True).start()

    def _engine(self):
        return self.main.interceptor.memory_engine()

    def _footprint(self):
        ic = self.main.interceptor
        eng = self._engine()
        ic.diagnostics.scan_footprint(
            lambda a, n: eng.read_range(a, n),
            eng.backend._modules(),
            wow64=eng.backend.pointer_size == 4,
            pid=ic.diagnostics.pid,
        )

    def _imports(self):
        from core.antidebug.probe import ProbeSession
        ic = self.main.interceptor
        probe = ProbeSession(ic._session)
        try:
            ic.diagnostics.scan_static_imports(probe.scan_imports)
        finally:
            probe.close()

    def _observe(self):
        import time
        from core.antidebug.probe import ProbeSession
        ic = self.main.interceptor
        probe = ProbeSession(ic._session)
        try:
            probe.observe()
            time.sleep(5.0)
            ic.diagnostics.ingest_api_observations(probe.collect())
        finally:
            probe.close()
