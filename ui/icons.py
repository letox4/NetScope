# -*- coding: utf-8 -*-
"""NetScope UI — Carga de assets SVG vectoriales y helpers de tipografía."""
from pathlib import Path
from typing import Dict, Optional, Tuple

from PySide6 import QtCore, QtGui, QtSvg, QtWidgets

ASSETS_DIR = Path(__file__).resolve().parent / 'assets'
ICONS_DIR = ASSETS_DIR / 'icons'
LOGO_PATH = ASSETS_DIR / 'netscope_logo.svg'

UI_FONT_CANDIDATES = ('Bahnschrift', 'Segoe UI')
MONO_FONT_CANDIDATES = ('Cascadia Code', 'Cascadia Mono', 'Ubuntu Mono', 'Consolas')

_PIXMAP_CACHE: Dict[Tuple[str, str, int], QtGui.QPixmap] = {}
_ICON_CACHE: Dict[Tuple[str, str, str, int], QtGui.QIcon] = {}
_APP_ICON: Optional[QtGui.QIcon] = None


def pick_ui_font(point_size: int = 10, bold: bool = False) -> QtGui.QFont:
    """Devuelve la tipografía principal de NetScope con fallback seguro."""
    available = set(QtGui.QFontDatabase.families())
    family = next((f for f in UI_FONT_CANDIDATES if f in available), UI_FONT_CANDIDATES[-1])
    font = QtGui.QFont(family, point_size)
    if bold:
        font.setWeight(QtGui.QFont.Weight.DemiBold)
    return font


def pick_mono_font(point_size: int = 9) -> QtGui.QFont:
    """Devuelve la tipografía monoespaciada moderna para hex, código y logs."""
    available = set(QtGui.QFontDatabase.families())
    family = next((f for f in MONO_FONT_CANDIDATES if f in available), MONO_FONT_CANDIDATES[-1])
    font = QtGui.QFont(family, point_size)
    font.setStyleHint(QtGui.QFont.StyleHint.Monospace)
    return font


def _render_svg_bytes(svg_bytes: bytes, size: int = 16) -> QtGui.QPixmap:
    dpr = 2
    px = QtGui.QPixmap(size * dpr, size * dpr)
    px.fill(QtCore.Qt.GlobalColor.transparent)
    renderer = QtSvg.QSvgRenderer(QtCore.QByteArray(svg_bytes))
    if renderer.isValid():
        painter = QtGui.QPainter(px)
        renderer.render(painter, QtCore.QRectF(0, 0, size * dpr, size * dpr))
        painter.end()
    px.setDevicePixelRatio(dpr)
    return px


def get_pixmap(name: str, color: str = '#cbd5e1', size: int = 16) -> QtGui.QPixmap:
    """Renderiza un SVG de ``ui/assets/icons`` tintado a ``color``."""
    key = (name, color, size)
    cached = _PIXMAP_CACHE.get(key)
    if cached is not None:
        return cached
    path = ICONS_DIR / f'{name}.svg'
    if not path.is_file():
        return QtGui.QPixmap()
    svg_text = path.read_text(encoding='utf-8').replace('currentColor', color)
    px = _render_svg_bytes(svg_text.encode('utf-8'), size=size)
    _PIXMAP_CACHE[key] = px
    return px


def get_icon(
    name: str,
    color: str = '#cbd5e1',
    active_color: str = '#38bdf8',
    disabled_color: str = '#475569',
    size: int = 16,
) -> QtGui.QIcon:
    """Construye un ``QIcon`` con estados Normal, Selected/Active y Disabled."""
    key = (name, color, active_color, size)
    cached = _ICON_CACHE.get(key)
    if cached is not None:
        return cached

    icon = QtGui.QIcon()
    normal_px = get_pixmap(name, color=color, size=size)
    active_px = get_pixmap(name, color=active_color, size=size)
    disabled_px = get_pixmap(name, color=disabled_color, size=size)

    icon.addPixmap(normal_px, QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
    icon.addPixmap(active_px, QtGui.QIcon.Mode.Active, QtGui.QIcon.State.Off)
    icon.addPixmap(active_px, QtGui.QIcon.Mode.Selected, QtGui.QIcon.State.On)
    icon.addPixmap(active_px, QtGui.QIcon.Mode.Selected, QtGui.QIcon.State.Off)
    icon.addPixmap(disabled_px, QtGui.QIcon.Mode.Disabled, QtGui.QIcon.State.Off)

    _ICON_CACHE[key] = icon
    return icon


def logo_pixmap(size: int = 36) -> QtGui.QPixmap:
    """Renderiza el logotipo vectorial de NetScope."""
    key = ('__logo__', '', size)
    cached = _PIXMAP_CACHE.get(key)
    if cached is not None:
        return cached
    if not LOGO_PATH.is_file():
        return QtGui.QPixmap()
    px = _render_svg_bytes(LOGO_PATH.read_bytes(), size=size)
    _PIXMAP_CACHE[key] = px
    return px


def app_icon() -> QtGui.QIcon:
    """Icono multi-resolución de ventana a partir de ``netscope_logo.svg``."""
    global _APP_ICON
    if _APP_ICON is not None:
        return _APP_ICON
    icon = QtGui.QIcon()
    for sz in (16, 24, 32, 48, 64):
        px = logo_pixmap(sz)
        if not px.isNull():
            icon.addPixmap(px)
    _APP_ICON = icon
    return icon


def icon_heading(name: str, title: str, *, color: str = '#38bdf8', size: int = 16) -> QtWidgets.QWidget:
    """Cabecera horizontal con icono SVG + QLabel con estilo ``sectionTitle``."""
    wrap = QtWidgets.QWidget()
    lay = QtWidgets.QHBoxLayout(wrap)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(7)
    glyph = QtWidgets.QLabel()
    glyph.setPixmap(get_pixmap(name, color=color, size=size))
    glyph.setFixedSize(size + 2, size + 2)
    lbl = QtWidgets.QLabel(title)
    lbl.setObjectName('sectionTitle')
    lay.addWidget(glyph)
    lay.addWidget(lbl)
    return wrap
