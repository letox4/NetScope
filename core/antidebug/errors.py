# -*- coding: utf-8 -*-
"""Errores de attach del subsistema de diagnóstico."""


class AttachBlockedError(RuntimeError):
    """El preflight detectó una condición en la que intentar el attach se
    colgaría (p. ej. guardas armadas sobre la tabla de exportación). No es una
    afirmación de anti-debug: lleva el informe con la evidencia."""

    def __init__(self, message: str, report=None):
        super().__init__(message)
        self.report = report


class AttachTimeoutError(TimeoutError):
    """frida.attach no respondió en el tiempo límite."""

    def __init__(self, message: str, seconds: float, report=None):
        super().__init__(message)
        self.seconds = seconds
        self.report = report
