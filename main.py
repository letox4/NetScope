# -*- coding: utf-8 -*-
"""NetScope · punto de entrada (GUI o CLI).

Uso GUI:  py -3.11 main.py
Uso CLI:  py -3.11 main.py ps | capture | scan | demo
"""
import sys
import ctypes


def _boost_priority():
    try:
        # HIGH_PRIORITY_CLASS: mejor respuesta de la GUI sin saturar CPU
        ctypes.windll.kernel32.SetPriorityClass(
            ctypes.windll.kernel32.GetCurrentProcess(), 0x00000080)
    except Exception:
        pass


_CLI_COMMANDS = {'ps', 'list-procs', 'capture', 'scan', 'demo', '-h', '--help', '--cli'}


def main():
    argv = sys.argv[1:]
    if argv and argv[0] in _CLI_COMMANDS:
        cli_args = argv[1:] if argv[0] == '--cli' else argv
        from cli import main as cli_main
        sys.exit(cli_main(cli_args))

    _boost_priority()
    try:
        import frida  # noqa: F401
    except ImportError:
        print('Falta "frida". Instala con:\n    py -3.11 -m pip install -r requirements.txt')
        return 1
    try:
        from PySide6 import QtWidgets
    except ImportError:
        print('Falta "PySide6". Instala con:\n    py -3.11 -m pip install -r requirements.txt')
        return 1

    from ui.icons import app_icon, pick_ui_font
    from ui.main_window import NetScopeGUI

    app = QtWidgets.QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setFont(pick_ui_font(10))
    app.setWindowIcon(app_icon())
    win = NetScopeGUI()
    win.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
