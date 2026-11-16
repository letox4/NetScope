# -*- coding: utf-8 -*-
"""Test hooks Schannel (EncryptMessage/DecryptMessage)."""
import os
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core.interceptor import FridaInterceptor

PS_SCRIPT = r'''
Start-Sleep -Milliseconds 1200
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
for ($i=0; $i -lt 5; $i++) {
  try { Invoke-WebRequest -Uri 'https://example.org/' -UseBasicParsing -TimeoutSec 8 | Out-Null }
  catch { }
  Start-Sleep -Milliseconds 400
}
'''


def test_schannel_tls_capture():
    counts = {'tls_out': 0, 'tls_in': 0, 'hook_error': 0, 'otros': 0}
    errs = []

    def on_event(ev):
        key = ev.event if ev.event in counts else 'otros'
        counts[key] = counts.get(key, 0) + 1
        if ev.event == 'hook_error':
            errs.append(ev.tag)

    child = subprocess.Popen(['powershell', '-NoProfile', '-Command', PS_SCRIPT],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ic = FridaInterceptor(
        on_event=on_event,
        on_status=lambda s: None,
        on_log=lambda s: None,
    )
    try:
        time.sleep(0.8)
        ic.attach(pid=child.pid)
        deadline = time.time() + 15
        while time.time() < deadline and child.poll() is None:
            if counts['tls_out'] >= 1:
                break
            time.sleep(0.2)
        time.sleep(0.5)
        assert counts['tls_out'] >= 1, f'Sin eventos tls_out: {counts}'
        assert counts['hook_error'] == 0, f'hook_error detectados: {errs}'
    finally:
        ic.stop()
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=5)


if __name__ == '__main__':
    test_schannel_tls_capture()
    print('TLS HOOKS OK')
