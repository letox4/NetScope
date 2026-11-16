# -*- coding: utf-8 -*-
"""Test end-to-end del interceptor: spawnea un dummy (HTTP+UDP loopback),
se le engancha con Frida y valida el reensamblado de streams."""
import os
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core.interceptor import FridaInterceptor


def test_interceptor_end_to_end():
    target = subprocess.Popen([sys.executable,
                               os.path.join(BASE, 'tests', 'dummy_target.py')])
    ic = FridaInterceptor(
        on_event=lambda ev: None,
        on_status=lambda s: print('[status]', s),
        on_log=lambda s: print('[log]', s),
    )
    ok_tcp = ok_udp = False
    try:
        time.sleep(0.15)
        ic.attach(pid=target.pid)

        deadline = time.time() + 12
        while time.time() < deadline:
            for st in ic.snapshot_streams():
                out, inn = bytes(st.out_data), bytes(st.in_data)
                if st.proto == 'TCP' and b'GET / HTTP/1.1' in out and b'NetScope OK' in inn:
                    ok_tcp = True
                if st.proto == 'UDP' and (b'UDP-PEEK-NETSCOPE' in out or b'UDP-PEEK-NETSCOPE' in inn):
                    ok_udp = True
            if ok_tcp and ok_udp:
                break
            time.sleep(0.3)

        assert ok_tcp, 'No se reensambló tráfico HTTP TCP'
        assert ok_udp, 'No se capturó datagrama UDP'
    finally:
        ic.stop()
        if target.poll() is None:
            target.terminate()
            target.wait(timeout=5)


if __name__ == '__main__':
    test_interceptor_end_to_end()
    print('INTERCEPTOR TEST OK')
