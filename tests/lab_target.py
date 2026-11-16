# -*- coding: utf-8 -*-
"""Proceso de laboratorio PROPIO para las pruebas de estabilidad de memoria.

Crea páginas con permisos conocidos y responde a comandos por stdin:
  free   libera la región `freeme` (64 KB)      ro / rw  cambia permisos de `flip`
  query  imprime protecciones reales (VirtualQuery) de las páginas de prueba
  exit   termina el proceso (os._exit)
Al arrancar imprime una línea JSON con las direcciones (todas dentro de este
proceso; nada de terceros).
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import sys

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.VirtualAlloc.restype = ctypes.c_void_p
k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD]
k.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wt.DWORD]
k.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wt.DWORD,
                             ctypes.POINTER(wt.DWORD)]


class MBI(ctypes.Structure):
    _fields_ = [('Base', ctypes.c_void_p), ('AllocBase', ctypes.c_void_p),
                ('AllocProt', wt.DWORD), ('Part', wt.WORD),
                ('Region', ctypes.c_size_t), ('State', wt.DWORD),
                ('Protect', wt.DWORD), ('Type', wt.DWORD)]


k.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
COMMIT_RESERVE = 0x3000
RW, RO, GUARD = 0x04, 0x02, 0x100
P = 4096
old = wt.DWORD()

two = k.VirtualAlloc(None, 2 * P, COMMIT_RESERVE, RW)       # página1 RW | página2 RO
k.VirtualProtect(two + P, P, RO, ctypes.byref(old))
ctypes.memmove(two, b'A' * P, P)
freeme = k.VirtualAlloc(None, 16 * P, COMMIT_RESERVE, RW)    # se libera bajo demanda
ctypes.memmove(freeme, b'FREEME-DATA', 11)
flip = k.VirtualAlloc(None, P, COMMIT_RESERVE, RW)           # RW -> RO bajo demanda
ctypes.memmove(flip, b'FLIP-DATA', 9)
guard = k.VirtualAlloc(None, P, COMMIT_RESERVE, RW)          # PAGE_GUARD
k.VirtualProtect(guard, P, RW | GUARD, ctypes.byref(old))
tail = k.VirtualAlloc(None, P, COMMIT_RESERVE, RW)           # escalares
ctypes.memmove(tail, bytes.fromhex('78563412efbeadde') + b'cstr-ok\x00', 16)
# página RW seguida de una página GUARD: lecturas que "cruzan" hacia la guard
edge = k.VirtualAlloc(None, 2 * P, COMMIT_RESERVE, RW)
k.VirtualProtect(edge + P, P, RW | GUARD, ctypes.byref(old))
ctypes.memmove(edge + P - 8, b'EDGE-END', 8)


def prot(a):
    m = MBI()
    k.VirtualQuery(a, ctypes.byref(m), ctypes.sizeof(m))
    return [m.Protect, m.State]


print(json.dumps({'two': two, 'freeme': freeme, 'flip': flip, 'guard': guard,
                  'tail': tail, 'edge': edge, 'pid': os.getpid(),
                  'bits': ctypes.sizeof(ctypes.c_void_p) * 8}), flush=True)
for line in sys.stdin:
    c = line.strip()
    if c == 'free':
        print('freed', bool(k.VirtualFree(freeme, 0, 0x8000)), flush=True)
    elif c == 'ro':
        print('ro', bool(k.VirtualProtect(flip, P, RO, ctypes.byref(old))), flush=True)
    elif c == 'rw':
        print('rw', bool(k.VirtualProtect(flip, P, RW, ctypes.byref(old))), flush=True)
    elif c == 'query':
        print(json.dumps({'guard': prot(guard), 'edge_guard': prot(edge + P),
                          'two1': prot(two), 'two2': prot(two + P),
                          'two_tail': ctypes.string_at(two + P - 4, 4).hex(),
                          'flip': prot(flip),
                          'flip_data': ctypes.string_at(flip, 9).decode()}),
              flush=True)
    elif c == 'exit':
        os._exit(0)
