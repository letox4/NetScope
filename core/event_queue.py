# -*- coding: utf-8 -*-
"""Cola segura para estados y logs entre Frida y el hilo GUI de PySide6.

Los streams se actualizan bajo el lock del interceptor; volver a alimentar
eventos desde esta cola duplicaría los bytes capturados. Los estados y logs sí
se encolan, y un QThread los entrega al hilo principal para actualizar Qt.

La cola tiene tope (maxsize) y descarta silenciosamente cuando se satura, para
que una ráfaga extrema nunca bloquee el proceso monitorizado.
"""
import queue

from PySide6 import QtCore


class EventQueue:
    def __init__(self, maxsize=200000):
        self._q = queue.Queue(maxsize=maxsize)

    def put_event(self, ev):
        try:
            self._q.put_nowait(('event', ev))
        except queue.Full:
            pass

    def put_status(self, text):
        try:
            self._q.put_nowait(('status', str(text)))
        except queue.Full:
            pass

    def put_log(self, text):
        try:
            self._q.put_nowait(('log', str(text)))
        except queue.Full:
            pass

    def get_batch(self, timeout=0.05, max_items=512):
        batch = []
        try:
            batch.append(self._q.get(timeout=timeout))
        except queue.Empty:
            return batch
        while len(batch) < max_items:
            try:
                batch.append(self._q.get_nowait())
            except queue.Empty:
                break
        return batch

    def clear(self):
        while True:
            try:
                self._q.get_nowait()
            except queue.Empty:
                return


class FridaEventWorker(QtCore.QObject):
    """Se mueve a un QThread; drena la cola y emite lotes al hilo principal."""
    batch_ready = QtCore.Signal(list)

    def __init__(self, q: EventQueue):
        super().__init__()
        self._q = q
        self._running = True

    def run(self):
        while self._running:
            batch = self._q.get_batch(timeout=0.05, max_items=512)
            if batch:
                self.batch_ready.emit(batch)

    def stop(self):
        self._running = False
