# -*- coding: utf-8 -*-
"""Genera docs/FASE3_RESULTS.md a partir de results/matrix.json (datos medidos)."""
import json
import os
import statistics
import time
from collections import Counter, defaultdict

AGENTS = ('memory', 'network', 'both')


def _cell(r):
    if r is None:
        return '—'
    o = r['outcome']
    t = r.get('t_attach_s')
    tt = f' {t:.2f}s' if t is not None else ''
    if o == 'ok':
        extra = []
        if r.get('lab_detects'):
            extra.append('detecta')
        if r.get('network_agent_errors'):
            extra.append('hooks con errores')
        return 'ok' + tt + (' (' + ', '.join(extra) + ')' if extra else '')
    return {'session_lost': 'sesión perdida', 'attach_blocked': 'attach evitado', 'attach_timeout': 'attach colgado',
            'attach_failed': 'attach falló', 'launch_failed': 'no arranca', 'skipped': 'omitido',
            'agent_failed': 'agente falló', 'netscope_crashed': 'NETSCOPE CAYÓ',
            'harness_timeout': 'TIMEOUT', 'harness_error': 'error arnés'}.get(o, o) + (tt if o != 'skipped' else '')


def _med(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.median(xs), 2) if xs else None


def build_markdown(json_path, md_path):
    data = json.load(open(json_path, encoding='utf-8'))
    L = []
    w = L.append
    w('# Fase 3 — Resultados medidos de la matriz de protecciones')
    w('')
    w(f'_Generado automáticamente por `tests/protection_lab/run_matrix.py --report` el '
      f'{time.strftime("%Y-%m-%d %H:%M")} a partir de `{os.path.basename(json_path)}` ({len(data)} casos)._')
    w('')
    w('Cada caso = escenario × arquitectura (x64/x86) × agentes (**memoria**: solo `memory.js`, sin hooks; '
      '**red**: solo `agent.js`; **ambos**) × modo (attach/spawn). Cada caso corre en un proceso Python '
      'propio. Los tiempos son de esta máquina y orientativos.')
    w('')
    oc = Counter(r['outcome'] for r in data)
    w('## 1. Resumen de resultados')
    w('')
    w('| Resultado | Casos |')
    w('|---|---|')
    for k, v in sorted(oc.items(), key=lambda kv: -kv[1]):
        w(f'| {k} | {v} |')
    crash = [r for r in data if r['outcome'] in ('netscope_crashed', 'harness_error', 'harness_timeout')]
    unexp = [r for r in data if r.get('unexpected')]
    w('')
    w(f'- **NetScope**: {len(crash)} caídas/errores del arnés, {len(unexp)} casos con excepciones no normalizadas '
      '(fuera de `MemoryError`/`SessionError`).')
    bad_integ = [r for r in data if r.get('mem') and r['mem'].get('integ_bad')]
    bad_scalar = [r for r in data if r.get('mem') and r['mem'].get('scalar_bad')]
    chg = [r for r in data if r.get('prot_changed')]
    w(f'- **Integridad de lecturas**: {sum(r["mem"]["integ_n"] for r in data if r.get("mem"))} lecturas de 64 KB '
      f'comparadas con el patrón, {len(bad_integ)} casos con discrepancias; escalares incorrectos en {len(bad_scalar)} casos.')
    w(f'- **Cambios involuntarios de protecciones** (VirtualQuery antes/después): {len(chg)} casos.')
    w('')

    # ---------- por escenario ----------
    for mode in ('attach', 'spawn'):
        rows = [r for r in data if r['mode'] == mode]
        if not rows:
            continue
        w(f'## 2{"a" if mode == "attach" else "b"}. Resultado por escenario — modo {mode}')
        w('')
        for arch in sorted({r['arch'] for r in rows}):
            w(f'### {arch}')
            w('')
            w('| Escenario | Agente de memoria | Agente de red | Ambos | Objetivo vivo (mem/red/ambos) | Detecciones del objetivo |')
            w('|---|---|---|---|---|---|')
            by = defaultdict(dict)
            for r in rows:
                if r['arch'] == arch:
                    by[r['scenario']][r['agents']] = r
            for sid, d in by.items():
                alive = '/'.join({True: 'sí', False: 'no', None: '—'}[d.get(a, {}).get('target_alive')] for a in AGENTS)
                det = sorted({m for a in AGENTS for m in (d.get(a, {}).get('lab_detects') or [])})
                w(f'| {sid} | {_cell(d.get("memory"))} | {_cell(d.get("network"))} | {_cell(d.get("both"))} | {alive} | {", ".join(det) or "—"} |')
            w('')

    # ---------- latencias ----------
    w('## 3. Rendimiento medido (mediana sobre casos con sesión estable)')
    w('')
    w('| Agentes | attach (s) | carga agente memoria (s) | lectura 64 KB (ms) | escritura+rollback (ms) | casos |')
    w('|---|---|---|---|---|---|')
    for a in AGENTS:
        rs = [r for r in data if r['agents'] == a and r['outcome'] == 'ok' and r['mode'] == 'attach']
        w(f'| {a} | {_med([r.get("t_attach_s") for r in rs])} | {_med([r.get("t_memory_load_s") for r in rs])} | '
          f'{_med([r["mem"]["lat_read"] for r in rs if r.get("mem")])} | '
          f'{_med([r["mem"]["lat_write"] for r in rs if r.get("mem")])} | {len(rs)} |')
    sp = [r for r in data if r['mode'] == 'spawn' and r['outcome'] == 'ok']
    if sp:
        w('')
        w(f'Spawn (objetivo suspendido, instrumentación antes del primer código): attach mediana '
          f'{_med([r.get("t_attach_s") for r in sp])} s, spawn→ready {_med([r.get("t_resume_to_ready_s") for r in sp])} s.')
    w('')

    # ---------- red + memoria simultáneas ----------
    w('## 4. Funcionamiento simultáneo memoria + red')
    w('')
    both = [r for r in data if r['agents'] == 'both' and r['outcome'] == 'ok' and r.get('mem')]
    ok_both = [r for r in both if r['mem']['ops'] > 0 and (r.get('net_ping_seen') or 0) > 0]
    w(f'- Casos “ambos” con sesión estable: {len(both)}; con operaciones de memoria **y** tráfico de red capturado a la vez: '
      f'{len(ok_both)}.')
    cap = [(r.get('net_ping_seen'), (r.get('lab_status') or {}).get('net_sent')) for r in ok_both]
    if cap:
        w(f'- Mensajes del objetivo observados por el agente de red durante el trabajo de memoria: mediana '
          f'{_med([c[0] for c in cap])} (el objetivo envió {_med([c[1] for c in cap])}).')
    w('')

    # ---------- verdad de terreno vs diagnóstico ----------
    w('## 5. Verdad de terreno del objetivo vs diagnóstico de NetScope')
    w('')
    w('| Escenario | Arq | Agentes | Qué hizo el objetivo | Hallazgos de NetScope (mecanismo: veredicto) |')
    w('|---|---|---|---|---|')
    for r in data:
        if r['mode'] != 'attach' or not (r.get('lab_detects') or r.get('lab_terminating') or r['outcome'] in
                                         ('session_lost', 'attach_blocked', 'attach_timeout')):
            continue
        what = []
        if r.get('lab_detects'):
            what.append('detectó: ' + ', '.join(r['lab_detects']))
        if r.get('lab_terminating'):
            what.append('terminó: ' + r['lab_terminating'])
        if r.get('exit_code'):
            what.append('código ' + r['exit_code'])
        if not what:
            what.append(r['outcome'])
        fnd = '; '.join(f'{m}: {v}' for m, v in r.get('findings', []))
        w(f'| {r["scenario"]} | {r["arch"]} | {r["agents"]} | {"; ".join(what)} | {fnd or "—"} |')
    w('')

    # ---------- mitigaciones ----------
    w('## 6. Mitigaciones de Windows (agentes por separado)')
    w('')
    w('| Mitigación | Arq | Memoria | Red | ¿Hooks de red con errores? | Ping capturados (red/ambos) |')
    w('|---|---|---|---|---|---|')
    by = defaultdict(dict)
    for r in data:
        if r['scenario'].startswith('mit_') and r['mode'] == 'attach':
            by[(r['scenario'], r['arch'])][r['agents']] = r
    for (sid, arch), d in by.items():
        net = d.get('network') or {}
        both_ = d.get('both') or {}
        w(f'| {sid} | {arch} | {_cell(d.get("memory"))} | {_cell(d.get("network"))} | '
          f'{net.get("network_agent_errors")} | {net.get("net_ping_seen")}/{both_.get("net_ping_seen")} |')
    w('')

    # ---------- notas ----------
    w('## 7. Anomalías y notas por caso')
    w('')
    seen = set()
    for r in data:
        for n in r.get('notes', []) + r.get('unexpected', []):
            key = (r['scenario'], r['agents'], n[:60])
            if key in seen:
                continue
            seen.add(key)
            w(f'- `{r["scenario"]}` {r["arch"]}/{r["agents"]}/{r["mode"]}: {n}')
    w('')
    text = '\n'.join(L)
    if md_path:
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(text)
    return text
