# -*- coding: utf-8 -*-
"""Modelo del motor de diagnóstico anti-debug / protecciones.

Tres niveles de veredicto, con criterios explícitos:

  CONFIRMED   Hay una medición directa, falsable y reproducible de ESE mecanismo
              (p. ej. PAGE_GUARD visto con VirtualQueryEx en la tabla de
              exportación, una API anti-debug observada devolviendo "depurado",
              bytes de una función distintos de los del fichero en disco,
              una mitigación de Windows activa, código de salida de fast-fail).
  INDICATION  Compatible con el mecanismo pero NO exclusivo: imports de APIs
              anti-debug, terminación poco después de un paso de instrumentación,
              artefactos que el objetivo podría ver. No prueba que el objetivo
              los use.
  UNKNOWN     No se puede atribuir una causa. Un fallo de attach, un cuelgue o
              una sesión perdida SIN correlación NUNCA se presentan como
              anti-debug: se informa como desconocido y se enumeran las
              causas posibles.

Además `kind` separa QUÉ se afirma:
  protection   un mecanismo presente en el objetivo
  footprint    huella que deja NUESTRA instrumentación (lo que el objetivo podría ver)
  environment  política de Windows (PPL, elevación, mitigaciones, EAF configurado)
  failure      resultado de una operación (attach, sesión, agente)
"""
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Verdict(str, Enum):
    CONFIRMED = 'confirmed'
    INDICATION = 'indication'
    UNKNOWN = 'unknown'


class Kind(str, Enum):
    PROTECTION = 'protection'
    FOOTPRINT = 'footprint'
    ENVIRONMENT = 'environment'
    FAILURE = 'failure'


@dataclass
class Evidence:
    kind: str                       # 'windows-api' | 'frida' | 'static' | 'session' | 'registry' | 'powershell'
    detail: str
    source: str = ''                # función/API/script que la produjo
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    mechanism: str
    kind: Kind
    verdict: Verdict
    summary: str
    evidence: List[Evidence] = field(default_factory=list)
    detected_at: float = field(default_factory=time.time)
    t_since_attach: Optional[float] = None
    session_effect: str = 'ninguno'
    memory_ops_affected: List[str] = field(default_factory=list)
    agents_affected: List[str] = field(default_factory=list)       # 'memory' | 'network'
    can_continue: Optional[bool] = None
    can_continue_note: str = ''
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'mechanism': self.mechanism, 'kind': self.kind.value, 'verdict': self.verdict.value,
            'summary': self.summary,
            'evidence': [{'kind': e.kind, 'detail': e.detail, 'source': e.source, 'data': e.data}
                         for e in self.evidence],
            'detected_at': self.detected_at, 't_since_attach': self.t_since_attach,
            'session_effect': self.session_effect,
            'memory_ops_affected': list(self.memory_ops_affected),
            'agents_affected': list(self.agents_affected),
            'can_continue': self.can_continue, 'can_continue_note': self.can_continue_note,
            'limitations': list(self.limitations),
        }


@dataclass
class DiagnosticReport:
    pid: Optional[int]
    target: str = ''
    created: float = field(default_factory=time.time)
    findings: List[Finding] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    def by_verdict(self, v: Verdict) -> List[Finding]:
        return [f for f in self.findings if f.verdict == v]

    def find(self, mechanism_prefix: str) -> List[Finding]:
        return [f for f in self.findings if f.mechanism.startswith(mechanism_prefix)]

    def to_dict(self) -> Dict[str, Any]:
        return {'pid': self.pid, 'target': self.target, 'created': self.created,
                'findings': [f.to_dict() for f in self.findings], 'timeline': self.timeline}

    def render_text(self) -> str:
        sym = {Verdict.CONFIRMED: 'CONFIRMADO', Verdict.INDICATION: 'INDICIO',
               Verdict.UNKNOWN: 'DESCONOCIDO'}
        lines = [f'Diagnóstico de protecciones — {self.target or "?"} (pid {self.pid})', '']
        if not self.findings:
            lines.append('Sin hallazgos: no se observó ningún mecanismo de protección.')
        for f in self.findings:
            lines.append(f'[{sym[f.verdict]}] ({f.kind.value}) {f.mechanism}')
            lines.append(f'    {f.summary}')
            for e in f.evidence:
                lines.append(f'    - evidencia [{e.kind}]: {e.detail}')
            when = (f'+{f.t_since_attach:.2f}s desde el attach' if f.t_since_attach is not None
                    else time.strftime('%H:%M:%S', time.localtime(f.detected_at)))
            lines.append(f'    momento: {when}')
            lines.append(f'    efecto sobre la sesión: {f.session_effect}')
            if f.memory_ops_affected:
                lines.append(f'    operaciones de memoria afectadas: {", ".join(f.memory_ops_affected)}')
            if f.agents_affected:
                lines.append(f'    agentes afectados: {", ".join(f.agents_affected)}')
            cont = {True: 'sí', False: 'no', None: 'no determinado'}[f.can_continue]
            lines.append(f'    ¿se puede continuar el análisis?: {cont}'
                         + (f' — {f.can_continue_note}' if f.can_continue_note else ''))
            for lim in f.limitations:
                lines.append(f'    limitación: {lim}')
            lines.append('')
        return '\n'.join(lines)
