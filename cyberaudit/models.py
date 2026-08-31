"""Modelos de datos del framework de auditoría."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

SEVERITY_COLORS = {
    "info": "\033[96m",
    "low": "\033[92m",
    "medium": "\033[93m",
    "high": "\033[91m",
    "critical": "\033[95m",
}


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {"info": 0, "low": 1, "medium": 4, "high": 7, "critical": 10}[self.value]

    @property
    def label(self) -> str:
        return {
            "info": "Informativo",
            "low": "Bajo",
            "medium": "Medio",
            "high": "Alto",
            "critical": "Crítico",
        }[self.value]

    @property
    def color(self) -> str:
        return SEVERITY_COLORS[self.value]


@dataclass
class Finding:
    """Un hallazgo de seguridad detectado durante la auditoría."""

    title: str
    description: str
    severity: Severity
    module: str = "general"
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    url: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "module": self.module,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "url": self.url,
            "details": self.details,
            "impacto_economico": self.economic_range(),
        }

    def economic_range(self) -> Dict[str, int]:
        """Rango de impacto económico estimado (EUR) para priorizar remediación."""
        base = {
            "critical": (120_000, 300_000),
            "high": (15_000, 80_000),
            "medium": (1_200, 15_000),
            "low": (150, 1_500),
            "info": (0, 0),
        }
        lo, hi = base.get(self.severity.value, (0, 0))
        mult = 1.0
        if self.module == "payments":
            mult = 3.0
        elif self.module == "apis":
            mult = 2.0
        elif self.module == "fuzzer" and self.severity.value == "critical":
            mult = 2.5
        return {"min_eur": int(lo * mult), "max_eur": int(hi * mult)}


@dataclass
class AuditResult:
    """Resultado global de la auditoría."""

    target: str
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    assets: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, int] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> None:
        self.end_time = time.time()
        self.summary = {s.value: sum(1 for f in self.findings if f.severity.value == s.value) for s in Severity}

    @property
    def duration(self) -> float:
        end = self.end_time or time.time()
        return round(end - self.start_time, 2)

    @property
    def risk_score(self) -> float:
        """Puntaje de riesgo 0–100 (100 = peor)."""
        total = sum(f.severity.score for f in self.findings)
        if total >= 200:
            return 100.0
        if total >= 100:
            return min(100.0, 55.0 + (total - 100) * 0.55)
        return round(min(100.0, total), 1)

    @property
    def grade(self) -> str:
        s = self.risk_score
        if s >= 60:
            return "Riesgo CRÍTICO — se requiere intervención inmediata"
        if s >= 40:
            return "Riesgo ALTO — se recomienda corrección urgente"
        if s >= 18:
            return "Riesgo MEDIO — vulnerabilidades reales a priorizar"
        if s >= 5:
            return "Riesgo BAJO — hardening recomendado"
        return "Superficie amplia — pocos riesgos detectados"