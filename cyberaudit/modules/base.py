"""Módulo base para todos los plugins de análisis."""

from __future__ import annotations

from typing import Any, Dict


class AuditModule:
    """Clase base. Cada módulo inspecciona un área de la superficie de ataque.

    El contexto (ctx) expone:
      - ctx.http:       HttpClient
      - ctx.config:     AppConfig
      - ctx.target:     URL objetivo normalizada
      - ctx.origin:     origen (esquema+host+puerto)
      - ctx.base:       HttpResponse de la petición inicial
      - ctx.assets:     dict acumulador de activos descubiertos
      - ctx.findings:   lista para registrar hallazgos
      - ctx.add_finding(): crea y añade un Finding
      - ctx.log(mensaje, color): salida de consola
    """

    name: str = "base"
    description: str = ""

    def __init__(self, ctx: Any):
        self.ctx = ctx
        self.assets = ctx.assets
        self.findings = ctx.findings

    def run(self) -> None:
        raise NotImplementedError

    def log(self, message: str, color: str = "\033[0m") -> None:
        self.ctx.log(f"[{self.name}] {message}", color)

    def register(self, **kwargs: Dict[str, Any]) -> None:
        self.ctx.add_finding(module=self.name, **kwargs)