"""Base module for all analysis plugins."""

from __future__ import annotations

from typing import Any, Dict


class AuditModule:
    """Base class. Each module inspects an area of the attack surface.

    The context (ctx) exposes:
      - ctx.http:       HttpClient
      - ctx.config:     AppConfig
      - ctx.target:     normalized target URL
      - ctx.origin:     origin (scheme+host+port)
      - ctx.base:       HttpResponse of the initial request
      - ctx.assets:     dict accumulator of discovered assets
      - ctx.findings:   list to register findings
      - ctx.add_finding(): creates and adds a Finding
      - ctx.log(message, color): console output
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