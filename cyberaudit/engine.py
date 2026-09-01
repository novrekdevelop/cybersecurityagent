"""Audit orchestrator: orchestrates modules, context and results."""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Type

from .config import AppConfig
from .http_client import HttpClient, HttpResponse
from .models import AuditResult, Finding, Severity
from .modules.base import AuditModule
from .utils import err, info, normalize_url, ok, warn

# Module registry
from .modules.apis import ApisModule
from .modules.auth import AuthModule
from .modules.cms import CmsModule
from .modules.content import ContentModule
from .modules.cves import CvesModule
from .modules.directories import DirectoriesModule
from .modules.emailsec import EmailsecModule
from .modules.fuzer import FuzzerModule
from .modules.headers import HeadersModule
from .modules.injection import InjectionModule
from .modules.osint import OsintModule
from .modules.payments import PaymentsModule
from .modules.ports import PortsModule
from .modules.recon import ReconModule
from .modules.tls import TLSModule

MODULES: List[Type[AuditModule]] = [
    ReconModule, OsintModule, EmailsecModule, TLSModule, HeadersModule,
    ContentModule, CmsModule, InjectionModule, DirectoriesModule, PortsModule,
    ApisModule, AuthModule, PaymentsModule, FuzzerModule, CvesModule,
]
@dataclass
class AuditContext:
    """Shared by all modules: HTTP, assets, findings and log."""

    target: str
    config: AppConfig
    http: HttpClient
    base: HttpResponse
    assets: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    def add_finding(self, **kwargs) -> Finding:
        from .models import Severity
        from .utils import cprint
        module = kwargs.pop("module", "general")
        title = kwargs.pop("title", "Finding without title")
        description = kwargs.pop("description", "")
        severity = kwargs.pop("severity", Severity.INFO)
        url = kwargs.pop("url", self.target)
        cwe = kwargs.pop("cwe", "CWE-0")
        owasp = kwargs.pop("owasp", "")
        evidence = kwargs.pop("evidence", "")
        remediation = kwargs.pop("remediation", "")
        f = Finding(title=title, description=description, severity=severity,
                    module=module, url=url, cwe=cwe, owasp=owasp,
                    evidence=evidence, remediation=remediation, details=kwargs)
        self.findings.append(f)
        color = severity.color
        bold = severity in (Severity.HIGH, Severity.CRITICAL)
        cprint(f"  [{severity.label.upper():>10}] {f.title}", color, bold=bold)
        return f

    def log(self, message: str, color: str = "\033[96m") -> None:
        from .utils import cprint
        cprint(message, color)


def run_audit(target: str, config: AppConfig) -> AuditResult:
    """Runs the full audit and returns the result with reports."""
    url = normalize_url(target)
    result = AuditResult(target=url)
    result.meta.update({
        "user_agent": config.user_agent,
        "timeout": config.timeout,
        "concurrency": config.concurrency,
        "active_checks": config.active_checks,
        "proxy": config.proxy,
    })

    http = HttpClient(config)
    info("Initial request to " + url)
    base = http.get(url)
    if not base.status and base.error:
        err(f"Could not connect: {base.error}")
        result.meta["error"] = base.error
        result.finalize()
        return result
    if base.status >= 400 and not config.active_checks:
        warn(f"The target responded with HTTP status {base.status} ({base.reason}).")

    ctx = AuditContext(target=url, config=config, http=http, base=base)
    ctx.assets["target"] = url
    ctx.assets["final_url"] = base.url or url
    ctx.assets["http_status"] = base.status
    ctx.assets["headers"] = dict(base.headers)
    ctx.assets["dns"] = {}
    ctx.assets["subdomains"] = []
    ctx.assets["tech"] = []
    ctx.assets["pages"] = []
    ctx.assets["ports"] = []
    ctx.assets["cookies_analyzed"] = []

    info(f"Target accessible · {len(base.body)} bytes · status {base.status}")

    requested = set(config.module_include) or {m.name for m in MODULES}
    excluded = set(config.module_exclude)
    for cls in MODULES:
        if requested is not None and cls.name not in requested:
            continue
        if cls.name in excluded:
            continue
        if not getattr(config, f"run_{cls.name}", True):
            continue

        start = time.monotonic()
        info(f"Phase [{cls.name}] — {cls.description}")
        try:
            cls(ctx).run()
        except Exception as exc:
            err(f"Module '{cls.name}' failed: {exc}")
            if config.active_checks:
                warn(traceback.format_exc(limit=4))
        elapsed = time.monotonic() - start
        ok(f"{cls.name} completed in {elapsed:.2f}s")

    result.findings = ctx.findings
    result.assets = ctx.assets
    result.finalize()

    info(f"Findings: {sum(result.summary.values())} · Risk score: {result.risk_score}/100")
    return result