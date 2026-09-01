"""Injection detection: error leaks, points of interestand benign reflection.

Reflection tests use a harmless markerand ONLY run with --active.
"""

from __future__ import annotations

import re
from html import unescape
from typing import List, Set, Tuple
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunparse

from ..models import Severity
from ..utils import ERROR_PATTERNS, warn
from .base import AuditModule

PARAMS_INTEREST = re.compile(
    r"^(id|file|page|cmd|exec|download|path|dir|doc|template|load|include|redir|"
    r"url|next|return|action|q|search|query|cat)(\d*|_id)?$", re.I)
MARKER = "auditxmark72345zz"


def _split_query(query: str) -> List[Tuple[str, str]]:
    return parse_qsl(query, keep_blank_values=True)


def _inject_param(url: str, key: str, payload: str) -> str:
    parsed = urlparse(url)
    params = [(k, payload) if k == key else (k, v) for k, v in _split_query(parsed.query)]
    new_query = urlencode(params)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                       new_query, parsed.fragment))


class InjectionModule(AuditModule):
    name = "injection"
    description = "Passive injection detectionand points of interest"

    def run(self):
        self._seen: Set[str] = set()
        pages = self.assets.get("pages_analyzed", [])
        bodies = self.assets.get("_bodies", {})

        self._scan_errors(pages, bodies)
        self._scan_params(pages)
        if self.ctx.config.active_checks:
            self._reflect_tests(pages)

    # ------------------------------------------------------------------ helpers
    def _dedupe(self, key: str) -> bool:
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    # ------PART2-------

    def _scan_errors(self, pages, bodies):
        error_pages: dict = {}
        for page in pages:
            body = bodies.get(page["url"], "")
            for pat, label in ERROR_PATTERNS:
                if pat.search(body):
                    error_pages.setdefault(label, page["url"])
                    break
        for label, url in error_pages.items():
            if self._dedupe("err:" + label):
                self.register(
                    title=f"Possible database error leak: {label}",
                    description="La aplicación devuelve información interna (errores SQL, "
                                "trazas, modo debug) útil para identificar vulnerabilidades "
                                "de inyección o detallar la infraestructura.",
                    severity=Severity.MEDIUM, cwe="CWE-209", owasp="A05:2021", url=url,
                    evidence=f"Patrón detectado: {label}",
                    remediation="Disable error detailsin productionand use custom "
                                "error pages.")

    def _scan_params(self, pages):
        params_seen = 0
        for page in pages:
            parsed = urlparse(page["url"])
            if not parsed.query:
                continue
            for key, val in _split_query(parsed.query):
                key_u = unquote(key)
                if PARAMS_INTEREST.match(key_u):
                    params_seen += 1
                    if self._dedupe("param:" + key_u):
                        self.register(
                            title=f"Potentially interesting parameter: '{key_u}'",
                            description="Parameters like id/page/file/url usually feed "
                                        "SQL queries, paths or redirects; mishandling "
                                        "them is the basis for SQLi, path traversal or open "
                                        "redirect.",
                            severity=Severity.INFO, cwe="CWE-20", owasp="A03:2021",
                            url=page["url"],
                            evidence=f'"{key_u}={val}" en {page["url"]}',
                            remediation="Parameterize queries, validate paths with an allowlistand "
                                        "redirects against an origin whitelist.")
                        break
            if params_seen >= 25:
                break
        self.assets["params_interest"] = params_seen

    def _reflect_tests(self, pages):
        warn("Pruebas de reflexión benignas habilitadas (--active).")
        hits = 0
        for page in pages:
            parsed = urlparse(page["url"])
            if not parsed.query:
                continue
            params = _split_query(parsed.query)
            for key in sorted({k for k, _ in params}):
                if hits >= 8:
                    return
                if not PARAMS_INTEREST.match(unquote(key)):
                    continue
                test_url = _inject_param(page["url"], key, "x" + MARKER + "\"'<>")
                resp = self.ctx.http.get(test_url)
                if resp.body and MARKER in resp.text:
                    if self._dedupe("reflect:" + key):
                        hits += 1
                        self.register(
                            title=f"Possible unescaped reflection in '{key}'",
                            description="The benign marker was reflected in the response without "
                                        "encoding, indicating a likely reflected XSS "
                                        "(no real payload was sent).",
                            severity=Severity.HIGH, cwe="CWE-79", owasp="A03:2021",
                            url=test_url,
                            evidence=f"Marker reflected {resp.text.count(MARKER)} time(s).",
                            remediation="Encode output according to contextand apply strict CSP.")