"""Deep discovery and analysis of APIs (REST/GraphQL).

- Extracts endpoints from JS code and pages.
- Probes common API paths (/api, /v1, /actuator, /graphql…).
- Queries the Wayback Machine for historical same-origin endpoints.
- Detects APIs that respond WITHOUT authentication, sensitive data,
  verbose errors, GraphQL introspection and open CORS.
All requests are benign (GET except the introspection query,
which is read-only). Active probes are limited to --active.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Set, Tuple
from urllib import request as http_request
from urllib.parse import urljoin, urlparse

from ..models import Severity
from ..utils import ERROR_PATTERNS, info, origin_of, same_origin, warn
from .base import AuditModule

# Patterns to extract URLs/endpoints from JavaScriptand HTML
JS_URL_PATTERNS = [
    re.compile(r"""(?:fetch|axios|XMLHttpRequest|\.ajax|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["']([^"'\s]{3,})["']""", re.I),
    re.compile(r"""["']((?:https?:)?//[^"'\s/][^"'\s]{3,})["']"""),
    re.compile(r"""["'](/[A-Za-z0-9_\-./]{3,})["']"""),
]
WS_PATTERN = re.compile(r"""wss?://[^"'\s]+""")

# Common API paths to probe
API_WORDLIST = [
    "api", "api/", "api/v1/", "api/v2/", "api/v3/", "v1/", "v2/", "v3/",
    "rest/", "rest/v1/", "graphql", "graphiql", "swagger", "swagger-ui.html",
    "swagger-ui/", "swagger/", "openapi.json", "v2/api-docs", "api-docs/",
    "actuator", "actuator/env", "actuator/health", "actuator/beans",
    "actuator/mappings", "api/health", "health", "healthz", "ping",
    "api/version", "version", "api/config", "config.json", "config",
    "api/users", "api/user", "users", "me", "api/me", "api/profile",
    "api/admin", "admin/api", "api/login", "login", "api/auth/", "oauth/token",
    "api/token", "token", "api/orders", "orders", "api/checkout", "checkout",
    "api/payment", "api/cart", "cart", "api/products", "products",
    "api/search", "search", "api/status", "status", "api/log", "api/logs",
    ".env", "env", "db", "api/db", "api/secret", "api/keys",
]

GRAPHQL_INTROSPECTION = ('{"query":"{ __schema { queryType { name } '
                         'types { name fields { name } } } }"}')

SENSITIVE_BODY_MARKERS = [
    '"password"', '"passwd"', '"token"', '"secret"', '"api_key"', '"apikey"',
    '"private_key"', '"client_secret"', '"access_token"', '"refresh_token"',
    '"authorization"', 'BEGIN RSA', 'BEGIN OPENSSH', '"credit_card"', '"cvv"',
    '"pan"', '"db_password"', '"AWS_SECRET', '"aws_secret', '"users"',
]

NO_AUTH_PATHS = re.compile(
    r"(users|user|admin|config|settings|orders|checkout|payment|cart|"
    r"me|profile|token|secret|keys|log|logs|debug|monitor|env|info|db|"
    r"internal|backup|members|accounts|clients)", re.I)

# -------PART2-------


def _extract_candidates(text: str) -> Set[str]:
    """Returns endpoint candidates(URLsand paths) from a JS/HTML text."""
    out: Set[str] = set()
    for pat in JS_URL_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1).strip().rstrip(",;")
            if not val or len(val) < 3:
                continue
            low = val.lower()
            if low in ("true", "false", "null", "undefined", "self", "this"):
                continue
            if low.startswith(("javascript:", "data:", "mailto:", "tel:")):
                continue
            out.add(val)
    for m in WS_PATTERN.finditer(text):
        out.add(m.group(0))
    return out


class ApisModule(AuditModule):
    name = "apis"
    description = "API discovery, unauthenticated endpoints and GraphQL"

    def run(self):
        base_url = self.ctx.base.url or self.ctx.target
        origin = origin_of(base_url)
        if not origin:
            return
        info("Looking for APIs and endpoints…")

        # 1) Extract from JS + HTML
        texts = list(self.assets.get("_bodies", {}).values())
        api_candidates: Set[str] = set()
        for rec in self.assets.get("js_analyzed", []):
            texts.append(rec.get("content", ""))
        for t in texts[:100]:
            for cand in _extract_candidates(t):
                api_candidates.add(cand)
        self.assets["api_candidates_found"] = sorted(api_candidates)[:200]

        # 1b) Historical endpoints via Wayback Machine (passive deep-dive)
        for up in self._wayback_urls(origin):
            api_candidates.add(up)

        # 2) Fuzzing common API paths
        probes = set()
        for p in API_WORDLIST:
            probes.add(urljoin(origin + "/", p))
        # Relative endpoints extracted from code (same origin)
        for up in api_candidates:
            up_t = urljoin(origin + "/", up) if up.startswith("/") else (
                urljoin(base_url, up) if up.startswith("http") else up)
            if up_t.startswith(origin) or same_origin(up_t, base_url):
                path = urlparse(up_t).path
                if path.count("/") <= 4:
                    probes.add(up_t)

        discovered: List[Dict] = []
        # Parallel (bounded) probes so as not to slow down the audit
        from concurrent.futures import ThreadPoolExecutor, as_completed
        probes_all = sorted(probes)[:140]

        def _probe(url: str):
            resp = self.ctx.http.get(url)
            is_json = ("json" in resp.header("content-type").lower()
                       or resp.text.lstrip().startswith(("{", "[")))
            if resp.status in (200,) and is_json:
                return {"url": url, "status": resp.status,
                        "ctype": resp.header("content-type"),
                        "size": len(resp.body), "snippet": resp.text[:300]}
            if resp.status in (301, 302, 307, 308) and is_json:
                return {"url": url, "status": resp.status, "ctype": "redirect-json",
                        "size": 0, "snippet": resp.header("location")[:160]}
            return None

        workers = min(self.ctx.config.concurrency, 16)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_probe, u) for u in probes_all]
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                except Exception:
                    r = None
                if r:
                    discovered.append(r)
        discovered.sort(key=lambda x: x["url"])
        self.assets["apis"] = discovered

        # 3) Analysis of the discovered endpoints
        if discovered:
            self.log(f"{len(discovered)} JSON/API responses discovered.")
        self._analyze_endpoints(discovered, origin, base_url)
        self._graphql_probe(origin)

    # ------------------------------------------------------------------ analysis
    def _analyze_endpoints(self, discovered, origin, base_url):
        registered_nofun = False
        for ep in discovered[:40]:
            url = ep["url"]
            text = ep.get("snippet", "")
            if ep.get("status") != 200:
                continue
            # Sensitive data in the response
            hit = next((m for m in SENSITIVE_BODY_MARKERS if m in text), "")
            if hit:
                self.register(
                    title="The API exposes potentially sensitive data",
                    description="The endpoint returns fields of type "
                                "credential, token, key or user listing without "
                                "visible authentication.",
                    severity=Severity.HIGH, cwe="CWE-200", owasp="A01:2021",
                    url=url, evidence=f"Body includes: {hit} … {text[:200]}",
                    remediation="Apply authentication/authorization to the endpoint and filter "
                                "sensitive fields from responses.")
                continue
            # Exposed actuator / config
            if "actuator" in url or url.endswith(("/config", "/env", "/api/config")):
                self.register(
                    title="Exposed actuator/configuration endpoint",
                    description=("Spring Actuator or a configuration endpoint returns "
                                 "the application state, libraries, versions and "
                                 "possible keys."),
                    severity=Severity.HIGH, cwe="CWE-200", owasp="A05:2021", url=url,
                    evidence=text[:300],
                    remediation="Protect the actuator endpoints or restrict them with auth.")
            # Sensitive endpoint without authentication
            path = urlparse(url).path
            if NO_AUTH_PATHS.search(path) and not registered_nofun:
                self.register(
                    title="API endpoint responds without authentication",
                    description=f"'{path}' returns HTTP 200 with JSON data without an "
                                "authentication challenge. If it contains user, order or "
                                "admin data, it allows operating without login or abusing the business.",
                    severity=Severity.HIGH, cwe="CWE-306", owasp="A01:2021", url=url,
                    evidence=f"GET {url} -> {ep.get('status')} · {ep.get('ctype')}",
                    remediation="Require authentication and per-endpoint authorization; use "
                                "server-side session, never request IDs.")
                registered_nofun = True
# Verbose errors on any API endpoint
        for ep in discovered[:40]:
            text = (ep.get("snippet", "") or "")[:4000]
            for pat, label in ERROR_PATTERNS:
                if pat.search(text):
                    self.register(
                        title="The API returns detailed errors",
                        description="The endpoint leaks traces/exceptions that reveal internal "
                                    "stack, queries or server paths.",
                        severity=Severity.MEDIUM, cwe="CWE-209", owasp="A05:2021",
                        url=ep["url"], evidence=text[:300],
                        remediation="Return generic error messages and log the "
                                    "detail in internal logs.")
                    break

        # CORS on APIs (benign probe with Origin header)
        if self.ctx.config.active_checks and discovered:
            test_url = discovered[0]["url"]
            resp = self.ctx.http.get(test_url, headers={
                "Origin": "https://attacker.example.com"})
            acao = resp.header("access-control-allow-origin")
            if acao and "attacker.example.com" in acao:
                self.register(
                    title="Open/reflected CORS on API endpoint",
                    description="The API reflects any origin in Access-Control-Allow-"
                                "Origin; an attacker can read responses from their site.",
                    severity=Severity.HIGH, cwe="CWE-942", owasp="A01:2021",
                    url=test_url, evidence=f"ACAO: {acao}",
                    remediation="Validate the origin against an allowlist.")

    # ------------------------------------------------------------------ graphql
    def _graphql_probe(self, origin):
        if not self.ctx.config.active_checks:
            return
        for url in (origin + "/graphql", origin + "/graphiql"):
            resp = self.ctx.http.get(url)
            if resp.status != 200 or "json" not in resp.header("content-type").lower():
                continue
            r2 = self.ctx.http.post(url, data=GRAPHQL_INTROSPECTION.encode(),
                                    headers={"Content-Type": "application/json"})
            if r2.status == 200 and "__schema" in r2.text:
                self.register(
                    title="GraphQL introspection enabled",
                    description="The GraphQL endpoint accepts the schema query, which "
                                "exposes all types, fields and mutations of the API.",
                    severity=Severity.HIGH, cwe="CWE-200", owasp="A01:2021", url=url,
                    evidence="__schema query returns 200 with 'types'.",
                    remediation="Disable introspection in production.")

    # ------------------------------------------------------------------ wayback
    def _wayback_urls(self, origin) -> List[str]:
        """Historical URLs from the same origin (public archive), max 80."""
        host = urlparse(origin).netloc
        cdx = (f"https://web.archive.org/cdx/search/cdx?"
               f"url={host}/*&output=json&fl=original&collapse=urlkey&limit=80")
        try:
            req = http_request.Request(cdx, headers={"User-Agent": "CyberAuditPro/2.0"})
            with http_request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            out = []
            for row in data[1:]:
                u = (row[0] if isinstance(row, list) else row)
                if u.startswith(origin) and urlparse(u).path.count("/") <= 3:
                    out.append(u)
            return out
        except Exception:
            return []