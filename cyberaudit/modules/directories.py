"""Enumeration of sensitive paths and files with wordlist + threads."""

from __future__ import annotations

import concurrent.futures as cf
import re
from typing import Dict, List, Set
from urllib.parse import urlparse

from ..models import Severity
from ..utils import load_wordlist, ok, info, warn
from .base import AuditModule

# Severity patterns per path
CRITICAL_PATHS = re.compile(
    r"\.git/|/\.env($|\.)|actuator/en(v|v/|v$)|wp-config\.php(\.bak|~|\.old)?$|"
    r"\.htpasswd$|phpinfo\.php$|adminer\.php$|\.sql$|\.dump$|backup\.zip$"
    r"|databases\.sql$|db\.sql$|dump\.sql$", re.I)
HIGH_PATHS = re.compile(
    r"\.gitignore$|\.hg/|\.svn/|config\.php(\.bak|~|old)?$|\.htaccess$|web\.config$|"
    r"composer\.(json|lock)$|package\.json$|\.bak$|\.tar\.gz$|\.zip$|\.gz$|"
    r"debug\.log$|error\.log$|access\.log$|\.log$|phpinfo|info\.php$|"
    r"swagger|openapi|api-docs|actuator($|/)|crossdomain\.xml$", re.I)
MEDIUM_PATHS = re.compile(
    r"(wp-admin|wp-login|administrator|admin\.php|panel|dashboard|backend|backoffice|"
    r"phpmyadmin|pma|adminer|cpanel|plesk|test\.php|demo\.php|status|health|"
    r"server-status|server-info|xmlrpc\.php|cgi-bin|upload\.php)", re.I)
INFO_PATHS = re.compile(r"robots\.txt|sitemap\.xml|security\.txt")

BLOCKED = {401, 403}


class DirectoriesModule(AuditModule):
    name = "directories"
    description = "Enumeration of directories and sensitive files"

    def run(self):
        cfg = self.ctx.config
        base = self.ctx.base.url or self.ctx.target
        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}"
        wordlist = load_wordlist(cfg.directory_wordlist)[:cfg.directory_max_requests]
        self.assets["dirs"] = []
        self.assets["robots"] = ""

        info(f"Probing {len(wordlist)} paths (same host)…")
        base_body = self.ctx.base.text

        # Can be slow for >150 paths; we run with a thread pool
        with cf.ThreadPoolExecutor(max_workers=min(cfg.concurrency, 16)) as pool:
            futures = {pool.submit(self._probe, base, p): p for p in wordlist}
            results = []
            for fut in cf.as_completed(futures):
                res = fut.result()
                if res:
                    results.append(res)

        results.sort(key=lambda r: (r["path"],))
        notable = [r for r in results if r["status"] not in (404,)]
        self.assets["dirs"] = notable

        for r in notable:
            found = r["status"] in (200, 201, 202, 204, 301, 302, 307, 308) or r["status"] in BLOCKED
            if not found:
                continue
            self._classify(root, r, base_body)

        self._robots_security(base)

    # ------------------------------------------------------------------ probe
    def _probe(self, base: str, path: str) -> dict:
        url = base.rstrip("/") + "/" + path.lstrip("/")
        http = self.ctx.http
        is_redirect = False
        resp = http.get(url)
        status = resp.status
        loc = resp.header("content-location") or ""
        if not loc:
            for k, v in resp.header_items:
                if k == "location":
                    loc = v
        body_len = len(resp.body)
        ctype = resp.header("content-type")
        return {"url": url, "path": path, "status": status,
                "size": body_len, "ctype": ctype, "location": loc[:160]}

    # ------------------------------------------------------------------ classify
    def _classify(self, root: str, r: dict, base_body: str):
        path = r["path"]
        url = r["url"]
        status = r["status"]

        if status in BLOCKED:
            if MEDIUM_PATHS.search(path):
                self.register(
                    title=f"Restricted resource: '{path}' returns {status}",
                    description="A resource protected with authentication (401/403) exists in a "
                                "sensitive area.",
                    severity=Severity.LOW, cwe="CWE-200", owasp="A01:2021", url=url,
                    evidence=f"{status} · {r['ctype']}",
                    remediation="Verify the endpoint protection and that it does not leak content.")
            return

        # Soft 404: a200 response with many size similar tothe home page
        soft = False
        if status == 200 and base_body and r["size"]:
            ratio = abs(r["size"] - len(base_body)) / max(1, len(base_body))
            soft = ratio < 0.05

        if CRITICAL_PATHS.search(path) and status == 200:
            sep = "Possible configuration or credential leak" if not soft else \
                "A critical path was detected (possible soft-404; verify manually)."
            self.register(
                title=f"Critical file/service accessible: '{path}'",
                description=sep + ("" if not soft else " The content must be confirmed manually."),
                severity=Severity.CRITICAL if not soft else Severity.MEDIUM,
                cwe="CWE-540", owasp="A05:2021", url=url,
                evidence=f"Status {status} · {r['size']} bytes · {r['ctype']}",
                remediation="Remove/exclude the file from the web server and rotate any "
                            "secret it may contain.")
            return

        if HIGH_PATHS.search(path) and status == 200:
            self.register(
                title=f"Potentially sensitive resource accessible: '{path}'",
                description="File that may expose configuration, dependencies, logs or " +
                            ("backups." if not soft else "(possible soft-404; verify)."),
                severity=Severity.HIGH if not soft else Severity.LOW,
                cwe="CWE-538", owasp="A05:2021", url=url,
                evidence=f"Status {status} · {r['size']} bytes · {r['ctype']}",
                remediation="Check the content and block access to these files.")
            return

        if MEDIUM_PATHS.search(path):
            sev = Severity.LOW
            if status == 200:
                sev = Severity.MEDIUM
            self.register(
                title=f"Admin panel or endpoint located: '{path}'",
                description="An administrative or management area was found. If it does not "
                            "include MFA, login attempt lockout and WAF, it is a "
                            "brute-force attack target.",
                severity=sev, cwe="CWE-306", owasp="A07:2021", url=url,
                evidence=f"Status {status} · {r['size']} bytes",
                remediation="Protect the panels with IP/network access, MFA and rate limiting.")

        # Directory listing (autoindex)
        if (("html" in r["ctype"]) and status == 200
                and (soft is False) and r["location"] == ""):
            pass  # el marcador de listing se comprueba con GET en _robots_security

    # ------------------------------------------------------------------ robots/security
    def _robots_security(self, base: str):
        http = self.ctx.http
        robots = http.get(base.rstrip("/") + "/robots.txt")
        if robots.ok and "txt" in robots.header("content-type"):
            disallow = [l.split(":", 1)[1].strip() for l in robots.text.splitlines() if l.lower().startswith("disallow")]
            self.assets["robots"] = robots.text[:2000]
            self.assets["robots_disallowed"] = disallow
            if disallow:
                self.register(
                    title="robots.txt reveals hidden paths",
                    description="The robots.txt lists paths that the administrator tried to "
                                "hide: it can reveal sensitive directories.",
                    severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=robots.url,
                    evidence="\n".join(disallow[:20]),
                    remediation="Do not use robots.txt to protect sensitive content; use "
                                "real authentication.")
        else:
            self.register(
                title="robots.txt missing",
                description="No robots.txt found (crawler behavior "
                            "uncontrolled).",
                severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=base,
                remediation="Publish a robots.txtanda security.txt.")

        sec = http.get(base.rstrip("/") + "/.well-known/security.txt")
        if not sec.ok and sec.status not in (404,):
            self.register(
                title="security.txt missing or inaccessible",
                description="Without security.txt, researchers have no official channel "
                            "to report vulnerabilities responsibly.",
                severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=base,
                remediation="Publish /.well-known/security.txt with contact and policy.")