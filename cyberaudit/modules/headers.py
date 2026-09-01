"""Analysis of HTTP security headers, cookies and CORS."""

from __future__ import annotations

import re
from typing import Dict

from ..models import Severity
from .base import AuditModule


class HeadersModule(AuditModule):
    name = "headers"
    description = "Security headers, cookies and CORS"

    def run(self):
        resp = self.ctx.base
        url = resp.url or self.ctx.target
        headers: Dict[str, str] = resp.headers
        self._check_transport(url, resp)
        self._check_hsts(url, headers)
        self._check_csp(url, headers)
        self._check_clickjacking(url, headers)
        self._check_basics(url, headers)
        self._check_disclosure(url, headers)
        self._check_cors(url, headers)
        self._check_cookies(url)
        self._check_http_methods(url)

    # ------------------------------------------------------------------ transport
    def _check_transport(self, url, resp):
        if url.startswith("http://"):
            self.register(
                title="Clear-text traffic (HTTP) without HTTPS redirect",
                description="The site responds on HTTP: credentials, cookies and data are "
                            "exposed to interception (MITM).",
                severity=Severity.HIGH, cwe="CWE-319", owasp="A02:2021", url=url,
                remediation="Redirect all traffic to HTTPS with a 301 and enable HSTS.")
            return
        self.assets["transport"] = "https"

    # ------------------------------------------------------------------ HSTS
    def _check_hsts(self, url, headers):
        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            self.register(
                title="Strict-Transport-Security (HSTS) header missing",
                description="The browser is not forced to use HTTPS; protocol downgrade "
                            "(SSL stripping) is allowed.",
                severity=Severity.MEDIUM, cwe="CWE-319", owasp="A02:2021", url=url,
                remediation="Send: Strict-Transport-Security: max-age=31536000; includeSubDomains")
            return
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15_552_000:
            self.register(
                title="HSTS with insufficient max-age",
                description="A max-age below 180 days leaves downgrade windows open.",
                severity=Severity.LOW, cwe="CWE-319", owasp="A02:2021", url=url,
                evidence=hsts,
                remediation="Use max-age=31536000 or higher in production.")

    # ------------------------------------------------------------------ CSP
    def _check_csp(self, url, headers):
        csp = headers.get("content-security-policy", "")
        if not csp:
            self.register(
                title="Content-Security-Policy (CSP) missing",
                description="Without CSP, XSS and in-browser data injection are mitigated worse.",
                severity=Severity.MEDIUM, cwe="CWE-693", owasp="A05:2021", url=url,
                remediation="Define a restrictive CSP: default-src 'self'; script-src 'self'.")
            return
        unsafe = sorted(set(re.findall(r"unsafe-inline|unsafe-eval", csp, re.I)))
        if unsafe:
            self.register(
                title="CSP weakened by unsafe-inline / unsafe-eval",
                description="They reduce the anti-XSS protection: " + ", ".join(unsafe),
                severity=Severity.MEDIUM, cwe="CWE-693", owasp="A05:2021", url=url,
                evidence=csp[:400],
                remediation="Remove them using nonces or hashes.")

    # ------------------------------------------------------------------ clickjacking
    def _check_clickjacking(self, url, headers):
        xfo = headers.get("x-frame-options", "")
        has_frame = "frame-ancestors" in headers.get("content-security-policy", "")
        if not xfo and not has_frame:
            self.register(
                title="Clickjacking protection missing",
                description="The page can be embedded in malicious iframes (clickjacking).",
                severity=Severity.MEDIUM, cwe="CWE-1021", owasp="A04:2021", url=url,
                remediation="Send X-Frame-Options: DENY/SAMEORIGIN and CSP frame-ancestors.")
        elif "allow-from" in xfo.lower():
            self.register(
                title="X-Frame-Options with deprecated allow-from value",
                description="allow-from is not supported in most browsers.",
                severity=Severity.LOW, cwe="CWE-1021", owasp="A04:2021", url=url,
                evidence=xfo,
                remediation="Use SAMEORIGIN/DENY or CSP frame-ancestors.")

    # ------------------------------------------------------------------ basic headers
    def _check_basics(self, url, headers):
        if not headers.get("x-content-type-options", ""):
            self.register(
                title="X-Content-Type-Options missing",
                description="The browser may guess (MIME sniffing) the response type.",
                severity=Severity.LOW, cwe="CWE-693", owasp="A05:2021", url=url,
                remediation="Send: X-Content-Type-Options: nosniff")
        if not headers.get("referrer-policy", ""):
            self.register(
                title="Referrer-Policy missing",
                description="The full URL (with tokens) can leak as Referer to third parties.",
                severity=Severity.LOW, cwe="CWE-200", owasp="A01:2021", url=url,
                remediation="Send: Referrer-Policy: strict-origin-when-cross-origin")
        if not headers.get("permissions-policy", "") and not headers.get("feature-policy", ""):
            self.register(
                title="Permissions-Policy missing",
                description="The use of sensitive APIs by third-party iframes is not restricted.",
                severity=Severity.INFO, cwe="CWE-693", owasp="A05:2021", url=url,
                remediation="Define a restrictive Permissions-Policy.")

    # ------------------------------------------------------------------ disclosure
    def _check_disclosure(self, url, headers):
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if server:
            self.register(
                title="Server header discloses platform",
                description="The banner reveals the web server and can guide targeted attacks.",
                severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=url,
                evidence=f"Server: {server}",
                remediation="Obfuscate or hide the Server header.")
        if powered:
            self.register(
                title="X-Powered-By header discloses technology",
                description="Reveals framework/version (e.g. ASP.NET, PHP).",
                severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=url,
                evidence=f"X-Powered-By: {powered}",
                remediation="Disable X-Powered-By in the framework.")
        aspnet = {k: v for k, v in headers.items() if "aspnet" in k}
        if aspnet:
            self.register(
                title="ASP.NET version exposed",
                description="Headers that reveal the exact .NET runtime version.",
                severity=Severity.LOW, cwe="CWE-200", owasp="A05:2021", url=url,
                evidence="; ".join(f"{k}: {v}" for k, v in aspnet.items()),
                remediation="Hide these headers in IIS/web.config.")

    # ------------------------------------------------------------------ CORS
    def _check_cors(self, url, headers):
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "false")
        if acao == "*" and acac.lower() == "true":
            self.register(
                title="CORS with wildcard and credentials",
                description="ACAO: * together with Allow-Credentials: true lets any origin "
                            "read authenticated responses from the site.",
                severity=Severity.HIGH, cwe="CWE-942", owasp="A01:2021", url=url,
                evidence=f"ACAO: {acao}; ACAC: {acac}",
                remediation="Never combine * with credentials; use an origin allowlist.")
        elif acao == "*":
            self.register(
                title="CORS with Access-Control-Allow-Origin: *",
                description="Any origin can read responses from the browser.",
                severity=Severity.MEDIUM, cwe="CWE-942", owasp="A01:2021", url=url,
                evidence=f"ACAO: {acao}",
                remediation="Restrict origins to trusted domains.")

    # ------------------------------------------------------------------ cookies
    def _check_cookies(self, url):
        sets = self.ctx.base.headers_by_name("set-cookie")
        self.assets["cookies_analyzed"] = []
        for raw in sets:
            name = raw.split("=", 1)[0].strip()
            flags = {a.split("=")[0].strip().lower() for a in raw.split(";")[1:]}
            self.assets["cookies_analyzed"].append({
                "name": name, "flags": sorted(flags), "raw": raw[:160]})
            if not name:
                continue
            if "secure" not in flags:
                self.register(
                    title=f"Cookie '{name}' without Secure attribute",
                    description="It would also be transmitted over clear-text HTTP.",
                    severity=Severity.MEDIUM, cwe="CWE-614", owasp="A05:2021",
                    url=url, evidence=f"Set-Cookie: {raw[:200]}",
                    remediation="Add the Secure attribute.")
            if "httponly" not in flags:
                self.register(
                    title=f"Cookie '{name}' without HttpOnly",
                    description="Accessible from JavaScript: an XSS can steal the session.",
                    severity=Severity.MEDIUM, cwe="CWE-1004", owasp="A05:2021",
                    url=url, evidence=raw[:200],
                    remediation="Add HttpOnly to session and sensitive cookies.")
            if not any(f.startswith("samesite") for f in flags):
                self.register(
                    title=f"Cookie '{name}' without SameSite",
                    description="More exposed to CSRF attacks.",
                    severity=Severity.LOW, cwe="CWE-1275", owasp="A01:2021",
                    url=url, evidence=raw[:200],
                    remediation="Add SameSite=Lax (or Strict) to cookies.")

    # ------------------------------------------------------------------ HTTP methods
    def _check_http_methods(self, url):
        """Checks dangerous methods (OPTIONS/TRACE) benignly (only --active)."""
        if not self.ctx.config.active_checks or not url:
            return
        opts = self.ctx.http.request("OPTIONS", url)
        allow = opts.header("allow")
        if not allow:
            return
        self.assets["http_methods_allow"] = allow.strip()
        methods = [m.strip().upper() for m in allow.split(",")]
        if "TRACE" in methods:
            trace = self.ctx.http.request("TRACE", url)
            if trace.status == 200 and trace.body:
                self.register(
                    title="TRACE method enabled (vulnerable to Cross-Site Tracing)",
                    description="The server accepts TRACE and returns the request, "
                                "including cookies and credentials; an XSS could "
                                "send TRACE and steal the session (XST attack).",
                    severity=Severity.HIGH, cwe="CWE-693", owasp="A05:2021",
                    url=url, evidence=f"OPTIONS Allow: {allow} · TRACE → 200",
                    remediation="Disable TRACE on the web server and firewall.")
        else:
            self.log("Published HTTP methods: " + ", ".join(methods))