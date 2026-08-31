"""Análisis de cabeceras de seguridad HTTP, cookies y CORS."""

from __future__ import annotations

import re
from typing import Dict

from ..models import Severity
from .base import AuditModule


class HeadersModule(AuditModule):
    name = "headers"
    description = "Cabeceras de seguridad, cookies y CORS"

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

    # ------------------------------------------------------------------ transporte
    def _check_transport(self, url, resp):
        if url.startswith("http://"):
            self.register(
                title="Tráfico en claro (HTTP) sin redirección a HTTPS",
                description="El sitio responde en HTTP: credenciales, cookies y datos quedan "
                            "expuestos a interceptación (MITM).",
                severity=Severity.HIGH, cwe="CWE-319", owasp="A02:2021", url=url,
                remediation="Redirige todo el tráfico a HTTPS mediante 301 y habilita HSTS.")
            return
        self.assets["transport"] = "https"

    # ------------------------------------------------------------------ HSTS
    def _check_hsts(self, url, headers):
        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            self.register(
                title="Cabecera Strict-Transport-Security (HSTS) ausente",
                description="El navegador no está obligado a usar HTTPS; se permite degradación "
                            "del protocolo (SSL stripping).",
                severity=Severity.MEDIUM, cwe="CWE-319", owasp="A02:2021", url=url,
                remediation="Envía: Strict-Transport-Security: max-age=31536000; includeSubDomains")
            return
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15_552_000:
            self.register(
                title="HSTS con max-age insuficiente",
                description="max-age menor de 180 días deja ventanas de degradación.",
                severity=Severity.LOW, cwe="CWE-319", owasp="A02:2021", url=url,
                evidence=hsts,
                remediation="Usa max-age=31536000 o superior en producción.")

    # ------------------------------------------------------------------ CSP
    def _check_csp(self, url, headers):
        csp = headers.get("content-security-policy", "")
        if not csp:
            self.register(
                title="Content-Security-Policy (CSP) ausente",
                description="Sin CSP se mitiga peor el XSS y la inyección de datos en navegador.",
                severity=Severity.MEDIUM, cwe="CWE-693", owasp="A05:2021", url=url,
                remediation="Define una CSP restrictiva: default-src 'self'; script-src 'self'.")
            return
        unsafe = sorted(set(re.findall(r"unsafe-inline|unsafe-eval", csp, re.I)))
        if unsafe:
            self.register(
                title="CSP debilitada por unsafe-inline / unsafe-eval",
                description="Reducen la protección anti-XSS: " + ", ".join(unsafe),
                severity=Severity.MEDIUM, cwe="CWE-693", owasp="A05:2021", url=url,
                evidence=csp[:400],
                remediation="Elimínalas usando nonces o hashes.")

    # ------------------------------------------------------------------ clickjacking
    def _check_clickjacking(self, url, headers):
        xfo = headers.get("x-frame-options", "")
        has_frame = "frame-ancestors" in headers.get("content-security-policy", "")
        if not xfo and not has_frame:
            self.register(
                title="Protección contra clickjacking ausente",
                description="La página puede incrustarse en iframes maliciosos (clickjacking).",
                severity=Severity.MEDIUM, cwe="CWE-1021", owasp="A04:2021", url=url,
                remediation="Envía X-Frame-Options: DENY/SAMEORIGIN y CSP frame-ancestors.")
        elif "allow-from" in xfo.lower():
            self.register(
                title="X-Frame-Options con valor obsoleto allow-from",
                description="allow-from no se soporta en la mayoría de navegadores.",
                severity=Severity.LOW, cwe="CWE-1021", owasp="A04:2021", url=url,
                evidence=xfo,
                remediation="Usa SAMEORIGIN/DENY o CSP frame-ancestors.")

    # ------------------------------------------------------------------ cabeceras básicas
    def _check_basics(self, url, headers):
        if not headers.get("x-content-type-options", ""):
            self.register(
                title="X-Content-Type-Options ausente",
                description="El navegador puede adivinar (MIME sniffing) el tipo de respuesta.",
                severity=Severity.LOW, cwe="CWE-693", owasp="A05:2021", url=url,
                remediation="Envía: X-Content-Type-Options: nosniff")
        if not headers.get("referrer-policy", ""):
            self.register(
                title="Referrer-Policy ausente",
                description="La URL completa (con tokens) puede filtrarse como Referer a terceros.",
                severity=Severity.LOW, cwe="CWE-200", owasp="A01:2021", url=url,
                remediation="Envía: Referrer-Policy: strict-origin-when-cross-origin")
        if not headers.get("permissions-policy", "") and not headers.get("feature-policy", ""):
            self.register(
                title="Permissions-Policy ausente",
                description="No se restringe el uso de APIs sensibles por iframes de terceros.",
                severity=Severity.INFO, cwe="CWE-693", owasp="A05:2021", url=url,
                remediation="Define una Permissions-Policy restrictiva.")

    # ------------------------------------------------------------------ divulgación
    def _check_disclosure(self, url, headers):
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if server:
            self.register(
                title="Cabecera Server divulga plataforma",
                description="El banner revela el servidor web y puede orientar ataques dirigidos.",
                severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=url,
                evidence=f"Server: {server}",
                remediation="Ofusca u oculta la cabecera Server.")
        if powered:
            self.register(
                title="Cabecera X-Powered-By divulga tecnología",
                description="Revela framework/versión (p. ej. ASP.NET, PHP).",
                severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=url,
                evidence=f"X-Powered-By: {powered}",
                remediation="Desactiva X-Powered-By en el framework.")
        aspnet = {k: v for k, v in headers.items() if "aspnet" in k}
        if aspnet:
            self.register(
                title="Versión de ASP.NET expuesta",
                description="Cabeceras que revelan la versión exacta del runtime .NET.",
                severity=Severity.LOW, cwe="CWE-200", owasp="A05:2021", url=url,
                evidence="; ".join(f"{k}: {v}" for k, v in aspnet.items()),
                remediation="Oculta estas cabeceras en IIS/web.config.")

    # ------------------------------------------------------------------ CORS
    def _check_cors(self, url, headers):
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "false")
        if acao == "*" and acac.lower() == "true":
            self.register(
                title="CORS con wildcard y credenciales",
                description="ACAO: * junto a Allow-Credentials: true permite a cualquier origen "
                            "leer respuestas autenticadas del sitio.",
                severity=Severity.HIGH, cwe="CWE-942", owasp="A01:2021", url=url,
                evidence=f"ACAO: {acao}; ACAC: {acac}",
                remediation="Nunca combines * con credenciales; usa lista blanca de orígenes.")
        elif acao == "*":
            self.register(
                title="CORS con Access-Control-Allow-Origin: *",
                description="Cualquier origen puede leer respuestas desde el navegador.",
                severity=Severity.MEDIUM, cwe="CWE-942", owasp="A01:2021", url=url,
                evidence=f"ACAO: {acao}",
                remediation="Restringe orígenes a dominios de confianza.")

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
                    title=f"Cookie '{name}' sin atributo Secure",
                    description="Se transmitiría también por HTTP en claro.",
                    severity=Severity.MEDIUM, cwe="CWE-614", owasp="A05:2021",
                    url=url, evidence=f"Set-Cookie: {raw[:200]}",
                    remediation="Añade el atributo Secure.")
            if "httponly" not in flags:
                self.register(
                    title=f"Cookie '{name}' sin HttpOnly",
                    description="Accesible desde JavaScript: un XSS permite robar la sesión.",
                    severity=Severity.MEDIUM, cwe="CWE-1004", owasp="A05:2021",
                    url=url, evidence=raw[:200],
                    remediation="Añade HttpOnly a cookies de sesión y sensibles.")
            if not any(f.startswith("samesite") for f in flags):
                self.register(
                    title=f"Cookie '{name}' sin SameSite",
                    description="Más expuesta a ataques CSRF.",
                    severity=Severity.LOW, cwe="CWE-1275", owasp="A01:2021",
                    url=url, evidence=raw[:200],
                    remediation="Añade SameSite=Lax (o Strict) a las cookies.")

    # ------------------------------------------------------------------ métodos HTTP
    def _check_http_methods(self, url):
        """Comprueba métodos peligrosos (OPTIONS/TRACE) de forma benigna (solo --active)."""
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
                    title="Método TRACE habilitado (vulnerable a Cross-Site Tracing)",
                    description="El servidor acepta TRACE y devuelve la petición, "
                                "incluyendo cookies y credenciales; un XSS podría "
                                "enviar TRACE y robar la sesión (ataque XST).",
                    severity=Severity.HIGH, cwe="CWE-693", owasp="A05:2021",
                    url=url, evidence=f"OPTIONS Allow: {allow} · TRACE → 200",
                    remediation="Desactiva TRACE en el servidor web y firewall.")
        else:
            self.log("Métodos HTTP publicados: " + ", ".join(methods))