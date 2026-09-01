"""Deep CMS enumeration when the technology fingerprint identifies one.

For WordPress / Drupal / Joomla / PrestaShop,a professional auditor runs
CMS-specific checks: user enumeration,
exposed REST API, version files, XML-RPC and panels. All probes
are benign,bounded GETs (≤9 requests( and only run if the CMS was
detectado.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from ..models import Severity
from ..utils import info, origin_of
from .base import AuditModule

WORDPRESS_MARKERS = re.compile(r"wp-content|wp-includes|wp-json", re.I)
DRUPAL_MARKERS = re.compile(r"sites/default/files|drupal-settings-json|/core/misc/drupal", re.I)
JOOMLA_MARKERS = re.compile(r"/media/system/js/|Joomla", re.I)
PRESTASHOP_MARKERS = re.compile(r"prestashop|/modules/", re.I)


class CmsModule(AuditModule):
    name = "cms"
    description = "CMS enumeration (WordPress/Drupal/Joomla/PrestaShop)"

    def run(self):
        techs = [t.get("name", "") for t in self.assets.get("tech", [])]
        if not techs:
            return
        body = self.ctx.base.text[:300_000]
        if "WordPress" in techs or "WooCommerce" in techs or WORDPRESS_MARKERS.search(body):
            self._wordpress()
            return  # solo un CMS habitual
        if "Drupal" in techs or DRUPAL_MARKERS.search(body):
            self._drupal()
            return
        if "Joomla" in techs or JOOMLA_MARKERS.search(body):
            self._joomla()
            return
        if "PrestaShop" in techs or PRESTASHOP_MARKERS.search(body):
            self._prestashop()

    # ------------------------------------------------------------------ wordpress
    def _wordpress(self):
        base = self.ctx.base.url or self.ctx.target
        origin = origin_of(base)
        info("CMS detected: WordPress — enumerating specific surface…")
        self.assets["cms"] = "wordpress"
        http = self.ctx.http

        # REST API expuesta
        rest = http.get(urljoin(origin + "/", "wp-json/"))
        if rest.ok and "json" in rest.header("content-type"):
            self.register(
                title="WordPress REST API exposed",
                description="The /wp-json/ endpoint responds publicly; it exposes schemas, "
                            "authors in postsand, depending on configuration, actions via the API.",
                severity=Severity.LOW, cwe="CWE-200", owasp="A05:2021", url=rest.url,
                evidence=rest.text[:200],
                remediation="Bloquea wp-json si no lo necesitas o protégelo por "
                            "autenticación y plugins de seguridad (ocultar autores).")

        # Enumeración de usuarios vía REST API (clásica)
        users = http.get(urljoin(origin + "/", "wp-json/wp/v2/users?per_page=20"))
        rows = []
        if users.ok and users.text.lstrip().startswith("["):
            try:
                data = json.loads(users.text)
                rows = [{"slug": u.get("slug"), "name": u.get("name"),
                         "link": u.get("link")} for u in data
                        if u.get("slug") or u.get("name")]
            except Exception:
                rows = []
        if rows:
            self.register(
                title="WordPress user enumeration via REST API",
                description="GET /wp-json/wp/v2/users reveals the usernames, "
                            "a key prerequisite for brute-force attacksand targeted phishing.",
                severity=Severity.HIGH, cwe="CWE-200", owasp="A05:2021", url=users.url,
                evidence="\n".join(f"{u['slug'] or '?'} ({u['name'] or '?'}) {u['link'] or ''}"
                                   for u in rows[:12]),
                remediation="Disable /wp-json/wp/v2/usersand hide the authors in the "
                            "posts.")

        # Enumeración de autores ?author=N
        for n in (1, 2):
            r = http.get(urljoin(origin + "/", f"?author={n}"), follow_redirects=False)
            loc = r.header("location") or ""
            m = re.search(r"/author/([^/]+)", loc)
            if r.status in (301, 302, 303, 307, 308) and m:
                self.register(
                    title="WordPress user enumeration via ?author=N",
                    description="?author=1 returns aredirect to /author/<user>, "
                                "confirming the login name ofthe first user.",
                    severity=Severity.MEDIUM, cwe="CWE-200", owasp="A05:2021", url=loc,
                    evidence=f"?author={n} -> {loc} (user: {m.group(1)})",
                    remediation="Restringe el patrón de autor; usa plugins que oculten "
                                "el autor en la URL.")
                break

        # readme.html (versión revelada)
        readme = http.get(urljoin(origin + "/", "readme.html"))
        if readme.ok and "wordpress" in readme.text[:500].lower():
            v = re.search(r"Version\s+([0-9.]+)", readme.text[:3000])
            self.register(
                title="readme.html accessible (WordPress version disclosed)",
                description="The public readme.html file reveals the exact version "
                            "and helps find exploits." + (f" Version: {v.group(1)}." if v else ""),
                severity=Severity.MEDIUM, cwe="CWE-200", owasp="A05:2021", url=readme.url,
                evidence=(f"Version: {v.group(1)}" if v else readme.text[:120]),
                remediation="Remove readme.htmland avoid disclosing the version.")

        # xmlrpc.php
        xmlrpc = http.get(urljoin(origin + "/", "xmlrpc.php"))
        if xmlrpc.ok and "XML-RPC" in xmlrpc.text[:200]:
            self.register(
                title="xmlrpc.php enabled (amplificationand pingback)",
                description="XML-RPC permite fuerza bruta amplificada (system.multicall), "
                            "pingbacks (SSRF)and reflection DDoS.",
                severity=Severity.MEDIUM, cwe="CWE-400", owasp="A05:2021", url=xmlrpc.url,
                evidence=xmlrpc.text[:120],
                remediation="Disable XML-RPC unless a plugin requires it.")

    # ------------------------------------------------------------------ drupal
    def _drupal(self):
        base = self.ctx.base.url or self.ctx.target
        origin = origin_of(base)
        info("CMS detected: Drupal — enumerating specific surface…")
        self.assets["cms"] = "drupal"
        http = self.ctx.http
        for path in ("CHANGELOG.txt", "core/CHANGELOG.txt"):
            r = http.get(urljoin(origin + "/", path))
            if r.ok and r.text:
                v = re.search(r"Drupal\s+([0-9.]+)", r.text[:3000])
                self.register(
                    title="Drupal CHANGELOG file accessible",
                    description="The public changelog reveals the exact Drupal version, "
                                "allowing known vulnerabilities to be found."
                                + (f" Versión: {v.group(1)}." if v else ""),
                    severity=Severity.MEDIUM, cwe="CWE-200", owasp="A05:2021", url=r.url,
                    evidence=(f"Version: {v.group(1)}" if v else r.text[:120]),
                    remediation="Remove CHANGELOG.txtfrom the public root or block its access.")
                break

    # ------------------------------------------------------------------ joomla
    def _joomla(self):
        base = self.ctx.base.url or self.ctx.target
        origin = origin_of(base)
        info("CMS detected: Joomla — enumerating specific surface…")
        self.assets["cms"] = "joomla"
        http = self.ctx.http
        r = http.get(urljoin(origin + "/", "administrator/"))
        if r.status == 200 and r.text:
            self.register(
                title="Joomla admin panel accessible",
                description="The /administrator/ Joomla panel responds 200; it is the "
                            "main target for brute-force attacks.",
                severity=Severity.MEDIUM, cwe="CWE-306", owasp="A07:2021", url=r.url,
                evidence=f"HTTP {r.status} · {len(r.body)} bytes",
                remediation="Protect the panel with MFA, login attempt lockoutand IP allowlist.")

    # ------------------------------------------------------------------ prestashop
    def _prestashop(self):
        base = self.ctx.base.url or self.ctx.target
        origin = origin_of(base)
        info("CMS detected: PrestaShop — enumerating specific surface…")
        self.assets["cms"] = "prestashop"
        # (la enumeración específica de PrestaShop puede ampliarse aquí)