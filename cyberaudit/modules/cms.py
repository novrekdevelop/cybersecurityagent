"""Enumeración profunda de CMS cuando la huella tecnológica identifica uno.

Para WordPress / Drupal / Joomla / PrestaShop, un auditor profesional ejecuta
controles específicos del gestor de contenidos: enumeración de usuarios,
API REST expuesta, ficheros de versión, XML-RPC y paneles. Todos los probes
son GET benignos, acotados (≤9 peticiones) y solo se lanzan si el CMS fue
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
    description = "Enumeración de CMS (WordPress/Drupal/Joomla/PrestaShop)"

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
        info("CMS detectado: WordPress — enumerando superficie específica…")
        self.assets["cms"] = "wordpress"
        http = self.ctx.http

        # REST API expuesta
        rest = http.get(urljoin(origin + "/", "wp-json/"))
        if rest.ok and "json" in rest.header("content-type"):
            self.register(
                title="WordPress REST API expuesta",
                description="El endpoint /wp-json/ responde públicamente; expone esquemas, "
                            "autores en posts y, según configuración, acciones vía API.",
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
                title="Enumeración de usuarios WordPress por REST API",
                description="GET /wp-json/wp/v2/users revela los nombres de usuario, "
                            "clave previa a ataques de fuerza bruta y phishing dirigido.",
                severity=Severity.HIGH, cwe="CWE-200", owasp="A05:2021", url=users.url,
                evidence="\n".join(f"{u['slug'] or '?'} ({u['name'] or '?'}) {u['link'] or ''}"
                                   for u in rows[:12]),
                remediation="Desactiva /wp-json/wp/v2/users y oculta los autores en las "
                            "publicaciones.")

        # Enumeración de autores ?author=N
        for n in (1, 2):
            r = http.get(urljoin(origin + "/", f"?author={n}"), follow_redirects=False)
            loc = r.header("location") or ""
            m = re.search(r"/author/([^/]+)", loc)
            if r.status in (301, 302, 303, 307, 308) and m:
                self.register(
                    title="Enumeración de usuarios WordPress por ?author=N",
                    description="?author=1 devuelve un redirect a /author/<usuario>, "
                                "confirmando el nombre de login del primer usuario.",
                    severity=Severity.MEDIUM, cwe="CWE-200", owasp="A05:2021", url=loc,
                    evidence=f"?author={n} -> {loc} (usuario: {m.group(1)})",
                    remediation="Restringe el patrón de autor; usa plugins que oculten "
                                "el autor en la URL.")
                break

        # readme.html (versión revelada)
        readme = http.get(urljoin(origin + "/", "readme.html"))
        if readme.ok and "wordpress" in readme.text[:500].lower():
            v = re.search(r"Version\s+([0-9.]+)", readme.text[:3000])
            self.register(
                title="readme.html accesible (versión de WordPress revelada)",
                description="El fichero readme.html público permite conocer la versión "
                            "exacta y buscar exploits." + (f" Versión: {v.group(1)}." if v else ""),
                severity=Severity.MEDIUM, cwe="CWE-200", owasp="A05:2021", url=readme.url,
                evidence=(f"Version: {v.group(1)}" if v else readme.text[:120]),
                remediation="Elimina readme.html y evita revelar la versión.")

        # xmlrpc.php
        xmlrpc = http.get(urljoin(origin + "/", "xmlrpc.php"))
        if xmlrpc.ok and "XML-RPC" in xmlrpc.text[:200]:
            self.register(
                title="xmlrpc.php habilitado (amplificación y pingback)",
                description="XML-RPC permite fuerza bruta amplificada (system.multicall), "
                            "pingbacks (SSRF) y DDoS de reflexión.",
                severity=Severity.MEDIUM, cwe="CWE-400", owasp="A05:2021", url=xmlrpc.url,
                evidence=xmlrpc.text[:120],
                remediation="Desactiva XML-RPC salvo que un plugin lo requiera.")

    # ------------------------------------------------------------------ drupal
    def _drupal(self):
        base = self.ctx.base.url or self.ctx.target
        origin = origin_of(base)
        info("CMS detectado: Drupal — enumerando superficie específica…")
        self.assets["cms"] = "drupal"
        http = self.ctx.http
        for path in ("CHANGELOG.txt", "core/CHANGELOG.txt"):
            r = http.get(urljoin(origin + "/", path))
            if r.ok and r.text:
                v = re.search(r"Drupal\s+([0-9.]+)", r.text[:3000])
                self.register(
                    title="Fichero CHANGELOG de Drupal accesible",
                    description="El changelog público revela la versión de Drupal exacta, "
                                "permitiendo buscar vulnerabilidades conocidas."
                                + (f" Versión: {v.group(1)}." if v else ""),
                    severity=Severity.MEDIUM, cwe="CWE-200", owasp="A05:2021", url=r.url,
                    evidence=(f"Version: {v.group(1)}" if v else r.text[:120]),
                    remediation="Borra CHANGELOG.txt de la raíz pública o bloquea su acceso.")
                break

    # ------------------------------------------------------------------ joomla
    def _joomla(self):
        base = self.ctx.base.url or self.ctx.target
        origin = origin_of(base)
        info("CMS detectado: Joomla — enumerando superficie específica…")
        self.assets["cms"] = "joomla"
        http = self.ctx.http
        r = http.get(urljoin(origin + "/", "administrator/"))
        if r.status == 200 and r.text:
            self.register(
                title="Panel de administración de Joomla accesible",
                description="El panel /administrator/ de Joomla responde 200; es el "
                            "objetivo principal de ataques de fuerza bruta.",
                severity=Severity.MEDIUM, cwe="CWE-306", owasp="A07:2021", url=r.url,
                evidence=f"HTTP {r.status} · {len(r.body)} bytes",
                remediation="Protege el panel con MFA, bloqueo de intentos y allowlist de IPs.")

    # ------------------------------------------------------------------ prestashop
    def _prestashop(self):
        base = self.ctx.base.url or self.ctx.target
        origin = origin_of(base)
        info("CMS detectado: PrestaShop — enumerando superficie específica…")
        self.assets["cms"] = "prestashop"
        # (la enumeración específica de PrestaShop puede ampliarse aquí)