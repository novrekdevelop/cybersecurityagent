"""Enumeración de rutas y archivos sensibles con wordlist + hilos."""

from __future__ import annotations

import concurrent.futures as cf
import re
from typing import Dict, List, Set
from urllib.parse import urlparse

from ..models import Severity
from ..utils import load_wordlist, ok, info, warn
from .base import AuditModule

# Patrones de severidad por ruta
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
    description = "Enumeración de directorios y archivos sensibles"

    def run(self):
        cfg = self.ctx.config
        base = self.ctx.base.url or self.ctx.target
        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}"
        wordlist = load_wordlist(cfg.directory_wordlist)[:cfg.directory_max_requests]
        self.assets["dirs"] = []
        self.assets["robots"] = ""

        info(f"Probando {len(wordlist)} rutas (mismo host)…")
        base_body = self.ctx.base.text

        # Puede ser lento para >150 rutas; ejecutamos con pool de hilos
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
                    title=f"Recurso restringido: '{path}' devuelve {status}",
                    description="Existe un recurso protegido con autenticación (401/403) en una "
                                "zona sensible.",
                    severity=Severity.LOW, cwe="CWE-200", owasp="A01:2021", url=url,
                    evidence=f"{status} · {r['ctype']}",
                    remediation="Verifica la protección del endpoint y que no filtre contenido.")
            return

        # Soft 404: respuesta 200 con tamaño muy similar al de la home
        soft = False
        if status == 200 and base_body and r["size"]:
            ratio = abs(r["size"] - len(base_body)) / max(1, len(base_body))
            soft = ratio < 0.05

        if CRITICAL_PATHS.search(path) and status == 200:
            sep = "Posible fuga de configuración o credenciales" if not soft else \
                "Se detectó una ruta crítica (posible soft-404; verificar manualmente)."
            self.register(
                title=f"Archivo/servicio crítico accesible: '{path}'",
                description=sep + ("" if not soft else " El contenido debe confirmarse a mano."),
                severity=Severity.CRITICAL if not soft else Severity.MEDIUM,
                cwe="CWE-540", owasp="A05:2021", url=url,
                evidence=f"Status {status} · {r['size']} bytes · {r['ctype']}",
                remediation="Elimina/excluye el archivo del servidor web y rota cualquier "
                            "secreto que pudiera contener.")
            return

        if HIGH_PATHS.search(path) and status == 200:
            self.register(
                title=f"Recurso potencialmente sensible accesible: '{path}'",
                description="Archivo que puede exponer configuración, dependencias, logs o " +
                            ("backups." if not soft else "(posible soft-404; verificar)."),
                severity=Severity.HIGH if not soft else Severity.LOW,
                cwe="CWE-538", owasp="A05:2021", url=url,
                evidence=f"Status {status} · {r['size']} bytes · {r['ctype']}",
                remediation="Comprueba el contenido y bloquea el acceso a estos ficheros.")
            return

        if MEDIUM_PATHS.search(path):
            sev = Severity.LOW
            if status == 200:
                sev = Severity.MEDIUM
            self.register(
                title=f"Panel o endpoint administrativo localizado: '{path}'",
                description="Se ha encontrado una zona administrativa o de gestión. Si no "
                            "incluye MFA, bloqueo de intentos y WAF, es un objetivo de "
                            "ataque de fuerza bruta.",
                severity=sev, cwe="CWE-306", owasp="A07:2021", url=url,
                evidence=f"Status {status} · {r['size']} bytes",
                remediation="Protege los paneles con acceso por IP/red, MFA y rate limiting.")

        # Listado de directorios (autoindex)
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
                    title="robots.txt revela rutas ocultas",
                    description="El robots.txt enumera rutas que el administrador pretendía "
                                "ocultar: puede delatar directorios sensibles.",
                    severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=robots.url,
                    evidence="\n".join(disallow[:20]),
                    remediation="No uses robots.txt para proteger contenido sensible; usa "
                                "autenticación real.")
        else:
            self.register(
                title="robots.txt ausente",
                description="No se encontró robots.txt (comportamiento de rastreadores "
                            "no controlado).",
                severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=base,
                remediation="Publica un robots.txt y un security.txt.")

        sec = http.get(base.rstrip("/") + "/.well-known/security.txt")
        if not sec.ok and sec.status not in (404,):
            self.register(
                title="security.txt ausente o inaccesible",
                description="Sin security.txt, los investigadores no tienen canal oficial "
                            "para reportar vulnerabilidades de forma responsable.",
                severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=base,
                remediation="Publica /.well-known/security.txt con contacto y política.")