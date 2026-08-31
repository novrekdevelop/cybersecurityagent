"""Descubrimiento y análisis profundo de APIs (REST/GraphQL).

- Extrae endpoints de código JS y de páginas.
- Prueba rutas de API comunes (/api, /v1, /actuator, /graphql…).
- Consulta el Wayback Machine para endpoints históricos del mismo origen.
- Detecta APIs que responden SIN autenticación, datos sensibles,
  errores verbosos, GraphQL introspection y CORS abierto.
Todas las peticiones son benignas (GET salvo la consulta de introspection,
que se limita a lecturas). Las sondas activas se limitan a --active.
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

# Patrones para extraer URLs/endpoints desde JavaScript y HTML
JS_URL_PATTERNS = [
    re.compile(r"""(?:fetch|axios|XMLHttpRequest|\.ajax|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["']([^"'\s]{3,})["']""", re.I),
    re.compile(r"""["']((?:https?:)?//[^"'\s/][^"'\s]{3,})["']"""),
    re.compile(r"""["'](/[A-Za-z0-9_\-./]{3,})["']"""),
]
WS_PATTERN = re.compile(r"""wss?://[^"'\s]+""")

# Rutas de API comunes para probar
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
    """Devuelve candidatos a endpoints (URLs y paths) de un texto JS/HTML."""
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
    description = "Descubrimiento de APIs, endpoints sin autenticación y GraphQL"

    def run(self):
        base_url = self.ctx.base.url or self.ctx.target
        origin = origin_of(base_url)
        if not origin:
            return
        info("Buscando APIs y endpoints…")

        # 1) Extraer de JS + HTML
        texts = list(self.assets.get("_bodies", {}).values())
        api_candidates: Set[str] = set()
        for rec in self.assets.get("js_analyzed", []):
            texts.append(rec.get("content", ""))
        for t in texts[:100]:
            for cand in _extract_candidates(t):
                api_candidates.add(cand)
        self.assets["api_candidates_found"] = sorted(api_candidates)[:200]

        # 1b) Endpoints históricos vía Wayback Machine (rebusca pasiva)
        for up in self._wayback_urls(origin):
            api_candidates.add(up)

        # 2) Fuzzing de rutas de API comunes
        probes = set()
        for p in API_WORDLIST:
            probes.add(urljoin(origin + "/", p))
        # Endpoints relativos extraídos del código (mismo origen)
        for up in api_candidates:
            up_t = urljoin(origin + "/", up) if up.startswith("/") else (
                urljoin(base_url, up) if up.startswith("http") else up)
            if up_t.startswith(origin) or same_origin(up_t, base_url):
                path = urlparse(up_t).path
                if path.count("/") <= 4:
                    probes.add(up_t)

        discovered: List[Dict] = []
        # Sondas en paralelo (acotadas) para no ralentizar la auditoría
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

        # 3) Análisis de los endpoints descubiertos
        if discovered:
            self.log(f"{len(discovered)} respuestas JSON/API descubiertas.")
        self._analyze_endpoints(discovered, origin, base_url)
        self._graphql_probe(origin)

    # ------------------------------------------------------------------ análisis
    def _analyze_endpoints(self, discovered, origin, base_url):
        registered_nofun = False
        for ep in discovered[:40]:
            url = ep["url"]
            text = ep.get("snippet", "")
            if ep.get("status") != 200:
                continue
            # Datos sensibles en la respuesta
            hit = next((m for m in SENSITIVE_BODY_MARKERS if m in text), "")
            if hit:
                self.register(
                    title="La API expone datos potencialmente sensibles",
                    description="El endpoint devuelve en su cuerpo campos de tipo "
                                "credencial, token, clave o listado de usuarios sin "
                                "autenticación visible.",
                    severity=Severity.HIGH, cwe="CWE-200", owasp="A01:2021",
                    url=url, evidence=f"Cuerpo incluye: {hit} … {text[:200]}",
                    remediation="Aplica autenticación/autorización al endpoint y filtra "
                                "campos sensibles de las respuestas.")
                continue
            # Actuator / config expuesta
            if "actuator" in url or url.endswith(("/config", "/env", "/api/config")):
                self.register(
                    title="Endpoint de configuración/actuador expuesto",
                    description=("Spring Actuator o un endpoint de configuración devuelve "
                                 "el estado de la aplicación, librerías, versiones y "
                                 "posibles claves."),
                    severity=Severity.HIGH, cwe="CWE-200", owasp="A05:2021", url=url,
                    evidence=text[:300],
                    remediation="Protege los endpoints de actuación o restrínjelos con auth.")
            # Endpoint sensible sin autenticación
            path = urlparse(url).path
            if NO_AUTH_PATHS.search(path) and not registered_nofun:
                self.register(
                    title="Endpoint de la API responde sin autenticación",
                    description=f"'{path}' devuelve HTTP 200 con datos JSON sin reto de "
                                "autenticación. Si contiene datos de usuarios, pedidos o "
                                "administración, permite operar sin login o abusar del negocio.",
                    severity=Severity.HIGH, cwe="CWE-306", owasp="A01:2021", url=url,
                    evidence=f"GET {url} -> {ep.get('status')} · {ep.get('ctype')}",
                    remediation="Exige autenticación y autorización por endpoint; usa "
                                "dial de sesión del servidor, nunca IDs del request.")
                registered_nofun = True
# Errores verbosos en cualquier endpoint de API
        for ep in discovered[:40]:
            text = (ep.get("snippet", "") or "")[:4000]
            for pat, label in ERROR_PATTERNS:
                if pat.search(text):
                    self.register(
                        title="La API devuelve errores detallados",
                        description="El endpoint filtra trazas/excepciones que revelan stack "
                                    "interno, queries o rutas del servidor.",
                        severity=Severity.MEDIUM, cwe="CWE-209", owasp="A05:2021",
                        url=ep["url"], evidence=text[:300],
                        remediation="Devuelve mensajes de error genéricos y registra el "
                                    "detalle en logs internos.")
                    break

        # CORS en APIs (sonda benigna con cabecera Origin)
        if self.ctx.config.active_checks and discovered:
            test_url = discovered[0]["url"]
            resp = self.ctx.http.get(test_url, headers={
                "Origin": "https://attacker.example.com"})
            acao = resp.header("access-control-allow-origin")
            if acao and "attacker.example.com" in acao:
                self.register(
                    title="CORS abierto/reflejado en endpoint de API",
                    description="La API refleja cualquier origen en Access-Control-Allow-"
                                "Origin; un atacante puede leer respuestas desde su web.",
                    severity=Severity.HIGH, cwe="CWE-942", owasp="A01:2021",
                    url=test_url, evidence=f"ACAO: {acao}",
                    remediation="Valida el origen contra una lista blanca.")

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
                    title="GraphQL introspection habilitada",
                    description="El endpoint GraphQL acepta la consulta de schema, lo que "
                                "expone todos los tipos, campos y mutaciones de la API.",
                    severity=Severity.HIGH, cwe="CWE-200", owasp="A01:2021", url=url,
                    evidence="Consulta __schema devuelve 200 con 'types'.",
                    remediation="Desactiva introspection en producción.")

    # ------------------------------------------------------------------ wayback
    def _wayback_urls(self, origin) -> List[str]:
        """URLs históricas del mismo origen (archivo público), máximo 80."""
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