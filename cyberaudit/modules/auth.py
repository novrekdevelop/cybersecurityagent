"""Análisis profundo de autenticación, sesión y caminos de evasión del login.

Detección pasiva + sondas benignas:
- Formularios/endpoints de login: ¿hay rate limiting?, ¿envía credenciales a
  terceros?, ¿credenciales por GET/HTTP?
- Tokens (JWT, sesión, API) expuestos en URLs o en localStorage/sessionStorage.
- Política de contraseñas débil (minlength).
- Open redirect en los parámetros de redirección (solo --active, benigno).
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Set
from urllib.parse import urlparse

from ..models import Severity
from ..utils import absolute, info, origin_of, same_origin, warn
from .base import AuditModule

TOKEN_PARAM_RE = re.compile(
    r"(token|jwt|access_token|session|auth|password|passwd|api_key|apikey|"
    r"secret|bearer|sid|login|user|username)=([^&]{3,})", re.I)
STORAGE_TOKEN_RE = re.compile(
    r"(?i)(localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*['\"]([^'\"]{0,40})['\"]")
REDIRECT_PARAM_RE = re.compile(
    r"^(redirect|next|return|returnurl|return_url|url|goto|dest|redir|"
    r"continue|r|ref|redirect_url|link)$", re.I)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")

WEAK_HMAC_SECRETS = ("secret", "password", "123456", "changeme", "secretkey",
                     "privatekey", "jwt", "token", "apikey", "key", "admin",
                     "12345678", "qwerty", "letmein", "123456789")


def _b64url_decode(seg: str) -> bytes:
    import base64
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _jwt_parts(token: str):
    """Devuelve (ok, header_dict, payload) decodificados de forma segura."""
    parts = token.split(".")
    if len(parts) != 3:
        return False, {}, {}
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", "replace"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", "replace"))
        return True, header, payload
    except Exception:
        return False, {}, {}


class AuthModule(AuditModule):
    name = "auth"
    description = "Autenticación, sesiones y caminos de evasión del login"

    def run(self):
        self._seen: Set[str] = set()
        pages = self.assets.get("pages_analyzed", [])
        bodies = self.assets.get("_bodies", {})
        js_all = self.assets.get("js_analyzed", [])
        base_url = self.ctx.base.url or self.ctx.target

        # 1) Endpoints de login y su endurecimiento
        logins = self.assets.get("login_forms", [])
        if not logins:
            self._find_login_hints(pages, bodies)
        else:
            self.log(f"Endpoints de login: {len(logins)}")

        # 2) Tokens en URLs (fuga pasiva)
        self._check_url_tokens(pages)

        # 3) Tokens en localStorage (XSS -> robo de sesión)
        self._check_storage_tokens(js_all, bodies)

        # 4) Política de contraseñas desde el HTML
        self._check_password_policy(pages)

        # 5) Sondas benignas en el flujo de login (solo --active)
        if self.ctx.config.active_checks:
            self._check_login_flow(logins, base_url)

        # 6) Análisis profundo de JWT encontrados
        self._check_jwts(js_all, bodies)

    # -------PART2-------

    def _find_login_hints(self, pages, bodies):
        found = []
        for page in pages:
            for form in page.get("forms", []):
                if any(f.get("type") == "password" for f in form.get("fields", [])):
                    found.append({"url": page["url"],
                                  "action": form.get("action", ""),
                                  "method": form.get("method", "GET")})
        self.assets["login_forms"] = found

    def _sep(self, key: str) -> bool:
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    # ------------------------------------------------------------------ tokens en URL
    def _check_url_tokens(self, pages):
        for page in pages[:60]:
            q = urlparse(page["url"]).query
            if not q:
                continue
            m = TOKEN_PARAM_RE.search(q)
            if not m:
                continue
            ident = "urlparam|" + re.sub(r"=\S*", "", q)[:40] + "|" + urlparse(page["url"]).path
            if not self._sep(ident):
                continue
            self.register(
                title="Parámetro sensible en la URL (fuga de sesión/token)",
                description=f"El parámetro '{m.group(1)}' aparece en la cadena de la URL. "
                            "Queda en historial, logs, Referer y proxies, permitiendo "
                            "robo de sesión.",
                severity=Severity.HIGH, cwe="CWE-598", owasp="A03:2021",
                url=page["url"], evidence=f"?{q[:200]}",
                remediation="Envía tokens y credenciales en el cuerpo (POST) o en "
                            "cabeceras HTTP, nunca en la query.")

    # ------------------------------------------------------------------ tokens en storage
    def _check_storage_tokens(self, js_all, bodies):
        for rec in js_all[:40]:
            content = rec.get("content", "")[:150_000]
            keys = ("token", "jwt", "auth", "auth_token", "access",
                    "access_token", "refresh", "session", "creds", "user")
            for key in keys:
                rx = re.compile(
                    rf"localStorage\s*\.\s*setItem\s*\(\s*['\"]{re.escape(key)}['\"]", re.I)
                if rx.search(content) and self._sep("storage:" + key):
                    self.register(
                        title="Token/credencial almacenado en localStorage",
                        description=f"El código guarda '{key}' en localStorage. Un XSS "
                                    "puede leerlo y robar la sesión; además persiste tras "
                                    "cerrar el navegador.",
                        severity=Severity.MEDIUM, cwe="CWE-922", owasp="A03:2021",
                        url=rec.get("url", self.ctx.target), evidence=key,
                        remediation="Guarda el token en una cookie HttpOnly+Secure o en "
                                    "memoria; evita localStorage para secretos.")

    # ------------------------------------------------------------------ contraseñas
    def _check_password_policy(self, pages):
        for page in pages:
            for form in page.get("forms", []):
                for f in form.get("fields", []):
                    if f.get("type") != "password":
                        continue
                    minlen = str(f.get("minlength", "") or "")
                    ident = "pwd|" + page["url"] + "|" + str(len(form.get("fields", [])))
                    if (not minlen or not minlen.isdigit() or int(minlen) < 8) and self._sep(ident):
                        self.register(
                            title="Política de contraseñas débil (login)",
                            description="El campo de contraseña no exige una longitud mínima "
                                        "de 8 caracteres; credenciales triviales y fuerza "
                                        "bruta más fácil.",
                            severity=Severity.LOW, cwe="CWE-521", owasp="A07:2021",
                            url=page["url"],
                            evidence=f"minlength={minlen or '(no definido)'}",
                            remediation="Exige contraseñas de mínimo 8-12 caracteres y "
                                        "complejidad en el servidor.")

    # ------------------------------------------------------------------ flujo de login
    def _check_login_flow(self, logins, base_url):
        from urllib.parse import parse_qsl
        origin = origin_of(base_url)
        for entry in logins[:5]:
            url = entry.get("url") or entry.get("action") or ""
            if not url:
                continue
            action = entry.get("action") or ""
            # Credenciales a un dominio externo
            if action and not same_origin(action, base_url):
                if self._sep("ext|" + action):
                    self.register(
                        title="El login envía credenciales a un dominio externo",
                        description=f"El formulario de login envía las credenciales a "
                                    f"'{action}', fuera del origen del sitio.",
                        severity=Severity.HIGH, cwe="CWE-320", owasp="A01:2021",
                        url=url, evidence=f"action={action}",
                        remediation="Verifica la integridad del destino; para SSO externo "
                                    "usa OIDC/SAML y nunca credenciales en claro.")
            # Rate limiting del login
            resp = self.ctx.http.get(url)
            rate_hits = [k for k, v in resp.header_items if "ratelimit" in k or k == "retry-after"]
            if resp.status == 200 and not rate_hits and self._sep("rl|" + url):
                self.register(
                    title="Login sin control de intentos (rate limiting)",
                    description="La página de login no declara cabeceras de rate limiting; "
                                "sin bloqueo, es candidata a fuerza bruta de credenciales.",
                    severity=Severity.MEDIUM, cwe="CWE-307", owasp="A07:2021",
                    url=url,
                    evidence="Cabeceras: " + (", ".join(k for k, _ in resp.header_items) or "—"),
                    remediation="Aplica bloqueo tras N intentos fallidos, backoff y rate "
                                "limiting por IP/cuenta.")
            # Open redirect (sonda benigna)
            parsed = urlparse(url)
            if parsed.query:
                for k, v in parse_qsl(parsed.query, keep_blank_values=True):
                    if not REDIRECT_PARAM_RE.match(k):
                        continue
                    evil = "https://example.com/"
                    test = url.replace(v or "", evil)
                    rr = self.ctx.http.get(test, follow_redirects=False)
                    loc = rr.header("location")
                    if rr.status in (301, 302, 303, 307, 308) and loc and \
                            "example.com" in loc and self._sep("redir|" + k + url):
                        self.register(
                            title="Open redirect en flujo de login",
                            description="El parámetro de redirección refleja un destino "
                                        "externo y el servidor responde 3xx hacia él "
                                        "(sonda benigna). Permite phishing que salta avisos.",
                            severity=Severity.HIGH, cwe="CWE-601", owasp="A01:2021",
                            url=test, evidence=f"Location: {loc}",
                            remediation="Valida las redirecciones contra una lista blanca "
                                        "de orígenes.")
                    break

    # ------------------------------------------------------------------ JWT
    def _check_jwts(self, js_all, bodies):
        """Decodifica JWTs del cliente y busca debilidades (alg none, HMAC débil)."""
        import hashlib
        import hmac

        seen = set()
        tokens = []
        for rec in js_all[:40]:
            content = rec.get("content", "")
            for m in JWT_RE.finditer(content):
                tok = m.group(0)
                if tok not in seen:
                    seen.add(tok)
                    tokens.append((tok, rec.get("url", self.ctx.target)))
        for page in self.assets.get("pages_analyzed", [])[:20]:
            body = bodies.get(page["url"], "")
            for m in JWT_RE.finditer(body):
                tok = m.group(0)
                if tok not in seen:
                    seen.add(tok)
                    tokens.append((tok, page["url"]))
        if not tokens:
            return
        self.log(f"Se encontraron {len(tokens)} tokens JWT en el cliente.")

        for tok, src_url in tokens[:8]:
            ok, header, payload = _jwt_parts(tok)
            if not ok:
                continue
            parts = tok.split(".")
            alg = str(header.get("alg", "?")).upper()
            if alg == "NONE":
                self.register(
                    title="JWT con algoritmo 'none' (falsable sin firma)",
                    description="El JWT declara alg=none; si el servidor lo acepta, se "
                                "pueden forjar tokens de administración sin secreto.",
                    severity=Severity.CRITICAL, cwe="CWE-347", owasp="A07:2021",
                    url=src_url, evidence=tok[:120] + "…",
                    remediation="Rechaza tokens con alg=none; fija un algoritmo whitelist "
                                "(HS256/RS256) y verifica firma.")
                continue
            if isinstance(payload, dict):
                sensitive = [k for k in payload
                             if k in ("password", "secret", "card", "admin", "private")]
                if sensitive:
                    self.register(
                        title="JWT expone claims sensibles en el cliente",
                        description="El token visible contiene campos sensibles: " +
                                    ", ".join(sensitive) + ".",
                        severity=Severity.MEDIUM, cwe="CWE-922", owasp="A05:2021",
                        url=src_url, evidence=str(payload)[:200],
                        remediation="No pongas datos sensibles en el JWT; usa referencias "
                                    "por id o cifra las claims.")
            # HMAC débil (HS256/HS384/HS512)
            if alg in ("HS256", "HS384", "HS512") and len(parts) == 3:
                signing_input = f"{parts[0]}.{parts[1]}".encode()
                sig = parts[2]
                for secret in WEAK_HMAC_SECRETS:
                    dig = hmac.new(secret.encode(), signing_input,
                                   hashlib.sha256).digest()
                    import base64
                    cand = base64.urlsafe_b64encode(dig).rstrip(b"=").decode()
                    if hmac.compare_digest(cand, sig):
                        self.register(
                            title="JWT firmado con secreto HMAC débil (forjable)",
                            description=f"El token usa {alg} con la clave trivial "
                                        f"'{secret}'; se puede recomputar la firma y "
                                        "crear tokens de administración.",
                            severity=Severity.CRITICAL, cwe="CWE-347", owasp="A07:2021",
                            url=src_url, evidence=tok[:120] + "…",
                            remediation="Usa secretos de alta entropía (≥32 bytes) y rota "
                                        "la clave actual.")
                        break