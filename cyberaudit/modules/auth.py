"""Deep analysis of authentication, sessions and login bypass paths.

Passive detection + benign probes:
- Login forms/endpoints: is there rate limiting?, does it send credentials to
  third parties?, credentials over GET/HTTP?
- Tokens (JWT, session, API) exposed in URLs or in localStorage/sessionStorage.
- Weak password policy (minlength).
- Open redirect in redirection parameters (only --active, benign).
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
    """Safely decodes the token into (ok, header_dict, payload)."""
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
    description = "Authentication, sessions and login bypass paths"

    def run(self):
        self._seen: Set[str] = set()
        pages = self.assets.get("pages_analyzed", [])
        bodies = self.assets.get("_bodies", {})
        js_all = self.assets.get("js_analyzed", [])
        base_url = self.ctx.base.url or self.ctx.target

        # 1) Login endpoints and their hardening
        logins = self.assets.get("login_forms", [])
        if not logins:
            self._find_login_hints(pages, bodies)
        else:
            self.log(f"Login endpoints: {len(logins)}")

        # 2) Tokens in URLs (passive leak)
        self._check_url_tokens(pages)

        # 3) Tokens in localStorage (XSS -> session theft)
        self._check_storage_tokens(js_all, bodies)

        # 4) Password policy from the HTML
        self._check_password_policy(pages)

        # 5) Benign probes in the login flow (only --active)
        if self.ctx.config.active_checks:
            self._check_login_flow(logins, base_url)

        # 6) Deep analysis of found JWTs
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

    # ------------------------------------------------------------------ tokens in URL
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
                title="Sensitive parameter in the URL (session/token leak)",
                description=f"The parameter '{m.group(1)}' appears in the URL query string. "
                            "It stays in history, logs, Referer and proxies, allowing "
                            "session theft.",
                severity=Severity.HIGH, cwe="CWE-598", owasp="A03:2021",
                url=page["url"], evidence=f"?{q[:200]}",
                remediation="Send tokens and credentials in the body (POST) or in "
                            "HTTP headers, never in the query.")

    # ------------------------------------------------------------------ tokens in storage
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
                        title="Token/credential stored in localStorage",
                        description=f"The code stores '{key}' in localStorage. An XSS "
                                    "can read it and steal the session; it also persists after "
                                    "closing the browser.",
                        severity=Severity.MEDIUM, cwe="CWE-922", owasp="A03:2021",
                        url=rec.get("url", self.ctx.target), evidence=key,
                        remediation="Store the token in an HttpOnly+Secure cookie or in "
                                    "memory; avoid localStorage for secrets.")

    # ------------------------------------------------------------------ passwords
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
                            title="Weak password policy (login)",
                            description="The password field does not require a minimum length "
                                        "of 8 characters, making trivial credentials and brute "
                                        "force easier.",
                            severity=Severity.LOW, cwe="CWE-521", owasp="A07:2021",
                            url=page["url"],
                            evidence=f"minlength={minlen or '(not defined)'}",
                            remediation="Require strong passwords (minimum 8-12 characters) " 
                                        "and enforce complexity server-side.")

    # ------------------------------------------------------------------ login flow
    def _check_login_flow(self, logins, base_url):
        from urllib.parse import parse_qsl
        origin = origin_of(base_url)
        for entry in logins[:5]:
            url = entry.get("url") or entry.get("action") or ""
            if not url:
                continue
            action = entry.get("action") or ""
            # Credentials sent to an external domain
            if action and not same_origin(action, base_url):
                if self._sep("ext|" + action):
                    self.register(
                        title="Login sends credentials to an external domain",
                        description=f"The login form sends the credentials to "
                                    f"'{action}', outside the site's origin.",
                        severity=Severity.HIGH, cwe="CWE-320", owasp="A01:2021",
                        url=url, evidence=f"action={action}",
                        remediation="Verify the destination integrity; for external SSO "
                                    "use OIDC/SAML and never send clear-text credentials.")
            # Login rate limiting
            resp = self.ctx.http.get(url)
            rate_hits = [k for k, v in resp.header_items if "ratelimit" in k or k == "retry-after"]
            if resp.status == 200 and not rate_hits and self._sep("rl|" + url):
                self.register(
                    title="Login without attempt rate limiting",
                    description="The login page does not declare rate limiting headers; "
                                "without lockout, it is a candidate for credential brute force.",
                    severity=Severity.MEDIUM, cwe="CWE-307", owasp="A07:2021",
                    url=url,
                    evidence="Headers: " + (", ".join(k for k, _ in resp.header_items) or "—"),
                    remediation="Apply lockout after N failed attempts, backoff and rate "
                                "limiting per IP/account.")
            # Open redirect (benign probe)
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
                            title="Open redirect in login flow",
                            description="The redirection parameter reflects an external "
                                        "destination and the server responds 3xx to it "
                                        "(benign probe)**, which allows phishing that skips "
                                        "warnings.",
                            severity=Severity.HIGH, cwe="CWE-601", owasp="A01:2021",
                            url=test, evidence=f"Location: {loc}",
                            remediation="Validate redirects against a whitelist "
                                        "of origins.")
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
        self.log(f"Found {len(tokens)} JWT tokens in the client.")

        for tok, src_url in tokens[:8]:
            ok, header, payload = _jwt_parts(tok)
            if not ok:
                continue
            parts = tok.split(".")
            alg = str(header.get("alg", "?")).upper()
            if alg == "NONE":
                self.register(
                    title="JWT with 'none' algorithm (forgeable without signature)",
                    description="The JWT declares alg=none; ifthe server accepts it, admin "
                                "tokens can be forged without a secret.",
                    severity=Severity.CRITICAL, cwe="CWE-347", owasp="A07:2021",
                    url=src_url, evidence=tok[:120] + "…",
                    remediation="Reject tokenswith alg=none; set an algorithm whitelist "
                                "(HS256/RS256) and verify signatures.")
                continue
            if isinstance(payload, dict):
                sensitive = [k for k in payload
                             if k in ("password", "secret", "card", "admin", "private")]
                if sensitive:
                    self.register(
                        title="JWT exposes sensitive claims in the client",
                        description="The visible token contains sensitive fields: " +
                                    ", ".join(sensitive) + ".",
                        severity=Severity.MEDIUM, cwe="CWE-922", owasp="A05:2021",
                        url=src_url, evidence=str(payload)[:200],
                        remediation="Do not put sensitive data in the JWT; use references "
                                    "by id or encrypt the claims.")
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
                            title="JWT signed with a weak HMAC secret(forgeable)",
                            description=f"El token usa {alg} con la clave trivial "
                                        f"'{secret}';the signature can be recomputedand "
                                        "admin tokens created.",
                            severity=Severity.CRITICAL, cwe="CWE-347", owasp="A07:2021",
                            url=src_url, evidence=tok[:120] + "…",
                            remediation="Use high-entropy secrets(≥32 bytes( and rotate "
                                        "the current key.")
                        break