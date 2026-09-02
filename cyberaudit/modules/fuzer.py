"""Bounded test of default credentials in login forms.

ONLY for authorized testing environments. It is explicitly activated with
--fuzz-login. It runs a reduced number of attempts (a short list of
known default credentials), with pauses, and stops at the first
success. No massive brute force.
"""

from __future__ import annotations

import re
import time
from typing import Dict, Optional
from urllib.parse import urlencode, urljoin

from ..models import Severity
from ..utils import info, same_origin, warn
from .base import AuditModule
from .content import SiteParser

DEFAULT_PASSWORDS = [
    ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
    ("admin", "admin123"), ("admin", "changeme"), ("admin", "12345678"),
    ("admin", "administrator"), ("root", "root"), ("root", "toor"),
    ("root", "123456"), ("test", "test"), ("test", "test123"),
    ("user", "user"), ("user", "password"), ("developer", "developer"),
    ("guest", "guest"), ("demo", "demo"), ("operador", "operador"),
    ("soporte", "soporte"), ("usuario", "usuario"), ("manager", "manager"),
    ("admin", "1234"), ("admin", "12345"), ("admin", "123456789"),
]

SUCCESS_MARKERS = ("logout", "dashboard", "bienvenid", "welcome", "panel",
                   "perfil", "mi cuenta", "sesión iniciada", "sesion iniciada",
                   "account", "iniciar sesión")
FAIL_MARKERS = ("invalid", "incorrecta", "incorrecto", "no valido",
                "no válido", "credenciales", "fallo", "denegado",
                "no existe", "error de autenticación", "contraseña incorrecta",
                "password incorrect")


class FuzzerModule(AuditModule):
    name = "fuzzer"
    description = "Default credentials on login (only with --fuzz-login)"

    def run(self):
        if not self.ctx.config.run_fuzer:
            return  # nunca automático
        warn("CREDENTIAL FUZZER: runs the default list; only against "
             "systems with express authorization.")
        logins = self.assets.get("login_forms", []) or []
        if not logins:
            logins = self._collect_logins()
        if not logins:
            info("No login forms detected to test.")
            return

        done = 0
        for entry in logins[:3]:
            if done >= 3:
                break
            url = entry.get("url") or entry.get("action") or ""
            action = entry.get("action") or url or ""
            if not action:
                continue
            # We only probe same-origin destinations(we never send credentials to third parties)
            if not same_origin(action, self.ctx.target):
                continue
            form = self._find_login_form(action)
            if not form:
                continue
            fields = {f.get("name", ""): f.get("value", "") for f in form.get("fields", [])}
            user_field = next((k for k in fields if k and "pass" not in k.lower() and
                               "token" not in k.lower() and "csrf" not in k.lower()), None)
            pass_field = next((k for k, v in fields.items() if k and "pass" in k.lower()), None)
            if not user_field or not pass_field:
                continue
            hidden = {k: v for k, v in fields.items() if k not in (user_field, pass_field)}
            found = self._test_defaults(action, user_field, pass_field, hidden)
            if found:
                break  # already a critical finding
            done += 1

    # ------------------------------------------------------------------ self-discovery
    def _collect_logins(self) -> list:
        """Finds login forms by their URL (typical routes)."""
        from urllib.parse import urljoin
        from ..utils import origin_of
        origin = origin_of(self.ctx.target)
        found = []
        for path in ("/login", "/admin", "/signin", "/acceso", "/administracion"):
            url = urljoin(origin + "/", path.lstrip("/"))
            form = self._find_login_form(url)
            if form:
                found.append({"url": url, "action": form.get("action") or url,
                              "method": form.get("method", "GET")})
                break
        return found

    # ------------------------------------------------------------------ helpers
    def _find_login_form(self, url: str) -> Optional[Dict]:
        resp = self.ctx.http.get(url)
        if resp.status != 200 or not resp.body:
            return None
        parser = SiteParser(url)
        try:
            parser.feed(resp.text)
        except Exception:
            return None
        for form in parser.forms:
            if any(f.get("type") == "password" for f in form.get("fields", [])):
                return form
        return None

    def _test_defaults(self, action, user_field, pass_field, hidden) -> bool:
        http = self.ctx.http
        for idx, (user, pwd) in enumerate(DEFAULT_PASSWORDS):
            payload = dict(hidden)
            payload[user_field] = user
            payload[pass_field] = pwd
            try:
                resp = http.post(action, data=urlencode(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
            except Exception:
                continue
            text = resp.text
            low = text.lower()
            succ = [m for m in SUCCESS_MARKERS if m in low]
            fail = [m for m in FAIL_MARKERS if m in low]
            success = bool(succ) and not fail
            if success:
                self.register(
                    title="Valid default credentials found on the login",
                    description=f"The pair '{user}/{pwd}' (known default credential) "
                                "logs into the system. It allows direct access as "
                                "a privileged user if the account is one, compromising "
                                "the entire application.",
                    severity=Severity.CRITICAL, cwe="CWE-798", owasp="A07:2021",
                    url=action, evidence=f"{user} / {pwd} -> HTTP {resp.status}",
                    remediation="Change ALL default credentials, require strong "
                                "passwords and MFA.")
                return True
            time.sleep(0.4)  # evita una ráfaga agresiva
        self.log("The default credential list did NOT access the login.")
        return False