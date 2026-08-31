"""Prueba acotada de credenciales por defecto en formularios de login.

SOLO para entornos de pruebas autorizados. Se activa explícitamente con
--fuzz-login. Realiza un número reducido de intentos (una lista corta de
credenciales por defecto conocidas), con pausas, y se detiene en el primer
éxito. No hace fuerza bruta masiva.
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
    description = "Credenciales por defecto en login (solo con --fuzz-login)"

    def run(self):
        if not self.ctx.config.run_fuzer:
            return  # nunca automático
        warn("FUZZER DE CREDENCIALES: ejecuta la lista por defecto; solo contra "
             "sistemas con autorización expresa.")
        logins = self.assets.get("login_forms", []) or []
        if not logins:
            logins = self._collect_logins()
        if not logins:
            info("No hay formularios de login detectados para probar.")
            return

        done = 0
        for entry in logins[:3]:
            if done >= 3:
                break
            url = entry.get("url") or entry.get("action") or ""
            action = entry.get("action") or url or ""
            if not action:
                continue
            # Solo probamos destinos del mismo origen (nunca enviamos credenciales a terceros)
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
                break  # ya hay un hallazgo crítico
            done += 1

    # ------------------------------------------------------------------ self-discovery
    def _collect_logins(self) -> list:
        """Busca formularios de login por su cuenta (rutas típicas)."""
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
                    title="Credenciales por defecto VÁLIDAS en el login",
                    description=f"El par '{user}/{pwd}' (credencial por defecto conocida) "
                                "inicia sesión en el sistema. Permite acceso directo como "
                                "usuario privilegiado si la cuenta lo es, comprometiendo "
                                "toda la aplicación.",
                    severity=Severity.CRITICAL, cwe="CWE-798", owasp="A07:2021",
                    url=action, evidence=f"{user} / {pwd} -> HTTP {resp.status}",
                    remediation="Cambia TODAS las credenciales por defecto, exige contraseñas "
                                "fuertes y MFA.")
                return True
            time.sleep(0.4)  # evita una ráfaga agresiva
        self.log("La lista de credenciales por defecto NO accedió al login.")
        return False