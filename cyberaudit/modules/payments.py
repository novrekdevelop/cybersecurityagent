"""Análisis de flujo de pagos: pasarelas, secretos y lógica de negocio.

Detecta:
- Pasarelas de pago usadas (Stripe, PayPal, MercadoPago, Redsys…).
- Claves públicas/secretas filtradas en el cliente (sk_live, pk_…, · secret).
- Cálculo de importes en JavaScript (vector clásico de manipulación de pago).
- Campos ocultos manipulables (precio, descuento, cantidad, envío).
- Endpoints de checkout/pago y si van por HTTP o sin CSRF.
Todo es pasivo/sin modificar flujos de pago.
"""

from __future__ import annotations

import re
from typing import List, Set

from ..models import Severity
from ..utils import info
from .base import AuditModule

# Detección de pasarelas por marcas en HTML/JS
GATEWAY_PATTERNS = {
    "Stripe": re.compile(r"stripe\.js|stripe\.com|pk_(live|test)_|sk_(live|test)_|\bstripe\b", re.I),
    "PayPal": re.compile(r"paypalobjects\.com|paypal\.com|\bpaypal\b", re.I),
    "MercadoPago": re.compile(r"mercadopago|mercadopagoads\.com", re.I),
    "Redsys/Sermepa": re.compile(r"(?i)redsys|sermepa|tpv|\bdsmerchantparameters\b|Redsys"),
    "Sabadell/Paycomet": re.compile(r"paycomet|paytpv|sabadell", re.I),
    "Braintree": re.compile(r"braintreepayments\.com|\bbraintree\b", re.I),
    "Adyen": re.compile(r"adyen\.com|\badyen\b", re.I),
    "Klarna": re.compile(r"klarna\.com|\bklarna\b", re.I),
    "Razorpay": re.compile(r"razorpay\.com|\brazorpay\b", re.I),
    "Square": re.compile(r"squareup\.com|js\.square|\bsquare\b", re.I),
    "Apple Pay": re.compile(r"applepay|apple-pay|\bapple pay\b", re.I),
    "Google Pay": re.compile(r"googlepay|google-pay|\bgoogle pay\b", re.I),
    "Bizum": re.compile(r"\bbizum\b|bizum\.com", re.I),
}

# Secretos de pasarela (clave secreta de servidor caída en el cliente)
SECRET_KEY_RE = re.compile(
    r"\b(sk|rk|whsec|ra|rzp_live|whsec_|rzp_test)_(live|test)_[0-9A-Za-z]{16,}\b")
PUBLIC_KEY_RE = re.compile(r"\b(pk_live|pk_test|rzp_live|rzp_test)_[0-9A-Za-z_]{16,}\b")
GENERIC_SECRET_RE = re.compile(
    r"(?i)(client_secret|secret_key|api_secret|merchant_secret|hoo?k|"
    r"private_key|signature[_-]?key)\s*[:=]\s*['\"][^'\"]{12,}['\"]")

# Importes calculados o asignados en el cliente
CLIENT_PRICE_RE = re.compile(
    r"(?i)(total|subtotal|amount|importe|precio|price|cost|coste)"
    r"\s*[:=]\s*[-+]?\s*\(?[^;]{0,80}?(?:qty|quantity|cantidad|unit|precio|price)"
    r"[^;]{0,80}?")
PRICE_CALC_RE = re.compile(
    r"(?i)(precio\s*\*\s*cantidad|price\s*\*\s*quantity|qty\s*\*\s*precio|"
    r"unit\s*\*\s*qty|total\s*=\s*[^;]*\*|subtotal\s*=\s*[^;]*\*)")

# Endpoints de checkout/pago
CHECKOUT_PATH_RE = re.compile(
    r"(/checkout|/cart|/carrito|/pago|/pay|/payment|/order|/orden|/orders|"
    r"/confirm|/confirmar|/buy|/comprar|/purchase|/finalizar|/merchant)", re.I)

HIDDEN_BIZ_RE = re.compile(
    r'<input[^>]+type=["\']?hidden["\']?[^>]+name=["\']'
    r'(price|precio|amount|importe|total|subtotal|discount|descuento|coupon|'
    r'cupon|quantity|qty|cantidad|shipping|envio|tax|impuesto|currency|divisa)["\']',
    re.I)


class PaymentsModule(AuditModule):
    name = "payments"
    description = "Pasarelas de pago, secretos filtrados y lógica de precios"

    def run(self):
        self._seen_keys: Set[str] = set()
        texts = list(self.assets.get("_bodies", {}).values())
        for rec in self.assets.get("js_analyzed", []):
            texts.append(rec.get("content", ""))
        haystack = "\n".join(t for t in texts if t)[:2_000_000]
        pages = self.assets.get("pages_analyzed", [])

        self._detect_gateways(haystack)
        self._detect_secrets(haystack)
        self._detect_client_prices(haystack)
        self._detect_hidden_fields(pages)
        self._detect_checkout(pages)

    # -------PART2-------

    def _detect_gateways(self, haystack):
        found = [g for g, rx in GATEWAY_PATTERNS.items() if rx.search(haystack)]
        self.assets["payment_gateways"] = found
        if found:
            self.log("Pasarelas detectadas: " + ", ".join(found))
            for g in found[:4]:
                pass  # la presencia de la pasarela en sí no es un hallazgo

    def _detect_secrets(self, haystack):
        m = SECRET_KEY_RE.search(haystack)
        if m:
            self.register(
                title="Clave SECRETA de pasarela de pago expuesta en el cliente",
                description=f"Se encontró '{m.group(0)[:24]}…' en código visible al "
                            "navegador. Es la clave de servidor: permite crear cobros, "
                            "reembolsos o leer operaciones si se cae en manos de terceros.",
                severity=Severity.CRITICAL, cwe="CWE-798", owasp="A07:2021",
                url=self.ctx.target, evidence=m.group(0)[:80],
                remediation="Rota la clave inmediatamente, muévela al backend y revócala.")
            return
        m = GENERIC_SECRET_RE.search(haystack)
        if m:
            self.register(
                title="Posible secreto de integración de pago en el cliente",
                description="Un valor con nombre de secreto de integración aparece en "
                            "HTML/JS cliente: client_secret, secret_key, firma…",
                severity=Severity.HIGH, cwe="CWE-798", owasp="A07:2021",
                url=self.ctx.target, evidence=m.group(0)[:120],
                remediation="Revisa y rota el secreto; mantén estos valores solo en el "
                            "servidor.")
        elif PUBLIC_KEY_RE.search(haystack):
            self.log("Se detectaron claves públicas de pago (pk_) — no son secretas.")

    def _detect_client_prices(self, haystack):
        calc = PRICE_CALC_RE.findall(haystack)
        assign = CLIENT_PRICE_RE.findall(haystack)
        if calc:
            self.register(
                title="Cálculo de importe de pago realizado en JavaScript",
                description="El precio/importe se calcula en el cliente con operaciones "
                            "como 'precio*qty' o 'total='. Si el servidor confía en el "
                            "valor recibido, un atacante puede cambiar el total a 0.01 "
                            "o negativo y saltarse la pasarela de pago.",
                severity=Severity.CRITICAL if calc else Severity.HIGH,
                cwe="CWE-840", owasp="A01:2021", url=self.ctx.target,
                evidence=calc[0][:160],
                remediation="Recalcula SIEMPRE el importe en el servidor desde precio "
                            "almacenado; nunca confíes en el total del cliente.")
        elif assign:
            self.register(
                title="Importe del pago asignado en el cliente",
                description="Se asignan valores de importe/total en código de cliente "
                            "que se envían al servidor. Verifica que el backend los "
                            "recalcule desde BD.",
                severity=Severity.HIGH, cwe="CWE-840", owasp="A01:2021",
                url=self.ctx.target, evidence=assign[0][:160],
                remediation="Usa precios/catálogo del servidor y valida cantidades e "
                            "importe en el backend.")

    # ------------------------------------------------------------------ campos ocultos
    def _detect_hidden_fields(self, pages):
        for page in pages:
            html = self.assets.get("_bodies", {}).get(page["url"], "")
            m = HIDDEN_BIZ_RE.search(html)
            if m and self._seen("h|" + m.group(1) + "|" + page["url"]):
                self.register(
                    title=f"Campo oculto de negocio manipulable: '{m.group(1)}'",
                    description="El checkout incluye un input hidden con un valor de "
                                "precio/importe/descuento/cantidad que se envía al "
                                "servidor. Cambiándolo en el cliente podría alterarse "
                                "el total cobrado si no hay revalidación.",
                    severity=Severity.HIGH, cwe="CWE-840", owasp="A01:2021",
                    url=page["url"], evidence=m.group(0)[:200],
                    remediation="No uses campos ocultos editables para negocio; "
                                "recalcula importe y descuentos en el servidor "
                                "desde la fuente autorizada.")

    def _seen(self, key: str) -> bool:
        if key in self._seen_keys:
            return False
        self._seen_keys.add(key)
        return True

    # ------------------------------------------------------------------ checkout endpoints
    def _detect_checkout(self, pages):
        found = []
        for page in pages:
            if CHECKOUT_PATH_RE.search(page.get("url", "")) and page.get("status") in (200,):
                found.append(page)
        self.assets["payment_endpoints"] = [p["url"] for p in found[:20]]
        if not found:
            return
        self.log(f"Endpoints de pago/checkout: {len(found)}")
        for page in found[:3]:
            url = page["url"]
            secure = url.startswith("https://")
            for form in page.get("forms", []):
                action = form.get("action", "")
                if action.startswith("http://") and secure:
                    self.register(
                        title="Envío de datos de pago por HTTP (en claro)",
                        description="Los datos del checkout viajan sin cifrar; tarjetas, "
                                    "importes y cupones quedan expuestos a MITM.",
                        severity=Severity.CRITICAL, cwe="CWE-319", owasp="A02:2021",
                        url=url, evidence=f"action={action}",
                        remediation="Sirve el endpoint de pago exclusivamente por HTTPS.")
                # Sin token CSRF en el formulario de pago
                fields = form.get("fields", [])
                has_csrf = any(f.get("name") and re.search(
                    r"csrf|token|authenticity|xsrf", f.get("name", ""), re.I) for f in fields)
                if not has_csrf and self._seen("cs|" + url):
                    self.register(
                        title="Formulario de pago sin token CSRF",
                        description="El checkout no incluye token anti-CSRF; un atacante "
                                    "puede forzar pedidos o cambios de datos de facturación "
                                    "en nombre de la víctima.",
                        severity=Severity.MEDIUM, cwe="CWE-352", owasp="A01:2021",
                        url=url, evidence=f"action={action}",
                        remediation="Añade tokens CSRF por sesión en el checkout y valida "
                                    "en el backend.")