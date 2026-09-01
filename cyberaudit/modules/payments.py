"""Payment flow analysis: gateways, secretsand business logic.

It detects:
- Pasarelas de pago usadas (Stripe, PayPal, MercadoPago, Redsys…).
- Claves públicas/secretas filtradas en el cliente (sk_live, pk_…, · secret).
- Cálculo de importes en JavaScript (vector clásico de manipulación de pago).
- Campos ocultos manipulables (precio, descuento, cantidad, envío).
- Checkout/payment endpointsand whether they go over HTTP or without CSRF.
Everything is passive/without modifying payment flows.
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
    description = "Payment gateways, leaked secretsand pricing logic"

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
            self.log("Gateways detected: " + ", ".join(found))
            for g in found[:4]:
                pass  # the presence of the gateway itself is not a finding

    def _detect_secrets(self, haystack):
        m = SECRET_KEY_RE.search(haystack)
        if m:
            self.register(
                title="Payment gateway SECRET key exposed in the client",
                description=f"Se encontró '{m.group(0)[:24]}…' en código visible al "
                            "browser. It is the server key: it allows creating charges, "
                            "refunds o reading operations ifit falls into third-party hands.",
                severity=Severity.CRITICAL, cwe="CWE-798", owasp="A07:2021",
                url=self.ctx.target, evidence=m.group(0)[:80],
                remediation="Rotate the key immediately, move it tothe backendand revoke it.")
            return
        m = GENERIC_SECRET_RE.search(haystack)
        if m:
            self.register(
                title="Possible payment integration secret in the client",
                description="Un valor con nombre de secreto de integración aparece en "
                            "HTML/JS cliente: client_secret, secret_key, firma…",
                severity=Severity.HIGH, cwe="CWE-798", owasp="A07:2021",
                url=self.ctx.target, evidence=m.group(0)[:120],
                remediation="Reviewandrotate the secret; keep these values only on the "
                            "server.")
        elif PUBLIC_KEY_RE.search(haystack):
            self.log("Public payment keys detected (pk_) — they are not secrets.")

    def _detect_client_prices(self, haystack):
        calc = PRICE_CALC_RE.findall(haystack)
        assign = CLIENT_PRICE_RE.findall(haystack)
        if calc:
            self.register(
                title="Payment amount calculation done in JavaScript",
                description="The price/amount is calculated in the client with operations "
                            "like 'price*qty' or 'total='. Ifthe server trusts the "
                            "received value, an attacker can change the total to 0.01 "
                            "or negativeand skip the payment gateway.",
                severity=Severity.CRITICAL if calc else Severity.HIGH,
                cwe="CWE-840", owasp="A01:2021", url=self.ctx.target,
                evidence=calc[0][:160],
                remediation="ALWAYS recalculate the amount on the server from stored "
                            "price; never trust the client total.")
        elif assign:
            self.register(
                title="Payment amount assignedin the client",
                description="Amount/total values are assignedin client code "
                            "and sent tothe server. Verify that the backend "
                            "recalculates them from DB.",
                severity=Severity.HIGH, cwe="CWE-840", owasp="A01:2021",
                url=self.ctx.target, evidence=assign[0][:160],
                remediation="Use server-side prices/catalogand validate quantitiesand "
                            "amount on the backend.")

    # ------------------------------------------------------------------ campos ocultos
    def _detect_hidden_fields(self, pages):
        for page in pages:
            html = self.assets.get("_bodies", {}).get(page["url"], "")
            m = HIDDEN_BIZ_RE.search(html)
            if m and self._seen("h|" + m.group(1) + "|" + page["url"]):
                self.register(
                    title=f"Manipulable hidden business field: '{m.group(1)}'",
                    description="The checkout includes a hidden input with a "
                                "price/amount/discount/quantity value that is sent tothe "
                                "server. Changing it in the client could alter "
                                "the charged total ifthere is no revalidation.",
                    severity=Severity.HIGH, cwe="CWE-840", owasp="A01:2021",
                    url=page["url"], evidence=m.group(0)[:200],
                    remediation="Do not use editable hidden fields for business; "
                                "recalculate amountand discounts on the server "
                                "from the authorized source.")

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
                        description="Checkout data travels unencrypted; cards, "
                                    "amountsand coupons are exposed to MITM.",
                        severity=Severity.CRITICAL, cwe="CWE-319", owasp="A02:2021",
                        url=url, evidence=f"action={action}",
                        remediation="Serve the payment endpoint exclusively over HTTPS.")
                # Sin token CSRF en el formulario de pago
                fields = form.get("fields", [])
                has_csrf = any(f.get("name") and re.search(
                    r"csrf|token|authenticity|xsrf", f.get("name", ""), re.I) for f in fields)
                if not has_csrf and self._seen("cs|" + url):
                    self.register(
                        title="Payment form without CSRF token",
                        description="The checkout does not include an anti-CSRF token; an "
                                    "attacker can force orders or billing data changes "
                                    "on behalf of the victim.",
                        severity=Severity.MEDIUM, cwe="CWE-352", owasp="A01:2021",
                        url=url, evidence=f"action={action}",
                        remediation="Add per-session CSRF tokensin the checkoutand validate "
                                    "them on the backend.")