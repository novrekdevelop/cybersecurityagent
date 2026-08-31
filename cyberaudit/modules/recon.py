"""Reconocimiento pasivo: DNS, RDAP (WHOIS), subdominios y huella tecnológica."""

from __future__ import annotations

import json
import re
import socket
import ssl
from typing import Dict, List, Optional, Set
from urllib import request as http_request

from ..models import Finding, Severity
from ..utils import COMMON_SUBDOMAINS, absolute, host_of, info, warn
from .base import AuditModule

UA = "CyberAuditPro/2.0 (reconocimiento pasivo autorizado)"


def _doh(domain: str, rtype: str) -> List[str]:
    """Consulta DNS sobre HTTPS (Cloudflare) — pasivo y sin binarios externos."""
    _, answers = _doh_lookup(domain, rtype)
    return answers


def _doh_lookup(domain: str, rtype: str):
    """Devuelve (Status, respuestas) de una consulta DoH JSON."""
    url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}"
    type_map = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "TXT": 16, "NS": 2}
    try:
        req = http_request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": UA})
        with http_request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        status = int(data.get("Status", 0))
        answers = [str(a.get("data", "")) for a in data.get("Answer", [])
                   if a.get("type") == type_map.get(rtype)]
        return status, answers
    except Exception:
        return 2, []


def _local_dns(domain: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []}
    try:
        seen = set()
        for info_ in socket.getaddrinfo(domain, None):
            ip = info_[4][0]
            if ip not in seen:
                seen.add(ip)
                key = "AAAA" if ":" in ip else "A"
                out[key].append(ip)
    except Exception:
        pass
    return out


def _dns_records(domain: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []}
    try:
        seen = set()
        for info_ in socket.getaddrinfo(domain, None):
            ip = info_[4][0]
            if ip not in seen:
                seen.add(ip)
                key = "AAAA" if ":" in ip else "A"
                out[key].append(ip)
    except Exception:
        pass
    for rtype in ("CNAME", "MX", "NS", "TXT"):
        out[rtype] = _doh(domain, rtype)
    return out


def _rdap(domain: str) -> Dict:
    """Datos de registro de dominio vía RDAP (sustituye a WHOIS clásico)."""
    url = f"https://rdap.org/domain/{domain}"
    try:
        req = http_request.Request(url, headers={"Accept": "application/rdap+json", "User-Agent": UA})
        with http_request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return {}


def _crt_sh(domain: str) -> List[str]:
    """Subdominios vía transparencia de certificados (crt.sh)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = http_request.Request(url, headers={"Accept": "application/json", "User-Agent": UA})
        ctx = ssl.create_default_context()
        with http_request.urlopen(req, timeout=10, context=ctx) as resp:
            raw = resp.read()
        data = json.loads(raw.decode("utf-8", "replace"))
        names: Set[str] = set()
        for entry in data:
            for n in str(entry.get("name_value", "")).split("\n"):
                n = n.strip().lstrip("*.")
                low = n.lower()
                if low == domain or (low.endswith("." + domain) and low.count(".") <= 3):
                    names.add(low)
        return sorted(names)
    except Exception:
        return []


TECH_SIGNATURES: Dict[str, dict] = {
    "WordPress": {"checks": [("body", r"wp-content|wp-includes|wp-json", 8), ("cookie", "wordpress", 6), ("meta", "generator.*WordPress", 7)]},
    "WooCommerce": {"checks": [("body", r"woocommerce", 8)]},
    "Joomla": {"checks": [("meta", "generator.*Joomla", 8), ("body", r"/media/system/js/", 6)]},
    "Drupal": {"checks": [("body", r"sites/default/files|drupal-settings-json", 7)]},
    "Magento": {"checks": [("cookie", "mage-cache", 7), ("body", r"static/version|Magento", 4)]},
    "PrestaShop": {"checks": [("body", r"prestashop", 8)]},
    "Shopify": {"checks": [("header", "x-shopid", 8), ("body", r"cdn\.shopify\.com", 6)]},
    "Wix": {"checks": [("body", r"wix\.com", 6)]},
    "Django": {"checks": [("cookie", "csrftoken", 7), ("body", r"csrfmiddlewaretoken", 7)]},
    "Laravel": {"checks": [("cookie", "laravel_session", 8), ("cookie", "XSRF-TOKEN", 7)]},
    "Symfony": {"checks": [("header", "x-debug-token", 8)]},
    "Ruby on Rails": {"checks": [("header", "x-powered-by.Phusion", 5), ("header", "x-runtime", 4)]},
    "Express/Node": {"checks": [("header", "x-powered-by", 3)]},
    "Next.js": {"checks": [("body", r"__NEXT_DATA__", 8), ("body", r"/_next/static", 7)]},
    "Nuxt": {"checks": [("body", r"__NUXT__", 8)]},
    "Gatsby": {"checks": [("body", r"___gatsby", 8)]},
    "Vue.js": {"checks": [("body", r"data-v-[0-9a-f]{8}", 5)]},
    "Angular": {"checks": [("body", r"ng-version|ng-app", 6)]},
    "jQuery": {"checks": [("body", r"jquery(\.min)?\.js", 6)]},
    "Bootstrap": {"checks": [("body", r"bootstrap\.(min\.)?(css|js)", 6)]},
    "Tailwind CSS": {"checks": [("body", r"tailwind|--tw-", 5)]},
    "ASP.NET": {"checks": [("header", "x-aspnet-version", 8), ("cookie", "ASP.NET_SessionId", 7), ("cookie", "__RequestVerificationToken", 7)]},
    "ASP.NET Core": {"checks": [("cookie", ".AspNetCore", 7)]},
    "PHP": {"checks": [("cookie", "PHPSESSID", 8), ("header", "x-powered-by.PHP", 6)]},
    "Java / Spring": {"checks": [("cookie", "JSESSIONID", 6), ("header", "x-application-context", 7)]},
    "Apache Tomcat": {"checks": [("header", "apache-coyote", 7)]},
    "Nginx": {"checks": [("header", "server.nginx", 7)]},
    "Apache HTTP": {"checks": [("header", "server.*apache", 6)]},
    "LiteSpeed": {"checks": [("header", "server.litespeed", 7)]},
    "IIS (Microsoft)": {"checks": [("header", "server.microsoft-iis", 8)]},
    "Caddy": {"checks": [("header", "server.caddy", 7)]},
    "Cloudflare": {"checks": [("header", "cf-ray", 8), ("header", "server.cloudflare", 8)]},
    "Amazon CloudFront": {"checks": [("header", "x-amz-cf-id", 8)]},
    "AWS (S3/ALB)": {"checks": [("header", "x-amz-request-id", 7), ("body", r"s3\.amazonaws\.com|s3-website", 6)]},
    "Azure (CDN/App)": {"checks": [("header", "x-ms-request-id", 7)]},
    "Google Cloud": {"checks": [("header", "x-goog-", 6)]},
    "Varnish": {"checks": [("header", "x-varnish", 6)]},
    "Fastly": {"checks": [("header", "fastly", 5), ("header", "x-served-by", 4)]},
    "Akamai": {"checks": [("header", "x-akamai-transformed", 7)]},
    "Sucuri WAF": {"checks": [("header", "x-sucuri-id", 6)]},
    "AWS WAF / CloudFront": {"checks": [("header", "x-amzn-trace-id", 7), ("header", "x-amz-cf-id", 6)]},
    "ModSecurity": {"checks": [("header", "x-modsec", 8)]},
    "Imperva (Incapsula)": {"checks": [("header", "x-cdn", 4), ("header", "x-request-id", 5)]},
    "F5 BIG-IP": {"checks": [("header", "x-ssl-server", 7), ("header", "server.bigip", 8)]},
    "Barracuda WAF": {"checks": [("header", "barracuda", 8)]},
    "FortiWeb": {"checks": [("header", "x-forti", 7), ("header", "server.fortiweb", 8)]},
    "GitHub Pages": {"checks": [("header", "server.github.com", 8)]},
    "Netlify": {"checks": [("header", "server.netlify", 8)]},
    "Vercel": {"checks": [("header", "x-vercel-id", 8)]},
    "Heroku": {"checks": [("header", "via.*vegur", 7)]},
    "OpenResty": {"checks": [("header", "server.openresty", 8)]},
    "Gunicorn": {"checks": [("header", "server.gunicorn", 7)]},
    "Google Analytics": {"checks": [("body", r"googletagmanager|gtag\(|UA-\d{4,}", 5)]},
    "Meta Pixel": {"checks": [("body", r"connect\.facebook\.net|fbq\(", 6)]},
    "Matomo": {"checks": [("body", r"matomo|piwik", 5)]},
    "Hotjar": {"checks": [("body", r"static\.hotjar\.com", 6)]},
    "reCAPTCHA": {"checks": [("body", r"google\.com/recaptcha|grecaptcha", 6)]},
    "hCaptcha": {"checks": [("body", r"hcaptcha\.com", 6)]},
    "Stripe": {"checks": [("body", r"js\.stripe\.com|stripe\.js", 7)]},
    "PayPal": {"checks": [("body", r"paypalobjects\.com", 5)]},
    "MercadoPago": {"checks": [("body", r"mercadopago|sdk\.mercadopago", 6)]},
    "Firebase": {"checks": [("body", r"firebaseapp\.com|firebase", 5)]},
}

SENSITIVE_SUBDOMAIN_KEYWORDS = ("admin", "vpn", "git", "jenkins", "grafana", "phpmyadmin",
                                "db", "database", "mysql", "redis", "backup", "staging",
                                "test", "dev", "internal", "portal", "secret", "intranet",
                                "external", "sftp", "gateway", "console", "dashboard")

# Servicios cuya falta de reserva permite "secuestrar" un subdominio (CNAME colgante)
TAKEOVER_APEXES = (
    "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net", "azurefd.net",
    "cloudapp.net", "trafficmanager.net", "blob.core.windows.net",
    "herokudns.com", "herokussl.com", "herokuapp.com", "github.io",
    "netlify.app", "vercel.app", "now.sh", "zendesk.com", "readthedocs.io",
    "cargocollective.com", "pantheonsite.io", "wpengine.com", "fastly.net",
    "ghost.io", "surge.sh", "bitbucket.io", "appspot.com", "firebaseapp.com",
    "myshopify.com", "pages.dev", "workers.dev", "gitbook.io", "helpjuice.com",
    "statuspage.io", "freshdesk.com", "webflow.io", "surge.surge", "bitbucket.io",
)

class ReconModule(AuditModule):
    name = "recon"
    description = "Reconocimiento pasivo: DNS, registro y huella tecnológica"

    def run(self):
        url = self.ctx.target
        domain = host_of(url)
        local = self._is_local(domain)

        # -- DNS ----------------------------------------------------------------------
        info("Resolviendo registros DNS…")
        dns = _local_dns(domain) if local else _dns_records(domain)
        self.assets["dns"] = dns
        if dns.get("A"):
            self.log(f"IPs IPv4: {', '.join(dns['A'])}")
        if dns.get("AAAA"):
            self.log(f"IPv6: {', '.join(dns['AAAA'])}")

        if not local:
            txt_raw = " ".join(dns.get("TXT", [])).lower()
            missing_mail = []
            if "spf1" not in txt_raw:
                missing_mail.append("SPF")
            if "v=dmarc" not in txt_raw and not self._has_dmarc(domain):
                missing_mail.append("DMARC")
            if txt_raw.strip() and "dkim" not in txt_raw:
                missing_mail.append("DKIM")
            if missing_mail and domain.count(".") >= 1:
                self.register(
                    title="Políticas de autenticación de correo ausentes",
                    description="No se encontraron: " + ", ".join(missing_mail) + ". "
                                "Un atacante podría suplantar este dominio en correos (spoofing).",
                    severity=Severity.LOW, cwe="CWE-172", owasp="A04:2021",
                    evidence=f"Registros TXT: {txt_raw[:200] or '(ninguno)'}",
                    remediation=f"Publica SPF, DKIM y DMARC para {domain}.", url=url)

            # -- RDAP / WHOIS -----------------------------------------------------------
            info("Consultando WHOIS/RDAP…")
            rdap = _rdap(domain)
            self.assets["rdap"] = {
                "handle": rdap.get("handle", ""),
                "events": [f"{ev.get('eventAction','')}: {ev.get('eventDate','')}"
                           for ev in rdap.get("events", [])][:6],
                "status": rdap.get("status", []),
                "nameservers": [n.get("ldhName", "") for n in rdap.get("nameservers", [])],
            }

            # -- Subdominios -------------------------------------------------------------
            if self.ctx.config.enumerate_subdomains or self.ctx.config.common_subdomains:
                self._find_subdomains(domain)

        self._fingerprint()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _is_local(domain: str) -> bool:
        return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain)) or domain == "localhost"

    def _has_dmarc(self, domain: str) -> bool:
        return bool(_doh("_dmarc." + domain, "TXT"))

    def _find_subdomains(self, domain: str):
        known: Set[str] = set()
        if self.ctx.config.enumerate_subdomains:
            info("Consultando transparencia de certificados (crt.sh)…")
            known.update(_crt_sh(domain))
        if self.ctx.config.common_subdomains:
            info("Comprobando wordlist de subdominios comunes…")
            for name in COMMON_SUBDOMAINS:
                if len(known) >= 250:
                    break
                try:
                    socket.getaddrinfo(f"{name}.{domain}", 80)
                    known.add(f"{name}.{domain}")
                except Exception:
                    pass

        found = sorted(known)
        self.assets["subdomains"] = found
        if not found:
            self.log("No se hallaron subdominios mediante transparencia de certificados.")
            return
        self.log(f"Se hallaron {len(found)} subdominios.")

        self._check_takeover(found)
        sensitive = [s for s in found if any(k in s.split(".")[0] for k in SENSITIVE_SUBDOMAIN_KEYWORDS)]
        if sensitive:
            self.register(
                title="Subdominios potencialmente sensibles expuestos",
                description="Subdominios cuyo nombre sugiere servicios internos, paneles o "
                            "entornos de prueba: " + ", ".join(sensitive[:10]),
                severity=Severity.MEDIUM, cwe="CWE-200", owasp="A01:2021",
                url=self.ctx.target, evidence="\n".join(sensitive[:10]),
                remediation="Revisa que no estén expuestos servicios sensibles, requieran "
                            "autenticación y aparezcan en el inventario de activos.",
            )

    # ------------------------------------------------------------------ takeover
    def _check_takeover(self, subdomains):
        from ..utils import host_of
        root = host_of(self.ctx.target)
        at_risk = []
        for s in subdomains[:40]:
            if s.lower().rstrip(".") == root.lower():
                continue  # el dominio raíz se comprueba por separado
            try:
                _, cnames = _doh_lookup(s, "CNAME")
            except Exception:
                continue
            cname_take = next((c for c in cnames if any(
                c.lower().rstrip(".").endswith(apex) for apex in TAKEOVER_APEXES)), None)
            if not cname_take:
                continue
            # Confirma el "dangling": sin registro A/AAAA propio que resuelva
            if self._resolves(s):
                continue
            at_risk.append({"subdomain": s, "cname": cname_take})

        if at_risk:
            self.assets["takeover_candidates"] = at_risk
            self.register(
                title="Subdominios secuestrables (subdomain takeover)",
                description="Estos subdominios tienen un CNAME hacia un servicio externo "
                            "que ya no está asignado (registro DNS colgante). Un atacante "
                            "puede reclamarlo, publicar contenido en el dominio y robar "
                            "cookies/sesión o hacer phishing sin levantar sospechas.",
                severity=Severity.HIGH, cwe="CWE-350", owasp="A05:2021",
                url=self.ctx.target,
                evidence="\n".join(f"{a['subdomain']} -> {a['cname']}" for a in at_risk),
                remediation="Elimina los CNAME huérfanos o reapunta el DNS a un recurso "
                            "real bajo tu control. Supervisa los CNAMEs de tus subdominios.")

    @staticmethod
    def _resolves(host: str) -> bool:
        try:
            socket.getaddrinfo(host, None)
            return True
        except socket.gaierror:
            return False

    # ------------------------------------------------------------------ fingerprint
    def _fingerprint(self):
        base = self.ctx.base
        body = base.text[:300_000]
        headers = [(k, v) for k, v in base.header_items]
        cookie_names = {c.name for c in self.ctx.http.cookies}
        meta = " ".join(re.findall(
            r'<meta[^>]+(?:name|property)=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            body, re.I))

        found = []
        for tech, spec in TECH_SIGNATURES.items():
            score = 0
            evidences = []
            for kind, pattern, weight in spec["checks"]:
                is_found = False
                if kind == "header":
                    rx = re.compile(pattern, re.I)
                    for key, val in headers:
                        if rx.search(val):
                            is_found = True
                            evidences.append(f"{key}: {val[:60]}")
                            break
                elif kind == "cookie":
                    for cname in cookie_names:
                        if pattern.lower() in cname.lower():
                            is_found = True
                            evidences.append(f"cookie {cname}")
                            break
                elif kind == "meta":
                    if meta and re.search(pattern, meta, re.I):
                        is_found = True
                        evidences.append(f"meta generator: {meta[:60]}")
                elif kind == "body":
                    if re.search(pattern, body, re.I):
                        is_found = True
                        evidences.append("marcador en HTML/JS")
                if is_found:
                    score += weight
            if score >= 7:
                found.append({"name": tech, "confidence": min(95, score * 6),
                             "evidence": evidences[:3]})

        found.sort(key=lambda f: -f["confidence"])
        self.assets["tech"] = found
        if found:
            self.log("Tecnologías detectadas: " + ", ".join(f["name"] for f in found))
        else:
            self.log("No se identificaron tecnologías conocidas.")