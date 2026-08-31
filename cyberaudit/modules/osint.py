"""Inteligencia pasiva externa (OSINT): exposición pública del objetivo.

Esto es lo que hace un equipo de ciberinteligencia antes de tocar el sistema:
- Consulta **Shodan InternetDB** (gratuito, sin API key) para cada IP del
  objetivo: puertos que han estado expuestos, CPEs ("productos" detectados),
  etiquetas y **CVEs conocidos** asociados.
- Detección de **WAF / CDN** del perímetro (Cloudflare, Incapsula/Imperva,
  Akamai, Sucuri, Vercel…) para entender qué hay entre el atacante y el origen.

Toda la información es pasiva (solo consultas a fuentes públicas). Nunca se
lanza tráfico contra el objetivo.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from typing import Dict, List, Optional
from urllib import request as http_request

from ..models import Severity
from ..utils import host_of, info
from .base import AuditModule

UA = "CyberAuditPro/2.0 (inteligencia pasiva autorizada; contacto profesional)"

# Cabeceras/cookies que delatan un WAF/CDN en el borde
WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "__cf_bm": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-cdn": "Incapsula (Imperva)",
    "x-iinfo": "Incapsula (Imperva)",
    "akamai-request-id": "Akamai",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-vercel-id": "Vercel",
    "x-vercel-cache": "Vercel",
    "x-litespeed-cache": "LiteSpeed",
}
WAF_COOKIES = {
    "incap_ses_": "Incapsula (Imperva)", "visid_incap_": "Incapsula (Imperva)",
    "ak_bmsc": "Akamai", "__cf_bm": "Cloudflare",
    "citrix_ns_id": "Citrix Netscaler", "_dd_s": "Datadog WAF",
}
WAF_BODY = [
    re.compile(r"cloudflare", re.I), re.compile(r"incapsula|imperva", re.I),
    re.compile(r"akamai", re.I), re.compile(r"sucuri", re.I),
    re.compile(r"request unsuccessful", re.I),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True


def _internetdb(ip: str) -> Optional[Dict]:
    """Consulta Shodan InternetDB (sin clave) sobre una IP pública."""
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        req = http_request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with http_request.urlopen(req, timeout=10) as resp:
            if resp.getcode() != 200:
                return None
            body = resp.read().decode("utf-8", "replace")
        data = json.loads(body)
        return {
            "ip": ip,
            "ports": [int(p) for p in data.get("ports", [])],
            "cpes": [str(c) for c in data.get("cpes", [])],
            "hostnames": [str(h) for h in data.get("hostnames", [])][:10],
            "tags": [str(t) for t in data.get("tags", [])][:10],
            "vulns": [str(v) for v in data.get("vulns", [])][:20],
        }
    except Exception:
        return None


class OsintModule(AuditModule):
    name = "osint"
    description = "Inteligencia pasiva externa (Shodan InternetDB, CVEs por IP, WAF)"

    def run(self):
        domain = host_of(self.ctx.target)
        if not domain:
            return
        # El análisis de WAF/CDN es 100% pasivo (cabeceras de la respuesta ya
        # descargada) y aplica a cualquier objetivo, incluso local.
        self._waf_detection()

        try:
            ipaddress.ip_address(domain)  # objetivo por IP
            if _is_private(domain):
                return  # InternetDB solo tiene sentido para IPs públicas
        except ValueError:
            pass  # dominio normal -> procedemos

        self._internet_exposure(domain)

    # ------------------------------------------------------------------ WAF/CDN
    def _waf_detection(self):
        base = self.ctx.base
        found = []
        for key_low, name in WAF_HEADERS.items():
            if base.header(key_low):
                found.append(name)
                break
        for c in self.ctx.http.cookies:
            for marker, name in WAF_COOKIES.items():
                if re.match(marker, c.name or ""):
                    found.append(name)
        if not found:
            sample = base.text.lower()
            for rx in WAF_BODY:
                if rx.search(sample):
                    found.append("posible WAF")
                    break
        if not found:
            return
        uniq = list(dict.fromkeys(found))
        self.assets["waf"] = uniq
        self.log("Perímetro detectado: " + ", ".join(uniq))
        if any(w in uniq for w in ("Cloudflare", "Incapsula (Imperva)", "Akamai")):
            self.register(
                title="WAF / CDN detectado en el borde",
                description="El tráfico pasa por un servicio de protección o aceleración: "
                            + ", ".join(uniq) + ". Verifica que no enmascare el origen "
                            "(bypass de WAF, DNS rebinding o fugas de IP real).",
                severity=Severity.INFO, cwe="CWE-0", owasp="", url=self.ctx.target,
                evidence="; ".join(uniq),
                remediation="Configura correctamente el WAF y evita que el origen sea "
                            "accesible directamente (allowlist de IPs del CDN/WAF).")

    # ------------------------------------------------------------------ InternetDB
    def _internet_exposure(self, domain: str):
        ips: List[str] = [str(i) for i in self.assets.get("dns", {}).get("A", [])]
        if not ips:
            try:
                ips = [res[4][0] for res in socket.getaddrinfo(domain, None)]
            except Exception:
                ips = []
        public = [ip for ip in dict.fromkeys(ips) if not _is_private(ip)][:6]
        if not public:
            return
        info("Consultando exposición pública en Shodan InternetDB…")
        exposure = []
        for ip in public:
            data = _internetdb(ip)
            if not data:
                continue
            exposure.append(data)
            self.log(f"InternetDB {ip}: {len(data['ports'])} puertos · "
                     f"{len(data['cpes'])} cpes · {len(data['vulns'])} cvEs")
        if not exposure:
            return
        self.assets["internet_exposure"] = exposure

        for data in exposure:
            vulns = data.get("vulns", [])
            if not vulns:
                continue
            ports = ", ".join(str(p) for p in data.get("ports", [])[:12]) or "desconocidos"
            self.register(
                title=f"IP {data['ip']} asociada a vulnerabilidades conocidas (internetDB)",
                description="Shodan InternetDB asocia CVEs públicos a esta IP según su "
                            "histórico de escaneos. Algunos pueden estar ya mitigados, "
                            "pero indican servicios/versiones que merecen revisión manual.",
                severity=Severity.CRITICAL if data.get("cpes") else Severity.HIGH,
                cwe="CWE-1035", owasp="A06:2021", url=self.ctx.target,
                evidence=f"IP {data['ip']} · puertos {ports}\n" + "\n".join(vulns[:12]),
                remediation="Haz inventario de los servicios de la IP, verifica versiones "
                            "reales y aplica los parches de los CVEs listados; oculta la IP "
                            "de origen si no necesita estar expuesta.")