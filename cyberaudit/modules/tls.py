"""Análisis del certificado TLS y de los protocolos SSL/TLS soportados."""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Optional

from ..models import Severity
from ..utils import host_of, info
from .base import AuditModule


def _flatten(rdns) -> dict:
    out: dict = {}
    for rdn in rdns:
        for k, v in rdn:
            out.setdefault(k, []).append(v)
    return {k: "+".join(v) for k, v in out.items()}


def _get_cert(host: str, port: int = 443, timeout: float = 8.0) -> Optional[dict]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ss:
                der = ss.getpeercert(True)
                pem = ssl.DER_cert_to_PEM_cert(der)
                cert = ss.getpeercert()
                data = {
                    "pem": pem,
                    "subject": _flatten(cert.get("subject", [])),
                    "issuer": _flatten(cert.get("issuer", [])),
                    "serial": cert.get("serialNumber", ""),
                    "notBefore": cert.get("notBefore", ""),
                    "notAfter": cert.get("notAfter", ""),
                    "san": [e[1] for e in cert.get("subjectAltName", [])],
                    "sig": cert.get("signatureAlgOID", ""),
                    "version": ss.version() or "",
                    "cipher": ss.cipher(),
                }
                return data
    except (ssl.SSLError, ssl.CertificateError, socket.timeout, TimeoutError,
            ConnectionRefusedError, ConnectionResetError, OSError, ValueError,
            IndexError):
        return None


def _probe_protocol(host: str, min_v, max_v, timeout: float = 5.0) -> str:
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = min_v
        ctx.maximum_version = max_v
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ss:
                return f"soportado ({ss.version()})"
    except ssl.SSLError:
        return "rechazado"
    except (socket.timeout, TimeoutError, ConnectionRefusedError,
            ConnectionResetError, OSError):
        return "no_accesible"
    except (ValueError, Exception):
        return "no_comprobable"


def _parse_gmt(gmt: str) -> Optional[datetime.datetime]:
    if not gmt:
        return None
    try:
        dt = datetime.datetime.strptime(gmt, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


class TLSModule(AuditModule):
    name = "tls"
    description = "Certificado digital y versiones de TLS"

    def run(self):
        host = host_of(self.ctx.target)
        if not host:
            return
        info("Analizando TLS y certificado…")
        cert = _get_cert(host)
        self.assets["tls"] = cert or {}
        if not cert:
            self.register(
                title="No se pudo obtener el certificado TLS",
                description="El handshake TLS falló o el puerto 443 no responde.",
                severity=Severity.MEDIUM, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target,
                remediation="Verifica la configuración del certificado en el servidor.")
            return
        self.log(f"Protocolo: {cert['version']} · Cipher: {cert['cipher']}")

        na = _parse_gmt(cert.get("notAfter", ""))
        now = datetime.datetime.now(datetime.timezone.utc)
        if na and na < now:
            self.register(
                title="Certificado EXPIRADO",
                description="El certificado caducó. Provoca errores de confianza y "
                            "rompe el cifrado para los usuarios.",
                severity=Severity.HIGH, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target, evidence=cert["notAfter"],
                remediation="Renueva el certificado inmediatamente.")
        elif na and na < now + datetime.timedelta(days=30):
            self.register(
                title="Certificado a punto de caducar",
                description="Caduca en menos de 30 días.",
                severity=Severity.MEDIUM, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target, evidence=cert["notAfter"],
                remediation="Renueva el certificado antes de la fecha de caducidad.")

        nb = _parse_gmt(cert.get("notBefore", ""))
        if nb and nb > now:
            self.register(
                title="Certificado con fecha de emisión futura",
                description="notBefore en el futuro; los clientes lo rechazarán.",
                severity=Severity.MEDIUM, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target,
                remediation="Reinstala un certificado con fecha válida.")

        # -------PART2-------

        san = [s.lower() for s in cert.get("san", [])]
        if host not in san:
            self.register(
                title="El certificado no cubre el dominio",
                description=f"El certificado tiene SAN={cert['san']} y no incluye a {host}.",
                severity=Severity.HIGH, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target,
                remediation="Regenera el certificado incluyendo el dominio en SAN.")

        if cert.get("subject") and cert["subject"] == cert.get("issuer"):
            self.register(
                title="Certificado autofirmado",
                description="El emisor y el sujeto coinciden: no es de confianza para usuarios "
                            "finales y facilita ataques MITM.",
                severity=Severity.MEDIUM, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target,
                remediation="Usa un certificado de una CA reconocida (Let's Encrypt, etc.).")

        self._probe_protocols(host)

    def _probe_protocols(self, host):
        results = {}
        for name, (min_v, max_v) in {
            "TLS 1.0": (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
            "TLS 1.1": (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
            "TLS 1.2": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
            "TLS 1.3": (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        }.items():
            results[name] = _probe_protocol(host, min_v, max_v)
        self.assets["tls"]["protocols"] = results
        supported = [n for n, r in results.items() if r.startswith("soportado")]
        weak = [n for n in supported if n in ("TLS 1.0", "TLS 1.1")]
        if weak:
            self.register(
                title="Protocolos TLS obsoletos soportados",
                description="Se permite negociar " + ", ".join(weak) + ", afectados por "
                            "BEAST, POODLE, Lucky13…",
                severity=Severity.HIGH, cwe="CWE-327", owasp="A02:2021",
                url=self.ctx.target,
                evidence="; ".join(f"{n}: {r}" for n, r in results.items()),
                remediation="Deshabilita TLS 1.0/1.1; exige TLS 1.2 como mínimo.")
        else:
            self.log("Protocolos: " + "; ".join(f"{n}={r}" for n, r in results.items()))
        if supported and supported[-1] not in ("TLS 1.2", "TLS 1.3"):
            self.log("Aviso: no se detectó TLS 1.2/1.3.")