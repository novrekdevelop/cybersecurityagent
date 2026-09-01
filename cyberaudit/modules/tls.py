"""Analysis of the TLS certificate and supported SSL/TLS protocols."""

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
                return f"supported ({ss.version()})"
    except ssl.SSLError:
        return "rejected"
    except (socket.timeout, TimeoutError, ConnectionRefusedError,
            ConnectionResetError, OSError):
        return "not_reachable"
    except (ValueError, Exception):
        return "not_testable"


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
    description = "Digital certificate and TLS versions"

    def run(self):
        host = host_of(self.ctx.target)
        if not host:
            return
        info("Analyzing TLS and certificate…")
        cert = _get_cert(host)
        self.assets["tls"] = cert or {}
        if not cert:
            self.register(
                title="Could not obtain the TLS certificate",
                description="The TLS handshake failed or port 443 does not respond.",
                severity=Severity.MEDIUM, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target,
                remediation="Verify the certificate configuration on the server.")
            return
        self.log(f"Protocol: {cert['version']} · Cipher: {cert['cipher']}")

        na = _parse_gmt(cert.get("notAfter", ""))
        now = datetime.datetime.now(datetime.timezone.utc)
        if na and na < now:
            self.register(
                title="Certificate EXPIRED",
                description="The certificate has expired. It causes trust errors and "
                            "breaks encryption for users.",
                severity=Severity.HIGH, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target, evidence=cert["notAfter"],
                remediation="Renew the certificate immediately.")
        elif na and na < now + datetime.timedelta(days=30):
            self.register(
                title="Certificate about to expire",
                description="It expires in less than 30 days.",
                severity=Severity.MEDIUM, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target, evidence=cert["notAfter"],
                remediation="Renew the certificate before the expiry date.")

        nb = _parse_gmt(cert.get("notBefore", ""))
        if nb and nb > now:
            self.register(
                title="Certificate with future issue date",
                description="notBefore in the future; clients will reject it.",
                severity=Severity.MEDIUM, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target,
                remediation="Reinstall a certificate with a valid date.")

        # -------PART2-------

        san = [s.lower() for s in cert.get("san", [])]
        if host not in san:
            self.register(
                title="The certificate does not cover the domain",
                description=f"The certificate has SAN={cert['san']} and does not include {host}.",
                severity=Severity.HIGH, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target,
                remediation="Regenerate the certificate including the domain in SAN.")

        if cert.get("subject") and cert["subject"] == cert.get("issuer"):
            self.register(
                title="Self-signed certificate",
                description="The issuer and subject match: not trustworthy for end users "
                            "and it facilitates MITM attacks.",
                severity=Severity.MEDIUM, cwe="CWE-295", owasp="A02:2021",
                url=self.ctx.target,
                remediation="Use a certificate from a recognized CA (Let's Encrypt, etc.).")

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
        supported = [n for n, r in results.items() if r.startswith("supported")]
        weak = [n for n in supported if n in ("TLS 1.0", "TLS 1.1")]
        if weak:
            self.register(
                title="Obsolete TLS protocols supported",
                description="Negotiation of " + ", ".join(weak) + " is allowed, affected by "
                            "BEAST, POODLE, Lucky13…",
                severity=Severity.HIGH, cwe="CWE-327", owasp="A02:2021",
                url=self.ctx.target,
                evidence="; ".join(f"{n}: {r}" for n, r in results.items()),
                remediation="Disable TLS 1.0/1.1; require TLS 1.2 as a minimum.")
        else:
            self.log("Protocols: " + "; ".join(f"{n}={r}" for n, r in results.items()))
        if supported and supported[-1] not in ("TLS 1.2", "TLS 1.3"):
            self.log("Warning: TLS 1.2/1.3 was not detected.")