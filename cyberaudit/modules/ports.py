"""Non-intrusive TCP scanning of common ports and services."""

from __future__ import annotations

import concurrent.futures as cf
import socket
from typing import Dict, List, Optional

from ..config import DEFAULT_PORTS
from ..models import Severity
from ..utils import host_of, info
from .base import AuditModule

SERVICE_HINTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 1883: "MQTT", 2049: "NFS", 3268: "LDAP GC", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP",
    8081: "HTTP", 8443: "HTTPS-Alt", 8888: "HTTP", 9200: "Elasticsearch",
    9300: "Elasticsearch-Tr", 11211: "Memcached", 27017: "MongoDB",
}

SENSITIVE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 9300, 11211, 27017,
                   2049, 445, 135, 139}
WEB_PORTS = {80, 443, 8080, 8081, 8443, 8888}


def _scan(host: str, port: int, timeout: float) -> Optional[int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) == 0:
            return port
    except OSError:
        return None
    finally:
        sock.close()
    return None


def _banner(host: str, port: int, timeout: float) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if port in WEB_PORTS:
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        elif port == 6379:
            s.sendall(b"PING\r\n")
        data = b""
        try:
            data = s.recv(200)
        except socket.timeout:
            pass
        s.close()
        return data.decode("utf-8", "replace").split("\n")[0][:120]
    except OSError:
        return ""


class PortsModule(AuditModule):
    name = "ports"
    description = "TCP scanning of common services"

    def run(self):
        cfg = self.ctx.config
        host = host_of(self.ctx.target)
        if not host:
            return
        info("Scanning common TCP ports…")
        open_ports: List[Dict] = []

        with cf.ThreadPoolExecutor(max_workers=min(cfg.concurrency, 32)) as pool:
            futures = {pool.submit(_scan, host, p, cfg.port_timeout): p for p in DEFAULT_PORTS}
            for fut in cf.as_completed(futures):
                p = fut.result()
                if p:
                    open_ports.append({"port": p, "service": SERVICE_HINTS.get(p, "?"), "banner": ""})

        for op in open_ports:
            op["banner"] = _banner(host, op["port"], min(cfg.port_timeout, 2.0))
        open_ports.sort(key=lambda x: x["port"])
        self.assets["ports"] = open_ports

        if not open_ports:
            self.log("No additional ports detected.")
            return
        self.log("Open: " + ", ".join(f"{p['port']}/{p['service']}" for p in open_ports))

        for op in open_ports:
            port, service = op["port"], op["service"]
            if port in SENSITIVE_PORTS:
                self.register(
                    title=f"Internal or data service exposed: {port}/{service}",
                    description="A database, messaging or administration service is "
                                "reachable from the Internet; usually indicates a misconfigured firewall.",
                    severity=Severity.HIGH, cwe="CWE-668", owasp="A05:2021",
                    url=self.ctx.target,
                    evidence=f"{host}:{port} ({service}) banner={op['banner']!r}",
                    remediation="Restrict access via firewall/security group to the IPs that "
                                "need it.")
            elif port == 23:
                self.register(
                    title="Telnet exposed (unencrypted)",
                    description="Telnet transmits credentials in clear text.",
                    severity=Severity.HIGH, cwe="CWE-319", owasp="A02:2021",
                    url=self.ctx.target,
                    remediation="Disable Telnet; use SSH.")
            elif port in (25, 110, 143):
                self.register(
                    title=f"Mail service without encryption: {port}/{service}",
                    description="Mail services that may accept credentials in clear text.",
                    severity=Severity.MEDIUM, cwe="CWE-319", owasp="A02:2021",
                    url=self.ctx.target,
                    remediation="Require STARTTLS/SMTPS/IMAPS and block open access.")
            elif port == 22:
                self.register(
                    title="SSH reachable from the Internet",
                    description="Exposed SSH is a constant target of brute force.",
                    severity=Severity.LOW, cwe="CWE-307", owasp="A07:2021",
                    url=self.ctx.target,
                    remediation="Use key-based authentication, disable root and restrict IPs.")
            elif port == 3389:
                self.register(
                    title="RDP reachable from the Internet",
                    description="Exposed RDP facilitates brute force and known exploits.",
                    severity=Severity.MEDIUM, cwe="CWE-307", owasp="A07:2021",
                    url=self.ctx.target,
                    remediation="Restrict RDP via VPN or allowlist and enable NLA.")