"""Configuración de la auditoría. Cargable desde config.json o por CLI."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 993, 995,
    1433, 1521, 1883, 2049, 3268, 3306, 3389, 5432, 5900, 6379, 8080, 8081,
    8443, 8888, 9200, 9300, 11211, 27017, 27018,
]


@dataclass
class AppConfig:
    # Red y transporte
    timeout: int = 12
    user_agent: str = "CyberAuditPro/2.0 (auditoría autorizada; contacto: seguridad)"
    proxy: Optional[str] = None
    verify_tls: bool = True
    session_cookie: Optional[str] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)
    delay: float = 0.0
    random_delay: bool = False

    # Rastreo de contenido
    max_crawl_pages: int = 40
    max_depth: int = 3

    # Rendimiento
    concurrency: int = 12
    port_timeout: float = 1.5

    # Módulos activados
    active_checks: bool = False      # pruebas de reflexión (XSS) benignas y optativas
    run_recon: bool = True
    run_tls: bool = True
    run_headers: bool = True
    run_content: bool = True
    run_injection: bool = True
    run_directories: bool = True
    run_ports: bool = False
    run_apis: bool = True
    run_auth: bool = True
    run_payments: bool = True
    run_fuzer: bool = False   # solo con --fuzz-login (pruebas de credenciales por defecto)
    run_cves: bool = True     # consulta de CVEs conocidos (OSV) para dependencias
    run_osint: bool = True    # inteligencia pasiva externa (Shodan InternetDB, WAF)
    run_emailsec: bool = True # postura de correo: SPF/DKIM/DMARC
    run_cms: bool = True      # enumeración de CMS (WordPress/Drupal/Joomla/PrestaShop)

    # Fuzzing y listas
    passwords_wordlist: Optional[str] = None
    max_targets: int = 60

    # Enumeración
    enumerate_subdomains: bool = True
    common_subdomains: bool = False
    probe_subdomains: bool = False
    directory_wordlist: Optional[str] = None
    directory_max_requests: int = 200

    # Informes
    output_formats: List[str] = field(default_factory=lambda: ["json", "html"])
    output_dir: str = "reports"

    # Extras
    module_include: List[str] = field(default_factory=list)
    module_exclude: List[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "AppConfig":
        default_path = Path(__file__).resolve().parent.parent / "config.json"
        data: dict = {}
        src = None
        if path:
            src = path
        elif default_path.exists():
            src = str(default_path)
        if src:
            with open(src, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        known = {f.name: f for f in fields(cls)}
        kwargs = {k: v for k, v in data.items() if k in known}
        return cls(**kwargs)

    @classmethod
    def merge_cli(cls, config: "AppConfig", args) -> "AppConfig":
        """Aplica opciones de argparse sobre la configuración base."""
        import dataclasses

        overrides = {}
        mapping = {
            "timeout": "timeout", "user_agent": "user_agent", "proxy": "proxy",
            "max_pages": "max_crawl_pages", "depth": "max_depth",
            "concurrency": "concurrency", "port_timeout": "port_timeout",
            "active": "active_checks", "insecure": "verify_tls",
            "subdomains": "common_subdomains",
            "probe_subdomains": "probe_subdomains",
            "ports": "run_ports",
            "wordlist": "directory_wordlist", "output_dir": "output_dir",
            "formats": "output_formats", "max_requests": "directory_max_requests",
            "module_include": "module_include", "module_exclude": "module_exclude",
            "fuzz_login": "run_fuzer",
            "cookie": "session_cookie",
            "delay": "delay", "random_delay": "random_delay",
            "passwords": "passwords_wordlist",
        }
        for cli_attr, cfg_attr in mapping.items():
            val = getattr(args, cli_attr, None)
            if val is not None:
                overrides[cfg_attr] = val
        # Desactivar módulos con --no-*
        for flag, cfg_attr in [("no_recon", "run_recon"), ("no_tls", "run_tls"),
                               ("no_headers", "run_headers"), ("no_content", "run_content"),
                               ("no_injection", "run_injection"),
                               ("no_directories", "run_directories"),
                               ("no_ports", "run_ports"),
                               ("no_apis", "run_apis"), ("no_auth", "run_auth"),
                               ("no_payments", "run_payments"),
                               ("no_fuzer", "run_fuzer"),
                               ("no_cves", "run_cves"),
                               ("no_osint", "run_osint"),
                               ("no_emailsec", "run_emailsec"),
                               ("no_cms", "run_cms")]:
            if getattr(args, flag, False):
                overrides[cfg_attr] = False
        return dataclasses.replace(config, **overrides)