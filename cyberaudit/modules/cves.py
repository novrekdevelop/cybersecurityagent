"""Consulta de CVEs conocidos (vía OSV.dev) para dependencias detectadas.

Analiza ficheros de dependencias del mismo origen (package.json, composer.lock,
requirements.txt) y consulta la API pública de OSV para listar vulnerabilidades
conocidas de esas versiones. Coste limitado a N consultas y timeouts cortos.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List
from urllib import request as http_request
from urllib.parse import urljoin

from ..models import Severity
from ..utils import info, origin_of
from .base import AuditModule


def _query_osv_package(name: str, ecosystem: str, version: str) -> List[Dict]:
    """Devuelve los CVEs conocidos para un paquete/versión (máx 4)."""
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": name, "ecosystem": ecosystem},
               "version": version}
    try:
        req = http_request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                   headers={"Content-Type": "application/json",
                                            "User-Agent": "CyberAuditPro/2.0"},
                                   method="POST")
        with http_request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        vulns = []
        for v in data.get("vulns", [])[:4]:
            sev = _max_severity(v)
            vulns.append({"id": v.get("id", ""),
                          "summary": (v.get("summary") or v.get("details") or "")[:180],
                          "severity": sev})
        return vulns
    except Exception:
        return []


def _max_severity(vuln: Dict) -> str:
    candidates = [s.get("severity", "") for s in vuln.get("severity", [])]
    for db in vuln.get("database_specific", {}).values():
        if isinstance(db, str) and db.lower() in ("critical", "high", "medium", "low"):
            candidates.append(db.lower())
    text = (" ".join(candidates)).lower()
    for sev_name in ("critical", "high", "medium", "low"):
        if sev_name in text:
            return sev_name if sev_name != "medium" or "moderate" not in text else "medium"
    return "unknown"


class CvesModule(AuditModule):
    name = "cves"
    description = "CVEs conocidos para dependencias detectadas (OSV.dev)"

    def run(self):
        if not self.ctx.config.run_cves:
            return
        origin = origin_of(self.ctx.base.url or self.ctx.target)
        if not origin:
            return

        packages = self._collect_dependencies(origin)
        if not packages:
            self.log("No se detectaron ficheros de dependencias en el origen.")
            return
        info(f"Consultando CVEs para {len(packages)} paquetes (OSV.dev)…")
        self.assets["dependencies"] = packages

        found_any = False
        probes = 0
        for pkg in packages:
            if probes >= 8:
                break
            probes += 1
            vulns = _query_osv_package(pkg["name"], pkg["ecosystem"], pkg["version"])
            if not vulns:
                continue
            found_any = True
            cve_ids = ", ".join(v["id"] for v in vulns)
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            sev = sev_map.get(vulns[0]["severity"], Severity.MEDIUM)
            if not pkg.get("silent") or sev == Severity.CRITICAL:
                self.register(
                    title=f"Vulnerabilidades conocidas (CVEs) en {pkg['name']}@{pkg['version']}",
                    description=f"El paquete '{pkg['name']}' versión {pkg['version']} "
                                f"(ecosistema {pkg['ecosystem']}) tiene CVEs públicos: "
                                f"{cve_ids}. Pueden permitir explotación remota o "
                                "manipulación de la aplicación.",
                    severity=sev, cwe="CWE-1035", owasp="A06:2021",
                    url=pkg.get("url", self.ctx.target),
                    evidence="; ".join(f"{v['id']} → {v['summary'][:90]}"
                                       for v in vulns[:4]),
                    remediation="Actualiza el paquete a la última versión parcheada; "
                                "revisa dependencias transitivas.")
        if not found_any:
            self.log("Sin CVEs conocidos para las dependencias detectadas.")

    # -------PART2-------

    # ------------------------------------------------------------------ packages
    def _collect_dependencies(self, origin) -> List[Dict]:
        found: List[Dict] = []
        candidates = [
            ("/package.json", "npm", "package.json"),
            ("/composer.lock", "Packagist", "composer.lock"),
            ("/requirements.txt", "PyPI", "requirements.txt"),
        ]
        for path, eco, _label in candidates:
            url = urljoin(origin + "/", path.lstrip("/"))
            resp = self.ctx.http.get(url)
            if resp.status != 200 or not resp.body:
                continue
            pks = self._parse_deps(resp.text[:300_000], eco, url)
            found.extend(pks)
        return found[:12]

    @staticmethod
    def _parse_deps(text: str, eco: str, url: str) -> List[Dict]:
        out = []
        if eco == "npm":
            try:
                data = json.loads(text)
            except Exception:
                data = {}
            for k, v in (data.get("dependencies", {}) or {}).items():
                if isinstance(v, str):
                    ver = v.lstrip("^~")
                    if ver and re.match(r"^[0-9]", ver):
                        out.append({"name": k, "version": ver, "ecosystem": eco,
                                    "url": url, "silent": False})
        elif eco == "Packagist":
            try:
                data = json.loads(text)
            except Exception:
                data = {}
            for k, v in (data.get("packages", {}) or {}).items():
                if isinstance(v, list) and v:
                    ver = (v[0].get("version") or "").lstrip("v")
                    if ver and re.match(r"^[0-9]", ver):
                        out.append({"name": k, "version": ver, "ecosystem": eco,
                                    "url": url, "silent": False})
        elif eco == "PyPI":
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "-")) and "==" in line:
                    name, ver = line.split("==", 1)
                    if ver and re.match(r"^[0-9]", ver.strip()):
                        out.append({"name": name.strip(), "version": ver.strip(),
                                    "ecosystem": eco, "url": url, "silent": False})
        return out[:30]