"""Generación de informes: JSON, Markdown y HTML autocontenido."""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .models import AuditResult, Severity


def result_dict(result: AuditResult) -> Dict[str, Any]:
    return {
        "herramienta": "CyberAudit Pro 2.0",
        "objetivo": result.target,
        "inicio": datetime.fromtimestamp(result.start_time).isoformat(),
        "fin": datetime.fromtimestamp(result.end_time).isoformat(),
        "duracion_seg": result.duration,
        "puntuacion_riesgo": result.risk_score,
        "valoracion": result.grade,
        "resumen_por_severidad": result.summary,
        "cobertura_owasp": _owasp_coverage(result),
        "hoja_de_ruta_remediacion": _roadmap_remediation(result),
        "meta": result.meta,
        "activos": {k: v for k, v in result.assets.items() if k != "_bodies"},
        "hallazgos": [f.to_dict() for f in result.findings],
    }


# ------------------------------------------------------------------ JSON
def save_json(result: AuditResult, path: str) -> str:
    Path(path).write_text(
        json.dumps(result_dict(result), ensure_ascii=False, indent=2),
        encoding="utf-8")
    return path


# ------------------------------------------------------------------ Markdown
def save_markdown(result: AuditResult, path: str) -> str:
    lines: List[str] = []
    w = lines.append
    w("# 🔒 CyberAudit Pro — Informe de auditoría de seguridad")
    w("")
    w(f"**Objetivo:** `{result.target}`")
    w(f"**Fecha:** {datetime.fromtimestamp(result.start_time):%Y-%m-%d %H:%M:%S} "
      f"· **Duración:** {result.duration}s")
    w("")
    w("## Resumen ejecutivo")
    w("")
    w("| Severidad | Nº hallazgos |")
    w("|-----------|--------------|")
    for s in Severity:
        w(f"| {s.label} | {result.summary.get(s.value, 0)} |")
    w("")
    w(f"**Puntuación de riesgo:** {result.risk_score}/100 → **{result.grade}**")
    lo, hi = _total_economico(result)
    w(f"**Impacto económico estimado:** {lo} – {hi} EUR")
    w("")

    cov = _owasp_coverage(result)
    w("## Cobertura del OWASP Top 10 (hallazgos por categoría)")
    w("")
    w("| Categoría | Hallazgos |")
    w("|-----------|-----------|")
    for ow, n in cov.items():
        label = OWASP_LABELS.get(ow, ow)
        w(f"| {label} | {n} |")
    w("")
    w("## Hoja de ruta de remediación")
    w("")
    for step in _roadmap_remediation(result):
        w(f"- {step}")
    w("")

    if result.findings:
        ordered = sorted(result.findings,
                         key=lambda fnd: fnd.economic_range()["max_eur"], reverse=True)
        w(f"## Hallazgos ({len(result.findings)}) — priorizados por impacto")
        w("")
        for i, f in enumerate(ordered, 1):
            eco = f.economic_range()
            eco_txt = (f"{_fmt_eur(eco['min_eur'])} – {_fmt_eur(eco['max_eur'])} EUR"
                       if eco["max_eur"] else "—")
            w(f"### {i}. [{f.severity.label.upper()}] {f.title}")
            w("")
            w(f"- **Clase:** {f.module}  ·  **CWE:** {f.cwe or '—'}  ·  **OWASP:** {f.owasp or '—'}")
            w(f"- **URL:** {f.url or '—'}")
            w(f"- **Impacto económico estimado:** {eco_txt}")
            w(f"- **Descripción:** {f.description}")
            if f.evidence:
                w(f"- **Evidencia:**")
                w("")
                w(f"  ```")
                w(f"  {f.evidence[:1200]}")
                w(f"  ```")
                w("")
            if f.remediation:
                w(f"- **Remediación:** {f.remediation}")
            w("")

    w("## Inventario de activos")
    w("")
    assets = result.assets
    exposure = assets.get("internet_exposure", [])
    internet_txt = ("; ".join(f"{e['ip']} → {len(e['vulns'])} cvEs · {len(e['ports'])} puertos"
                              for e in exposure[:4]) or "sin datos públicos")
    mail_txt = (f"SPF: {assets.get('email_spf', '—')} · DKIM: {assets.get('email_dkim', '—')}"
                f" · DMARC: {assets.get('email_dmarc', '—')}")
    for name, value in [
        ("Transporte", "https" if assets.get("transport") else "http (en claro)"),
        ("WAF / perímetro", ", ".join(assets.get("waf", [])) or "no detectado"),
        ("Exposición Internet (Shodan)", internet_txt),
        ("Correo (SPF/DKIM/DMARC)", mail_txt),
        ("Subdominios", ", ".join(assets.get("subdomains", [])[:20]) or "ninguno"),
        ("Tecnologías", ", ".join(t["name"] for t in assets.get("tech", [])) or "no identificadas"),
        ("Páginas rastreadas", len(assets.get("pages", []))),
        ("Formularios", assets.get("forms_total", 0)),
        ("Puertos abiertos", ", ".join(f"{p['port']}/{p['service']}" for p in assets.get("ports", [])) or "solo 80/443"),
    ]:
        w(f"- **{name}:** {value}")
    w("")
    w("---")
    w("*Informe generado automáticamente. Uso exclusivo para auditorías autorizadas.*")
    Path(path).write_text("\n".join(lines), encoding="utf-8")
    return path


# -------PART2-------

def _esc(v: Any) -> str:
    return html.escape(str(v), quote=True)


_CSS = """
:root{--bg:#0b1220;--panel:#111a2e;--panel2:#0f1526;--text:#dbe4f0;--muted:#8ea3c0}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:15px/1.55 'Segoe UI',system-ui,sans-serif;padding:24px}
.wrap{max-width:1150px;margin:0 auto}
h1{font-size:26px;letter-spacing:.4px}
h2{font-size:20px;margin:34px 0 12px;color:#fff;border-left:4px solid #38bdf8;padding-left:10px}
header{background:linear-gradient(135deg,#0f1b32,#1c2f52);border:1px solid #243b61;border-radius:14px;padding:22px 26px}
header .tag{color:#38bdf8;font-weight:600;letter-spacing:2px;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(115px,1fr));gap:12px;margin:18px 0}
.card{background:var(--panel);border:1px solid #223458;border-radius:10px;padding:14px;text-align:center}
.card .num{font-size:30px;font-weight:700}
.card .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:1px}
.score{display:flex;gap:24px;align-items:center;background:var(--panel2);border:1px solid #223458;border-radius:12px;padding:18px 22px}
.score .big{font-size:52px;font-weight:800;color:#38bdf8}
.meta{color:var(--muted);margin-top:14px;font-size:13px}
.assets{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
.asset{background:var(--panel);border:1px solid #223458;border-radius:10px;padding:14px 16px}
.asset h3{color:#7dd3fc;font-size:14px;margin-bottom:6px}
.asset p,.asset li{color:var(--text);font-size:13.5px}
.badge{padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:.5px}
.rank{display:inline-block;min-width:26px;font-weight:800;color:#fbbf24;font-size:13px}
.s-critical{background:#dc2626}.s-high{background:#ea580c}.s-medium{background:#ca8a04}
.s-low{background:#0284c7}.s-info{background:#0891b2}
.finding{margin-bottom:10px;background:var(--panel);border:1px solid #223458;border-left:4px solid #223458;border-radius:8px}
.finding.s-critical{border-left-color:#dc2626}.finding.s-high{border-left-color:#ea580c}
.finding.s-medium{border-left-color:#ca8a04}.finding.s-low{border-left-color:#0284c7}.finding.s-info{border-left-color:#0891b2}
details summary{cursor:pointer;padding:12px 16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.ftitle{font-weight:600;flex:1;min-width:200px}
.fmeta{color:var(--muted);font-size:12px}
.fbody{padding:0 16px 14px;color:#c9d6e8}
.fbody pre{background:#0a1120;border:1px solid #1c2c4c;border-radius:8px;padding:10px;white-space:pre-wrap;word-break:break-word;font-size:12.5px}
.fbody code{background:#14213c;padding:1px 6px;border-radius:4px;font-size:12px}
.fix{background:#0c2a1e;border:1px solid #0b4a2f;border-radius:8px;padding:8px 12px}
.roadmap{margin:16px 0 32px;padding-left:22px}
.roadmap li{margin:9px 0;line-height:1.55}
footer{margin-top:40px;color:var(--muted);font-size:12px;text-align:center}
@media(max-width:640px){.score{flex-direction:column}}
.filterbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0 16px}
.filterbar button{border:1px solid #2c4068;background:#15233f;color:#c9d6e8;padding:4px 12px;border-radius:20px;cursor:pointer;font-size:12px}
.filterbar button:hover{background:#20385f}
.filterbar input{flex:1;min-width:160px;background:#0a1120;border:1px solid #2c4068;color:#e5eefb;border-radius:20px;padding:5px 12px;font-size:12.5px;outline:none}
"""


def _summary_block(result: AuditResult, assets: Dict[str, Any]) -> str:
    f = _esc
    summary = {s.value: result.summary.get(s.value, 0) for s in Severity}
    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO]
    colors = {"critical": "#7f1d1d", "high": "#7c2d12", "medium": "#854d0e",
              "low": "#1e3a5f", "info": "#164e63"}
    cards = "".join(
        f'<div class="card" style="border-top:4px solid {colors[s.value]}">'
        f'<div class="num">{summary.get(s.value, 0)}</div>'
        f'<div class="lbl">{s.label}</div></div>' for s in sev_order)
    pages = len(assets.get("pages", []))
    total_lo, total_hi = _total_economico(result)
    return f"""
<h2>Resumen ejecutivo</h2>
<div class="grid">{cards}</div>
<div class="score">
  <div class="big">{result.risk_score:.0f}/100</div>
  <div><h2 style="border:0;margin:0">Valoración</h2>
  <p style="color:#7dd3fc">{f(result.grade)}</p>
  <p class="meta">Superficie analizada: {pages} páginas ·
  {assets.get('forms_total', 0)} formularios · {len(result.findings)} hallazgos
  <br><b style="color:#fbbf24">Impacto económico estimado:
  {total_lo} – {total_hi} EUR</b></p></div>
</div>"""


def _total_economico(result: AuditResult):
    lo = sum(f.economic_range()["min_eur"] for f in result.findings)
    hi = sum(f.economic_range()["max_eur"] for f in result.findings)
    return _fmt_eur(lo), _fmt_eur(hi)


def _fmt_eur(v: int) -> str:
    return f"{v:,.0f}".replace(",", ".")


# ------------------------------------------------------------------ OWASP / roadmap
OWASP_LABELS = {
    "A01:2021": "A01 — Control de acceso roto",
    "A02:2021": "A02 — Fallos criptográficos",
    "A03:2021": "A03 — Inyección",
    "A04:2021": "A04 — Diseño inseguro",
    "A05:2021": "A05 — Mala configuración de seguridad",
    "A06:2021": "A06 — Componentes vulnerables y desactualizados",
    "A07:2021": "A07 — Fallos de identificación y autenticación",
    "A08:2021": "A08 — Fallos de integridad de software y datos",
    "A09:2021": "A09 — Fallos de registro y monitorización",
    "A10:2021": "A10 — Falsificación de solicitudes del lado del servidor",
    "sin-mapa": "Sin categoría OWASP asignada",
}


def _owasp_coverage(result: AuditResult) -> Dict[str, int]:
    """Hallazgos agrupados por categoría OWASP Top 10 (ordenadas por frecuencia)."""
    counts: Dict[str, int] = {}
    for fnd in result.findings:
        ow = (fnd.owasp or "").strip() or "sin-mapa"
        counts[ow] = counts.get(ow, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def _roadmap_remediation(result: AuditResult) -> List[str]:
    """Hoja de ruta ejecutiva para remediar la auditoría (numeración continua)."""
    s = {sv.value: result.summary.get(sv.value, 0) for sv in Severity}
    items: List[str] = []
    if result.risk_score < 18:
        items.append(f"**Postura actual aceptable** ({result.grade}). Mantén el "
                     "hardening y programa auditorías de control periódicas.")
    if s.get("critical"):
        items.append("**Críticos (acción inmediata):** detén la explotación del hallazgo "
                     "(rota secretos/credenciales filtradas, desactiva endpoints o "
                     "servicios comprometidos) y aplica el parche correspondiente en "
                     "<24–72 h.")
    if s.get("high"):
        items.append("**Altos (plan en 1–2 semanas):** corrige la configuración de acceso, "
                     "autenticación y exposición de datos marcada en los hallazgos altos; "
                     "prioriza lo alcanzable desde Internet.")
    if s.get("medium"):
        items.append("**Medios (plan en 1 mes):** endurece cabeceras de seguridad, cookies, "
                     "TLS y procesos (CSRF, rate limiting, validación en servidor).")
    items += [
        "**Identidad y accesos:** activa MFA en paneles y cuentas administrativas, "
        "mínimos privilegios y bloqueo de intentos.",
        "**Superficie de ataque:** cierra puertos y servicios innecesarios, oculta IPs "
        "de origen tras WAF/CDN y revisa subdominios/API expuestos.",
        "**Correo anti-spoofing:** completa SPF/DKIM/DMARC (p=reject) si no están en verde.",
        "**Gestión de vulnerabilidades:** calendario de actualización de componentes "
        "(CMS, dependencias) y suscripción a avisos CVE.",
        "**Monitorización y respuesta:** despliega detección (WAF, SIEM, alertas de "
        "auth) y un plan de respuesta a incidentes.",
        "**Re-auditoría:** repite esta auditoría en 4–8 semanas para verificar la "
        "remediación y medir la bajada del riesgo.",
    ]
    return [f"{i}. {item}" for i, item in enumerate(items, 1)]


# ------------------------------------------------------------------ CSV
def save_csv(result: AuditResult, path: str) -> str:
    import csv
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["modulo", "severidad", "titulo", "url", "cwe", "owasp",
                    "impacto_min_eur", "impacto_max_eur", "evidencia", "remediacion"])
        for fnd in result.findings:
            eco = fnd.economic_range()
            w.writerow([fnd.module, fnd.severity.value, fnd.title, fnd.url,
                        fnd.cwe, fnd.owasp, eco["min_eur"], eco["max_eur"],
                        fnd.evidence, fnd.remediation])
    return path


# ------------------------------------------------------------------ SARIF 2.1.0
def _sarif_level(sev) -> str:
    return {"critical": "error", "high": "error", "medium": "warning",
            "low": "note", "info": "note"}.get(sev.value, "warning")


def save_sarif(result: AuditResult, path: str) -> str:
    rules = []
    results = []
    for idx, fnd in enumerate(result.findings, 1):
        rule_id = f"CBR-{idx:03d}"
        rules.append({
            "id": rule_id,
            "name": fnd.title[:200],
            "shortDescription": {"text": fnd.description[:300]},
            "helpUri": fnd.url or result.target,
            "properties": {"severity": fnd.severity.value, "cwe": fnd.cwe,
                           "owasp": fnd.owasp, "module": fnd.module,
                           "impact": fnd.economic_range()},
        })
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(fnd.severity),
            "message": {"text": fnd.description[:400]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": fnd.url or result.target},
                "region": {"startLine": 1}}}],
            "properties": {"evidence": fnd.evidence[:500],
                           "remediation": fnd.remediation[:300]},
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                   "master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CyberAudit Pro", "informationUri":
                    "https://localhost", "version": "2.0",
                    "rules": rules}},
            "results": results,
            "automationDetails": {"id": result.target},
            "properties": {"risk_score": result.risk_score,
                           "grade": result.grade},
        }],
    }
    Path(path).write_text(json.dumps(sarif, ensure_ascii=False, indent=2),
                          encoding="utf-8")
    return path


# -------PART3-------


def _findings_block(result: AuditResult) -> str:
    f = _esc
    # Ranking: los de mayor impacto económico primero
    ordered = sorted(result.findings,
                     key=lambda fnd: fnd.economic_range()["max_eur"], reverse=True)
    filter_bar = (
        '<div class="filterbar">'
        '<button onclick="filterBy(\'\')">Todos</button>'
        '<button onclick="filterBy(\'critical\')" style="background:#7f1d1d;color:#fff">Críticos</button>'
        '<button onclick="filterBy(\'high\')" style="background:#7c2d12;color:#fff">Altos</button>'
        '<button onclick="filterBy(\'medium\')" style="background:#854d0e;color:#fff">Medios</button>'
        '<button onclick="filterBy(\'low\')" style="background:#1e3a5f;color:#fff">Bajos</button>'
        '<button onclick="filterBy(\'info\')" style="background:#164e63;color:#fff">Informativos</button>'
        '<input id="q" placeholder="Buscar por texto…" onkeyup="searchF()"></div>'
    )
    rows = ""
    for rank, find in enumerate(ordered, 1):
        evidence = (f'<pre>{f(find.evidence[:1500])}</pre>' if find.evidence else "")
        fix = (f'<p class="fix">Remediación: {f(find.remediation)}</p>' if find.remediation else "")
        eco = find.economic_range()
        eco_txt = (f'{_fmt_eur(eco["min_eur"])} – {_fmt_eur(eco["max_eur"])} €'
                   if eco["max_eur"] else "—")
        rows += (
            f'<div class="finding s-{find.severity.value}"><details><summary>'
            f'<span class="rank">#{rank}</span> '
            f'<span class="badge s-{find.severity.value}">{find.severity.label}</span> '
            f'<span class="ftitle">{f(find.title)}</span> '
            f'<span class="fmeta">{f(find.cwe or "")} · {f(find.owasp or "")}</span></summary>'
            f'<div class="fbody">'
            f'<p><b>Módulo:</b> {f(find.module)} &nbsp; '
            f'<b>URL:</b> <code>{f(find.url or "—")}</code> &nbsp; '
            f'<b>Impacto estimado:</b> <span style="color:#fbbf24">{f(eco_txt)}</span></p>'
            f'<p>{f(find.description)}</p>'
            f'{evidence}{fix}</div></details></div>')
    return f'<h2>Hallazgos ({len(result.findings)}) — priorizados por impacto</h2>\n' + \
        filter_bar + (rows or '<p class="meta">No se detectaron hallazgos en el alcance analizado.</p>')


def _owasp_roadmap_block(result: AuditResult) -> str:
    f = _esc
    cov = _owasp_coverage(result)
    badges = ""
    for ow, n in cov.items():
        color = "#7dc4a0" if ow in ("A01:2021", "A02:2021", "A03:2021") else "#e0a03a"
        label = OWASP_LABELS.get(ow, ow)
        badges += (f'<div class="asset"><h3 style="color:{color}">{f(ow)}</h3>'
                   f'<p>{f(label)}</p><p class="meta"><b>{n}</b> hallazgo(s)</p></div>')
    if not badges:
        badges = '<p class="meta">Sin hallazgos clasificados.</p>'
    steps = "".join(f"<li>{f(step)}</li>" for step in _roadmap_remediation(result))
    return f"""
<h2>Cobertura según OWASP Top 10</h2>
<div class="assets">{badges}</div>
<h2>Hoja de ruta de remediación</h2>
<ol class="roadmap">{steps}</ol>"""


def _assets_block(result: AuditResult) -> str:
    assets = result.assets
    f = _esc
    tech = ", ".join(f(t["name"]) for t in assets.get("tech", [])) or "—"
    subs = ", ".join(f(s) for s in assets.get("subdomains", [])[:25]) or "—"
    ports = ", ".join(f'{p["port"]}/{p["service"]}' for p in assets.get("ports", [])) or "—"
    transport = assets.get("transport") or "HTTP en claro"
    cookies = assets.get("cookies_analyzed", [])
    cookie_str = ", ".join(f'{c["name"]} [{",".join(c.get("flags", []))}]' for c in cookies) or "—"
    dns = assets.get("dns", {})
    dns_str = "; ".join(f'{k}: {",".join(str(v)[:4])}' for k, v in dns.items() if v) or "—"
    login = assets.get("login_forms", [])
    login_str = "<br>".join(f'<code>{f(l["url"])}</code> ({f(l["method"])})' for l in login[:8]) or "—"
    waf = ", ".join(f(w) for w in assets.get("waf", [])) or "—"
    exposure = assets.get("internet_exposure", [])
    exp_str = ("<br>".join(f'<code>{f(e["ip"])}</code> — {len(e["vulns"])} CVE(s) · '
                          f'{len(e["ports"])} puerto(s) · {len(e["cpes"])} cpe(s)'
                          for e in exposure[:4]) or "sin datos públicos")
    mail_txt = (f'SPF: {f(assets.get("email_spf", "—"))} · '
                f'DKIM: {f(assets.get("email_dkim", "—"))} · '
                f'DMARC: {f(assets.get("email_dmarc", "—"))}')

    pages = assets.get("pages", [])
    page_marker = "".join(
        f'<li><code>{f(p["url"])}</code> — HTTP {p.get("status", "?")} '
        f'{f(p.get("title", ""))[:70]}</li>' for p in pages[:12])
    return f"""
<h2>Inventario de activos</h2>
<div class="assets">
  <div class="asset"><h3>Transporte</h3><p>{f(transport)}</p></div>
  <div class="asset"><h3>Tecnologías</h3><p>{f(tech)}</p></div>
  <div class="asset"><h3>Subdominios</h3><p>{f(subs)}</p></div>
  <div class="asset"><h3>Puertos abiertos</h3><p>{f(ports)}</p></div>
  <div class="asset"><h3>DNS</h3><p>{f(dns_str)}</p></div>
  <div class="asset"><h3>Cookies</h3><p>{f(cookie_str)}</p></div>
  <div class="asset"><h3>Formularios de login</h3><p>{login_str}</p></div>
  <div class="asset"><h3>WAF / perímetro</h3><p>{waf}</p></div>
  <div class="asset"><h3>Exposición Internet (Shodan)</h3><p>{exp_str}</p></div>
  <div class="asset"><h3>Seguridad de correo</h3><p>{mail_txt}</p></div>
  <div class="asset"><h3>Páginas analizadas ({len(pages)})</h3><ul>{page_marker or '<li class="meta">—</li>'}</ul></div>
</div>"""
def save_html(result: AuditResult, path: str) -> str:
    f = _esc
    assets = result.assets
    header = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de seguridad — {f(result.target)}</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<header>
  <div class="tag">CYBERAUDIT PRO · INFORME TÉCNICO</div>
  <h1>Auditoría de seguridad web</h1>
  <div class="meta">Objetivo: <code>{f(result.target)}</code> &nbsp;·&nbsp;
  Inicio: {datetime.fromtimestamp(result.start_time):%Y-%m-%d %H:%M:%S} &nbsp;·&nbsp;
  Duración: {result.duration:.1f}s &nbsp;·&nbsp;
  Estado objetivo: HTTP {assets.get('http_status', '—')}</div>
</header>"""

    footer = """<footer>Informe generado con CyberAudit Pro 2.0 · Uso exclusivo para auditorías autorizadas.
Los hallazgos indican debilidades que deben verificarse y corregirse; la explotación sin
permiso escrito está prohibida y puede ser ilegal.</footer>
<script>
function filterBy(cls){document.querySelectorAll('.finding').forEach(function(el){
el.style.display=(!cls||el.classList.contains('s-'+cls))?'':'none';});}
function searchF(){var q=(document.getElementById('q')||{}).value||'';
q=q.toLowerCase();document.querySelectorAll('.finding').forEach(function(el){
el.style.display=el.textContent.toLowerCase().indexOf(q)>-1?'':'none';});}
</script>
</div></body></html>"""

    html_doc = header + _summary_block(result, assets) + _owasp_roadmap_block(result) + \
        _findings_block(result) + _assets_block(result) + footer
    Path(path).write_text(html_doc, encoding="utf-8")
    return path


def save_reports(result: AuditResult, config) -> List[str]:
    from urllib.parse import urlparse
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(config.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    host = (urlparse(result.target).netloc or "objetivo").replace(":", "_")
    written = []
    if "json" in config.output_formats:
        written.append(save_json(result, str(outdir / f"informe_{host}_{ts}.json")))
    if "md" in config.output_formats:
        written.append(save_markdown(result, str(outdir / f"informe_{host}_{ts}.md")))
    if "html" in config.output_formats:
        written.append(save_html(result, str(outdir / f"informe_{host}_{ts}.html")))
    if "csv" in config.output_formats:
        written.append(save_csv(result, str(outdir / f"informe_{host}_{ts}.csv")))
    if "sarif" in config.output_formats:
        written.append(save_sarif(result, str(outdir / f"informe_{host}_{ts}.sarif")))
    return written