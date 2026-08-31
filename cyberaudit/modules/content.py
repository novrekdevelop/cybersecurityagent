"""Análisis de contenido: crawler del sitio, HTML, JS, formularios y e-commerce."""

from __future__ import annotations

import re
from collections import deque
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..models import Severity
from ..utils import JS_DANGEROUS_SINKS, absolute, detect_secrets, same_origin, strip_fragment, warn
from .base import AuditModule

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
BIZ_HIDDEN_NAME = re.compile(
    r"(^|_)(price|precio|amount|importe|total|cost|coste|discount|descuento|qty|quantity|"
    r"cantidad|shipping|envio|role|permiso|permission|isadmin|is_admin|adminlevel|tier|"
    r"nivel|premium|saldo|balance|credit|points|puntos|freeship)(_|$)", re.I)
ROLE_HIDDEN_NAME = re.compile(r"(role|permiso|permission|isadmin|is_admin|isAdmin|admin|nivel|tier|type)", re.I)
CSRF_NAME = re.compile(r"csrf|token|authenticity|xsrf|_token", re.I)
UPLOAD_MSG = "El formulario incluye envío de archivos (multipart/form-data)"
ERROR_DIR_MARKERS = ("Index of /", "<title>Index of", "Parent Directory", "Directory listing for")


class SiteParser(HTMLParser):
    """Extrae enlaces, scripts, formularios, meta y comentarios de una página."""

    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.links: Set[str] = set()
        self.scripts: List[Dict[str, str]] = []
        self.forms: List[Dict[str, Any]] = []
        self.meta: List[Tuple[str, str]] = []
        self.comments: List[str] = []
        self.emails: Set[str] = set()
        self.iframes: List[str] = []
        self.external_resources: List[Dict[str, str]] = []
        self.hidden_inputs: List[Dict[str, str]] = []
        self._in_script = False
        self._script_buf: List[str] = []
        self._cur_form: Optional[Dict[str, Any]] = None
        self._form_fields: List[Dict[str, str]] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        href = absolute(self.page_url, a.get("href", "")) if a.get("href") else None
        src = absolute(self.page_url, a.get("src", "")) if a.get("src") else None
        if tag == "a" and href:
            stripped = strip_fragment(href)
            if stripped:
                self.links.add(stripped)
        elif tag == "script":
            self._in_script = True
            self._script_buf = []
            self.scripts.append({"src": src or "", "integrity": a.get("integrity", ""),
                                 "inline": ""})
            if src:
                self.external_resources.append({"kind": "script", "url": src,
                                                "integrity": a.get("integrity", "")})
        elif tag in ("link", "img", "iframe", "object", "embed"):
            url = src or (absolute(self.page_url, a.get("href", "")) if a.get("href") else None)
            if url:
                if tag == "iframe":
                    self.iframes.append(url)
                self.external_resources.append({"kind": tag, "url": url,
                                                "integrity": a.get("integrity", "")})
        elif tag in ("form",):
            method = a.get("method", "get").upper()
            action = absolute(self.page_url, a.get("action", "")) if a.get("action") else ""
            self._cur_form = {"action": action, "method": method,
                              "enctype": a.get("enctype", ""), "fields": []}
            self._form_fields = []
        elif tag == "input" and self._cur_form is not None:
            field = {"type": a.get("type", "text"), "name": a.get("name", ""),
                     "value": a.get("value", ""), "id": a.get("id", ""),
                     "autocomplete": a.get("autocomplete", "")}
            self._cur_form["fields"].append(field)
            if field["type"] == "hidden":
                self.hidden_inputs.append(field)
        elif tag == "meta":
            name = a.get("name") or a.get("property") or ""
            content = a.get("content", "")
            if name and content:
                self.meta.append((name.lower(), content))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag == "input" and self._cur_form is not None:
            self._form_fields = []

    def handle_endtag(self, tag):
        if tag == "script":
            if self._in_script:
                self._in_script = False
                if self.scripts:
                    self.scripts[-1]["inline"] = "".join(self._script_buf)[:300_000]
        elif tag == "form":
            if self._cur_form is not None:
                self._cur_form["fields"] = self._form_fields or self._cur_form["fields"]
                self.forms.append(self._cur_form)
                self._cur_form = None
            self._form_fields = []

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)
            return
        for m in EMAIL_RE.findall(data):
            self.emails.add(m.lower())

    def handle_comment(self, data):
        if data and data.strip():
            self.comments.append(data.strip()[:500])

    # ------------------------------------------------------------------
    def parse_forms(self):
        for f in self.forms:
            if not f["fields"]:
                f["fields"] = []
        return self.forms

    # -------PART2-------


def _page_title(body: str) -> str:
    m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
    return m.group(1).strip()[:120] if m else ""


def crawl(http, start_url: str, max_pages: int = 40, max_depth: int = 3,
          js_files: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """BFS limitado al mismo origen. Devuelve registros de páginas analizadas."""
    visited: Set[str] = set()
    queue: deque = deque([(start_url, 0)])
    pages: List[Dict[str, Any]] = []
    origin = urlparse(start_url).scheme + "://" + urlparse(start_url).netloc
    fetched_js: Set[str] = set()
    if js_files is None:
        js_files = []

    # Puebla la cola con sitemap.xml y robots.txt (más superficie)
    for extra_file in ("/sitemap.xml", "/robots.txt"):
        r = http.get(origin + extra_file)
        if r.status not in (200,) or not r.body:
            continue
        if "sitemap" in extra_file:
            for m in re.finditer(r"<loc[^>]*>(.*?)</loc>", r.text, re.I | re.S):
                u = m.group(1).strip()
                if u and same_origin(u, start_url) and len(pages) < max_pages:
                    key = u.split("#")[0]
                    if key not in visited:
                        queue.append((key, 1))
        elif "robots" in extra_file:
            for line in r.text.splitlines():
                low = line.lower().strip()
                if low.startswith("sitemap:"):
                    u = line.split(":", 1)[1].strip()
                    if u and same_origin(u, start_url) and len(pages) < max_pages:
                        queue.append((u.split("#")[0], 1))

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        resp = http.get(url)
        body_text = resp.text
        ctype = resp.header("content-type").lower()
        is_html = ("html" in ctype) or ("xml" in ctype) or not ctype or resp.status >= 400
        if not is_html or not resp.body:
            pages.append({"url": url, "status": resp.status, "content_type": ctype,
                          "html": False, "size": len(resp.body)})
            continue

        parser = SiteParser(url)
        try:
            parser.feed(body_text)
        except Exception:
            pass

        # Descargar JS externos del mismo origen (máx. 20 ficheros, 1.5 MB)
        for s in parser.scripts:
            src = s.get("src", "")
            if not src or src in fetched_js or len(fetched_js) >= 20:
                continue
            if not same_origin(src, start_url):
                continue
            fetched_js.add(src)
            jsr = http.get(src)
            if jsr.status == 200 and jsr.body:
                jcontent = jsr.text[:500_000]
                js_files.append({
                    "url": src, "status": jsr.status,
                    "content": jcontent,
                    "secrets": detect_secrets(jcontent),
                    "size": len(jsr.body),
                })

        secrets = detect_secrets(" ".join(s["inline"] for s in parser.scripts))
        sinks = [desc for pat, desc in JS_DANGEROUS_SINKS
                 if any(pat.search(s["inline"] or "") for s in parser.scripts)]
        is_dir_listing = any(mkr in body_text[:4000] for mkr in ERROR_DIR_MARKERS)

        record = {
            "url": url,
            "status": resp.status,
            "content_type": ctype,
            "html": True,
            "size": len(resp.body),
            "title": _page_title(body_text),
            "secrets": secrets,
            "js_sinks": sinks,
            "dir_listing": is_dir_listing,
            "emails": sorted(parser.emails)[:20],
            "comments": parser.comments[:20],
            "forms": parser.parse_forms(),
            "iframes": parser.iframes[:10],
            "external": parser.external_resources[:80],
            "hidden_inputs": parser.hidden_inputs[:50],
            "links": sorted(parser.links)[:500],
            "scripts_urls": [s["src"] for s in parser.scripts if s["src"]],
            "_body": body_text[:400_000],
        }
        pages.append(record)

        if depth < max_depth:
            for link in parser.links:
                if len(pages) >= max_pages:
                    break
                if same_origin(link, start_url) and link not in visited:
                    queue.append((link, depth + 1))
    return pages


class ContentModule(AuditModule):
    name = "content"
    description = "Crawler y análisis de HTML/JS/formularios"

    def run(self):
        self._seen: Set[str] = set()
        start = self.ctx.base.url or self.ctx.target
        cfg = self.ctx.config
        self.log("Rastreando el sitio (mismo origen)…")
        js_files: List[Dict[str, Any]] = []
        pages = crawl(self.ctx.http, start, cfg.max_crawl_pages, cfg.max_depth, js_files)
        bodies = {p["url"]: p.pop("_body", "") for p in pages}
        self.assets["pages"] = [dict(p) for p in pages]
        self.assets["_bodies"] = bodies
        self.assets["pages_analyzed"] = [p for p in pages if p.get("html")]
        self.assets["js_analyzed"] = js_files
        self.log(f"{len(pages)} respuestas · {len([p for p in pages if p.get('html')])} HTML"
                 + (f" · {len(js_files)} archivos JS analizados" if js_files else ""))

        total_forms = 0
        csrf_forms = 0
        login_forms = []
        for page in pages:
            if not page.get("html"):
                continue
            self._analyze_page(page)
            for form in page.get("forms", []):
                total_forms += 1
                self._analyze_form(form, page["url"], start.startswith("https://"))
                fields = form.get("fields", [])
                if any(f.get("name") and CSRF_NAME.search(f["name"]) for f in fields):
                    csrf_forms += 1
                if any(f.get("type") == "password" for f in fields):
                    login_forms.append((page["url"], form.get("action", ""), form.get("method", "")))
        self.assets["forms_total"] = total_forms
        self.assets["forms_csrf"] = csrf_forms
        if login_forms:
            self.assets["login_forms"] = [
                {"url": u, "action": a, "method": m} for u, a, m in login_forms]
        if total_forms and not csrf_forms:
            self.register(
                title="Formularios sin protección CSRF aparente",
                description=f"Se localizaron {total_forms} formularios y ninguno incluye token "
                            "anti-CSRF visible. Riesgo de CSRF en acciones sensibles.",
                severity=Severity.MEDIUM, cwe="CWE-352", owasp="A01:2021",
                url=self.ctx.target,
                remediation="Añade tokens CSRF exclusivos por sesión en todos los formularios.")

    # ------------------------------------------------------------------ dedupe
    def _dedupe(self, key: str, url: str) -> bool:
        ident = key + "|" + url
        if ident in self._seen:
            return False
        self._seen.add(ident)
        return True
# ------------------------------------------------------------------ página
    def _analyze_page(self, page):
        url = page["url"]
        secure_page = url.startswith("https://")

        for secret in page.get("secrets", []):
            if self._dedupe("secret:" + secret, url):
                self.register(
                    title=f"Posible secreto en código: {secret}",
                    description="Se ha detectado un patrón de credencial o clave privada en "
                                "JavaScript/HTML del lado del cliente.",
                    severity=Severity.HIGH, cwe="CWE-798", owasp="A07:2021", url=url,
                    evidence=f"Motivo detectado: {secret}",
                    remediation=("Retira la credencial del código cliente; inválidala (rotación) "
                                 "y muévela al backend."))

        for sink in page.get("js_sinks", []):
            if self._dedupe("sink:" + sink, url):
                self.register(
                    title=f"Uso de patrón peligroso en JavaScript: {sink.split('(')[0]}()",
                    description=f"Se usa '{sink}'. Con entrada de usuario sin sanitizar es un "
                                "vector clásico de XSS.",
                    severity=Severity.MEDIUM, cwe="CWE-79", owasp="A03:2021", url=url,
                    evidence=sink,
                    remediation="Sanitiza la entrada y evita escribir HTML desde datos del usuario.")

        for res in page.get("external", []):
            if res.get("kind") == "script" and not res.get("integrity"):
                if self._dedupe("sri", url):
                    scripts = [r["url"] for r in page["external"] if r["kind"] == "script"]
                    self.register(
                        title="Scripts de terceros sin Subresource Integrity (SRI)",
                        description="Los scripts externos podrían ser sustituidos en el CDN o en "
                                    "tránsito (ataque a la cadena de suministro).",
                        severity=Severity.LOW, cwe="CWE-353", owasp="A08:2021", url=url,
                        evidence="; ".join(scripts)[:300],
                        remediation="Añade integrity (hash SHA-384+) y crossorigin a cada "
                                    "<script> de terceros.")
                break

        if secure_page:
            for res in page.get("external", []):
                if res["url"].startswith("http://"):
                    if self._dedupe("mixed", url):
                        self.register(
                            title="Contenido mixto: recurso HTTP en página HTTPS",
                            description="Cargar recursos por HTTP permite su manipulación o robo "
                                        "de datos en tránsito.",
                            severity=Severity.MEDIUM, cwe="CWE-319", owasp="A02:2021", url=url,
                            evidence=res["url"],
                            remediation="Sirve todos los recursos vía https://.")
                    break

        if page.get("dir_listing") and self._dedupe("dirlisting", url):
            self.register(
                title="Listado de directorio expuesto",
                description="El servidor muestra el índice de un directorio, revelando archivos "
                            "y facilitando encontrar ficheros sensibles.",
                severity=Severity.HIGH, cwe="CWE-538", owasp="A01:2021", url=url,
                remediation="Desactiva el listado de directorios (autoindex off / -Indexes).")

        emails = page.get("emails", [])
        if emails and self._dedupe("email", url):
            self.register(
                title="Correos expuestos en el HTML",
                description="Direcciones de correo recolectables para phishing/spam.",
                severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=url,
                evidence=", ".join(emails[:10]),
                remediation="Ofusca las direcciones públicas.")

        sensitive_comments = [c for c in page.get("comments", []) if re.search(
            r"(?i)password|token|login|secret|api[_-]?key|debug|todo|fixme|hack|servidor|bbdd|ftp", c)]
        if sensitive_comments and self._dedupe("comment", url):
            self.register(
                title="Comentarios HTML con pistas de seguridad",
                description="Pueden filtrar detalles internos, endpoints o credenciales.",
                severity=Severity.LOW, cwe="CWE-615", owasp="A01:2021", url=url,
                evidence="\n".join(sensitive_comments[:6]),
                remediation="Elimina comentarios de producción que revelen información interna.")

    # ------------------------------------------------------------------ formularios
    def _analyze_form(self, form, page_url: str, secure_origin: bool, url_key: str = ""):
        action = form.get("action", "") or page_url
        method = form.get("method", "GET")
        fields = form.get("fields", [])
        is_login = any(f.get("type") == "password" for f in fields)
        has_csrf = any(f.get("name") and CSRF_NAME.search(f["name"]) for f in fields)
        fkey = action + "|" + method + "|" + str(len(fields))
        if not self._dedupe("form:" + fkey, url_key or page_url):
            return

        # Login sin CSRF
        if is_login and not has_csrf:
            self.register(
                title="Formulario de login sin token CSRF",
                description="Un atacante puede forzar inicios de sesión (login CSRF) o hacer "
                            "phishing en el propio dominio.",
                severity=Severity.MEDIUM, cwe="CWE-352", owasp="A01:2021",
                url=page_url, evidence=f"action={action} method={method}",
                remediation="Añade token CSRF al formulario y verifica en backend.")

        # Login por GET
        if is_login and method == "GET":
            self.register(
                title="Credenciales enviadas por GET (login)",
                description="El login con metodo GET deja las credenciales en la URL, logs y "
                            "cabeceras Referer.",
                severity=Severity.HIGH, cwe="CWE-598", owasp="A03:2021",
                url=page_url, evidence=f"action={action}",
                remediation="Usa método POST para todo formulario de credenciales.")

        # Login o formulario sensible por HTTP
        if action.startswith("http://") and secure_origin:
            self.register(
                title="Envío de formulario por HTTP (en claro)",
                description="El formulario envía datos a una URL HTTP; credenciales y datos "
                            "viajan sin cifrar.",
                severity=Severity.HIGH if is_login else Severity.MEDIUM,
                cwe="CWE-319", owasp="A02:2021", url=page_url, evidence=action,
                remediation="Sirve el endpoint sobre HTTPS únicamente.")

        # Campos de subida de archivos
        enctype = form.get("enctype", "")
        if "multipart/form-data" in enctype.lower():
            if self._dedupe("upload", page_url):
                self.register(
                    title="Formulario con subida de archivos detectado",
                    description="La subida sin control de tipo, tamaño o contenido permite "
                                "alojar malware o provocar vulnerabilidades (upload bypass).",
                    severity=Severity.INFO, cwe="CWE-434", owasp="A03:2021",
                    url=page_url, evidence=f"action={action} enctype={enctype}",
                    remediation="Valida tipo MIME real, extensión, tamaño y contenido; sirve los "
                                "archivos desde un dominio sin ejecución.")

        # Campos ocultos de negocio (precio / rol / cupón)
        biz_hits = [f for f in fields if f.get("name") and BIZ_HIDDEN_NAME.search(f["name"])]
        if biz_hits:
            bad = [f for f in biz_hits if ROLE_HIDDEN_NAME.search(f.get("name", "")) and f.get("value", "") != ""]
            kind = "roles/permisos" if bad else "valores de negocio (precio, descuento, importe…)"
            if self._dedupe("biz:" + kind, page_url):
                self.register(
                    title=f"Lógica de negocio vulnerable a manipulación: {kind}",
                    description="Existen campos ocultos (hidden) con valores que controlan "
                                "precios, cupones, cantidades o roles. Si el servidor no los "
                                "revalida, podrían manipularse desde el cliente.",
                    severity=Severity.MEDIUM, cwe="CWE-840", owasp="A01:2021",
                    url=page_url,
                    evidence="\n".join(f"{f['type']} name={f.get('name')} value={f.get('value')}"
                                       for f in biz_hits[:8]),
                    remediation="Revalida precios, cantidades y permisos en el servidor; jamás "
                                "confíes en valores ocultos del formulario.")