"""Content analysis: site crawler, HTML, JS, forms and e-commerce."""

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
UPLOAD_MSG = "The form includes file upload (multipart/form-data)"
ERROR_DIR_MARKERS = ("Index of /", "<title>Index of", "Parent Directory", "Directory listing for")


class SiteParser(HTMLParser):
    """Extracts links, scripts, forms, meta and comments from a page."""

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
    """BFS limited to the same origin. Returns records of analyzed pages."""
    visited: Set[str] = set()
    queue: deque = deque([(start_url, 0)])
    pages: List[Dict[str, Any]] = []
    origin = urlparse(start_url).scheme + "://" + urlparse(start_url).netloc
    fetched_js: Set[str] = set()
    if js_files is None:
        js_files = []

    # Seeds the queue with sitemap.xml and robots.txt (more surface)
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

        # Download same-origin external JS (max 20 files, 1.5 MB)
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
    description = "Crawler and HTML/JS/form analysis"

    def run(self):
        self._seen: Set[str] = set()
        start = self.ctx.base.url or self.ctx.target
        cfg = self.ctx.config
        self.log("Crawling the site (same origin)…")
        js_files: List[Dict[str, Any]] = []
        pages = crawl(self.ctx.http, start, cfg.max_crawl_pages, cfg.max_depth, js_files)
        bodies = {p["url"]: p.pop("_body", "") for p in pages}
        self.assets["pages"] = [dict(p) for p in pages]
        self.assets["_bodies"] = bodies
        self.assets["pages_analyzed"] = [p for p in pages if p.get("html")]
        self.assets["js_analyzed"] = js_files
        self.log(f"{len(pages)} responses · {len([p for p in pages if p.get('html')])} HTML"
                 + (f" · {len(js_files)} JS files analyzed" if js_files else ""))

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
                title="Forms without apparent CSRF protection",
                description=f"{total_forms} forms were found and none include a visible "
                            "anti-CSRF token. CSRF risk on sensitive actions.",
                severity=Severity.MEDIUM, cwe="CWE-352", owasp="A01:2021",
                url=self.ctx.target,
                remediation="Add per-session unique CSRF tokens to all forms.")

    # ------------------------------------------------------------------ dedupe
    def _dedupe(self, key: str, url: str) -> bool:
        ident = key + "|" + url
        if ident in self._seen:
            return False
        self._seen.add(ident)
        return True
# ------------------------------------------------------------------ page
    def _analyze_page(self, page):
        url = page["url"]
        secure_page = url.startswith("https://")

        for secret in page.get("secrets", []):
            if self._dedupe("secret:" + secret, url):
                self.register(
                    title=f"Possible secret in code: {secret}",
                    description="A credential or private key pattern was detected in "
                                "client-side JavaScript/HTML.",
                    severity=Severity.HIGH, cwe="CWE-798", owasp="A07:2021", url=url,
                    evidence=f"Detected reason: {secret}",
                    remediation=("Remove the credential from client code; invalidate it "
                                 "(rotation) and move it to the backend."))

        for sink in page.get("js_sinks", []):
            if self._dedupe("sink:" + sink, url):
                self.register(
                    title=f"Dangerous JavaScript pattern in use: {sink.split('(')[0]}()",
                    description=f"'{sink}' is used. With unsanitized user input it is a "
                                "classic XSS vector.",
                    severity=Severity.MEDIUM, cwe="CWE-79", owasp="A03:2021", url=url,
                    evidence=sink,
                    remediation="Sanitize input and avoid writing HTML from user data.")

        for res in page.get("external", []):
            if res.get("kind") == "script" and not res.get("integrity"):
                if self._dedupe("sri", url):
                    scripts = [r["url"] for r in page["external"] if r["kind"] == "script"]
                    self.register(
                        title="Third-party scripts without Subresource Integrity (SRI)",
                        description="External scripts could be swapped at the CDN or in "
                                    "transit (supply chain attack).",
                        severity=Severity.LOW, cwe="CWE-353", owasp="A08:2021", url=url,
                        evidence="; ".join(scripts)[:300],
                        remediation="Add integrity (SHA-384+ hash) and crossorigin to each "
                                    "third-party <script>.")
                break

        if secure_page:
            for res in page.get("external", []):
                if res["url"].startswith("http://"):
                    if self._dedupe("mixed", url):
                        self.register(
                            title="Mixed content: HTTP resource on HTTPS page",
                            description="Loading resources over HTTP allows their manipulation or data theft "
                                        "in transit.",
                            severity=Severity.MEDIUM, cwe="CWE-319", owasp="A02:2021", url=url,
                            evidence=res["url"],
                            remediation="Serve all resources via https://.")
                    break

        if page.get("dir_listing") and self._dedupe("dirlisting", url):
            self.register(
                title="Directory listing exposed",
                description="The server shows a directory index, revealing files "
                            "and making it easier to find sensitive ones.",
                severity=Severity.HIGH, cwe="CWE-538", owasp="A01:2021", url=url,
                remediation="Disable directory listing (autoindex off / -Indexes).")

        emails = page.get("emails", [])
        if emails and self._dedupe("email", url):
            self.register(
                title="Emails exposed in the HTML",
                description="Email addresses collectable for phishing/spam.",
                severity=Severity.INFO, cwe="CWE-200", owasp="A05:2021", url=url,
                evidence=", ".join(emails[:10]),
                remediation="Obfuscate public addresses.")

        sensitive_comments = [c for c in page.get("comments", []) if re.search(
            r"(?i)password|token|login|secret|api[_-]?key|debug|todo|fixme|hack|server|db|ftp", c)]
        if sensitive_comments and self._dedupe("comment", url):
            self.register(
                title="HTML comments with security hints",
                description="They can leak internal details, endpoints or credentials.",
                severity=Severity.LOW, cwe="CWE-615", owasp="A01:2021", url=url,
                evidence="\n".join(sensitive_comments[:6]),
                remediation="Remove production comments that reveal internal information.")

    # ------------------------------------------------------------------ forms
    def _analyze_form(self, form, page_url: str, secure_origin: bool, url_key: str = ""):
        action = form.get("action", "") or page_url
        method = form.get("method", "GET")
        fields = form.get("fields", [])
        is_login = any(f.get("type") == "password" for f in fields)
        has_csrf = any(f.get("name") and CSRF_NAME.search(f["name"]) for f in fields)
        fkey = action + "|" + method + "|" + str(len(fields))
        if not self._dedupe("form:" + fkey, url_key or page_url):
            return

        # Login without CSRF
        if is_login and not has_csrf:
            self.register(
                title="Login form without CSRF token",
                description="An attacker can force logins (login CSRF) or run "
                            "phishing on the domain itself.",
                severity=Severity.MEDIUM, cwe="CWE-352", owasp="A01:2021",
                url=page_url, evidence=f"action={action} method={method}",
                remediation="Add a CSRF token to the form and verify it on the backend.")

        # Login via GET
        if is_login and method == "GET":
            self.register(
                title="Credentials sent via GET (login)",
                description="A GET login leaves credentials in the URL, logs and "
                            "Referer headers.",
                severity=Severity.HIGH, cwe="CWE-598", owasp="A03:2021",
                url=page_url, evidence=f"action={action}",
                remediation="Use the POST method for every credential form.")

        # Login or sensitive form over HTTP
        if action.startswith("http://") and secure_origin:
            self.register(
                title="Form submission over HTTP (in clear)",
                description="The form sends data to an HTTP URL; credentials and data "
                            "travel unencrypted.",
                severity=Severity.HIGH if is_login else Severity.MEDIUM,
                cwe="CWE-319", owasp="A02:2021", url=page_url, evidence=action,
                remediation="Serve the endpoint over HTTPS only.")

        # File upload fields
        enctype = form.get("enctype", "")
        if "multipart/form-data" in enctype.lower():
            if self._dedupe("upload", page_url):
                self.register(
                    title="Form with file upload detected",
                    description="Upload without type, size or content control allows "
                                "hosting malware or triggering vulnerabilities (upload bypass).",
                    severity=Severity.INFO, cwe="CWE-434", owasp="A03:2021",
                    url=page_url, evidence=f"action={action} enctype={enctype}",
                    remediation="Validate real MIME type, extension, size and content; serve "
                                "files from a domain without code execution.")

        # Hidden business fields (price / role / coupon)
        biz_hits = [f for f in fields if f.get("name") and BIZ_HIDDEN_NAME.search(f["name"])]
        if biz_hits:
            bad = [f for f in biz_hits if ROLE_HIDDEN_NAME.search(f.get("name", "")) and f.get("value", "") != ""]
            kind = "roles/permissions" if bad else "business values (price, discount, amount…)"
            if self._dedupe("biz:" + kind, page_url):
                self.register(
                    title=f"Business logic vulnerable to tampering: {kind}",
                    description="There are hidden fields with values that control "
                                "prices, coupons, quantities or roles. If the server does not "
                                "re-validate them, they could be tampered with from the client.",
                    severity=Severity.MEDIUM, cwe="CWE-840", owasp="A01:2021",
                    url=page_url,
                    evidence="\n".join(f"{f['type']} name={f.get('name')} value={f.get('value')}"
                                       for f in biz_hits[:8]),
                    remediation="Re-validate prices, quantities and permissions on the server; "
                                "never trust hidden form values.")