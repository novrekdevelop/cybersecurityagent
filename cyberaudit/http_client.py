"""Cliente HTTP robusto sin dependencias externas (solo stdlib).

Ofrece cookies, redirecciones, proxies, compresión gzip/deflate, control de
TLS y reintentos básicos para las peticiones de auditoría.
"""

from __future__ import annotations

import gzip
import http.cookiejar
import random
import socket
import ssl
import time
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib import error, request
from urllib.parse import urlencode, urlparse

from .config import AppConfig


@dataclass
class HttpResponse:
    status: int = 0
    reason: str = ""
    url: str = ""
    body: bytes = b""
    elapsed: float = 0.0
    error: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    header_items: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    def headers_by_name(self, name: str) -> List[str]:
        low = name.lower()
        return [v for k, v in self.header_items if k == low]


def _decompress(raw: bytes, content_encoding: str) -> bytes:
    if not raw:
        return raw
    enc = (content_encoding or "").lower()
    if "gzip" in enc:
        try:
            return gzip.decompress(raw)
        except (OSError, zlib.error):
            return raw
    if "deflate" in enc:
        try:
            return zlib.decompress(raw)
        except zlib.error:
            try:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
            except zlib.error:
                return raw
    return raw


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpClient:
    """Cliente HTTP de auditoría con sesión persistente de cookies."""

    def __init__(self, config: AppConfig):
        self.timeout = config.timeout
        self.user_agent = config.user_agent
        self.proxy = config.proxy
        self.verify_tls = config.verify_tls
        self.session_cookie = config.session_cookie
        self.extra_headers = dict(config.extra_headers or {})
        self.delay = config.delay
        self.random_delay = config.random_delay
        self.cookies = http.cookiejar.CookieJar()
        self._opener = self._build_opener(follow=True)
        self._opener_noredirect = self._build_opener(follow=False)

    def _tls_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _build_opener(self, follow: bool):
        handlers = []
        proxies = {}
        if self.proxy:
            proxies = {"http": self.proxy, "https": self.proxy}
        handlers.append(request.ProxyHandler(proxies))
        handlers.append(request.HTTPCookieProcessor(self.cookies))
        handlers.append(request.HTTPRedirectHandler() if follow else _NoRedirect())
        handlers.append(request.HTTPSHandler(context=self._tls_context()))
        return request.build_opener(*handlers)

    def _default_headers(self, extra: Optional[Dict[str, str]]) -> Dict[str, str]:
        h = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        }
        if self.session_cookie:
            h["Cookie"] = self.session_cookie
        h.update(self.extra_headers)
        if extra:
            h.update(extra)
        return h

    def _polite_wait(self) -> None:
        """Espera configurada entre peticiones (modo cortesía/stealth)."""
        if self.delay > 0:
            wait = self.delay
            if self.random_delay:
                wait = self.delay * random.uniform(0.6, 1.5)
            time.sleep(wait)

    def request(
        self,
        method: str,
        url: str,
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        timeout: Optional[float] = None,
        raw_body: bool = False,
    ) -> HttpResponse:
        """Ejecuta una petición y devuelve un HttpResponse normalizado."""
        self._polite_wait()
        req = request.Request(url, data=data, headers=self._default_headers(headers))
        req.method = method.upper()
        opener = self._opener if follow_redirects else self._opener_noredirect
        t0 = time.monotonic()
        try:
            with opener.open(req, timeout=timeout or self.timeout) as resp:
                status = resp.getcode() or resp.status
                reason = getattr(resp, "reason", "")
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                items = [(k.lower(), v) for k, v in resp.headers.items()]
                encoding = hdrs.get("content-encoding", "")
                body = _decompress(resp.read(), encoding) if not raw_body else resp.read()
                return HttpResponse(status=status, reason=reason, url=resp.geturl(),
                                    body=body, elapsed=time.monotonic() - t0,
                                    headers=hdrs, header_items=items)
        except error.HTTPError as e:
            body = b""
            try:
                body = e.read()
            except Exception:
                pass
            hdrs = {k.lower(): v for k, v in e.headers.items()}
            items = [(k.lower(), v) for k, v in e.headers.items()]
            if not raw_body:
                body = _decompress(body, hdrs.get("content-encoding", ""))
            return HttpResponse(status=e.code, reason=e.reason, url=e.geturl() or url,
                                body=body, elapsed=time.monotonic() - t0,
                                headers=hdrs, header_items=items)
        except (error.URLError, socket.timeout, TimeoutError, ConnectionResetError,
                ConnectionRefusedError, ConnectionAbortedError, ssl.SSLError,
                ssl.CertificateError, OSError) as e:
            return HttpResponse(error=f"{type(e).__name__}: {e}", url=url)

    # ------------------------------------------------------------------ atajos
    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def options(self, url, **kw):
        return self.request("OPTIONS", url, **kw)

    def post(self, url, data: bytes, headers=None):
        return self.request("POST", url, data=data, headers=headers)

    def get_params(self, url, params: Dict[str, str], **kw):
        sep = "&" if urlparse(url).query else "?"
        return self.get(f"{url}{sep}{urlencode(params)}", **kw)