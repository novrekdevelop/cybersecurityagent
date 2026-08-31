#!/usr/bin/env python3
"""Autocomprobación de los módulos nuevos (osint, emailsec, cms).

Sirve un sitio tipo WordPress detrás de un "borde" que simula Cloudflare
(cabeceras cf-ray/Server) para que:
  - osint      detecte el WAF/perímetro (hallazgo INFO) y salte InternetDB
               con elegancia en IPs privadas.
  - cms        enumere WordPress (REST API + usuarios) gracias a los marcadores
               wp-content/generator.
  - emailsec   se omita con elegancia en objetivos tipo IP (localhost).
"""
import http.server
import json
import socketserver
import threading
import urllib.parse

from cyberaudit.cli import main

PORT = 8893

INDEX = """<!DOCTYPE html><html><head><title>Mi WordPress</title>
<meta name="generator" content="WordPress 6.4.3">
<link rel="stylesheet" href="/wp-content/themes/tema/style.css"></head>
<body><h1>Blog</h1><a href="/wp-admin/">Admin</a>
<script src="/wp-includes/js/jquery.js"></script></body></html>"""

USERS = json.dumps([
    {"slug": "admin", "name": "Admin", "link": "http://127.0.0.1:8893/author/admin"},
    {"slug": "editor", "name": "Editor", "link": "http://127.0.0.1:8893/author/editor"},
])

README = """<h1>WordPress</h1><p>Version 6.4.3</p>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # Simula un borde Cloudflare (para que osint lo detecte)
        self.send_header("cf-ray", "7f1a2b3c4d5e-MAD")
        self.send_header("Server", "cloudflare")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            return self._send(200, INDEX)
        if path == "/wp-json/":
            return self._send(200, '{"name":"mi-wordpress","namespaces":["wp/v2"]}',
                              "application/json")
        if path == "/wp-json/wp/v2/users":
            return self._send(200, USERS, "application/json")
        if path == "/readme.html":
            return self._send(200, README)
        if urllib.parse.urlparse(self.path).query.startswith("author=1"):
            return self._send(301, "", extra={"Location": "/author/admin"})
        return self._send(404, "<h1>404</h1>")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main_test():
    server = Server(("127.0.0.1", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"WordPress simulado con WAF en http://127.0.0.1:{PORT}/")

    # Verificación previa de granularidad de módulos nuevos
    from cyberaudit import engine
    names = {m.name for m in engine.MODULES}
    assert {"osint", "emailsec", "cms"} <= names, f"Faltan módulos: {names}"

    code = main([
        "-u", f"http://127.0.0.1:{PORT}",
        "--yes", "--no-color",
        "--no-tls", "--no-directories", "--no-ports", "--no-cves",
        "--no-payments", "--no-fuzzer",
        "-f", "json",
    ])

    # Comprobar que los hallazgos de los módulos nuevos han aparecido
    import glob
    import os
    rep = sorted(glob.glob(os.path.join("reports", f"informe_127.0.0.1_{PORT}_*.json")),
                 key=os.path.getmtime)[-1]
    data = json.load(open(rep, encoding="utf-8"))
    mods = {f["module"] for f in data["hallazgos"]}
    print("\nMódulos con hallazgos:", sorted(mods))
    assert "cms" in mods, "El módulo cms no generó hallazgos"
    assert "osint" in mods, "El módulo osint no generó hallazgos (WAF no detectado)"
    assert "emailsec" not in mods, "emailsec no debería generar hallazgos en IP privada"
    server.shutdown()
    print("Módulos nuevos verificados correctamente ✔")
    return code


if __name__ == "__main__":
    raise SystemExit(main_test())