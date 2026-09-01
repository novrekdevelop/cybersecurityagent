#!/usr/bin/env python3
"""Self-test of the new modules (osint, emailsec, cms).

Serves a WordPress-like site behind an "edge" that simulates Cloudflare
(cf-ray/Server headers) so that:
  - osint      detects the WAF/perimeter (INFO finding) and skips InternetDB
               gracefully on private IPs.
  - cms        enumerates WordPress (REST API + users) thanks to the
               wp-content/generator markers.
  - emailsec   is skipped gracefully on IP-type targets (localhost).
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
        # Simulates a Cloudflare edge (so osint detects it)
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
    print(f"Simulated WordPress with WAF at http://127.0.0.1:{PORT}/")

    # Pre-check of the new modules granularity
    from cyberaudit import engine
    names = {m.name for m in engine.MODULES}
    assert {"osint", "emailsec", "cms"} <= names, f"Missing modules: {names}"

    code = main([
        "-u", f"http://127.0.0.1:{PORT}",
        "--yes", "--no-color",
        "--no-tls", "--no-directories", "--no-ports", "--no-cves",
        "--no-payments", "--no-fuzzer",
        "-f", "json",
    ])

    # Check that the new modules findings appeared
    import glob
    import os
    rep = sorted(glob.glob(os.path.join("reports", f"report_127.0.0.1_{PORT}_*.json")),
                 key=os.path.getmtime)[-1]
    data = json.load(open(rep, encoding="utf-8"))
    mods = {f["module"] for f in data["findings"]}
    print("\nModules with findings:", sorted(mods))
    assert "cms" in mods, "The cms module produced no findings"
    assert "osint" in mods, "The osint module produced no findings (WAF not detected)"
    assert "emailsec" not in mods, "emailsec should not produce findings on a private IP"
    server.shutdown()
    print("New modules verified correctly ✔")
    return code


if __name__ == "__main__":
    raise SystemExit(main_test())