#!/usr/bin/env python3
"""Autocomprobación: modo lote (-l) + formatos SARIF/CSV sobre 2 sitios locales."""
import http.server
import os
import socketserver
import sys
import threading
from pathlib import Path

from cyberaudit.cli import main

SITE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_site")


class Static(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


class EchoHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        import urllib.parse
        if self.path.startswith("/echo"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("q", [""])[0]
            body = f"<html><body><div>{q}</div></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


def serve(port, handler_factory):
    class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
    srv = S(("127.0.0.1", port), handler_factory)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    s1 = serve(8899, lambda *a, **k: Static(*a, directory=SITE, **k))
    s2 = serve(8898, EchoHandler)
    lst = Path("objetivos_demo.txt")
    lst.write_text("http://127.0.0.1:8899/\nhttp://127.0.0.1:8898/echo?q=hola\n",
                   encoding="utf-8")
    code = main([
        "-l", str(lst), "--yes", "--no-color",
        "--no-recon", "--no-tls", "--no-directories", "--no-ports", "--no-cves",
        "-f", "sarif", "csv",
    ])
    s1.shutdown(); s2.shutdown()
    sys.exit(code)