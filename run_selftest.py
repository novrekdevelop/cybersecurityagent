#!/usr/bin/env python3
"""Autocomprobación: sirve test_site y ejecuta una auditoría completa."""
import http.server
import os
import socketserver
import threading

from cyberaudit.cli import main

SITE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_site")
PORT = 8899


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=SITE, **kw)

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main_test():
    server = Server(("127.0.0.1", PORT), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"Servidor local en http://127.0.0.1:{PORT}/")
    code = main([
        "-u", f"http://127.0.0.1:{PORT}",
        "--yes", "--no-color",
        "--no-tls", "--no-directories", "--no-ports",
        "-f", "md", "json", "html",
    ])
    server.shutdown()
    return code


if __name__ == "__main__":
    raise SystemExit(main_test())