#!/usr/bin/env python3
"""Test of ports + active modules: starts test_site, scans ports and reflects a marker."""
import http.server
import os
import socketserver
import threading

from cyberaudit.cli import main

SITE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_site")
PORT = 8898


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=SITE, **kw)

    def log_message(self, *a):
        pass

    # Endpoint that reflects the 'q' parameter (to test benign reflection)
    def do_GET(self):
        if self.path.startswith("/echo"):
            import urllib.parse
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("q", [""])[0]
            body = f"<html><body><div class='result'>{q}</div></body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main_test():
    server = Server(("127.0.0.1", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"Server with /echo at http://127.0.0.1:{PORT}/")
    code = main([
        "-u", f"http://127.0.0.1:{PORT}/echo?q=hola",
        "--yes", "--no-color",
        "--ports", "--active",
        "--no-recon", "--no-tls", "--no-directories",
        "-f", "json",
    ])
    server.shutdown()
    return code


if __name__ == "__main__":
    raise SystemExit(main_test())