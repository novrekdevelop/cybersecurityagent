#!/usr/bin/env python3
"""Valida el fuzzer de credenciales: sitio con login vulnerable a admin/admin."""
import http.server
import socketserver
import threading
import urllib.parse

from cyberaudit.cli import main

PORT = 8896

LOGIN = """<!DOCTYPE html><html><head><title>Login</title></head><body>
<form action="/login" method="POST">
<input type="text" name="usuario"><input type="password" name="pass">
<input type="hidden" name="csrf" value="abc123">
<button>Entrar</button>
</form></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/login"):
            body = LOGIN.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        params = dict(urllib.parse.parse_qsl(body))
        logged = params.get("usuario") == "admin" and params.get("pass") == "admin"
        if logged:
            out = "<html><body>Bienvenido, admin. <a href='/logout'>Salir</a></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out.encode())
        else:
            out = "<html><body>Credenciales incorrectas</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out.encode())


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main_test():
    server = Server(("127.0.0.1", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("Servidor login vulnerable en http://127.0.0.1:%d/login" % PORT)
    code = main([
        "-u", f"http://127.0.0.1:{PORT}/login",
        "--yes", "--no-color",
        "--fuzz-login",
        "--no-recon", "--no-tls", "--no-headers", "--no-content", "--no-injection",
        "--no-directories", "--no-ports", "--no-apis", "--no-auth", "--no-payments",
        "-f", "json", "html",
    ])
    server.shutdown()
    return code


if __name__ == "__main__":
    raise SystemExit(main_test())