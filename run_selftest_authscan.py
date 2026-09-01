#!/usr/bin/env python3
"""Self-test: authenticated scan with --cookie and --header."""
import http.server
import socketserver
import sys
import threading

from cyberaudit.cli import main

PORT = 8895


class AuthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        token = self.headers.get("X-Auth-Token", "")
        if "session_id=valid123" in cookie or token == "secret-token":
            body = ("<html><head><title>Dashboard admin</title></head><body>"
                    "<h1>Welcome admin</h1><a href='/logout'>Logout</a></body></html>").encode()
            self.send_response(200)
        else:
            body = b"<html><body>Access denied</body></html>"
            self.send_response(401)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    srv = S(("127.0.0.1", PORT), AuthHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    print("--- WITHOUT cookie (should detect 401) ---")
    main(["-u", f"http://127.0.0.1:{PORT}/", "--yes", "--no-color",
          "--no-recon", "--no-tls", "--no-directories", "--no-ports",
          "--no-cves", "-f", "json"])
    print("--- WITH authenticated cookie ---")
    main(["-u", f"http://127.0.0.1:{PORT}/", "--yes", "--no-color",
          "--cookie", "session_id=valid123",
          "--header", "X-Auth-Token: secret-token",
          "--no-recon", "--no-tls", "--no-directories", "--no-ports",
          "--no-cves", "-f", "json"])
    srv.shutdown()
    sys.exit(0)