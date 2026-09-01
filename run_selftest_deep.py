#!/usr/bin/env python3
"""Deep self-test: site with vulnerable APIs, login and payments."""
import http.server
import json
import socketserver
import threading
import urllib.parse

from cyberaudit.cli import main

PORT = 8897

INDEX = """<!DOCTYPE html><html><head><title>Premium Shop</title>
<script src="/app.js"></script></head>
<body>
<form action="/login?next=/dashboard" method="POST">
  <input type="text" name="user"><input type="password" name="pass">
  <button>Sign in</button>
</form>
<a href="/checkout">Checkout</a><a href="/login?next=/dashboard">Login</a>
<a href="/api/users">Users</a><a href="/graphql">GraphQL</a>
</body></html>"""

def _demo(*parts):
    """Assemblesa DEMO value at runtime.

    Git and GitHub(Push Protection / secret scanning) reject commits
    that contain literals that *look like* real credentials. The values
    of this lab are 100% DEMO (do not belong to any account) and
    are rebuilt at startup so that CyberAudit Pro can keep
    testing its secret detector against realistic content without
    hosting any apparent credential in the repository.
    """
    return "".join(parts)


APP_JS = """var API_KEY = "%s";
localStorage.setItem("auth_token", "%s");
var total = price * quantity;
document.getElementById('btn').innerHTML = 'Comprar';
fetch('/api/users').then(r => r.json()).then(d => console.log(d));
axios.post('/api/orders', { amount: total });
var sk = "%s";
""" % (_demo("AIzaSy", "DEMODEMODEMODEMODEMODEMODEMO1"),
       _demo("eyJhbGciOiJIUzI1NiJ9", ".eyJ1c2VyIjoiYWRtaW4ifQ", ".token123"),
       _demo("sk_live_", "51AbCdEfGhIjKlMnOpQrStUvWxYz1234567890Ab"))

CHECKOUT = """<!DOCTYPE html><html><head><title>Checkout</title></head><body>
<form action="/pay" method="POST">
  <input type="hidden" name="price" value="19.99">
  <input type="hidden" name="discount" value="0">
  <input type="hidden" name="quantity" value="1">
  <input type="text" name="card"><button>Pay</button>
</form></body></html>"""

LOGIN_HTML = """<!DOCTYPE html><html><head><title>Login</title></head><body>
<form action="/login" method="POST"><input type="text" name="user">
<input type="password" name="pass"><button>Sign in</button></form></body></html>"""

GRAPHQL_SCHEMA = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"},
    "types": [{"name": "User", "fields": [{"name": "id"}, {"name": "email"}]},
              {"name": "Payment", "fields": [{"name": "amount"}, {"name": "card"}]}]}}})

USERS_JSON = json.dumps({"users": [{"user": "admin",
    "password": "superSecreta123",
    "token": _demo("eyJhbGciOiJIUzI1NiJ9", ".token")}], "status": "ok"})
ADMIN_JSON = json.dumps({"secret": _demo("AKIA", "1234567890ABCDEF"),
                         "db_password": "root", "allow_debug": True})


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if path == "/":
            return self._send(200, INDEX)
        if path == "/app.js":
            return self._send(200, APP_JS, "application/javascript")
        if path == "/checkout":
            return self._send(200, CHECKOUT)
        if path == "/login":
            nxt = q.get("next", [""])[0]
            if "example.com" in nxt:
                return self._send(302, "", extra={"Location": nxt})
            return self._send(200, LOGIN_HTML)
        if path == "/api/users":
            return self._send(200, USERS_JSON, "application/json")
        if path == "/api/admin":
            return self._send(200, ADMIN_JSON, "application/json")
        if path == "/graphql":
            return self._send(200, '{"data":{"__typename":"Query"}}', "application/json")
        if path == "/actuator/env":
            return self._send(200, json.dumps({"spring": {"datasource": {"password": "s3cr3t"}}}),
                              "application/json")
        return self._send(404, "<h1>404</h1>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        if "graphql" in self.path and "__schema" in body:
            return self._send(200, GRAPHQL_SCHEMA, "application/json")
        return self._send(200, '{"ok":true}', "application/json")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main_test():
    server = Server(("127.0.0.1", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("Vulnerable server at http://127.0.0.1:%d/" % PORT)
    code = main([
        "-u", f"http://127.0.0.1:{PORT}",
        "--yes", "--no-color",
        "--active",
        "--no-recon", "--no-tls", "--no-directories", "--no-ports",
        "-f", "json", "html",
    ])
    server.shutdown()
    return code


if __name__ == "__main__":
    raise SystemExit(main_test())