"""Shared utilities: console, URLs, secret detection, DNS and wordlists."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import List, Optional
from urllib import request as _request
from urllib.parse import urljoin, urlparse, urlunparse

# --------------------------------------------------------------------------- console
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
BLUE = "\033[94m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"

_COLOR_ON = True


def enable_windows_ansi() -> None:
    """Enables ANSI support on Windows 10+ consoles (VT100)."""
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


def set_color(enabled: bool) -> None:
    global _COLOR_ON
    _COLOR_ON = enabled


def paint(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if _COLOR_ON else text


def cprint(text: str = "", code: str = RESET, bold: bool = False, end: str = "\n") -> None:
    prefix = BOLD if bold else ""
    sys.stdout.write(prefix + paint(str(text), code) + end)
    sys.stdout.flush()


def ok(msg: str) -> None:
    cprint("  ✔  " + msg, GREEN)


def warn(msg: str) -> None:
    cprint("  !  " + msg, YELLOW)


def err(msg: str) -> None:
    cprint("  ✖  " + msg, RED)


def info(msg: str) -> None:
    cprint("  ·  " + msg, CYAN)


# --------------------------------------------------------------------------- URLs
def normalize_url(raw: str) -> str:
    """Normalizes a URL, adding https:// if missing and cleaning the path."""
    url = raw.strip()
    if not url:
        raise ValueError("Empty URL.")
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    u = urlparse(url)
    if not u.netloc:
        raise ValueError(f"Invalid URL: {raw!r}")
    host = u.netloc.lower()
    path = u.path or "/"
    return urlunparse((u.scheme.lower(), host, path, u.params, u.query, u.fragment))


def origin_of(url: str) -> str:
    u = urlparse(url)
    return f"{u.scheme.lower()}://{u.netloc.lower()}"


def host_of(url: str) -> str:
    return urlparse(url).netloc.lower().split(":")[0]


def same_origin(a: str, b: str) -> bool:
    return origin_of(a) == origin_of(b)


def absolute(base: str, ref: str) -> Optional[str]:
    """Converts a relative reference into an absolute http(s) URL."""
    url = urljoin(base, ref.strip())
    if url.startswith(("http://", "https://")):
        return url
    return None


def strip_fragment(url: str) -> str:
    u = urlparse(url)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, u.query, ""))


# --------------------------------------------------------------------------- DNS / DoH
_DOH_TYPE = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "TXT": 16, "NS": 2}


def doh_lookup(domain: str, rtype: str, timeout: float = 6.0, us: str = "CyberAuditPro/2.0") -> List[str]:
    """Queries DNS records via DNS over HTTPS (Cloudflare), no external binaries.

    Returns the answers for the requested type ('' if it fails or doesn't exist).
    """
    type_id = _DOH_TYPE.get(rtype.upper())
    if not type_id:
        return []
    url = (f"https://cloudflare-dns.com/dns-query?name={domain}&type={type_id}")
    try:
        req = _request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": us})
        with _request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        return [str(a.get("data", "")) for a in data.get("Answer", [])
                if a.get("type") == type_id]
    except Exception:
        return []


def doh_txt(domain: str) -> List[str]:
    """TXT records for a domain (useful for SPF/DKIM/DMARC)."""
    return doh_lookup(domain, "TXT")


# --------------------------------------------------------------------------- secrets
SECRET_PATTERNS: dict = {
    "private_key": re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "stripe_secret": re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{16,}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    "embedded_jwt": re.compile(r"\beyJ[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{8,}\b"),
    "password_in_code": re.compile(r"""(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{3,}["']"""),
    "secret_in_code": re.compile(r"""(?i)(secret|client_secret|app_secret|api_secret)\s*[:=]\s*["'][^"']{3,}["']"""),
    "static_authorization": re.compile(r"""(?i)(authorization|bearer)\s*[:=]\s*["'][A-Za-z0-9\-._~+/]{12,}["']"""),
    "firebase_token": re.compile(r"\bAAAA[A-Za-z0-9_\-]{80,}\b"),
    "recaptcha_key": re.compile(r"\b6L[0-9A-Za-z_\-]{38}\b"),
}

# Dangerous JavaScript sinks
JS_DANGEROUS_SINKS = [
    (re.compile(r"\beval\s*\("), "eval() executes arbitrary code from strings"),
    (re.compile(r"\bdocument\.write\s*\("), "document.write() can inject unsanitized content"),
    (re.compile(r"\b\.innerHTML\s*="), "innerHTML allows HTML/JS injection"),
    (re.compile(r"\bouterHTML\s*="), "outerHTML allows HTML/JS injection"),
    (re.compile(r"\bdangerouslySetInnerHTML"), "dangerouslySetInnerHTML (React) injects raw HTML"),
    (re.compile(r"\binsertAdjacentHTML\s*\("), "insertAdjacentHTML can inject HTML"),
    (re.compile(r"\bpostMessage\s*\(\s*['\"][^*]"), "postMessage to unverified origins"),
]


def detect_secrets(text: str) -> List[str]:
    """Returns the list of secret types found in a text (sample ≤200KB)."""
    found: List[str] = []
    sample = text[:200_000]
    for name, pat in SECRET_PATTERNS.items():
        if pat.search(sample):
            found.append(name)
    return found


# --------------------------------------------------------------------------- errors
ERROR_PATTERNS = [
    (re.compile(r"(?i)sql syntax|mysql_fetch|sqlstate\[|you have an error in your sql"),
     "Classic SQL error (MySQL)"),
    (re.compile(r"(?i)unclosed quotation mark|microsoft oledb"), "SQL Server error"),
    (re.compile(r"(?i)duplicate key val|psycopg2|postgresql"), "SQL error (PostgreSQL/ORM)"),
    (re.compile(r"(?i)ora-\d{5}"), "Oracle error"),
    (re.compile(r"(?i)java\.sql\.sqlexception|jdbc\."), "Java/SQL error"),
    (re.compile(r"(?i)debug\s*=\s*true|traceback \(most recent call last\)|line \d+, in "),
     "Traceback or debug mode active"),
    (re.compile(r"(?i)xdebug|stack trace:"), "Debugging active"),
]

# --------------------------------------------------------------------------- wordlists
COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "web", "smtp", "pop", "imap", "mx", "ftp", "ssh",
    "vpn", "remote", "admin", "portal", "intranet", "extranet", "internal",
    "api", "app", "m", "mobile", "secure", "sso", "auth", "login", "idp",
    "keycloak", "oauth", "gateway", "proxy", "cdn", "static", "assets",
    "img", "images", "media", "files", "uploads", "dev", "stage", "staging",
    "test", "uat", "qa", "pre", "preprod", "demo", "git", "gitlab", "jenkins",
    "sonar", "ci", "cd", "build", "deploy", "blog", "shop", "store", "status",
    "help", "support", "docs", "forum", "community", "news", "calendar",
    "office", "owa", "exchange", "autodiscover", "cpanel", "whem", "plesk",
    "db", "mysql", "database", "mongo", "mongodb", "redis", "elastic", "elk",
    "kibana", "grafana", "monitoring", "zabbix", "nagios", "logs", "backup",
]

# Sensitive paths and files
DIRECTORY_WORDLIST: List[str] = [
    # Admin panels and management areas
    "admin", "administrator", "admin.php", "admin/", "backend", "backoffice",
    "panel", "console", "dashboard", "wp-admin", "wp-login.php", "wp-content",
    "wp-includes", "wp-json", "administrator/", "adminer.php", "phpmyadmin",
    "pma", "pgadmin", "mysql/", "dbadmin", "maaticket", "webmail",
    # Authentication
    "login", "signin", "signup", "auth", "account", "user", "users",
    "register", "password", "reset", "forgot", "sso", "oauth",
    # API and documentation
    "api", "api/", "api/v1", "api/v2", "graphql", "rest", "swagger-ui.html",
    "swagger/", "swagger/index.html", "api-docs", "openapi.json", "v2/api-docs",
    "actuator", "actuator/env", "actuator/health", "actuator/beans",
    # Version control and configuration
    ".git/", ".git/config", ".git/HEAD", ".gitignore", ".hg/", ".svn/",
    ".env", ".env.local", ".env.production", ".env.dev", "config.php",
    "config.php.bak", "config.php~", "configuration.php", "settings.php",
    "wp-config.php", "wp-config.php.bak", "wp-config.php~", "web.config",
    ".htaccess", ".htpasswd", "db.php", "database.php", "conn.php",
    "index.php.bak", "index.php~", "config.inc.php", "application.ini",
    # Backups and database dumps
    "databases.sql", "db.sql", "dump.sql", "backup.sql", "database.sql",
    "backup.zip", "backup.tar.gz", "backup.tar", "site.zip", "site.tar.gz",
    "backups/", "backups.zip", "bbdd.sql", "dump/", "archive/", "old/",
    # System metadata files
    ".DS_Store", "Thumbs.db", "desktop.ini", "package-lock.json",
    "composer.json", "composer.lock", "package.json", "yarn.lock",
    "vendor/", "node_modules/", "environment.json", "runtime.json",
    # Public information
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
    "crossdomain.xml", "clientaccesspolicy.xml", "humans.txt",
    "README", "README.md", "LICENSE", "CHANGELOG", "INSTALL", "UPGRADE",
    "phpinfo.php", "info.php", "test.php", "info", "version", "server-status",
    "server-info", "status", "health", "healthz", "ping", "debug",
    # Logs and traces
    "log/", "logs/", "log.txt", "error.log", "access.log", "debug.log",
    "trace.log", "application.log", "nginx/logs/", "logging/",
    # Content directories
    "upload/", "uploads/", "upload.php", "images/", "img/", "js/", "css/",
    "assets/", "fonts/", "media/", "files/", "tmp/", "temp/", "cache/",
    # Other common endpoints
    "xmlrpc.php", "owa", "exchange", "autodiscover", "actuator", "selenium",
    "cgi-bin/", "scripts/", "cron", "cron.php", "shell", "server-diagnostics",
    "service-worker.js", "manifest.json", "content.xml", "crossdomain",
]
def load_wordlist(path: Optional[str] = None) -> List[str]:
    """Loads a directory wordlist from a file or uses the built-in one."""
    if path and Path(path).exists():
        lines = [
            ln.strip()
            for ln in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
        return lines
    return DIRECTORY_WORDLIST


def read_robots_disallow(text: str) -> List[str]:
    """Extracts Disallow rules from a robots.txt."""
    out: List[str] = []
    for line in text.splitlines():
        if line.lower().startswith("disallow"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                out.append(parts[1].strip())
    return out