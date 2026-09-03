# 🔒 CyberAudit Pro

**Professional web security auditing and analysis framework.**
Designed for cybersecurity engineers — it **probes** every corner of a
web — headers, cookies, TLS, DNS, subdomains, HTML, JavaScript, forms, payments,
admin panels, sensitive files and exposed services — and generates executive
high-quality reports (HTML / Markdown / JSON).

> #### ⚠️ Mandatory legal notice
> This tool must be used **exclusively** against systems you own or with
> **express written authorization** from the owner. Unauthorized scanning or exploitation
> may constitute a crime (in Spain, art. 197 *bis* of the Penal Code;
> EU Directive 2013/40 and equivalent in each country). The author is not responsible for
> misuse of this tool.

---

## 📥 Download and usage

```bash
# 1. Clone the repository
git clone https://github.com/novrekdevelop/cybersecurityagent.git
cd agentedeciberseguridad

# 2. Verify the installation (only needs Python 3.10+, no external dependencies)
python main.py --about
```

It only needs **Python 3.10+** (no external dependencies) and runs on
**Windows, Linux and macOS**. Use the launcher that fits your platform:

| Platform                          | Command                                   |
|-----------------------------------|-------------------------------------------|
| **Windows**                       | `run.bat` (double-click, or `.\run.bat`)  |
| **Linux / macOS**                 | `./run.sh` (first time: `chmod +x run.sh`) |
| **Any OS with `make`/Git Bash**   | `make run` (same interactive menu)        |
| **Any OS after `pip install -e .`** | `cyberaudit` (global CLI command)        |

The `test_site/` folder includes a local practice lab to test the
scanner without leaving your machine.

---

## 🚀 Quick start

```powershell
# Full audit (recommended if the owner authorizes)
python main.py -u https://yourdomain.com --yes

# Only a quick check of headers and content
python main.py -u https://yourdomain.com --yes --no-recon --no-tls --no-directories --no-ports

# Full audit + port scanning + benign reflection tests
python main.py -u https://yourdomain.com --yes --ports --active

# JSON-only reports
python main.py -u https://yourdomain.com --yes -f json

# Your own wordlist to discover paths
python main.py -u https://yourdomain.com --yes --wordlist routes.txt --max-requests 500

# List the available modules
python main.py --about
```

> 💡 **Developer shortcuts:** `make run` opens the interactive menu,
> `make audit URL=https://example.com` runs a full audit,
> `make demo` serves the local practice lab, and `make selftest` runs the
> self-test suite.

**One-step launchers:** if you prefer a menu without typing a target, run
`run.bat` on Windows or `./run.sh` on Linux/macOS.

Reports are saved in `reports/` with a timestamp.

---

## 🧩 Analysis modules

| Module | What it detects | OWASP |
|--------|-------------|-------|
| `recon` | DNS (A/AAAA/MX/NS/TXT via DoH), WHOIS/RDAP, subdomains via certificate transparency (crt.sh), technology fingerprint (~60 technologies) | — |
| `osint` | **Passive external intelligence**: Shodan InternetDB by IP (historical ports, CPEs and **known CVEs**), edge **WAF/CDN** detection (Cloudflare, Incapsula, Akamai, Vercel…) | A06 |
| `emailsec` | **Anti-spoofing email posture**: SPF (`-all` strict vs `~all`/`+all`), DKIM selectors, DMARC (`p=` none/quarantine/reject) and MX — 100% passive via DNS | A04 |
| `tls` | Certificate expiry/self-signed/SAN, obsolete TLS 1.0/1.1, negotiated ciphers | A02 |
| `headers` | HSTS, CSP (incl. unsafe-inline), clickjacking, nosniff, Referrer-Policy, Permissions-Policy, CORS, server banners, cookie flags (Secure/HttpOnly/SameSite) | A02/A01/A05 |
| `content` | Same-origin crawler; embedded secrets in JS; dangerous sinks (eval, innerHTML…); mixed content; third-party scripts without SRI; **login forms without CSRF**, credentials sent by GET/HTTP; **hidden price/role/coupon fields (business logic manipulation)**; file upload; filtered emails and comments | A03/A01/A07/A08 |
| `injection` | Database error leaks (MySQL/PG/Oracle/Java…), interesting parameters (id, file, url…), and — with `--active` — **benign reflection tests** (XSS) using a harmless marker | A03 |
| `directories` | Path brute force (≈175 built-in) with threads: `.git`, `.env`, `actuator`, backups, `wp-config`, `phpinfo`, panels (401/403/200), robots.txt/security.txt, directory listings | A05/A01 |
| `cms` | **CMS enumeration** with WordPress/Drupal/Joomla/PrestaShop fingerprint: REST API, users(`wp-json/v2/users`, `?author=N`), `readme.html`/CHANGELOG with version, `xmlrpc.php`, panels | A05/A07 |
| `apis` | **API discovery**: extracts endpoints from JS/HTML, path fuzzing `/api`, `/v1`, `/graphql`, `/actuator`…; detects **unauthenticated APIs**, exposed sensitive data, GraphQL introspection, open CORS, verbose errors | A01/A05 |
| `auth` | **Login bypass**: login rate limiting, credentials sent to external domains or by GET/HTTP, **tokens/JWT in URLs and in localStorage** (XSS → session theft), weak password policy, **open redirect** in the authentication flow (benign probe) | A07/A01/A03 |
| `payments` | **Fraud/payments**: detected gateways (Stripe, PayPal, MercadoPago, Redsys…), **secret payment keys leaked in the client** (`sk_live`, `client_secret`), **amount calculation in JS** (manipulation vector of the charged total), manipulable hidden price/discount/quantity fields, checkout on HTTP or without CSRF | A01/A07/A02 |
| `fuzzer` *(with `--fuzz-login`)* | Bounded **default credential** test (admin/admin, root/toor…) on the login with pauses and limit; only explicitly activable | A07 |
| `cves` | Analyzes `package.json`/`composer.lock`/`requirements.txt` of the origin and queries **public CVEs (OSV.dev)** for each dependency | A06 |

**Also:** the crawler reads `sitemap.xml`/`robots.txt` and downloads same-origin **JS**; `apis` queries the **Wayback Machine** for historical endpoints; `recon` detects **subdomain takeover** (dangling CNAME) and WAFs; `headers` tests **HTTP methods (TRACE→XST)**; `auth` **decodes JWTs** from the client (alg=none, sensitive claims, weak HMAC); `osint` adds for each public IP the **historical Shodan CVEs** and `emailsec` reviews the domain's **anti-spoofing** posture.
| `ports` | Non-intrusive TCP scanning (≈30 ports), banners, detection of exposed data services (MySQL, MongoDB, Redis, Elastic…), public SSH/RDP/Telnet | A05/A07 |

The reports (JSON/MD/HTML/CSV/SARIF) also include **OWASP Top 10 coverage** by category and a numbered executive **remediation roadmap**, together with the estimated economic impact by finding.
---

## ⚙️ Main options

| Option | Description |
|--------|-------------|
| `-u/--url` | Target URL (`https://` is added if missing) |
| `-l --list file` | **Audits several URLs** from a file (one per line, `#` for comments) with consolidated summary |
| `--yes` | Accepts the authorization notice (non-interactive mode) |
| `--cookie` | Session cookie (`--cookie "session=abc"`) for **authenticated scanning** |
| `--header 'X: y'` | Extra repeatable header (tokens, Basic auth…) for authenticated scanning |
| `--active` | Benign reflection tests (XSS marker without payload, open redirect, GraphQL) |
| `--delay 0.5` | Pause between requests (courtesy/stealth mode); `--random-delay` adds jitter |
| `--ports` | Enables TCP port scanning |
| `--fuzz-login` | **Tests default credentials** on the login (bounded list, authorized only) |
| `--subdomains` | Also tests a wordlist of common subdomains (with **subdomain takeover detection**) |
| `--proxy` | HTTP/S proxy (e.g. `--proxy http://127.0.0.1:8080`) |
| `--insecure` | Does not verify TLS certificates |
| `--wordlist` | Custom path wordlist (one per line) |
| `-f json md html csv sarif` | Report formats (SARIF usable in GHAS/Semgrep/VSCode; CSV in spreadsheets) |
| `-o folder` | Output folder (default `reports/`) |
| `--include recon tls` / `--exclude …` | Module selection |
| `--no-<module>` | Disable a module (e.g. `--no-ports`, `--no-osint`, `--no-emailsec`, `--no-cms`) |
| `--config` | Alternative JSON config |
| `--max-pages`, `--depth`, `--concurrency`, `--timeout` | Limits and performance |

All persistent configuration lives in `config.json` (proxy, limits, formats…).

---

## 📄 License

Project published under the **MIT** license (see `LICENSE`): you can download,
use, modify and share it freely, keeping the copyright notice.
Always use it ethically and **only against authorized systems**.
