# 🔒 CyberAudit Pro

**Framework profesional de auditoría y análisis de seguridad web.**  
Diseñado para ingenieros/as de ciberseguridad: **rebusca** en todos los rincones de una
web — cabeceras, cookies, TLS, DNS, subdominios, HTML, JavaScript, formularios, pagos,
paneles de administración, archivos sensibles y servicios expuestos — y genera informes
ejecutivos de alta calidad (HTML / Markdown / JSON).

> #### ⚠️ Aviso legal obligatorio
> Esta herramienta debe usarse **exclusivamente** sobre sistemas de tu propiedad o con
> **autorización expresa por escrito** del propietario. El escaneo o la explotación no
> autorizados pueden constituir delito (en España, art. 197 *bis* del Código Penal;
> Directiva UE 2013/40 y equivalente en cada país). El autor no se responsabiliza del
> mal uso que se le dé a esta herramienta.

---

## 📥 Descargar y usar

```bash
# 1. Clona el repositorio
git clone https://github.com/danielsonn2009-svg/agentedeciberseguridad.git
cd agentedeciberseguridad

# 2. Verifica instalación (solo necesita Python 3.10+, sin dependencias externas)
python main.py --about
```

En **Windows** puedes ejecutar directamente `run.bat` para abrir el menú interactivo.
La carpeta `test_site/` incluye un laboratorio local de práctica para probar el
escáner sin salir de tu máquina.

---

## 🚀 Inicio rápido

```powershell
# Auditoría completa (recomendado si el propietario autoriza)
python main.py -u https://tudominio.com --yes

# Solo chequeo rápido de cabeceras y contenido
python main.py -u https://tudominio.com --yes --no-recon --no-tls --no-directories --no-ports

# Auditoría completa + escaneo de puertos + pruebas de reflexión benignas
python main.py -u https://tudominio.com --yes --ports --active

# Informes sólamente JSON
python main.py -u https://tudominio.com --yes -f json

# Wordlist propia para descubrir rutas
python main.py -u https://tudominio.com --yes --wordlist rutas.txt --max-requests 500

# Listar los módulos disponibles
python main.py --about
```

Los informes se guardan en `reports/` con marca de tiempo.

---

## 🧩 Módulos de análisis

| Módulo | Qué detecta | OWASP |
|--------|-------------|-------|
| `recon` | DNS (A/AAAA/MX/NS/TXT vía DoH), WHOIS/RDAP, subdominios vía transparencia de certificados (crt.sh), huella tecnológica (≈60 tecnologías) | — |
| `osint` | **Inteligencia pasiva externa**: Shodan InternetDB por IP (puertos históricos, CPEs y **CVEs conocidos**), detección de **WAF/CDN** del borde (Cloudflare, Incapsula, Akamai, Vercel…) | A06 |
| `emailsec` | **Postura de correo anti-suplantación**: SPF (`-all` estricto vs `~all`/`+all`), selectores DKIM, DMARC (`p=` none/quarantine/reject) y MX — 100% pasivo vía DNS | A04 |
| `tls` | Caducidad/autofirma/SAN del certificado, TLS 1.0/1.1 obsoletos, ciphers negociados | A02 |
| `headers` | HSTS, CSP (incl. unsafe-inline), clickjacking, nosniff, Referrer-Policy, Permissions-Policy, CORS, banners de servidor, flags de cookies (Secure/HttpOnly/SameSite) | A02/A01/A05 |
| `content` | Crawler del mismo origen; secretos incrustados en JS; sinks peligrosos (eval, innerHTML…); contenido mixto; scripts de terceros sin SRI; **formularios de login sin CSRF**, envío de credenciales por GET/HTTP; **campos ocultos de precio/rol/cupón (manipulación de lógica de negocio)**; subida de archivos; emails y comentarios filtrados | A03/A01/A07/A08 |
| `injection` | Fugas de errores de BD (MySQL/PG/Oracle/Java…), parámetros de interés (id, file, url…), y —con `--active`— **pruebas de reflexión benignas** (XSS) usando un marcador inofensivo | A03 |
| `directories` | Fuerza bruta de rutas (≈175 incorporadas) con hilos: `.git`, `.env`, `actuator`, backups, `wp-config`, `phpinfo`, paneles (401/403/200), robots.txt/security.txt, listados de directorio | A05/A01 |
| `cms` | **Enumeración de CMS** con huella WordPress/Drupal/Joomla/PrestaShop: REST API, usuarios (`wp-json/v2/users`, `?author=N`), `readme.html`/CHANGELOG con versión, `xmlrpc.php`, paneles | A05/A07 |
| `apis` | **Descubrimiento de APIs**: extrae endpoints del JS/HTML, fuzzing de rutas `/api`, `/v1`, `/graphql`, `/actuator`…; detecta **APIs sin autenticación**, datos sensibles expuestos, GraphQL introspection, CORS abierto, errores verbosos | A01/A05 |
| `auth` | **Bypass de login**: rate limiting del login, credenciales enviadas a dominios externos o por GET/HTTP, **tokens/JWT en URLs y en localStorage** (XSS → robo de sesión), política de contraseñas débil, **open redirect** en el flujo de autenticación (sonda benigna) | A07/A01/A03 |
| `payments` | **Fraude/pagos**: pasarelas detectadas (Stripe, PayPal, MercadoPago, Redsys…), **claves secretas de pago filtradas en el cliente** (`sk_live`, `client_secret`), **cálculo de importes en JS** (vector de manipulación del total cobrado), campos ocultos de precio/descuento/cantidad manipulables, checkout en HTTP o sin CSRF | A01/A07/A02 |
| `fuzzer` *(con `--fuzz-login`)* | Prueba acotada de **credenciales por defecto** (admin/admin, root/toor…) en el login con pausas y límite; activable solo explícitamente | A07 |
| `cves` | Analiza `package.json`/`composer.lock`/`requirements.txt` del origen y consulta **CVEs públicos (OSV.dev)** de cada dependencia | A06 |

**Además:** el rastreador lee `sitemap.xml`/`robots.txt` y descarga los **JS del mismo origen**; `apis` consulta el **Wayback Machine** por endpoints históricos; `recon` detecta **subdomain takeover** (CNAME colgante) y WAFs; `headers` prueba **métodos HTTP (TRACE→XST)**; `auth` **decodifica JWTs** del cliente (alg=none, claims sensibles, HMAC débil); `osint` añade a cada IP pública los **CVEs históricos de Shodan** y `emailsec` revisa el **anti-spoofing** del dominio.
| `ports` | Escaneo TCP no intrusivo (≈30 puertos), banners, detección de servicios de datos expuestos (MySQL, MongoDB, Redis, Elastic…), SSH/RDP/Telnet públicos | A05/A07 |

Los informes (JSON/MD/HTML/CSV/SARIF) incluyen además **cobertura del OWASP Top 10** por categoría y una **hoja de ruta de remediación** ejecutiva numerada, junto al impacto económico estimado por hallazgo.

## ⚙️ Opciones principales

| Opción | Descripción |
|--------|-------------|
| `-u/--url` | URL objetivo (se añade `https://` si falta) |
| `-l --list fichero` | **Audita varias URLs** de un fichero (una por línea, `#` para comentar) con resumen consolidado |
| `--yes` | Acepta el aviso de autorización (modo no interactivo) |
| `--cookie` | Cookie de sesión (`--cookie "session=abc"`) para **escaneo autentificado** |
| `--header 'X: y'` | Cabecera extra repetible (tokens, Basic auth…) para escaneo autentificado |
| `--active` | Pruebas benignas de reflexión (marcador XSS sin payload, open redirect, GraphQL) |
| `--delay 0.5` | Pausa entre peticiones (modo cortesía/stealth); `--random-delay` añade jitter |
| `--ports` | Activa el escaneo de puertos TCP |
| `--fuzz-login` | **Prueba credenciales por defecto** en el login (lista acotada, solo autorizado) |
| `--subdomains` | Prueba además una wordlist de subdominios comunes (con **detección de subdomain takeover**) |
| `--proxy` | Proxy HTTP/S (p. ej. `--proxy http://127.0.0.1:8080`) |
| `--insecure` | No verifica certificados TLS |
| `--wordlist` | Wordlist de rutas personalizada (una por línea) |
| `-f json md html csv sarif` | Formatos de informe (SARIF usable en GHAS/Semgrep/VSCode; CSV en hojas de cálculo) |
| `-o carpeta` | Carpeta de salida (por defecto `reports/`) |
| `--include recon tls` / `--exclude …` | Selección de módulos |
| `--no-<modulo>` | Desactivar un módulo (p. ej. `--no-ports`, `--no-osint`, `--no-emailsec`, `--no-cms`) |
| `--config` | Config JSON alternativa |
| `--max-pages`, `--depth`, `--concurrency`, `--timeout` | Límites y rendimiento |

Toda la configuración persistente vive en `config.json` (proxy, límites, formatos…).

---

## 📄 Licencia

Proyecto publicado bajo licencia **MIT** (ver `LICENSE`): puedes descargarlo,
usarlo, modificarlo y compartirlo libremente, manteniendo el aviso de copyright.
Úsalo siempre de forma ética y **solo sobre sistemas autorizados**.