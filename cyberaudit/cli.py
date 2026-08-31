"""Interfaz de línea de comandos de CyberAudit Pro."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .config import AppConfig
from .engine import MODULES, run_audit
from .models import Severity
from .reporters import save_reports
from .utils import (RESET, BOLD, CYAN, GREEN, MAGENTA, RED, YELLOW,
                    cprint, enable_windows_ansi, err, info, ok, set_color)

BANNER = r"""
  ______  ____   __   _    ______   ______  __  __  ______  _____  _____
 / ____/ /  '  / /  | |  /  __  '  /  __  '/ /  / / /  __  '/  _  '/  _  ',
( (___  / /|_|  ) )  | | ( (__)_) ( (__)_)  ) )  ) )( (__)_)  )  _/(  (_|  )
 \____ \ ) |  | / /   | |  \____ \|\__   __// /  / / \____ \  )  )  \_____/
 ____)   ) |_| ( (    | |            ) )  ( (__) )        ) ) )  )
 \____/ /_______\ \___|  |_/         / /    \____/        / / /__/
                                            (__/          (__/
"""

BANNER = r"""
  _____ __  ________ ______  _______    ____  ____  ___ ____  _____ 
 |__  // / / ____/ // __  / /  __  /   / __ )/ __ \/ __// __ \/ ___ \
  /_ </ / / / / / // /_/ / / / /_/ /  / __  / /_/ / /_ / /_/ / /_/ /
 ___/ / /_/ / / / / ____/ / / /_/ /  / /_/ / ____/ __// _, _/  __/ /
/____/\____/_/ /_/_/     /_____/   /_____/_/   /_/  /_/ |_|/____/
                                                                         
      Framework profesional de auditoría de seguridad web
            CyberAudit Pro   ·   investigacion ofensiva defensiva
"""


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberaudit",
        description="Framework profesional de auditoría de seguridad web (solo uso autorizado).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ejemplo: python main.py -u https://tudominio.com --active --ports -f html json",
    )
    p.add_argument("-u", "--url", help="URL objetivo (se añade https:// si falta)")
    p.add_argument("-l", "--list", dest="target_list",
                   help="Fichero con varias URLs (una por línea, # para comentar)")
    p.add_argument("--timeout", type=int, default=None, help="Timeout de red en segundos")
    p.add_argument("--max-pages", type=int, default=None, help="Máx. páginas a rastrear")
    p.add_argument("--depth", type=int, default=None, help="Profundidad del rastreo")
    p.add_argument("--concurrency", type=int, default=None, help="Hilos de concurrencia")
    p.add_argument("--port-timeout", type=float, default=None, help="Timeout del escaneo TCP")
    p.add_argument("--user-agent", default=None, help="User-Agent personalizado")
    p.add_argument("--proxy", default=None, help="Proxy HTTP/S (http://host:puerto)")
    p.add_argument("--cookie", default=None, help="Cookie de sesión (ej. sessionid=abc)")
    p.add_argument("--header", dest="extra_headers", action="append", metavar="'Nombre: valor'",
                   help="Cabecera HTTP extra (repetible) para escaneo autentificado")
    p.add_argument("--delay", type=float, default=None,
                   help="Pausa entre peticiones en segundos (modo cortesía)")
    p.add_argument("--random-delay", dest="random_delay", action="store_true",
                   help="Añade jitter aleatorio a la pausa entre peticiones")
    p.add_argument("--insecure", action="store_true", help="No verificar certificados TLS")
    p.add_argument("--active", action="store_true",
                   help="Pruebas activas benignas de reflexión (XSS) — opcional")
    p.add_argument("--ports", action="store_true", help="Habilitar escaneo de puertos TCP")
    p.add_argument("--subdomains", action="store_true", help="Probar wordlist de subdominios "
                                                             "comunes (además de crt.sh)")
    p.add_argument("--probe-subdomains", action="store_true", help="Resolver HTTP los subdominios "
                                                                   "encontrados (activo)")
    p.add_argument("--wordlist", default=None, help="Wordlist externa de rutas (una por línea)")
    p.add_argument("--max-requests", type=int, default=None, help="Límite de peticiones de rutas")
    p.add_argument("--passwords", dest="passwords_wordlist", default=None,
                   help="Wordlist de contraseñas para el fuzzer de login")
    p.add_argument("-f", "--formats", nargs="+",
                   choices=["json", "html", "md", "csv", "sarif"], default=None,
                   help="Formatos de informe")
    p.add_argument("-o", "--output-dir", default=None, help="Carpeta de informes")
    p.add_argument("--config", default=None, help="Ruta a un config.json alternativo")
    p.add_argument("--include", dest="module_include", nargs="*", metavar="MOD",
                   help="Solo estos módulos (p.ej. recon headers)")
    p.add_argument("--exclude", dest="module_exclude", nargs="*", metavar="MOD",
                   help="Excluir módulos")
    p.add_argument("--fuzz-login", dest="fuzz_login", action="store_true",
                   help="Probar credenciales por defecto en el login (SOLO autorizado)")
    p.add_argument("--no-color", action="store_true", help="Desactivar colores")
    p.add_argument("--yes", action="store_true",
                   help="Acepta el aviso de autorización (modo no interactivo)")
    p.add_argument("-q", "--quiet", action="store_true", help="Menos salida")
    p.add_argument("--about", action="store_true", help="Lista los módulos y sale")
    p.add_argument("--version", action="version", version=f"CyberAudit Pro {__version__}")
    # desactivable
    for mod in MODULES:
        p.add_argument(f"--no-{mod.name}", dest=f"no_{mod.name}", action="store_true",
                       help=f"Desactivar el módulo {mod.name}")
    return p


def _show_about() -> None:
    cprint(BANNER, CYAN)
    cprint(f"CyberAudit Pro {__version__} — módulos:", GREEN, bold=True)
    for m in MODULES:
        cprint(f"   • {m.name:<14} {m.description}", RESET)
    cprint("", RESET)


def _confirm_authorization() -> bool:
    cprint("=" * 74, RED)
    cprint("  ⚠  IMPORTANTE — USO LEGAL                         ", RED, bold=True)
    cprint("  Esta herramienta debe utilizarse SOLO contra sistemas", RED)
    cprint("  cuyo propietario te haya autorizado por escrito.     ", RED)
    cprint("  El escaneo no autorizado es ilegal en la mayoría de  ", RED)
    cprint("  países (España: art. 197 bis CP; UE: Directiva 2013/40).", RED)
    cprint("=" * 74, RED)
    if not sys.stdin.isatty():
        cprint("  (ejecución no interactiva: usa --yes para aceptar)", YELLOW)
        return False
    r = input("  ¿Tienes autorización expresa para auditar este objetivo? (s/N): ")
    return r.strip().lower() in ("s", "si", "y", "yes")


def _print_summary(result) -> None:
    from .utils import paint
    cprint("=" * 74, CYAN, bold=True)
    cprint("  RESUMEN DE LA AUDITORÍA", CYAN, bold=True)
    cprint(f"  Objetivo : {result.target}", RESET)
    cprint(f"  Duración : {result.duration:.2f}s", RESET)
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for s in order:
        n = result.summary.get(s.value, 0)
        cprint(f"  {s.label.upper():>9} : {n}", s.color)
    cprint("-" * 74, CYAN)
    cprint(f"  RIESGO   : {result.risk_score}/100  →  {result.grade}", YELLOW, bold=True)
    cprint("=" * 74, CYAN, bold=True)


def _setup_console() -> None:
    """Consola en UTF-8 para soportar el banner y emojis en Windows."""
    enable_windows_ansi()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _parse_headers(items) -> Dict[str, str]:
    out = {}
    for h in items or []:
        if ":" in h:
            k, v = h.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _run_single(url: str, config, args) -> tuple:
    """Audita una URL y devuelve (código, resultado)."""
    result = run_audit(url, config)
    if result.meta.get("error") and not result.findings:
        err("No se pudo completar la auditoría de " + url)
        save_reports(result, config)
        return 2, result
    _print_summary(result)
    paths = save_reports(result, config)
    cprint("", RESET)
    cprint("  Informes generados:", GREEN, bold=True)
    for p in paths:
        ok(p)
    cprint("  Revisa los hallazgos 'Criticos/Alto' primero y prioriza la remediación.", YELLOW)
    return 0, result


def _run_batch(args, config) -> int:
    """Audita varias URLs de un fichero y escribe un resumen consolidado."""
    import json as _json
    from pathlib import Path
    from datetime import datetime

    try:
        lines = Path(args.target_list).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        err(f"No se pudo leer el fichero de objetivos: {args.target_list}")
        return 2
    targets = [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    if len(targets) > config.max_targets:
        warn(f"El fichero tiene {len(targets)} objetivos; se usarán los "
             f"primeros {config.max_targets}.")
        targets = targets[:config.max_targets]
    if not targets:
        err("El fichero de objetivos no contiene URLs válidas.")
        return 2

    cprint("", RESET)
    cprint(f"  Se auditarán {len(targets)} objetivos…", CYAN, bold=True)
    batch = []
    failures = 0
    for i, tgt in enumerate(targets, 1):
        info(f"[{i}/{len(targets)}] {tgt}")
        try:
            code, res = _run_single(tgt, config, args)
        except Exception as exc:
            warn(f"Error en {tgt}: {exc}")
            failures += 1
            continue
        batch.append({"url": res.target, "risk": res.risk_score, "findings": len(res.findings),
                      "grade": res.grade, "severities": res.summary})
        if code != 0:
            failures += 1

    # Resumen consolidado
    outdir = Path(config.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_path = outdir / f"resumen_batch_{ts}.json"
    summary_path.write_text(_json.dumps({
        "generado": datetime.now().isoformat(),
        "objetivos": batch,
        "totales": {k: sum(b["severities"].get(k, 0) for b in batch)
                    for k in ("critical", "high", "medium", "low", "info")},
        "objetivos_con_error": failures,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    cprint("", RESET)
    cprint("  ===== RESUMEN POR LOTES =====", CYAN, bold=True)
    for b in batch:
        cprint(f"  {b['url']:<50} riesgo {b['risk']:>5}/100 · {b['findings']} hallazgos", RESET)
    cprint("", RESET)
    ok(f"Resumen consolidado: {summary_path}")
    return 0 if failures == 0 else 1


def main(argv: Optional[List[str]] = None) -> int:
    _setup_console()
    args = _parser().parse_args(argv)
    set_color(not args.no_color)
    if args.about:
        _show_about()
        return 0

    cprint(BANNER, CYAN)
    cprint(f"CyberAudit Pro {__version__} — Framework de análisis de seguridad web", GREEN, bold=True)

    if not args.url and not args.target_list:
        _show_about()
        return 2

    if not args.yes:
        if not _confirm_authorization():
            err("Auditoría cancelada. Se requiere autorización expresa del propietario.")
            return 1
        cprint("  ✔  Autorización aceptada. Continuando…", GREEN)

    config = AppConfig.load(args.config)
    config = AppConfig.merge_cli(config, args)
    if args.extra_headers:
        config.extra_headers.update(_parse_headers(args.extra_headers))
    if args.quiet:
        config.output_formats = ["json"]

    if args.target_list:
        return _run_batch(args, config)

    code, _ = _run_single(args.url, config, args)
    return code


def _raw_tokens() -> List[str]:
    return [a for a in sys.argv]