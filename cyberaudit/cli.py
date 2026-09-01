"""Command line interface for CyberAudit Pro."""

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
                                                                         
      Professional web security auditing framework
            CyberAudit Pro   ·   offensive defensive research
"""


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberaudit",
        description="Professional web security auditing framework (authorized use only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python main.py -u https://yourdomain.com --active --ports -f html json",
    )
    p.add_argument("-u", "--url", help="Target URL (https:// is added if missing)")
    p.add_argument("-l", "--list", dest="target_list",
                   help="File with several URLs (one per line, # for comments)")
    p.add_argument("--timeout", type=int, default=None, help="Network timeout in seconds")
    p.add_argument("--max-pages", type=int, default=None, help="Max pages to crawl")
    p.add_argument("--depth", type=int, default=None, help="Crawl depth")
    p.add_argument("--concurrency", type=int, default=None, help="Concurrency threads")
    p.add_argument("--port-timeout", type=float, default=None, help="TCP scan timeout")
    p.add_argument("--user-agent", default=None, help="Custom User-Agent")
    p.add_argument("--proxy", default=None, help="HTTP/S proxy (http://host:port)")
    p.add_argument("--cookie", default=None, help="Session cookie (e.g. sessionid=abc)")
    p.add_argument("--header", dest="extra_headers", action="append", metavar="'Name: value'",
                   help="Extra HTTP header (repeatable) for authenticated scans")
    p.add_argument("--delay", type=float, default=None,
                   help="Pause between requests in seconds (polite mode)")
    p.add_argument("--random-delay", dest="random_delay", action="store_true",
                   help="Add random jitter to the pause between requests")
    p.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    p.add_argument("--active", action="store_true",
                   help="Benign active reflection tests (XSS) — optional")
    p.add_argument("--ports", action="store_true", help="Enable TCP port scanning")
    p.add_argument("--subdomains", action="store_true", help="Test common subdomain wordlist "
                                                             "(in addition to crt.sh)")
    p.add_argument("--probe-subdomains", action="store_true", help="HTTP-resolve discovered "
                                                                   "subdomains (active)")
    p.add_argument("--wordlist", default=None, help="External path wordlist (one per line)")
    p.add_argument("--max-requests", type=int, default=None, help="Path request limit")
    p.add_argument("--passwords", dest="passwords_wordlist", default=None,
                   help="Password wordlist for the login fuzzer")
    p.add_argument("-f", "--formats", nargs="+",
                   choices=["json", "html", "md", "csv", "sarif"], default=None,
                   help="Report formats")
    p.add_argument("-o", "--output-dir", default=None, help="Report output folder")
    p.add_argument("--config", default=None, help="Path to an alternative config.json")
    p.add_argument("--include", dest="module_include", nargs="*", metavar="MOD",
                   help="Only these modules (e.g. recon headers)")
    p.add_argument("--exclude", dest="module_exclude", nargs="*", metavar="MOD",
                   help="Exclude modules")
    p.add_argument("--fuzz-login", dest="fuzz_login", action="store_true",
                   help="Test default credentials on the login (AUTHORIZED ONLY)")
    p.add_argument("--no-color", action="store_true", help="Disable colors")
    p.add_argument("--yes", action="store_true",
                   help="Accept the authorization notice (non-interactive mode)")
    p.add_argument("-q", "--quiet", action="store_true", help="Less output")
    p.add_argument("--about", action="store_true", help="List the modules and exit")
    p.add_argument("--version", action="version", version=f"CyberAudit Pro {__version__}")
    # disableable modules
    for mod in MODULES:
        p.add_argument(f"--no-{mod.name}", dest=f"no_{mod.name}", action="store_true",
                       help=f"Disable the {mod.name} module")
    return p


def _show_about() -> None:
    cprint(BANNER, CYAN)
    cprint(f"CyberAudit Pro {__version__} — modules:", GREEN, bold=True)
    for m in MODULES:
        cprint(f"   • {m.name:<14} {m.description}", RESET)
    cprint("", RESET)


def _confirm_authorization() -> bool:
    cprint("=" * 74, RED)
    cprint("  IMPORTANT — LEGAL USE                                   ", RED, bold=True)
    cprint("  This tool must be used ONLY against systems whose", RED)
    cprint("  owner has authorized you in writing. Unauthorized ", RED)
    cprint("  scanning is illegal in most countries (Spain:       ", RED)
    cprint("  art. 197 bis CP; EU: Directive 2013/40).            ", RED)
    cprint("=" * 74, RED)
    if not sys.stdin.isatty():
        cprint("  (non-interactive run: use --yes to accept)", YELLOW)
        return False
    r = input("  Do you have express authorization to audit this target? (y/N): ")
    return r.strip().lower() in ("s", "si", "y", "yes")


def _print_summary(result) -> None:
    from .utils import paint
    cprint("=" * 74, CYAN, bold=True)
    cprint("  AUDIT SUMMARY", CYAN, bold=True)
    cprint(f"  Target   : {result.target}", RESET)
    cprint(f"  Duration : {result.duration:.2f}s", RESET)
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for s in order:
        n = result.summary.get(s.value, 0)
        cprint(f"  {s.label.upper():>9} : {n}", s.color)
    cprint("-" * 74, CYAN)
    cprint(f"  RISK     : {result.risk_score}/100  →  {result.grade}", YELLOW, bold=True)
    cprint("=" * 74, CYAN, bold=True)


def _setup_console() -> None:
    """UTF-8 console to support the bannerand emojis on Windows."""
    enable_windows_ansi()
    # On Windows, set the console output codepage to UTF-8 so that the banner
    # and emojis/accents are displayed correctly (equivalent to `chcp 65001`).
    if os.name == "nt":
        try:
            import subprocess
            subprocess.call(["chcp", "65001"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
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
    """Audits a single URL and returns (exit_code, result)."""
    result = run_audit(url, config)
    if result.meta.get("error") and not result.findings:
        err("Could not complete the audit of " + url)
        save_reports(result, config)
        return 2, result
    _print_summary(result)
    paths = save_reports(result, config)
    cprint("", RESET)
    cprint("  Reports generated:", GREEN, bold=True)
    for p in paths:
        ok(p)
    cprint("  Review 'Critical/High' findings first and prioritize remediation.", YELLOW)
    return 0, result


def _run_batch(args, config) -> int:
    """Audits several URLs from a file and writes a consolidated summary."""
    import json as _json
    from pathlib import Path
    from datetime import datetime

    try:
        lines = Path(args.target_list).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        err(f"Could not read the target file: {args.target_list}")
        return 2
    targets = [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    if len(targets) > config.max_targets:
        warn(f"The file has {len(targets)} targets; only the first "
             f"{config.max_targets} will be used.")
        targets = targets[:config.max_targets]
    if not targets:
        err("The target file does not contain valid URLs.")
        return 2

    cprint("", RESET)
    cprint(f"  {len(targets)} targets will be audited…", CYAN, bold=True)
    batch = []
    failures = 0
    for i, tgt in enumerate(targets, 1):
        info(f"[{i}/{len(targets)}] {tgt}")
        try:
            code, res = _run_single(tgt, config, args)
        except Exception as exc:
            warn(f"Error in {tgt}: {exc}")
            failures += 1
            continue
        batch.append({"url": res.target, "risk": res.risk_score, "findings": len(res.findings),
                      "grade": res.grade, "severities": res.summary})
        if code != 0:
            failures += 1

    # Consolidated summary
    outdir = Path(config.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_path = outdir / f"batch_summary_{ts}.json"
    summary_path.write_text(_json.dumps({
        "generated": datetime.now().isoformat(),
        "targets": batch,
        "totals": {k: sum(b["severities"].get(k, 0) for b in batch)
                   for k in ("critical", "high", "medium", "low", "info")},
        "targets_with_errors": failures,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    cprint("", RESET)
    cprint("  ===== BATCH SUMMARY =====", CYAN, bold=True)
    for b in batch:
        cprint(f"  {b['url']:<50} risk {b['risk']:>5}/100 · {b['findings']} findings", RESET)
    cprint("", RESET)
    ok(f"Consolidated summary: {summary_path}")
    return 0 if failures == 0 else 1


def main(argv: Optional[List[str]] = None) -> int:
    _setup_console()
    args = _parser().parse_args(argv)
    set_color(not args.no_color)
    if args.about:
        _show_about()
        return 0

    cprint(BANNER, CYAN)
    cprint(f"CyberAudit Pro {__version__} — Web security analysis framework", GREEN, bold=True)

    if not args.url and not args.target_list:
        _show_about()
        return 2

    if not args.yes:
        if not _confirm_authorization():
            err("Audit cancelled. Express authorization from the owner is required.")
            return 1
        cprint("  ✔  Authorization accepted. Continuing…", GREEN)

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