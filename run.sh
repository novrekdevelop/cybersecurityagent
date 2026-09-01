#!/usr/bin/env bash
# CyberAudit Pro - interactive launcher for Linux / macOS
# (also works from Git Bash or WSL on Windows).
#
# Usage:  chmod +x run.sh   &&   ./run.sh
set -euo pipefail
cd "$(dirname "$0")"

# 1) Locate Python (python3 on Linux/macOS, python as fallback)
PY=""
if command -v python3 >/dev/null 2>&1; then
    PY="python3"
elif command -v python >/dev/null 2>&1; then
    PY="python"
fi
if [ -z "$PY" ]; then
    echo
    echo "  [ERROR] Python was not found."
    echo "  Install it from https://www.python.org/downloads/"
    exit 1
fi

# 2) Require Python 3.10+
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo
    echo "  [ERROR] Python 3.10 or newer is required."
    exit 1
fi

run_audit() {  # $1 = URL, rest = extra CLI arguments
    local url="$1"
    shift
    "$PY" main.py -u "$url" --yes -f json md html "$@"
}

while true; do
    clear
    echo
    echo "  ============================================================"
    echo "     CYBERAUDIT PRO - Web security audit"
    echo "  ============================================================"
    echo
    echo "  Professional cybersecurity analysis tool."
    echo "  * LEGAL USE: only on websites you own or with permission from the owner."
    echo
    echo "   [1] Full audit (headers, content, paths, DNS, APIs, logins and payments)"
    echo "   [2] Audit + port scanning + subdomains"
    echo "   [3] Exhaustive audit (+ benign active tests: XSS, redirect, GraphQL)"
    echo "   [4] Default credential test on the login (--fuzz-login)"
    echo "   [5] Exit"
    echo
    read -r -p "Choose an option (1-5): " op
    case "$op" in
        1) extra=() ;;
        2) extra=(--ports --subdomains) ;;
        3) extra=(--ports --active) ;;
        4) extra=() ;;
        5) exit 0 ;;
        *) continue ;;
    esac

    # Ask for the URL
    url=""
    while [ -z "$url" ]; do
        read -r -p "URL (e.g. https://myweb.es/panel): " url
    done

    echo
    echo "  Auditing $url ... (do not close this window)"
    if [ "$op" = "4" ]; then
        "$PY" main.py -u "$url" --yes --fuzz-login --include fuzzer -f json html || echo "  [ERROR] The audit could not be completed."
    else
        run_audit "$url" "${extra[@]}" || echo "  [ERROR] The audit could not be completed."
    fi

    read -r -p "Press ENTER to return to the menu, or 's' to exit: " again
    [ "$again" = "s" ] && exit 0
done