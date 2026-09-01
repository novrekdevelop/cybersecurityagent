#!/usr/bin/env python3
"""CyberAudit Pro entry point."""

import sys

from cyberaudit.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))