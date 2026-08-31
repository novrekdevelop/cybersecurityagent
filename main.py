#!/usr/bin/env python3
"""Punto de entrada de CyberAudit Pro."""

import sys

from cyberaudit.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))