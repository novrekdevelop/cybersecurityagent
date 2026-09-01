# ============================================================
#  CyberAudit Pro - developer-friendly Makefile
#  Works on Linux / macOS and on Windows (make via Git Bash,
#  WSL, or `choco install make`).
#
#  Try:  make help
# ============================================================

PY ?= python3

.PHONY: help run about audit demo selftest install check

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

run: ## Open the interactive menu (Linux/macOS)
	bash run.sh

about: ## List the modules and verify the tool is installed
	$(PY) main.py --about

audit: ## Full audit: make audit URL=https://example.com
	@if [ -z "$(URL)" ]; then echo "Usage: make audit URL=https://example.com"; exit 1; fi
	$(PY) main.py -u "$(URL)" --yes -f json md html

demo: ## Serve the local practice lab on http://127.0.0.1:8000
	$(PY) -m http.server 8000 --directory test_site

selftest: ## Run the self-test suite against the local lab
	$(PY) run_selftest.py

install: ## Optional: pip install -e . -> adds the `cyberaudit` command
	$(PY) -m pip install -e .

check: ## Show the Python version and the module list
	$(PY) --version
	$(PY) main.py --about