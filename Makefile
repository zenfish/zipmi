# zipmi — build / install / uninstall.
#
#   make                 (default) build sdist + wheel into dist/.
#                        Does NOT install anything.
#   make install        normal pip install; auto-falls back to --user
#                        if the global write is refused (PEP 668).
#                        Gives you the zipmi/bmc-id commands on PATH AND
#                        an importable `import zipmi`.
#   make dev             editable install + dev extras (live source edits)
#   make uninstall       drain every layer (global / --user / editable
#                        .pth / pipx) using the SAME interpreter.
#   make verify          show what's installed where
#   make clean           BLOW IT ALL AWAY: build/ dist/ egg-info/
#                        __pycache__ *.pyc caches AND .venv.
#                        Keeps only .git. Regen venv with `make dev`.
#   make wire-trace      regenerate docs/img/wire-trace.svg: spin a
#                        throwaway vbmc, run `bmc info -d` against it with
#                        FORCE_COLOR, freeze the coloured trace to SVG.
#
# Override the interpreter:  make install PY=python3.12
# Ignore dep upper-bounds:   make install ZIPMI_ALLOW_UNTESTED=1
#                        (installs latest scapy/cryptography past the pyproject
#                         caps; zipmi then just runs and hopes the APIs held.)

PY ?= python3

# Escape hatch for the pyproject dep upper-bounds (scapy<3, cryptography<46).
# `make install ZIPMI_ALLOW_UNTESTED=1` installs zipmi --no-deps then pulls the
# LATEST scapy/cryptography, ignoring the caps. For testing zipmi against a new
# major before the ceiling is officially bumped. Unset = normal, capped install.
ZIPMI_ALLOW_UNTESTED ?=

SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.PHONY: all build install dev uninstall verify clean wire-trace readme-stats
.DEFAULT_GOAL := build

all: build

build:
	@rm -rf build dist *.egg-info       # setuptools reuses build/ by mtime → stale wheels
	@echo ">> building sdist + wheel into dist/"
	@if $(PY) -m build 2>/tmp/zipmi-build.err; then \
		echo ">> built:"; ls -1 dist/; \
	else \
		echo ">> 'python -m build' unavailable — wheel-only via pip" >&2; \
		sed 's/^/   build: /' /tmp/zipmi-build.err >&2 || true; \
		$(PY) -m pip wheel . -w dist --no-deps; \
		echo ">> built:"; ls -1 dist/; \
	fi

install:
	@echo ">> interpreter: $$($(PY) -c 'import sys;print(sys.executable)')"
	@# CRITICAL: setuptools reuses build/ by mtime and ships stale code, so wipe it.
	@rm -rf build dist *.egg-info
	@# Stamp the git sha into the packaged copy so the INSTALLED (non-editable)
	@# zipmi -V can report which commit it was built from. Removed from the
	@# source tree on exit (it's gitignored, and editable installs read .git live).
	@trap 'rm -f zipmi/_buildstamp.py' EXIT; \
	sha=$$(git rev-parse --short HEAD 2>/dev/null || true); \
	if [ -n "$$(git status --porcelain 2>/dev/null)" ]; then dirty=True; else dirty=False; fi; \
	printf 'GIT_SHA = "%s"\nGIT_DIRTY = %s\n' "$$sha" "$$dirty" > zipmi/_buildstamp.py; \
	echo ">> stamped build: g$$sha (dirty=$$dirty)"; \
	if [ -n "$(ZIPMI_ALLOW_UNTESTED)" ]; then \
		echo ">> ZIPMI_ALLOW_UNTESTED set — ignoring dep upper-bounds; pulling latest scapy/cryptography"; \
		$(PY) -m pip install --no-deps --force-reinstall --no-cache-dir . \
		&& $(PY) -m pip install --upgrade scapy cryptography \
		|| { $(PY) -m pip install --user --break-system-packages --no-deps --force-reinstall --no-cache-dir . \
		     && $(PY) -m pip install --user --break-system-packages --upgrade scapy cryptography; }; \
		echo ">> installed (UNTESTED dep versions — zipmi runs and hopes)"; \
	elif $(PY) -m pip install . 2>/tmp/zipmi-pip.err \
	   && $(PY) -m pip install --force-reinstall --no-deps --no-cache-dir . 2>/tmp/zipmi-pip.err; then \
		echo ">> installed (global/venv)"; \
	else \
		echo ">> global install refused — falling back to --user" >&2; \
		sed 's/^/   pip: /' /tmp/zipmi-pip.err >&2 || true; \
		$(PY) -m pip install --user --break-system-packages . \
		&& $(PY) -m pip install --user --break-system-packages --force-reinstall --no-deps --no-cache-dir .; \
		echo ">> installed (--user)"; \
	fi
	@$(MAKE) -s verify PY=$(PY)

dev:
	@$(PY) -m pip install -e '.[dev]' || \
	 $(PY) -m pip install --user --break-system-packages -e '.[dev]'
	@$(MAKE) -s verify PY=$(PY)

uninstall:
	@if command -v pipx >/dev/null 2>&1 && pipx list 2>/dev/null | grep -qw zipmi; then \
		echo ">> pipx uninstall zipmi"; pipx uninstall zipmi || true; \
	fi
	@n=0; while $(PY) -m pip show zipmi >/dev/null 2>&1; do \
		n=$$((n+1)); echo ">> pip uninstall pass $$n"; \
		$(PY) -m pip uninstall -y zipmi; \
		if [ $$n -ge 8 ]; then echo "error: still present after 8 passes" >&2; exit 1; fi; \
	done
	@if $(PY) -c 'import zipmi' >/dev/null 2>&1; then \
		echo ">> note: import zipmi still resolves -> $$($(PY) -c 'import zipmi;print(zipmi.__file__)')"; \
		echo "   (harmless if that's this checkout and you're cd'd into it)"; \
	else \
		echo ">> clean: import zipmi -> ModuleNotFoundError"; \
	fi

clean:
	@echo ">> BLOWING AWAY build artifacts + .venv (keeping .git only)"
	@rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache .venv venv
	@find . -path ./.git -prune -o \
		-name __pycache__ -type d -print0 | xargs -0 rm -rf 2>/dev/null || true
	@find . -path ./.git -prune -o \
		-name '*.py[co]' -type f -print0 | xargs -0 rm -f 2>/dev/null || true
	@echo ">> clean — regen env with: make dev"

verify:
	@# Import from a NON-repo dir so we resolve the INSTALLED package, not the
	@# ./zipmi shadow on sys.path[0] (which would mask a stale install).
	@cd / && $(PY) -c "import zipmi,scapy,cryptography; print(f'>> import zipmi OK ({zipmi.__file__})'); print(f'>> scapy {scapy.__version__}, cryptography {cryptography.__version__}')"
	@# Freshness guard: the installed CLI must byte-match this checkout. Catches
	@# stale build/ dirs, pip wheel-cache hits, and version-pin no-op installs —
	@# all of which silently shipped old code before. Generic; never rots.
	@inst=$$(cd / && $(PY) -c "import zipmi.cli.zipmi as m; print(m.__file__)"); \
	 if cmp -s "$$inst" zipmi/cli/zipmi.py; then \
		echo ">> freshness OK: installed CLI matches checkout"; \
	 else \
		echo "error: installed zipmi is STALE — does not match this checkout" >&2; \
		echo "       installed: $$inst" >&2; \
		echo "       checkout : $$(pwd)/zipmi/cli/zipmi.py" >&2; \
		echo "       fix: make clean && make install   (or: make dev)" >&2; \
		exit 1; \
	 fi
	@for c in zipmi bmc-id; do command -v $$c >/dev/null 2>&1 && echo ">> $$c -> $$(command -v $$c)" || echo ">> $$c not on PATH (check the --user scripts dir)"; done

# Throwaway vbmc on a high port so it can't collide with a real BMC or a
# dev instance on 6230. FORCE_COLOR keeps the -d trace coloured through the
# pipe (colorize.color_enabled() is otherwise TTY-gated). trap kills the
# server even if the capture fails.
wire-trace:
	@echo ">> rendering docs/img/wire-trace.svg from a throwaway vbmc"
	@mkdir -p docs/img
	@$(PY) -m zipmi.cli.zipmi vbmc serve --persona dell_idrac6 --port 16230 >/dev/null 2>&1 &
	@vb=$$!; trap "kill $$vb 2>/dev/null || true" EXIT; \
	 for i in $$(seq 1 40); do \
	   $(PY) -m zipmi.cli.zipmi -H 127.0.0.1 -p 16230 -U root -P calvin bmc info >/dev/null 2>&1 && break; \
	   sleep 0.25; \
	   if [ $$i -eq 40 ]; then echo "error: vbmc never came up" >&2; exit 1; fi; \
	 done; \
	 FORCE_COLOR=1 $(PY) -m zipmi.cli.zipmi -H 127.0.0.1 -p 16230 -U root -P calvin bmc info -d \
	   | $(PY) scripts/ansi_to_svg.py docs/img/wire-trace.svg
	@echo ">> done — embed: ![wire trace](docs/img/wire-trace.svg)"

# Regenerate the OEM command-count in README.md from the live registry, so it
# never drifts as vendor dispatch tables grow. check_doc_sync.py blocks commits
# if it's stale; this fixes it.
readme-stats:
	@$(PY) scripts/update_readme_stats.py
