#!/bin/bash
# what: point this clone's git hooks at the version-controlled .githooks dir
# why: pre-commit doc/code symmetry guard must run for every contributor,
#      not just whoever wrote it. core.hooksPath survives clone.
# success: `git config --local --get core.hooksPath` prints `.githooks`.
# run: ./scripts/install-hooks.sh   (from repo root or anywhere inside)
# related: .githooks/pre-commit, scripts/check_doc_sync.py, README.md
set -e
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
git config --local core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true
echo "hooks installed: core.hooksPath=$(git config --local --get core.hooksPath)"
echo "guard: scripts/check_doc_sync.py runs on every commit"
