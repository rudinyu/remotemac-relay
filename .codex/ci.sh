#!/usr/bin/env bash
# Local CI for the codex pre-commit hook (runs before pytest is consulted).
# Uses stdlib unittest so no extra packages (e.g. pytest) need to be installed.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "== Running unit tests (unittest) =="
python3 -m unittest discover -s tests -v
