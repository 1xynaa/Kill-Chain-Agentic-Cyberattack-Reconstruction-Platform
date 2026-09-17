#!/usr/bin/env bash
set -euo pipefail

if [[ "${CI:-false}" == "true" || "${USE_VENV:-false}" == "true" ]]; then
  VENV="${VENV:-.venv-ci}"
  if [[ ! -x "$VENV/bin/python" ]]; then
    python3 -m venv "$VENV"
  fi
  PYTHON="$VENV/bin/python"
  "$PYTHON" -m pip install -e '.[test]'
  "$PYTHON" -m pip check
else
  # Kali's system Python is PEP 668-managed and contains independent tool
  # packages; do not treat their unrelated dependency conflicts as this app's failure.
  PYTHON="${PYTHON:-python3}"
fi

"$PYTHON" -m compileall -q backend
"$PYTHON" -m pytest -q
"$PYTHON" -m backend.tui tests/fixtures/auth.log --max-calls 4 >/tmp/kill-chain-tui.log
grep -q 'Exploitation' /tmp/kill-chain-tui.log
printf 'local CI checks passed\n'
