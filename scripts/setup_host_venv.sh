#!/usr/bin/env bash
# Host Python environment. The venv lives OUTSIDE the repo (scripts/check_spec.py rglobs *.json/*.md).
# Usage: scripts/setup_host_venv.sh sync   create/refresh venv from host/requirements.lock (hash-checked)
#        scripts/setup_host_venv.sh lock   regenerate host/requirements.lock from host/requirements.in
# Env:   LEANMESH_VENV (default ~/.cache/leanmesh/host-venv)
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
venv="${LEANMESH_VENV:-$HOME/.cache/leanmesh/host-venv}"
case "$venv" in "$repo"|"$repo"/*) echo "LEANMESH_VENV must be outside the repo" >&2; exit 2;; esac
py="${PYTHON:-python3.12}"
case "${1:-}" in
  sync)
    [ -x "$venv/bin/python" ] || "$py" -m venv "$venv"
    "$venv/bin/python" -m pip install --require-hashes --only-binary=:all: -r "$repo/host/requirements.lock"
    "$venv/bin/python" -m pip check ;;
  lock)
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    "$py" -m venv "$tmp/v"; "$tmp/v/bin/python" -m pip install -q pip-tools
    # Relative paths keep the machine-specific repo path out of the lock's "via" comments.
    (cd "$repo" && "$tmp/v/bin/pip-compile" --generate-hashes --allow-unsafe --strip-extras --no-header \
      --quiet --output-file host/requirements.lock host/requirements.in) ;;
  *) echo "usage: $0 sync|lock" >&2; exit 2 ;;
esac
