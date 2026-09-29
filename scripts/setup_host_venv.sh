#!/usr/bin/env bash
# Host Python environment. The venv lives OUTSIDE the repo (scripts/check_spec.py rglobs *.json/*.md).
# Usage: scripts/setup_host_venv.sh sync       create/refresh venv from host/requirements.lock (hash-checked)
#        scripts/setup_host_venv.sh sync-dev   same plus test tools from host/requirements-dev.lock
#        scripts/setup_host_venv.sh lock       regenerate both locks from host/requirements*.in
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
  sync-dev)
    [ -x "$venv/bin/python" ] || "$py" -m venv "$venv"
    "$venv/bin/python" -m pip install --require-hashes --only-binary=:all: -r "$repo/host/requirements-dev.lock"
    "$venv/bin/python" -m pip check ;;
  lock)
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    "$py" -m venv "$tmp/v"; "$tmp/v/bin/python" -m pip install -q pip-tools
    # Relative paths keep the machine-specific repo path out of the lock's "via" comments.
    (cd "$repo" && "$tmp/v/bin/pip-compile" --generate-hashes --allow-unsafe --strip-extras --no-header \
      --quiet --output-file host/requirements.lock host/requirements.in)
    (cd "$repo" && "$tmp/v/bin/pip-compile" --generate-hashes --allow-unsafe --strip-extras --no-header \
      --quiet --output-file host/requirements-dev.lock host/requirements-dev.in)
    # Runtime pins must be identical in both locks (tests exercise the production versions).
    python3 - "$repo/host/requirements.lock" "$repo/host/requirements-dev.lock" <<'PY'
import re, sys
def pins(path):
    return dict(re.findall(r'^([A-Za-z0-9_.-]+)==([^ \\]+)', open(path).read(), re.M))
run, dev = pins(sys.argv[1]), pins(sys.argv[2])
bad = {k: (v, dev.get(k)) for k, v in run.items() if dev.get(k) != v}
if bad:
    sys.exit(f"runtime pins differ between locks: {bad}")
PY
    ;;
  *) echo "usage: $0 sync|sync-dev|lock" >&2; exit 2 ;;
esac
