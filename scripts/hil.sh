#!/usr/bin/env bash
# BENCH / HIL ONLY: build and flash firmware/hil_node (see its CMakeLists.txt).
# Usage: scripts/hil.sh build <root|leaf|relay> [target]          target default esp32s3
#        scripts/hil.sh flash <root|leaf|relay> <port> [target]   erases the whole flash first (a fresh bench identity)
#        scripts/hil.sh update <root|leaf|relay> <port> [target]  writes the app only: keeps identity and membership
# Env:   IDF_PATH (default ~/esp/esp-idf-v6.0.3), LEANMESH_BUILD_ROOT (default ~/.cache/leanmesh/build),
#        IDF_PYTHON_DIR: a directory whose python3 is the one the IDF env was installed with (macOS: python@3.12).
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export IDF_PATH="${IDF_PATH:-$HOME/esp/esp-idf-v6.0.3}"
root="${LEANMESH_BUILD_ROOT:-$HOME/.cache/leanmesh/build}"
[ -z "${IDF_PYTHON_DIR:-}" ] || export PATH="$IDF_PYTHON_DIR:$PATH"

action="${1:-}"; role="${2:-}"
case "$role" in root) overlay=root; profile=ROOT ;; leaf) overlay=leaf; profile=LEAF ;;
  relay) overlay=leaf; profile=RELAY ;; *) echo "usage: $0 build|flash root|leaf|relay ..." >&2; exit 2 ;; esac

case "$root" in "$repo"|"$repo"/*) echo "LEANMESH_BUILD_ROOT must be outside the repo" >&2; exit 2;; esac
# shellcheck disable=SC1091
. "$IDF_PATH/export.sh" >/dev/null

proj="$repo/firmware/hil_node"
case "$action" in
  build)
    target="${3:-esp32s3}"
    b="$root/hil_node-$profile/$target"
    mkdir -p "$root/hil_node-$profile"
    extra="$root/hil_node-$profile/$target.defaults"
    printf 'CONFIG_LEANMESH_PROFILE_%s=y\n' "$profile" > "$extra"
    defaults="$proj/sdkconfig.defaults;$proj/sdkconfig.$overlay;$extra"
    # A board overlay of the target (e.g. the XIAO ESP32C6 RF switch), when the bench has one.
    [ ! -f "$proj/sdkconfig.board.$target" ] || defaults="$defaults;$proj/sdkconfig.board.$target"
    if [ ! -f "$b/sdkconfig" ]; then
      (cd "$proj" && idf.py -B "$b" -DSDKCONFIG="$b/sdkconfig" -DSDKCONFIG_DEFAULTS="$defaults" set-target "$target")
    fi
    (cd "$proj" && idf.py -B "$b" -DSDKCONFIG="$b/sdkconfig" -DSDKCONFIG_DEFAULTS="$defaults" build)
    ;;
  flash)
    port="${3:?port}"; target="${4:-esp32s3}"
    b="$root/hil_node-$profile/$target"
    [ -f "$b/flash_args" ] || { echo "build first: $0 build $role $target" >&2; exit 2; }
    python -m esptool --chip "$target" -p "$port" erase-flash
    (cd "$b" && python -m esptool --chip "$target" -p "$port" -b 460800 --before default-reset --after hard-reset \
      write-flash "@flash_args")
    ;;
  update)
    port="${3:?port}"; target="${4:-esp32s3}"
    b="$root/hil_node-$profile/$target"
    [ -f "$b/flash_project_args" ] || { echo "build first: $0 build $role $target" >&2; exit 2; }
    app="$(python -c 'import json,sys;print(json.load(open(sys.argv[1]))["app"]["offset"])' "$b/flasher_args.json")"
    (cd "$b" && python -m esptool --chip "$target" -p "$port" -b 460800 --before default-reset --after hard-reset \
      write-flash "$app" leanmesh_hil_node.bin)
    ;;
  *) echo "usage: $0 build|flash|update ..." >&2; exit 2 ;;
esac
