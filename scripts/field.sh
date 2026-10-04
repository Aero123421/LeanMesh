#!/usr/bin/env bash
# BENCH / FIELD TEST ONLY: build and flash firmware/field_node (see its CMakeLists.txt and README.md).
# Usage: scripts/field.sh build <relay|leaf|display> [target]          target default esp32s3 (display: esp32s3 only)
#        scripts/field.sh flash <relay|leaf|display> <port> [target]   erases the whole flash first (a fresh bench identity)
#        scripts/field.sh update <relay|leaf|display> <port> [target]  writes the app only: keeps identity and membership
# Env:   FIELD_ANTENNA=external (XIAO ESP32-C6 with a U.FL antenna; use its own LEANMESH_BUILD_ROOT: an existing build
#        directory keeps its sdkconfig)
# `display` = RELAY + CONFIG_FIELD_HUB75 (the Seengreat HUB75 S3 board). That board has no USB auto-reset: put it in
# download mode by hand first (hold BOOT, press and release EN), then flash; it is flashed with --before no-reset
# (override: FIELD_ESPTOOL_BEFORE=default-reset) and has to be reset by hand afterwards (EN).
# Env:   IDF_PATH (default ~/esp/esp-idf-v6.0.3), LEANMESH_BUILD_ROOT (default ~/.cache/leanmesh/build),
#        IDF_PYTHON_DIR: a directory whose python3 is the one the IDF env was installed with (macOS: python@3.12),
#        FIELD_LED: none | low:<gpio> | high:<gpio>  the status LED of this build (default: Kconfig: XIAO ESP32C6
#                   GPIO15 active low on esp32c6, none elsewhere). Changing it needs a fresh build dir (rm -rf).
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export IDF_PATH="${IDF_PATH:-$HOME/esp/esp-idf-v6.0.3}"
root="${LEANMESH_BUILD_ROOT:-$HOME/.cache/leanmesh/build}"
[ -z "${IDF_PYTHON_DIR:-}" ] || export PATH="$IDF_PYTHON_DIR:$PATH"

action="${1:-}"; role="${2:-}"
case "$role" in relay) profile=RELAY ;; leaf) profile=LEAF ;; display) profile=RELAY ;;
  *) echo "usage: $0 build|flash|update relay|leaf|display ..." >&2; exit 2 ;; esac

case "$root" in "$repo"|"$repo"/*) echo "LEANMESH_BUILD_ROOT must be outside the repo" >&2; exit 2;; esac
# shellcheck disable=SC1091
. "$IDF_PATH/export.sh" >/dev/null

proj="$repo/firmware/field_node"
case "$action" in
  build)
    target="${3:-esp32s3}"
    [ "$role" != display ] || [ "$target" = esp32s3 ] || { echo "the display build is esp32s3 only" >&2; exit 2; }
    b="$root/field_node-$role/$target"
    mkdir -p "$root/field_node-$role"
    extra="$root/field_node-$role/$target.defaults"
    printf 'CONFIG_LEANMESH_PROFILE_%s=y\n' "$profile" > "$extra"
    case "${FIELD_LED:-}" in
      "") ;;
      none) printf 'CONFIG_FIELD_LED_NONE=y\n' >> "$extra" ;;
      low:*|high:*)
        level="${FIELD_LED%%:*}"; gpio="${FIELD_LED#*:}"
        case "$gpio" in ''|*[!0-9]*) echo "FIELD_LED: gpio must be a number" >&2; exit 2 ;; esac
        [ "$level" = low ] && printf 'CONFIG_FIELD_LED_ACTIVE_LOW=y\n' >> "$extra" || printf 'CONFIG_FIELD_LED_ACTIVE_HIGH=y\n' >> "$extra"
        printf 'CONFIG_FIELD_LED_GPIO=%s\n' "$gpio" >> "$extra" ;;
      *) echo "FIELD_LED: none | low:<gpio> | high:<gpio>" >&2; exit 2 ;;
    esac
    case "${FIELD_ANTENNA:-}" in  # XIAO ESP32-C6 only: the U.FL connector instead of the on-board antenna
      ""|onboard) ;;
      external) printf 'CONFIG_HIL_XIAO_C6_EXTERNAL_ANTENNA=y\n' >> "$extra" ;;
      *) echo "FIELD_ANTENNA: onboard | external" >&2; exit 2 ;;
    esac
    defaults="$proj/sdkconfig.defaults"
    [ "$role" != display ] || defaults="$defaults;$proj/sdkconfig.hub75"
    defaults="$defaults;$extra"
    # A board overlay of the target (e.g. the XIAO ESP32C6 RF switch), shared with firmware/hil_node.
    [ ! -f "$repo/firmware/common/sdkconfig.board.$target" ] || defaults="$defaults;$repo/firmware/common/sdkconfig.board.$target"
    if [ ! -f "$b/sdkconfig" ]; then
      (cd "$proj" && idf.py -B "$b" -DSDKCONFIG="$b/sdkconfig" -DSDKCONFIG_DEFAULTS="$defaults" set-target "$target")
    fi
    (cd "$proj" && idf.py -B "$b" -DSDKCONFIG="$b/sdkconfig" -DSDKCONFIG_DEFAULTS="$defaults" build)
    ;;
  flash|update)
    port="${3:?port}"; target="${4:-esp32s3}"
    b="$root/field_node-$role/$target"
    [ -f "$b/flash_args" ] || { echo "build first: $0 build $role $target" >&2; exit 2; }
    # Boards with auto-reset (default): the same esptool calls as scripts/hil.sh. The display board has none: the whole
    # flash/update runs in one download-mode session started by hand (no reset before, none after: press EN).
    eb=default-reset; ea=hard-reset; wb=default-reset; wa=hard-reset
    if [ "$role" = display ] && [ -z "${FIELD_ESPTOOL_BEFORE:-}" ]; then
      eb=no-reset; ea=no-reset; wb=no-reset; wa=no-reset
      echo "display board: hold BOOT, press EN, release both, then this flashes; press EN afterwards to start it" >&2
    fi
    [ -z "${FIELD_ESPTOOL_BEFORE:-}" ] || { eb="$FIELD_ESPTOOL_BEFORE"; wb="$FIELD_ESPTOOL_BEFORE"; }
    if [ "$action" = flash ]; then
      python -m esptool --chip "$target" -p "$port" --before "$eb" --after "$ea" erase-flash
      (cd "$b" && python -m esptool --chip "$target" -p "$port" -b 460800 --before "$wb" --after "$wa" write-flash "@flash_args")
    else
      app="$(python -c 'import json,sys;print(json.load(open(sys.argv[1]))["app"]["offset"])' "$b/flasher_args.json")"
      (cd "$b" && python -m esptool --chip "$target" -p "$port" -b 460800 --before "$wb" --after "$wa" \
        write-flash "$app" leanmesh_field_node.bin)
    fi
    ;;
  *) echo "usage: $0 build|flash|update ..." >&2; exit 2 ;;
esac
