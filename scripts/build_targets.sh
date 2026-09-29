#!/usr/bin/env bash
# Build ESP-IDF apps for the four target SoCs, one after another. Never flashes, never opens a port.
# Usage: scripts/build_targets.sh [--app NAME]... [target ...]
#   apps (default: all):
#     baseline_espnow    empty IDF + ESP-NOW size reference (docs/16); no SDK code
#     example_node       the same bring-up + leanmesh component (SDK size = diff to baseline)
#     crypto_link_check  build gate: pinned libedhoc + IDF PSA link through the component
#   targets (default): esp32s3 esp32c3 esp32c5 esp32c6
# Env:   IDF_PATH             ESP-IDF checkout (default ~/esp/esp-idf-v6.0.3)
#        LEANMESH_BUILD_ROOT  build/sdkconfig output (default ~/.cache/leanmesh/build).
#                             Keep it OUTSIDE the repo: scripts/check_spec.py rglobs *.json/*.md.
# Output: <root>/<app>/<target>/..., <root>/<app>-size.json, and for baseline_espnow the committed
#         record build-records/T01-baseline-size.json.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export IDF_PATH="${IDF_PATH:-$HOME/esp/esp-idf-v6.0.3}"
root="${LEANMESH_BUILD_ROOT:-$HOME/.cache/leanmesh/build}"
apps=()
targets=()
while [ $# -gt 0 ]; do
  case "$1" in
    --app) apps+=("$2"); shift 2 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) targets+=("$1"); shift ;;
  esac
done
[ ${#apps[@]} -gt 0 ] || apps=(baseline_espnow example_node crypto_link_check)
[ ${#targets[@]} -gt 0 ] || targets=(esp32s3 esp32c3 esp32c5 esp32c6)

case "$root" in "$repo"|"$repo"/*) echo "LEANMESH_BUILD_ROOT must be outside the repo" >&2; exit 2;; esac
for app in "${apps[@]}"; do
  [ -f "$repo/firmware/$app/CMakeLists.txt" ] || { echo "unknown app $app" >&2; exit 2; }
done

# shellcheck disable=SC1091
. "$IDF_PATH/export.sh" >/dev/null

# The pin in config/dependencies.json is the single source of truth.
pin="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['esp_idf']['commit'])" "$repo/config/dependencies.json")"
head="$(git -C "$IDF_PATH" rev-parse HEAD)"
if [ "$pin" != "$head" ]; then
  echo "IDF HEAD $head != pinned $pin" >&2; exit 3
fi
if [ -n "$(git -C "$IDF_PATH" status --porcelain --untracked-files=no)" ]; then
  echo "IDF tree has local modifications" >&2; exit 3
fi
# libedhoc/zcbor pins and the exact-input patch are verified before any SDK build.
"$repo/scripts/third_party.sh" verify

for app in "${apps[@]}"; do
  proj="$repo/firmware/$app"
  for t in "${targets[@]}"; do
    b="$root/$app/$t"
    echo "=== $app $t -> $b"
    # A build dir left by another target is discarded by set-target; per-target dirs avoid that.
    (cd "$proj" && idf.py -B "$b" -DSDKCONFIG="$b/sdkconfig" set-target "$t")
    (cd "$proj" && idf.py -B "$b" -DSDKCONFIG="$b/sdkconfig" build)
    (cd "$proj" && idf.py -B "$b" size --format json2) > "$b/size.json"
  done

  case "$app" in
    # The committed record is only rewritten by a full 4-target run; partial runs stay in $root.
    baseline_espnow)
      if [ "${targets[*]}" = "esp32s3 esp32c3 esp32c5 esp32c6" ]; then
        out="$repo/build-records/T01-baseline-size.json"
      else
        out="$root/$app-size.json"
      fi ;;
    *) out="$root/$app-size.json" ;;
  esac
  python3 - "$root/$app" "$out" "$head" "$app" "${targets[@]}" <<'PY'
import json, sys
root, out, idf_commit, app, *targets = sys.argv[1:]
res = {"idf_commit": idf_commit, "app": f"firmware/{app}",
       "note": ("empty IDF + ESP-NOW baseline, -Os; bytes from `idf.py size --format json2`"
                if app == "baseline_espnow" else
                f"{app}, -Os; bytes from `idf.py size --format json2`"), "targets": {}}
for t in targets:
    raw = open(f"{root}/{t}/size.json").read()
    d = json.loads(raw[raw.index("{"):])
    mem = {m["name"]: {"used": m["used"], "total": m["total"]} for m in d["layout"]}
    res["targets"][t] = {"image_total_bytes": d.get("total_size"), "memory": mem}
json.dump(res, open(out, "w"), indent=2)
open(out, "a").write("\n")
PY
  echo "size summary: $out"
done
