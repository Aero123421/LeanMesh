#!/usr/bin/env bash
# Build the ESP-IDF baseline firmware for the four target SoCs, one after another.
# Usage: scripts/build_targets.sh [target ...]     (default: esp32s3 esp32c3 esp32c5 esp32c6)
# Env:   IDF_PATH             ESP-IDF checkout (default ~/esp/esp-idf-v6.0.3)
#        LEANMESH_BUILD_ROOT  build/sdkconfig output (default ~/.cache/leanmesh/build).
#                             Keep it OUTSIDE the repo: scripts/check_spec.py rglobs *.json/*.md.
# Output: <root>/<target>/... and build-records/T01-baseline-size.json (size summary).
# Never flashes or opens a serial port.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export IDF_PATH="${IDF_PATH:-$HOME/esp/esp-idf-v6.0.3}"
root="${LEANMESH_BUILD_ROOT:-$HOME/.cache/leanmesh/build}"
targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(esp32s3 esp32c3 esp32c5 esp32c6)

case "$root" in "$repo"|"$repo"/*) echo "LEANMESH_BUILD_ROOT must be outside the repo" >&2; exit 2;; esac

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

proj="$repo/firmware/baseline_espnow"
cd "$proj"
for t in "${targets[@]}"; do
  b="$root/$t"
  echo "=== $t -> $b"
  # A build dir left by another target is discarded by set-target; per-target dirs avoid that.
  idf.py -B "$b" -DSDKCONFIG="$b/sdkconfig" set-target "$t"
  idf.py -B "$b" -DSDKCONFIG="$b/sdkconfig" build
  idf.py -B "$b" size --format json2 > "$b/size.json"
done

python3 - "$root" "$repo/build-records/T01-baseline-size.json" "$head" "${targets[@]}" <<'PY'
import json, subprocess, sys
root, out, idf_commit, *targets = sys.argv[1:]
res = {"idf_commit": idf_commit, "app": "firmware/baseline_espnow",
       "note": "empty IDF + ESP-NOW baseline, -Os; bytes from `idf.py size --format json2`", "targets": {}}
for t in targets:
    raw = open(f"{root}/{t}/size.json").read()
    d = json.loads(raw[raw.index("{"):])
    mem = {m["name"]: {"used": m["used"], "total": m["total"]} for m in d["layout"]}
    res["targets"][t] = {"image_total_bytes": d.get("total_size"), "memory": mem}
json.dump(res, open(out, "w"), indent=2)
open(out, "a").write("\n")
PY
echo "size summary: build-records/T01-baseline-size.json"
