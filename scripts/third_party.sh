#!/usr/bin/env bash
# libedhoc (submodule, pinned) + its zcbor: full checkout, local patch, byte-level verification.
# Usage: scripts/third_party.sh setup    init submodules, apply patch (idempotent)
#        scripts/third_party.sh verify   check pins and blob ids; exit 1 on any mismatch
# The full upstream tree is checked out (cmake/sources.cmake and cmake/edhoc_config.h.in are used by
# cmake/lm_edhoc.cmake). scripts/check_spec.py excludes third_party/ from its *.json/*.md scans.
# Only libedhoc core, the CBOR backend and zcbor sources are compiled; the other externals
# (mbedtls, compact25519, Unity, liboqs, XKCP) are never fetched: the crypto backend is IDF's PSA.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ed="$repo/third_party/libedhoc"
zc="$ed/externals/zcbor"
ED_COMMIT=c8857b62d66be3664d1694bbe4eea37c56c05d9e
ZC_COMMIT=d3093b5684f62268c7f27f8a5079f166772619de
patch_file="$repo/third_party/patches/libedhoc-2.3.2-exact-input-consumption.patch"
# path -> "upstream blob id" "patched blob id" (patched ids equal RouteLoom 77b5792 vendored blobs)
declare -A UP=(  [message_2]=736ac4a8de5cdbf5f7d9051c9f907b68f7b9450e [message_3]=61e0cde862c9f128929bd434a378c17974b5fd10 [message_4]=6deb56270d67d602e13e0919e3933fa1621e8099 )
declare -A PAT=( [message_2]=b1ba89076d1ebf13a06e45b9a05ed84f38900230 [message_3]=f84231d09e579e0502a5420ff55af72103c19209 [message_4]=48ac46cc381eff88149e5673709f4d5d1731817f )

setup() {
  git -C "$repo" submodule update --init third_party/libedhoc
  # Earlier checkouts used a sparse subset; restore the full tree if that is still configured.
  if [ "$(git -C "$ed" config --bool core.sparseCheckout || true)" = "true" ]; then
    git -C "$ed" sparse-checkout disable
  fi
  git -C "$ed" submodule update --init externals/zcbor
  if [ "$(git -C "$zc" config --bool core.sparseCheckout || true)" = "true" ]; then
    git -C "$zc" sparse-checkout disable
  fi
  if git -C "$ed" apply --check -R "$patch_file" 2>/dev/null; then
    echo "patch already applied"
  else
    git -C "$ed" apply "$patch_file"; echo "patch applied"
  fi
}

verify() {
  local rc=0
  [ "$(git -C "$ed" rev-parse HEAD)" = "$ED_COMMIT" ] || { echo "libedhoc HEAD != $ED_COMMIT"; rc=1; }
  [ "$(git -C "$zc" rev-parse HEAD)" = "$ZC_COMMIT" ] || { echo "zcbor HEAD != $ZC_COMMIT"; rc=1; }
  for m in message_2 message_3 message_4; do
    f="library/core/classic/edhoc_classic_$m.c"
    got="$(git -C "$ed" hash-object "$f")"
    if   [ "$got" = "${PAT[$m]}" ]; then echo "$f: patched (matches RouteLoom blob)"
    elif [ "$got" = "${UP[$m]}" ]; then echo "$f: UPSTREAM, patch NOT applied"; rc=1
    else echo "$f: unknown blob $got"; rc=1; fi
  done
  # Any other modification of the checked-out subset is unexpected.
  dirty="$(git -C "$ed" status --porcelain --untracked-files=no | grep -v 'edhoc_classic_message_[234]\.c' || true)"
  [ -z "$dirty" ] || { echo "unexpected changes in libedhoc: $dirty"; rc=1; }
  [ -z "$(git -C "$zc" status --porcelain --untracked-files=no)" ] || { echo "zcbor modified (zero-length memmove guard is not applied)"; rc=1; }
  return $rc
}

case "${1:-}" in setup) setup ;; verify) verify ;; *) echo "usage: $0 setup|verify" >&2; exit 2 ;; esac
