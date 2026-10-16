# 2026-10-16 additional review fixes

Base: `1ea56048304ea9940c5adf4bdc6e924f8ef5464a`, branch `fix/mesh-field-robustness`.
Implementation: `95eeef5` (per-member renewal deferral/coalescing), `e10053f` (Bind ACK ownership and peer proof), `93dbc39` (route evidence age), `712bf78` (slow-route timing scope; final implementation source).
ESP-IDF: pinned `76f5dedd9950a3012fee8fb7d5586df21fc67802`; required libedhoc patches verified, unchanged by this work. No device was flashed.

The five review findings are covered by real SDK paths in native tests, rather than extracted-function stubs:

- A sleeping renewal target is skipped while an awake target progresses; the retry deadline survives unrelated maintenance completion. Load/sign errors and CONTROL contention retain the request and reason.
- A queued or in-flight renewal keeps its pending bit, so duplicate READY does not issue another credential.
- One pooled ciphertext cache protects a link Bind ACK independently of the exchange scratch. All ordinary link TX waits for authenticated proof of the peer's new session; the proof callback runs after its RX is dispatched. Join/end ACKs retain their execution slot until sent/first-hop accepted.
- Abandon includes an initiator that yielded under glare, including worker cancellation and generation checks.
- Route advertisements have their own age/term, independent of authenticated neighbor traffic. Stale or self-containing non-parent candidates cannot be selected, including voluntary moves/spares, and their slots may be reused. A planned wake has one bounded exception for the last root-approved parent.

The slow-radio field regression also exposed an existing timing assumption: a routed credential response was timed as one frame and its first-hop acceptance was treated as arrival at the destination. For observed per-hop service above 120 ms, the initial credential RTO now includes its bounded fragmentation time; the responder uses its existing idle/hard deadlines for message_1. An unconditional timing extension failed the existing 50-second R07 mean limit (51.088 seconds); restricting the allowance to observed slow service preserves fast formation (final 46.051 seconds). The existing 25-second field criterion was retained (observed 20.620 seconds after the alternative relay became ready, versus 51.680 seconds before this correction).

## Reproduction and commands

`regressions-before.txt` records the five original failures against immutable baseline firmware source and the extra RX-dispatch ordering failure before its fix. Regression names begin `REVIEW16 sim:` in `tests/native/test_{lifecycle,link,mesh}.cpp` (10 cases in total). No existing thresholds were relaxed.

Workspace paths below are local execution locations, not checked-in build artifacts:

```sh
source /workspace/leanmesh-env/activate.sh
B=/workspace/work/leanmesh-review
cmake -S . -B "$B/native-clean" -G Ninja -DLM_IDF_PATH="$IDF_PATH" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  '-DCMAKE_C_FLAGS_RELWITHDEBINFO=-O1 -g -DNDEBUG' \
  '-DCMAKE_CXX_FLAGS_RELWITHDEBINFO=-O1 -g -DNDEBUG'
cmake --build "$B/native-clean" -j4
ctest --test-dir "$B/native-clean" --output-on-failure --no-tests=error -j2
LEANMESH_NATIVE_BUILD="$B/native-clean" LEANMESH_SIM_STRICT_EXIT=1 \
  python -m pytest -q host/tests/unit host/tests/integration host/tests/e2e
cmake -S . -B "$B/native-asan-final" -G Ninja -DLM_IDF_PATH="$IDF_PATH" \
  -DLM_SANITIZE=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  '-DCMAKE_C_FLAGS_RELWITHDEBINFO=-O1 -g -DNDEBUG' \
  '-DCMAKE_CXX_FLAGS_RELWITHDEBINFO=-O1 -g -DNDEBUG'
cmake --build "$B/native-asan-final" -j3
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir "$B/native-asan-final" --output-on-failure --no-tests=error -j2
LEANMESH_BUILD_ROOT="$B/firmware-current" scripts/build_targets.sh --app example_node --profile RELAY
LEANMESH_BUILD_ROOT="$B/firmware-current" scripts/build_targets.sh --app example_node --profile ROOT esp32s3
python scripts/check_spec.py
python -m ruff check host tools/fieldview scripts/check_api_defined.py scripts/budget_report.py scripts/scenario_coverage.py scripts/report_pytest_failures.py
scripts/third_party.sh verify
python scripts/check_api_defined.py --native-build "$B/native-clean"
python scripts/scenario_coverage.py --out-dir "$B/coverage-final"
python scripts/budget_report.py --native-build "$B/native-clean" --idf-root "$B/firmware-current" --out-dir "$B/final-budget"
```

The baseline firmware sizes use the same IDF/toolchains, configuration and five profile/SoC builds at `1ea5604`. The final native trees are separate clean directories: an earlier build directory was discarded after concurrent Ninja invocations produced stale header dependencies. An earlier unoptimized sanitizer run was stopped after a crypto measurement timeout under build contention; final results below use the optimized, clean sanitizer tree. Neither discarded run is counted as a pass.

## Validation results

- Plain native: **31/31 suites passed**, 85.69 seconds; all 10 REVIEW16 regression cases passed. See `native-ctest.txt` and `native-observations.txt`.
- ASan + UBSan + leak detection: **31/31 suites passed**, 591.64 seconds. See `asan-ctest.txt`.
- Host: **553 unit/integration + 59 E2E = 612 unique cases passed**. The first combined run had 611 passes and one `PermissionError` (errno 13): it launched `issuer_driver` while that file was being relinked (input timestamp 04:21:13.554 UTC, binary timestamp 04:21:13.645 UTC). The preserved exact inputs passed with the completed binary; the subsequent full 553-case unit/integration run passed in 215.57 seconds. All 59 E2E cases in the combined run passed against the completed binaries. See `host-results.json`; this is an aggregate of the clean runs, not a claim that the first invocation was green.
- Firmware: **RELAY on ESP32-S3/C3/C5/C6 and ROOT on ESP32-S3 all built**. All five were incrementally rebuilt after the final implementation commit, then sized. LEAF firmware and ROOT on C3/C5/C6 were not built; their workspace numbers below are compiler sizeof probes only.
- Spec consistency (G0), pinned third-party verification, Ruff 0.16.9, public API definition completeness (38 functions, 0 problems), and scenario ID coverage checks passed. Scenario mapping: 158 IDs / 343 references; its hardware-not-run classifications were not promoted to hardware passes.

## Resource changes

Baseline and final use the same pinned toolchains/configuration. Details and before/after numbers are in `resource-delta.json`. Flash code/data are for `libleanmesh.a` from the link map. Binary bytes are actual `.bin` lengths, distinct from the `esp_idf_size` total stored as `image_bytes` in the JSON.

| Firmware build | .bin delta B | SDK Flash code+data delta B | Fixed RAM before → after B | RAM delta B |
|---|---:|---:|---:|---:|
| esp32s3 RELAY | +3072 | +3066 | 69664 → 69744 | +80 |
| esp32s3 ROOT | +3536 | +3566 | 186244 → 186852 | +608 |
| esp32c3 RELAY | +3552 | +3568 | 69648 → 69728 | +80 |
| esp32c5 RELAY | +3552 | +3568 | 69648 → 69728 | +80 |
| esp32c6 RELAY | +3552 | +3574 | 69648 → 69728 | +80 |

Fixed RAM here is workspace + the SDK's static DRAM (task stacks/rings included), excluding Wi-Fi/PSA vendor heap and runtime peaks. SDK static DRAM outside the workspace did not grow. Workspace growth on all four target compilers is LEAF/RELAY **+80 B**, ROOT **+608 B**. Native sizeof reports the same deltas; SessionKeys/Neighbor sizes did not grow. The extra state is fixed-size and holds one ciphertext in the existing frame pool, with no new task or queue.

First-party SDK C/C++ SLOC: **40,382 → 40,741 (+359)** against the existing 28,000 target. The existing budget overruns remain: measured RELAY fixed RAM is 69,728–69,744 B against 57,344 B; S3 ROOT is 186,852 B against 163,840 B. The five firmware Flash differentials against the repository's empty-IDF baseline remain above 256 KiB; C5/C6 RELAY and S3 ROOT also remain above the 320 KiB review line. These are not new budget crossings caused by this patch; no budget compliance is claimed.

The native crypto measurement is 8,600 B worker stack + 4,368 B PSA heap = 12,968 B; it is an x86-64 software measurement. No baseline stack delta is claimed because optimization flags differ. Existing native owner-path stack guards passed. No SoC stack/heap peak, idle CPU, airtime or J/report was measured. Normal authenticated traffic suppresses the fallback Bind confirmation; idle peers may send the bounded confirmation/retries, whose physical airtime and energy remain unmeasured.

## Remaining hardware evidence and review

No RF, shared-medium collision, hidden-terminal, real flash power-cut, USB/power-disconnect, device peak heap/stack, idle CPU, airtime or J/report measurement was performed. Simulator timing and loss injection do not qualify physical startup congestion or energy use.

Before merge/release, obtain the independent security review required by `docs/15-coding-standards.md` §5 for changes involving session binding/time. This execution performed source review and automated checks; it has no independent security reviewer.

Retest on actual devices: simultaneous start/root restart; renewal overlapping planned Sleep with another awake member; Bind ACK blocked/lost during TX load and rotation; glare followed by a stronger candidate; parent/child reversal plus relay restart; and USB disconnect separately from RF load. Collect bounded logs with loss counts via an independent root UART where possible. Correlate boot/monotonic time, peer, exchange generation/role/phase/reason; distinguish ACK generated, admitted, TX-completed and authenticated peer confirmation; correlate renewal load/sign/CONTROL admission with recipient verification, persistence and adoption. These detailed field traces remain to be collected; the native counters are not adoption or hardware evidence.
