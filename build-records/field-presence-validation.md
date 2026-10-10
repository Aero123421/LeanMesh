# Field presence: final-source validation and resource report

**Requested compile checks passed. Hardware qualification is not established.**
The final ordinary display, ToF display, S3/C6 field relays, S3 ROOT and all
12 `example_node` SoC/profile combinations build with pinned ESP-IDF v6.0.3.
The SDK's existing RAM, Flash and SLOC budget overruns remain. This report records
measurements; passing compilation does not waive those budgets.

## Context and exact comparison

- Baseline: independent `git clone --no-hardlinks` checkout of
  `37df3f20ac9b90c9e7b85d429f2d88df88cdb27d` in `/root/leanmesh-baseline`.
- AFTER: the approved, uncommitted field presence/K1/K3 work on that same HEAD,
  source tree `C:\dev\job\LeanMesh`, build mirror `/root/leanmesh-work`.
  Final-source fingerprint checks passed before using AFTER measurements.
- Reviewed history: PR #20 establishes the development rules; PR #21 addresses
  Issue #19 mesh timing/recovery; PR #22 limits the TX service bound to recent
  completions. Issue #23 describes earlier bench work and the PC handoff.
  These historical RF results are not validation of this new application.
  PR #21/#22 automated reviews were skipped/quota-limited, not independent approvals.
- Scope: field application and browser evidence, plus persisted Host reception
  timestamp exposure. No SDK sources, example sources, ROOT application sources
  or shared bench sources differ from the baseline.
- Read README, normative chapters 01–23, registry/CDDL/C API/OpenAPI/DB contracts,
  field contracts, acquisition/control/detector/driver/rendering sources and
  `scripts/budget_report.py`. No feature source was edited by this validation work.
- IDF: `76f5dedd9950a3012fee8fb7d5586df21fc67802`, v6.0.3;
  Xtensa/RISC-V GCC `esp-15.2.0_20251204`, 15.2.0, `-Os`.
  Source checks exclude generated `dependencies.lock`, managed components and
  Python bytecode, and normalize CRLF to LF. Managed HUB75 uses its existing pin
  and the same two existing patches in both display builds.
- Measurements collected after successful final-source incremental field builds,
  initially at `2026-10-09T15:23:13.918951+00:00`; the display figures and source/SLOC
  snapshot were refreshed at `2026-10-09T15:50:34.798972+00:00` (2026-10-10 JST)
  after the final Japanese learning-label change. Pre-review binaries were not used
  as AFTER evidence. Baseline vendor setup/verification passed.
- Latest compiled-input fingerprint:
  `603ee43288dcded1819587253475d1b3f4d7db1ed486f33f5044cdca7b608b67`.
  The sole compiled-source change since the previous measurements is
  `firmware/field_node/main/field_render.c` (normalized SHA256
  `6e3fb32fcf8102376dc2ccf25b06b48b8af3f209787fd72dbf79785126a7602a`).
  The main-owned source mirror already matched; this worker did not sync/edit it.
  Source fingerprints matched before/after both builds and at collection end.
  Host/native-test/tool SLOC has a separate stable Windows-source snapshot hash
  in the JSON; evolving Host tests are not silently covered by a firmware fingerprint.

## Commands actually executed

Commands ran as root in WSL `Ubuntu-24.04`. The Windows invocation pattern was
`wsl -d Ubuntu-24.04 -u root --cd /root/leanmesh-work -- bash -lc 'COMMAND'`.
For baseline commands the working directory was `/root/leanmesh-baseline`.
Disposable measurement helpers were added with `apply_patch` under
`C:\Users\daits\AppData\Local\Temp\opencode`, not under feature sources.

```sh
test -d /root && test ! -e /root/leanmesh-baseline && \
git clone --no-hardlinks /mnt/c/dev/job/LeanMesh /root/leanmesh-baseline && \
git -C /root/leanmesh-baseline checkout --detach 37df3f2 && \
/root/leanmesh-baseline/scripts/third_party.sh setup && \
/root/leanmesh-baseline/scripts/third_party.sh verify

# Independent baseline; explicit field builds do not update T01 records.
LEANMESH_BUILD_ROOT=/root/.cache/leanmesh/build-baseline-field scripts/field.sh build display esp32s3
LEANMESH_BUILD_ROOT=/root/.cache/leanmesh/build-baseline-field scripts/field.sh build relay esp32s3
LEANMESH_BUILD_ROOT=/root/.cache/leanmesh/build-baseline-field scripts/field.sh build relay esp32c6

# Final current source; existing build directories, incremental rebuilds.
scripts/field.sh build display esp32s3
scripts/field.sh build display-tof esp32s3
scripts/field.sh build relay esp32s3
scripts/field.sh build relay esp32c6
scripts/hil.sh build root esp32s3

# Latest refresh after Japanese glyphs: only these two builds were repeated.
scripts/field.sh build display esp32s3
scripts/field.sh build display-tof esp32s3

# Explicit app/profile: no default baseline_espnow/T01 record overwrite.
scripts/build_targets.sh --app example_node --profile LEAF esp32s3 esp32c3 esp32c5 esp32c6
scripts/build_targets.sh --app example_node --profile RELAY esp32s3 esp32c3 esp32c5 esp32c6
scripts/build_targets.sh --app example_node --profile ROOT esp32s3 esp32c3 esp32c5 esp32c6

. /root/esp/esp-idf-v6.0.3/export.sh >/dev/null
python scripts/budget_report.py --native-build /root/.cache/leanmesh/native \
  --idf-root /root/.cache/leanmesh/build --out-dir /root/.cache/leanmesh/field-budget
```

Size extraction used the IDF Python environment's
`python -m esp_idf_size --format json2 MAP` and
`python -m esp_idf_size --archives --format json2 MAP`, equivalent to the size
utility behind `idf.py size --format json2`. `--archive-details libleanmesh.a
--diff BASE_MAP --format json2 AFTER_MAP` explains the SDK link contribution.
`nm -S -C ELF` proves sensor exclusion. Compiler `sizeof` probes were compiled
outside the repository with recorded SoC build compile commands, then read by
the same toolchain's `nm -S` (array size minus its one-byte marker).

Raw outputs, build commands, UTC starts, durations, source fingerprints, map/bin
hashes and symbol dumps are under `/root/.cache/leanmesh/field-budget`.
The companion [JSON](field-presence-validation.json) carries the durable summary
and raw-artifact hashes. `build-records/T01-baseline-size.json` was not changed.
No flash, serial, hardware or git commit command was executed.

| Build command scope | Result | Wall time s |
|---|---|---:|
| Baseline display S3 | PASS | 125.486 |
| Baseline relay S3 | PASS | 163.622 |
| Baseline relay C6 | PASS | 176.737 |
| Pre-Japanese display S3, historical rebuild | PASS | 96.077 |
| Pre-Japanese display-ToF S3, historical rebuild | PASS | 85.225 |
| Final Japanese display S3 | PASS | 31.718 |
| Final Japanese display-ToF S3 | PASS | 25.296 |
| Final relay S3 | PASS | 84.745 |
| Final relay C6 | PASS | 103.083 |
| Current HIL application ROOT S3, compile only | PASS | 11.478 |
| Example LEAF, all four SoCs | PASS, 4/4 | 552.355 |
| Example RELAY, all four SoCs | PASS, 4/4 | 337.182 |
| Example ROOT, all four SoCs | PASS, 4/4 | 345.268 |

Durations include configure/build and contention with concurrent work; they are
not runtime performance measurements. The ROOT incremental check reused unchanged
objects. No independent baseline ROOT rebuild was requested/performed, so a
measured ROOT binary delta is **unknown**, not zero. ROOT on C3 remains unsupported
pending its real-heap gate despite its successful compile.
Baseline, relay, ROOT, SDK probes and four-SoC example build/resource evidence are
retained from the earlier run, not rerun or rebound to a new fingerprint. Only the
renderer changed among compiled inputs; relays and examples do not compile it.
`pre-japanese-field-measurements.json` preserves the earlier full evidence.

## Field images and static memory

Bytes. Image means the utility's `total_size`; `.bin` additionally has image
framing/padding. The baseline display had neither keys nor ToF. Both new display
variants are compared with that original display, not with an earlier feature build.

| Variant | Image BEFORE → AFTER | Image delta | App `.bin` BEFORE → AFTER | `.bin` delta | DRAM BSS BEFORE → AFTER | DRAM data BEFORE → AFTER |
|---|---:|---:|---:|---:|---:|---:|
| Display S3 | 994889 → 1017500 | +22611 | 995008 → 1017632 | +22624 | 54080 → 54704 (+624) | 20014 → 20089 (+75) |
| Display-ToF S3 | 994889 → 1025320 | +30431 | 995008 → 1025440 | +30432 | 54080 → 56352 (+2272) | 20014 → 20089 (+75) |
| Relay S3 | 972089 → 972137 | +48 | 972208 → 972256 | +48 | 49920 → 49936 (+16) | 20014 → 20014 (0) |
| Relay C6 | 1141379 → 1141461 | +82 | 1141760 → 1141840 | +80 | 55968 → 55984 (+16) | 15263 → 15263 (0) |
| Current ROOT S3, reference only | unknown → 1022187 | unknown | unknown → 1022304 | unknown | unknown → 78728 | unknown → 18696 |

Both displays add 1092 B of linked IRAM text (77527 → 78619 B); relays add none.
ToF versus the **final ordinary display** adds 7820 B image, 7808 B `.bin`,
1648 B BSS and no DRAM data/IRAM increase. Ordinary-display growth is expected:
it now contains keys, bounded K3/snapshot/control state, I2C and feedback rendering.
Relays retain no acquisition task, KG detector or VL53L1X symbols; their small
application footprint increase is still reported rather than rounded to zero.

The Japanese-label refresh alone adds **344 B image / 352 B `.bin`** to ordinary
display and **348 B image / 336 B `.bin`** to ToF display. Its whole-image Flash
text delta is +104 / +108 B and rodata +240 B in each; DRAM data, BSS, IRAM text,
SDK archive contribution, object layouts and stack reservations do not change.
Seven additional public-domain Shinonome glyphs (学 習 中 完 了 失 敗) contain
224 B raw bitmap data. Labels are now 学習中 / 完了 / 失敗, centered in rows8–23;
learning animation remains row24 and mesh bar rows30–31. These are source/frame
facts, not a physical display observation.

### SDK unchanged source/layout, actual link contribution

SDK SLOC is 40133 both before and after. All SDK budget-probe object sizes are
identical in independent baseline/current S3 and C6 compiler probes:
`lm_context` LEAF/RELAY/ROOT = **41688 / 46120 / 130880 B**.
This is a measured SoC-compiler comparison. A baseline native comparison was not
performed; no native zero-delta result is claimed.

| Variant | SDK DRAM BSS + data BEFORE → AFTER | Linked SDK flash text + rodata BEFORE → AFTER | Delta |
|---|---:|---:|---:|
| Display S3 | 24640 + 24 → 24640 + 24 | 237074 + 5399 → 237201 + 5399 | +127 B Flash, 0 DRAM |
| Display-ToF S3 | 24640 + 24 → 24640 + 24 | 237074 + 5399 → 237265 + 5399 | +191 B Flash, 0 DRAM |
| Relay S3 | 24640 + 24 → 24640 + 24 | 237038 + 5399 → 237038 + 5399 | 0 |
| Relay C6 | 24632 + 16 → 24632 + 16 | 273922 + 5393 → 273922 + 5393 | 0 |
| Current ROOT S3, reference only | 56444 + 24 | 330637 + 5988 | no baseline comparison |

The display now links the existing `lm_cancel` (63 B), absent in the baseline
display; archive-detail diffs also show placement/literal differences. Thus
unchanged SDK source does **not** imply byte-identical linked SDK Flash.

### Additional runtime reservation and exclusion proof

- Both displays request one `field_io` task, priority 4, **6144 B stack reservation**.
  This is dynamically allocated by `xTaskCreate`, not an additional map BSS array
  and not a measured stack high-water mark. Main's existing 16384 B stack is unchanged.
- New DRAM data+BSS plus that stack reservation: ordinary display **6843 B**,
  ToF display **8491 B**. Separately add the 1092 B IRAM code occupation if accounting
  all internal SRAM, giving 7935 / 9583 B known contributions. These are incomplete
  runtime totals: dynamic task-control, I2C/driver/vendor heap and peaks are unknown.
  Existing panel DMA buffers, Wi-Fi, NVS and SDK workspace must also be accounted.
- S3 compiler `sizeof`: detector 1536, keys including queue8 176, key event 16,
  snapshot 48, K3 slot 56, snapshot-send slot 88, learning-feedback slot 16,
  acquisition stats 40 B. These objects overlap the measured static state; do not
  add them again to BSS. The earlier host detector value 1552 B is a different ABI.
- `nm -S -C` ordinary-display ELF: **zero** KG detector/VL53L1X matches; its compile
  inputs exclude their sources. ToF ELF: 60 matches, including
  `(anonymous namespace)::detector`, `00000600` B (=1536), and real driver methods.
  S3/C6 relay and ROOT ELFs also have zero detector/driver matches.

## SLOC: same counter, separate denominators

Use `scripts/budget_report.py:c_sloc` for C/C++ headers/sources (nonblank,
non-comment lines), `py_sloc` for Python (nonblank, not starting `#`; docstrings
remain counted). Field main sources exclude `kg_presence`; native shim, reused
detector and licensed driver are separate. JS uses the same C-style comment
counter as a separate tool metric; HTML is nonblank lines, not C/C++ SLOC.
Generated sources, managed HUB75 sources and documentation are not SDK SLOC.

| Category | BEFORE | AFTER | Delta |
|---|---:|---:|---:|
| SDK core/security/store/C API | 28748 | 28748 | 0 |
| SDK IDF / ROOT / serial | 1820 / 6185 / 3380 | 1820 / 6185 / 3380 | 0 |
| **SDK total, budget 28000** | **40133** | **40133** | **0; already +12133 over** |
| Field main C/C++, prior application-counter scope, 12 → 18 files | 1266 | 2101 | +835 |
| Imported KG detector, 3 files | 0 | 880 | +880, separate reused code |
| Licensed Pololu/ST IDF driver, 2 files | 0 | 1598 | +1598, separate licensed code |
| Native I2C/RTOS shim, 6 files | 0 | 45 | +45, test-only |
| Python Host excluding tests, budget 6000 | 5667 | 5671 | +4 |
| Fieldview Python, 11 → 12 files | 2414 | 2729 | +315 |
| Fieldview JavaScript | 226 | 269 | +43 |
| Fieldview HTML nonblank | 77 | 81 | +4 |
| Native tests C/C++ | 22582 | 23190 | +608 |
| Host tests Python, snapshot at refresh | 9054 | 9597 | +543 |

The earlier **1480** driver reference is not the current-source count:
`VL53L1X.cpp` is 311 and `VL53L1X.h` 1287, total **1598** under the required counter.
Neither detector nor driver is charged as new first-party SDK code. Documentation
and test growth are not presented as firmware savings. Aggregate vendor counts
depend on whether the pinned submodules have been materialized; compare the
explicit imported files above rather than Windows/Linux vendor-tree totals.
Relative to the pre-Japanese report, the field counter grows by 26 and native
tests by 56 SLOC. The field counter includes the new glyph definitions as it
included the original five: 14 of those added source lines are reused bitmap
definitions, not newly authored glyphs. The native regression covers the three
learning-label cases, exact golden glyph rows, animation, mesh bar and command
bypass. Host test counts include main's scope/race fixes and are pinned to this
snapshot; later main test edits require their own updated evidence.

## Current SDK budget state (four-SoC example builds)

The unmodified budget script wrote its outputs outside the repository. Same IDF
pin and generated registry hash `1c8682d587ca3b25` in all 12 builds.
The existing external `budget-report.{json,md}` is the earlier SDK-resource run;
its field-unrelated test SLOC is historical. This report recomputes current SLOC
using the same counter without repeating those 12 unaffected builds.
Fixed RAM = workspace + SDK archive static DRAM; application/runtime vendor heap
is excluded. Flash differences below use the **existing T01 empty-IDF+ESP-NOW
reference**, not the independent pre-feature field checkout.

| SoC | Fixed RAM LEAF / RELAY / ROOT B | Image Flash delta to T01 LEAF / RELAY / ROOT B |
|---|---:|---:|
| S3 | 63784 / 69336 / 185900 | 280845 / 285605 / 392473 |
| C3 | 63768 / 69320 / 185880 | 312574 / 318298 / 439528 |
| C5 | 63768 / 69320 / 185880 | 318458 / 324182 / 445348 |
| C6 | 63768 / 69320 / 185880 | 318328 / 324144 / 446542 |

Revised RAM targets: 49152 / 57344 / 163840 B. **12/12 over**, worst +22060 B.
Flash target 262144 B: **12/12 over**; all four ROOT images also exceed the
327680 B review line. SDK SLOC is over; Host Python remains within 6000.
The budget script actually ran the native crypto measurement: worker stack 8792 B
+ PSA heap 4368 B = 13160 B, inside 24576 B. That is an x86-64 software-model
measurement, not ESP32 heap/stack evidence or a feature delta.

## Validation evidence, failures and warnings

- This worker ran the builds and resource probes above. Native/Host/spec validation
  remains main-owned. The inspected main-owned native `LastTest.log` contains
  **31/31 passed**, ended 2026-10-10 00:00 JST. The field ASan/UBSan log contains
  **4/4 passed**, ended 2026-10-09 23:56 JST. These were inspected, not rerun here.
  A retained `LastTestsFailed.log` still names `test_field_driver`; the newer full
  log explicitly shows its 4 cases passing. Do not mistake that stale list for the
  newer run or claim it was removed. Host pytest/ruff/G0 final results need main's
   own command evidence; the later final run is recorded in the final validation section below.
- Refresh handoff supplied by main: full native 31 passed; initial full Host
  run **605 passed / 2 failed**. One failure was K06 wrongly scanning the field
  application; main corrected the scope and reported its focused **3 passed**.
  The other was E2E seeing `root_connected` before domain readiness; main fixed
  the `await_root` race and is rerunning. **Final full Host PASS is pending**.
  Checker/ruff are now installed, but their final command results are still main's
  evidence to append. These are main-reported status updates, not tests run here.
- Field negative cases in those logs/source: held key at boot; NACK breaking
  debounce; full queue drops newest; invalid/unlearned/no-sample states; failed
  relearn preserves background but does not expose old vacant; lost/delayed result
  rendering; busy/dropped K3 presses retain the correct operation association;
  SENT/acceptance does not confirm K3; expiry retains uncertainty; snapshot refusal
  rate-limit/sequence-wrap; invalid driver reads/interrupt clear; finite sensor
  initialization. Native render tests preserve rows 30/31 but do not measure LEDs.
- All requested firmware commands exited 0. No compiler error or new field
  enum/int compiler warning occurred in the final incremental field rebuilds.
  The latest two Japanese-label logs contain **zero compiler warnings/errors and
  zero CMake warnings**. They each retain three existing IDF Kconfig notes:
  `bt/host/nimble/Kconfig.in:1453` `BT_NIMBLE_MESH_PROVISIONER`,
  `fatfs/Kconfig:230` `FATFS_PRINT_LLI`, and `fatfs/Kconfig:235`
  `FATFS_PRINT_FLOAT` use invalid bool `default 0`, treated as `n`.
  Existing warnings reproduced by baseline/full example builds are
  `idf_pm.cpp:95:43,151:45` deprecated `esp_sleep_get_wakeup_cause`,
  `edhoc_ead_internal.c:70:12` unused `comp_message_number`, and
  `zcbor_decode.c:1409:17` unused-but-set `additional`. Each occurs once per
  baseline field build and four times per example profile. Unchanged SDK/vendor
  objects were reused in AFTER field builds; lack of those warnings there is not
  a claim that they were fixed.
- Existing configure diagnostics: managed HUB75 directory considered unexpected
  when conditionally disabled; missing Kconfig option prompts the second configure
  pass; `ESP32_HUB75_USE_GFX=n` unknown on the initial pass. Baseline/current logs
  retain these rather than suppressing them. They are not new sensor compiler errors.
- Measurement-tool failures, not firmware failures: initial mirror check included
  generated `dependencies.lock`; baseline historical fingerprints also included
  it. Checks were corrected to exclude generated locks before collecting results.
  Recorder metadata initially collided with external `budget-report.json`;
  budget output was rerun with metadata named `budget-command.json` (19.217 s,
  exit 0), preserving the actual budget JSON. No feature source changed to fix tooling.
- Documentation recheck: field protocol §2 now uses the source's 2/4/8/15/20-second
  Join backoff. Fieldview README now distinguishes application-only sensing from
  the Host's generic persisted reception timestamp. No KG logic entered SDK/Host.

## Cadence, bounded resources and unverified work

Source-reviewed, not measured electrically: keys every 25 ms, 50 ms debounce;
ToF sampling/ready checks every 40 ms, Long mode, 33000 us sensor budget, ROI8x8,
center199; 20 ms transaction timeouts; initialization retry after 3000 ms.
The acquisition task waits for the earliest due work. It does not add an
unconditional 1/2/5 ms steady poll. The driver's reset-status 1 ms loop is bounded
by its 100 ms initialization timeout; the existing DMA wait is bounded at 300 ms.
This path is I2C ToF acquisition, not an ADC measurement.

Key queue8 drops newest with saturating counters; one latest acquisition snapshot;
one learning result; one K3 operation; one snapshot send; telemetry changes at
most 1 Hz with 10 s refresh. Browser tables256, boot scopes8, press bitmap256,
history20 remain bounded. No per-range radio stream, new core owner/task, new
authentication engine or per-sample Flash write is introduced. ALWAYS_RX is the
explicit field-kit policy. Power-mode/session/replay/PM-lock/sleep-ticket/group
behavior receives no new hardware qualification from this compile exercise.

Report consistency check executed:
`python3 /mnt/c/Users/daits/AppData/Local/Temp/opencode/field_verify_report.py` — PASS.
It compares the JSON's commands/results/durations, resource tables, four-SoC budget
values, raw/bin hashes and `sizeof` with collected evidence, and rechecks the
current-source fingerprint. `git diff --check -- build-records/field-presence-validation.md
build-records/field-presence-validation.json` exited 0; both report files are new
untracked files, so the evidence comparison is the substantive content check.

**Not measured:** target stack high-water, task-control/I2C/vendor peak heap,
minimum-ever/maximum-contiguous free heap, steady/idle CPU, owner p99/max,
sampling under rendering/USB/Flash load, RF airtime, delivery latency under RF,
J/report, current, recovery energy, electrical wiring/pull-ups/reset behavior,
physical K3 labeling, optical correctness, LEDs, nine-node deployment, real power
cuts and key custody. No synthetic current or host model is substituted for these.

Attribution is retained: KG detector at
`b80ce46d63f7c1a5d36552f8ee38969b96cca412`, owner-authorized field reuse with
rights reserved; no public license is invented. The Pololu/ST driver retains
BSD-3-Clause notices and KG adaptation provenance at
`1e91d02202ad25c43f21a0274c000f9f5ee1000a`. Broader distribution rights, the SDK's
distribution license and release SBOM/custody review remain rights-holder/release
work. Hardware acceptance and these rights are explicitly pending.
The final font ledger now lists all twelve public-domain Shinonome glyphs and
their KG `b80ce46d` source-pack provenance, including the seven added for learning.

## Final software validation (main execution)

The final source remains uncommitted on `37df3f2`; no commit or device write was requested.
The initial whole-Host run was **605 passed / 2 failed**. One existing topology
test read the domain before it was committed (USB `root_connected` is weaker
evidence); it now uses the existing `await_root` helper. The vocabulary test
wrongly scanned the explicitly application-only field firmware; its scope now
excludes that one application while retaining SDK, neutral example and ROOT
firmware checks, with a new scope regression. Source attribution was not erased
to silence that test. Both failures were rerun after their fixes.

Commands actually run from `/root/leanmesh-work` via WSL:

```sh
cmake --build /root/.cache/leanmesh/native -j4
ctest --test-dir /root/.cache/leanmesh/native --output-on-failure -j4
# Final: 31/31 passed, 24.03 s.

cmake -S . -B /root/.cache/leanmesh/native-asan -G Ninja \
  -DLM_IDF_PATH=/root/esp/esp-idf-v6.0.3 -DLM_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build /root/.cache/leanmesh/native-asan -j4
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir /root/.cache/leanmesh/native-asan --output-on-failure -j4
# Final: 31/31 passed, 312.30 s. No sanitizer E2E rerun is claimed.

/root/.cache/leanmesh/host-venv/bin/python -m pytest -q -p no:cacheprovider
# Final: 608 passed, 641.63 s. Includes real Host/meshsim/USB-helper E2E.

/root/.cache/leanmesh/host-venv/bin/python scripts/check_spec.py
# Overall PASS (G0 only).
/root/.cache/leanmesh/host-venv/bin/ruff check host tools/fieldview \
  scripts/check_api_defined.py scripts/budget_report.py scripts/scenario_coverage.py \
  scripts/report_pytest_failures.py
# All checks passed.
git diff --check
```

The G0 generated `evidence/VALIDATION.json` was written only in the Linux build
checkout; the prior Windows workspace evidence was not replaced. Additional
checker dependencies and Ruff 0.16.9 were installed in the Linux Host venv, not
the Windows/global Python environment.

Independent source review found six defects before acceptance: impossible sample
timing, failed-relearn vacancy, startup boot catch-up, stale K3 freshness revival,
hidden learning-completion feedback, and unused non-ToF detector buffers. Each
received a failing regression followed by the minimal correction. Follow-up review
confirmed those corrections and found no remaining critical/high defect; that is
source review, not hardware qualification. The Japanese labels also had a failing
render regression before the seven glyphs were added, then normal and sanitizer
passes. The new receipt timestamp initially failed Host/E2E regressions before the
persisted time was connected. All hardware/resource limits above remain unverified.
