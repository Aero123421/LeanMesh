# Issue #3: offline initial-Join issuer

Base: `9966cd49cdc52a49c33e88dc8d023e60b5b8f339` (main after PR #2).
Branch: `feat/fleet-issuer-initial-join`. The implementing commit is the commit containing this record;
the PR/CI results identify the exact head separately. This is the first slice of #3, not its hardware completion.

## Purpose and boundary

An offline operator can create an encrypted fresh fleet key, issue DeviceCredential and RootDelegation from
verified P-256 public keys, and create a bounded initial-admission batch (tickets + expected pages).
Existing SDK validation, wire numbers, storage formats, firmware/Host HTTP paths and trust rules are unchanged.
The signer uses the already locked `cryptography==50.0.1` and existing Host CBOR/COSE structural codecs.
`tools/lmfleet` remains deterministic TEST-ONLY; the new CLI never imports it.

Key store: exclusive 0700 directory, owned single-link 0600 files, encrypted PKCS#8, explicit test/production
environment, metadata/public/private key consistency, O_NOFOLLOW and pinned directory fd. Outputs are exclusive
and fsynced; the batch manifest is written last. Passwords come from a hidden prompt or protected file.
The CLI reports ids/hash/count only and suppresses input/backend exception details.

Initial assignment only: zero source / expected-old=0, random mode1 one-time grants, device and delegation
hash bindings, one generation/revision per batch, <=64 devices / <=8 entries per page / <=1024 bytes per object.
No firmware key import, NVS image, eFuse write, USB kit, transfer/window/revoke/handover issuance, inventory
floor management or Host backup is supplied by this change. See [custody and use](../docs/sdk/fleet-issuer.md).

## Actual local validation

Activation: `source /workspace/leanmesh-env/activate.sh`. Logs/output remain outside the checkout under
`/workspace/leanmesh-env/logs/issuer-*`. Native GCC 14.2, Python 3.12.14, Ruff 0.16.9; IDF/PSA sources use the
repository's pin. No dependency lock changed and no key material is committed.

| Command | Observed result |
|---|---|
| `cmake -S . -B "$LEANMESH_NATIVE_BUILD" -G Ninja -DLM_IDF_PATH="$IDF_PATH"` and `cmake --build "$LEANMESH_NATIVE_BUILD" --target issuer_driver -j4` | Build succeeds with the existing warning-as-error flags |
| `python -m pytest -q host/tests/integration/test_fleet_issuer.py` | **54 passed in 1.63 s**, including CLI-output Join |
| `python -m pytest -q host/tests/unit host/tests/integration` | **250 passed in 53.58 s**, including CLI-output Join |
| `ctest --test-dir "$LEANMESH_NATIVE_BUILD" --output-on-failure --no-tests=error -R 'test_(credentials\|security\|join)$' -j2` | **3/3 passed**, 6.57 s (SDK credentials, crypto/EDHOC, Join) |
| `cmake -S . -B /workspace/leanmesh-env/asan -G Ninja -DLM_IDF_PATH="$IDF_PATH" -DLM_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug` and `cmake --build /workspace/leanmesh-env/asan --target issuer_driver -j4` | ASan/UBSan driver build succeeds |
| `ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:print_stacktrace=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 LEANMESH_ISSUER_DRIVER=/workspace/leanmesh-env/asan/tests/native/issuer_driver python -m pytest -q host/tests/integration/test_fleet_issuer.py` | **54 passed in 7.04 s**, including CLI-output Join; no sanitizer report |
| `ruff check host scripts/check_api_defined.py scripts/budget_report.py scripts/scenario_coverage.py scripts/report_pytest_failures.py` and `git diff --check` | Pass |
| `python scripts/check_spec.py` | Overall PASS; regenerated `evidence/VALIDATION.json` restored to its original bytes afterward |
| `python scripts/scenario_coverage.py --out-dir /workspace/leanmesh-env/issuer-coverage` | Exit 0: 158 scenarios / 337 references; 116 NOT_RUN_HARDWARE remain |
| `python scripts/budget_report.py --native-build "$LEANMESH_NATIVE_BUILD" --json /workspace/leanmesh-env/logs/issuer-budget.json` | Exit 0, existing budget overruns reported; no gate relaxed |

Failure cases: shared or linked files, plaintext/key-mismatched metadata, wrong password/environment,
invalid serial/curve/domain/generation/permissions, duplicate/oversized batches, foreign or corrupted inputs,
modified signatures on all five supplied credential/control objects, and valid signatures with wrong device,
CCS, fleet, ticket credential/delegation hash or expected grant binding. Native verification rejects the mutations.
The maximum batch's eight pages are each checked by the SDK with u63-max generation/revision.

The new fixture initially encountered BUSY while the boot's record jobs still owned their resources. The driver
now retries **only unaccepted BUSY/AUTH_PENDING calls**, with a fixed bound, and polls accepted operation evidence.
It never resubmits an accepted Join or installation. Both the Python API and actual CLI outputs pass EDHOC and
sealed-record Join through Root ACTIVE **confirmed**, using random ephemeral device keys and unchanged SDK paths.

CI changes: build the driver in the Host job; run the same tests with the ASan/UBSan driver in the sanitizer job.
The existing native/model/E2E/4-SoC jobs and their gates remain enabled. Remote results are recorded in the PR;
local validation alone is not a remote CI success claim.

## Resource delta

Measured with the same native budget probes and SLOC counter as main:

| Resource | Main | This change | Delta |
|---|---:|---:|---:|
| LEAF native workspace | 41,936 B | 41,936 B | 0 B |
| RELAY native workspace | 46,240 B | 46,240 B | 0 B |
| ROOT native workspace | 127,784 B | 127,784 B | 0 B |
| SDK C/C++ SLOC | 37,954 | 37,954 | 0 |
| Python under host, excluding tests | 4,558 | 4,869 | +311 (offline CLI only) |

The test-only native driver adds 196 C++ SLOC and is never linked into firmware. Existing SDK SLOC / SoC RAM /
flash budget overruns are not resolved. The native workspace measurements exclude platform/vendor heap.
There is no firmware source/config change; SoC builds run in CI. Actual flash/RAM/stack/heap/CPU, RF airtime,
energy, real power cuts, hardware Join, independent EDHOC interoperability and custody review are not measured.

## Follow-up for #3–#6

#3 remains open: device-owned key generation/ownership binding, protected record writing, trust-anchor deployment,
Root/Host pairing and the remaining signed lifecycle objects must follow. #4 needs the board-specific Root firmware
and real resource measurements. #5 needs the backup/recovery contract and type21 implementation. #6 needs the
hardware execution and truthful capability/traceability update. Transfer and spare-Root recovery require a second
Root; a single-Root simulation pass does not satisfy those physical acceptance conditions.
