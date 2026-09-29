# LeanMesh implementation guide (architecture, work breakdown, decisions)

Status: skeleton for T02–T28. Normative sources stay [README](../README.md), docs/01–23,
[registry](../protocol/registry.json), [control.cddl](../protocol/control.cddl),
[leanmesh.h](../api/leanmesh.h), [openapi.json](../api/openapi.json), [schema.sql](../db/schema.sql).
This file decides *how* they are implemented and who owns what. Rules of [AGENTS.md](../AGENTS.md)
and [15-coding-standards](15-coding-standards.md) apply to every slice.

## 0. Build and test (every slice runs all of these before reporting)

```sh
scripts/third_party.sh setup && scripts/third_party.sh verify      # libedhoc pin + patch
cmake -S . -B ~/.cache/leanmesh/native -G Ninja                   # needs ~/esp/esp-idf-v6.0.3
cmake --build ~/.cache/leanmesh/native
ctest --test-dir ~/.cache/leanmesh/native --output-on-failure
cmake -S . -B ~/.cache/leanmesh/native-asan -G Ninja -DLM_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug   # ASan+UBSan
scripts/setup_host_venv.sh sync-dev                               # hash-locked runtime + pytest
~/.cache/leanmesh/host-venv/bin/python -m pytest                  # unit/integration/E2E (meshsim)
scripts/build_targets.sh --app example_node --app crypto_link_check esp32c3   # quick IDF check
scripts/build_targets.sh --app example_node --profile ROOT esp32c3             # root-only code too
scripts/build_targets.sh                                          # all apps x 4 targets (wave close)
scripts/budget_report.py --native-build ~/.cache/leanmesh/native \
    --idf-build ~/.cache/leanmesh/build/example_node/esp32c3 \
    --idf-build ~/.cache/leanmesh/build/example_node-ROOT/esp32c3        # ADR-002 numbers
python3 scripts/check_spec.py && git checkout evidence/VALIDATION.json
```

Build/venv directories live outside the repo. E2E tests find meshsim in `$LEANMESH_NATIVE_BUILD`
(default `~/.cache/leanmesh/native`) and FAIL when it is missing. Nothing is flashed, ever.
CI (`.github/workflows/ci.yml`): `spec`, `native-and-host` (IDF image for the PSA sources),
`idf-targets` (matrix of 4 SoCs, image pinned by digest).

## 1. Directory layout and ownership

| Path | Content | Built for |
|---|---|---|
| `api/leanmesh.h` | C ABI (spec). Also the implementation's public header; never copied. | all |
| `cmake/` | pins check, JSON→C++ generators, native crypto, libedhoc source list, module list | all |
| `src/core/` | foundation types, ports, owner `Engine`, job table, event queue, commands | all |
| `src/core/{wire,radio,link,member,route,delivery,sched,group,channel,power,diag}/` | I/O-free feature modules (one slice each, §11) | all |
| `src/security/` | PSA wrappers, record layer, EDHOC suite-3 glue (C), COSE, job bodies | all |
| `src/store/` | sealed 2-slot records, boot incarnation, journal (job bodies over the Store port) | all |
| `src/root/`, `src/serial/` | topology, ledger, groups, channel coordinator, lifecycle; USB serial + bridge | root builds |
| `src/capi/` | `lm_*` entry points (`capi_<area>.cpp` per slice) | all |
| `src/port/idf/` | ESP-IDF ports and tasks. The only place for chip `#ifdef`s | firmware |
| `src/port/sim/` | sim ports, `World` (virtual time + medium), `SimNode` | native |
| `src/hostnative/` | C shared library for the Host (EDHOC purpose 3 + records), same sources (S10) | native |
| `components/leanmesh/` | IDF component wrapper (`Kconfig`: LEAF/RELAY/ROOT profile) | firmware |
| `firmware/baseline_espnow` | empty IDF+ESP-NOW size reference. Keep pure. | firmware |
| `firmware/example_node` | same bring-up + SDK (docs/16 comparison sample) | firmware |
| `firmware/crypto_link_check` | build gate: libedhoc + IDF PSA link (never flashed) | firmware |
| `tools/meshsim/` | simulator process: control protocol (stdin/stdout JSON lines) + pty | native |
| `tools/lmtool/`, `tools/lmfleet/` | codec CLI for differential tests; TEST-ONLY fleet issuer (S1, S5) | native/py |
| `tests/native/` | CTest binaries (`lmtest.hpp`, no framework) | native |
| `host/leanmesh_host/` | FastAPI service; `host/tests/{unit,integration,e2e}` + `harness.py` | host |

Source lists: every module dir has a `sources.cmake` appending explicit files to
`LM_COMMON_SOURCES` / `LM_ROOT_SOURCES` / `LM_PORT_SIM_SOURCES` / `LM_PORT_IDF_SOURCES`;
`cmake/lm_sources.cmake` includes the fixed module list above (missing dirs are skipped).

## 2. Processes, threads and ownership (docs/02 §2)

| Owner | IDF | meshsim / native | Does | Never |
|---|---|---|---|---|
| mesh owner | 1 task, sleeps until `Engine::step()` deadline or notification | the sim thread at scheduled `Wake` events | queues, peers, routes, TX, RX verification, timers, AES-GCM per frame | P-256, Flash, app callbacks, logging on hot paths |
| slow-job worker | 1 task + bounded queue (`IdfJobs`) | job bodies run at virtual `now+latency` | EDHOC steps, sign/verify, Store I/O | touch owner state except its `arg`; radio |
| app executor | caller tasks through `OwnerCall` | direct calls on the sim thread | `lm_*` calls, `lm_next_event`, results | hold core pointers, fake ACKs |
| serial bridge (root) | 1 task: framing/COBS/CRC/AEAD, then C API + root-local commands | pty bytes on the sim thread | Host methods (docs/19) | touch mesh state directly |

Driver callbacks copy into `SpscRing` and notify; nothing else (docs/15 §2).

## 3. Core event → effect model

`Engine` (src/core/engine.hpp) is the owner. Contract:

- `MonoTime step(now)`: drains job completions, then at most `k_max_radio_events_per_step`
  radio events, runs due timers, returns the earliest deadline (`MonoTime::never()` = sleep until
  an external event). No fixed tick, no 1/2 ms poll; idle owner steps once and stops (tested).
- `Reply execute(const Command&, now)`: one C-API or root-local command. The caller is blocked
  in `OwnerCall::call` and its memory stays valid, so the owner copies payloads into its fixed
  pools during `execute`. Unimplemented kinds return `Unsupported` (the operation does not exist).
- Effects leave only through ports (`Radio::transmit`, `Jobs::submit`) and the app event queue.
  Ports never block; a full queue is `Busy`/`NoCapacity`, never RF loss.
- Jobs: `JobTable` reserves (`JobOwner`, slot `Handle`, class). One public-key job at a time.
  A completion acts only if `(table_index, job_id)` matches; then the module checks its slot
  handle generation. **The memory behind a job's `arg` stays reserved until the completion is
  polled, even if the slot was cancelled** (zombie state), so a late worker write never lands in a
  reused slot (R10).
- Events: `AppEventQueue` is owner-only (`lm_next_event` runs through the owner call); overflow
  never blocks the owner and produces one `LM_EVENT_GAP` where events were lost.
- Pools: `Pool<T,N>` + `Handle{index,generation}`; `BoundedQueue`; `SpscRing` for callbacks.
- Wiring a module: add the member to `Engine`, one line in `on_radio_event` / `on_job_completion`
  (`JobOwner` case) / `next_deadline()` / `execute()`, in the `[SLICE]`-marked places. Additive
  edits only; re-read the file right before editing (other slices edit it in the same wave).

Types (use them; do not re-invent): `Status` ([[nodiscard]], generated from the registry and
`static_assert`-ed against `LM_STATUS_*`), `Result<T>`, `LM_TRY`, `Duration`/`MonoTime` (µs),
`RootTime`/`RootTimeBound` + `check_deadline()` (TIME_UNCERTAIN unless provable), `UtcTime`
(host only), `Tagged<>` generations (`RootTerm`, `AssignmentGen`, `MembershipGen`,
`ChannelEpoch`, `PathRevision`, `LinkSid`, `EndSid`, `ShortAddr`…) with `next_generation()`
refusing wrap, `FixedId<N>` identities (`DeviceId` 32, `DomainId`/`FleetId`/`RequestId` 16),
`MessageId`, `MacAddr`, `ByteView`/`MutByteView`, `Reader`/`Writer` (sticky errors, `finish()`
rejects trailing bytes), `wire::CborWriter` (deterministic). Constants come from generated headers
(§6); never type a registry/profile/default number by hand.

## 4. The four ports and the owner call (src/core/ports.hpp)

| Port | Contract | IDF (`src/port/idf`, S3/S4) | Sim (`src/port/sim`) |
|---|---|---|---|
| `Clock` | monotonic µs since boot | `esp_timer_get_time` (done) | world time − boot time, optional ppm drift |
| `Radio` | start (refuses unapproved RF profile), channel+readback, peers (20 = 16+3+1), 1 TX in flight with `TxToken{driver_generation, seq}`, `poll()` RX/TX-done | ESP-NOW, init order docs/03 §3, LR250 per peer, callbacks → `SpscRing`, 1000 ms watchdog | `World` medium: allowlist links, loss, MAC-ACK loss, delay, callback delay, channel, power |
| `Store` | keyed 2-slot blobs (durable on Ok, read errors ≠ empty) + append-only journal with segment erase; worker only | NVS `identity`/`state` partitions, raw `journal` partition | in-memory, survives power cut; S4 adds cut injection per boundary |
| `Jobs` | bounded `submit`, owner `poll`, CSPRNG `random()` for SDK nonces/jitter | worker task; `esp_fill_random` | virtual latency; seeded xorshift (sim only) |

`OwnerCall` is the owner-task mechanism, not a port: IDF = bounded queue + task notification
(Busy when full); sim = direct call. The root serial byte stream is a root-only adapter owned by
`src/serial` (IDF USB/UART driver, sim pty), not a fifth core port (decision D5).

## 5. Crypto and EDHOC wiring (docs/06)

- One backend: PSA. Firmware links IDF's `mbedtls` component (Mbed TLS 4.1.1/TF-PSA-Crypto).
  Native builds compile the *same* TF-PSA-Crypto sources from the pinned IDF tree
  (`cmake/lm_crypto_native.cmake`, verified pin; two-line include shims for the Espressif fork).
  Proven: `test_crypto_backend` opens all golden AES-GCM frames and verifies the golden COSE_Sign1
  via PSA; `crypto_link_check` links libedhoc + PSA for all four SoCs.
- libedhoc v2.3.2 (pinned, exact-input patch): core + CBOR backend + zcbor compiled via the upstream
  `cmake/sources.cmake` list (`cmake/lm_edhoc.cmake`: 1 suite, method 0, log off, stack backend).
  None of libedhoc's reference suites is compiled. S2 writes the **suite-3 crypto glue in C**
  (`src/security/edhoc/`, libedhoc headers are C11-only) implementing `struct edhoc_crypto` over
  PSA: ES256, P-256 ECDH as NIKE-as-KEM (`generate_key_pair/encapsulate/decapsulate`),
  HKDF-SHA-256, AES-CCM-16-128-128. C++ calls it through a narrow C header without libedhoc types.
- Handshake steps (`message_1..4_compose/process`, exporter label 40000) are job bodies on the
  worker; the handshake slot (holding the `edhoc_context`, size from `edhoc_context_size()`) obeys
  the zombie rule of §3. The record layer (HKDF key/prefix, AES-128-GCM, counters, 64-packet replay
  window consumed only after AEAD + checks) runs on the owner.
- Host: `src/hostnative` builds a shared library from the same security sources + PSA; Python
  uses it via `ctypes` for EDHOC purpose 3 and USB records (no Python EDHOC).
- PSA allocates (key slots, bignum). This is the documented vendor exception: S2 installs a bounded
  allocator (mbedtls platform calloc/free) where the backend allows and S19 reports peak use.
  Concurrent PSA use (owner AES-GCM + worker ECDH) requires PSA thread safety on IDF — S2 verifies
  the IDF config and records it.

## 6. Generated constants (cmake/lm_generate.cmake)

At configure time: `gen/registry.hpp` (`Status`, `FrameKind`, `RecordKind`, `ControlType`,
`SerialKind`, `CapabilityBit`, `limits::`, `layout::<link|route|end>::*_offset/_size`, `aead::`,
signed/reserved control type arrays; static_asserts against `leanmesh.h`), `gen/profiles.hpp`
(`ProfileLimits` for leaf/relay/root), `gen/defaults.hpp` (`lm::gen::defaults::<section>::<key>`),
`gen/golden.hpp` (tests only: golden frames, COSE, power poll/grant). Enumerators are UpperCamel
of the registry names (`HOP_ACK` → `HopAck`); control types keep their registry names.
Profiles: firmware picks one maximum profile (Kconfig) that sizes arrays; `LM_BUILD_PROFILE_SIM`
sizes for root and each sim node applies its role's limits at runtime.

## 7. meshsim

Single-threaded discrete-event world (µs, deterministic per `--seed`): `Wake`, `Rx`, `TxDone`,
`JobDone` events; power cuts bump a node epoch so stale radio/job events vanish; the Store
survives. Each node is a real `lm_context` + `Engine` on sim ports. `--clock virtual` advances only
with `run <ms>`; `--clock realtime` follows the wall clock (needed when the real Host drives the
pty). Control: one command per stdin line, one JSON reply per line (table in
`tools/meshsim/control.cpp`; slices add commands in `tools/meshsim/cmd_<slice>.cpp` + one table
line). Node 0 is the root; `--serial-pty` exposes its serial port. It is a protocol bench: no RSSI,
no RF, no energy; sim results never replace hardware scenarios (docs/03 §5, docs/18 §3).

## 8. Host

`leanmesh_host.main:app` (lazy, env-configured: `LEANMESH_DB`, `LEANMESH_TOKENS` (0600 JSON of
SHA-256 token digests + permissions), `LEANMESH_SERIAL`, `LEANMESH_SCHEMA`). Storage thread owns
the only sqlite connection (explicit `BEGIN IMMEDIATE` per submitted function, bounded queue →
503), schema + durable `journal_id` created in one transaction, `quick_check` on open, flock
singleton lock (H07). Next: serial I/O thread (S10), bridge/outbox/inbox (S13). Test deps are in
`host/requirements-dev.lock` (runtime pins identical to `requirements.lock`).
`harness.py`: `MeshSim` (process + control), `HostProcess` (uvicorn on a UDS + httpx2 client).

## 9. Test strategy

- Prefer E2E/integration: C++ tests drive real `SimNode`s in a `World`; pytest drives meshsim and
  the real Host process. Unit tests only for codecs, crypto vectors (tests/golden.json,
  tests/power_golden.json, RFC traces) and pure decision functions. No mocks of the component under
  test; a test double is allowed only for an external boundary (e.g. a scripted malicious peer via
  `inject`).
- Naming: a test covering an acceptance scenario starts with its ID (`LM_TEST("R10 …")`,
  `@pytest.mark.scenario("H07")`). S19 collects them into a generated coverage report.
  `tests/scenarios.json`, `tests/traceability.csv` and `config/capability-manifest.json` stay
  unchanged (the checker asserts NOT_RUN/not implemented); software evidence ≠ product evidence.
- Property/model tests log seed, event trace and minimal counterexample (docs/18 §2).
- Hardware-only, remain NOT_RUN: RF-* (16), physical parts of R01/R02/R06/R07, C01, S03, S08
  timing, H03 physical USB, O01, O03, K01–K05, M07, L01 72 h, LP02, LP19, ME01–ME03, ME06–ME08,
  POWER-* on real Flash, T20/T21/T22/T24. Sim versions of HARDWARE scenarios are labelled
  "sim" in reports.

## 10. Spec gaps and decisions

| # | Gap / contradiction | Decision |
|---|---|---|
| D1 | Suite 3 is not among libedhoc's reference suites (0,2,4,24,PQC); RFC 9529 has no method-0/suite-3 trace | LeanMesh C glue implements suite 3 over PSA. S01 = (a) RFC 9529 §3 trace through the same glue parameterised to suite 2 (test build only), (b) method-0/suite-3 loopback + exact-input mutation tests, (c) independent-implementation interop remains **unverified** until one is chosen |
| D2 | libedhoc public headers are C11-only (`_Static_assert`) | EDHOC glue in C; C++ sees a narrow C API |
| D3 | Frame kinds 3/4/5/7 usage not defined | DATA(3)=routed body (route header+path+end record) for all end-to-end records incl. E2E control; ROUTE(4)=1-hop link-AEAD control-body of routing types (Probe/hello); CONTROL(5)=1-hop link-AEAD non-routing control (each use documented by its slice); EDHOC(6)=bootstrap carrier for link handshakes/SESSION_BIND; JOIN_PROXY(7)=1-hop carrier between an unjoined device and its proxy (SID 0, EDHOC-protected content); DISCOVERY(1)=SID 0 hints and signed beacons only |
| D4 | C ABI has no root-local calls for JOIN_DECIDE, NODE_QUERY, HOST_STORE_ACK, EVENT_ACK, GROUP_SNAPSHOT, SLEEP_WINDOW | Internal root-local `CommandKind`s used by the serial bridge; no public ABI change in v0.2 |
| D5 | Serial is a fifth I/O beside the 4 ports | Root-only transport adapter in `src/serial`; the bridge is an application executor (C API + root-local commands). USB EDHOC steps are submitted through the owner so the single P-256 job limit also covers USB |
| D6 | Host identity for EDHOC purpose 3 unspecified | Host holds a fleet-issued DeviceCredential; the root stores a sealed "paired host DeviceId" record installed at provisioning; the Host verifies root DeviceCredential + RootDelegation for its domain. No shared USB secret |
| D7 | No generic internal-error status | PSA/backend failures → `RECOVERY_REQUIRED` (fail closed); programming errors → `LM_ASSERT` |
| D8 | `lm_next_event` with no event | `NOT_FOUND` |
| D9 | ABI check of output structs | Caller initialises `struct_size`/`abi_version` of every struct it passes (as `examples/low_power.c`); ABI ≠ 2 → `UNSUPPORTED`, size ≠ sizeof → `INVALID_ARGUMENT` |
| D10 | `application_event_slots` bound absent from profiles.json | ≤ profile `app_messages` |
| D11 | Checker requires scenarios NOT_RUN / manifest all false | Implementation evidence goes to generated reports (S19), spec files unchanged; runtime capability bits are separate facts |
| D12 | Espressif TF-PSA-Crypto fork includes `mbedtls/bignum.h`,`ecp.h` via IDF wrappers | 2 include shims for native builds (`cmake/native_crypto_compat`) |
| D13 | zcbor float16 helpers type-pun | vendor sources built with `-fno-strict-aliasing -Wno-error` (warnings stay visible) |
| D14 | IDF defaults gnu23/gnu++26 vs C11/C++17 rule | component forces gnu11 (vendor C) and gnu++17 (first-party), `-fno-exceptions -fno-rtti` |
| D15 | One native binary must run every role | `LM_BUILD_PROFILE_SIM` (root-sized arrays, per-node runtime limits); firmware: Kconfig profile, root code compiled only for ROOT |
| D16 | PSA heap use vs "no malloc after init"; PSA concurrency | explicit vendor exception with bounded allocator + peak report; PSA thread-safety verified on IDF (S2) |
| D17 | Host token file, readiness, schema location unspecified | 0600 JSON of SHA-256 digests; `ready` = DB + USB credential + migrations (false until S10); schema read from `db/schema.sql` (`LEANMESH_SCHEMA`) |
| D18 | Starlette 1.7 TestClient deprecates httpx | dev-only `httpx2` (license ledger updated) |
| D19 | Commit-marker representation of docs/12 §2 unspecified | S4 defines it on top of the keyed-slot Store port (a marker record per sealed record) |
| D20 | Deterministic sim vs hardware RNG | `Jobs::random` (SDK nonces/jitter) is seeded only in sim; keys are always generated inside PSA |
| D21 | T16 (group) pages exceed one frame | control fragmentation (S12) precedes groups (S15) |
| D22 | check_spec scanned vendor/build trees | excludes `.git`, `third_party`, `build`, caches; libedhoc sparse checkout dropped |

Workers add new decisions to this table (next free number) in their report; the orchestrator
merges them.

## 11. Work breakdown (waves of parallel slices on disjoint files)

Acceptance for every slice also includes §0 green (native, pytest, esp32c3 IDF build of the LEAF and
the ROOT profile, `scripts/build_targets.sh --profile ROOT`; 4 targets at wave close), no new
warnings in first-party code, and a report: files, commands + real output, scenario IDs covered
(sim/host evidence), `scripts/budget_report.py` before/after (sizeof per profile, static DRAM, image
diff, SLOC) against the slice's allocation in [ADR-002](../decisions/ADR-002-budget-status.md), unverified
items, decisions.

### Wave 1 — foundations
| Slice | T | Owns | Deps | Acceptance |
|---|---|---|---|---|
| S1 WIRE | T02 | `src/core/wire/**`, `tools/lmtool/`, `host/leanmesh_host/wire/`, `tests/native/test_wire*.cpp`, `host/tests/unit/test_wire*.py` | skeleton | strict CBOR decoder (non-minimal, indefinite, dup/unsorted keys, trailing, bad UTF-8, depth, floats rejected); link/route(+path rules)/end/HOP_ACK/fragment/bitmap/bootstrap carrier/serial header/power poll+grant codecs; control-body envelope with type→data table (22–24 rejected); COSE_Sign1 structure + Sig_structure; golden headers of 1/3/20/40-hop frames; every length 0..250; **differential** pytest (C++ `lmtool` vs Python host codec vs `scripts/wire_fixture.decode`, random + mutated inputs); R04 (codec part) |
| S2 CRYPTO | T03 | `src/security/**`, `tests/native/test_security*.cpp` | skeleton | record layer reproduces golden packets byte-exact from test seeds and opens them; tamper/nonce/context changes rejected; replay window; ctx/ctx_hash, DeviceId, COSE sign/verify (golden); suite-3 glue + job-body handshake driver; S01 (per D1), S02, S04, S07 (curve point/length/hash/signature/low generation); secrets zeroised; stack/heap peak of a handshake measured natively |
| S3 RUNTIME | T04 | `src/core/*` (not `wire/`), `src/core/radio/**`, `src/capi/{capi.cpp,context.hpp}`, `src/port/sim/**` and `src/port/idf/**` except `*_store.*`, `tools/meshsim/**`, `tests/native/test_runtime*.cpp` | skeleton | IDF radio/owner/worker/OwnerCall tasks (4-target build); peer registry 16+3+1 with transient reservation; single-TX manager (token, watchdog 1000 ms → unknown, isolation); meshsim `inject`, callback-delay, topology file, trace; R08-sim (100 churn cycles, no leak, full → NO_CAPACITY), R10, D10-sim (20/100/500 ms callback delay, early completion never credited to the next frame), idle owner 0 wakes (ME05 sim part), BUSY/NO_MEM never counted as loss |
| S4 STORE | T05 | `src/store/**`, `src/port/{sim,idf}/*_store.*`, `tests/native/test_store*.cpp` | skeleton | sealed 2-slot record + marker (D19), monotone generation, quarantine on higher-generation evidence, boot incarnation persisted before use, journal (CRC/len/seq, segment erase, 20 ms batch, full → NO_CAPACITY, ACKed records never dropped); sim cut injection at the 7 POWER-* boundaries for record commit and journal append (each → only the allowed state); read error ≠ unprovisioned |

### Wave 2 — identity and state
| Slice | T | Owns | Deps | Acceptance |
|---|---|---|---|---|
| S5 IDENTITY+LINK | T06 + link sessions | `src/core/member/{credentials,records}.*`, `src/core/link/**`, `tools/lmfleet/` (test-only issuer), `src/port/sim/sim_provision.*`, `tools/meshsim/cmd_provision.cpp` | S1–S4 | DeviceCredential/RootDelegation/AssignmentTicket/MemberCredential/ExpectedSet/Revoke codecs + checks; link RX path (header→SID→AEAD→replay commit→dispatch) and TX seal; EDHOC purpose 1 + SESSION_BIND between two provisioned ACTIVE sim nodes; S02, S03-sim, S07, S10 (link rotation), LP13-sim, S05 link part (old SID/ciphertext after reboot rejected) |
| S6 ROUTE-MODEL | T08 logic | `src/core/route/**` (validation, cache, score), `src/root/topology.*`, `tests/native/test_route*.cpp` | S1 | forwarding checks of docs/04 §4; integer score/ETX vectors (docs/04 §6); root tree with cycle-free approval, depth ≤ 20, LCA paths ≤ 40, canonical path, path_revision; R03 (seeded model, counterexample logging), R04 |
| S7 HOST-CORE | T12 (no serial) | `host/leanmesh_host/{main,storage,auth,settings}.py`, `host/leanmesh_host/{api,db,events}/`, `host/tests/{unit,integration}/test_host_*.py` | skeleton | all OpenAPI endpoints' shapes (responses validated against `api/openapi.json`), SEMANTICS.md rules (u63 strings, hex ids, strict base64, LATEST/deadline rules), epochs, idempotency + canonical hash (409), operations HOST_COMMITTED only after commit, outbox, events/cursor/SSE, consumer ACK, lifecycle list, capacity/protected events; H01, H02, H05, H06, H07, Q03, Q02 host part |

### Wave 3 — first end-to-end paths
| Slice | T | Owns | Deps | Acceptance |
|---|---|---|---|---|
| S8 JOIN | T07 | `src/core/member/{join,membership}.*`, `src/root/ledger.*`, `src/capi/capi_membership.cpp` | S5 | 1-hop preapproved Join without Host in sim: both sides commit (PREPARE→STORED→COMMIT→ACTIVE); resume, leave DRAIN/IMMEDIATE; J05-sim, J06, J07, LC06, S05, M06, R09, POWER-* for join boundaries (sim) |
| S9 DELIVERY | T09 | `src/core/delivery/**` (not `fragment.*`), `src/capi/capi_send.cpp` | S5 (+S6 for multi-hop) | end sessions (purpose 2), E2E records, intent_hash, HOP_ACK + link retry/RTO, E2E rounds, receipts, APP_APPLIED, dedup cache, deadlines, durable journal; D01, D03, D04, D06, D02-sim, S04 (no re-apply), Q02 device part, D10 (HOP_ACK before TX callback) |
| S10 USB-SERIAL | T11 | `src/serial/**` (not `bridge.*`), `src/hostnative/**`, `host/leanmesh_host/serial/`, `tools/meshsim/cmd_serial.cpp` | S2, S3, S5 | COBS/18 B header/CRC32/8230 cap + resync, HELLO→EDHOC(3)→ACTIVE, credits + reserved control lane, PING, D6 pairing; E2E host↔meshsim reaches ACTIVE and `/v1/status.root_connected=true`; S09-sim, H03-sim (reset/replug via meshsim, results of old session not applied) |

### Wave 4 — multi-hop and the full Host path
| Slice | T | Owns | Deps | Acceptance |
|---|---|---|---|---|
| S11 MESH | T08 integration + T13 | `src/core/route/` flows, `src/core/member/discovery.*`, `src/root/{routes,expected}.*` | S6, S8, S9 | REGISTER/LEASE/READY/QUERY, repair, listen-first, hints, proxy, expected revision; R01-sim (21 nodes/20 hops), R02-sim (41 nodes/40 hops), R05, R06-sim, J01-sim (19-hop proxy), J02, J03, R07-sim (20 full power cycles) |
| S12 FRAGMENT | T10 | `src/core/delivery/fragment.*` | S9 | 16 B quanta, bitmap kind 5, slots/timeouts, object 4096 opt-in, control objects > 1 frame; D07-sim, D08-sim, D09 |
| S13 HOST-BRIDGE | T12 serial part | `src/serial/bridge.*`, `host/leanmesh_host/bridge/`, `host/tests/e2e/test_bridge*.py` | S7, S9, S10 | methods 1–15; outbox/inbox/HOST_STORE_ACK/EVENT_ACK; crash reconciliation by GET_MESSAGE; E2E POST /v1/messages → sim node → evidence; node→Host durable commit before ACK; H04, J04, Q02 E2E, docs/11 §4 INDETERMINATE |
| S14 SCHED | T15 | `src/core/sched/**` | S9 | DRR 4:8:4:1, 20 %/100 ms control reserve, airtime tokens, admission limits (device + host 429), LATEST coalescing; Q01, D05, S08-sim (owner progress under join storm) |

### Wave 5 — control plane, power, lifecycle
| Slice | T | Owns | Deps | Acceptance |
|---|---|---|---|---|
| S15 GROUP | T16, T27 | `src/core/group/**`, `src/root/groups.*`, `src/capi/capi_group.cpp`, host targets endpoint | S12, S14 | GroupSnapshotV2 pages/token/hash, per-target results, cancel; D11-sim, D12, GS01–GS03, GS07–GS11 |
| S16 POWER | T18, T25 | `src/core/power/**`, `src/capi/capi_power.cpp`, PM lock code in `src/port/idf/` | S9, S11 | poll/grant, mailbox from TX pool, episodes/budgets, ticket race, session retention (power_golden cases), offline budget; P01, P02-sim, P03, LP01, LP03–LP17, LP20 (sim), GS04–GS06, GS12 |
| S17 CHANNEL | T17 | `src/core/channel/**`, `src/root/channel_coordinator.*` | S4, S11, S14 | time bounds, survey (sim per-channel loss), plan PREPARE/COMMIT/beacon, freeze, rollback by higher epoch, persisted states; C02, C03, C06, C07, C12, C04/C05/C08–C11 sim, LP15, LP16 |
| S18 LIFECYCLE | T14, T26 | `src/core/member/transfer.*`, `src/root/lifecycle.*`, host lifecycle endpoints | S8, S13 | revocation, transfer A→B→A, commissioning window, root handover, reset; M01–M05 (sim), S06-sim, LC01–LC11 (sim) |

### Wave 6 — closure
| Slice | T | Owns | Deps | Acceptance |
|---|---|---|---|---|
| S19 DIAG+BUDGET | T19, T23 sw, T28 sw | `src/core/diag/**`, OTA manifest check, `scripts/budget_report.py` (exists since ARCH-D10: extend it), `scripts/scenario_coverage.py` | all | diagnostics/capabilities with validity bits; O02; budget report vs docs/16 (PSA peak and per-SoC map diff added to the existing report); coverage report; K06; B01 |
| S20 E2E-HARDENING | — | `host/tests/e2e/`, `tests/native/test_model*.cpp`, CI sanitizer job | all | full-stack 21-node E2E via Host, power-cut matrix across join/transfer/channel/journal, 64-node LC02-sim, LC12 (two non-KG apps), seeded property tests, ASan/UBSan (`-DLM_SANITIZE=ON`) green |

Shared files (additive edits only, re-read before editing): `src/core/engine.{hpp,cpp}` (`[SLICE]`
places), `JobOwner` in `src/core/jobs.hpp`, `CommandKind` in `src/core/command.hpp`, the command
table in `tools/meshsim/control.cpp`, `tests/native/CMakeLists.txt` (one `lm_add_test` line),
`host/leanmesh_host/main.py` (router includes). Spec files (`protocol/`, `api/`, `config/`,
`db/`, `docs/01–23`, `tests/*.json`) change only with orchestrator approval and together with every
user of the changed value.

## 12. Not verified by the skeleton

No feature slice exists: no link/route/join/delivery behaviour, no serial session, no radio
bring-up through the SDK, no measured RAM/CPU/energy. The IDF builds are compile/link only.
The CI workflow has not been executed on GitHub runners (the image digest was checked on Docker
Hub). EDHOC independent interop (D1c) and PSA thread safety on IDF (D16) are open.

## 13. Slice decisions (wave 1)
Decision ids from here on are slice-prefixed (`S5-D1` …) to avoid collisions. Condensed; the code is authoritative.
- **S1 WIRE**: DISCOVERY/JOIN_PROXY plain with SID 0; EDHOC plain iff SID 0; DATA/HOP_ACK/ROUTE/CONTROL/POWER need SID≠0, AEAD, counter≠0. Route `budget == path_len - next_index`; addresses 0/0xFFFF invalid. `app_port` 1..65534 for DATA. Fragment ≤94 B payload, Small class total ≤512. Serial: HELLO/EDHOC untagged ≤1024 B, others +16 B tag, cap 8230, CRC BE. Undefined version/kind/type → UNSUPPORTED; signed-type/COSE mismatch → AUTH_REJECTED; else BAD_FRAME. `wire/control.*` = COSE structure only; signatures live in `src/security/cose_sign1.*`. Known fixture bug: `scripts/wire_fixture.decode` accepts bool map keys (asserted in the differential test).
- **S2 CRYPTO**: `RecordSession::open()` never advances the replay window; caller calls `accept()` after its own checks; tag-valid duplicate → `Replay`/`Duplicate` (re-ACK, never re-apply). AES keys imported per call (no PSA slot held). Key lifetime: 2^24 counter enforced here; the 1 h clock is the session owner's job. Peer CCS set (≤2) given at `HandshakeSlot::begin()`; unknown kid aborts. Critical EAD rejected; no EDHOC error messages (abort + peer timeout). Local PSA faults → NoCapacity/RecoveryRequired, never blamed on peer. Worker stack peak 9.3 KB native; PSA heap peak ~5 KB. `CONFIG_MBEDTLS_THREADING_C` required.
- **S3 RUNTIME**: RF profile is Kconfig, default unapproved → `lm_start` returns RF_PROFILE_UNAPPROVED. Unknown TX result → radio restart with new driver generation, 3 tries @1 s, then FAULT; on IDF an overdue (≥1000 ms) callback forces controlled reboot. Separate RX and TX-done rings. `lm_stop` synchronous when nothing to drain; second `lm_start` → CONFLICT. Owner stack 4 KB, worker 8 KB (worker must fit the 9.3 KB EDHOC peak → revisit), RX ring 16.
- **S4 STORE**: sealed record = 2 slots + marker (record|0x8000), 2 writes/commit; payload ≤512 B per record id. Journal = `Put(id,data)`/`Retire(id)` with live index, compaction by copy-forward; one `apply()` = one flash write; the 20 ms batch window is the caller's. Full → NO_CAPACITY. IDF `init()` never formats. NVS encryption not enabled (key-custody decision pending). Sim nodes must call `SimStore::power_restore()` after a cut.
- **S7 HOST-CORE**: bridge plug point = `app.state.hub` (`set_root`, `write`/`read`, `outbox_ready`), `db/outbox.py` (`claim` commits `external_write_possible=1` before sending; `record`, `pending_reconcile`, `cancel_requests`, `release_unwritten`), `events/journal.ingest` (HOST_STORE_ACK only after it returns; 507 → no ACK), `db/mirror.py` writers. Host does not verify fleet signatures (root does → REJECTED evidence). Without root: capability-gated controls 503 UNSUPPORTED, power/channel 503/404 ROOT_UNAVAILABLE. Rollback detection via DB floor sidecar. Host 429 rate limiting left to S14.
- **S7 update (review fixes)**: signatures changed — `outbox.release_unwritten(conn, cfg, op_id)`, `ops.open_epoch(conn, cfg, …)`, `ops.accept(conn, cfg, sub, precheck)`, `journal.ack(conn, cfg, …)`. `outbox.record()` rejects a mismatched message_id with 409 and rolls back; evidence dedup by equality, history capped (64+16); per-op event quota `op_event_reserve`=4; transitions via explicit `_NEXT` graph; bridge evidence published verbatim in `HOST_RECORDED` events; central byte budget `db/budget.room()`; consumers leased (7 d) and capped (8/principal, 64 global).
- **S5 IDENTITY+LINK**: see S5-D1..D12 in the S5 sources. Credentials exchanged before EDHOC in bootstrap carriers (object_kind 1..6, 160 B fragments); BIND/ACK sealed under the new key; glare → lower DeviceId initiates; old session RX-only 10 s after rotation; rotation at 50/55 min or 2^24−2^20 records, hard 1 h; single exchange slot + rate gate; identity load fail-closed; unknown SID silent drop; authentic duplicates reach the RX sink flagged `duplicate`. Worker stack is 10 KiB (measured EDHOC step 4856 B, calibrated) — supersedes the S3 note.
- **RAM budget warning (after wave 2)**: superseded by [ADR-002](../decisions/ADR-002-budget-status.md) (measured status after wave 3, the consolidation pass and the per-slice RAM/SLOC allocations of S11-S20). Every later slice borrows from existing pools (TX frame pool, message pool, exchange scratch, record job memory) instead of adding per-feature buffers and reports `scripts/budget_report.py` before/after.
- **FIX1 (external review, security/store/runtime)**: `RecordSession`/`RecordKeys` are move-only with zeroising destructors; `RecordSession::install(RecordKeys&&)` returns `Status` and is Conflict while active (FIX1-D1/2/19). IDF owner calls wait on a per-call stack `StaticSemaphore_t`, no notification index (D3). A radio whose `stop()` fails leaves the engine Faulted (never Stopped), `lm_destroy` stays Busy and `lm_stop` retries (D5). Boot incarnation: a missing counter is virgin only while no identity record exists; provisioning MUST commit `rec::boot_incarnation` (u64be 0) before `rec::identity`, otherwise RecoveryRequired (D9). Oversized slot/marker = corruption → RecoveryRequired, never NotFound (D10). Journal reclaim validates header/id/seq/len/CRC against `JournalLive` before re-sealing, fails with the source untouched (D11). `HandshakeSlot::wipe()` propagates a failed PSA destroy (`teardown_failed()`, retried by `cancel()`/`begin()`); the C glue stashes handles libedhoc forgets after a failed destroy and retries them in `lm_edhoc_session_destroy` (now `int`) (D20). One-shot AES keys are destroyed (one retry) before seal/open may return Ok (D21). Every local PSA hash failure calls `note()` (D22). `sign1_create` requires `kid == DeviceId(key)` (InvalidArgument; costs one public-key derivation per signed control object) (D23). `Pool` retires a slot at generation UINT32_MAX instead of wrapping (D25).
- **ARCH consolidation (after wave 3, [ADR-002](../decisions/ADR-002-budget-status.md))**:
  ARCH-D1 one handshake engine: `delivery::EndExchange` is folded into `link::Exchange` (`Mode::End`), so link, join and end sessions share one exchange slot, one `HandshakeSlot` and one credential buffer; `JobOwner::EndExchange` is gone (completions come as `JobOwner::Link`). A send that finds the slot taken by any mode waits (`Delivery::slot_wait_`) and is kicked when it frees; `Delivery::end_stats()` is `link::EndStats` (+`cred_time_uncertain`); `Delivery::exchange()` returns the link exchange. Wire unchanged.
  ARCH-D2 `HandshakeSlot` keeps its CCS inputs only in the EDHOC session (no second copy).
  ARCH-D3 one in-order chunk format, `member::JoinChunk` (tag u8 | total u16 | offset u16 | bytes <= 160): JOIN_ONLY control objects (S8-D4) and the routed handshake carrier (S9-D2) use the same codec (byte-identical to before). The 1-hop bootstrap carrier keeps its docs/09 §8 layout. S12 adds only the spec's FRAGMENT/TRANSFER_BITMAP for authenticated end objects; S11 proxy legs carry pre-authentication and JOIN_ONLY objects as `JoinChunk`, never a third format.
  ARCH-D4 one route table: `route::PathCache` (address- and DeviceId-keyed) replaces `Delivery::RouteEntry`; `EndSession::reply`/`born` are gone: the reverse of every authenticated route is `learn()`ed (never replacing an entry of the same term that is at least as new, never shortening its lifetime) and receipts use `route_for()`.
  ARCH-D5 `SpscRing` takes any capacity (indices over [0, 2N)); the IDF RX ring is exactly `rx_frames + 2`.
  ARCH-D6 USB records are decrypted in place in the 8230 B decode buffer (`RecordSession::open_in_place`: multi-part PSA AES-GCM through a 64 B bounce buffer, because `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS` forbids overlapping in/out; unauthenticated plaintext is zeroed on failure); `UsbLink::plain_` is gone.
  ARCH-D7 record ids folded into `store::rec`: `assignment_ticket = 12` (was 0x40, S8-D5) and `paired_host = 13` (was 0x40, S10-D2: the two collided). The identity load job reads the paired Host on root-capable builds (`LocalIdentity::paired_host[_status]()`, its own status: a pairing problem never fails the identity); `RootUsb` has no Flash job or record buffers of its own and takes the verified delegation from the identity.
  ARCH-D8 `store::Journal` stages entries in memory its owner lends (`>= k_journal_min_scratch`, 532 B; its size bounds a batch); `Durable` lends its boot job's record scratch.
  ARCH-D9 `Engine::execute()` sets `step_time()` too: hooks and completions reached from a command see the command's time.
  ARCH-D10 `scripts/budget_report.py` + `tools/budget_probe` (sizeof per profile via `nm -S`, SoC compiler through an IDF build's compile command, map static DRAM, image diff, SLOC); `scripts/build_targets.sh --profile LEAF|RELAY|ROOT`; CI runs the report (not a gate) and builds `example_node` ROOT for every SoC.
- **S14 SCHED** (`src/core/sched/**`, `radio/tx_pool.hpp`, `delivery/delivery_sched.cpp`, `host/leanmesh_host/api/limits.py`; consolidations P1/P7/P9 of ADR-002):
  S14-D1 the queue of the scheduler is the TX pool: a queued frame is a pool slot with a class tag (`sched::Class` Control/Urgent/Normal/Bulk = the order of `defaults.json scheduler.drr_weights` 4:8:4:1). The class comes from the priority bits of the end-record header (`delivery::record_class`), which a relay reads without a key; receipts, bitmaps, handshake carriers and bind records are sent as Priority::Control. A neighbour can label everything CONTROL: it then gets the CONTROL DRR share and the 20 % entitlement, the per-peer cap and the S8/S9 rate gates bound the rest (no escalation beyond that).
  S14-D2 one decision function, `Scheduler::pick(head_bytes[4], now)`: (1) CONTROL is entitled to 20 ms of airtime in every 100 ms window (20 %, S14 reading of docs/08 §8): until it used that much, a ready control frame goes next whatever the bucket says; (2) after two URGENT frames in a row a ready control frame goes next if the bucket allows it; (3) otherwise DRR over the classes the bucket allows (quantum = weight * 2.5 ms of estimated airtime, deficit per class, idle class keeps no credit). No timer of its own: a blocked pick returns the time the bucket allows the cheapest ready frame and `HopTx` arms `retry_at_` with it.
  S14-D3 airtime bucket: 300 ms/s, burst 600 ms, URGENT and CONTROL may borrow 100 ms (`urgent_debt_ms`), floor -burst. `Engine::transmit(..., cls, queued)` is the one accounting point: data frames (scheduled, gated), HOP_ACKs and every handshake/join/discovery frame (charged, never gated: an ACK frees the sender's buffer, a refused handshake fragment only wastes the peer's time; the floor bounds what they can take from the data classes). The airtime of a frame is an estimate: (bytes + 43) * 32 us + 600 us; both constants are unmeasured until the RF qualification.
  S14-D4 admission has two levels. TX pool (`TxPool::limit`): BULK may use half of the slots, NORMAL five eighths, URGENT all but two, CONTROL all but one; borrowers (HOP_ACK seal buffer, build frames, staged objects) take any free slot, so the last slot is never held by a queued frame (two full pools cannot wait for each other's ACKs); one next hop holds at most three quarters of the slots for non-control frames (a dead peer cannot pin the pool). Operation slots (`Delivery::admit_send`): BULK may hold half of the `app_messages` slots. Every local refusal is counted under the class of the request (`sched::Stats`), and a NoCapacity/Busy `Reply` carries `retry_after_ms` (500, unmeasured) and `queue_depth`; `lm_send` still returns only the status (C ABI unchanged), diagnostics (S19) expose the counters.
  S14-D5 LATEST: key = (destination, app_port, coalesce_key) (the device has one principal and one domain). LATEST is BEST_EFFORT + VOLATILE only and FIFO with a non-zero key is INVALID_ARGUMENT (both were UNSUPPORTED before; D06 test updated). Only a send that never left the node is replaced (`left_node()` false: no `sent` evidence and no frame handed to the radio); it ends SUPERSEDED before the new one allocates (nothing can fail for capacity after that) and its operation event carries the id of the replacing operation as an 8-byte big-endian payload (`superseded_by`). The Host coalesces on its own (S7) and hands the root FIFO sends.
  S14-D6 Host 429: token buckets, per principal 20 req/s burst 40 and whole service 100 req/s burst 100, charged in `require()` after authentication (unauthenticated requests never spend anything); a principal over its own rate is refused without touching the global bucket (fairness); the body is the OpenAPI Error with `retry_after_ms` and `details.scope` (`principal`|`global`). An exact idempotent replay is a request and is charged, but it never creates RF work (Q02). `LEANMESH_PRINCIPAL_RPS/_BURST`, `LEANMESH_GLOBAL_RPS/_BURST` override, 0 disables a bucket (the S7 tests that send hundreds of requests in a burst run with the limits off).
  S14-D7 P7: a pool slot is 288 B = 32 B of metadata + `FrameBuf` (250 B + length). Metadata: one `at` (not-before while Ready, RTO while WaitAck), 16-bit FIFO `order` (wrap-safe), 16-bit `handoff_ms` (RTT samples only), flag bits; `SealedFrame` is an alias of `FrameBuf` and reads the link counter (nonce) from the header instead of storing it.
  S14-D8 P9: one frame pool (`Engine::frames()`). Borrowed with a generation handle and RAII `Lease`: the HOP_ACK seal buffer (per ACK), the build frame of every outgoing routed record (`build_and_send`: route header + path + record; receipts, bitmaps and receipt fragments seal straight into it, a receipt's plaintext is 96 B on the stack, fragments of a send are sealed into the send's own `Active::record`), the carrier record of the end exchange. Held while active: the exchange's staged object (`Exchange::stage()` returns Status, never truncates; released at `finish_idle`) and the join pipe's staging frame (released at `reset()`). `HopTx::clear()` leaves borrowed frames to their owners, `Engine::stop_radio` sweeps the pool after every owner returned its frames. S16 mailboxes borrow the same way.
  S14-D9 P1: the dedup cache splits into `InEntry` (136 B: key, hash, outcome, result, receipt sequence, expiry, journal slot; enough to answer a duplicate) and `InLive` (48 B x (`app_messages` + 2): payload buffer, journal versions, owed event, owed receipt, term/port/assignment). A record holds a live slot only while it has work to do (`settle()` gives it back): payload held, journal commit in flight, MESSAGE event owed, APPLIED result owed. Consequences: an arrival needs a free live slot (else BUSY, checked before a finished record is recycled), and at most `k_in_live` messages can be held or owe a result at once (was: `durable_pending` results); recovery raises FAULT NoCapacity if the journal holds more (fail closed).
  S14-D10 meshsim: `flood <node> <dest> <count> <bulk|normal|urgent> <bytes> <term> <expires> [latest_key]` and `sched <node>`.
- **S11 MESH (T08 integration + T13)**: `route::Mesh` (node and root state machine), `root::Routes` (tree service on the root), `member::Discovery` (listen-first policy shared by joiner and member), `member::Proxy` (join tunnel), P2 and P6 of ADR-002.
  S11-D1 The end-to-end mesh records (REGISTER, LEASE, READY, QUERY, ANSWER) are a compact fixed binary form (first byte 0xE1..0xE5, `route/mesh_wire.*`) in CONTROL end records of the node<->root end session, not the CBOR bodies of control types 13..15: those are 200+ B and cannot cross a hop in the single frame that exists before S12. READY (no control type exists for it) is its own record and doubles as the 60 s lease renewal. PROBE/hello is the spec's control-body type 16 in a link-AEAD ROUTE frame. When S12 carries CBOR control objects, both can coexist (a CBOR control-body starts with 0x87).
  S11-D2 Delivery plug points (`delivery_mesh.cpp`, `delivery::MeshHooks`): `send_control`, `send_routed`, `start_session`, `has_session`; hooks for control records, tunnel carriers, session completion, hop results, `route_of` (own root path / root topology first; `Busy` = known destination, no usable path while a repair runs, so sends wait instead of burning E2E rounds) and `want_route`. `end_sid` 0xFFFFFFFE is reserved for tunnel carriers next to 0xFFFFFFFF.
  S11-D3 Join proxy: the device talks to a relay as to a root; the relay wraps each of its frames into routed tunnel records (`mac6 | JoinChunk`, the ARCH-D3 codec, one chunk in flight), the root feeds them to its link layer as if they came from a radio and answers through the same tunnel (`Engine::transmit` intercepts a proxied MAC). One outgoing and one incoming 250 B frame per node, `join_slots` MACs, 420 s idle life; a leaf build keeps no buffers. The joiner learns depth and expected revision from the offer (v2 body) and paces itself (`LinkPolicy::tx_gap` 60 ms, RTO 1 s + 200 ms x depth); the root paces its frames the same way. The tunnel adds no authority: EDHOC/AEAD are joiner<->root. A tunnel record can never capture the MAC of a real neighbour.
  S11-D4 Hints (beacons: DISCOVERY frames; offers/hellos: JOIN_PROXY carriers) are unauthenticated lookup data. The optional DiscoveryScopeKey HMAC is not implemented (no such key exists in the credential set). A false hint costs one bounded full handshake (J03). The channel sweep of a search ("許可channel2周") belongs to S17: discovery runs on the current channel.
  S11-D5 Paths: a node keeps its approved root path (max 21 entries) and stitches source routes to other nodes from the root's ANSWER (root->dest path) with `route::stitch_route` (the same function the root's `Topology::route_between` uses). The root sends on paths derived from the tree; its route cache (8 entries) only holds reverse routes learned from traffic.
  S11-D6 NOT_EXPECTED (`NotFound` refusal in preapproved mode) is a hold, not a rejection: the operation stays pending, the device reports one MEMBERSHIP event, stays silent for 30 s (60 s after the second refusal; never below the 30 s full-handshake gate towards the root, docs/06 §8) and asks again; an offer with a higher expected revision ends the hold. A default budget is extended by the hold, an explicit one is kept (then EXPIRED); a new `lm_join` clears all suppression (no fixed ban). The S8 test J02 expectation changed accordingly.
  S11-D7 `root_term` is still the term of the MemberCredential (persistent per-boot increase belongs to the time/lifecycle slices; `Topology::begin_term` exists). The ledger stamps member leases with the root's monotonic clock; the sim tests give every node that same reading as root time bound.
  S11-D8 (P2) `Neighbor::prev` is gone: replaced sessions of all neighbours share two receive-only grace slots (10 s), the one that ends first is dropped when both are busy.
  S11-D9 (P6) `root::Topology` has no DeviceId and no generations: it is a routing table by short address (plus a 32-bit generation tag that resets a slot). Identity comes from the ledger entry of the address, or, for a member the ledger has no entry for (factory-provisioned, S8-D7), from the verified MemberCredential of its end session (`Routes::identify`); a ledger entry may only deny. The 64-path cache of the root became 8.
  S11-D10 Sim/bench: `NodeOptions::mesh` (default off) starts the mesh module by itself; earlier slices' tests drive links by hand and keep it off; `meshsim --mesh`, command `mesh <node>`. REGISTER sequences are `boot incarnation (16 bit) << 16 | counter`, monotone across reboots (a wrap after 65,536 boots of one node needs a root restart). Repair: 3 targeted RF failures (3 attempts without HOP_ACK to the parent, or 3 MacFailed probes) or silence of 3 x 32 s, spares linked and probed, unanswered probes end a stale link session, unanswered REGISTER/READY rounds mark the end session suspect (a restarted root), the root pushes new paths to the subtree of a moved node.
