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
- **FIX2 (external review, delivery/serial/host; this worker)**: FIX2-D1 message identity is (origin DeviceId, origin assignment_generation, MessageId) everywhere at the destination: `InEntry::assignment` (moved from `InLive`, +8 B per receipt entry) is compared by the receive cache, `mark_resend`, `lm_get_message`, `lm_report_application_result`, the MESSAGE event lookups, `HostStoreAckRequest` and the bridge ring; the journal record already stored it. The same MessageId+intent from another assignment is a new message. FIX2-D6 `store::k_journal_max_payload` and `store::k_max_payload` are 672 (145 B fixed fields of a received durable record + 512 B); `k_durable_payload_max` (360) is gone, durable messages may be 512 B; static_asserts in delivery_durable.cpp/durable.hpp. Cost: every `RecordJob` grows by 320 B (see budget). FIX2-D9 Host: EVENT_ACK never covers an open event: every root event seen (or dropped on queue overflow) stays open until its handling succeeded (a MESSAGE until HOST_STORE_ACK), and the ACK sent is min(highest finished, lowest open - 1). A permanently failing event therefore blocks later ACKs (the root keeps resending) instead of being settled silently. FIX2-D10 Host: a bare OK to JOIN_DECIDE records ROOT_ACCEPTED / WAITING_RECEIPT only; FINAL comes from GET_REQUEST (`join_verdict`): approval = ledger state >= Prepared, rejection = no longer pending AND the root said OK, still pending without OK = INDETERMINATE, no durable state within 180 s = INDETERMINATE. The Host never sends a decision twice. FIX2-D12 Host: `join:<op>` (request id, device, approve, deadline) is committed in the claim transaction as the reconciliation key of a join decision; `_reconcile` uses GET_MESSAGE for messages and GET_REQUEST for join decisions, controls without a key end INDETERMINATE explicitly, and an unfinished pass re-arms itself every 2 s (an interrupted pass no longer clears the flag). FIX2-D13 `SerialLink.stop()` destroys the native state only after the thread ended (else it is kept and False returned); every waiting request gets its own SessionChanged(sent=...). FIX2-D14 libleanmesh_host ABI 2: `lmh_usb_peek_tx` + `lmh_usb_consume_tx` replace `take_tx`; the thread writes with a non-blocking os.write and consumes exactly what the OS accepted, waits on writability for the rest, and treats 2 s without progress as a lost port.
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
- **S15 GROUP (T16, T27)** (`src/core/group/**`, `src/root/groups.*`, `src/capi/capi_group.cpp`, `delivery/delivery_group.cpp`, `host/leanmesh_host/bridge/groups.py`):
  S15-D1 The origin fans out, on every role: `group::Fanout` fixes a snapshot, reserves a block of MessageIds (`total x 4` sequences of the boot; target i, dispatch attempt a = `(incarnation, base + a*total + i)`, so an id is arithmetic, not state) and turns each target into an ordinary `Delivery` send (`send_child`, idempotent per MessageId) - at most `min(4, app_messages/2)` in flight, round-robin. A Host group send is expanded by the root (it is the origin); a member origin expands for itself and the root never sees the body (D12). The destination needs nothing: a target is an ordinary unicast, it cannot and need not know it is a group member. The payload is one message-pool buffer of the operation (never per target); children copy it only while in flight.
  S15-D2 `protocol/serial.cddl` SEND has only a DeviceId destination. A group is the 32 byte marker `12 x 0 | group_id u32be | revision u64be | 8 x 0` (`group::group_dest`, mirrored in `bridge/groups.py`); the root recomputes the Host's `intent_hash` over that marker as the target. Spec files unchanged; an explicit group destination in the next serial.cddl revision would replace it. GROUP_SNAPSHOT (method 8) stays UNSUPPORTED (the Host never fans out); GROUP_SET (14) and GROUP_TARGETS (15) are implemented (a zero token in 15 names the operation's own snapshot: the Host learns the token from the first page).
  S15-D3 Snapshot pages: request = control 33 (session AEAD, page 0 / token nil opens a snapshot, later pages name the token), reply = control 32 as a COSE_Sign1 signed by the root (kid = root DeviceId, request id echoed), 16 targets per page (one control page, <= 1024 B for generations below 2^16), pages 0..3. `snapshot_hash` = SHA-256 of the deterministic CBOR `[domain, group_id, revision, token, origin, [[device, assignment, membership] ...]]` (sorted by DeviceId); the origin recomputes it over the whole set and refuses a mismatch (AUTH_REJECTED). The root keeps a snapshot 120 s, one per origin, at most `k_ops - 1` served at once (its own operations keep a slot); the token is bound to origin/group/revision. There is no refusal message on the wire: an unknown group/revision, a full pool or a busy worker is silence, and the origin ends REJECTED / ROOT_UNAVAILABLE after 3 requests (3 s each, same request id). The sign/verify job (JobOwner::Group = 15) uses the exchange's lent 1 KiB scratch, so a handshake gets Busy meanwhile.
  S15-D4 Compact state: a `Target` is 16 B (generations stored as 32 bit - a larger one makes the snapshot UNSUPPORTED - plus a 16 bit DeviceId tag). A root-origin operation and every snapshot the root serves refer to members by ledger slot (DeviceId, address and generations are read from the ledger; a slot given to another device since is detected by the tag and refuses the page/target); a member origin keeps the DeviceIds of its one snapshot in `Fanout::ids_` (2 KiB, absent from a real ROOT image). The origin itself may be a target: that target is REJECTED (no loopback).
  S15-D5 The group registry (`root::Groups`, 8 groups x 64 ledger slots) is RAM only: the Host holds the definitions and sets them again after a root restart (revisions start over). `lm_group_set` needs the root role, ACTIVE members and the current revision (`expected` = 0 for a new group); the new revision is `expected + 1`. A snapshot names the revision it was taken at; a send with another revision is CONFLICT at the root and silence (ROOT_UNAVAILABLE at the origin) for a member.
  S15-D6 Not built: DURABLE group sends (a compact group journal record, GS09) and LATEST group sends are UNSUPPORTED before any state exists; a group send needs a finite deadline. WAIT_WAKE is never produced (S16 is absent): every target is treated as awake.
  S15-D7 Results: exactly one current outcome per target, counts sum to `total`; the phase of a live target is its child's (WAIT_ROUTE / WAIT_AUTH / SENDING / WAIT_RECEIPT), READY before dispatch, FINAL after. A child that has not left the node after 5 s (no route or session) is withdrawn exactly (cancel before send), the target shows WAIT_ROUTE and is dispatched again with the next id of its block (4 dispatches at most); a dead target that did send ends by the E2E limits of Delivery. Dispatch checks the ledger (root origin: ACTIVE with exactly the snapshot's generations) and the end session's peer generations (`GroupHooks::gate`): a mismatch is REJECTED / TARGET_GENERATION_CHANGED, never a resend to another device. Cancel ends the unstarted targets CANCELLED_NOT_SENT; a child that already left stays open (INDETERMINATE after its round timer) and a later APPLIED still improves it (Delivery's late-receipt rule), raising `progress_revision`. Aggregate: every target has the requested evidence -> that outcome (SUBMITTED for BEST_EFFORT); every target failed alike -> that; else PARTIAL; an empty group is complete with total 0 and PARTIAL (not "all"). Children never raise application events; the operation raises OPERATION at its end (again after a late improvement) and GROUP_PROGRESS (coalesced to 500 ms).
  S15-D8 `Delivery` plug points: `set_group_hooks`, `send_child`, `probe`, `cancel_child`, `deadline_status`, `reserve_sequences`, `messages()`; `Op::group`. `sec::sha256_chunks` hashes a message given part by part. `lm_get_capabilities` now reports `GROUP_FANOUT_V2` as build, implemented and enabled on every role (qualified stays 0). The engine's control sink belongs to the fan-out (types 32/33); other control types would be dispatched there.
- **SEC (external security review of wave 4, 2026-09-29; `src/core/{member,link,route}/**`, `src/root/{ledger*,routes*}`, `src/security/edhoc/*`, `tools/lmfleet`)**:
  SEC-D1 PREPARE is no credential. JoinPrepare carries the MemberCredential COSE_Sign1 with its 64 signature bytes withheld (zero; `member::withheld_hash` = prepare-hash of exactly that form), so no verifier (the root or any ordinary member) accepts it; JoinCommit = `[prepare-hash, membership, member-signature 64 B]` is sent only after the root's ACTIVE entry is durable (`Ledger::stage_commit`; a refusal carries an empty signature). The device stores the withheld form as PREPARED, splices the signature in at activation and verifies the completed credential (worker job) before the ACTIVE commit. Peers are unchanged: the signature check they already made is the activation check. Wire change: `protocol/control.cddl` join-prepare note + join-commit, `wire/control.cpp` and `host/.../wire/control.py` shapes of type 9.
  SEC-D2 (supersedes S8-D7 and the credential fallback of S11-D9) Every root-side Link and End session, whichever side started it, needs an ACTIVE ledger entry of exactly this device, address, assignment and membership (`Ledger::link_admit` through `JoinHooks::link_admit`, asked after the credential check and again right before the session is installed); a device the ledger does not list is refused, and `Routes::identify` reads the ledger only. A committed leave closes the member's link and end sessions and removes it from the approved tree at once (`Ledger::forget_member`, `Routes::forget`; its children re-register). Bench provisioning lists members: `fleet::provision` of the root writes an ACTIVE entry for every `Network::make_node` so far (`root::encode_provisioned_member`), `fleet::register_member` / meshsim `provision` for later ones; such members need addresses 2..65 (the ledger's slots). A root that cannot decide admission (ledger not loaded yet, e.g. another owner holds the identity's record memory at boot; or lost) starts and answers no Link/End exchange (`Ledger::admission` through `JoinHooks::admission`: `connect`/`start_end` return BUSY / RECOVERY_REQUIRED, a CredI is dropped as `hs_busy_drop`): its own state is never counted as the peer's rejected credential. The root provisioning of `fleet::provision` also writes the manifest's used bits (no boot-time repair commit).
  SEC-D3 A session is authorised only while its peer's credential lease is. Link (`Neighbor::lease`) and end sessions (`EndSession::peer_lease`, one field added to the delivery struct) keep the lease; admission reads the delivery's estimate as of now (the link's own copy was only the last anchor). Provable at admission: the session's life is capped at the lease (`member::lease_local_end`: remaining time from the latest estimate less 1000 ppm and 1 ms). Unprovable (no root time yet): the session is installed but restricted: it carries SDK control (port 0: handshake carriers, the join tunnel, mesh/time control) and no application DATA in either direction (`LinkLayer::seal` TIME_UNCERTAIN; RX `RxInfo::restricted`, answered BUSY 1000 ms by the engine, window not advanced). Every new root-time estimate (`Engine::set_root_time`) re-judges all sessions (`LinkLayer::revalidate`, `Exchange::revalidate_end`): provably over closes, provable caps and lifts the restriction, unprovable restricts. MemberCredential lease renewal is not built (docs/06 §7, 10 min renewal): a 15 min lease issued at join ends its sessions when time proves it over.
  SEC-D4 Ticket consumption. The root keeps, per ledger entry, the highest assignment generation the device made ACTIVE here (`Entry::consumed`, entry record +8 B, committed with the ACTIVE entry, kept by expected pages); a ticket at or below it is CONFLICT in every mode and policy, independent of the 10-entry floor table. SEC-D4a mode 0 (bound to a nonce the device issued) is refused by the device at install and by the root (UNSUPPORTED): no API hands the device's nonce to the fleet, so its freshness cannot be judged; the missing piece is a call exporting the device's outstanding nonce (bound to the JoinRequest nonce), due with the transfer slice (S18). Mode 1 is consumed by generation at both ends (root: `consumed`; device: SEC-D8).
  SEC-D5 The root ledger is bound to its domain by a manifest (`store::rec::root_ledger`: version, domain, expected revision, used-slot bitmap, expected-set progress, `root::Manifest`). A domain root without it, with another domain's, or missing the record of a slot the manifest lists is RECOVERY_REQUIRED (FAULT event, no joins, no admissions): a lost ledger never restarts empty (docs/12 §5). Only new-network provisioning writes the first one (`sim::ProvisionInput::new_ledger_domain`; production provisioning must do the same). Entry first, used bit after (a cut between is repaired at load). No migration (pre-release): a ledger written before SEC has an 8-byte expected-revision header where the manifest belongs and loads as RECOVERY_REQUIRED; entry records grew by 8 B (SEC-D4) and JoinCommit changed shape (SEC-D1), so builds before and after SEC do not join each other.
  SEC-D7 ExpectedSet revisions are one signed set: the first page of a revision fixes its set hash and page count in the manifest; a page must have `page < pages`, carry the same set hash/count, and a page number already taken must have the same content (8-byte digest per page in the manifest); the same page again is the same answer. Before any entry changes, room for the page's new devices is counted and the page is marked pending durably; after its entries it is marked received. A failure after the pending mark is RECOVERY_REQUIRED (authorisation may have moved; the same page completes it), not an ordinary refusal. Pages still upsert entries (a revision does not delete devices it omits). Follow-up for the serial owner: the bridge maps every non-zero reason of a membership/control operation to REJECTED; RECOVERY_REQUIRED (and storage failures) must map to INDETERMINATE.
  SEC-D8 The device's leave is one commit: the membership record becomes LEFT carrying the device's own floor (assignment + 1, membership + 1). No room in the revocation-floor table is needed, so nothing can be lost for lack of it; APPLIED only once it is durable, INDETERMINATE if the commit fails. `LocalIdentity::own_floor()` is checked at ticket install and before a JoinRequest.
  SEC-D11 An authentic fresh link frame enters the replay window only after the minimum checks of docs/06 §6 (`LinkLayer::admissible`): DATA must be a routed body naming this node as the next hop of this very sender in the current term (`route::decide_forward`) with a carriable/openable end record, a HOP_ACK must parse; ROUTE/CONTROL/POWER bodies belong to their consumers. Inadmissible DATA still reaches delivery (which answers REJECTED) without moving the window; duplicates of accepted frames are re-ACKed as before.
  SEC-D15 The deepest worker job (EDHOC message_2/3) is shallower: ECDH through `psa_raw_key_agreement` into the handshake slot's context (wiped at once) instead of `psa_key_agreement`'s 1 KiB frame, ES256 over a precomputed digest (`psa_sign_hash`/`psa_verify_hash`). Measured natively: -O2 4840 -> 4344 B, -Og 4488 B, -O0 5856 -> 5600 B (the rest is libedhoc's frames and mbedtls ECDSA). `port::k_worker_stack_bytes` sizes the worker per optimisation level (10 KiB optimised, 12 KiB unoptimised) and the test asserts 2 x depth <= it.
  SEC-Da (S11-D4) The optional DiscoveryScopeKey (`store::rec::discovery_scope` = 15; 14 is S16's power policy, and `rec::k_all` with a static_assert now keeps record ids unique; 32 B, factory-provisioned, loaded with the identity; unreadable = not narrowed) tags hellos and offers (bodies hello `[3, tag8]`, offer `[4, depth, revision, tag8]`) with HMAC-SHA256(key, "LM1-DISC" || kind || hello nonce || offer fields) truncated to 8 B. A scoped root/relay answers only hellos of its scope and tags its offers; a scoped joiner follows only offers of its scope. It narrows discovery and spares handshakes; it authorises nothing (every holder of the key can tag). Mesh beacons between members are not tagged (their sessions authenticate them).
- **S16 POWER (T18, T25)** (`src/core/power/**`, `src/capi/capi_power.cpp`, `src/port/idf/idf_pm.*`, `src/port/sim/sim_pm.*`, `tools/meshsim/cmd_power.cpp`, `host/leanmesh_host/bridge/power.py`):
  S16-D1 One engine, one state (`power::Power`). WINDOWED_RX is the engine sleeping by itself (radio driver off, RAM kept, timer wake, poll, window); REPORT_ONLY is the same sleep entered by the application through prepare -> ticket -> enter. While `radio_state == Asleep` `Engine::step` does nothing but wake at its own timer (`next_deadline` is only the wake time): the 32 s hello and 60 s lease refresh cannot wake a sleeping node (LP17), and a step that starts a sleep returns before any other module runs on the stopped radio. `port::Pm` (optional in `Ports`) carries PM locks, sleep entry, wake facts and 32 retained bytes; a build without it reports the modes as not enabled and refuses non-ALWAYS_RX policies with UNSUPPORTED (never a silent fall back).
  S16-D2 PM locks are a level, recomputed after every step from what is happening (episode, public-key job, Flash job, frame on air) and handed to `Pm::set_locks(mask)` on change: a timeout, cancel or failed job that ends the activity ends the lock; no edge API exists that could leak (LP18).
  S16-D3 One episode budget: `ep_end = wake + awake_budget - shutdown_reserve`, fixed at boot/wake/policy activation. It gates new sends (`POWER_BUDGET_EXHAUSTED`; `BUSY` while a sleep is being prepared), mesh search (`search_allowed`: episode search budget and hourly offline radio budget) and new attach steps (`handshake_allowed`, an estimated 1000 ms step - unmeasured). Retries/repairs never re-grant it. Overrun (`awake + shutdown_overrun_limit`) is counted and evented, not hidden. Rotation/EDHOC of already running sessions and journal work are not gated.
  S16-D4 Ticket race: `state_generation` moves on every new authenticated DATA frame, every accepted send, every policy commit; the membership generation and "nothing in flight" are re-checked at `lm_sleep_enter`. A ticket is taken once, expires after 2000 ms, and is invalid after abort/failure. A prepare whose generation moved ends `SLEEP_TICKET_STALE` (nothing dropped).
  S16-D5 Prepare completes when the journal is committed and no frame is on the air; REQUIRE_SETTLED additionally when no send is active and the pool is empty, else `POWER_BUDGET_EXHAUSTED` at the caller's budget. Frames waiting for a HOP_ACK do not block SAVE_AND_SLEEP. Prepare/policy operation ids use bit 60 (`k_op_power`); `lm_get_operation` finds them (phase 3, outcome APPLIED/REJECTED with the status in `reason`).
  S16-D6 Session retention is `power::session_path()` (= `power_contract.session_path`) fed with facts noted at sleep entry (min of authorization and key remaining) and the wake facts of the port. Light/window wake with complete RAM, proven elapsed time below the shorter life: same sessions. Everything else: the link sessions and end sessions are dropped (fresh EDHOC, membership untouched). `peer_session_valid` is proven by the poll: two polls without GRANT -> `Mesh::parent_session_lost` drops only that parent's session and attaches again at once. Deep sleep/cold boot always start fresh; `rtc_secure_resume` stays implemented=false/enabled=false. `tests/power_golden.json` is replayed through the engine (LP08/LP09 test).
  S16-D7 Poll/grant (frame kind 8, link AEAD, direct parent only): one poll per episode to the approved parent (`Mesh::commit`/episode start), same nonce for its one retry, window fixed by the first poll. A parent keeps a `Child` (table = `neighbors / 2`, none in a LEAF build) only because of an authenticated poll: awake until the window of the first poll ends, extended by that child's own authenticated frames (`on_child_frame`) and while its link session is newer than its last poll. An entry unheard for `max(60 s, 3 x interval)` is forgotten (the child is then treated as awake again).
  S16-D8 The mailbox is the TX pool (P9): frames for a sleeping child are ordinary `Ready` frames that `HopTx::pump_once` skips (`Power::deliverable`: awake, guard, credit), counted by `mailbox_frames_per_child`/`_total` at `reserve` (CONTROL class exempt), expired by `hold = 2 x interval + window` (10 s..2 h, 60 s when unknown; forwards, receipts and mesh records only - a send's own frames end with the send), aborted when the link session they were sealed under was replaced. Parked frames spend no link attempt (RTO refund when the window closed while waiting). A full mailbox at the origin is `PEER_ASLEEP` with the send's backoff, not a 50 ms pool poll. HOP_ACK of a parked frame is HOP_ACCEPTED; nothing here is a receipt.
  S16-D9 Root view: a device tells the root its schedule in a compact mesh record (`route::Op::Power` 0xEE; 0xE6..0xED belong to S17) sent at prepare - a hint, never authority. The root keeps 24 B per member (compiled out of LEAF/RELAY), sizes a sleepy member's route lease to `2 x interval + 60 s` (base 180 s, cap 2 h, still granted per authenticated READY), refuses a send whose deadline is before the earliest possible wake with `DEADLINE_UNREACHABLE` (BOUNDED/ESTIMATED reports only; unknown never), makes the origin wait `latest wake + 20 s` before the next E2E round, and does not count next-hop refusals towards `REJECTED` for a target that sleeps by schedule. The report is delayed by up to the path transit (`round_timeout(depth)`), and the earliest bound is lowered by it.
  S16-D10 Budgets are leaky buckets in microseconds (offline radio, extra radio, extra wakes), refilled by observed time only. Boot without proven continuity starts empty and is granted its boot episode; a deep sleep whose elapsed time is proven keeps them in `Pm::retain` (RTC memory) and refills by that time. Offline backoff is exponential from `retry_min` to `retry_max` with <= 20 % jitter, advanced only by an episode that had the radio on; a WINDOWED node sleeps longer instead of being denied. `cursor` counts failed offline episodes and survives a deep sleep; it does not switch channels (S17 owns channels).
  S16-D11 Policy: `lm_power_policy_set` is CAS (`expected == revision`, new revision = expected + 1, u63 stop), validated by `power::validate` (schema ranges + power_contract rules; relay/root only ALWAYS_RX), committed as sealed record `rec::power_policy` (14) in the identity's lent `RecordJob`, applied only after the commit. Unreadable record: ALWAYS_RX defaults + FAULT event.
  S16-D12 Host: `NODE_QUERY` carries a `power` array (root-reported schedule hints); the bridge writes `node_power` and `GET /v1/nodes/{id}/power` shows only what was reported (404 before, no counters that were never reported). `RootSleepWindow` (bridge method 12) stays UNSUPPORTED.
  Not done / open: LP15/LP16 (channel + sleep) belong to S17; no explicit SESSION_REFRESH_REQUIRED message (a parked frame sealed under a replaced session is aborted and the origin sends again through the S9 rounds); MemberCredential lease renewal does not exist, so a node that sleeps past its authorization stays out of the mesh (LP12 b); GS04-06/GS12 are exercised with unicast sends and the S15 hooks (`child_asleep`, `next_wake`, `DEADLINE_UNREACHABLE`), not with a group operation.
