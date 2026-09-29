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
scripts/build_targets.sh                                          # all apps x 4 targets (wave close)
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

Acceptance for every slice also includes §0 green (native, pytest, esp32c3 IDF build; 4 targets
at wave close), no new warnings in first-party code, and a report: files, commands + real output,
scenario IDs covered (sim/host evidence), size diff of `example_node` vs baseline, `sizeof` of new
tables, unverified items, decisions.

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
| S19 DIAG+BUDGET | T19, T23 sw, T28 sw | `src/core/diag/**`, OTA manifest check, `scripts/budget_report.py`, `scripts/scenario_coverage.py` | all | diagnostics/capabilities with validity bits; O02; budget report vs docs/16 (SLOC first-party vs vendor/tests, map diff per SoC, static RAM, sizeof per profile, PSA peak); coverage report; K06; B01 |
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
- **RAM budget warning (after wave 2)**: leaf is at ≈27 KiB of the 32 KiB target (lm_context 14.7 KB, LinkLayer 10.2 KB, task stacks 14 KiB). Every later slice must borrow from existing pools (frame/TX pool, boot scratch, reassembly buffer) instead of adding per-feature buffers, and report `sizeof` deltas for LEAF/RELAY/ROOT.
