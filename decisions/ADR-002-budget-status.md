# ADR-002: Budget status after wave 3, the consolidation pass, and allocations for S11-S20

Status: Proposed. Measured 2026-09-29 on `feat/sdk-impl` HEAD `a5e9834` ("before") and on HEAD plus
the consolidation pass ("after"). Software measurements only: nothing here is a hardware result
(no heap, stack or current was measured on a SoC).

## Context

[docs/16](../docs/16-budgets.md) sets design targets that `config/profiles.json` repeats as
`ram_target_bytes`: fixed RAM (static + fixed pools + SDK task stacks; RX ring and the serial
receive buffer included) of 32 KiB leaf, 48 KiB relay, 96 KiB root, crypto peak <= 24 KiB counted
separately, SDK flash difference 256 KiB (320 KiB review line), and 16,000 first-party C/C++ SLOC for
core + idf + root/serial. After wave 3 the SDK was far over those numbers with half of the features
still missing (S11-S20). This ADR records the measured status, what the consolidation pass changed,
what stays over and why, and hard allocations for the remaining slices.

## How the numbers are measured (the same for every later slice)

`scripts/budget_report.py` (decision ARCH-D10, [IMPLEMENTATION.md §13](../docs/IMPLEMENTATION.md)):
- `sizeof` of every owner object per compile-time profile: `tools/budget_probe/probe.cpp` defines one
  array per object, `nm -S` reads the compiler's size. Native (x86-64) from the `lm_budget_probe_*`
  targets; for a SoC the probe is compiled with the compile command of an ESP-IDF build of
  `firmware/example_node` (esp32c3 below: riscv32-esp-elf GCC 15.2.0 of IDF v6.0.3, -Os).
- Static DRAM of `libleanmesh.a` (task stacks, queues, radio rings, ROOT: USB serial adapter, its task
  stack and byte ring) from the link map with `esp_idf_size`; image size against
  `build-records/T01-baseline-size.json` (empty IDF + ESP-NOW, same SoC and options).
- Fixed RAM = workspace (`lm_context`, allocated once by the application at `lm_init`) + that static
  DRAM. Not included: Wi-Fi/IDF runtime heap, the application's stacks, PSA heap (crypto peak below).
- SLOC = non-blank lines that are not only a comment. Budget set "sdk" = everything compiled into the
  firmware: `src/core/**`, `src/security`, `src/store`, `src/capi`, `src/root`, `src/serial`,
  `src/port/idf`. Native-only code (`src/port/sim`, `src/hostnative`), tools and tests are separate.

Commands: `scripts/build_targets.sh --app example_node [--profile RELAY|ROOT] esp32c3`, then
`scripts/budget_report.py --native-build <native> --idf-build <leaf build> --idf-build <relay build>
--idf-build <root build>`.

## Results

### Fixed RAM, esp32c3 (bytes)

| | LEAF before | LEAF after | RELAY before | RELAY after | ROOT before | ROOT after |
|---|---:|---:|---:|---:|---:|---:|
| workspace (`lm_context`) | 44,568 | 35,368 | 48,896 | 39,696 | 128,912 | 113,016 |
| `libleanmesh.a` static DRAM (map) | 19,520 | 17,840 | 19,520 | 18,960 | 64,372 | 52,332 |
| **fixed total** | **64,088** | **53,208** | **68,416** | **58,656** | **193,284** | **165,348** |
| target (`ram_target_bytes`) | 32,768 | 32,768 | 49,152 | 49,152 | 98,304 | 98,304 |
| over target | +31,320 | +20,440 | +19,264 | +9,504 | +94,980 | +67,044 |
| change | | -10,880 | | -9,760 | | -27,936 |

Static DRAM breakdown (all profiles): owner stack 4,096, worker stack 10,240 (2x the natively measured
EDHOC job depth, S5), radio RX ring (rx_frames + 2) x 280 B = 2,800 / 3,920 / 7,280, done ring, queues,
task control blocks; ROOT adds the USB serial adapter (25,272 after, 35,632 before), its 2,560 B task
stack and 2,048 B byte ring. Native `lm_context` (x86-64): 45,088 / 49,416 / 129,624 before,
35,792 / 40,120 / 113,640 after.

Crypto peak (separate, docs/16 "crypto scratch/peak <= 24 KiB"; native software model, unchanged by this
pass): PSA heap peak 4,992 B during a full handshake, worker stack depth of the deepest EDHOC job
4,840 B (inside the 10 KiB worker stack counted above); the one `HandshakeSlot` (3,528 B on the SoC,
4,088 before) is part of the workspace. About 8.5 KB in all: inside 24 KiB.

The "after" columns are this consolidation alone. The shared tree at the end of this pass also holds
the S13 host bridge, still in progress: with it the fixed RAM is LEAF 53,208, RELAY 58,656 and ROOT
180,348 B (ROOT static DRAM 67,332 B: the bridge adds 15,000 B, mostly an 8-slot event ring of
~870 B each, a 4,608 B response scratch and a 512 B payload copy, against the 3,000 B S13 allocation
below), the ROOT image is +231,360 B over the baseline and the sdk SLOC are 21,318 (S13: +984).

### Largest objects, esp32c3 sizeof (bytes)

| object | LEAF before | LEAF after | ROOT before | ROOT after |
|---|---:|---:|---:|---:|
| end-session exchange (`EndExchange`) | 7,520 | 0 (folded) | 7,520 | 0 (folded) |
| link exchange (now the only exchange) | 6,744 | 6,616 | 6,744 | 6,616 |
| `HandshakeSlot` inside it | 4,088 | 3,528 | 4,088 | 3,528 |
| dedup/receipt cache (receipts x 192 B) | 6,144 | 6,144 | 24,576 | 24,576 |
| end sessions (x 304 B -> 200 B) | 1,224 | 808 | 19,464 | 12,808 |
| TX frame pool (`HopTx`, tx_frames x 328 B) | 3,368 | 3,368 | 8,712 | 8,712 |
| `Durable` (journal + boot job) | 3,440 | 2,344 | 5,168 | 4,072 |
| message pool (app_messages x 512 B) | 2,048 | 2,048 | 8,192 | 8,192 |
| operation history (2 x app_messages x 208 B) | 1,664 | 1,664 | 6,656 | 6,656 |
| neighbours (x 368 B) | 3,000 | 3,000 | 5,992 | 5,992 |
| `LocalIdentity` (bundle, record job, creds) | 3,456 | 3,464 | 3,904 | 3,936 |
| root ledger (64 entries x 112 B + txns) | - | - | 11,264 | 11,264 |
| route table (path_cache x ~140 B) | ~560 | ~560 | ~9,000 | ~9,000 |
| USB serial adapter (`RootUsb`, static) | - | - | 35,632 | 25,272 |

### Flash (esp32c3 image minus the empty IDF + ESP-NOW baseline)

LEAF +182,004 -> +177,266 B, RELAY +182,008 -> +177,822 B, ROOT +224,148 -> +221,752 B: inside the
256 KiB target (vendor libedhoc/zcbor included; PSA is shared with the baseline's Wi-Fi stack).

### First-party SLOC (sdk set)

| module | before | after |
|---|---:|---:|
| src/core (top level) | 1,449 | 1,454 |
| src/core/wire | 1,426 | 1,426 |
| src/core/radio | 245 | 245 |
| src/core/link | 1,841 | 2,245 |
| src/core/member | 3,168 | 3,193 |
| src/core/route | 311 | 354 |
| src/core/delivery | 4,435 | 3,465 |
| src/security | 2,081 | 2,136 |
| src/store | 739 | 747 |
| src/capi | 360 | 360 |
| src/root | 2,042 | 2,042 |
| src/serial | 1,892 | 1,833 |
| src/port/idf | 841 | 834 |
| **total (budget 16,000)** | **20,830** | **20,334** |

Native-only 1,405, tools 2,244, native tests 8,371 -> 8,534 (new tests for the changed contracts).
Python Host 2,946 (budget 6,000).

## What changed (decisions ARCH-D1..D10, details in IMPLEMENTATION.md §13)

- ARCH-D1 one handshake engine: the end-session exchange (EDHOC purpose 2) was a second copy of the
  link exchange state machine with its own `HandshakeSlot`, 1 KiB credential buffer, staging buffers
  and job owner, although at most one P-256 job may run (docs/06 §8). It is now `Mode::End` of
  `link::Exchange`: one slot, one `HandshakeSlot`, one credential buffer for link, join and end
  sessions; only the carrier differs (1-hop bootstrap frames vs routed end records). -7.1 KB every
  profile; the two exchanges were 2,221 SLOC, the one exchange is 1,666. Consequence: a link, join and end handshake never overlap; a send that
  finds the slot taken waits and is kicked when it frees (the P-256 work was already serialised).
- ARCH-D2 `HandshakeSlot` keeps the local/peer CCS only in the EDHOC session: -560 B.
- ARCH-D3 one in-order chunk format and rule for objects sent in order (JOIN_ONLY objects and routed
  handshake carriers already had the same 5-byte header; now one codec). See "chunking" below.
- ARCH-D4 one route table: `route::PathCache` (S6, unused in production) and the delivery module's own
  `RouteEntry` table implemented the same rules twice. The delivery module now sends by `PathCache`
  (address- and DeviceId-keyed); the per-session reply path (`EndSession::reply`, 96 B) became learned
  routes in the same table. -104 B per end session (root -6.7 KB).
- ARCH-D5 RX ring sized exactly (rx_frames + 2 instead of the next power of two): leaf -1.7 KB,
  relay -0.6 KB, root -1.7 KB.
- ARCH-D6 USB records decrypted in place in the 8,230 B decode buffer (multi-part PSA AES-GCM through
  a 64 B bounce buffer; PSA forbids overlapping buffers on IDF): the 8,192 B plaintext buffer is gone.
- ARCH-D7 the identity load reads the paired-Host record (root builds); the USB adapter lost its own
  Flash job and 1.6 KB of record buffers. Bug fixed on the way: the assignment-ticket record (S8-D5)
  and the paired-Host record (S10-D2) both used record id 0x40; both are now in `store::rec`.
- ARCH-D8 the journal stages entries in the boot job's record scratch instead of its own 1,100 B.
- ARCH-D9, D10: `step_time()` also for commands; the measurement tooling above, `--profile` for the IDF
  build script, CI reports (not a gate) and builds `example_node` ROOT for all four SoCs.

## Chunking: the single mechanism S12 extends (ARCH-D3)

1. Pre-authentication and JOIN_ONLY objects move in order: `member::JoinChunk`
   (`tag u8 | total u16 | offset u16 | bytes <= 160`), one fragment in flight (window 1), the whole
   object repeated on RTO, assembled in order into a buffer the owner lends (never a reservation made
   for an unauthenticated peer, docs/09 §8). Used by JoinPipe (tag = object id, plus the ack chunk)
   and the exchange's routed carrier (tag = object kind). The 1-hop bootstrap carrier keeps its
   docs/09 §8 layout (exchange id and length fields are spec) and the same in-order rule.
2. Authenticated end objects (small messages, receipts, control objects > 1 frame) use only the
   spec's FRAGMENT record + TRANSFER_BITMAP (docs/09 §6), implemented once by S12 in
   `src/core/delivery/fragment.*`. Reassembled payloads land in the message pool (`MsgBuf`), not in a
   second per-slot payload buffer.
3. S11's join proxy carries pre-authentication and JOIN_ONLY objects as `JoinChunk` on both legs
   (1-hop JOIN_PROXY and the proxy's member route); no third format and no second in-order assembler.

## What stays over budget, why, and the plan

LEAF is 20.4 KB over 32 KiB. 17.8 KB is platform (task stacks 14.3 KB, RX ring 2.8 KB); the rest is
dominated by the capacities of `profiles.json` at their per-entry cost (32 receipts x 192 B, 8 TX
frames x 328 B, 4 x 512 B messages, 8 neighbours x 368 B), one handshake (6.6 KB) and the device's
credentials (3.5 KB). ROOT is 67 KB over 96 KiB for the same reasons at root capacities (128
receipts, 64 end sessions, 64 routes, 64 ledger entries, 16 messages, 24 TX/RX frames) plus the USB
link (25 KB, of which 16.5 KB are the decode and TX buffers docs/19 requires).

Planned consolidations (estimates from the measured per-entry sizes; owner in brackets):

| # | change | LEAF | RELAY | ROOT |
|---|---|---:|---:|---:|
| P1 | dedup cache: compact terminal record (key, hash, outcome, result) + live extension only for app_messages entries [S14, or a consolidation slice after S13 lands] | -2.0 KB | -2.0 KB | -9.0 KB |
| P2 | neighbour `prev` session (144 B each, needed 10 s after a rotation) as 2 shared grace slots [S11] | -0.9 KB | -2.0 KB | -2.0 KB |
| P3 | worker stack from a target measurement (high-water mark over link/join/end/USB handshakes), keeping 2x margin [HIL, S19] | 0 to -4 KB | 0 to -4 KB | 0 to -4 KB |
| P4 | one record-job memory per node: `Durable` borrows the identity's `RecordJob` per job; join/ledger hold it per job, not per transaction [S18] | -1.1 KB | -1.1 KB | -1.1 KB |
| P5 | USB handshake on the node's exchange slot (a USB attempt reserves the slot next, bounded wait) [S13 follow-up] | - | - | -5.4 KB |
| P6 | root: paths derived from the S11 topology instead of 64 cached paths; topology nodes merged with ledger entries (no second DeviceId table) [S11] | - | - | -9 to -12 KB |
| P7 | TX frame metadata to 32 B (docs/16 §2; counter read from the header) [S14] | -0.3 KB | -0.4 KB | -0.8 KB |
| P8 | `Membership` and `Ledger` exclusive by role on ROOT images [S18] | - | - | -1.1 KB |
| P9 | one frame pool: the HOP_ACK seal buffer, the exchange's staged frame, the delivery TX scratch and JoinPipe staging borrow TX-pool frames; S16 mailboxes come from the same pool [S14] | -1.0 KB | -1.0 KB | -1.8 KB |

After P1-P9 the projection (with the S11-S20 allocations below) is about 49-53 KB leaf, 53-57 KB
relay, 143-150 KB root (the lower ends need P3): the targets are still not met. They are not reachable with the current
capacities and architecture; a decision is required (not taken here, `profiles.json` is unchanged
because its numbers are consistent with the spec text):
- either revise `ram_target_bytes` to what the specified capacities cost (a proposal: leaf 48 KiB,
  relay 56 KiB, root 160 KiB), or
- cut capacities (e.g. root receipts 128 -> 64 = -12.3 KB, end_sessions 64 -> 32 = -6.4 KB,
  app_messages 16 -> 8 = about -10 KB with messages, operations and actives; leaf receipts
  32 -> 16 = -3.1 KB).

ROOT on ESP32-C3 is the hard case: static DRAM of the ROOT image is 150,310 B of 321,296 B, and the
113,016 B workspace comes from the heap, leaving about 58 KB before any IDF runtime user (Wi-Fi
buffers and task stacks, PSA's ~5 KB peak). The docs/16 gate "C3 minimum-ever free heap >= 48 KiB"
is therefore at risk for ROOT on C3 even after P1-P9 unless capacities are cut. Unverified: the free
heap was not measured on hardware.

SLOC is 20.3k against 16k with S11-S20 still to come (allocated 6,950 below: projected 27.3k; P1, P4,
P5 and a shared job-slot helper for the six modules that repeat "one job, generation, zombie" plumbing
save an estimated 600-800). The 16,000 line is not reachable for the specified feature set; the
decision (raise the line with this per-slice plan, or drop features) belongs to the spec owner.

## Allocations for S11-S20 (hard numbers)

Fixed RAM (workspace + static, esp32c3 sizeof as the report measures it) and sdk SLOC per slice. A
slice that needs more amends this ADR in its report before merging; unused allocation is not carried
over to other slices.

| slice | LEAF B | RELAY B | ROOT B | SLOC | what the allocation covers / must borrow |
|---|---:|---:|---:|---:|---|
| S11 MESH | 800 | 1,000 | 4,000 | 1,200 | root path <= 20, parent + 2 candidates, per-neighbour quality, hello/discovery state; root: topology merged with ledger entries (P6). Routes go into the existing `PathCache`; no second route table |
| S12 FRAGMENT | 1,500 | 1,500 | 1,500 | 700 | small-reassembly metadata (slots x ~100 B) with payloads in the message pool; one 1 KiB control page buffer. Object reassembly (4 KiB) only when `object_transfer_enabled` (+4.2 KB then, 0 otherwise); control objects > 1 KiB to leaf/relay need a paging decision first |
| S13 HOST-BRIDGE | 0 | 0 | 3,000 | 1,000 | bridge state on the root only; payloads stay in the message pool and the USB TX buffer (the in-progress bridge measures 15,000 B: build responses in the USB link's TX buffer and read event payloads from the message pool instead of copying them into a ring) |
| S14 SCHED | 200 | 200 | 200 | 450 | DRR deficits, airtime tokens, admission counters; queues are TX-pool frames with a class tag |
| S15 GROUP | 500 | 500 | 3,500 | 900 | per operation 64-target compact state (payload in the message pool); root group registry by ledger slot, not DeviceId copies |
| S16 POWER | 1,024 | 1,024 | 1,536 | 900 | docs/16 1 KiB per node; mailbox frames borrowed from the TX pool |
| S17 CHANNEL | 200 | 200 | 500 | 700 | plan/epoch/freeze/rollback, survey table; root coordinator |
| S18 LIFECYCLE | 300 | 300 | 800 | 800 | grant-consumption ledger, commissioning window, handover; floors table exists |
| S19 DIAG | 100 | 100 | 100 | 300 | validity bits and snapshot assembly (reuse the event payload path) |
| S20 E2E | 0 | 0 | 0 | 0 | tests only |
| **total** | **4,624** | **4,824** | **15,136** | **6,950** | |

Projection without P1-P9: 57.8 KB leaf, 63.5 KB relay, 180.5 KB root, 27.3k SLOC.

Rules for every slice (additions to IMPLEMENTATION.md §11 acceptance):
- Report `scripts/budget_report.py` before/after (sizeof per profile, static DRAM of the LEAF and ROOT
  IDF builds, image diff, SLOC) against the row above.
- No new buffer >= 256 B per feature without an entry here: borrow the message pool, the TX frame pool,
  the exchange's lent scratch (1 KiB), the record-job memory or the durable scratch.
- Root-only state is compiled out of leaf/relay (`k_root_capable`); a disabled feature leaves no buffer.
- A slice that touches an existing mechanism (routes, chunking, handshakes, job plumbing) extends it
  instead of adding a parallel one, and says which duplicate it removed.

## Not verified

No SoC measurement of heap, stack high-water marks, CPU or energy; PSA heap and stack depths are the
native software model. The multi-part AES-GCM path of `open_in_place` is exercised natively (TF-PSA-
Crypto builtin); on IDF it is only compiled (the esp_aes GCM driver implements the multi-part entry
points). Wire behaviour did not change (same carriers, same record layout); link, join and end
handshakes can no longer overlap on one node, which the sim tests cover but no RF test has measured
for formation time (docs/16 §3 "全21台cold boot").

## Decision (orchestrator, 2026-09-29)
- The specified capacities in `config/profiles.json` stay (they are functional contract: 64 members, 20 hops, receipts). The docs/16 RAM targets are revised to the measured cost of those capacities: **leaf 48 KiB, relay 56 KiB, root 160 KiB** (static + pools + task stacks + rings; crypto peak reported separately). The 256 KiB Flash target is unchanged. **It was true on 2026-09-29 only for the early slices; it is NOT met now** (later slices; FIX11 review): the flash difference exceeds 256 KiB in all 12 SoC/profile builds at the time of the FIX11 report and ROOT exceeds the 320 KiB review line on all four SoCs. The current figures are the summary at the top of `build-records/budget-report.md`.
- P1–P9 are mandatory in their owning slices; every slice reports `scripts/budget_report.py` against its allocation row above.
- **ROOT on ESP32-C3 is not a supported configuration** until a HIL measurement shows minimum-ever free heap ≥ 48 KiB with Wi-Fi up. ROOT is built and CI-checked on all four SoCs, but the supported root SoCs are S3/C5/C6. C3 remains fully supported as leaf and relay. No PSRAM may be used to hide this.
- The SLOC line is raised to **28k** for the specified feature set (core+idf+root/serial), with the per-slice caps above as hard limits. Over-cap slices need a line here with cause.

## S14 SCHED with P1, P7, P9 (2026-09-29, esp32c3 sizeof / build as `scripts/budget_report.py` measures it)

Measured against HEAD `cf49d12` built in a clean worktree ("before") and the shared working tree at the
end of S14 ("after"; the tree also holds S11-S13 work in progress, so the totals of the report are not
S14 alone; the per-object rows below are). Software measurements only.

| object (bytes) | LEAF before | LEAF after | RELAY before | RELAY after | ROOT before | ROOT after |
|---|---:|---:|---:|---:|---:|---:|
| TX pool + `HopTx` (P7: 328 -> 288 B per frame; P9: ACK seal buffer gone) | 3,368 | 2,784 | 4,704 | 3,960 | 8,712 | 7,488 |
| dedup cache: `InEntry` 192 -> 136 B, plus `InLive` 48 B x (`app_messages` + 2) (P1) | 6,144 | 4,640 | 6,144 | 4,640 | 24,576 | 18,272 |
| exchange staged object (P9) | 6,616 | 6,360 | 6,616 | 6,360 | 6,616 | 6,360 |
| join pipe staging (P9; root: 4 pipes in the ledger) | 304 | 120 | 304 | 120 | 11,264 (ledger) | 10,528 (ledger) |
| delivery TX scratch, 288 B (P9) | 288 | 0 | 288 | 0 | 288 | 0 |
| scheduler state (S14) | 0 | 136 | 0 | 136 | 0 | 136 |
| LATEST key + flag per `Active` (S14; measured with S12's own `Active` growth, so an upper bound) | 0 | <= 64 | 0 | <= 64 | 0 | <= 256 |
| **P1 + P7 + P9 + S14 state** | | **-2,616** | | **-2,776** | | **-8,672** |

Against the allocation row (LEAF/RELAY/ROOT 200 B): the scheduler is 136 B; with the LATEST key of every
operation slot (8 B + flag, 16 x 16 B on the root) the S14 state is 200 / 200 / 392 B. The root is 192 B
over its row: the key must be compared in full (a 64-bit value chosen by the application), so it cannot
be hashed to fewer bytes, and it lives in the operation slot that owns it. The consolidations more than
pay for it (the row of the table above is the net). P1 saves less than estimated (-1.5 KB leaf / -6.3 KB
root against -2.0 / -9.0): the terminal record keeps the origin and message id in full (dedup is a security
property), the 32-byte result and the expiry a receipt repeats, and an owed APPLIED result keeps a live slot.
P9 saves 992 B (leaf) and 1,544 B (root) against 1.0 / 1.8 KB. P7 matches (320 / 480 / 960 B).

Static DRAM of `libleanmesh.a` does not change for LEAF/RELAY (17,840 / 18,960 B): S14 adds no static
buffer (the scheduler and the pool live in the workspace). ROOT static DRAM moved for S13's reasons.

Object code of S14's files (riscv32, -Os): `sched.cpp` 1.3 KB, `delivery_sched.cpp` 0.9 KB, `hop.cpp`
+1.0 KB, `engine.cpp` +0.5 KB, `join.cpp` +0.7 KB, `exchange.cpp` +0.7 KB; the changes to `delivery*.cpp`
are mixed with S12 and not separable. First-party SLOC of new S14 files: 394 (`src/core/sched` 190,
`radio/tx_pool.hpp` 132, `delivery/delivery_sched.cpp` 72) against the 450 cap; the plumbing of P1/P7/P9
in existing files adds about 130 more (hop, engine, exchange staging, join staging, dedup slots): S14 is
about 520 SLOC in all, 70 over its row, because the consolidations are code (leases, live slots) as well
as deletions.

Behaviour that changed (decisions S14-D1..D10 in IMPLEMENTATION.md §13): a node can hold or owe results for
at most `app_messages + 2` received messages at a time (the seventh arrival at a leaf is answered BUSY until
one is taken or its result reported; before, only `durable_pending` limited owed results); a send that finds
the TX pool without a free frame retries after 50 ms as before, but a BULK send is refused earlier (half of
the pool and of the operation slots).

## S11 MESH report (measured on `cf49d12` and `cf49d12` + S11 alone, esp32c3, -Os; software only)

Fixed RAM (workspace + static DRAM), bytes:

| | LEAF | RELAY | ROOT |
|---|---:|---:|---:|
| before | 53,208 | 58,656 | 180,348 |
| after | 53,680 | 58,504 | 175,348 |
| change | +472 | -152 | -5,000 |
| S11 row | 800 | 1,000 | 4,000 |

What moved (sizeof): `Mesh` +952 (3 candidates with their advertised root path 3 x ~115 B, one attach with its granted path, 2 query slots, timers), `Proxy` +176 / +704 / +768 (a leaf build keeps no frame buffers; a relay and the root two 250 B frames), `Membership` +120 (offers, discovery policy), `Routes` +3,168 on the root (64 routing slots of 48 B: no DeviceId, no generations, P6). P2: `Neighbor` 368 -> 224 B, -848 B leaf and -2,000 B relay/root (two shared grace slots). P6: the root's route cache 64 -> 8 entries, `delivery` 80,768 -> 72,736 B. Gross additions of S11 are 1.25 KB (leaf), 1.9 KB (relay), 4.3 KB (root: mesh, proxy, routes); the row is met net of P2/P6 in all three, not gross for the leaf (1.25 KB against 800 B). Static DRAM of `libleanmesh.a` is unchanged (17,840 / 18,960 / 67,332 B): the mesh lives in the workspace.

Flash (image minus the empty IDF + ESP-NOW baseline): LEAF +178,484 -> +199,528 B, RELAY +178,554 -> +201,680 B, ROOT +231,376 -> +262,278 B. The ROOT image is 134 B over the 256 KiB target (below the 320 KiB review line): S11 code is about 21-31 KB of it.

First-party SLOC (sdk set): 21,318 -> 24,260 (+2,942) against a row of 1,200. Cause, by module: `route` +1,715 (mesh state machine 1,148 + wire 351 + stitch), `member` +658 (proxy 415, discovery 119, Membership/join changes), `root` +329 (route service 308, topology now by address), `delivery` +115 (plug points, control lane), `link` +77. The row assumed a mesh that registers, leases and repairs; it did not count the proxy tunnel (415), the listen-first discovery policy shared by joiner and member (119), the root service (308) and the compact wire codecs (351). No tick, no polling loop and no general "engine" was added; the largest single item is the attach/repair state machine (link -> probe -> end session -> REGISTER -> READY, with the failure paths a restarted parent or root needs).

Behaviour: S11-D1..D10 in IMPLEMENTATION.md §13. Formation time on a 21-node/20-hop chain is 35.8 s in the simulator (worker latency 2 ms) and 108 s with a modelled 150 ms per public-key job: the latter is the number to compare with the 120 s target, and it is a model, not a measurement of a C3.

## S15 GROUP report (esp32c3 sizeof, -Os; software only)

Measured on the tree at the end of S15 (`scripts/budget_report.py` probe compiled with the SoC compiler; the
"before" is HEAD `2029c7e` in a clean worktree). The tree also holds S16/S17 and the security/delivery fixes in
progress, so only the group rows below are S15; totals of the report are not.

| object (bytes) | LEAF | RELAY | ROOT | S15 row (L / R / Root) |
|---|---:|---:|---:|---|
| `group::Fanout` (all of it) | 3,664 | 3,664 | 6,120 | 500 / 500 / 3,500 |
| - operations: `Op` = 264 B header + 64 x 16 B `Target` (1,288 B each); leaf/relay 1, root 4 | 1,288 | 1,288 | 5,152 | |
| - DeviceIds of a member origin's snapshot (64 x 32 B; absent from a real ROOT image) | 2,048 | 2,048 | 0 | |
| - sign/verify job arguments (`Page`; the 16 x 40 B page rows exist on ROOT builds only) | 328 | 328 | 968 | |
| `root::Groups` registry (8 groups x 64 ledger slots) | 0 | 0 | 648 | |
| **S15 total** | **3,664** | **3,664** | **6,768** | **+3,164 / +3,164 / +3,268 over the row** |
| `Delivery` plug points (hooks, child id pointer; not in the total above) | +16 | +16 | +16 | |

Why the row does not hold: the row assumed "64-target compact state" of 500 B on a leaf. docs/22 §4 requires the
origin to keep the verified full set (64 DeviceIds = 2 KiB; the root's page cache may expire meanwhile) plus the
per-target results (1 KiB); the minimum for a 64-target member origin is therefore about 3.2 KB. The root row held
because targets there are ledger slots (16 B per target, DeviceIds read from the ledger), but four operations at
1.3 KB and the page job arguments exceed 3.5 KB; the root also serves the snapshots of other origins from the same
four operation slots (no extra RAM). Nothing else is new: the payload is one message-pool buffer, a child is an
ordinary `Delivery` send, the sign/verify job borrows the exchange's lent 1 KiB scratch, the control page uses S12's
control buffer. Options for the spec owner, not taken here: a build limit for the targets of a member origin
(`k_id_slots`; 16 targets = 512 B, saves 1.5 KB per leaf/relay, over-limit snapshots would end NO_CAPACITY before
acceptance), or root-origin-only groups on leaf/relay (docs/22 §1 says any Node may be the origin).

Flash (object code, riscv32, -Os): `group.cpp` 7.7 KB, `snapshot.cpp` 4.2 KB (4.9 KB ROOT), `capi_group.cpp` 0.5 KB,
`delivery_group.cpp` 0.3 KB, `groups.cpp` 1.0 KB (ROOT): LEAF +12.8 KB, ROOT +14.5 KB, plus about +2.4 KB in the
bridge objects (ROOT) and +0.2 KB `sec::sha256_chunks`. The ROOT example image overflows the example's 1 MB app
partition by 8.9 KB in this shared tree (all slices together; it fit at HEAD).

First-party SLOC (sdk): 1,532 in the new files (`group.hpp` 233, `group.cpp` 643, `snapshot.cpp` 392, `groups.*` 152,
`capi_group.cpp` 69, `delivery_group.cpp` 43) and about 230 in existing files (bridge: group SEND, GROUP_SET, GROUP_TARGETS, the
event; engine wiring; delivery hooks; `sha256_chunks`), about 1,760 against a row of 900. Cause: the row counted the
fan-out; it did not count the signed snapshot protocol both ways (request, sign job, verify job, page assembly, hash,
retry: 570), the root registry (150), the bridge methods (150) and the C API (70). No general "engine" was added;
the one duplicated concern that was removed: there is no second per-message state machine, a target *is* a
`Delivery` send.

Measured (sim, seed 61, worker latency 2 ms): 64 targets from a member that is not the root (8 relays + 56 leaves,
512 B, RECEIVED) end after 129.8 s virtual time, 4 in flight, 4 snapshot pages; the time is the 64 end-session
handshakes of a leaf whose session cache holds 4 (`end_sessions` = 4 for leaf/relay): a second fan-out to the same
64 targets repeats them. With unreachable targets (five members that never started) the eleven reachable ones were
received after 11.2 s: the dead ones are withdrawn after 5 s and dispatched again, so up to four dead targets delay
the others by that long, not to their deadline.

## S16 POWER (2026-09-29; `scripts/budget_report.py`, native x86-64 sizeof; the esp32c3 probe was not re-run after the last trim)

Allocation: LEAF 1,024 / RELAY 1,024 / ROOT 1,536 B, 900 SLOC. The mailbox borrows the TX pool (P9: no buffer of its own), the policy record borrows the identity's `RecordJob`, the poll/grant frames are built on the stack. Tables are compiled out where the role cannot exist: the child table (`neighbors / 2` x 56 B) only in RELAY/ROOT images, the member table (64 x 24 B) only in ROOT. SLOC is far over the row: the slice is a state machine with three tables, the sleep transition, the ticket protocol, the budgets and the root's view, plus five small integrations; no general engine, no polling and no second scheduler were added.

Measured: `power::Power` in the workspace 712 B (LEAF) / 1,288 B (RELAY) / 2,816 B (ROOT) against 1,024 / 1,024 / 1,536: LEAF inside, RELAY +264 B (8 child entries of ~72 B), ROOT +1,280 B (the member table alone is the allocation: 64 x 24 B; the children add ~580 B). LEAF static DRAM did not move (17,864 B) and ROOT image links but no longer fits the 1 MiB `factory` partition of `firmware/example_node` (0x104830 B, 0x4830 over: the sum of S11-S17 on ROOT, not S16 alone; the Flash figure of S16's own objects is not separated). SLOC of `src/core/power` 1,847 + `capi_power.cpp` 169 + `idf_pm` 156 = about 2,170 against 900, plus about 130 lines of hooks in existing files: cause in the paragraph above (three tables, the sleep transition, the ticket protocol, budgets, the root view, the PM port); the sdk total in the report is 33,152 (all slices).

## SEC fixes (external review of wave 4, 2026-09-29; esp32c3, -Os; software only)

Measured on HEAD `2029c7e` ("before") and HEAD + the SEC changes alone ("after"), both in clean worktrees (the
shared tree also holds S15-S17, so its totals are not SEC). Decisions SEC-D1..D15, SEC-Da in IMPLEMENTATION.md §13.
No allocation row exists for these fixes; they are required behaviour, reported here with their cause.

| fixed RAM (workspace + static DRAM) | LEAF | RELAY (estimate) | ROOT |
|---|---:|---:|---:|
| before | 52,928 | 57,008 | 153,356 |
| after | 53,336 | 57,544 | 155,788 |
| change | +408 | +536 | +2,432 |

What moved (sizeof): `Neighbor` 224 -> 240 B (the peer's credential lease and its "unproven" flag, SEC-D3: +128 leaf,
+256 relay/root); `EndSession` 200 -> 216 B (the same for end sessions: +64 leaf/relay, +1,024 root with 64 slots);
`LocalIdentity` +88 B (own leave floor SEC-D8, DiscoveryScopeKey SEC-Da); `Membership` +56 B (the withheld signature
of the pending join, SEC-D1); handshake slot +32 B (the ECDH output kept in the slot and wiped, SEC-D15); `Ledger`
(root only) 10,528 -> 11,464 B: the manifest and its staging copy (2 x 200 B, SEC-D5/D7) and the consumed
generation of every entry (64 x 8 B, SEC-D4). The consumed-generation part (512 B root, about 40 SLOC) is the
"grant-consumption ledger" of the S18 row and should be charged there. Static DRAM of `libleanmesh.a` is unchanged
(17,840 / 51,852 B).

Worker stack (SEC-D15): the deepest job, an EDHOC message_2/3 step, measured natively 4,840 -> 4,344 B (-O2),
4,488 B (-Og), 5,856 -> 5,600 B (-O0). The IDF worker stays 10,240 B in optimised builds; an unoptimised (Debug)
build now gets 12,288 B, because 2 x 5,600 no longer fits 10 KiB (before, the -O0 depth exceeded half the stack
unnoticed). Not measured on a target.

Flash (image minus the empty IDF + ESP-NOW baseline): LEAF +216,644 -> +219,752 B (+3,108), ROOT +280,964 ->
+287,280 B (+6,316).

First-party SLOC: sdk 26,005 -> 26,645 (+640: `root` +253 ledger manifest/ExpectedSet set rules/consumption/forget,
`member` +183 withheld signature and activation check/LEFT tombstone/scope tags, `link` +148 admission, lease
revalidation and the replay-window order, `security` +25, `core` +14, `delivery` +9 (end-session lease), `port/idf` +6,
`wire`/`store` +1 each); tests +545, tools +60 (bench provisioning of ledger entries and the manifest), native-only +8.

## S19 status (2026-09-29, software measurements)

Generated by `scripts/budget_report.py` into `build-records/budget-report.{json,md}` (all four SoCs, LEAF and ROOT; RELAY on esp32c3). S19's own cost: `src/core/diag` 231 SLOC (allocation 300), Engine +16 B (first-start time, lost-event total), no new pool or buffer; the optional OTA module (320 SLOC + hooks) is compiled out by default and does not change the image (esp32c3 LEAF .bin identical with and without it). Overruns that remain are reported there and are not new: fixed RAM esp32c3 LEAF/RELAY/ROOT and the SDK SLOC exceed the revised targets, esp32c3/c5/c6 LEAF flash diff exceeds 256 KiB, every ROOT image exceeds the 320 KiB review line. Nothing was measured on a SoC.

## S18 LIFECYCLE (2026-09-29, esp32c3 sizeof / build as `scripts/budget_report.py` measures it)

Before: HEAD `3596820` built in a clean copy; after: the shared working tree at the end of S18 (it also holds S19,
FIX3 and FIX4 work, so the report's totals are not S18 alone; the rows below are S18's objects).

| object (bytes, esp32c3) | LEAF before | LEAF after | ROOT before | ROOT after |
|---|---:|---:|---:|---:|
| `Membership` (switch state, target domain, mode-0 nonce, revocation floors, renewal) | 1,088 | 1,160 | 1,088 | 1,160 |
| `Ledger` (renewal mask, lifecycle install with one decoded object, window + durable budget id, retirement, notice) | - | - | 11,464 | 11,896 |
| `LinkLayer` (renewal-only window and counter) | 9,272 | 9,288 | 11,240 | 11,256 |
| `Mesh` (discovery hint bucket, review finding 1) | 952 | 960 | 952 | 960 |
| `Proxy` (pre-auth expiry and proof per slot, start pacing, review finding 2) | 176 | 200 | 768 | 840 |
| **S18** | | **+120** | | **+600** |

RELAY is not built on the SoC; its objects are LEAF's plus the relay proxy table (native estimate +150 B). With the
512 B of SEC-D4's consumed generations that the SEC section charges to this row, ROOT is +1,112 B against 800 B:
**over by 312 B**. Cause: the handover, window and revocation installs share one `Lifecycle` (a union of the four
decoded objects: 200 B, the ticket; it was 464 B as four members before the union), the active window (64 B) and
its budget id (16 B), the revocation notice keeps the device for 10 s (32 B + address + time), five statistics
(40 B); the review fixes (proxy +72 B) came into this slice. No new buffer >= 256 B:
the renewal, the lifecycle installs and the window budget commit borrow the identity's `RecordJob` and the exchange
scratch like every other ledger job. Static DRAM of `libleanmesh.a`: 17,864 -> 17,896 / 51,876 -> 51,908 B (tree).

Flash (text+data of the S18 objects, riscv32 `size`): LEAF +7,084 B, ROOT +14,572 B (`member/lifecycle.cpp` 2,384,
`root/lifecycle.cpp` 5,338, `root/ledger.cpp` +1,204, `membership_join.cpp` +1,216, the rest spread over member,
link, route and root); the tree's image diff moved LEAF +271,918 -> +281,508 B and ROOT +359,144 -> +384,456 B
(all slices).

SLOC (the report's counter): the S18 files +1,120 (`root/lifecycle.cpp` 361, `member/lifecycle.cpp` 177, ledger +193,
membership +189, credentials/records +91, proxy/discovery +40 (review findings 1-2), link +39 (renewal-only link,
finding 20), route +9) plus about 40 in shared files (engine, capi, record ids) and SEC-D4's 40: about 1,200 against
800: **over by about 400**. Cause: the row priced renewal, window and handover; the slice also carries the member's
switch (transfer with its resume after a cut, reconciliation, return), revocation with its notice and tombstone, the
mode-0 nonce API and four review fixes. Not reduced: P4 (the `Durable` job memory is in `src/core/delivery/**`, owned
by another fixer during S18) and P8 (Membership/Ledger exclusive on ROOT images: an Engine layout change in shared
files); both stay open for their owners.

## ARCH2 final core pass (2026-09-30; `scripts/budget_report.py`, all four SoCs, LEAF/RELAY/ROOT; software only)

Before: HEAD `25849ed` built in a clean copy (`build-arch2-base`, `native-arch2-base`). After: the shared tree at the
end of this pass (it also holds S20's tests, examples and ledger fix), regenerated into `build-records/budget-report.*`.
Decisions ARCH2-D1..D8 and ARCH2-P2A..P2C are in IMPLEMENTATION.md §13.

### Fixed RAM (workspace + static DRAM of libleanmesh.a), bytes

| SoC | LEAF before | LEAF after | RELAY before | RELAY after | ROOT before | ROOT after |
|---|---:|---:|---:|---:|---:|---:|
| esp32c3 | 60,176 | 58,672 | 65,600 | 64,096 | 180,468 | 176,324 |
| esp32c5 | 60,176 | 58,672 | 65,600 | 64,096 | 180,468 | 176,324 |
| esp32c6 | 60,176 | 58,672 | 65,600 | 64,096 | 180,468 | 176,324 |
| esp32s3 | 60,184 | 58,680 | 65,608 | 64,104 | 180,484 | 176,340 |
| target | 49,152 | 49,152 | 57,344 | 57,344 | 163,840 | 163,840 |
| over after | | +9,520 | | +6,752 | | +12,484 |

What moved (esp32c3 sizeof): P4 `Durable` 2,664 -> 1,248 (its own `BootJob` is gone, -1,416 every profile); P8
`Membership` + `Ledger` -> one role storage (ROOT 13,056 -> 11,904, -1,152; LEAF/RELAY unchanged: their ledger is an
empty stand-in); `Op` 208 -> 192 B (fields regrouped while adding the origin assignment, -128 LEAF / -512 ROOT); the
UsbLink keeps views instead of copies of the kit's CCS and credentials (ROOT static -1,104); the root term adds
`LocalIdentity::term_` (+8) and a per-candidate proof flag in `Mesh` (+24); `DeliveryStats::old_assignment` +8.

### Flash (image minus the empty IDF + ESP-NOW baseline), bytes

| SoC | LEAF before | LEAF after | RELAY before | RELAY after | ROOT before | ROOT after |
|---|---:|---:|---:|---:|---:|---:|
| esp32c3 | 281,508 | 284,322 | 287,098 | 289,884 | 384,480 | 388,132 |
| esp32c5 | 287,652 | 290,466 | 293,242 | 296,028 | 390,602 | 394,254 |
| esp32c6 | 287,156 | 289,660 | 292,830 | 295,264 | 391,394 | 394,612 |
| esp32s3 | 253,221 | 255,253 | 257,825 | 259,629 | 344,545 | 347,097 |

+1.8..2.8 KB (LEAF/RELAY) and +2.6..3.7 KB (ROOT): the per-boot term (the root's credential re-issue in the load job,
term learning and re-sync, the channel's old-term plan rules), the P4 waiting/retry paths, the assignment binding and
the lm_root_time_get entry. Merging P2A + P2B took back 308-1,028 B (a mid-pass build of Part 1 + P2C against the
final build; P2C's own flash effect was not measured separately). Every ROOT image stays over the 320 KiB review line
and every LEAF/RELAY image but esp32s3 over 256 KiB (unchanged verdicts).

### First-party SLOC (sdk = core + idf + root + serial)

35,633 before -> 35,662 after (+29). Part 1 peaked at 36,007 (+374): P4/P8 with their two fixes +206 and the
assignment binding / address invalidation +21 (each measured on its own branch), the rest (+147, by difference) the
per-boot term, ARCH2-D2 and S20's ledger fix. Part 2 removed 345, each step measured on its tree and net of the helpers
it introduced: in-place AES-GCM helper -35 and `send_sealed` -14 (P2C), field-list codecs -89 (P2A), C API /
record-job / credential-pair / send_control / channel plumbing and UsbLink views -203 (P2B), -4 in the merge. Per
module: capi -35, core top level +150 (codec field
lists, one_of.hpp), channel -47, delivery +76, group -16, link +19, member +26, power -30, route -70, wire -10, root -26,
security -35, serial +18, store +9. Tests +1,947 (test_term, test_codec, the P4/P8/(b)/(c) tests; S20's test_model).

### What remains over, and why

- **LEAF +9.5 KB / RELAY +6.8 KB.** Static DRAM 17.9 / 19.0 KB is platform: owner stack 4 KiB, worker stack 10 KiB
  (at least twice the natively measured deepest job, 4.5 KB; P3 needs a target measurement), RX ring 2.8 / 3.9 KB.
  The workspace (40.8 / 45.1 KB) is the specified capacities (config/profiles.json) at their per-entry cost: 32
  receipts x 144 B, 8 / 12 TX frames x 296 B, 4 x 512 B messages and 4 active sends x 280 B, one handshake slot (6.4
  KB, of which 2.9 KB is libedhoc's context), the 1 KiB credential bundle, and a member origin's 64-target group
  operation (1.8 KB state + 2 KiB full DeviceIds, docs/22 §1 and FIX3-D10). None of these is duplicated state;
  reducing them changes a capacity or the spec.
- **ROOT +12.5 KB.** Root capacities: 128 receipts (18.4 KB), 64 end sessions (13.8 KB), 16 messages (8 KB), the
  ledger (11.9 KB), the USB link (20.2 KB, 16.5 KB of it the 8,230 B decode buffer and the TX buffer docs/19 sizes)
  and four group operations with their full DeviceIds (8 KiB of `Fanout::ids_`). The group ids are the one large
  item that could go (the ledger holds the same DeviceIds), but only by pinning a ledger slot while a live snapshot
  references it, so a join could be refused meanwhile: a behaviour decision, not taken here. The ledger's
  job-argument unions (about 0.5 KB, survey estimate) were not taken: `vargs_`/`sargs_` became possible only with
  ARCH2-D8 at the end of the pass, and `exp_`/`lc_` first needs `lc_.active` moved out (a zombie ExpectedSet job may
  still write `exp_` after `stop()`). Behaviour decisions the survey also listed, not taken: `Fanout::page_` pinned to
  its sign job (~0.8 KB ROOT), the proxy's 250 B frame from the TX pool.
- **SLOC +7.7k over 28k.** The duplication survey (a normalised clone scan: no verbatim copy longer than ~16 lines;
  the rest is the same shape with renamed fields) found ~630 SLOC of behaviour-neutral candidates; this pass took the
  larger ones (codecs, C API, record plumbing, credential pairs, send_control, AEAD streaming, seal-and-send: -345).
  Not taken, with cause: the one-job/zombie helper (~40 SLOC net; nine owners differ in what a cancelled completion
  frees and when the handle moves), an EDHOC step table shared by the radio and USB exchanges (~60, handshake code),
  a join-object header helper and smaller items (~150 together). None of these changes the verdict. The overrun is
  the feature set measured per slice above: S11 +1.7k, S15 +0.9k, S16 +1.3k and S18 +0.4k over their rows, the SEC
  fixes +0.6k, the optional OTA module 320 (counted though compiled out) and this pass's correctness work (+374, of
  which Part 2 took back 345).
- **Not reached by this pass**: P3 (worker stack from a target measurement, up to -4 KiB every profile) needs HIL.
- **Found, not removed** (after the final verification, to keep the verified tree): three dead fields
  (`Exchange::cancelled_` is written, never read; `Ledger::job_state_` and `Ledger::job_confirmed_` are unused).

Part 1 behaviour costs measured in sim (not RF): R07 (21 nodes, 20 hops, 20 cold boots) formation mean 36.0 -> 39.8 s
(one more REGISTER round trip per node for the new term); after a full cold boot every member is renewed into the new
term 130.7 s after formation and a 20-hop message follows 31.9 s later (application DATA waits for the renewals the
old clock's misread had skipped); C05 converges in 368 s instead of 488 s (members follow the committed plan as soon as
they learn the new term); R06 root return 159.7 -> 145.9 s. Nothing was measured on a SoC.
