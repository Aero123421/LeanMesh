# Field test kit: protocol (bench / field tool, not product)

A test application on top of LeanMesh for range and topology tests in the field. It is NOT part of the SDK core
(AGENTS.md: no application vocabulary in core) and not a product: no KGuard safety logic, no Cloud.

```
[laptop]  LeanMesh Host (host/, unchanged role)  <-- fieldview (tools/fieldview/, new): web page + logs
             | USB-Serial/JTAG
[root]    ESP32-S3, firmware/hil_node ROOT build (unchanged), join mode PREAPPROVED
             | LeanMesh (ESP-NOW, LR 250 kbps)
[nodes]   firmware/field_node (new): S3 / C3 / C6, relay or leaf build; HUB75 S3 display build (relay)
```

## 1. Boards and roles

| build | role | boards | notes |
|---|---|---|---|
| `field_node` RELAY | relay | ESP32-S3 / C3 / C6 | forwards for others |
| `field_node` LEAF | leaf | ESP32-S3 / C3 / C6 | |
| `field_node` RELAY + `CONFIG_FIELD_HUB75=y` | display (relays too: mains powered) | Seengreat RGB Matrix HUB75 S3 (ESP32-S3-WROOM-1-N16R8), 64x32 panel | draws the display state |

All nodes run ALWAYS_RX (no sleep) during field tests.

## 2. Provisioning and joining

- Once, at the desk, over USB: the same bench console as `firmware/hil_node` (`keygen`, `prov-leaf ...`), driven by
  `tools/hil/hil.py provision leaf|relay --port P --name N`. The device key is made on the board.
- The root is PREAPPROVED (`hil.py policy PREAPPROVED`); each board's ExpectedSet page is installed through the Host
  (`hil.py expected`). No approval step in the field.
- In the field: power on. A provisioned node that is not an ACTIVE member asks `lm_join(NEW)` by itself and keeps asking
  (backoff 5, 10, 20, 40, 60, 60 ... s) until it is ACTIVE; an ACTIVE member re-attaches by the SDK itself. A node that
  is REVOKED stops asking. Mesh formation (parent choice, relaying, repair) is the SDK's.

## 3. Application messages

Ports are LeanMesh `app_port` values. All integers are big-endian. Unknown `version` -> the receiver ignores the message
(a node reports REJECTED for a Host->node message it cannot read).

### 3.1 Telemetry (node -> root application), app_port 210

Sent by every node after it becomes REACHABLE, then every 10 s + random 0..1000 ms (no synchronised bursts). The Host
receives it as a MESSAGE event (`origin` = the node, `payload_b64`). Delivery `LM_BEST_EFFORT`, storage `LM_VOLATILE`,
priority NORMAL, deadline 30 s on the node's root clock (no telemetry while the node has no valid root time). Loss is
measured by the sequence number, not by receipts.

| offset | type | field |
|---|---|---|
| 0 | u8 | version = 1 |
| 1 | u8 | role: 1 leaf, 2 relay, 3 display |
| 2 | u8 | chip: 0 other, 1 esp32s3, 2 esp32c3, 3 esp32c6 |
| 3 | u8 | flags: bit0 display state valid, bit1 display FORBID (else USABLE), bit2 render fault |
| 4 | u32 | seq (1.. per boot) |
| 8 | u32 | uptime_s |
| 12 | u16 | boot_count (NVS counter, wraps) |
| 14 | u8 | last reset reason (`lm_diagnostics_t.last_reset_reason`, 0xFF unknown) |
| 15 | u8 | root_depth from `lm_connectivity_get` (0xFF unknown) |
| 16 | i8 | parent RSSI dBm from `lm_diagnostics_get` (-128 unknown: validity bit clear) |
| 17 | u8 | reserved 0 |
| 18 | u16 | telemetry interval s (10) |
| 20 | u32 | tx_frames (low 32 bits) |
| 24 | u32 | rx_frames (low 32 bits) |
| 28 | u32 | rf_failures (low 32 bits) |
| 32 | u32 | local_busy (low 32 bits) |
| 36 | u32 | min_heap_bytes |
| 40 | u32 | display command seq last applied (0 none) |

44 bytes. Counters that the diagnostics mark invalid are sent as 0xFFFFFFFF.

### 3.2 Ping (Host -> node), app_port 211

The laptop checks every node at once (one request per node), once or in a loop (interval >= 1 s). Host request:
`delivery APPLIED`, `storage VOLATILE`, `queue_mode FIFO` (the Host allows LATEST / `coalesce_key` only with
BEST_EFFORT + VOLATILE), priority NORMAL, deadline (UTC, converted by the Host on its bound of the root clock) =
min(loop interval, 3 s): a ping is never kept, so rounds of a loop cannot pile up.

Payload: `u8 version = 1, u32 round`. The node application reports `lm_report_application_result(APPLIED)` at once, with
no result bytes. Alive = the operation ends APPLIED (evidence APP_APPLIED). RTT = `APP_APPLIED.observed_mono_ms -
ROOT_SENT.observed_mono_ms` (both on the root's clock; fall back to END_RECEIVED when APP_APPLIED has no time). The
current Host does not fill `observed_mono_ms`; fieldview then measures POST -> final event on the laptop and marks the
value as laptop-measured (it includes the Host's own latency).
A request the Host or root refuses (RATE_LIMITED, NO_CAPACITY, BUSY ...) is "not sent", counted apart from "no answer"
(EXPIRED / INDETERMINATE).

### 3.3 Display state (Host -> display), app_port 212

Payload: `u8 version = 1, u8 state (0 USABLE, 1 FORBID), u32 command_seq`. Host request: `delivery APPLIED`,
`storage VOLATILE`, `queue_mode FIFO`, priority NORMAL, deadline 10 s (UTC).

The display draws the state and, when the frame is on the panel, reports APPLIED; if it cannot draw, REJECTED. It
stores the last applied state and seq in NVS and shows it again after a restart (telemetry flags carry it). A node that
is not a display build answers REJECTED. "Arrived" (END_RECEIVED) and "drawn" (APP_APPLIED) are shown apart.

## 4. Panel (64 x 32)

- rows 0..7: status line in a 5x7 font: hop count and parent RSSI (`H2 -67`), or `JOIN` / `LOST` / `REVOKED`
- rows 8..23: main text, 16x16 glyphs, centred: USABLE = 使用可 in green, FORBID = 使用禁止 in red, no state yet = blank
- rows 30..31: status bar: green REACHABLE, blue not reachable / not a member, yellow joining

Only the five glyphs 使 用 可 禁 止 are embedded (16x16 bitmaps from the public-domain Shinonome font).

## 5. Laptop (tools/fieldview)

One process next to the Host, talking only to the Host API on its Unix socket (bearer token). It serves one local
page with no external scripts or fonts (fields have no Internet):

- topology: the root and every node as a tree from `GET /v1/nodes` (`parent_device_id`, `root_depth`), link colour by
  the child's parent RSSI and its telemetry loss; nodes the root lists but that send nothing are still drawn
- table per node: name (from the bench state file when present), chip, role, membership/connectivity, depth, parent
  RSSI, last telemetry age, telemetry loss % (from seq gaps), boots, ping result / RTT / loss %, display state
- ping: "ping all now" and a loop with an interval from 1 s; results per node and round
- display: pick a display, USABLE / FORBID, shows arrived / drawn
- log of joins, parent changes, losses, reboots (from MEMBERSHIP / node changes and telemetry)
- records per session under `logs/<session>/`: `telemetry.ndjson`, `ping.ndjson`, `display.ndjson`, `events.ndjson`
  (laptop UTC time on every line), and `summary.csv` (one row per node per 10 s)

## 6. SDK additions this needs

- `GET /v1/nodes`: `parent_device_id` (the node's approved parent in the root's tree; the root's own DeviceId for a
  direct child; absent when the node has no approved parent) and `root_depth` (1 = direct child of the root). Source:
  the root's topology, reported by serial NODE_QUERY.
- `lm_diagnostics_t.parent_rssi_dbm` with validity bit `LM_DIAGNOSTICS_VALID_PARENT_RSSI` (bit 22): RSSI of the last
  frame received from the node's current parent.
