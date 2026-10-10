# Field display: ToF, K1 learning and K3 notification

This is a bench/field application, not KGuard safety logic or a LeanMesh core feature. Approved equipment: three Seengreat HUB75 S3 displays (one with TOF400C/VL53L1X), three XIAO C6 relays and three XIAO S3 relays, plus a separate root. Each display owns mesh, sensing and rendering on its own S3; no companion XIAO or UART renderer.

## Wiring and keys

- ToF uses I2C, not UART: SDA to labelled TX0 (GPIO43), SCL to RX0 (GPIO44), GND common and module supply appropriate to the actual TOF400C carrier (3.3 V for the bench configuration). Use proper I2C pull-ups; do not attach a 5 V pull-up. GPIO43 can emit UART boot output: sensor reset/download interaction is a hardware acceptance item. XSHUT is unassigned.
- Onboard PCA9557 is on SDA GPIO1 / SCL GPIO2, address 0x19, separate from the ToF bus (address 0x29). Input register 0, polarity 2, configuration 3. Configure only key bits as inputs and preserve other pins. K1 is active-low bit1, K3 active-low bit2, following the manufacturer's executable definitions. The example's printed K2/K3 labels contradict those definitions: physically verify K3 before field use; K2 does nothing.
- Debounce presses for 50 ms. One action per press; a key held during boot must be released first. Failed key reads are unknown, never fabricated presses. Sensor/key I/O has finite timeouts and its own application task, not the mesh owner or callbacks. Rendering/USB delays must not stop 40 ms sensor acquisition.
- All display builds have keys. ToF is enabled only in the dedicated `display-tof` build; ordinary `display` reports sensor disabled rather than vacant.

## Detection and K1

Use the KG `presence_v2` detector, not a new approximation. Provenance: MOVEI144/KG `b80ce46d63f7c1a5d36552f8ee38969b96cca412`, `firmware/common/{include/kguard_field/presence_v2.hpp,src/presence_v2.cpp}`. This owner-requested reuse does not assign an invented public license to KG code. Keep source attribution; broader distribution licensing remains with the rights holder. The Pololu/ST VL53L1X driver retains its BSD-3-Clause notices separately.

KG measurement settings: Long, timing budget 33000 us, period 40 ms, ROI 8x8, center 199. Only fresh, successful, mapped RangeValid samples in 100..4000 mm are evidence. Near means at least 150 mm nearer than the learned background: entry needs 8 supporting readings among the newest 11 classified readings; exit needs 10 background readings among the newest 12. Invalid/neither-class readings never prove absence. Unknown and last confirmed state are separate. Use KG display's 10000 ms no-sample fault setting.

K1 is the operator's assertion that nobody is in the sensing area. No automatic learning at boot/reconnect. Learn with KG's 3-second sliding window, sample-count and 90% validity checks, bounded spread, and 60-second timeout. Show learning, then done/failed. Another K1 while learning does not restart it. No sensor: show no sensor. For this test kit, calibration is RAM-only: after reboot it is unknown until K1; do not import KG's business ledger or silently persist an unconfirmed background. An existing background survives a failed relearn within the same boot.

The panel's learning labels are Japanese: 学習中, 完了, 失敗, using seven additional public-domain Shinonome glyphs. The communication animation uses a moving indicator and the distinct sending/received/not-sent/unconfirmed labels; it never modifies the bottom mesh bar.

## K3 and display evidence

One debounced K3 press makes one bounded notification, not a repeating stream. Send to ROOT_APP as RECEIVED / VOLATILE / FIFO / NORMAL, with a finite 30-second budget. Keep only one K3 operation in flight; additional presses while it is pending are counted as busy, never overwrite the operation. No route/root time or local refusal means not sent, not RF loss. Do not create a fresh operation to retry a transmitted notification.

The panel animates sending and shows confirmation only for the matching operation's END_RECEIVED. Acceptance, SENT and HOP_ACCEPTED are insufficient. The existing ROOT_APP receipt waits for the Host terminal-store acknowledgement: confirmation means Host DB received the notification, not browser display or human observation. After possible transmission, expiry/unknown means unconfirmed, not definitely undelivered. Completion feedback lasts briefly, then returns to normal display.

Learning/K3 feedback never changes the bottom mesh bar (rows 30..31). Display commands retain their own DMA evidence: a temporarily obscured command must be explicitly rendered before reporting APPLIED. No software claim that physical LEDs were measured.

Learning completion uses one bounded pending-result slot. Its three-second visible duration begins only after a matching result frame has passed DMA; it temporarily takes precedence over K3 animation. K1 is blocked while that result remains pending, so results cannot silently overwrite one another. Failed relearning keeps current presence unknown until fresh post-failure evidence has been evaluated; the old background is retained separately.

## Application messages (big-endian, version 1)

Existing ports 210..213 remain unchanged. These two new ports are application-only; do not add KG types to protocol/registry or Host contracts.

### Port 214: display sensor/key snapshot, 44 bytes

| Offset | Type | Field |
|---|---|---|
| 0 | u8 | version 1 |
| 1 | u8 | presence: 0 disabled, 1 unknown, 2 vacant, 3 occupied |
| 2 | u8 | learning: 0 idle/unlearned, 1 running, 2 done, 3 failed, 4 no sensor |
| 3 | u8 | flags: bit0 sensor ready, bit1 background valid, bit2 keys ready; others zero |
| 4 | u64 | random nonzero application boot ID (not Identity or a mesh generation) |
| 12 | u32 | snapshot sequence, nonzero, increasing per boot |
| 16 | u32 | snapshot capture uptime ms |
| 20 | u16 | sample age ms, 65535 unknown; saturate at 65534 |
| 22 | u16 | fresh valid distance mm, 65535 unknown |
| 24 | u16 | background mm, 65535 unlearned |
| 26 | u16 | background noise mm, 0 when unlearned |
| 28 | u32 | learning request number, 0 none |
| 32 | u32 | detector fault bits: sensor bit0, background bit1, learning bit2 |
| 36 | u32 | tracked K3 notification sequence corresponding to the result, 0 none (busy/dropped physical presses are diagnostic counters only) |
| 40 | u8 | K3 result: 0 idle, 1 sending, 2 confirmed, 3 not sent, 4 unconfirmed |
| 41 | 3 bytes | reserved zero |

Send a current snapshot on meaningful changes (presence/learning/fault/keys/K3), at most once per second, and refresh at least every 10 seconds while reachable. Only one snapshot send outstanding; newer pending state coalesces to the latest snapshot. Do not stream each range sample. No unlimited offline history. Sequence wrap is refused. Snapshot delivery is RECEIVED / VOLATILE / FIFO / NORMAL, deadline 30 seconds; a refused send is retried no sooner than one second.

### Port 215: K3 press notification, 20 bytes

| Offset | Type | Field |
|---|---|---|
| 0 | u8 | version 1 |
| 1 | u8 | button 3 |
| 2 | 2 bytes | reserved zero |
| 4 | u64 | same nonzero application boot ID |
| 12 | u32 | nonzero press sequence |
| 16 | u32 | actual debounced press uptime ms |

The browser records received notifications by full origin DeviceId plus boot ID and sequence. Redelivery does not create a second press. Host receipt UTC and node press uptime are different facts; backlog is history, never a fresh alert. Preserve an older received K3 record even if a newer sensor snapshot says not sent/unconfirmed: missing receipt evidence on the node does not invalidate Host reception.
Host receipt UTC is `MESSAGE_RECEIVED.received_utc`: the persisted `events.created_utc_ms` at which the Host journal recorded reception, not physical press time or exact COMMIT completion. Rereads, backlog and deduplicated redelivery retain that timestamp. Missing/null time stays unknown; browser observation time is never substituted. UTC reversal or inconsistent capture/sample timing is ambiguous and must not manufacture current occupancy or a fresh K3 alert.

## Browser and test gates

Add per-display presence (disabled/unknown/vacant/occupied), learning, sample age/distance, and K3 received time/count to the existing fieldview topology/table and event log. Unknown, disabled and stale are different. Presence becomes stale/unknown after 30 seconds without a fresh snapshot, on boot change, or journal gap; old backlog cannot manufacture current vacant. Tables remain capped at the existing 256-device limit. New records share the existing record/fsync-before-consumer-ACK discipline.

Known sample age exceeding capture uptime is impossible evidence and must not authorize current occupancy or a fresh alert. The unknown-age sentinel is exempt. A boot lasting long enough to wrap the u32 uptime (49.7 days) is outside this field-test wire contract: reports after wrap remain ambiguous rather than masquerading as new observations. K3 freshness expires against both receipt time and the explicitly estimated press time. Previous-boot or gap/clock-ambiguous history never regains fresh-alert status merely because newer snapshots arrive. Historical telemetry may provide a boot-comparison baseline during startup catch-up, never live presence by itself.

Regression gates: learning/entry/exit/dropout/timeout with KG detector, no boot learning, debounce/hold/NACK, key queue-full behavior, matching K3 end-receipt vs mere acceptance, stale/duplicate/backlog data, both display builds, relay builds and unchanged bottom bar. Host/meshsim proves the notification's real delivery path, not electrical I2C, optical performance, LEDs or RF. Physically verify key labels, sensor wiring/pull-ups, reset behavior, sampling under load, and the complete nine-node deployment separately.
