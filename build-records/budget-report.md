# LeanMesh budget report (docs/16 + ADR-002 revised targets; a report, not a gate)

Commit `8668c69` (working tree dirty); python 3.12.3, c++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0.
Command: `scripts/budget_report.py --native-build /home/admister/.cache/leanmesh/native --idf-root /home/admister/.cache/leanmesh/build-final --out-dir build-records`

Software measurements only: sizeof from the compiler, static DRAM from the link map, image diff against
`build-records/T01-baseline-size.json`. No heap, stack, CPU or current was measured on a SoC.

## Summary of overruns (budget state at this commit)

- Fixed RAM over target: 12 of 12 SoC/profile builds (worst +13404 B, esp32s3 ROOT).
- Native estimate (sizeof + constants, not SoC evidence): 3 of 3 profiles over target (LEAF, RELAY, ROOT).
- Flash over the 256 KiB target: 12 of 12 builds, of which 4 are also over the 320 KiB review line (worst +158636 B over 256 KiB, esp32c6 ROOT).
- Crypto peak: OK; SDK SLOC: OVER.

## Fixed RAM (workspace + static DRAM of libleanmesh.a) vs revised targets

| SoC | profile | fixed RAM B | target B | over B | verdict | basis |
|---|---|---:|---:|---:|---|---|
| esp32c3 | LEAF | 59160 | 49152 | +10008 | OVER | link map of example_node/esp32c3 |
| esp32c3 | RELAY | 64584 | 57344 | +7240 | OVER | link map of example_node-RELAY/esp32c3 |
| esp32c3 | ROOT | 177228 | 163840 | +13388 | OVER | link map of example_node-ROOT/esp32c3 |
| esp32c5 | LEAF | 59160 | 49152 | +10008 | OVER | link map of example_node/esp32c5 |
| esp32c5 | RELAY | 64584 | 57344 | +7240 | OVER | link map of example_node-RELAY/esp32c5 |
| esp32c5 | ROOT | 177228 | 163840 | +13388 | OVER | link map of example_node-ROOT/esp32c5 |
| esp32c6 | LEAF | 59160 | 49152 | +10008 | OVER | link map of example_node/esp32c6 |
| esp32c6 | RELAY | 64584 | 57344 | +7240 | OVER | link map of example_node-RELAY/esp32c6 |
| esp32c6 | ROOT | 177228 | 163840 | +13388 | OVER | link map of example_node-ROOT/esp32c6 |
| esp32s3 | LEAF | 59168 | 49152 | +10016 | OVER | link map of example_node/esp32s3 |
| esp32s3 | RELAY | 64592 | 57344 | +7248 | OVER | link map of example_node-RELAY/esp32s3 |
| esp32s3 | ROOT | 177244 | 163840 | +13404 | OVER | link map of example_node-ROOT/esp32s3 |
| native-estimate | LEAF | 59112 | 49152 | +9960 | OVER | estimate (sizeof + stack/ring constants) |
| native-estimate | RELAY | 64536 | 57344 | +7192 | OVER | estimate (sizeof + stack/ring constants) |
| native-estimate | ROOT | 174256 | 163840 | +10416 | OVER | estimate (sizeof + stack/ring constants) |

## Flash: image minus empty IDF + ESP-NOW baseline (target 256 KiB, review line 320 KiB)

| SoC | profile | image B | baseline B | diff B | verdict | libleanmesh.a DRAM bss+data B | flash code+data B |
|---|---|---:|---:|---:|---|---:|---:|
| esp32c3 | LEAF | 1008550 | 707608 | 300942 | OVER | 17896 | 254276 |
| esp32c3 | RELAY | 1013992 | 707608 | 306384 | OVER | 19016 | 259718 |
| esp32c3 | ROOT | 1121340 | 707608 | 413732 | OVER-REVIEW-LINE | 50812 | 355360 |
| esp32c5 | LEAF | 1110649 | 803417 | 307232 | OVER | 17896 | 254256 |
| esp32c5 | RELAY | 1116091 | 803417 | 312674 | OVER | 19016 | 259698 |
| esp32c5 | ROOT | 1223407 | 803417 | 419990 | OVER-REVIEW-LINE | 50812 | 355340 |
| esp32c6 | LEAF | 1108261 | 801401 | 306860 | OVER | 17896 | 256972 |
| esp32c6 | RELAY | 1113783 | 801401 | 312382 | OVER | 19016 | 262494 |
| esp32c6 | ROOT | 1222181 | 801401 | 420780 | OVER-REVIEW-LINE | 50812 | 359208 |
| esp32s3 | LEAF | 946397 | 675460 | 270937 | OVER | 17904 | 223736 |
| esp32s3 | RELAY | 950593 | 675460 | 275133 | OVER | 19024 | 227958 |
| esp32s3 | ROOT | 1045709 | 675460 | 370249 | OVER-REVIEW-LINE | 50828 | 312224 |

## Crypto peak (target <= 24 KiB, separate from fixed RAM)

worker stack 8792 B + PSA heap 4368 B = 13160 B (OK); measured natively (x86-64 software model), tests/native/test_security (run now).

## First-party SLOC (non-blank, non-comment)

| group | SLOC | budget |
|---|---:|---|
| core | 27787 |  |
| idf | 1226 |  |
| root | 5038 |  |
| serial | 3181 |  |
| native-only | 1731 |  |
| tools | 3409 |  |
| tests | 20173 |  |
| vendor | 61493 |  |
| sdk (core+idf+root+serial) | 37232 | 28000 (OVER) |
| python host (excl. tests) | 4408 | 6000 |
| python host/tests | 5257 |  |

| module | group | SLOC |
|---|---|---:|
| src/core | core | 2093 |
| src/core/wire | core | 1417 |
| src/core/radio | core | 381 |
| src/core/link | core | 2586 |
| src/core/member | core | 4817 |
| src/core/route | core | 2134 |
| src/core/delivery | core | 5154 |
| src/core/sched | core | 227 |
| src/core/group | core | 1294 |
| src/core/channel | core | 1502 |
| src/core/power | core | 1974 |
| src/core/diag | core | 233 |
| src/core/ota | core | 320 |
| src/security | core | 2228 |
| src/store | core | 781 |
| src/capi | core | 646 |
| src/port/idf | idf | 1226 |
| src/root | root | 5038 |
| src/serial | serial | 3181 |
| src/port/sim | native-only | 1288 |
| src/hostnative | native-only | 443 |
| tools | tools | 3409 |
| tests/native | tests | 20173 |
| third_party | vendor | 61493 |

## B01 build evidence (4 targets, one pin)

IDF pin 76f5dedd9950a3012fee8fb7d5586df21fc67802; checkout 76f5dedd9950a3012fee8fb7d5586df21fc67802; same pin: True; all four SoCs built LEAF and ROOT: True; generated registry.hpp identical across builds: True.

| SoC | profiles built | registry.hpp hash |
|---|---|---|
| esp32s3 | leaf, relay, root | 0ebbb0f5c06e9005 |
| esp32c3 | leaf, relay, root | 0ebbb0f5c06e9005 |
| esp32c5 | leaf, relay, root | 0ebbb0f5c06e9005 |
| esp32c6 | leaf, relay, root | 0ebbb0f5c06e9005 |

Cannot show: that unsupported APIs return UNSUPPORTED instead of a fake success (review + tests do), runtime heap peaks, or that the images run on the SoC.

## sizeof per profile (native x86-64)

| object | LEAF | RELAY | ROOT |
|---|---:|---:|---:|
| ctx | 41848 | 46152 | 127160 |
| ctx.engine | 41832 | 46136 | 127144 |
| ctx.engine.app_events | 584 | 584 | 2216 |
| ctx.engine.chan | 456 | 456 | 456 |
| ctx.engine.coordinator | 1 | 1 | 1536 |
| ctx.engine.delivery | 16344 | 16344 | 61184 |
| ctx.engine.delivery.actives | 1120 | 1120 | 4480 |
| ctx.engine.delivery.durable | 1320 | 1320 | 3048 |
| ctx.engine.delivery.durable.journal | 448 | 448 | 448 |
| ctx.engine.delivery.end_sessions | 872 | 872 | 13832 |
| ctx.engine.delivery.fragments | 2134 | 2134 | 2358 |
| ctx.engine.delivery.hop | 464 | 464 | 464 |
| ctx.engine.delivery.in_entries | 4608 | 4608 | 18432 |
| ctx.engine.delivery.in_live | 240 | 240 | 720 |
| ctx.engine.delivery.msg_pool | 2048 | 2048 | 8192 |
| ctx.engine.delivery.ops | 1536 | 1536 | 6144 |
| ctx.engine.frames | 2424 | 3632 | 7256 |
| ctx.engine.group | 4192 | 4192 | 16504 |
| ctx.engine.group.ops | 1800 | 1800 | 7200 |
| ctx.engine.groups | 1 | 1 | 760 |
| ctx.engine.identity | 3992 | 3992 | 4464 |
| ctx.engine.identity.record_job | 1432 | 1432 | 1432 |
| ctx.engine.job_table | 92 | 92 | 92 |
| ctx.engine.ledger | 1 | 1 | 12280 |
| ctx.engine.link | 9464 | 11432 | 11432 |
| ctx.engine.link.exchange | 6488 | 6488 | 6488 |
| ctx.engine.link.exchange.handshake | 3592 | 3592 | 3592 |
| ctx.engine.link.exchange.handshake.edhoc_session | 2896 | 2896 | 2896 |
| ctx.engine.link.neighbors | 2280 | 4248 | 4248 |
| ctx.engine.membership | 1224 | 1224 | 1224 |
| ctx.engine.membership.join_pipe | 136 | 136 | 136 |
| ctx.engine.mesh | 992 | 992 | 992 |
| ctx.engine.peer_registry | 248 | 248 | 248 |
| ctx.engine.power | 760 | 1344 | 2872 |
| ctx.engine.proxy | 224 | 768 | 864 |
| ctx.engine.roles | 1232 | 1232 | 12288 |
| ctx.engine.routes | 1 | 1 | 3168 |
| ctx.engine.sched | 152 | 152 | 152 |
| ctx.engine.tx_manager | 120 | 120 | 120 |
| each.active | 280 | 280 | 280 |
| each.end_session | 216 | 216 | 216 |
| each.group_op | 1800 | 1800 | 1800 |
| each.group_target | 24 | 24 | 24 |
| each.in_entry | 144 | 144 | 144 |
| each.in_live | 40 | 40 | 40 |
| each.neighbor | 240 | 240 | 240 |
| each.op | 192 | 192 | 192 |
| each.power_member | 24 | 24 | 24 |
| each.session_keys | 144 | 144 | 144 |
| each.tx_frame | 296 | 296 | 296 |
| platform.radio | 2928 | 4048 | 7408 |
| platform.radio.rx_ring | 2800 | 3920 | 7280 |
| root.usb | 20744 | 20744 | 20744 |
| root.usb.link | 20256 | 20256 | 20256 |
