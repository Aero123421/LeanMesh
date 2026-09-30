# LeanMesh budget report (docs/16 + ADR-002 revised targets; a report, not a gate)

Commit `25849ed` (working tree dirty); python 3.12.3, c++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0.
Command: `scripts/budget_report.py --native-build /home/admister/.cache/leanmesh/native-arch2 --idf-root /home/admister/.cache/leanmesh/build-arch2 --out-dir build-records`

Software measurements only: sizeof from the compiler, static DRAM from the link map, image diff against
`build-records/T01-baseline-size.json`. No heap, stack, CPU or current was measured on a SoC.

## Fixed RAM (workspace + static DRAM of libleanmesh.a) vs revised targets

| SoC | profile | fixed RAM B | target B | over B | verdict | basis |
|---|---|---:|---:|---:|---|---|
| esp32c3 | LEAF | 58672 | 49152 | +9520 | OVER | link map of example_node/esp32c3 |
| esp32c3 | RELAY | 64096 | 57344 | +6752 | OVER | link map of example_node-RELAY/esp32c3 |
| esp32c3 | ROOT | 176324 | 163840 | +12484 | OVER | link map of example_node-ROOT/esp32c3 |
| esp32c5 | LEAF | 58672 | 49152 | +9520 | OVER | link map of example_node/esp32c5 |
| esp32c5 | RELAY | 64096 | 57344 | +6752 | OVER | link map of example_node-RELAY/esp32c5 |
| esp32c5 | ROOT | 176324 | 163840 | +12484 | OVER | link map of example_node-ROOT/esp32c5 |
| esp32c6 | LEAF | 58672 | 49152 | +9520 | OVER | link map of example_node/esp32c6 |
| esp32c6 | RELAY | 64096 | 57344 | +6752 | OVER | link map of example_node-RELAY/esp32c6 |
| esp32c6 | ROOT | 176324 | 163840 | +12484 | OVER | link map of example_node-ROOT/esp32c6 |
| esp32s3 | LEAF | 58680 | 49152 | +9528 | OVER | link map of example_node/esp32s3 |
| esp32s3 | RELAY | 64104 | 57344 | +6760 | OVER | link map of example_node-RELAY/esp32s3 |
| esp32s3 | ROOT | 176340 | 163840 | +12500 | OVER | link map of example_node-ROOT/esp32s3 |
| native-estimate | LEAF | 58624 | 49152 | +9472 | OVER | estimate (sizeof + stack/ring constants) |
| native-estimate | RELAY | 64048 | 57344 | +6704 | OVER | estimate (sizeof + stack/ring constants) |
| native-estimate | ROOT | 173360 | 163840 | +9520 | OVER | estimate (sizeof + stack/ring constants) |

## Flash: image minus empty IDF + ESP-NOW baseline (target 256 KiB, review line 320 KiB)

| SoC | profile | image B | baseline B | diff B | verdict | libleanmesh.a DRAM bss+data B | flash code+data B |
|---|---|---:|---:|---:|---|---:|---:|
| esp32c3 | LEAF | 991930 | 707608 | 284322 | OVER | 17896 | 247436 |
| esp32c3 | RELAY | 997492 | 707608 | 289884 | OVER | 19016 | 252998 |
| esp32c3 | ROOT | 1095740 | 707608 | 388132 | OVER-REVIEW-LINE | 50804 | 339540 |
| esp32c5 | LEAF | 1093883 | 803417 | 290466 | OVER | 17896 | 247416 |
| esp32c5 | RELAY | 1099445 | 803417 | 296028 | OVER | 19016 | 252978 |
| esp32c5 | ROOT | 1197671 | 803417 | 394254 | OVER-REVIEW-LINE | 50804 | 339520 |
| esp32c6 | LEAF | 1091061 | 801401 | 289660 | OVER | 17896 | 250122 |
| esp32c6 | RELAY | 1096665 | 801401 | 295264 | OVER | 19016 | 255726 |
| esp32c6 | ROOT | 1196013 | 801401 | 394612 | OVER-REVIEW-LINE | 50804 | 343390 |
| esp32s3 | LEAF | 930713 | 675460 | 255253 | OK | 17904 | 217735 |
| esp32s3 | RELAY | 935089 | 675460 | 259629 | OK | 19024 | 222120 |
| esp32s3 | ROOT | 1022557 | 675460 | 347097 | OVER-REVIEW-LINE | 50820 | 298911 |

## Crypto peak (target <= 24 KiB, separate from fixed RAM)

worker stack 8792 B + PSA heap 4368 B = 13160 B (OK); measured natively (x86-64 software model), tests/native/test_security (run now).

## First-party SLOC (non-blank, non-comment)

| group | SLOC | budget |
|---|---:|---|
| core | 26982 |  |
| idf | 1189 |  |
| root | 4324 |  |
| serial | 3167 |  |
| native-only | 1672 |  |
| tools | 3399 |  |
| tests | 18131 |  |
| vendor | 61493 |  |
| sdk (core+idf+root+serial) | 35662 | 28000 (OVER) |
| python host (excl. tests) | 4224 | 6000 |
| python host/tests | 4897 |  |

| module | group | SLOC |
|---|---|---:|
| src/core | core | 1906 |
| src/core/wire | core | 1417 |
| src/core/radio | core | 381 |
| src/core/link | core | 2586 |
| src/core/member | core | 4619 |
| src/core/route | core | 2119 |
| src/core/delivery | core | 5078 |
| src/core/sched | core | 227 |
| src/core/group | core | 1298 |
| src/core/channel | core | 1293 |
| src/core/power | core | 1898 |
| src/core/diag | core | 231 |
| src/core/ota | core | 320 |
| src/security | core | 2228 |
| src/store | core | 780 |
| src/capi | core | 601 |
| src/port/idf | idf | 1189 |
| src/root | root | 4324 |
| src/serial | serial | 3167 |
| src/port/sim | native-only | 1229 |
| src/hostnative | native-only | 443 |
| tools | tools | 3399 |
| tests/native | tests | 18131 |
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
| ctx | 41360 | 45664 | 126272 |
| ctx.engine | 41344 | 45648 | 126256 |
| ctx.engine.app_events | 584 | 584 | 2216 |
| ctx.engine.chan | 368 | 368 | 368 |
| ctx.engine.coordinator | 1 | 1 | 1504 |
| ctx.engine.delivery | 16312 | 16312 | 61056 |
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
| ctx.engine.groups | 1 | 1 | 648 |
| ctx.engine.identity | 3992 | 3992 | 4464 |
| ctx.engine.identity.record_job | 1432 | 1432 | 1432 |
| ctx.engine.job_table | 92 | 92 | 92 |
| ctx.engine.ledger | 1 | 1 | 12112 |
| ctx.engine.link | 9472 | 11440 | 11440 |
| ctx.engine.link.exchange | 6496 | 6496 | 6496 |
| ctx.engine.link.exchange.handshake | 3592 | 3592 | 3592 |
| ctx.engine.link.exchange.handshake.edhoc_session | 2896 | 2896 | 2896 |
| ctx.engine.link.neighbors | 2280 | 4248 | 4248 |
| ctx.engine.membership | 1216 | 1216 | 1216 |
| ctx.engine.membership.join_pipe | 136 | 136 | 136 |
| ctx.engine.mesh | 992 | 992 | 992 |
| ctx.engine.peer_registry | 248 | 248 | 248 |
| ctx.engine.power | 744 | 1328 | 2856 |
| ctx.engine.proxy | 224 | 768 | 864 |
| ctx.engine.roles | 1224 | 1224 | 12120 |
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
| root.usb | 20736 | 20736 | 20736 |
| root.usb.link | 20248 | 20248 | 20248 |
