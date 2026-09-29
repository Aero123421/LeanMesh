# LeanMesh budget report (docs/16 + ADR-002 revised targets; a report, not a gate)

Commit `3a195ce` (working tree dirty); python 3.12.3, c++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0.
Command: `scripts/budget_report.py --native-build /home/admister/.cache/leanmesh/native-s19 --idf-root /home/admister/.cache/leanmesh/build-s19 --out-dir build-records`

Software measurements only: sizeof from the compiler, static DRAM from the link map, image diff against
`build-records/T01-baseline-size.json`. No heap, stack, CPU or current was measured on a SoC.

## Fixed RAM (workspace + static DRAM of libleanmesh.a) vs revised targets

| SoC | profile | fixed RAM B | target B | over B | verdict | basis |
|---|---|---:|---:|---:|---|---|
| esp32c3 | LEAF | 59592 | 49152 | +10440 | OVER | link map of example_node/esp32c3 |
| esp32c3 | RELAY | 65000 | 57344 | +7656 | OVER | link map of example_node-RELAY/esp32c3 |
| esp32c3 | ROOT | 169572 | 163840 | +5732 | OVER | link map of example_node-ROOT/esp32c3 |
| esp32c5 | LEAF | 59592 | 49152 | +10440 | OVER | link map of example_node/esp32c5 |
| esp32c5 | RELAY | 64360 | 57344 | +7016 | OVER | estimate (sizeof + stack/ring constants) |
| esp32c5 | ROOT | 169572 | 163840 | +5732 | OVER | link map of example_node-ROOT/esp32c5 |
| esp32c6 | LEAF | 59592 | 49152 | +10440 | OVER | link map of example_node/esp32c6 |
| esp32c6 | RELAY | 64360 | 57344 | +7016 | OVER | estimate (sizeof + stack/ring constants) |
| esp32c6 | ROOT | 169572 | 163840 | +5732 | OVER | link map of example_node-ROOT/esp32c6 |
| esp32s3 | LEAF | 59600 | 49152 | +10448 | OVER | link map of example_node/esp32s3 |
| esp32s3 | RELAY | 64360 | 57344 | +7016 | OVER | estimate (sizeof + stack/ring constants) |
| esp32s3 | ROOT | 169588 | 163840 | +5748 | OVER | link map of example_node-ROOT/esp32s3 |
| native-estimate | LEAF | 59520 | 49152 | +10368 | OVER | estimate (sizeof + stack/ring constants) |
| native-estimate | RELAY | 64928 | 57344 | +7584 | OVER | estimate (sizeof + stack/ring constants) |
| native-estimate | ROOT | 166616 | 163840 | +2776 | OVER | estimate (sizeof + stack/ring constants) |

## Flash: image minus empty IDF + ESP-NOW baseline (target 256 KiB, review line 320 KiB)

| SoC | profile | image B | baseline B | diff B | verdict | libleanmesh.a DRAM bss+data B | flash code+data B |
|---|---|---:|---:|---:|---|---:|---:|
| esp32c3 | LEAF | 984056 | 707608 | 276448 | OVER | 17896 | 239618 |
| esp32c3 | RELAY | 989622 | 707608 | 282014 | OVER | 19016 | 245184 |
| esp32c3 | ROOT | 1080748 | 707608 | 373140 | OVER-REVIEW-LINE | 51908 | 324612 |
| esp32c5 | LEAF | 1086009 | 803417 | 282592 | OVER | 17896 | 239598 |
| esp32c5 | ROOT | 1182679 | 803417 | 379262 | OVER-REVIEW-LINE | 51908 | 324592 |
| esp32c6 | LEAF | 1083503 | 801401 | 282102 | OVER | 17896 | 242620 |
| esp32c6 | ROOT | 1181293 | 801401 | 379892 | OVER-REVIEW-LINE | 51908 | 328742 |
| esp32s3 | LEAF | 924165 | 675460 | 248705 | OK | 17904 | 211247 |
| esp32s3 | ROOT | 1009989 | 675460 | 334529 | OVER-REVIEW-LINE | 51924 | 286552 |

## Crypto peak (target <= 24 KiB, separate from fixed RAM)

worker stack 8792 B + PSA heap 4368 B = 13160 B (OK); measured natively (x86-64 software model), tests/native/test_security (run now).

## First-party SLOC (non-blank, non-comment)

| group | SLOC | budget |
|---|---:|---|
| core | 26469 |  |
| idf | 1189 |  |
| root | 3936 |  |
| serial | 3142 |  |
| native-only | 1669 |  |
| tools | 3171 |  |
| tests | 14955 |  |
| vendor | 61493 |  |
| sdk (core+idf+root+serial) | 34736 | 28000 (OVER) |
| python host (excl. tests) | 4199 | 6000 |
| python host/tests | 4507 |  |

| module | group | SLOC |
|---|---|---:|
| src/core | core | 1736 |
| src/core/wire | core | 1427 |
| src/core/radio | core | 381 |
| src/core/link | core | 2542 |
| src/core/member | core | 4193 |
| src/core/route | core | 2189 |
| src/core/delivery | core | 5002 |
| src/core/sched | core | 227 |
| src/core/group | core | 1293 |
| src/core/channel | core | 1340 |
| src/core/power | core | 1928 |
| src/core/diag | core | 231 |
| src/core/ota | core | 320 |
| src/security | core | 2263 |
| src/store | core | 767 |
| src/capi | core | 630 |
| src/port/idf | idf | 1189 |
| src/root | root | 3936 |
| src/serial | serial | 3142 |
| src/port/sim | native-only | 1229 |
| src/hostnative | native-only | 440 |
| tools | tools | 3171 |
| tests/native | tests | 14955 |
| third_party | vendor | 61493 |

## B01 build evidence (4 targets, one pin)

IDF pin 76f5dedd9950a3012fee8fb7d5586df21fc67802; checkout 76f5dedd9950a3012fee8fb7d5586df21fc67802; same pin: True; all four SoCs built LEAF and ROOT: True; generated registry.hpp identical across builds: True.

| SoC | profiles built | registry.hpp hash |
|---|---|---|
| esp32s3 | leaf, root | 0ebbb0f5c06e9005 |
| esp32c3 | leaf, relay, root | 0ebbb0f5c06e9005 |
| esp32c5 | leaf, root | 0ebbb0f5c06e9005 |
| esp32c6 | leaf, root | 0ebbb0f5c06e9005 |

Cannot show: that unsupported APIs return UNSUPPORTED instead of a fake success (review + tests do), runtime heap peaks, or that the images run on the SoC.

## sizeof per profile (native x86-64)

| object | LEAF | RELAY | ROOT |
|---|---:|---:|---:|
| ctx | 42256 | 46544 | 118440 |
| ctx.engine | 42240 | 46528 | 118424 |
| ctx.engine.app_events | 584 | 584 | 2216 |
| ctx.engine.chan | 368 | 368 | 368 |
| ctx.engine.coordinator | 1 | 1 | 1504 |
| ctx.engine.delivery | 17840 | 17840 | 62968 |
| ctx.engine.delivery.actives | 1120 | 1120 | 4480 |
| ctx.engine.delivery.durable | 2728 | 2728 | 4456 |
| ctx.engine.delivery.durable.boot_job | 1440 | 1440 | 1440 |
| ctx.engine.delivery.durable.journal | 448 | 448 | 448 |
| ctx.engine.delivery.end_sessions | 872 | 872 | 13832 |
| ctx.engine.delivery.fragments | 2134 | 2134 | 2358 |
| ctx.engine.delivery.hop | 464 | 464 | 464 |
| ctx.engine.delivery.in_entries | 4608 | 4608 | 18432 |
| ctx.engine.delivery.in_live | 240 | 240 | 720 |
| ctx.engine.delivery.msg_pool | 2048 | 2048 | 8192 |
| ctx.engine.delivery.ops | 1664 | 1664 | 6656 |
| ctx.engine.frames | 2424 | 3632 | 7256 |
| ctx.engine.group | 3680 | 3680 | 6136 |
| ctx.engine.group.ops | 1288 | 1288 | 5152 |
| ctx.engine.groups | 1 | 1 | 648 |
| ctx.engine.identity | 3984 | 3984 | 4456 |
| ctx.engine.identity.record_job | 1432 | 1432 | 1432 |
| ctx.engine.job_table | 92 | 92 | 92 |
| ctx.engine.ledger | 1 | 1 | 11696 |
| ctx.engine.link | 9472 | 11440 | 11440 |
| ctx.engine.link.exchange | 6496 | 6496 | 6496 |
| ctx.engine.link.exchange.handshake | 3592 | 3592 | 3592 |
| ctx.engine.link.exchange.handshake.edhoc_session | 2896 | 2896 | 2896 |
| ctx.engine.link.neighbors | 2280 | 4248 | 4248 |
| ctx.engine.membership | 1160 | 1160 | 1160 |
| ctx.engine.membership.join_pipe | 136 | 136 | 136 |
| ctx.engine.mesh | 960 | 960 | 960 |
| ctx.engine.peer_registry | 248 | 248 | 248 |
| ctx.engine.power | 736 | 1320 | 2848 |
| ctx.engine.proxy | 200 | 728 | 792 |
| ctx.engine.routes | 1 | 1 | 3168 |
| ctx.engine.sched | 160 | 160 | 160 |
| ctx.engine.tx_manager | 120 | 120 | 120 |
| each.active | 280 | 280 | 280 |
| each.end_session | 216 | 216 | 216 |
| each.group_op | 1288 | 1288 | 1288 |
| each.group_target | 16 | 16 | 16 |
| each.in_entry | 144 | 144 | 144 |
| each.in_live | 40 | 40 | 40 |
| each.neighbor | 240 | 240 | 240 |
| each.op | 208 | 208 | 208 |
| each.power_member | 24 | 24 | 24 |
| each.session_keys | 144 | 144 | 144 |
| each.tx_frame | 296 | 296 | 296 |
| platform.radio | 2928 | 4048 | 7408 |
| platform.radio.rx_ring | 2800 | 3920 | 7280 |
| root.usb | 21824 | 21824 | 21824 |
| root.usb.link | 21336 | 21336 | 21336 |
