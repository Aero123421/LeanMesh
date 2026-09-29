# 調査・一次資料台帳

この資料のURLと固定SHAは再調査の入口です。文書中の `[E01]` / `[RL-196]` 等は下記ID。Issueの古い本文を現在の実装の欠陥と自動認定せず、要望・履歴・コード・計画を区別しました。

KG `4ed3e1ff0e63eec54c52e89444e18b2a18be2130` / RouteLoom `77b5792669fefee13498ef29a3c2e48119c562a0`。調査対象に2026-09-28 20:37 JSTのKG #112追記を含む。

## USER — 利用者が指定した要求
種別: `user_requirement`。
汎用長距離Wi-Fi、4SoC、rootから20hop、自動channel、Join/移設、Python/FastAPI、小容量/低負荷/安定。
参照: conversation:current

## E01 — Espressif ESP32-C6 Wi-Fi
種別: `primary_external`。
C6のESP-NOW/LR能力確認。選定pin6.0.3での実機認定を意味しない。
参照: https://docs.espressif.com/projects/esp-idf/en/v5.3.1/esp32c6/api-guides/wifi.html

## E02 — Espressif ESP32-C5 Wi-Fi
種別: `primary_external`。
C5の2.4GHzとLRの条件。5GHzを混在Mesh共通経路にしない。stable URLは後で変わり得る。
参照: https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-guides/wifi-driver/overview.html

## E03 — Espressif ESP-NOW
種別: `primary_external`。
v1/v2 payload・peer数・callback/PHY設定。LMは250B互換基準。20peerと網の20hopは別。
参照: https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-reference/network/esp_now.html

## E04 — RFC9528 EDHOC
種別: `primary_external`。
method/suite、credentials、Exporter private-use範囲とEAD registryを確認。LM専用recordは別レビュー。
参照: https://www.rfc-editor.org/rfc/rfc9528.html

## E05 — RFC9529 EDHOC traces
種別: `primary_external`。
実装時の公式trace照合元。今回そのEDHOC試験を実行したという意味ではない。
参照: https://www.rfc-editor.org/rfc/rfc9529.html

## E06 — Espressif RNG
種別: `primary_external`。
真性entropy供給条件を満たして生成する。静的testseedは製品禁止。
参照: https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/system/random.html

## E07 — Espressif OTA
種別: `primary_external`。
複数partition・rollback・valid確認の公式挙動。4MiB計画の実機試験は未実施。
参照: https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/system/ota.html

## E08 — FastAPI lifespan
種別: `primary_external`。
起動/停止資源管理の公式境界。1worker/singletonはこの仕様の設計決定。
参照: https://fastapi.tiangolo.com/advanced/events/

## E09 — SQLite WAL
種別: `primary_external`。
WAL・同一ホスト・永続化条件。現場配備時の実SQLite版/修正状況を別に固定する。
参照: https://sqlite.org/wal.html

## E10 — COSE RFC9052
種別: `primary_external`。
署名objectの構造。公開testkeyでのfixtureは認証システムの監査ではない。
参照: https://www.rfc-editor.org/rfc/rfc9052.html

## E11 — CBOR RFC8949
種別: `primary_external`。
§4.2.1 core deterministic encoding。length-first方式と混同しない。
参照: https://www.rfc-editor.org/rfc/rfc8949.html

## E12 — SQLite STRICT
種別: `primary_external`。
STRICT tableが3.37以降であること。今回実行版はVALIDATIONに記録。
参照: https://sqlite.org/stricttables.html

## E13 — SQLite synchronous
種別: `primary_external`。
WAL/FULL、commit前後の電源断条件の参照。OS/ストレージのflush保証は実機別。
参照: https://sqlite.org/pragma.html#pragma_synchronous

## KG-CODE-01 — KG Transport
種別: `source_code_or_repository_doc`。固定点: `4ed3e1ff0e63eec54c52e89444e18b2a18be2130`。
読取範囲 1–99: EventFrame未認証、Route非再使用、SendWrittenはserial Writeのみ。
参照: https://github.com/MOVEI144/KG/blob/4ed3e1ff0e63eec54c52e89444e18b2a18be2130/apps/edge-go/internal/displaylink/transport.go

## KG-CODE-02 — KG Go README
種別: `source_code_or_repository_doc`。固定点: `4ed3e1ff0e63eec54c52e89444e18b2a18be2130`。
読取範囲 1–160: 9/27現行Go sitecore、S3親機、RouteLoom未同梱と旧計画の区別。
参照: https://github.com/MOVEI144/KG/blob/4ed3e1ff0e63eec54c52e89444e18b2a18be2130/apps/edge-go/README.md

## RL-CODE-01 — RouteLoom public C header
種別: `source_code_or_repository_doc`。固定点: `77b5792669fefee13498ef29a3c2e48119c562a0`。
読取範囲 1–160: C ABIのAPPLIED未提供とC++との差、128B/250B制限、版付き構造。
参照: https://github.com/MOVEI144/RouteLoom/blob/77b5792669fefee13498ef29a3c2e48119c562a0/components/routeloom/include/routeloom/routeloom.h

## RL-CODE-02 — RouteLoom SiteStore
種別: `source_code_or_repository_doc`。固定点: `77b5792669fefee13498ef29a3c2e48119c562a0`。
読取範囲 480–590: 異site拒否と世代/floor・commit順序。移設ではこの検査を単純削除しない。
参照: https://github.com/MOVEI144/RouteLoom/blob/77b5792669fefee13498ef29a3c2e48119c562a0/components/routeloom/src/sdkv1_store.cpp

## RL-CODE-03 — RouteLoom ESP-NOW owner
種別: `source_code_or_repository_doc`。固定点: `77b5792669fefee13498ef29a3c2e48119c562a0`。
読取範囲 1–170: drivererror分類、単一owner、peer/返信予約。全120kBを精査したとは扱わない。
参照: https://github.com/MOVEI144/RouteLoom/blob/77b5792669fefee13498ef29a3c2e48119c562a0/components/routeloom_espnow/src/espnow_runtime.cpp

## RL-CODE-04 — RouteLoom vendor manifest
種別: `source_code_or_repository_doc`。固定点: `77b5792669fefee13498ef29a3c2e48119c562a0`。
読取範囲 1–180: libedhoc pin/MIT/末尾byte検査patch。巨大化を理由に既知の厳密decodeを削らない。
参照: https://github.com/MOVEI144/RouteLoom/blob/77b5792669fefee13498ef29a3c2e48119c562a0/components/routeloom/third_party/VENDORED.json

## KG-16 — KG Issue #16
種別: `request_or_historical_issue`。
QRと予備機の単体追加/交換。開発PC必須を避ける。
参照: https://github.com/MOVEI144/KG/issues/16

## KG-15 — KG Issue #15
種別: `request_or_historical_issue`。
移設時の旧校正の無効化。SDKではなくアプリのbinding責務。
参照: https://github.com/MOVEI144/KG/issues/15

## KG-9 — KG Issue #9
種別: `request_or_historical_issue`。
通信断と安全上の禁止状態を分離。古い業務状態を無期限保証しない。
参照: https://github.com/MOVEI144/KG/issues/9

## KG-10 — KG Issue #10
種別: `request_or_historical_issue`。
cloud断時の履歴保持と復旧同期。有限容量を明記。
参照: https://github.com/MOVEI144/KG/issues/10

## KG-25 — KG Issue #25
種別: `request_or_historical_issue`。
言語間契約fixture。
参照: https://github.com/MOVEI144/KG/issues/25

## KG-29 — KG Issue #29
種別: `request_or_historical_issue`。
小さいDeviceLink/Transport境界。
参照: https://github.com/MOVEI144/KG/issues/29

## KG-41 — KG Issue #41
種別: `request_or_historical_issue`。
取消・上書き・期限・遅いACKの整合。
参照: https://github.com/MOVEI144/KG/issues/41

## KG-44 — KG Issue #44
種別: `request_or_historical_issue`。
表示系の健康状態と無線onlineの分離。
参照: https://github.com/MOVEI144/KG/issues/44

## KG-76 — KG Issue #76
種別: `request_or_historical_issue`。
asset/installation/roleと本人認証を分離。
参照: https://github.com/MOVEI144/KG/issues/76

## KG-100 — KG Issue #100
種別: `request_or_historical_issue`。
9/23デモの固定スター案は履歴。20hop仕様の上限根拠にしない。
参照: https://github.com/MOVEI144/KG/issues/100

## KG-109 — KG Issue #109
種別: `request_or_historical_issue`。
10台の自己形成、relay停止、全台復電、表示盤連動。10台は10hopを意味しない。
参照: https://github.com/MOVEI144/KG/issues/109

## KG-112 — KG Issue #112
種別: `request_or_historical_issue`。
9/26統合評価は過去時点。最新コメントを優先して意味を照合。
参照: https://github.com/MOVEI144/KG/issues/112

## KG-112-NEW — KG #112 2026-09-28追記
種別: `dated_plan`。固定点: `2026-09-28T11:37:09Z`。
20:37 JST。4SoC、DeviceAPI、optional4KiB、移設、occ/latest・tr/event、S3USB、IDF/binary/adaptorの導入計画。実装完了ではない。
参照: https://github.com/MOVEI144/KG/issues/112#issuecomment-5869076509

## RL-191 — RouteLoom Issue #191
種別: `request_or_issue_report`。
公開C/C++ Device APIとlifecycle/APPLIEDの不足。
参照: https://github.com/MOVEI144/RouteLoom/issues/191

## RL-192 — RouteLoom Issue #192
種別: `request_or_issue_report`。
所属とreachabilityの独立状態。
参照: https://github.com/MOVEI144/RouteLoom/issues/192

## RL-193 — RouteLoom Issue #193
種別: `request_or_issue_report`。
Join cooldown/拒否の硬直化。設定revisionとbounded再探索。
参照: https://github.com/MOVEI144/RouteLoom/issues/193

## RL-194 — RouteLoom Issue #194
種別: `request_or_issue_report`。
KG固有語彙/decision_modeやgroup実装の汎用性。
参照: https://github.com/MOVEI144/RouteLoom/issues/194

## RL-195 — RouteLoom Issue #195
種別: `request_or_issue_report`。
送信受付・latest・group予算の一貫性。
参照: https://github.com/MOVEI144/RouteLoom/issues/195

## RL-196 — RouteLoom Issue #196
種別: `request_or_issue_report`。
旧rootが停止した機器の現場間移設、旧siteguard、A→B→A。
参照: https://github.com/MOVEI144/RouteLoom/issues/196

## RL-197 — RouteLoom Issue #197
種別: `request_or_issue_report`。
listen→hint→本手続きという賢いJoin案。認可の代替にはしない。
参照: https://github.com/MOVEI144/RouteLoom/issues/197

## RL-199 — RouteLoom Issue #199
種別: `request_or_issue_report`。
コード/flash/RAM/処理負荷の抜本見直し要望。投稿中のサイズ数値は本作業で再測定していない。
参照: https://github.com/MOVEI144/RouteLoom/issues/199

## RL-176 — RouteLoom Issue #176
種別: `request_or_issue_report`。
閉じた参加方針のrelay伝播と適用証拠。
参照: https://github.com/MOVEI144/RouteLoom/issues/176

## RL-101 — RouteLoom Issue #101
種別: `request_or_issue_report`。
曖昧なgrant/opaque承認ticketを具体契約へ。
参照: https://github.com/MOVEI144/RouteLoom/issues/101

## RL-179 — RouteLoom Issue #179
種別: `request_or_issue_report`。
4KiB級fragmentation/reassemblyの要求。
参照: https://github.com/MOVEI144/RouteLoom/issues/179

## RL-171 — RouteLoom Issue #171
種別: `request_or_issue_report`。
署名OTA、2面partition、更新/rollbackの課題。
参照: https://github.com/MOVEI144/RouteLoom/issues/171

## RL-169 — RouteLoom Issue #169
種別: `request_or_issue_report`。
relay-firstからNO_ROUTEに陥る実機事例。C6対象外という当時の方針はsilicon非対応の証拠ではない。
参照: https://github.com/MOVEI144/RouteLoom/issues/169

## RL-168 — RouteLoom Issue #168
種別: `request_or_issue_report`。
revoke/GK/cutoverの実機失敗。closeだけで実機再試験合格を推測しない。
参照: https://github.com/MOVEI144/RouteLoom/issues/168

## RL-202 — RouteLoom PR #202
種別: `merged_test_change`。固定点: `77b5792669fefee13498ef29a3c2e48119c562a0`。
real-Ownerソフトウェアharnessのroute-loss試験追加。test-onlyでRF/HILの代用ではない。
参照: https://github.com/MOVEI144/RouteLoom/pull/202

## RL-201 — RouteLoom PR #201
種別: `merged_software_change`。
失効拒否と通知の分離・tree順cutover。実機再試験は別。
参照: https://github.com/MOVEI144/RouteLoom/pull/201

## RL-PLAN — RouteLoomの最新導入計画（KG側への報告）
種別: `dated_plan`。固定点: `2026-09-28T11:37:09Z`。
計画として4SoCを採用。mainの実装/資格状態と区別。
参照: https://github.com/MOVEI144/KG/issues/112#issuecomment-5869076509

## spec0.2追加の一次資料

元のKG/RouteLoomの固定参照は維持。本改訂ではGitHub最新HEADを再取得していない。下記stableページは確認時にv6.0.2表記を返した。製品pin6.0.3の成立は依然G1/G2の検証入力。

- **E-PWR-01** [Espressif ESP-NOW / ESP32-C6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/network/esp_now.html) — STA power-save wake window and interval; disconnected-PM condition; callbacks must remain short.
- **E-PWR-02** [Espressif Sleep modes / ESP32-C3](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/system/sleep_modes.html) — Light-sleep RAM retention vs Deep-sleep shutdown; manual wireless shutdown vs automatic driver-managed sleep; RTC/GPIO constraints.
- **E-PWR-03** [Espressif Power management / ESP32-S3](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/system/power_management.html) — DFS and automatic Light-sleep depend on PM locks and Tickless Idle; nearest wake deadline and timer behavior.
- **E-PWR-04** [Espressif connectionless power save / ESP32-C6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-guides/wifi-driver/wifi-performance-and-power-save.html) — Connectionless window/interval and runtime Wi-Fi memory/power behavior; target qualification required.

**USER-REV2**: この会話の追加要件。小さい・安定・軽い・長距離・省電力を汎用SDKとして両立し、全量ZIPで渡す。
