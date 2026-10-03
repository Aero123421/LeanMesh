# 実機試験の記録 — 2026-10-03（最初のベンチ）

Issue #6 の最初の一巡。試験用ファーム（`firmware/hil_node`）と試験用 fleet で行った**ベンチ試験**の記録で、製品の認定ではない。
NVS は平文、RF 承認はベンチ用、鍵は試験用 fleet（`tools/hil/hil.py init` で新規生成）。

## 構成

| 役割 | ボード / チップ | 備考 |
|---|---|---|
| Root | ESP32-S3（Flash 8MB、PSRAM 8MB、USB-Serial/JTAG） | Host（macOS、Python 3.12）と USB |
| Relay | Seeed XIAO ESP32C6（ESP32-C6FH4） | RF スイッチのボード設定が必要（下記） |
| Leaf | Seeed XIAO ESP32C6（ESP32-C6FH4） | 同上 |
| Leaf | ESP32-C3（C3FH4） | |
| Leaf（途中で外した） | ESP32-S3 | 最初の 1 対 1 試験 |

ESP-IDF v6.0.3（`76f5ded`）、チャネル 1、JP、机上（数十 cm）。距離・干渉・消費電流は測っていない。

## 手順（再現）

```sh
scripts/hil.sh build root            # leaf / relay、第 3 引数で target（esp32c3 / esp32c6）
scripts/hil.sh flash root <port>     # 全消去して書込み。update は app だけ（身分証を残す）
PYTHONPATH=host ~/.cache/leanmesh/host-venv/bin/python tools/hil/hil.py init
... hil.py provision root --port <root port>
... hil.py provision leaf --port <port> --name <name>      # relay も leaf と同じ（role だけ違う）
# Host を LEANMESH_SERIAL=<root port> で起動（hil.py host-env）
... hil.py cmd --port <leaf port> join ; hil.py approve ; hil.py host-send <name> "text"
```

鍵は各ボードの中で PSA が生成し（`lmb_keygen`、RF 前なので bootloader の entropy source を有効にして生成）、PC に出るのは公開鍵だけ。

## 結果

| # | 項目 | 結果 |
|---|---|---|
| 1 | 機器内での鍵生成と記録の書込み（S3 / C3 / C6） | 合格 |
| 2 | Host ↔ Root の USB セッション（EDHOC purpose 3） | 合格 |
| 3 | Join（Host の承認） | 合格（S3 / C6 / C3） |
| 4 | Join（CommissioningWindow + ExpectedSet、承認なし） | 合格（C6）。Host の POLICY_SET では preapproved にできない（下記 F5） |
| 5 | Host → node 配送 | 合格。全例で ROOT_* → HOP_ACCEPTED(LINK_VERIFIED) → END_RECEIVED(END_VERIFIED) |
| 6 | node → Host 配送 | 合格（MESSAGE_RECEIVED、END_VERIFIED） |
| 7 | node → node 配送（C3 → C6） | 合格 |
| 8 | 中継（2 段） | 合格（C3 が C6 relay 経由 depth=2 で Host と往復） |
| 9 | 2 段で 25 通連続（Host → C3） | 25/25 RECEIVED、約 30 秒 |
| 10 | 一斉配信（group 7、3 台） | 合格（3 target とも RECEIVED） |
| 11 | Leaf の再起動 | 合格。14 秒で同じ DeviceId・membership に復帰、再承認なし |
| 12 | Root の再起動 | 合格。Host は自動再接続、members は新 term に追随（138 秒） |
| 13 | 失効（fleet 署名 RevokeObject） | 合格。対象は MEMBER_REVOKED、送受信とも止まる（F6） |
| 14 | 省電力 WINDOWED_RX（5 s / 250 ms） | 配送遅延 0.7 s → 3.7〜9.8 s、全通 RECEIVED。USB は使えなくなる（F7） |
| 15 | チャネル再計算 | survey は開始。机上で変更なし（変える理由がない）。切替は未確認 |
| 16 | 移設（TRANSFER） | 未実施（移設用 ticket を発行する CLI が無い） |

### 実測した資源（試験終了時点の最小値）

| ボード | heap 最小空き | SDK task stack 最小空き |
|---|---:|---:|
| Root S3 | 約 83 KB | 3.2〜4.5 KB |
| Leaf S3 | 約 196 KB | 3.2 KB |
| Relay C6 | 約 226 KB | 4.2 KB |
| Leaf C6 | 約 231 KB | 4.2 KB |
| Leaf C3 | 約 133 KB | 3.8 KB |

## 見つかった問題

| # | 内容 | 状態 |
|---|---|---|
| F1 | owner task の stack 4096 B が不足（S3 で約 4.1 KB 使用、空き 20 B まで低下）。Join 後に mesh attach が進まない | **修正** 8192 B（`8cf0ae6`）。task 別の実測は下表 |
| F2 | 同時に複数台が Join すると EXPIRED。1-hop initiator が CredI 送信時に 1 相手 30 s の handshake gate を消費していたため、Root の single slot に CredI を捨てられると、同じ探索（最大 30 s）内でやり直せなかった | **修正** gate は message_1（双方の公開鍵演算の開始）で消費（`61a52f0`）。sim で 8 台同時 Join が全台成功（修正前は 2/8 が EXPIRED）、実機で 2 台同時・アプリ再申請なしで両方成功 |
| F3 | 同じ MAC から鍵を作り直した機器は、Root がその MAC の旧 neighbour session を持つ間（最大 1 h）Join できない（`exchange_io.cpp` が Join carrier を無条件に捨てていた） | **修正**（`802ef1b`）判断を検証後へ移し、同じ device なら拒否、EDHOC で別 device と証明されたら旧 session を置換。実機で消去から 27 s で承認待ち（Root 再起動なし）。**残る制限**: 旧 identity を neighbour に持つ relay を経由する Join は、その session が切れるまで通らない（relay は joiner を検証できない） |
| F4 | XIAO ESP32C6 は RF スイッチ（GPIO3 low、GPIO14 でアンテナ選択）を設定しないと電波が極端に弱い。MacFailed が続き attach できない | ボード設定を追加（`firmware/hil_node/sdkconfig.board.esp32c6`）。docs/03 §5 の board overlay の実例 |
| F5 | Host の POLICY_SET は signed type 12 を要求するが SDK は type 12 を UNSUPPORTED にする。Host から join_mode を変える手段が無い | **修正**（`82f2174`）serial method 17 POLICY_SET → root の `lm_policy_set`、`GET /v1/policy`。実機で Host から PREAPPROVED（revision 0→1）、新しい C6 が承認なしで 7 s で Join |
| F6 | 失効済みの機器宛ての DURABLE 送信が SENDING のまま終わらない | **修正**（`54f702a`）Root は失効時にその機器宛ての送信を終わらせ（未送出は REJECTED、送出済みは INDETERMINATE、理由 REVOKED）、新しい送信は REVOKED で拒否。実機で 0.7 s で終了、次の送信は ROOT_REFUSED |
| F7 | WINDOWED_RX の自動 light sleep で USB-Serial/JTAG が止まり、console も esptool も届かない。電源の入れ直しでも直後に眠る。BOOT ボタンでのダウンロードモードと全消去が必要だった | **手段を追加**（`Pm::may_sleep` / `lm_idf_sleep_veto`）。試験ファームは USB 接続中は眠らない（実機で WINDOWED_RX 中も console 10/10 応答）と起動 10 s の safe。safe が効かなかった原因は試験ファームの誤り（ALWAYS_RX に window 値を残して INVALID_ARGUMENT）で修正済み。**遠隔の POWER_POLICY_SET（signed type 29）は SDK 未実装**（root が UNSUPPORTED） |
| F8 | USB リセット後の reset reason が UNKNOWN | **修正**（`53ed918`）。実機で EXTERNAL と表示 |
| F9 | Root 再起動後、member の追随に 138 s（3 × hello 上限 32 s 前後の不在判定による） | **修正**（`fe3a7ed`）親の beacon の新しい term で再接続（30 s に 1 回まで）。実機で 11.7 s / 19.5 s |

調べて問題でなかったもの: WINDOWED_RX 中の flash commit（約 4 分で 21 回）は power policy の保存と DURABLE メッセージの journal で、受信窓ごとの書込みではなかった。
F4 を直した後の Relay / Leaf の MacFailed は 0。

### SDK task の stack（再接続と送受信の後、`hil.py cmd debug`）

| ボード | lm_owner 空き / 8192 | lm_worker 空き / 10240 |
|---|---:|---:|
| Leaf C3 | 4356 | 7448 |
| Leaf C6 | 4228 | 7708 |
| Root S3 | SDK task の最小空き 3164〜4508（task 別は未測定: Root は console が無い） | |

worker は Join 時の深さと Xtensa（S3）の task 別値が未測定のため据え置き。

## 修正の過程で見つかったこと

- F6 の最初の修正は native（root を含む SIM profile）では通ったが、LEAF/RELAY の IDF build を壊していた（`NoLedger` に `find` が無い）。SDK を変えたら IDF の LEAF / RELAY / ROOT を build してから commit する。
- `test_serial` が `ctest -j6` で 1 回だけ失敗し、単独と再実行では通った（実時間に依存する試験の可能性。原因は未調査）。

## 未検証

距離・20 hop・干渉下のチャネル切替・消費電流・実電源断（Flash 書込み中）・長時間連続運転・移設・RootHandover・NVS 暗号化と eFuse・独立 EDHOC 実装との相互接続。
