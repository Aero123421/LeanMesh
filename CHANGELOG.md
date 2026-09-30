# Changelog

## Unreleased — ソフトウェア実装（feat/sdk-impl）

仕様0.2に沿ったソフトウェア実装を追加した。**実機で認定された製品ではない。** 使い方は [docs/sdk/](docs/sdk/README.md)、判断の履歴は [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)、資源の現状は [ADR-002](decisions/ADR-002-budget-status.md)。

- 追加: 単一ownerのcore（wire、link、member、route、delivery、sched、group、channel、power、diag）、EDHOC suite 3 glue + PSA、2-slot封印Store、ESP-IDF port（4 SoC build）、root用USB serial bridge、FastAPI Host（SQLite、event journal、SSE）、meshsim、C ABI 2の全関数の実装（`scripts/check_api_defined.py` が未定義を検出）。`lm_policy_set` はchannel freezeの変更だけを適用し、他の変更は署名policy object（`lm_install_control`）が必要なため `UNSUPPORTED`。
- 検証（ソフトウェア/simulation）: native ctest（ASan+UBSan含む）、Host unit/integration/E2E、meshsim上の21 node / 20 hop全経路、Store切断matrix（sim）、seed付きモデル試験、IDF build（S3/C3/C5/C6 の LEAF と ROOT、C3 の RELAY）。
- 未検証: RF、HIL、消費電力、実電源断、鍵custody、EDHOCの独立実装との相互接続。ROOTのESP32-C3搭載は未対応（実機heap未測定）。量産用provisioningツールなし。RF承認は既定off。
- 仕様ファイル（docs/01〜23、protocol、api、db）の意味は変更していない。`api/leanmesh.h` には配送evidence bit（`LM_EVIDENCE_*`）とphase（`LM_PHASE_*`）、`lm_connectivity_t.validity_bits` の定義（`LM_CONNECTIVITY_VALID_*`）を追加した（既存の番号は不変）。`lm_connectivity_t.validity_bits` は未使用だったuint32からuint64へ変更。manifest.json は仕様bundleの目録であること、SHA256SUMS.txt はその目録の checksum であることを明記。RAM/SLOCは目標超過（ADR-002）。

## 0.2 — 2026-09-28 / 統合改訂

全54ファイルの0.1を土台にした**全量版**。差分パッチだけではない。SDK firmware/製品FastAPI実装は含まない。

- powerをALWAYS_RX/WINDOWED_RX/REPORT_ONLYに整理。有限episode、圏外radio budget、leaf主導poll、親RAM mailbox、下り待ち、session保持可否を具体化。
- sleep requestにwake source、duration、保存方針を追加。policy/diagnostics、C ABI2、OpenAPI、control/binary契約と試験を連動。
- 設置window、一斉設置、工場/倉庫、本番移設、root交換、resetの境界を追加。既存07章のcommitが全装置同時atomicではないことを明記。
- groupのorigin fan-out、世代込みsnapshot、sleepy target、per-target result、cancel、容量の会計を固定。
- 電力CSV積分ツール、power schema/fixture、mode別の受入試験を追加。実機測定値は一切捏造しない。
- 4SoC・20hop・自動channel・個体認証・機器移設・FastAPI・小ささの目標は維持。
- Deep Sleepの高速鍵復帰は未定義機能を約束しない。RAM保持session再利用とfresh EDHOCを明確化し、電池目標未達ならpower gateを落とす。

## 互換性

文書0.1→0.2、C ABI1→2（既存structはサイズ完全一致、再compileが必要）。Wire envelopeは1のまま、Power frame kind8とcontrol28〜33をcapability交渉で追加する。GroupSnapshot22を新しい意味へ上書きしない。0.2のgroupは新32を用い、旧22をUNSUPPORTEDとして拒否する。既存golden DATA frameは変更しない。

## 0.1

元仕様一式。manifest/SHA256/validationは0.2用に再生成。参照元KG/RouteLoomのcommit hashは変更していない。
