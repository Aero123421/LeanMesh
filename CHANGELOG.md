# Changelog

- Issue #5: rootの台帳（member ledger）のbackupと交換rootへの復元。rootはsigned backup（control type 34、秘密を含まない一貫した断面）を作り、Hostが変更後に自動で取って保持する（`GET /v1/ledger/backup`）。旧rootが故障したら、fleet署名のRootHandoverと保持したbackupで `POST /v1/control` `LEDGER_RESTORE`（serial 18〜22）がrecordを1件ずつhash chain検証してから交換rootへ書き、manifestを最後に書いて準備完了にする。memberは台帳が既にあるのでjoinし直さない。Host DBはadditive migration（`ledger_backups`）。実機のFlash電源断・USB・複数hopでのmember追従は未検証（simulationのみ、[12章 §5](docs/12-storage.md)、[21章 §8](docs/21-lifecycle-operations.md)）。
- Issue #3 の初回経路: `python -m leanmesh_fleet` によるオフライン fleet 鍵の新規生成・暗号化保管と、DeviceCredential / RootDelegation / 初回 AssignmentTicket / ExpectedSet の発行。通常 Host の署名権限・SDK wire 契約は変更なし。SDK/PSA 検証と sim Join を CI に追加。機器書込み、USB kit、他の lifecycle 発行 CLI、実機 custody は後続（[使い方](docs/sdk/fleet-issuer.md)）。

- 移設参加券の発行: `python -m leanmesh_fleet transfer`（`Issuer.transfer`）。source domain A から target domain B（B root の RootDelegation で指定）への AssignmentTicket（mode 0 = 機器の `lm_transfer_nonce_get`、mode 1 = 一回限り grant）と、B の ExpectedSet 1 page を発行する。SDK の wire・検証は変更なし。Python 発行の ticket で sim の機器が A（root 停止）→ B へ移り、古い/再使用 ticket を拒否する試験と、実機ベンチ用の console `nonce` / `ticket` / `join transfer`・`hil.py transfer` を追加（[使い方](docs/sdk/fleet-issuer.md)、[ベンチ](docs/hil/transfer-two-roots.md)）。実機の移設は未検証。

## Unreleased — ソフトウェア実装（feat/sdk-impl）

仕様0.2に沿ったソフトウェア実装を追加した。**実機で認定された製品ではない。** 使い方は [docs/sdk/](docs/sdk/README.md)、判断の履歴は [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)、資源の現状は [ADR-002](decisions/ADR-002-budget-status.md)。

- 追加: 単一ownerのcore（wire、link、member、route、delivery、sched、group、channel、power、diag）、EDHOC suite 3 glue + PSA、2-slot封印Store、ESP-IDF port（4 SoC build）、root用USB serial bridge、FastAPI Host（SQLite、event journal、SSE）、meshsim、C ABI 2の全関数の実装（`scripts/check_api_defined.py` が未定義を検出）。`lm_policy_set` は1回に `channel_freeze` または `join_mode`（rootのpolicy recordへcommit後に適用）の1項目を変更する。`relay_allowed` / 自動移設は変更手段が無く `UNSUPPORTED`、signed policy object（`lm_install_control` type 12）も未対応。
- 検証（ソフトウェア/simulation、ローカル実行。結果と実行日はFIX11の記録 [docs/sdk/getting-started.md](docs/sdk/getting-started.md) §「確認した内容」）: native ctest（ASan+UBSan含む）、Host unit/integration/E2E、meshsim上の21 node / 20 hop全経路、Store切断matrix（sim）、seed付きモデル試験、IDF build（S3/C3/C5/C6 のLEAF、ROOT、RELAY）。**CI**: `57a2b66` の直近のgreen run は https://github.com/Aero123421/LeanMesh/actions/runs/36707722886（その時点で最新。以降のcommitは別に確認する）。`8668c69` までのpushは赤だった。CIもsimulation/hostの範囲で、実機の合格ではない。
- 未検証: RF、HIL、消費電力、実電源断、鍵custody、EDHOCの独立実装との相互接続。ROOTのESP32-C3搭載は**未対応**（実機heap未測定）。量産用provisioningツールなし。RF承認は既定off。**資源は目標超過**: RAM（全SoC・全profile）、flash差分（全12 buildが256 KiB目標超え、ROOTの4 SoCは320 KiBのreview lineも超え。数値は変わるので build-records/budget-report.md の冒頭を見る）、SDK SLOC（28k超え）。現在値は [build-records/budget-report.md](build-records/budget-report.md) の冒頭、理由は [ADR-002](decisions/ADR-002-budget-status.md)。
- **仕様ファイルの意味を実装中に変更した箇所**（0.2の仕様だけの版から。互換性の節に一覧）。`api/leanmesh.h` には配送evidence bit（`LM_EVIDENCE_*`）、phase（`LM_PHASE_*`）、`LM_CONNECTIVITY_VALID_*`、`lm_root_time_get`、`lm_transfer_nonce_get` を**追加**しただけで、既存structの配置は変えていない（`lm_connectivity_t` は一度uint64へ広げたが、FIX11で仕様の配置〈uint32 `validity_bits`、48 B〉へ戻した）。manifest.json は仕様bundleの目録、SHA256SUMS.txt はその checksum。

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

文書0.1→0.2、C ABI1→2（0.2の仕様の時点で既存structはサイズ完全一致、再compileが必要）。Wire envelopeは1のまま、Power frame kind8とcontrol28〜33をcapability交渉で追加する。GroupSnapshot22を新しい意味へ上書きしない。0.2のgroupは新32を用い、旧22をUNSUPPORTEDとして拒否する。既存golden DATA frameは変更しない。

**ソフトウェア実装（`feat/sdk-impl`）が0.2の仕様だけの版から変えた点**（これらを「意味は変えていない」とは言わない）:
- C ABIは2のまま。**既存structの配置は変えていない**（`lm_connectivity_t` は仕様の48 Bへ復元）。追加: 関数 `lm_root_time_get` / `lm_transfer_nonce_get` と型 `lm_root_time_t`、定数 `LM_PHASE_*` / `LM_EVIDENCE_*` / `LM_CONNECTIVITY_VALID_*`。
- **Wire/control（非互換）**: `join-prepare` のmemberは署名64 Bを保留（0）したMemberCredentialで、`join-commit` は3要素目 `member-signature`（64 Bまたは空）を持つ。GroupSnapshotのpageは0..4（1 pageは16行かつ符号化700 Bまで）。
- **Serial**: method 16 DIAGNOSTICS。SENDの `flags` は0..63（bit5 = strict_single_frame。局所option）。カウンタ抜けを検出したUSB sessionは切って新しいEDHOCへ（docs/19 §5どおり）。
- **OpenAPI**: `/v1/health`、`/v1/diagnostics` と対応するschemaを追加（16→18 path、24→26 schema）、PowerSnapshotの `state: UNKNOWN` と `reported_root_ms` / `report_age_ms`。titleを「design contract」から実装の契約へ。Hostは署名済みobjectを**中のtypeの権限**で検査する（docs/sdk/host.md）。
- **DB**: `events_operation` index。Host operationはepoch閉鎖後7日で削除（保持窓。idempotent replayは窓の外で410）。
- **意味の明確化（docs 04〜08、12、16、19、21、22）**: rootのtermはboot毎に+1（ARCH2）、sessionはleaseに従う、DiscoveryScopeKey、rootのledger manifestと `RECOVERY_REQUIRED`、provisioning record、RootHandoverの規則、実装時のRAM/SLOC目標の改訂（ADR-002）。

## 0.1

元仕様一式。manifest/SHA256/validationは0.2用に再生成。参照元KG/RouteLoomのcommit hashは変更していない。
