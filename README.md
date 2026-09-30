# LeanMesh — 小さく、速く、運用できる長距離Wi-Fi SDK
## 実装仕様書セット v0.2 / 2026-09-28

**LeanMesh は本資料内の仮称。既存RouteLoomの新しい正式名称・公開リリースではありません。**
本リポジトリは、新規・非Wire互換実装のための設計基準、公開契約、試験仕様に加え、`feat/sdk-impl` ブランチにソフトウェア実装（core、ESP-IDF port、Host、シミュレータ）を含みます。**実機で認定された製品SDK・firmware・FastAPI製品サービスではありません**（下の「実装」を参照）。

### 何を作るか
ESP32-S3 / C3 / C5 / C6が混在できる、ESP-NOW + 2.4GHz Wi-Fi LRの汎用メッセージSDK。親機から20無線hopの端末へ到達し、自動経路修復・チャネル最適化・安全なJoin/移設・配送証拠・省電力leafを提供します。HostはPython/FastAPIの1サービス。KGuardは適用例であり、トイレ、校正、安全ルール、Cloud契約をcoreへ入れません。

### 決定した設計の中心
- 1 domain = 1 active routing root。各端末のroot深度は最大20辺。端末間は木上の単純経路を使い最大40辺。**20peer、20台、20hopは別の数字**です。
- source routeを使い、中継端末に全宛先の経路表を持たせません。通常DATAの全網flood、毎周期全ノード再計算をしません。
- 同一Meshは同時に1チャネル。自動最適化は測定→提案→準備→確定→追随・復旧の1方式。全員の原子的切替や電波妨害下の必達は保証しません。
- 暗号ハンドシェイクはEDHOCの1プロファイル。Identity/所属/経路/session/アプリ配置を分離します。独自ECDH交換を省コードのために作りません。
- 送受信coreは単一owner。**公開鍵演算とFlash I/Oは別の有界job実行部**へ出し、中継を止めません。「taskは何があっても1個」は採用しません。
- Root firmwareだけで経路制御とチャネル制御を維持します。FastAPI停止で新しい外部承認は保留しますが、既存Node間通信はHostに依存しません。
- 各層は受理・永続化・終端受信・アプリ適用・結果不明を区別します。再送は「物理副作用のexactly-once」を保証しません。

### 読む順番
1. [要求と非目標](docs/01-requirements.md) → [アーキテクチャ](docs/02-architecture.md)
2. [無線と4チップ](docs/03-radio-targets.md) → [routing](docs/04-routing.md) → [チャネル](docs/05-channel.md)
3. [Security](docs/06-security.md) → [Join・移設](docs/07-membership.md) → [配送](docs/08-delivery.md)
4. [Wire](docs/09-wire.md) / [Serialと制御](docs/19-serial-and-control.md) / [CBOR契約](protocol/control.cddl) / [型・定数](protocol/registry.json)
5. [Device API](docs/10-device-api.md) / [C header](api/leanmesh.h) / [Host API](api/openapi.json)
6. [Host](docs/11-host.md) → [保存・電源断](docs/12-storage.md) → [Sleep・保守](docs/13-power-maintenance.md)
7. [KG適用](docs/14-kg-integration.md) → [実装計画](docs/17-implementation-plan.md)

実装担当者は併せて[AGENTS.md](AGENTS.md)、[規約](docs/15-coding-standards.md)、[性能・資源予算](docs/16-budgets.md)、[試験仕様](docs/18-verification.md)を読みます。

### 根拠の時点
- KG main: `4ed3e1ff0e63eec54c52e89444e18b2a18be2130`
- RouteLoom main: `77b5792669fefee13498ef29a3c2e48119c562a0`
- **KG #112の2026-09-28 20:37 JST追記**を含みます。追記のv2計画は、mainの実装済み機能とは区別しています。
- [調査台帳](evidence/SOURCES.md)、[差分と判断](evidence/REVIEW.md)、[要求追跡](tests/traceability.csv)を参照してください。

### 文書内の強さ
MUST=実装必須、SHOULD=逸脱時は理由・試験を記録、MAY=任意。数値には「固定契約」「初期設定」「測定目標」の別を付けます。性能・電池寿命・RF距離は未測定です。**仕様検査合格 ≠ 通信実装合格 ≠ 実機認定**。

### このZIPの検査
```sh
python -m pip install -r scripts/requirements-check.txt
python scripts/check_spec.py
```
[検査結果](evidence/VALIDATION.json)に今回実行した検査と未実施項目を記録します。インターネットから製品SDKを取り寄せたり、実機を変更したりするスクリプトではありません。

### 実装
`feat/sdk-impl` には、仕様に沿った実装があります。使い方は **[docs/sdk/](docs/sdk/README.md)**（[はじめに](docs/sdk/getting-started.md)、[Device API](docs/sdk/device-api.md)、[Host](docs/sdk/host.md)、[構造](docs/sdk/architecture.md)、[試験](docs/sdk/testing.md)）。
- 実装し、ローカルで検証したのは**ソフトウェアとシミュレーションの範囲**です: native ctest（ASan/UBSan含む）、Host pytest、meshsim上のE2E（21 node / 20 hop）、4 SoC（S3/C3/C5/C6）のESP-IDF build。**CIは `8668c69` まで直近pushで赤**でした（FIX11で修正。修正後のtreeでgreenだったrunはまだ無い）。RAM・flash・SLOCは目標超過です（[budget](build-records/budget-report.md)）。
- **未検証**: RF、実機（HIL）、消費電力、実電源断、鍵のcustody。ROOTのESP32-C3搭載は実機のheap測定まで未対応（[ADR-002](decisions/ADR-002-budget-status.md)）。量産用provisioningツールはありません。
- 実装の判断は[実装ガイド](docs/IMPLEMENTATION.md)、未検証の一覧は[試験](docs/sdk/testing.md)の§5。仕様検査（下）は引き続き仕様側のG0のみです。

### 最初の実装着手
[実装計画](docs/17-implementation-plan.md)のT01から開始します。最初はparser・保存・署名検査・1hopの縦経路を実装し、その後root深度20と自動channelを同じengine上で認定します。初期段階の1hop動作を完成版としてリリースする計画ではありません。

[158件の受入シナリオ](tests/SCENARIOS.md)と[依存入力](config/dependencies.json)も参照してください。`evidence/VALIDATION.json`はこの文書セットの検査結果、各実機シナリオは未実施です。`SHA256SUMS.txt`で同梱ファイルを照合できます。

### 全量版と機能の状態
前回の54ファイルを保持した全量版です。旧ZIPを別途展開する必要はありません。章番号20〜23が追加の中心ですが、API、Wire、設定、受入条件も同時に更新しています。[capability台帳](config/capability-manifest.json)は全機能を「仕様あり・製品実装なし」と区別しています。

### spec0.2で追加した内容
[Low power詳細](docs/20-low-power.md)、[設置・在庫・root交換](docs/21-lifecycle-operations.md)、[一斉配信とsleep](docs/22-group-and-sleep.md)、[電力・性能計測](docs/23-energy-and-qualification.md)を統合しています。
ALWAYS_RX/WINDOWED_RX/REPORT_ONLYを選べる共通SDKで、圏外の探索、起床poll、原本の永続保持、暗号sessionの有効性を同じ状態機械で扱います。C ABI2、Power policy schema、per-target API、追加受入試験と検査ツールも含みます。[変更履歴](CHANGELOG.md)
