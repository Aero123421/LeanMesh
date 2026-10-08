# LeanMesh

**小さく、速く、運用できる長距離Wi-Fi Mesh SDK** — ESP32-S3 / C3 / C5 / C6 を混在させ、ESP-NOW + 2.4GHz Wi-Fi LR で親機から最大20 hopの端末へメッセージを届けます。Hostは Python/FastAPI の1サービスです。

![LeanMesh: Application - Host - Root から、relayの木を20 hop下った leaf までsource routeで届く様子](docs/assets/leanmesh-mesh.svg)

*App → Host → (認証済みUSB) → Root。メッセージは経路全体を持つsource routeで進み、途中relayに全宛先の経路表は要りません。壊れた区間は予備の近隣linkで修復し、眠る端末は起床窓で受け取ります。*

> **LeanMesh は仮称**です。既存RouteLoomの新しい正式名称・公開リリースではなく、Wire互換もありません。KGuardは適用例であり、業務語彙・Cloud契約・安全ルールはcoreに入れません。

## できること

- **20 hopのsource route Mesh**: 1 domain = 1 root。root深度は最大20辺、通常DATAのfloodも全ノード再計算もしません。
- **4 SoC混在**: ESP32-S3 / C3 / C5 / C6。radio/OS境界以外の差を作らず、機能の意味は共通です。
- **EDHOC認証**: 個体認証つきJoin、session、移設、失効。Identity・所属・経路・session・アプリ配置を分離します。
- **配送証拠**: 受理・永続化・送信・終端受領・アプリ適用・結果不明を別々に返します（exactly-onceの副作用は保証しません）。
- **自動チャネル**: 測定→提案→準備→確定→追随の1方式。全員の原子的切替や妨害下の必達は保証しません。
- **3つの電力mode**: ALWAYS_RX / WINDOWED_RX / REPORT_ONLY を1つの通信・認証engineで扱います。
- **一斉配信**（group send）と、設置・在庫・親機交換などの**ライフサイクル操作**。
- **Host**: 認証済みUSB serialでRootに接続。OpenAPI、SQLite、idempotency、event/SSE。FastAPI停止中も既存Node間通信は続きます。

## 現在の状態

ソフトウェアとシミュレーションの範囲の実装です。**実機で認定された製品SDK・firmware・FastAPI製品サービスではありません。**

|区分|内容|
|---|---|
|実装し、ローカルで検証した|native ctest（ASan/UBSan含む）、Host pytest、meshsim上のE2E（21 node / 20 hop）、4 SoCのESP-IDF build（LEAF/RELAY/ROOT）。CIは使わず、マージ前に同じ確認を開発環境で流す（[試験 §2](docs/sdk/testing.md)）。どれもsimulation/hostの範囲|
|未検証|RF、実機（HIL）、消費電力、実電源断、鍵のcustody、EDHOCの独立実装との相互接続|
|未対応|ROOTのESP32-C3搭載（実機heap測定まで）、量産用provisioningツール。RF承認は既定off|
|目標超過|RAM（12/12 build、最大 +13404 B）、flash差分（12/12 buildが256 KiB超、ROOT 4 SoCは320 KiBも超）、SDK SLOC（28k超）。[budget-report](build-records/budget-report.md)、[ADR-002](decisions/ADR-002-budget-status.md)|

仕様検査のPASS、ctest/pytest/meshsimのPASSは、いずれも実機の合格ではありません。一覧は[試験 §5](docs/sdk/testing.md)。

## クイックスタート

前提: ESP-IDF v6.0.3（`~/esp/esp-idf-v6.0.3`）、CMake / Ninja / g++、Python 3.12。詳細は[はじめに](docs/sdk/getting-started.md)。flashは行いません。

```sh
scripts/third_party.sh setup && scripts/third_party.sh verify     # libedhoc / zcbor を固定commitで取得・検証

cmake -S . -B ~/.cache/leanmesh/native -G Ninja                    # native build + ctest
cmake --build ~/.cache/leanmesh/native
ctest --test-dir ~/.cache/leanmesh/native --output-on-failure -j4

scripts/setup_host_venv.sh sync-dev                                # Host: pytest（E2Eはmeshsimを使う）
~/.cache/leanmesh/host-venv/bin/python -m pytest

scripts/build_targets.sh --app example_node esp32c3                # ESP-IDF build（LEAF、1 SoC）
```

## ドキュメント

- **SDKの使い方**: [docs/sdk/](docs/sdk/README.md) — [はじめに](docs/sdk/getting-started.md)、[Device API](docs/sdk/device-api.md)、[Host](docs/sdk/host.md)、[構造](docs/sdk/architecture.md)、[試験と未検証の一覧](docs/sdk/testing.md)
- **仕様（正本）**: [docs/01〜23](START_HERE.md)（[要求](docs/01-requirements.md)、[アーキテクチャ](docs/02-architecture.md)、[routing](docs/04-routing.md)、[省電力](docs/20-low-power.md)ほか）、[protocol/](protocol/registry.json)、[api/](api/leanmesh.h)、[db/](db/schema.sql)。読む順番と目的別の表は[START_HERE](START_HERE.md)
- **実装の判断**: [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)、[ADR-001](decisions/ADR-001-small-by-single-path.md)、[ADR-002](decisions/ADR-002-budget-status.md)
- **規約・予算・試験**: [AGENTS.md](AGENTS.md)、[規約](docs/15-coding-standards.md)、[資源予算](docs/16-budgets.md)、[158シナリオ](tests/SCENARIOS.md)
- **変更履歴**: [CHANGELOG](CHANGELOG.md)

## リポジトリ構成

```
docs/         仕様 01〜23、sdk/（使い方）、assets/（図）
protocol/ api/ db/ config/   registry・CDDL、C header・OpenAPI、SQLite schema、設定schema
src/          core（単一owner）、security、store、serial、root、capi、port（ESP-IDF）、hostnative
components/ firmware/        ESP-IDF component、example_node など
host/         Python/FastAPI Host と試験（unit / integration / E2E）
tools/        meshsim（シミュレータ）、lmtool、lmfleet（TEST-ONLY）
tests/ scripts/ build-records/ decisions/ evidence/
```

## 設計の要点

- 各端末のroot深度は最大20辺、木上の端末間は最大40辺。**20peer、20台、20hopは別の数字**です。
- 送受信coreは単一owner。公開鍵演算とFlash I/Oは別の有界job実行部へ出し、中継を止めません。
- 暗号ハンドシェイクはEDHOCの1プロファイル。独自ECDH交換は作りません。
- Root firmwareだけで経路制御とチャネル制御を維持します。FastAPI停止で新しい外部承認は保留しますが、既存Node間通信はHostに依存しません。

## 仕様bundleの由来と読み方

**根拠の時点**

- KG main: `4ed3e1ff0e63eec54c52e89444e18b2a18be2130`
- RouteLoom main: `77b5792669fefee13498ef29a3c2e48119c562a0`
- **KG #112の2026-09-28 20:37 JST追記**を含みます。追記のv2計画は、mainの実装済み機能とは区別しています。
- [調査台帳](evidence/SOURCES.md)、[差分と判断](evidence/REVIEW.md)、[要求追跡](tests/traceability.csv)を参照してください。

**文書内の強さ**: MUST=実装必須、SHOULD=逸脱時は理由・試験を記録、MAY=任意。数値には「固定契約」「初期設定」「測定目標」の別を付けます。性能・電池寿命・RF距離は未測定です。**仕様検査合格 ≠ 通信実装合格 ≠ 実機認定**。

仕様検査（仕様側のG0のみ。実機・外部ネットワークには書き込みません）:

```sh
python -m pip install -r scripts/requirements-check.txt
python scripts/check_spec.py
```

[検査結果](evidence/VALIDATION.json)は再実行で再生成されます。`SHA256SUMS.txt` で同梱ファイルを照合できます。この版は仕様v0.2（2026-09-28）の全量版で、Low power・設置/移設・一斉配信を統合しています（[変更履歴](CHANGELOG.md)、[capability台帳](config/capability-manifest.json)）。

## License / 出典

[LICENSE-AND-SOURCES.md](LICENSE-AND-SOURCES.md)、[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)。新SDKの配布licenseは権利者が選定してください。検査用鍵は公開のtest-only材料で、本番で使ってはいけません。
