# LeanMesh SDK ドキュメント

ESP32-S3 / C3 / C5 / C6 向けの汎用長距離Mesh（ESP-NOW + Wi-Fi LR）SDKの**使い方**です。仕様そのものは [docs/01〜23](../../README.md)（正本）で、このディレクトリは仕様を書き換えません。

![LeanMesh mesh](../assets/leanmesh-mesh.svg)

## SDKとは / でないもの

- C11 の公開API（[api/leanmesh.h](../../api/leanmesh.h)、ABI 2）と、その下の単一ownerのcore、ESP-IDF port、root用USB bridge。
- Python/FastAPIのHost 1サービス（[OpenAPI](../../api/openapi.json)、SQLite）。KGuardなど業務の語彙はcoreに入れません。
- 配送は「受理・永続化・送信・終端受領・アプリ適用・結果不明」を**別の証拠**として返します。exactly-onceの副作用は保証しません。
- **状態**: ソフトウェアとシミュレーションで実装し、ローカルで検証した（native ctest、ASan/UBSan、Host pytest、meshsim上の21 node / 20 hop E2E、4 SoCのIDF build）。CIは使わず、マージ前に同じ確認を開発環境で流します（[testing.md](testing.md) §2）。これもsimulation/hostの範囲で、実機の合格ではありません。
- **実機で認定されたものは何もありません**。RF、HIL、消費電力、実電源断、鍵のcustodyは未検証です（一覧は [testing.md](testing.md) §5）。
- **ROOT を ESP32-C3 に載せる構成は、実機のheap測定が済むまで未対応**です（[ADR-002](../../decisions/ADR-002-budget-status.md)）。**RAM・flash・SLOCはすべて目標を超過しています**（flash差分は測定時点で全12 buildが256 KiB目標を超え、ROOTは4 SoCとも320 KiBのreview lineも超える。現在の数値は [build-records/budget-report.md](../../build-records/budget-report.md) の冒頭にまとめ、理由はADRにあります）。
- 量産用のprovisioning（鍵・資格情報の書込み）ツールは含みません。sim用の `tools/lmfleet` はTEST-ONLYです。RF承認（`LEANMESH_RF_DEPLOYMENT_APPROVED`）は既定でoffです。
- `api/leanmesh.h` の全関数は定義済みです（`scripts/check_api_defined.py`）。`lm_policy_set` は1回に `channel_freeze` または `join_mode` の1項目を変更します（`relay_allowed` / 自動移設は変更手段が無く `UNSUPPORTED`、signed object type 12 も未対応。[device-api §9](device-api.md)）。

## 読む順番

| ページ | 内容 |
|---|---|
| [getting-started.md](getting-started.md) | 前提、取得、native build / ctest、Host venv / pytest、IDF build（4 SoC × LEAF/RELAY/ROOT）、meshsim + Host の起動 |
| [device-api.md](device-api.md) | Cの使い方: init〜stop、join、send/受信、証拠と結果、group、power、channel、エラー |
| [host.md](host.md) | Hostの設定・token、curl例、idempotency、event/SSE/cursor、crash時の意味 |
| [fleet-issuer.md](fleet-issuer.md) | オフライン fleet 鍵管理と初回 Join の署名 CLI。機器書込みと custody 認定は後続 |
| [architecture.md](architecture.md) | owner / worker / app、4 port、ディレクトリ、決定の所在 |
| [testing.md](testing.md) | 試験の層、電源断matrix、シナリオ対応、資源報告、**未検証の一覧** |

## 最短の確認

```sh
scripts/third_party.sh setup && cmake -S . -B ~/.cache/leanmesh/native -G Ninja \
  && cmake --build ~/.cache/leanmesh/native && ctest --test-dir ~/.cache/leanmesh/native -j4
```

（ESP-IDF v6.0.3が `~/esp/esp-idf-v6.0.3` にある前提。詳細は [getting-started.md](getting-started.md)。）
