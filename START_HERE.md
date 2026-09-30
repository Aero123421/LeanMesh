# 最初に読むページ — LeanMesh spec v0.2

**新しい汎用長距離Wi-Fi SDKの実装仕様書・公開契約・検査素材をまとめた全量版です。`feat/sdk-impl` にはソフトウェア実装とシミュレーション上の検証がありますが、実機認定済みの製品SDK・製品FastAPIサービスではありません。**

旧v0.1の全54ファイルのパスを保持し、Low power、Join/設置/移設、親機交換、一斉配信を統合改訂しました。このZIPだけを展開すればよく、旧版と上書き混在させる必要はありません。仮称LeanMesh、既存RouteLoomとはWire非互換です。

## 実装を使う

ビルド、Device API、Host、試験の手順は **[docs/sdk/](docs/sdk/README.md)**。実装済みなのはソフトウェアとsimulationの範囲で、RF・実機・消費電力・実電源断・鍵custodyは未検証です（[一覧](docs/sdk/testing.md)）。

## 読む場所

|目的|ファイル|
|---|---|
|全体像と責務の境界|[README](README.md)、[要求](docs/01-requirements.md)、[アーキテクチャ](docs/02-architecture.md)|
|4チップ・root20hop・自動チャネル|[無線](docs/03-radio-targets.md)、[経路](docs/04-routing.md)、[チャネル](docs/05-channel.md)|
|Join/復帰/移設/失効|[暗号](docs/06-security.md)、[所属](docs/07-membership.md)、[設置・在庫・親機交換](docs/21-lifecycle-operations.md)|
|Low powerの具体動作|[省電力詳細](docs/20-low-power.md)、[設定schema](config/power.schema.json)、[報告端末の設定例](config/power.report-only.json)|
|一斉配信と眠る対象|[配送](docs/08-delivery.md)、[グループ詳細](docs/22-group-and-sleep.md)|
|APIと保存|[C header](api/leanmesh.h)、[OpenAPI](api/openapi.json)、[意味の契約](api/SEMANTICS.md)、[DB](db/schema.sql)|
|byte単位の通信形式|[Wire](docs/09-wire.md)、[Serial](docs/19-serial-and-control.md)、[registry](protocol/registry.json)|
|小ささ・速さ・電力の評価|[資源予算](docs/16-budgets.md)、[電力測定](docs/23-energy-and-qualification.md)|
|コードを書く人・AIの規約|[AGENTS](AGENTS.md)、[規約](docs/15-coding-standards.md)、[実装計画](docs/17-implementation-plan.md)|
|KGへ適用する場合|[KG統合](docs/14-kg-integration.md)。業務意味をSDKへ入れない。|
|受入試験と調査根拠|[158シナリオ](tests/SCENARIOS.md)、[参照台帳](evidence/SOURCES.md)、[検査結果](evidence/VALIDATION.json)|
|全ファイルと変更点|[manifest](manifest.json)、[CHANGELOG](CHANGELOG.md)、[機能の成熟度](config/capability-manifest.json)|

## 仕様検査を再実行

```sh
python -m pip install -r scripts/requirements-check.txt
python scripts/check_spec.py
```

Python 3.12以上を想定します。C11/C++17の構文検査には`cc`と`c++`が必要です。検査は一時SQLiteとローカルファイルだけを使い、実機、GitHub、KG、外部ネットワークへ書き込みません。検査結果を`evidence/VALIDATION.json`へ再生成するため、再実行後は配布時チェックサムと差が出ることがあります。

電力積分ツールを**合成データ**で試す場合:

```sh
python scripts/energy_report.py examples/power-trace.SYNTHETIC.csv \
  --kind SYNTHETIC --max-gap-s 0.11
```

このCSVは計算器の動作確認用で、ESP32の実測値ではありません。実測には装置・ボード・ファーム・条件・traceのmetadataが必要です。

## 誤解しないための境界

3種類のpower modeは実装契約で、4チップの実機認定済み機能ではありません。RAMを安全に保持したsessionは再利用しますが、通常のDeep Sleep/cold bootはfresh EDHOCです。独自RTC高速鍵復帰は未実装・予約扱いです。

仕様検査のPASSは、ファームウェア、FastAPI製品サービス、20hop実RF、実電源断、電池寿命、独立暗号レビューのPASSではありません。実装側の試験（ctest、pytest、meshsim）も同様に、実機の合格ではありません。

`tests/golden.json`とpower fixtureは公開のtest-only材料です。鍵を本番へ転用せず、通常検査で期待値を自動更新しないでください。現行のAPI契約はC ABI2。Wire拡張やGroupSnapshotV2はCHANGELOGで互換条件を確認してください。
