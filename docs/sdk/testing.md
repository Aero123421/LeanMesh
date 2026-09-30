# 試験と検証

方針: 個別の細かいunit testより、本物のcoreをsim上で動かす統合/E2Eを優先します。テスト数は指標ではありません。詳細は [IMPLEMENTATION §9](../IMPLEMENTATION.md)、受入条件は [docs/18](../18-verification.md)。

## 1. 層

| 層 | 実行 | 何を検査するか |
|---|---|---|
| 仕様検査（G0） | `python scripts/check_spec.py` | 仕様文書・registry・header・schemaの整合、markdownリンク。実装の合格ではない |
| native ctest | `ctest --test-dir ~/.cache/leanmesh/native -j4` | 実coreを載せた `SimNode`/`World` での網（`tests/native/test_*.cpp`）。codec・暗号vectorだけがunit |
| sanitizer | `-DLM_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug` の別buildでctest | ASan + UBSan（UBSanは致命扱い）。CIではASan meshsimでE2Eも通す |
| Host unit / integration | `pytest host/tests/unit host/tests/integration` | codec、認証、API契約（OpenAPIと突き合わせ）、DB上限、Hostプロセスのcrash |
| 公開C APIの網羅 | `python3 scripts/check_api_defined.py --native-build <build>`（ctest `api_defined`） | `api/leanmesh.h` の全関数がnative buildで定義済み、`LM_EVIDENCE_*`/`LM_PHASE_*` がHost・OpenAPIと一致 |
| Host E2E | `pytest host/tests/e2e` | 本物のHost + 本物のcoreを載せた `meshsim`（pty経由のUSBセッション）。21 node / 20 hop の全経路（`test_fullstack_meshsim.py`）を含む |
| 電源断matrix | 下記 | Storeの変更呼び出しの**各点**で電源断を注入して再起動 |
| モデル試験 | `tests/native/test_model` | seed付きランダムな送信・loss・link・再起動列で証拠の不変条件を検査 |

sim試験はプロトコル試験台で、RSSI・RF・電力・実Flashを持ちません。

### 電源断matrix（sim Store）

```sh
T=~/.cache/leanmesh/native/tests/native
$T/test_join POWER; $T/test_lifecycle M05; $T/test_lifecycle LC08; $T/test_channel POWER; $T/test_delivery POWER-
```

`tests/native/cut_matrix.hpp` が唯一の駆動部です。k = 0.. の各変更呼び出しで切断し、許される状態だけが残ることを確認します。失敗は scenario / node / mode / k を出力し、1行 `[matrix]` が要約です。k が上限（40）に達しても切断が効き続けた掃引は `TRUNCATED`（掃引が未完）と表示し、totalに数えます。これは**Flash commitのモデル**であり、実電源断ではありません。

### モデル試験

```sh
LM_MODEL_SEEDS=200 ~/.cache/leanmesh/native/tests/native/test_model   # 既定48 seed
LM_MODEL_SEED=17 LM_MODEL_LOG=1 ~/.cache/leanmesh/native/tests/native/test_model   # 1 seedの再現
```

失敗時はseed、event log、最小化した列、commitを出します。検査するのは「証拠は前にしか進まない」「APPLIEDは宛先アプリの報告がある時だけ」「再起動をまたいでも配送回数の上限を超えない」「復旧後、有限期限の操作は終わる」です。

## 2. CI（`.github/workflows/ci.yml`）

| job | 内容 |
|---|---|
| `spec` | check_spec（依存はexact version固定） |
| `lint` | `ruff check`（host と、このrepoが保守するscript）。clang-format / clang-tidy は設定があるが**gateにしていない**（C++は設定のcolumn limitに従っておらず、指摘が数千件あるため。将来の課題） |
| `native` | build、ctest（`--no-tests=error`）、電源断matrix、budget report、scenario coverage |
| `model-random` | `test_model` を**毎回ランダムな基点**から3000 seed連続で実行（範囲をlogに出す。失敗時はseedを出す。`LM_MODEL_SEED=<n>` で再現）。既定のctestの48 seed（1000〜1047 + 回帰5 seed）は固定で、新しい列は見ない |
| `host` / `e2e` | Host unit+integration / meshsimとのE2E（20 hop、report出力） |
| `sanitizers` | ASan+UBSanのctestとE2E |
| `idf-targets` | esp32s3/c3/c5/c6 それぞれで baseline・example_node・crypto_link_check と RELAY / ROOT profile をbuild、予算報告 |

全jobに `timeout-minutes` があり、actionはcommit SHAで固定、IDF imageはdigest固定です。pytestは `timeout` コマンドで全体を打ち切ります（per-test timeoutのpluginはhash lockに未追加）。CIはflashしません。

## 3. シナリオの結びつけ

受入シナリオ（`tests/scenarios.json`、158件）との対応は**名前の規約**で作ります。

```cpp
LM_TEST("D01 D02 message reaches the far end and the origin hears END_RECEIVED")   // 先頭のID列
```
```python
@pytest.mark.scenario("H04")     # 複数可
def test_host_crash_after_send_reconciles_by_message_id(...): ...
```

```sh
python3 scripts/scenario_coverage.py --out-dir /tmp/cov      # scenario-coverage.{json,md}
```

- 出力は**参照の静的な対応表**で、実行結果ではありません（必要なら `--results-junit`）。存在しないIDは exit 1。**`COVERED_SOFTWARE_ONLY` は「テスト名（C++の `LM_TEST` 先頭、pytestの `scenario` mark）がそのIDを名指す」の意味で、テスト本体がシナリオの全手順を実行するとは限りません**（`-style` 等の接尾辞は除去して数えます）。行を根拠にする前に参照先のテストを読んでください（生成物にも同じ注意を出力します）。
- 状態: `COVERED_SOFTWARE_ONLY` / `NOT_RUN_HARDWARE`（実機必須のもの。simの証拠があれば "sim" と併記）/ `NO_SOFTWARE_EVIDENCE` / `BUILD_REPORT`。
- コミット済みの写しは `build-records/scenario-coverage.md`。`tests/scenarios.json`・`traceability.csv`・`capability-manifest.json` は変更しません（実装の証拠は生成物へ、判断D11）。

## 4. 資源報告

```sh
python3 scripts/budget_report.py --native-build ~/.cache/leanmesh/native \
  --idf-build ~/.cache/leanmesh/build/example_node/esp32c3 \
  --idf-build ~/.cache/leanmesh/build/example_node-ROOT/esp32c3 --out-dir /tmp/budget
```

固定RAM（`sizeof` + リンクmapの静的DRAM）、flash差分（baselineとの差）、first-party SLOC、stack実測を出す**報告**であり、gateではありません。数値の読み方と超過の理由は [ADR-002](../../decisions/ADR-002-budget-status.md)、コミット済みの写しは `build-records/budget-report.md`。
heap最小値・stack余裕・CPU・airtime・energyは実機測定が必要で、ここには含まれません。

## 5. 検証していないこと

| 項目 | 状態 |
|---|---|
| CI（GitHub Actions）でのgreen | **未記録**。`8668c69` までの直近pushは赤（ASan E2Eの待ち条件の競合ほか）。FIX11で修正したが、修正後のtreeで走ったrunはまだ無い。green runのidをここへ記録するまで、CIでの検証済みを主張しない |
| C++の整形・静的解析（clang-format / clang-tidy） | **gateにしていない**。設定はあるがtreeが従っておらず（指摘が数千件）、CIは走らせない |
| RF（距離、20 hop実機、channel切替の実網、共存、RSSI） | **未実施**。simはRFモデルを持たない |
| HIL（4 SoCでの実動作、USB実機、Wi-Fi LR250、ESP-NOWのpeer/ACK挙動） | **未実施**。firmwareは4 SoCで**buildだけ**確認 |
| ROOT を ESP32-C3 に載せる構成 | **未対応**。RAM超過があり、実機の空きheap未測定（ADR-002） |
| エネルギー・電池寿命・Deep Sleep復帰時間 | **未測定**。`examples/power-trace.SYNTHETIC.csv` は計算器の確認用の合成データ |
| 実電源断（Flashの書込み途中断、brown-out） | **未実施**。電源断matrixは sim Store のモデル |
| 鍵のcustody（工場での鍵生成・保管・失効、秘密の消去） | **未審査**。sim/testの鍵はTEST-ONLYで製品へ入れない。量産用provisioningツールは無い。NVS暗号化（FIX8-D7）は**buildと構成だけ**確認（esp32c3で暗号化mountのlink、無効かつ未承認でcompileエラー）。NVS鍵の生成・eFuse書込み・暗号化partitionの書込み・実機での読み戻しは未実施 |
| 失効の伝播（member間session） | rootは失効を即時に拒否するが、他のmemberは失効を知らない：失効した端末は最後に更新されたlease（最大15分）が切れるまでmember同士の新規sessionを張れる（FIX8-D11、docs/06 §7の有限lease） |
| EDHOC suite 3 の独立実装との相互接続 | **未実施**（RFC 9529 traceはsuite 2で同一glueを通したもの。D1） |
| OTA（画像転送・書込み・rollback） | manifest検証と状態のみ。転送/書込みは無く、Kconfig既定はoff |
| 実機必須の受入シナリオ（158件中116件） | `NOT_RUN_HARDWARE`（`build-records/scenario-coverage.md`） |
| 長時間試験（72 h）、大規模台数（64 node / 20 hop 実網）| **未実施**（simの21 node / 20 hopのみ） |

「仕様検査合格 ≠ 通信実装合格 ≠ 実機認定」です。
