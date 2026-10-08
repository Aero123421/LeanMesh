# Issue 19 高・中対応記録

2026-10-08。[Issue 19](https://github.com/Aero123421/LeanMesh/issues/19)の番号付き高3件・中4件を対象に実装した。比較元はgit pull --ff-only後の`7f62aaa`、実装の最終commitは`6f7e8853982d457be9a89182faa93216970af92d`。branchは`codex/issue19-kiss`。機器書込み・現場配備は行っていない。

## 変更と確認した経路

| 項目 | 変更 | 実装経路の検証 |
|---|---|---|
| 高1 遅いTX/RX | Probe、HOP_ACK、REGISTER/READY/renew/query、DATA、routed credentialの待ちをTX完了に対応させた。観測service時間の最大値を既存watchdog以下で保持。早いACKの証拠は即記録し、frame解放と次段待ちはcallback後。 | TX callback 1,060ms、RX 1,059msの1/3hopでcold形成、双方向DATAとEND_RECEIVED。600秒の形成上限、DATA期限60秒。元の500ms early ACK、全mesh/power/group/channel suiteも合格。 |
| 高2 ProbeのBUSY | 受け付けたProbeだけattach triesへ加算。Busy/DriverResultUnknown/NoCapacityはローカル再試行にし、既存linkを維持。 | 各拒否を注入し、同じneighbor/sessionが残ること、再開後attachすることを確認。 |
| 高3 ROOT復旧 | HIL ROOTアプリがowner snapshotでFAULT/RX stallを監視しstop/start。イベントqueueはHostだけが読む。RX stallは過去のRX・120秒の無受信・3回以上の成功unicastが必要。2分に3回まで復旧し、失敗はRTC記録後reboot。 | 実coreでroot FAULTを発生させ、共通stop/start経路からRoot復帰、memberの再接続、membership generation不変を確認。判定関数は実firmwareと同じCをnativeで試験。USB/RFの実機復旧は未検証。 |
| 中4 連続失敗の抑制 | 既存neighbor/end-session slotに1/2/4/8/16/30秒の待機を持つ。認証済みHOP_ACK/receiptで解除。同じ所属世代のsession更新では保持。controlは復帰/認証のため除外。 | dead peerへの3回後の抑制、成功後の即時配送、健全なfirst hopと到達不能なdestの区別。期限、所属台帳、暗号化済みframe再送の既存検査を維持。 |
| 中5 field FAULT分類 | radio reasonだけ復旧。他FAULTはSDKを停止してSDK_FAULTを一度記録。復旧decisionの時刻・理由・status・回数・TX/RXを記録し、失敗rebootをRTCで引き継ぐ。 | StorageFailure/RecoveryRequiredをradioと誤認しない判定、既知/未知診断、fieldviewで復旧理由の復号・表示。RTC保持と電源断は実機未検証。 |
| 中6 実出力 | esp_wifi_get_max_tx_powerのreadbackをIDF拡張、serial/Host driver map、fieldログで公開。要求以下を受け入れる条件は維持。未知はunknown。C ABI v2に存在しないbit5/6は立てない。 | 40の要求に対する34 quarter-dBm相当の注入値を診断と暗号化USB実経路で確認。Host API/fieldviewで8.5dBmとunknownを区別。実PHYの出力/量子化は未測定。 |
| 中7 CI | 通常CTestに低速回帰を追加。IDF matrixのS3 jobにfield leaf/relay/display、HIL ROOT buildを追加。 | ローカルで4SoC×LEAF/RELAY/ROOTとfield三役/HIL ROOT S3をbuild。GitHub Actions上の実行は未確認。 |

汎用retry engineや新しいcore task/queueは追加していない。HOP_ACKの保留はTxFrameの既存flags/時刻領域を使い、frame sizeofは296B、metadataは44Bのまま。重い暗号/Flashをradio callbackへ移していない。Identity、各generation、term、session、application bindingの用途は維持した。

relayの次hopがTIME_UNCERTAINの間はHOP_ACK BUSY/retry_after 2秒を返し、既存の最大16 defersで制限する。credential更新待ちをNoRoute/RF失敗へ混ぜず、署名・認可を省略しない。routed credentialの全体予算は開始時に固定し、fragmentで無期限に延長しない。鍵導出後のSESSION_BINDの30秒期限と公開鍵job/slot/gateは維持。遅い長経路ではexchange slotの保持が増えるため、今回の低速1/3hop試験を40hop低速のqualificationと扱わない。

## 失敗する回帰と修正後の結果

- 高1: `git archive 7f62aaa`の独立cache checkoutに最終の低速テストだけを移し、同じ600秒形成上限で1/3hopの失敗を再確認。製品コードはbaselineのまま。`timing-before-final-regression.log`が失敗、最終treeの`test_mesh ISSUE19`は成功。
- 高2: 修正前はBusy/DriverResultUnknown/NoCapacityの各注入でlinkを失うassertが失敗。受け付けた送信だけtriesへ数える変更後に合格。
- 高3: stop/start復旧前はrootがFaultedに残りRunning assertが失敗（`root-before.log`）。復旧経路追加後に合格。
- 中4: 抑制前はRF試行数・復帰後の受領・次messageの受領が失敗（`backoff-before.log`）。最終はdead peerとdead destinationの両方が合格。
- 高1の認可待ち: 変更前はBusy ACKが無く、認可回復後もDATA未受領（`authorization-before.log`）。最終はBusyとして待機し受領。
- 中6: driver readbackのHost変換前はtx_power_qdbmが無くKeyError（`power-before.log`）。既知と未知を含む最終の変換・USB・fieldview試験が合格。

検証中にLinkの試行数やresponder RTOを広く変更するとgroup/Link/power/channelに退行が出たため、その変更は取り除いた。Probeだけの受理回数と、実送信完了に対応した待ちへ限定して全suiteを再実行した。Host unit/integrationの初回には負荷下でfake-hostの遅延結果試験がtimeoutした（477 pass/1 fail）。当該試験の再実行と最終の全537件が成功しており、製品の期限を延ばす変更はしていない。暗号化USB追加テストの最初のfixtureはstub adapterだったため実Bridgeへ接続して修正。HIL追加再buildでは出力先の誤指定による既定構成の失敗があり、正しい`hil_node-ROOT/esp32s3`で再buildして合格した。これらの途中失敗を実機試験の成功へ読み替えていない。

## 実行したコマンド

作業directoryは`/home/admister/dev/LeanMesh`。ログは`/home/admister/.cache/leanmesh/issue19`。Pythonは同cacheのhost-venv、IDFはpinされたv6.0.3（`76f5dedd9950a3012fee8fb7d5586df21fc67802`）。以下のtool実行は全てローカルで実施した。

```sh
git pull --ff-only
cmake --build /home/admister/.cache/leanmesh/native -j 4
ctest --test-dir /home/admister/.cache/leanmesh/native --output-on-failure -j 2
/home/admister/.cache/leanmesh/native/tests/native/test_mesh ISSUE19
LEANMESH_NATIVE_BUILD=/home/admister/.cache/leanmesh/native \
LEANMESH_E2E_REPORT_DIR=/home/admister/.cache/leanmesh/issue19/final-e2e \
/home/admister/.cache/leanmesh/host-venv/bin/python -m pytest -q \
  host/tests/unit host/tests/integration host/tests/e2e \
  --junitxml=/home/admister/.cache/leanmesh/issue19/final-e2e/pytest-results.xml
```

native 28/28 suite合格。Host unit/integration/E2E全537件合格（564.12秒、`d89adfa`のcode）。最後の相関tagのzero予約後（`6f7e885`）もnative全28件を再build・再実行し、Host fullstack/diagnosticsの4件が合格（68.22秒）。最終fullstackは21node/20hop、HTTP→DB→認証USB→実core→RESULT/groupの経路。

```sh
cmake -S . -B /home/admister/.cache/leanmesh/issue19/native-asan -G Ninja \
  -DLM_IDF_PATH=/home/admister/esp/esp-idf-v6.0.3 -DLM_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build /home/admister/.cache/leanmesh/issue19/native-asan -j 4
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir /home/admister/.cache/leanmesh/issue19/native-asan --output-on-failure -j 2
```

ASan/UBSan全28件合格（395.72秒）。その後に追加したUSBテスト、最後の相関tag変更も再buildし、`-R '^test_(mesh|diag|serial|field)$'`の4件が合格（140.73秒）。実機HILの代替ではない。

```sh
for issue19_profile in LEAF RELAY ROOT; do
  scripts/build_targets.sh --app example_node --profile "$issue19_profile" esp32s3 esp32c3 esp32c5 esp32c6
done
scripts/field.sh build leaf esp32s3
scripts/field.sh build relay esp32s3
scripts/field.sh build display esp32s3
scripts/hil.sh build root esp32s3
```

12 firmwareとfield三役/HIL ROOTが成功。最後のtag変更後、IDF export環境で全12の既存build directoryに`idf.py -C /home/admister/dev/LeanMesh/firmware/example_node -B /home/admister/.cache/leanmesh/build/<example_node|example_node-RELAY|example_node-ROOT>/<SoC> build`と`size --format json2`を再実行した。field各build directory、`hil_node-ROOT/esp32s3`も同様に再buildして成功。flashing commandは実行していない。

```sh
/home/admister/.cache/leanmesh/host-venv/bin/python scripts/budget_report.py \
  --idf-root /home/admister/.cache/leanmesh/build --native-build /home/admister/.cache/leanmesh/native \
  --out-dir /home/admister/.cache/leanmesh/issue19/final-budget
/home/admister/.cache/leanmesh/host-venv/bin/python scripts/check_spec.py
/home/admister/.cache/leanmesh/host-venv/bin/python scripts/check_api_defined.py --native-build /home/admister/.cache/leanmesh/native
/home/admister/.cache/leanmesh/host-venv/bin/python scripts/scenario_coverage.py --out-dir /home/admister/.cache/leanmesh/issue19/scenario-coverage
/home/admister/.cache/leanmesh/host-venv/bin/ruff check host/leanmesh_host/bridge/diag.py host/tests/unit/test_diag.py \
  host/tests/unit/test_fieldview_nodelog.py tools/fieldview/protocol.py tools/fieldview/nodelog.py
scripts/third_party.sh verify
git diff 7f62aaa --check
```

G0/spec、38公開C API定義、Ruff、差分検査、vendor pin/blob検証が成功。scenarioは158件/342 references、hardware NOT_RUNが116件。CIのsim power-cut matrix filters（test_join POWER、test_lifecycle M05/LC08、test_channel POWER、test_delivery POWER-）も成功。G0の生成JSONはcacheへ保存し、過去の`evidence/VALIDATION.json`は保持した。libedhocの既存3file変更は指定patchで、今回のcommitへ追加していない。

## 資源差分

比較元/今回とも同じ4SoC、3profile、IDF pin、-Os、crypto backend。同じbudget_report手順で測定した。[機械可読差分](issue19-budget-diff.json)。Flash列はbaseline commitとのimage増分、SDK Flash列はlibleanmesh.aのcode+data増分。固定RAMはworkspace + SDK静的DRAM（固定task stack/ring等を含む）。vendor heap/crypto peak/RTCは別。imageにはbuild metadataも含まれる。

| 集計範囲 | baseline | 今回 | 差分 |
|---|---:|---:|---:|
| firmware C/C++ | 2,030 | 2,136 | +106 |
| IDF extension header | 25 | 44 | +19 |
| fieldview Python | 2,400 | 2,414 | +14 |
| SDK C/C++ | 39,818 | 40,125 | +307 |
| Python Host (excluding tests) | 5,664 | 5,667 | +3 |

SDKは既存のcore+idf+root+serial集計で、test/vendor/generatedを含まない。firmware、IDF拡張header、fieldviewは別欄。SDKの28k上限はbaselineから超過したまま（今回もOVER）、Hostは6k以下。SLOCやテスト数を完了度の指標にしていない。

単位B。workspaceは全4SoCでLEAF +272、RELAY +400、ROOT +1,360。

| SoC | profile | image Δ | SDK Flash Δ | 静的DRAM Δ | workspace baseline → 今回 | 固定RAM 今回 (Δ) |
|---|---|---:|---:|---:|---:|---:|
| esp32c3 | LEAF | +3,802 | +3,802 | +59 | 41,400 → 41,672 | 63,752 (+331) |
| esp32c3 | RELAY | +3,644 | +3,644 | +59 | 45,704 → 46,104 | 69,304 (+459) |
| esp32c3 | ROOT | +4,144 | +3,960 | +59 | 129,504 → 130,864 | 185,864 (+1,419) |
| esp32c5 | LEAF | +3,804 | +3,804 | +59 | 41,400 → 41,672 | 63,752 (+331) |
| esp32c5 | RELAY | +3,646 | +3,646 | +59 | 45,704 → 46,104 | 69,304 (+459) |
| esp32c5 | ROOT | +4,142 | +3,962 | +59 | 129,504 → 130,864 | 185,864 (+1,419) |
| esp32c6 | LEAF | +3,894 | +3,894 | +59 | 41,400 → 41,672 | 63,752 (+331) |
| esp32c6 | RELAY | +3,752 | +3,752 | +59 | 45,704 → 46,104 | 69,304 (+459) |
| esp32c6 | ROOT | +4,290 | +4,122 | +59 | 129,504 → 130,864 | 185,864 (+1,419) |
| esp32s3 | LEAF | +3,276 | +3,284 | +67 | 41,400 → 41,672 | 63,768 (+339) |
| esp32s3 | RELAY | +3,216 | +3,194 | +67 | 45,704 → 46,104 | 69,320 (+467) |
| esp32s3 | ROOT | +3,508 | +3,287 | +67 | 129,504 → 130,864 | 185,884 (+1,427) |

改訂RAM予算48/56/160KiBも全profileでbaselineからOVERのまま。空IDF+ESP-NOWに対するFlash予算256KiB、ROOT審査線320KiBも従来超過しており、本対応で予算内達成とは報告しない。C3 ROOTはminimum-ever free heap ≥48KiBのHILが無く非サポートのまま。

RTC restart recordはC3 ELF symbolで44B（以前の4×u32 layoutは16B、+28B）、上表のDRAMとは別。native software crypto測定はPSA heap 4,368B、worker stack 8,792B、合計13,160Bでbaselineと同じ。SDK owner/workerの固定stack予約は8,192/10,240Bのまま。SoCのstack high-water、Wi-Fi/NVS込みpeak heap・最大連続blockは未測定。

## 省電力と未検証

3modeの通信/認証engineは共通のまま。新しい無条件1/2ms pollは無い。ROOTの1秒watchはHILアプリに限る。fieldの出力ログは既存10秒診断時に値が変わったときだけ追加。Sleep/予定channel gap/ローカルBUSYをRF損失へ加算しない。counter/replay保持、secret消去、PM lock、sleep ticketの既存経路を維持し、power・group・channelのnative suiteで退行を検査した。個別group結果も既存E2Eで確認した。

共通coreのnative検査と4SoCのbuild検査は成功したが、4SoC HILは実施していない。電波/長距離、実機FAULT→radio/USB復旧、Light/Deep Sleep、電源断、鍵custody/相互接続、steady idle CPU、airtime、J/report、復帰エネルギーは未検証。field/HIL app imageのbaseline差分も別測定が必要。sim/store-cutは実coreの試験であり、実電波・実電源断・実測電流の証拠ではない。G0に含まれるsynthetic電流を実測に扱わない。

## commit

| commit | 不変条件・縦経路 |
|---|---|
| bcb42bf | Probeローカル拒否とattach試行数の分離 |
| 26d04bf | 送信完了とProbe/control/DATA待ちの対応 |
| 09a8ad4 | DATAの有界peer/destination backoff |
| de517cc | ROOT/fieldのFAULT分類・復旧・RTC/Host診断 |
| 225a357 | 実送信出力のIDF→serial/Host/field縦経路 |
| d89adfa | CIのfield/HIL ROOT S3 build |
| 6f7e885 | control相関tagのzero予約 |
