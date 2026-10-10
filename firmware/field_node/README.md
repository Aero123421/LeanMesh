# field_node: 屋外試験キットのノード (bench / field 試験専用)

`docs/field/protocol.md` のノード側。製品image・SDK coreではない(plaintext NVS、bench用RF承認、test fleet)。ルートは
`firmware/hil_node` のROOT build、PC側は Host と `tools/fieldview`。

## 何をするか

- 未provisionの板: `firmware/hil_node` と同じ行コンソール(`info` `keygen` `prov-leaf <trust88> <device_cose> <ticket>` `reboot`)。
  コンソールは `firmware/common/bench_console` を両方が使う。`tools/hil/hil.py provision leaf|relay|display` がそのまま動く。
- provision済みの板: 電源を入れるだけで自律動作(コンソール不要)。
  - **join**: ACTIVEでなければ `lm_join(NEW)` を自分で出す。1回が終わったら 2, 4, 8, 15, 20, 20 ... 秒待って再度。ACTIVEなら
    SDKが自分で再接続する(何もしない)。REVOKED / QUARANTINED は尋ねるのをやめる。
  - **telemetry** (app_port 210, 44 byte, protocol 3.1): REACHABLEになった直後に1回、以後 10 s + 0..1000 ms ごと。
    `LM_DEST_ROOT_APP`、BEST_EFFORT、VOLATILE、期限30 s(root時計。root時刻が無い間は送らない)。seq は受理された送信だけ進める
    (rootで見える欠番=本当の損失)。NVSのboot counterを載せる。
  - **ping** (211): delivery RECEIVED (protocol 3.2)。SDKの受領がそのまま答えで、アプリは結果を報告しない。数えるだけ(`field` の
    `pings`、版や長さが違えば `pings_unknown`)。
  - **display state** (212): displayビルド以外は `REJECTED`。displayビルドは描画し、DMAが新しいbufferを1周分panelへ送った
    証拠(patch済みライブラリのGDMA frame終了割り込みを数える。protocol 3.3)を得てから `APPLIED`。panelが起動していない・証拠が
    300 ms以内に来なければ `REJECTED` + telemetryのrender fault。panelが起動できなかったときは1分ごとに(最大10回)初期化し直す。
    状態とseqをNVSに保存し、再起動後に描き直す。
  - 電源方針は常に ALWAYS_RX(起動直後にSDKのpolicyがそうでなければ戻す。hil_nodeの10秒の `safe` 窓は待たない。`safe` 行は受けて何もしない)。
- 起動後のコンソール(任意。何も依存しない): `info` `status` `field`(最後のtelemetryとカウンタ) `join`(待ちを飛ばして今すぐ) `ev [on|off]`(EV行) `reboot`。

## ビルドと書込み

`scripts/field.sh build|flash|update <relay|leaf|display|display-tof> ...` (hil.sh と同じ流儀。buildは `$LEANMESH_BUILD_ROOT` 、repoの外)。

| 板 | build | 備考 |
|---|---|---|
| ESP32-S3 | `scripts/field.sh build relay esp32s3` / `leaf esp32s3` | |
| ESP32-C3 | `scripts/field.sh build relay esp32c3` / `leaf esp32c3` | |
| XIAO ESP32-C6 | `scripts/field.sh build relay esp32c6` / `leaf esp32c6` | RFスイッチ(GPIO3 low)とオンボードアンテナ(GPIO14 low)は `firmware/common/sdkconfig.board.esp32c6` (hil_nodeと共通) |
| HUB75 S3 | `scripts/field.sh build display esp32s3` | RELAY + `CONFIG_FIELD_HUB75=y`。S3専用 |
| HUB75 S3 + ToF (1台のみ) | `scripts/field.sh build display-tof esp32s3` | 同じS3が全機能を担当。別出力 `field_node-display-tof/esp32s3` |

```sh
export IDF_PYTHON_DIR=/opt/homebrew/opt/python@3.12/libexec/bin LEANMESH_BUILD_ROOT=$HOME/.cache/leanmesh/build-field
scripts/field.sh build relay esp32c3
scripts/field.sh flash relay /dev/cu.usbmodemXXXX esp32c3     # 全消去してから書く(新しいbench identity)
scripts/field.sh update relay /dev/cu.usbmodemXXXX esp32c3    # appだけ(identityとmembershipを残す)
```

**HUB75 S3 板**(Seengreat RGB Matrix HUB75 S3、ESP32-S3-WROOM-1-N16R8)はUSB自動リセットが無い。書込み前に手でダウンロードモードにする:
BOOTを押したままEN(リセット)を押して離す。`field.sh flash|update display ...` は `--before no-reset --after no-reset` で書くので、
書き終えたらENを押して起動する。パネルのピンは板に固定(R1=5 G1=4 B1=6 R2=15 G2=7 B2=17 A=8 B=18 C=10 D=9 E=16 LAT=11 OE=13 CLK=12)、64x32、FM6124、
`clkphase=false`。明るさは `CONFIG_FIELD_HUB75_BRIGHTNESS`(既定96/255)。

## provision(机の上で一度)

Host側が済んでいること(`hil.py init`、rootのprovision、`hil.py policy PREAPPROVED`)。板ごとに:

```sh
PYTHONPATH=host ~/.cache/leanmesh/host-venv/bin/python tools/hil/hil.py provision leaf  --port /dev/cu.usbmodemX --name leaf1
PYTHONPATH=host ~/.cache/leanmesh/host-venv/bin/python tools/hil/hil.py provision relay --port /dev/cu.usbmodemY --name relay1
PYTHONPATH=host ~/.cache/leanmesh/host-venv/bin/python tools/hil/hil.py provision display --port /dev/cu.usbmodemZ --name disp1
PYTHONPATH=host ~/.cache/leanmesh/host-venv/bin/python tools/hil/hil.py expected leaf1     # rootにExpectedSetを入れる(板ごと)
```

provisionすると板が再起動し、そのまま動き出す。

## LED(任意、Kconfig `FIELD_LED`)

既定: XIAO ESP32-C6 は GPIO15 のユーザLED(active low)、他は無し。`FIELD_LED=low:<gpio>` / `high:<gpio>` / `none` を
`scripts/field.sh build` に環境変数で渡して変える(新しいbuild dirが要る)。点滅=join中、点灯=REACHABLE、消灯=メンバーでない/LOST/REVOKED。
タイマーもtaskも使わず、アプリループ(50 ms)から切り替える。

## パネル(displayビルド、64 x 32)

行0..7: status行(5x7)`H2 -67`(hop数と親RSSI)/ `JOIN` / `LOST` / `REVOKED`。行8..23: 使用可(緑、3字)/ 使用禁止(赤、4字)を16x16で中央。
行30..31: 緑=REACHABLE、青=到達不可・メンバーでない・REVOKED、黄=join中。
16x16の12字(使 用 可 禁 止 学 習 中 完 了 失 敗)は東雲フォント(Public Domain)、
KG `b80ce46d` の `firmware/pico-hub75/src/fonts_hybrid.hpp` から各16行をそのまま抜粋。
パネルのライブラリは ESP32-HUB75-MatrixPanel-DMA (MIT、`main/idf_component.yml` でcommit固定、Adafruit GFXなし)。ESP-IDF v6.0.3では
GDMA APIが変わったためそのままではcompileできず、`third_party/patches/esp32-hub75-matrixpanel-dma-3.0.14-idf6-gdma.patch` をconfigure時に当てる
(`third_party/` と `THIRD-PARTY-LICENSES.md` の1b・2)。2本目の `...-gdma-errors-and-frames.patch` はGDMAの各エラーを `begin()` の失敗にし
(以前はlogして続行し、`begin()` はbufferができたことだけで真を返した)、frame終了割り込みでframe数を数え、`release()` でDMAを止めて
descriptor・channel・peripheralを解放する。どちらもconfigure時に冪等(各々のmarkerで判定)、この順に当てる。

## ToF・K1・K3 (display / display-tof)

正本は [`docs/field/presence.md`](../../docs/field/presence.md)。通常のdisplayはセンサーdisabled、
display-tofだけがVL53L1Xを使う。通常displayはdetectorのheader/source、128 sample/16 transition ringも除外し、
軽量なdisabled/no-sensor wrapperだけを使う。relay/leafにはI2C取得taskもセンサードライバーも入らない。

- ToF: I2C1 **400kHz** SDA GPIO43 (TX0) / SCL GPIO44 (RX0)、XSHUTなし。Long、33ms/40ms、ROI8x8、center199。
- キー: 別I2C0 **100kHz** GPIO1/2、PCA9557 0x19、K1 bit1 / K3 bit2 active-low。
  **印刷されたK2/K3と実行例の定義が矛盾しており、実物のK3対応はHIL未検証**。
- K1は操作者の「空」の宣言。KG detectorをそのまま使い、起動時は未学習。
  学習はRAMのみ、再起動後は再度K1。学習中のK1は再開始しない。
  再学習がsample間のtickで失敗しても、古い空状態を公開しない。古い背景は保持し、
  失敗後の新しいsampleでdetectorが判断し直すまではUnknown。
- K3はROOT_APPへ1件だけRECEIVED通知。対応するEND_RECEIVEDだけがRECEIVED表示。
  受理/SENT/HOP_ACCEPTEDでは成功にしない。30秒は実際の押下から数え、追加押下はbusy。
- `field_io`: stack予約6144 byte、priority4、唯一のI2C/検出owner。
  25msキー期限、40ms取得/時刻更新期限、初期化再試行3秒。I2C取引は20msで打ち切る。
  5ms固定pollは使わない。mainの描画/USB待ちは取得taskを止めない。
- mainへ渡す状態は最新1件。キーqueueは8件、満杯なら新しいイベントを捨て、drop数を飽和加算。
  SDK送信・通知完了確認・描画はmainだけ。K1は取得taskで学習要求を処理する。
- snapshot (214/44byte)は意味のある変更を最大1Hz、10秒更新、送信中1件。
  K3 (215/20byte)は実際のdebounce押下時刻を含む。独立したrandom nonzero boot ID。
  snapshotのK3 seq/resultは同じ追跡operationの組。busy/dropした物理押下のseqに古い成功を結び付けない。
  生の押下数は`field` diagnosticsの`k3_presses`だけ。`learning_busy`は新学習を断った回数。
- 学習表示は16x16で中央に **学習中**(黄) / **完了**(緑) / **失敗**(赤)、行8..23。
  学習中のanimationは行24、mesh barは行30/31。通信・no-sensor表示は既存の英大文字。
  学習完了結果は固定1 slotに保持し、
  K3送信animationより優先する。mainがそのtokenのframeのDMA成功を確認してから3秒表示し、
  K3へ戻る。panelが失敗/遅延しても未表示の結果を時間だけで捨てない。
  表示待ち/表示中の新しいK1はbusyとして断り、古い結果を上書きしない。
  行30/31のbarは変えない。Hostの表示命令はoverlayを外して実フレームをDMAへ渡してからAPPLIED。

native試験はwire/debounce/queue/receipt状態/実KG detector/実ドライバーをfake I2Cで試す。
電気・光学・物理LEDの観測ではない。供給電圧/pull-up、GPIO43 boot出力とreset/download、
負荷中の実際の40ms取得、9ノード+rootでのRF/Host受領、実機stack/heap/CPU/電流は未検証。

日本語glyph追加前のreview修正時点の測定（base `37df3f20ac9b90c9e7b85d429f2d88df88cdb27d`）：
`scripts/budget_report.py` のcounterでfirst-party field applicationは1266→2075 SLOC (+809、review修正分+111)。
KG detector再利用は別枠880 SLOC、native I2C shimは別枠45 SLOC、SDK core差分0。
hostの`sizeof`はdetector1552 / key queue込み176 / snapshot48 / K3 slot56 / snapshot-send slot88 byte。
task stack予約6144 byteは設定値で、実機の使用量ではない。
native wrapper objectのtext/data/BSSはnon-ToFで308/0/1 byte、ToFで2140/8/1616 byte。
これは同じhost compilerでの比較であり、ESP32のFlash/静的RAM測定ではない。
native通常・ASan/UBSanの`test_field`、`test_field_driver`、`test_field_disabled`、
`test_field_disabled_symbols`はPASS。最後の試験はnmでdetector/driver symbolが無いことを検査する。
review前のfull IDF buildはmainが通過を報告済み。この修正後の両display/relay/leafのfull IDF buildと
Flash/静的RAM差分はmainが再検証する。

## 検証していないこと

- どのビルドも実機で動かしていない(compile/linkと、wire format・join待ち時間・panel frameのhost単体試験だけ: `tests/native/test_field.cpp`)。
- HUB75 panelが実際に表示されること(patch済みライブラリのIDF v6上の動作、FM6124のタイミング)。「描いた」の証拠(GDMA frame終了
  割り込みが実機で来ること、flip後3 frame = 新bufferの1周)は実機未確認。来なければ起動時に `panel init failed: the DMA ends no
  frames` になる。LEDが光ったことは測れない。
- 親RSSI(SDK側の追加待ち)。無効なら -128 を送りstatus行は `--`。
- 電波・距離・topology・消費電力・長時間のheap/stack。電源断中のNVS書込み。
- C3 / C6 の LED 配線(既定のGPIOは板により違う)。
