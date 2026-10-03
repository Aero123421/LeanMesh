# field_node: 屋外試験キットのノード (bench / field 試験専用)

`docs/field/protocol.md` のノード側。製品image・SDK coreではない(plaintext NVS、bench用RF承認、test fleet)。ルートは
`firmware/hil_node` のROOT build、PC側は Host と `tools/fieldview`。

## 何をするか

- 未provisionの板: `firmware/hil_node` と同じ行コンソール(`info` `keygen` `prov-leaf <trust88> <device_cose> <ticket>` `reboot`)。
  コンソールは `firmware/common/bench_console` を両方が使う。`tools/hil/hil.py provision leaf|relay|display` がそのまま動く。
- provision済みの板: 電源を入れるだけで自律動作(コンソール不要)。
  - **join**: ACTIVEでなければ `lm_join(NEW)` を自分で出す。1回が終わったら 5, 10, 20, 40, 60, 60 ... 秒待って再度。ACTIVEなら
    SDKが自分で再接続する(何もしない)。REVOKED / QUARANTINED は尋ねるのをやめる。
  - **telemetry** (app_port 210, 44 byte, protocol 3.1): REACHABLEになった直後に1回、以後 10 s + 0..1000 ms ごと。
    `LM_DEST_ROOT_APP`、BEST_EFFORT、VOLATILE、期限30 s(root時計。root時刻が無い間は送らない)。seq は受理された送信だけ進める
    (rootで見える欠番=本当の損失)。NVSのboot counterを載せる。
  - **ping** (211): 受けたら直ちに `APPLIED` を報告。版が違えば `REJECTED`。
  - **display state** (212): displayビルド以外は `REJECTED`。displayビルドは描画し、panelに出てから `APPLIED`、描けなければ
    `REJECTED`。状態とseqをNVSに保存し、再起動後に描き直す。
  - 電源方針は常に ALWAYS_RX(起動直後にSDKのpolicyがそうでなければ戻す。hil_nodeの10秒の `safe` 窓は待たない。`safe` 行は受けて何もしない)。
- 起動後のコンソール(任意。何も依存しない): `info` `status` `field`(最後のtelemetryとカウンタ) `join`(待ちを飛ばして今すぐ) `ev [on|off]`(EV行) `reboot`。

## ビルドと書込み

`scripts/field.sh build|flash|update <relay|leaf|display> ...` (hil.sh と同じ流儀。buildは `$LEANMESH_BUILD_ROOT` 、repoの外)。

| 板 | build | 備考 |
|---|---|---|
| ESP32-S3 | `scripts/field.sh build relay esp32s3` / `leaf esp32s3` | |
| ESP32-C3 | `scripts/field.sh build relay esp32c3` / `leaf esp32c3` | |
| XIAO ESP32-C6 | `scripts/field.sh build relay esp32c6` / `leaf esp32c6` | RFスイッチ(GPIO3 low)とオンボードアンテナ(GPIO14 low)は `firmware/common/sdkconfig.board.esp32c6` (hil_nodeと共通) |
| HUB75 S3 | `scripts/field.sh build display esp32s3` | RELAY + `CONFIG_FIELD_HUB75=y`。S3専用 |

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
行30..31: 緑=REACHABLE、青=到達不可・メンバーでない・REVOKED、黄=join中。16x16の5字(使 用 可 禁 止)は東雲フォント(Public Domain)。
パネルのライブラリは ESP32-HUB75-MatrixPanel-DMA (MIT、`main/idf_component.yml` でcommit固定、Adafruit GFXなし)。ESP-IDF v6.0.3では
GDMA APIが変わったためそのままではcompileできず、`third_party/patches/esp32-hub75-matrixpanel-dma-3.0.14-idf6-gdma.patch` をconfigure時に当てる
(`third_party/` と `THIRD-PARTY-LICENSES.md` の1b・2)。

## 検証していないこと

- どのビルドも実機で動かしていない(compile/linkと、wire format・join待ち時間・panel frameのhost単体試験だけ: `tests/native/test_field.cpp`)。
- HUB75 panelが実際に表示されること(patch済みライブラリのIDF v6上の動作、FM6124のタイミング、APPLIEDを返す時点でframeが出ていること。
  待ちは「2 refresh」40 msの見込み)。
- 親RSSI(SDK側の追加待ち)。無効なら -128 を送りstatus行は `--`。
- 電波・距離・topology・消費電力・長時間のheap/stack。電源断中のNVS書込み。
- C3 / C6 の LED 配線(既定のGPIOは板により違う)。
