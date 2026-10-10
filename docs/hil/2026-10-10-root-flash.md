# このPCの親機S3: 全消去・書込み・起動確認

2026-10-10。ユーザーが「接続した親機の中身を全消去して書き込んでよい」と明示した後、その1台だけを操作した。表示板・中継器、KGリポジトリ、旧PCの鍵には触れていない。これは試験用firmwareの書込み確認で、mesh/RFや製品の認定ではない。

## 対象と書き込んだ版

- Windows USB port: COM7（その時点で列挙されたserial portは1個）。USB VID:PID 303A:1001。
- esptoolで実個体を確認: ESP32-S3 QFN56 rev0.2、PSRAM 8MB、Flash 8MB、MAC `e0:72:a1:d7:77:28`。
- firmware: `hil_node` ROOT / esp32s3、基準main `37df3f20ac9b90c9e7b85d429f2d88df88cdb27d`。前回の通信問題の修正（PR #18/#21/#22）を含む。新しい人感アプリは表示板専用で、親機firmwareのソースは変更していない。
- IDF v6.0.3、commit `76f5dedd9950a3012fee8fb7d5586df21fc67802`。
- app binary: 1,022,304 bytes、SHA256 `bf2d9d94c9708baa44096eac2b399a9c583394be1682646560d38116b6fe673f`（既存の検証済みbuildと一致）。
- 物理Flashは8MB。検証済みfirmwareの4MB partition設定をそのまま使った。eFuseやFlash encryption設定は変更していない。

## 実行したコマンドと結果

Windowsの既存Python環境を置き換えず、`uv run --no-project --with esptool==5.5.0` の隔離環境を使用した。cacheは `C:\Users\daits\AppData\Local\Temp\opencode\uv-cache`。

```powershell
python -m serial.tools.list_ports -v
uv --cache-dir "C:\Users\daits\AppData\Local\Temp\opencode\uv-cache" run --no-project --with esptool==5.5.0 python -m esptool --chip esp32s3 --port COM7 chip-id
uv --cache-dir "C:\Users\daits\AppData\Local\Temp\opencode\uv-cache" run --no-project --with esptool==5.5.0 python -m esptool --chip esp32s3 --port COM7 flash-id
uv --cache-dir "C:\Users\daits\AppData\Local\Temp\opencode\uv-cache" run --no-project --with esptool==5.5.0 python -m esptool --chip esp32s3 --port COM7 erase-flash
```

全消去は4.5秒で成功。続けて同じMACの個体へ `--baud 460800 --before default-reset --after hard-reset write-flash --flash-mode dio --flash-size 4MB --flash-freq 80m` で次を記録した。ファイルは `\\wsl.localhost\Ubuntu-24.04\root\.cache\leanmesh\build\hil_node-ROOT\esp32s3` のもの。

| Offset | File | 結果 |
|---|---|---|
| 0x0 | bootloader/bootloader.bin | 書込み後hash検証成功 |
| 0x8000 | partition_table/partition-table.bin | 書込み後hash検証成功 |
| 0xe000 | ota_data_initial.bin | 書込み後hash検証成功 |
| 0x50000 | leanmesh_hil_node.bin | 書込み後hash検証成功（app転送3.6秒） |

その後 `python "C:\Users\daits\AppData\Local\Temp\opencode\root_probe.py"` を実行。probeはUSBの個体番号が上記MACと一致する1台だけを開き、DTR/RTSを操作せず、`info`だけを送った。返答:

```text
OK state=0 role=root
```

Rootアプリが起動し、全消去後の未登録状態であることを確認した。今回の手順中に消去/書込み/probeの失敗は無い。鍵生成・provisioning・Host接続・無線開始・子機との通信はまだ行っていない。初期登録待ちをmesh通信成功と扱わない。

## 次の作業と未検証

このPC用に新しい試験fleet/Hostの鍵を作り、親機を登録してHostへ接続する。旧PCの秘密鍵は移行しない。Linux Hostから実USBを使う設定は別途必要。ほかの9台は個体を確認してから書込み、TOF付き1台の指定・K1/K3配線と実動作・光学条件・RF・長時間試験を行う。今回の書込みはそれらの合格ではない。
