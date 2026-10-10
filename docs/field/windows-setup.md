# このPCの試験環境（Windows / WSL2）

2026-10-09、LeanMesh main `37df3f20ac9b90c9e7b85d429f2d88df88cdb27d` を基準に準備。機器の消去、書込み、鍵生成、旧PCからの鍵移行は未実施。

## 準備した場所

- WSL2: `Ubuntu-24.04`（Docker用の環境とは別）
- Linux作業用checkout: `/root/leanmesh-work`
- ESP-IDF: `/root/esp/esp-idf-v6.0.3`、固定commit `76f5dedd9950a3012fee8fb7d5586df21fc67802`
- S3/C3/C5/C6 toolchains: `/root/.espressif`
- Host Python 3.12の固定依存: `/root/.cache/leanmesh/host-venv`
- native build: `/root/.cache/leanmesh/native`

Windowsの編集元は `C:\dev\job\LeanMesh`。Linux checkoutはビルド用の写しであり、編集内容を同期してからビルドする。秘密鍵や機器の登録はまだ作っていない。既存の別プロジェクトやDocker環境は変更しない。

## 実施した確認

PowerShellから `wsl --install --distribution Ubuntu-24.04 --no-launch`、Linuxのcompiler/CMake/Ninja/Python等をaptで導入、固定版IDFをcloneして `install.sh esp32s3,esp32c3,esp32c5,esp32c6` を実施。`third_party.sh setup/verify` と `setup_host_venv.sh sync-dev` を実施した。

基準commitの `cmake --build` と `ctest --output-on-failure -j4` は28/28合格。fieldview core/nodelogのpytestは113件合格。IDF v6.0.3起動とHost `pip check` も成功。実機の合格を意味しない。

機能追加後の最終確認: native 31/31、ASan/UBSan 31/31、Host全pytest 608件、仕様検査とRuffが合格。表示板の通常/ToF版、S3/C6中継器、S3親機、4SoC×3profileのビルドも合格。差分・実行コマンド・途中失敗・未検証は [検証記録](../../build-records/field-presence-validation.md)。学習値は試験用にRAMだけで持つため、表示板を再起動したら誰もいない状態でK1を押す。

## 今後の機器構成

表示板3台（うちTOF400C付き1台）、XIAO C6中継器3台、XIAO S3中継器3台、別の親機1台。C6のオンボード/外付けアンテナを実機で確認してbuildを選ぶ。センサー付き表示板は別build。書込み先はUSBポート名だけでなくボードの個体を確認する。

USBのWSLへの接続は未設定。機器書込み前にユーザーの確認が必要。学習操作は誰もいない状態でK1を押す。通知は既存のブラウザーfieldviewで確認する。

2026-10-10追記: ユーザー承認後、親機S3（MAC `e0:72:a1:d7:77:28`、COM7）だけをWindows側esptoolで全消去・書込みし、`state=0 role=root` の起動を確認した。[実行記録](../hil/2026-10-10-root-flash.md)。新しい鍵・親機登録・Host接続はまだ。表示板と中継器は未書込み。
