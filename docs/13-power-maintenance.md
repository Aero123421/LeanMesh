# 13 省電力、保守、OTA

## 1. 省電力の正本
spec0.2は[20章](20-low-power.md)を省電力の規範章にする。ALWAYS_RX、WINDOWED_RX、REPORT_ONLYの3mode。roleはLEAF/RELAY/ROOTとは別軸。sleepy機器は中継させない。旧称ALWAYS_ON_APPLICATION/ALWAYS_ON_RELAY/SLEEPY_LEAFを別protocolとして実装しない。

## 2. 省電力で削ってはいけないもの
本人認証、replay状態、counter単調性、durable受理、MessageId、deadline、有限容量を維持する。RAM保持の短い休止とcold/deep bootを区別する。未ACK履歴を永続保存して次wakeへ持ち越す場合も、relay RAM ACKだけを完了扱いしない。

## 3. 下り・一斉配信
leaf主導AWAKE_POLLと有界mailboxを使う。眠るtargetはWAIT_WAKE、期限内に受信不能と分かればDEADLINE_UNREACHABLE。groupの他targetの送信を止めない。詳細は[22章](22-group-and-sleep.md)。

## 4. 実測
J/report、mAh/cycle、圏外mAh/h、CPU/無線/Flash/周辺回路を[23章](23-energy-and-qualification.md)で測定する。Sleep中の電流だけで電池寿命を名乗らない。


## 5. object
最大4096B、1bulk受信slot、通常control用予約slotとは分離。config/template/logの意味はapp。オブジェクトが受信完了してもappへ設定適用済みとしない。version/hash/preconditionが一致した時にアプリがatomic適用してresultを返す。

## 6. OTA（optional独立release gate）
共通object engineで4096Bのimage blockをinactive OTA slotへstream。image全体をRAMに持たない。署名manifestはtarget SoC/board constraints、image_size/hash、version、security_version、storage_schema_min/max、minimum_loader、block_size4096を持つ。中継の急停止を避け、rootがleaf→relay→rootの順で更新する。
4MiB layoutは `config/partitions_4m.csv`。OTA2面を事後に空きがあると思って追加しない。flash容量不足ならOTA_UNSUPPORTED、identity領域を削ってねじ込まない。
manifest検証→inactive slot消去/書込み→hash検証→boot target更新→新image boot→自己試験/最低限通信→esp_ota_mark_app_valid_cancel_rollback。未確認起動はIDF rollback機構で復旧。[E07] ストレージschemaを旧imageが読めない形へ不可逆移行する前にrollback windowを閉じる設計が必要。
安全版数のeFuse変更は復旧計画と承認を必須とし、通常OTAのついでに焼かない。Secure Boot/Flash Encryption/適切なanti-rollbackは製品ごとに有効化・確認。OTA対応をうたうには実機power-cutとboot rollback試験が必要。

## 7. PC-less
rootのlocal C APIはHostなしで使用可能。外部internetにはSPI Ethernet/別radio/別modemを使用する。単一radio AP接続と自動channel最適化を同時保証する新modeはこのreleaseへ入れない。uplink adapterがtransport受付を返しても、cloud/serviceの永続受理を偽装しない。
