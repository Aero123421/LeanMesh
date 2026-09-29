# 03 RF・4チップ・ビルド

## 1. 対応
ESP32-S3/C3/C5/C6をすべて必須。C6が旧RouteLoomで対象外だったことは、C6にLRがないことを意味しない。EspressifのC6公式Wi-Fi guideはESP-NOW/LRを掲載する。C5の5GHz能力を本SDKの長距離モードと混同しない。LRは2.4GHz。[E01,E02,E03; evidence/SOURCES.md]

初期ビルド基準はESP-IDF `v6.0.3 / 76f5dedd9950a3012fee8fb7d5586df21fc67802`（RouteLoom pin参照）。4targetすべてでこのpinをfetch/buildするGate B01を実装開始時に実行する。本資料で6.0.3の4targetビルドは実行していない。公式stable URLの参照版が変動するため、ヘッダー/API差はpinしたソースで確定する。更新は4targetの同一PRとfixtureで行う。

## 2. 共通radio profile（固定契約）
- STA interface起動、APへは接続しない。SoftAP/BLE/802.15.4は本profileで有効にしない。
- 2.4GHz、HT20設定、secondary channelなし。LR250を全SDK DATA/制御送信に明示設定。通常1Mbpsへの黙ったfallbackは禁止。
- LR500は同じadapter内のoptional能力だが、自動rate選択はv0.2でもbaselineにしない。自動channelはbaseline機能。
- ESP-NOW payload上限を**250Bに自主制限**。v2の1470B対応を全ボード・全peer共通と仮定しない。
- peer同時登録は最大20。16 regular + 3 transient（Join/修復）+ 1 broadcastに分ける。rootが64membersを管理しても64radio peersを常時登録しない。
- softwareによるlink AEADを使用し、ESP-NOWのLMK/CCMPを第二の必須セキュリティ方式として重ねない。plaintext application DATAは不可。broadcastはdiscoveryのhintだけ、所属・channel指示は署名検証が必要。

## 3. 初期化順
NVS/鍵floor検査→entropy条件→Wi-Fi初期化→国/許可channel/帯域/HT20→STA start→channel/power設定とreadback→ESP-NOW init→callback→broadcast peer→peer毎LR250設定。peer未登録のrate指定、Wi-Fi start前のESP-NOW送信は禁止。全戻り値を処理する。
RF profileにはcountry、board revision、antenna part、許可channel集合、tx_power上限、適合確認記録IDを持つ。**国をJPにしただけで適法・技適条件適合とはしない**。未確定profileではRF開始を拒否。数km等の到達距離は保証しない。

## 4. callbackと失敗
in-flight物理送信は1。callbackにはsession/driver generationと期待peerを照合できるowner側記録を対応付ける。公開driver callbackがtokenを返さない条件でtimeout後すぐ次TXへ進み、遅いcallbackを次のpacket成功へ割当ててはならない。
watchdog 1000msで結果不明→新規TX隔離→停止/排出/再初期化。callback drainを保証できないdriverではcontrolled reboot。再起動時はfresh sessionで旧callbackを無効化する。
NO_MEM/BUSY/peer容量不足は資源エラー。link品質の失敗サンプルへ加えない。予定off-channel/sleepも同様。受信RSSIはsigned int16 dBm、unknownはnull/validity bit。0やunsigned変換で不明を表さない。

## 5. 実機マトリクス
S3/C3/C5/C6×送受信方向16cell、unicast/loss/reset/channel migrationのそれぞれを試験。20hopは21台以上のRF chainを強制する。3台simulatorの100/100配送を100台・20hopの証拠にしない。
ボードは同じSoCでもFlash、USB、アンテナ、PSRAMが違う。XIAO等のboard overlayを別管理し、coreはPSRAM不要。4MiB Flash構成が最低保守profile、2MiBはdual-slot非対応として別能力を返す。
