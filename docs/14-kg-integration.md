# 14 KGuard適用例 — coreをKG専用にしない

## 1. 最新読取結果
KG `4ed3e1f` の `apps/edge-go/internal/displaylink/transport.go` は現在のWi-Fi parentを差替えるTransportを定義する。keys/verification/meaningはPortが所有し、EventFrameは**未認証**、SendWrittenはserial Write完了でしかない。Go READMEは2026-09-27基準でsitecoreが現場安全判断を持ち、USB S3親機を使い、RouteLoom runtimeは同梱しないと記載する。[KG-CODE-01,02]
KG #112の2026-09-28 20:37追記はRouteLoom v2の計画を説明し、S3/C3/C5/C6、Device API、EDHOC worker、4KiB object、賢いJoin、手動移設、IDF6.0.3移行を提案している。これは既存mainで完成した証拠ではない。[KG-112-NEW]

## 2. integration境界
```text
KG sitecore/Port
    ↕ KG DeviceLink adapter + KG-WIRE codec
LeanMesh FastAPI local API
    ↕ authenticated USB
LeanMesh Root S3
    ↕ mesh
LeanMesh SDK + KG application on S3
    ↕ UART
Pico描画
```
KGのroot/relayにKG固有のsensor enumやCloud tokenを置かない。sensor判定、Pico待ち、禁止/解除、binding/calibrationはKG。デバイスcredentialとdiscoveryはSDK。shared counterの乱用でKG binding_epochとSDK membership_generationを一緒に増やさない。

## 3. 既存Transportへの対応
|現在の口|adapterの実装|
|---|---|
|Run|FastAPI/serial状態の監視。USBはHostが所有するためGoから二重openしない。|
|Events|cursorで保存済み受信+route変化を読む。アプリ保存後にconsumer_ack。|
|Route|domain + adapter incarnation + DeviceId + end_session_generation。USB port名だけにしない。|
|Send|Message submitの非同期受付。capacity/NO_ROUTEを対応するerrorへ。|
|SendWritten|HOST_COMMITTED/GATEWAY_QUEUEDをアプリ適用に変換しない。既存Writeと同義でない証拠には別eventを足す。|
|Bind|KG Portがframeの本人性/配置を確認した結果だけをbindingへ反映。|
|Links|reachability+最終認証受信のsnapshot。RSSIをuint64へunsigned変換しない。既存型変更はKG側の互換変更として扱う。|

新Host APIはRouteLoom API1ではない。API1のレスポンスを偽装して現行adapterをそのまま通さない。capabilitiesで本人確認証拠がない場合はUNKNOWNを保持する。

## 4. 何を運ぶか
最新コメントの区別を採用する（過去の「入退出は全部保持event」という一括分類を訂正）。
- `view`: latest desired state。テンプレート本文は低頻度object、周期には参照と世代。
- `st`: latest actual state。`drawn`・世代・内容番号が実表示証拠。通信RECEIVEDとは別。
- `occ`: latest occupancy snapshot。historyの代わりではない。
- `tr`: 累積application ACKまで保持するusage transition/history。DURABLE/FIFO。
- `ack`: applicationの累積ack/result。transport receiptと混同しない。
- `hello`: 機器capabilityと起動情報。既知ID文字列だけで認証しない。

SDK payloadはopaque。KG-WIRE v2は別repository/adapterのversioned契約。資料中のサイズ試算（view約110B、template参照82〜98B等）は既存RouteLoom向けの計画値で、本SDKの実測ではない。LeanMeshはroot20hopで96B single-frameなので110Bは分割が必要、st約88B等は1frame候補。長いpathでも無言切詰めをしない。

## 5. 実適用
使用禁止・解除などの業務命令はcommand_id、target DeviceId、binding_epoch、desired_generation、control_mode、元expiryを維持。Sensor unknown、通信offline、安全holdは別の軸。短い通信断で赤にする/空室にするというルールをSDKへ埋めない。Picoの一致した応答がなければKGアプリはAPP_APPLIEDを報告しない。
`view`の周期的な最新化だけで、監査上のcommand outcomeを破棄してよいわけではない。業務操作ledgerと周期stateは別。遅いst/ackは歴史証拠として残し、新generationを巻き戻さない。

## 6. Join/移設/交換
QRはasset候補特定、DeviceCredentialの暗号検証が本人確認。SDKのMemberCredentialに、トイレ番号や校正値を格納しない。
同現場の移動: KG binding/calibration revision更新、SDKは経路を修復するだけ。
現場A→B: fleet署名AssignmentTicketによる移設、A停止でもB commitを可能にする。KG inventory/installationはその証拠を受けて別transactionで更新。KG update失敗で網側移設をなかったことにしない。
故障交換: roleは引継げるが旧DeviceId/session/未完command/calibrationはコピー禁止。

## 7. 移行手順
まずbinary fixtures+adapter contract→IDF移植→MiniPC/S3 root/2表示盤/relayの24h PoC→72h現場pilot。旧FW/設定/DB互換を含めた切戻しを残し、1表示盤への制御ownerを1経路に固定する。
現在Arduino版の動作資産を全削除して同時全面書換えしない。センサー判定器やPico wire等のpure C++を再利用し、旧通信taskだけを置換。IDF6.0.3とArduino componentの実版互換が未検証なら互換ありと言わない。SDKの公式baselineはIDFでありArduinoラッパーは追加検証後。

## 8. 受入
KG #109の10ESP自動形成/relay抜去/全台再起動は10台試験であり10hop証明ではない。3表示盤の対象別反映、温度/水位等の実測→KG安全判断→描画→戻り証拠→復旧を通す。#112最新案の5s更新、st p99<2s、reset20回<10s、CURSOR_GAP0は**小規模PoCの目標**であり20hopへそのまま保証しない。古いIssueの一律反復回数を新たな利用者決定として復活させない。
