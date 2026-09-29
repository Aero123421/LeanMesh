# 12 永続化、復旧、電源断

## 1. 保存対象
Device: identity credential、fleet trust/floors、membership committed+prepared、assignment高水位、boot incarnation、channel committed plan、policy revision、durable pendingとapplication receipts。
Root: 上記+member ledger、short address割当、group revision、失効floor、expected entries、外部approval決定。topology/traffic sessionは基本RAM。
Host: `db/schema.sql`。操作/冪等性/event/inbox/outbox/consumerを保存。アプリ固有の安全DBは作らない。

## 2. 2slot record
record = magic4 + schema2 + state1 + reserved1 + generation8 + payload_length4 + SHA256(payload)32 + payload + CRC32。
秘密payloadはNVS encryptionまたは固定portのauthenticated sealingで保護。CRC/hashだけで悪意ある改ざんを検出できると説明しない。
非active slotへ全record write→commit→readback/hash検査→commit markerのdurable更新→RAM公開。この最後より前に成功eventを出さない。世代は単調でwrap拒否。旧slotは安全床と新recordが残る順に回収。
片slotが破損し、高い世代が存在した証拠がある場合、古いslotへ黙って戻して失効を巻き戻さない。QUARANTINEDで復旧署名を要求。読み取りエラーを「未provision」と誤認しない。

## 3. journal
packetごとのroute/replayをFlashへ書かない。durable pending/結果のみappend、CRC+長さ+単調seq、segmented erase、commit batch最大20ms。ただしACKは当該commit以後。
leaf/relayの初期pending16件×最大512B、結果32件。rootはpending64、結果128。object本文はoptional別領域へstreamする。queue容量とFlash領域/erase余白の実測を一致させ、RAMの最大objectを100台分確保しない。
満杯時は新しいdurable受付を拒否、未ACK安全eventをlatest扱いで消さない。Nodeに長期保存不能ならNO_CAPACITYをアプリへ伝え、アプリはfault表示/別ストレージを選べる。

## 4. 故障点と唯一の正しい結果
|故障点|復旧|
|---|---|
|Join PREPARE前|未所属/旧所属|
|新member slotの途中|旧committed、未完slot無効|
|Node STORED後、root COMMIT前|PREPAREDとして同request照会|
|root COMMIT後、Node反映前|rootはconfirmed=false、再送/照会|
|Node COMMIT後、ACK消失|新membership維持、同ID結果再通知|
|transfer prepared中|旧domain active、新domainはpending|
|transfer COMMIT後|新domainだけactive、旧鍵は使用禁止|
|channel prepared中|old channelで照会|
|channel committed後|target channelで復旧、単独rollbackしない|
|物理適用直後、結果保存前|アプリが照合するまでINDETERMINATE|
|Host DB commit後、HTTP切断|同keyで保存済みoperationを返す|
|Host receive commit後、serial ACK損失|dedupしてACK再送|
|古いDB backupへ復元|new client epoch、root/fleet高水位照合。自動再発行停止|

全点で電源断を注入する。存在しないcommitを「おそらく完了」と復元しない。

## 5. 認可情報の回復
root ledgerを失ったら空member網として同じdomainキーで再起動しない。fleet署名recovery objectでroot delegation/authorization世代を更新する。失効情報の完全な復旧ができなければ既存資格の再検証を要求。offline性能と失効の即時性には限界がある。既存認可lease15分を過ぎた通信は期限切れ理由を返し、root不在なのに恒久的な認可更新を合成しない。

## 6. 実記憶容量と物理限界
NVS内部のcopy、page overhead、書込み増幅、GC、brownout挙動はIDF実装に依存する。論理record計算だけでFlash enduranceを保証しない。erase回数/byte量/最大commit latencyをHILで測る。tamper resistant monotonic counterなしの全Flash巻戻しを、2slotだけで防げるとは主張しない。

## Flash書込みと中継の実時間
Flash I/Oをworkerへ移しても、SoC/IDFのflash-cache停止や割込み制約が無線処理へ影響しないとは限らない。IRAM配置、watchdog、最長NVS commit、erase時間とTX callbackの遅延を全4SoCで測る。dirty recordを必要時だけまとめてcommitするが、DURABLE成功をcommit前に返さない。lifecycle/safety receiptの保存と高頻度telemetryを同じ無制限logへ入れない。SDK外のFlash writerとの調停もアプリ統合条件として明記する。

## spec0.2の追加record
power policy/scheduleは既存sealed recordのtyped objectとして保存し、別の汎用設定DBをNodeへ足さない。毎poll/packetでNVS書込みを行わない。group DURABLEはpayload1copy・immutable snapshot・target ID割当・進捗を一つの有界operation journalにまとめる。mid-commit sleep禁止。
Host既存DBへの導入はadditive schema migrationで`node_power/group_targets`を追加し、旧consumerを止めずphaseごとに有効化する。本ZIPのschema.sqlを既存製品DBへそのまま再実行しない。
