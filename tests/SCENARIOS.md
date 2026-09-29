# 受入シナリオ — spec0.2

**全158件、製品実行はすべて未実施。** 仕様checkerの成功と区別する。

## B01 — 4target同一pin build
- 要求: REQ-01, REQ-14 / 種別: BUILD
- 前提: IDF6.0.3固定、同一機能
- 操作・故障: C3/S3/C5/C6それぞれでbuild
- 合格条件: 同Wire/定数、map/heap予算、未対応APIを偽stubで通さない
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c3-c3 — 異種SoC双方向通信 c3→c3
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c3-s3 — 異種SoC双方向通信 c3→s3
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c3-c5 — 異種SoC双方向通信 c3→c5
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c3-c6 — 異種SoC双方向通信 c3→c6
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-s3-c3 — 異種SoC双方向通信 s3→c3
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-s3-s3 — 異種SoC双方向通信 s3→s3
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-s3-c5 — 異種SoC双方向通信 s3→c5
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-s3-c6 — 異種SoC双方向通信 s3→c6
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c5-c3 — 異種SoC双方向通信 c5→c3
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c5-s3 — 異種SoC双方向通信 c5→s3
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c5-c5 — 異種SoC双方向通信 c5→c5
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c5-c6 — 異種SoC双方向通信 c5→c6
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c6-c3 — 異種SoC双方向通信 c6→c3
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c6-s3 — 異種SoC双方向通信 c6→s3
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c6-c5 — 異種SoC双方向通信 c6→c5
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## RF-c6-c6 — 異種SoC双方向通信 c6→c6
- 要求: REQ-01 / 種別: HARDWARE
- 前提: 個体鍵・同一LR250 profile
- 操作・故障: send、ACK loss、reset、再認証
- 合格条件: 真の実RF受信とreceipt、型/peer制限/PHYreadback一致
- 状態: NOT_RUN_PRODUCT_TEST

## R01 — 21radio20hop強制chain
- 要求: REQ-02 / 種別: HARDWARE
- 前提: root+20ノード、96B低負荷
- 操作・故障: 直接shortcutを制限
- 合格条件: 20辺で到達しp95/p99とairtimeを記録
- 状態: NOT_RUN_PRODUCT_TEST

## R02 — 40hop端末間
- 要求: REQ-02 / 種別: HARDWARE
- 前提: rootの両側20hop、少なくとも41radio
- 操作・故障: 56Bと512B
- 合格条件: depth20と総path40を別報告、分割含め到達
- 状態: NOT_RUN_PRODUCT_TEST

## R03 — 同時親選択
- 要求: REQ-03 / 種別: MODEL
- 前提: 古い候補pathでA/Bが互いを選択
- 操作・故障: 同時register・逆順ACK
- 合格条件: root承認木にcycleなし、各packet単純path
- 状態: NOT_RUN_PRODUCT_TEST

## R04 — 重複source route
- 要求: REQ-03 / 種別: UNIT
- 前提: 認証したDATA
- 操作・故障: 同じaddressを2回pathへ入れる
- 合格条件: AEAD正常でもDROP、アプリ未通知
- 状態: NOT_RUN_PRODUCT_TEST

## R05 — stale source path
- 要求: REQ-03 / 種別: INTEGRATION
- 前提: diamond+既存pending
- 操作・故障: relay1台停止
- 合格条件: 古い経路をfloodせずrepair、新pathで同IDを配送
- 状態: NOT_RUN_PRODUCT_TEST

## R06 — rootなし
- 要求: REQ-03 / 種別: HARDWARE
- 前提: 既存session/pathあり
- 操作・故障: root電源断
- 合格条件: 有効pathは継続、期限後は失効/不明、新root捏造なし
- 状態: NOT_RUN_PRODUCT_TEST

## R07 — 全台停電
- 要求: REQ-03 / 種別: HARDWARE
- 前提: 21台ACTIVE
- 操作・故障: 同時cold boot20回
- 合格条件: membership維持、fresh sessions、Join storm予算を計測
- 状態: NOT_RUN_PRODUCT_TEST

## R08 — peer容量とhandoff
- 要求: REQ-03 / 種別: HARDWARE
- 前提: 16regular+3transient+broadcast
- 操作・故障: 100回peer入替、遅いrelease
- 合格条件: 予約漏れ/隣接消失なし、満杯明示
- 状態: NOT_RUN_PRODUCT_TEST

## R09 — short ID再使用
- 要求: REQ-05 / 種別: INTEGRATION
- 前提: 旧Deviceへshort42
- 操作・故障: 別Deviceへ同short再割当
- 合格条件: 古いsession/routeを拒否、fullIdentity混同なし
- 状態: NOT_RUN_PRODUCT_TEST

## R10 — 古いjob完了
- 要求: REQ-15 / 種別: UNIT
- 前提: crypto job実行中にslot解放
- 操作・故障: slot再利用後に旧completion
- 合格条件: 新slotに副作用を与えない
- 状態: NOT_RUN_PRODUCT_TEST

## C01 — 自動最適化正常
- 要求: REQ-04 / 種別: HARDWARE
- 前提: 2地点以上の候補比較
- 操作・故障: homeの複数linkを継続悪化
- 合格条件: 閾値/clock/RF条件を満たした場合だけ新plan
- 状態: NOT_RUN_PRODUCT_TEST

## C02 — 単一悪link
- 要求: REQ-04 / 種別: MODEL
- 前提: 一つの経路だけ悪化
- 操作・故障: RSSI低下/remote busy混在
- 合格条件: まずroute修復、全体channel変更しない
- 状態: NOT_RUN_PRODUCT_TEST

## C03 — READY欠落
- 要求: REQ-04 / 種別: INTEGRATION
- 前提: 必須relay snapshot固定
- 操作・故障: READY喪失
- 合格条件: 分母から外さずtimeout ABORT
- 状態: NOT_RUN_PRODUCT_TEST

## C04 — COMMIT欠落
- 要求: REQ-04 / 種別: HARDWARE
- 前提: 全READY後
- 操作・故障: 1relayにCOMMITが届かない
- 合格条件: 他はtarget、missingは認証scanで追随、partial明示
- 状態: NOT_RUN_PRODUCT_TEST

## C05 — COMMIT後root停電
- 要求: REQ-04 / 種別: HARDWARE
- 前提: root committed slot保存直後
- 操作・故障: root再起動
- 合格条件: 保存target先適用、新term、単独旧channelrollbackなし
- 状態: NOT_RUN_PRODUCT_TEST

## C06 — clock誤差超過
- 要求: REQ-04 / 種別: MODEL
- 前提: 20hop遅延変動
- 操作・故障: 片方向500ms遅延/clock drift
- 合格条件: READY拒否TIME_UNCERTAIN、UTCを偽装しない
- 状態: NOT_RUN_PRODUCT_TEST

## C07 — チャネルfreeze
- 要求: REQ-04 / 種別: UNIT
- 前提: PREPARINGとCOMMITTEDを別々に試す
- 操作・故障: freeze=true
- 合格条件: 前者新規抑制、後者勝手に取消しない
- 状態: NOT_RUN_PRODUCT_TEST

## C08 — candidate部分悪化
- 要求: REQ-04 / 種別: HARDWARE
- 前提: 平均では良いchannel
- 操作・故障: 重要relay地点だけ妨害
- 合格条件: 最悪link条件未達なら移行しない
- 状態: NOT_RUN_PRODUCT_TEST

## C09 — sleepy取り残し
- 要求: REQ-04 / 種別: HARDWARE
- 前提: leaf24h asleep
- 操作・故障: 起床前にchannel移行
- 合格条件: 旧→pending→許可集合探索、所属は維持
- 状態: NOT_RUN_PRODUCT_TEST

## C10 — all-channel jam
- 要求: REQ-04 / 種別: HARDWARE
- 前提: 許可channelに到達なし
- 操作・故障: RF妨害/遮蔽
- 合格条件: 復旧不能を明示、送信/探索予算を超えない
- 状態: NOT_RUN_PRODUCT_TEST

## C11 — chainのsurvey休止
- 要求: REQ-04 / 種別: HARDWARE
- 前提: 代替のない中間relay
- 操作・故障: maintenance_gap=falseでscan要求
- 合格条件: 予定なしoff-channelを拒否、child孤立を隠さない
- 状態: NOT_RUN_PRODUCT_TEST

## C12 — rollback
- 要求: REQ-04 / 種別: INTEGRATION
- 前提: 新channelが悪い
- 操作・故障: rootがrollback発行
- 合格条件: さらに大きいepoch、古いplanを再有効化しない
- 状態: NOT_RUN_PRODUCT_TEST

## S01 — EDHOC公式trace
- 要求: REQ-05 / 種別: UNIT
- 前提: 採用したEDHOC実装
- 操作・故障: RFC9529該当vectors/相互実装
- 合格条件: 完全input消費とExporter一致、test-only shortcutなし
- 状態: NOT_RUN_PRODUCT_TEST

## S02 — session context混同
- 要求: REQ-05 / 種別: UNIT
- 前提: 正しい鍵で異なるcontext
- 操作・故障: domain/purpose/generation変更
- 合格条件: Exporter context/bind照合で失敗、通常DATAは許可しない
- 状態: NOT_RUN_PRODUCT_TEST

## S03 — QR複製
- 要求: REQ-05 / 種別: HARDWARE
- 前提: 同じラベル別private key
- 操作・故障: Join要求
- 合格条件: 候補表示のみ、本手続きは拒否
- 状態: NOT_RUN_PRODUCT_TEST

## S04 — packet replay
- 要求: REQ-05 / 種別: UNIT
- 前提: 受理済み暗号frame
- 操作・故障: 重複/窓外/同counter異payload
- 合格条件: 重複はアプリ再適用なし、異payload拒否
- 状態: NOT_RUN_PRODUCT_TEST

## S05 — cold boot nonce
- 要求: REQ-05 / 種別: HARDWARE
- 前提: traffic途中
- 操作・故障: 双方片側のcold boot
- 合格条件: freshEDHOC、旧ciphertext/sessionを受理しない
- 状態: NOT_RUN_PRODUCT_TEST

## S06 — 失効通知未達
- 要求: REQ-05 / 種別: HARDWARE
- 前提: 対象node圏外
- 操作・故障: revoke
- 合格条件: 残存側拒否を進め、端末消去未確認を分離
- 状態: NOT_RUN_PRODUCT_TEST

## S07 — invalid key/cert
- 要求: REQ-05 / 種別: UNIT
- 前提: 認証credential
- 操作・故障: invalid curve point/key length/hash/署名/lowgeneration
- 合格条件: 必ず拒否、固定PSKfallbackなし
- 状態: NOT_RUN_PRODUCT_TEST

## S08 — 認証CPU飽和
- 要求: REQ-14 / 種別: HARDWARE
- 前提: 既存DATA+Joinburst
- 操作・故障: 不正/正規handshake集中
- 合格条件: 中継owner非blocking、queue有界、ms/energy記録
- 状態: NOT_RUN_PRODUCT_TEST

## S09 — USB偽相手
- 要求: REQ-16 / 種別: HARDWARE
- 前提: 正しいserialdeviceと偽Host
- 操作・故障: HELLO偽装/固定共通鍵
- 合格条件: 相互認証失敗、config/send拒否
- 状態: NOT_RUN_PRODUCT_TEST

## S10 — 鍵rotation
- 要求: REQ-05 / 種別: INTEGRATION
- 前提: 旧session通信中
- 操作・故障: 閾値到達、ACK欠落
- 合格条件: 新旧期限分離、無期限overlapなし
- 状態: NOT_RUN_PRODUCT_TEST

## J01 — proxy Join
- 要求: REQ-06 / 種別: HARDWARE
- 前提: 未所属機がroot直達不可
- 操作・故障: 19hop relay経由
- 合格条件: Device↔root相互認証、relayは承認権限なし
- 状態: NOT_RUN_PRODUCT_TEST

## J02 — 期待リスト更新
- 要求: REQ-06 / 種別: INTEGRATION
- 前提: B未登録で先にNodeを起動
- 操作・故障: 後からexpected_revision更新
- 合格条件: 長期固定拒否せず再探索、本承認でactive
- 状態: NOT_RUN_PRODUCT_TEST

## J03 — hint false positive
- 要求: REQ-06 / 種別: UNIT
- 前提: 偽OFFER/誤ったfilter
- 操作・故障: candidate accepted hint
- 合格条件: bounded本handshakeで拒否、認可は成立しない
- 状態: NOT_RUN_PRODUCT_TEST

## J04 — approval停止
- 要求: REQ-06 / 種別: HARDWARE
- 前提: external承認mode
- 操作・故障: FastAPI停止
- 合格条件: pending、既存通信継続、無条件approveなし
- 状態: NOT_RUN_PRODUCT_TEST

## J05 — 既存member復帰
- 要求: REQ-07 / 種別: HARDWARE
- 前提: ACTIVE stored
- 操作・故障: parent断→復帰
- 合格条件: ACTIVE+ISOLATED→REACHABLE、初回承認やidentity削除なし
- 状態: NOT_RUN_PRODUCT_TEST

## J06 — Join同ID異hash
- 要求: REQ-05 / 種別: UNIT
- 前提: PREPARED pending
- 操作・故障: 同request_idの異内容
- 合格条件: CONFLICT、short address二重発行なし
- 状態: NOT_RUN_PRODUCT_TEST

## J07 — Join最終ACK消失
- 要求: REQ-05 / 種別: INTEGRATION
- 前提: NodeCOMMIT完了
- 操作・故障: JOIN_ACTIVE損失
- 合格条件: request照会で収束、false新加入なし
- 状態: NOT_RUN_PRODUCT_TEST

## M01 — A停止でB移設
- 要求: REQ-13 / 種別: HARDWARE
- 前提: A member、A root off
- 操作・故障: 署名transfergrant+新B起動
- 合格条件: Bcommit可能、A reconciliation pending
- 状態: NOT_RUN_PRODUCT_TEST

## M02 — A稼働でB移設
- 要求: REQ-13 / 種別: HARDWARE
- 前提: A/B双方電波圏
- 操作・故障: Bへ明示transfer
- 合格条件: 同時ACTIVEなし、Aから旧command拒否
- 状態: NOT_RUN_PRODUCT_TEST

## M03 — A→B→A
- 要求: REQ-13 / 種別: INTEGRATION
- 前提: 安定DeviceIdentity
- 操作・故障: 連続移設、新generation
- 合格条件: key/DeviceId維持、short再割当可、古いgrant拒否
- 状態: NOT_RUN_PRODUCT_TEST

## M04 — 紛失機器
- 要求: REQ-13 / 種別: INTEGRATION
- 前提: 最新revocation floorあり
- 操作・故障: 旧ticketでJoin
- 合格条件: 拒否、stale情報の新規承認はfailclosed
- 状態: NOT_RUN_PRODUCT_TEST

## M05 — transfer途中停電
- 要求: REQ-15 / 種別: HARDWARE
- 前提: 各record write境界
- 操作・故障: 一つずつpowercut
- 合格条件: oldまたはnewだけ、halfmerged keysなし
- 状態: NOT_RUN_PRODUCT_TEST

## M06 — leave drain
- 要求: REQ-13 / 種別: HARDWARE
- 前提: 子がいるrelay
- 操作・故障: deadline30s、代替なし
- 合格条件: 勝手にIMMEDIATE化しない、明示失敗
- 状態: NOT_RUN_PRODUCT_TEST

## M07 — 同現場移設
- 要求: REQ-18 / 種別: APPLICATION
- 前提: KG旧calibrationあり
- 操作・故障: placement/bindingrevision更新
- 合格条件: SDKはmembership維持、KGだけ校正無効化
- 状態: NOT_RUN_PRODUCT_TEST

## D01 — APPLIED非同期
- 要求: REQ-08 / 種別: INTEGRATION
- 前提: 端末受信は成功
- 操作・故障: アプリI/O遅延/拒否
- 合格条件: END_RECEIVEDとAPP_APPLIED分離
- 状態: NOT_RUN_PRODUCT_TEST

## D02 — 適用直後停電
- 要求: REQ-15 / 種別: HARDWARE
- 前提: 物理I/O成功
- 操作・故障: receipt保存前powercut
- 合格条件: INDETERMINATE、アプリ再照合、exactlyonce捏造なし
- 状態: NOT_RUN_PRODUCT_TEST

## D03 — late receipt
- 要求: REQ-09 / 種別: INTEGRATION
- 前提: 新generation発行済み
- 操作・故障: 古いAPP_APPLIED到着
- 合格条件: 履歴保存、最新state巻戻しなし
- 状態: NOT_RUN_PRODUCT_TEST

## D04 — cancel競合
- 要求: REQ-09 / 種別: UNIT
- 前提: queue前/外部write後
- 操作・故障: cancel
- 合格条件: NOT_SENTと不明を区別
- 状態: NOT_RUN_PRODUCT_TEST

## D05 — latest key分離
- 要求: REQ-09 / 種別: UNIT
- 前提: 同dest異なるkey
- 操作・故障: burst state更新
- 合格条件: 同key未送信のみcoalesce、他key保持
- 状態: NOT_RUN_PRODUCT_TEST

## D06 — 期限の再延長禁止
- 要求: REQ-09 / 種別: INTEGRATION
- 前提: deadline付きpending
- 操作・故障: path/Host/root reboot
- 合格条件: 元期限を再付与しない、clockunknownは明示
- 状態: NOT_RUN_PRODUCT_TEST

## D07 — 小message分割
- 要求: REQ-10 / 種別: HARDWARE
- 前提: 20/40hop path
- 操作・故障: 512B、順不同、dup、1chunk欠落
- 合格条件: 1回だけcomplete通知、選択再送、hash一致
- 状態: NOT_RUN_PRODUCT_TEST

## D08 — 4KiB最大
- 要求: REQ-10 / 種別: HARDWARE
- 前提: objectenabled
- 操作・故障: 4096/4097B
- 合格条件: 4096は有界復元、4097は拒否
- 状態: NOT_RUN_PRODUCT_TEST

## D09 — fragment異内容
- 要求: REQ-10 / 種別: UNIT
- 前提: 受理済みoffset
- 操作・故障: 同offset別bytes
- 合格条件: CONFLICT、半分の本文をappへ出さない
- 状態: NOT_RUN_PRODUCT_TEST

## D10 — ACK callback順
- 要求: REQ-15 / 種別: HARDWARE
- 前提: ESP-NOW TX進行
- 操作・故障: earlyHOP_ACK、callback500ms遅延
- 合格条件: 正しいTXと結合、次frame成功へ誤帰属なし
- 状態: NOT_RUN_PRODUCT_TEST

## D11 — 全台fan-out
- 要求: REQ-08 / 種別: APPLICATION
- 前提: 64target snapshot、origin非root
- 操作・故障: join/revokeが途中で発生
- 合格条件: 対象集合固定、per-target結果、部分成功
- 状態: NOT_RUN_PRODUCT_TEST

## D12 — groupend秘密
- 要求: REQ-08 / 種別: UNIT
- 前提: relay/root観測
- 操作・故障: 端末間fanout ciphertext取得
- 合格条件: rootにend keyを渡さず、assuranceを過剰表示しない
- 状態: NOT_RUN_PRODUCT_TEST

## Q01 — 飢餓なし
- 要求: REQ-14 / 種別: INTEGRATION
- 前提: control+urgent+bulk大量
- 操作・故障: queue90%負荷
- 合格条件: 予約controlが進む、airtime/拒否理由記録
- 状態: NOT_RUN_PRODUCT_TEST

## Q02 — idempotency予算
- 要求: REQ-09 / 種別: UNIT
- 前提: 完了request大量retry
- 操作・故障: 同key100回
- 合格条件: 新規RF送信なし、別principalと混同なし
- 状態: NOT_RUN_PRODUCT_TEST

## Q03 — DB満杯
- 要求: REQ-11 / 種別: HOST
- 前提: protected未ACKeventあり
- 操作・故障: 容量枯渇
- 合格条件: 新受付507、既存critical保持、false202なし
- 状態: NOT_RUN_PRODUCT_TEST

## H01 — commit後HTTP切断
- 要求: REQ-11 / 種別: HOST
- 前提: POST同key
- 操作・故障: commit直後socketclose
- 合格条件: 再POSTで同operation、二重命令なし
- 状態: NOT_RUN_PRODUCT_TEST

## H02 — consumer gap
- 要求: REQ-11 / 種別: HOST
- 前提: cursor保持下限外
- 操作・故障: 旧cursor再開
- 合格条件: 410+最古最新、黙ったスキップなし
- 状態: NOT_RUN_PRODUCT_TEST

## H03 — serial再接続
- 要求: REQ-16 / 種別: HARDWARE
- 前提: Host送信中
- 操作・故障: USBunplug/reset、別device入替
- 合格条件: identity再確認、旧sessionresults不適用
- 状態: NOT_RUN_PRODUCT_TEST

## H04 — Host停止
- 要求: REQ-16 / 種別: HARDWARE
- 前提: Node2NodeとHost宛両方
- 操作・故障: servicekill
- 合格条件: Node通信継続、Hostdurableは未commit
- 状態: NOT_RUN_PRODUCT_TEST

## H05 — backup巻戻し
- 要求: REQ-15 / 種別: HOST
- 前提: newrevoke/epoch確定後
- 操作・故障: 旧DBrestore
- 合格条件: floor照合、新epoch、盲再送なし
- 状態: NOT_RUN_PRODUCT_TEST

## H06 — slow subscriber
- 要求: REQ-11 / 種別: HOST
- 前提: consumer読取停止
- 操作・故障: 他consumerと同時高頻度受信
- 合格条件: boundedstage/gap、他の受信を止めない
- 状態: NOT_RUN_PRODUCT_TEST

## H07 — 二重Host
- 要求: REQ-11 / 種別: HOST
- 前提: 既存service起動
- 操作・故障: 2worker/2process起動
- 合格条件: singleton lockで一方拒否、USB2重openなし
- 状態: NOT_RUN_PRODUCT_TEST

## P01 — sleep ticket race
- 要求: REQ-12 / 種別: UNIT
- 前提: sleep_prepare完了
- 操作・故障: 新DATA/commit到着
- 合格条件: sleepenter拒否して再prepare
- 状態: NOT_RUN_PRODUCT_TEST

## P02 — sleep≠loss
- 要求: REQ-07 / 種別: HARDWARE
- 前提: 既知wake予定
- 操作・故障: leaf長sleep
- 合格条件: RF損失に加算しない、membership維持
- 状態: NOT_RUN_PRODUCT_TEST

## P03 — wake deadline不足
- 要求: REQ-12 / 種別: INTEGRATION
- 前提: commanddeadline<nextwake
- 操作・故障: 下りsubmit
- 合格条件: 受信不可を早期明示、無限spoolなし
- 状態: NOT_RUN_PRODUCT_TEST

## P04 — 圏外電池
- 要求: REQ-12 / 種別: HARDWARE
- 前提: 電池leaf
- 操作・故障: 長時間圏外
- 合格条件: 探索予算・sleep電流・energy/report測定
- 状態: NOT_RUN_PRODUCT_TEST

## O01 — OTA2面
- 要求: REQ-17 / 種別: HARDWARE
- 前提: 4MiB各SoC
- 操作・故障: imagewrite中/boot前後powercut
- 合格条件: 旧または新の有効image、identity保持
- 状態: NOT_RUN_PRODUCT_TEST

## O02 — OTA署名/target
- 要求: REQ-17 / 種別: UNIT
- 前提: 別SoC/古いsecurityversion
- 操作・故障: manifest/image改ざん
- 合格条件: 拒否、boot対象変更なし
- 状態: NOT_RUN_PRODUCT_TEST

## O03 — schema rollback
- 要求: REQ-17 / 種別: HARDWARE
- 前提: newimagependingverify
- 操作・故障: crashrollback
- 合格条件: oldimageでstoreを安全に読める、不可逆床を先に壊さない
- 状態: NOT_RUN_PRODUCT_TEST

## K01 — 3表示盤対象識別
- 要求: REQ-18 / 種別: APPLICATION
- 前提: 実ToF/S3/Pico/Go
- 操作・故障: Aのみ禁止→全台→A解除
- 合格条件: 各drawn一致、他hold無断解除なし
- 状態: NOT_RUN_PRODUCT_TEST

## K02 — occとtr
- 要求: REQ-18 / 種別: APPLICATION
- 前提: snapshotとusagehistory併送
- 操作・故障: 短い断線/再送
- 合格条件: occ最新化、tr累積ACKまで保持
- 状態: NOT_RUN_PRODUCT_TEST

## K03 — Pico故障
- 要求: REQ-18 / 種別: APPLICATION
- 前提: radioonline
- 操作・故障: PicoUART応答停止
- 合格条件: onlineかつdisplayfailed、falseAPPLIEDなし
- 状態: NOT_RUN_PRODUCT_TEST

## K04 — 8hcloud断
- 要求: REQ-18 / 種別: APPLICATION
- 前提: KG+Hostlocal稼働
- 操作・故障: internet8h遮断
- 合格条件: 有限容量でevent/outcome保持、古い履歴で現在を巻戻さない
- 状態: NOT_RUN_PRODUCT_TEST

## K05 — KG共存owner
- 要求: REQ-18 / 種別: APPLICATION
- 前提: 旧WiFiFWと新SDK候補
- 操作・故障: 同一表示盤を同時登録
- 合格条件: 1制御owner規則、切戻し手順を検証
- 状態: NOT_RUN_PRODUCT_TEST

## K06 — KG参照をcore排除
- 要求: REQ-18 / 種別: UNIT
- 前提: firstpartycore
- 操作・故障: KG語彙/CloudURL/固有ID検索
- 合格条件: integration以外に業務語彙なし
- 状態: NOT_RUN_PRODUCT_TEST

## L01 — 72h負荷/資源
- 要求: REQ-14 / 種別: HARDWARE
- 前提: 64members混在
- 操作・故障: Joinburst+control+bulk+移設
- 合格条件: map/heap/stack/energy/latency、leak/resetを記録
- 状態: NOT_RUN_PRODUCT_TEST

## POWER-before-slot-write — durable境界 before-slot-write
- 要求: REQ-15 / 種別: HARDWARE
- 前提: Join/transfer/channel/journalをそれぞれ対象
- 操作・故障: before-slot-writeで電源断
- 合格条件: docs12の唯一の許可状態へ復旧。旧世代を黙って再使用しない
- 状態: NOT_RUN_PRODUCT_TEST

## POWER-during-slot-write — durable境界 during-slot-write
- 要求: REQ-15 / 種別: HARDWARE
- 前提: Join/transfer/channel/journalをそれぞれ対象
- 操作・故障: during-slot-writeで電源断
- 合格条件: docs12の唯一の許可状態へ復旧。旧世代を黙って再使用しない
- 状態: NOT_RUN_PRODUCT_TEST

## POWER-after-slot-commit — durable境界 after-slot-commit
- 要求: REQ-15 / 種別: HARDWARE
- 前提: Join/transfer/channel/journalをそれぞれ対象
- 操作・故障: after-slot-commitで電源断
- 合格条件: docs12の唯一の許可状態へ復旧。旧世代を黙って再使用しない
- 状態: NOT_RUN_PRODUCT_TEST

## POWER-before-marker — durable境界 before-marker
- 要求: REQ-15 / 種別: HARDWARE
- 前提: Join/transfer/channel/journalをそれぞれ対象
- 操作・故障: before-markerで電源断
- 合格条件: docs12の唯一の許可状態へ復旧。旧世代を黙って再使用しない
- 状態: NOT_RUN_PRODUCT_TEST

## POWER-after-marker — durable境界 after-marker
- 要求: REQ-15 / 種別: HARDWARE
- 前提: Join/transfer/channel/journalをそれぞれ対象
- 操作・故障: after-markerで電源断
- 合格条件: docs12の唯一の許可状態へ復旧。旧世代を黙って再使用しない
- 状態: NOT_RUN_PRODUCT_TEST

## POWER-before-ack — durable境界 before-ack
- 要求: REQ-15 / 種別: HARDWARE
- 前提: Join/transfer/channel/journalをそれぞれ対象
- 操作・故障: before-ackで電源断
- 合格条件: docs12の唯一の許可状態へ復旧。旧世代を黙って再使用しない
- 状態: NOT_RUN_PRODUCT_TEST

## POWER-after-ack — durable境界 after-ack
- 要求: REQ-15 / 種別: HARDWARE
- 前提: Join/transfer/channel/journalをそれぞれ対象
- 操作・故障: after-ackで電源断
- 合格条件: docs12の唯一の許可状態へ復旧。旧世代を黙って再使用しない
- 状態: NOT_RUN_PRODUCT_TEST

## LP01 — power role検査
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: LEAF/RELAY/ROOTに3mode設定
- 操作・故障: relay/rootをWINDOWED/REPORTへ変更
- 合格条件: ROLE_NOT_ALLOWED、旧policy継続、radioを停止しない
- 状態: NOT_RUN_PRODUCT_TEST

## LP02 — 間欠窓の実受信
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: 各SoCで未接続STA、window250ms/interval5s
- 操作・故障: 非同期に各時刻で下り発生
- 合格条件: 認証poll後の窓のみ送信、待ち時間を測定、常時RX fallbackなし
- 状態: NOT_RUN_PRODUCT_TEST

## LP03 — report起床→停止
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: DURABLE報告/1h、活動15s
- 操作・故障: 通常送信とdownlink pending
- 合格条件: journal/receipt/pendingの事実を保持して再sleep
- 状態: NOT_RUN_PRODUCT_TEST

## LP04 — sleep ticket race
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: prepare完了後ticket取得
- 操作・故障: 直前に新DATA/policy変更
- 合格条件: 古ticket拒否、受信/commitを捨てない
- 状態: NOT_RUN_PRODUCT_TEST

## LP05 — sleep veto
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: 周辺センサーがまだbusy
- 操作・故障: appからsleep_abort
- 合格条件: ticket無効、PM lock/通信状態正常復帰
- 状態: NOT_RUN_PRODUCT_TEST

## LP06 — 圏外24h
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: REPORT_ONLY、1hのradio budget60s
- 操作・故障: 全親/全許可channel不可
- 合格条件: 追加探索予算有限、cursor/backoff維持、Jとoverrunを記録
- 状態: NOT_RUN_PRODUCT_TEST

## LP07 — イベントwake storm
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: 外部割込みを連続発生
- 操作・故障: 追加wake quota超過
- 合格条件: 通常/例外budget分離、無制限TXなし、失った計測の有無を明示
- 状態: NOT_RUN_PRODUCT_TEST

## LP08 — RAM保持session
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: Light/Modem Sleep間で有効key/counter/window保持
- 操作・故障: 1,000wakeと重複frame
- 合格条件: 期限内は不要EDHOCなし、counter単調、再適用なし
- 状態: NOT_RUN_PRODUCT_TEST

## LP09 — Deep/cold session
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: Deep Sleep/cold/watchdog/brownout
- 操作・故障: 旧SID/旧暗号frame注入
- 合格条件: fresh EDHOC、承認再要求なし、旧key/counterを復元しない
- 状態: NOT_RUN_PRODUCT_TEST

## LP10 — parent mailbox喪失
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: sleepy target待ちframe2件
- 操作・故障: parent電源断
- 合格条件: HOP受理をDURABLE扱いせずorigin再送で回復
- 状態: NOT_RUN_PRODUCT_TEST

## LP11 — 20hop ACK持越し
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: 20hop末端DURABLE report
- 操作・故障: 終端receipt前に活動予算終了
- 合格条件: SAVE_AND_SLEEPで原本保持、次wake同ID照会/再送、虚偽成功なし
- 状態: NOT_RUN_PRODUCT_TEST

## LP12 — leaseを跨ぐsleep
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: authorization期限15min
- 操作・故障: 30min寝てwake
- 合格条件: 旧leaseを復元せず新鮮な権限確認、membershipは消さない
- 状態: NOT_RUN_PRODUCT_TEST

## LP13 — 相手だけ再起動
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: leafはRAM保持、parentだけreset
- 操作・故障: 旧peer SIDを照会
- 合格条件: 対象sessionだけ再確立、全網Joinなし
- 状態: NOT_RUN_PRODUCT_TEST

## LP14 — poll/grant loss
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: 250ms窓、authenticated poll
- 操作・故障: grant欠落/遅着/重複
- 合格条件: nonce一致、再試行2回、window開始を延長しない
- 状態: NOT_RUN_PRODUCT_TEST

## LP15 — sleepとchannel
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: leaf sleeping、root channel変更
- 操作・故障: PREPARE/COMMITを全て取り逃す
- 合格条件: wake時に有界探索、署名/epoch確認後追随
- 状態: NOT_RUN_PRODUCT_TEST

## LP16 — critical sleeper移行
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: critical receiverが長期sleep
- 操作・故障: channel plan開始
- 合格条件: 勝手に必須集合から除外せず延期/明示deferred
- 状態: NOT_RUN_PRODUCT_TEST

## LP17 — 予定外periodic wake
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: 安定REPORT_ONLY
- 操作・故障: hello/route refresh期限だけ経過
- 合格条件: そのためだけにwakeしない、次wakeに必要lease更新
- 状態: NOT_RUN_PRODUCT_TEST

## LP18 — PM lock負例
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: 送受信/暗号/保存実行
- 操作・故障: timeout/cancel/driver fault
- 合格条件: lockリークなし、owner progress、energy比較
- 状態: NOT_RUN_PRODUCT_TEST

## LP19 — sensor周辺電力
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: 実基板+LDO/USB/センサー
- 操作・故障: 切替/電源OFF/測定器接続差
- 合格条件: MCU railと基板入口を分離し全体Jを測る
- 状態: NOT_RUN_PRODUCT_TEST

## LP20 — RTC連続性不明
- 要求: REQ-12, REQ-19, REQ-20, REQ-21 / 種別: HARDWARE
- 前提: hour/day budget保持後
- 操作・故障: cold boot/RTC初期化
- 合格条件: 起動episode以外の不確かな残予算は保守的再補充
- 状態: NOT_RUN_PRODUCT_TEST

## LC01 — 設置window expiry
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: 有効署名と予定一覧、5min window
- 操作・故障: 期限と同時に新規承認
- 合格条件: 新規承認拒否、既commit案件の確認だけ継続
- 状態: NOT_RUN_PRODUCT_TEST

## LC02 — 64台設置
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: 予定64Device、予算固定
- 操作・故障: 全台同時電源ON
- 合格条件: 進捗は個別証拠、同request予約重複なし、通常DATAを中断しない
- 状態: NOT_RUN_PRODUCT_TEST

## LC03 — 電源先行
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: B予定登録前にwake
- 操作・故障: 後からexpected revision更新
- 合格条件: 次の通常wakeで再評価、偽revisionで電力budgetリセットしない
- 状態: NOT_RUN_PRODUCT_TEST

## LC04 — 工場→倉庫→本番
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: 別DomainId/個体key
- 操作・故障: 試験credentialを本番へ提示
- 合格条件: 高い正当assignmentなし参加不可、共有factory秘密なし
- 状態: NOT_RUN_PRODUCT_TEST

## LC05 — 承認待ちsleep
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: 外部承認pending
- 操作・故障: appがsleep、Host再起動後承認
- 合格条件: 同request復帰、必要fresh auth、予約/期限の二重発行なし
- 状態: NOT_RUN_PRODUCT_TEST

## LC06 — commit片側喪失
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: Join PREPARED/ACTIVE境界
- 操作・故障: JOIN_COMMITかJOIN_ACTIVE欠落
- 合格条件: 再照会で収束、active_unconfirmedを完了にしない
- 状態: NOT_RUN_PRODUCT_TEST

## LC07 — A→B旧履歴
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: 未ACKのA向け履歴あり
- 操作・故障: 旧root停止したまま移設
- 合格条件: 履歴をBへ新データとして送らない、回収/破棄方針を明示
- 状態: NOT_RUN_PRODUCT_TEST

## LC08 — 正常root交換
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: 旧root drain、新個体delegation
- 操作・故障: 計画handover
- 合格条件: 新term/generation確認、fresh auth、旧命令の盲再送なし
- 状態: NOT_RUN_PRODUCT_TEST

## LC09 — root故障交換
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: 検証済みbackupとfleet権限
- 操作・故障: 旧rootなしでhandover
- 合格条件: 既知floorより高いterm、情報不足はRECOVERY_REQUIRED
- 状態: NOT_RUN_PRODUCT_TEST

## LC10 — 旧root再出現
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: handover確認済みNode群
- 操作・故障: 旧root起動/旧命令
- 合格条件: 受入済み高delegationで拒否、未達Nodeを完了扱いしない
- 状態: NOT_RUN_PRODUCT_TEST

## LC11 — network reset
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: active membership、consumed grant
- 操作・故障: leave IMMEDIATE/再起動
- 合格条件: DeviceId/fleet/floors/boot counter維持、無権限再参加不可
- 状態: NOT_RUN_PRODUCT_TEST

## LC12 — 異なる利用アプリ
- 要求: REQ-05, REQ-13, REQ-23 / 種別: HARDWARE
- 前提: 設備制御と環境計測、同SDK
- 操作・故障: KG依存なしで設置/送信/移設
- 合格条件: coreにKG型/URL/業務ルールが不要
- 状態: NOT_RUN_PRODUCT_TEST

## GS01 — origin fan-out
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: 通常Nodeからgroup32
- 操作・故障: rootを経由して複数endへ送信
- 合格条件: rootは本文平文を見ず、originが宛先別end暗号化
- 状態: NOT_RUN_PRODUCT_TEST

## GS02 — 世代snapshot
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: 64target複数page
- 操作・故障: page途中にrevoke/移設
- 合格条件: token/hash固定、世代変化は拒否、別個体へ再転送なし
- 状態: NOT_RUN_PRODUCT_TEST

## GS03 — group編集
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: 送信開始後snapshot保存
- 操作・故障: membersを追加/削除
- 合格条件: 既操作の集合不変、新操作のみ新版
- 状態: NOT_RUN_PRODUCT_TEST

## GS04 — mixed sleep
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: awake75%/sleep25%
- 操作・故障: 全体へAPPLIED要求
- 合格条件: awake対象を先に配送、WAIT_WAKEがslot独占しない
- 状態: NOT_RUN_PRODUCT_TEST

## GS05 — wake不可能
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: deadline5s、次wake60s
- 操作・故障: 未送信targetを選択
- 合格条件: DEADLINE_UNREACHABLE、RF loss非加算
- 状態: NOT_RUN_PRODUCT_TEST

## GS06 — wake時刻不明
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: GPIOだけのwake target
- 操作・故障: 期限なしDURABLE履歴と有限command
- 合格条件: UNKNOWNを勝手に不可能判定せず、期限で適切に終端
- 状態: NOT_RUN_PRODUCT_TEST

## GS07 — cancel/late結果
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: group送信一部はradio済み
- 操作・故障: 全体cancelと遅いAPPLIED
- 合格条件: 未送信だけ取消、late事実保存、集約revision更新
- 状態: NOT_RUN_PRODUCT_TEST

## GS08 — payload単一copy
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: 64target、512B payload
- 操作・故障: groupを最大同時数まで受付
- 合格条件: 役割budget内、targetごとpayload複製なし、容量超過受付拒否
- 状態: NOT_RUN_PRODUCT_TEST

## GS09 — group DURABLE再起動
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: snapshot/target IDsと本文commit
- 操作・故障: 途中でoriginまたはHost reset
- 合格条件: 同ID/進捗で再照合、全台新commandへ化けない
- 状態: NOT_RUN_PRODUCT_TEST

## GS10 — 結果の総和
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: pending/received/applied混在
- 操作・故障: 重複receiptとloss
- 合格条件: current outcome総和=total、履歴証拠を二重計上しない
- 状態: NOT_RUN_PRODUCT_TEST

## GS11 — 一斉配信負荷
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: 30/64targetsとdepth20
- 操作・故障: Join+channel候補+group burst
- 合格条件: control非飢餓、airtime/最後の反映遅延公開
- 状態: NOT_RUN_PRODUCT_TEST

## GS12 — sleepy origin
- 要求: REQ-08, REQ-09, REQ-22, REQ-24 / 種別: HARDWARE
- 前提: 電池originのDURABLE group
- 操作・故障: 途中でSAVE_AND_SLEEP
- 合格条件: 自己journal保持、無断root平文委託なし、次wake収束
- 状態: NOT_RUN_PRODUCT_TEST

## ME01 — 4SoC power比較
- 要求: REQ-14, REQ-25 / 種別: HARDWARE
- 前提: C3/S3/C5/C6全3mode
- 操作・故障: 同payload/周期/距離でA-B
- 合格条件: 各board独立測定、Jと成功率・最大遅延を同時報告
- 状態: NOT_RUN_PRODUCT_TEST

## ME02 — sleep方式break-even
- 要求: REQ-14, REQ-25 / 種別: HARDWARE
- 前提: 10s/60s/15min/1h周期
- 操作・故障: WINDOWEDとDEEP+EDHOC比較
- 合格条件: CPU/無線/センサー含めenergy比較、安全機能維持
- 状態: NOT_RUN_PRODUCT_TEST

## ME03 — 距離の一連成功
- 要求: REQ-14, REQ-25 / 種別: HARDWARE
- 前提: 近距離/限界域/干渉
- 操作・故障: Discovery/Join/DATA/ACK/recovery
- 合格条件: 片方向DATA成功だけで長距離認定しない
- 状態: NOT_RUN_PRODUCT_TEST

## ME04 — 容量差分
- 要求: REQ-14, REQ-25 / 種別: HARDWARE
- 前提: 同IDF/radio基線
- 操作・故障: SDK+全必須機能build
- 合格条件: vendor込みFlash/RAM/最大heapblockとSLOCを別計上
- 状態: NOT_RUN_PRODUCT_TEST

## ME05 — 低負荷CPU
- 要求: REQ-14, REQ-25 / 種別: HARDWARE
- 前提: 全網stable idle
- 操作・故障: タイマー/observer有効
- 合格条件: wakeups/CPU<目標、2ms全表pollなし
- 状態: NOT_RUN_PRODUCT_TEST

## ME06 — CSV計測品質
- 要求: REQ-14, REQ-25 / 種別: HARDWARE
- 前提: 校正機器・trace metadata
- 操作・故障: gap/帯域不足/符号異常
- 合格条件: 問題を報告し補間や削除で成功値を作らない
- 状態: NOT_RUN_PRODUCT_TEST

## ME07 — 故障条件energy
- 要求: REQ-14, REQ-25 / 種別: HARDWARE
- 前提: 24h圏外/1,000wake
- 操作・故障: reset/key期限/Host停止を混在
- 合格条件: 省電力budgetと成功/不明件数、power gateの限界公開
- 状態: NOT_RUN_PRODUCT_TEST

## ME08 — 低電池＋安全優先
- 要求: REQ-14, REQ-25 / 種別: HARDWARE
- 前提: 設定された電池目標とdeadline
- 操作・故障: 両方同時に満たせない構成
- 合格条件: 未達と理由を返す、認証省略や未送信成功はしない
- 状態: NOT_RUN_PRODUCT_TEST
