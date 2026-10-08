# 08 配送、順序、group、混雑

## 1. アプリ向けクラス
deliveryはBEST_EFFORT / RECEIVED / APPLIEDの3値、storageはVOLATILE / DURABLE、queue_modeはFIFO / LATEST。独立した軸だが、LATESTはBEST_EFFORT+VOLATILEのみ。保持すべきeventや副作用commandには使わない。
LATESTのキーは `(principal, domain, destination snapshot, app_port, coalesce_key)`。最新値による置換は**まだ外部送信していない**recordだけ。同じdestでも異なるkeyは残す。置換の因果をsuperseded_byで保存する。既送信commandを最新値へ変形しない。
最大通常message512B。<=経路MTUなら1frame、超過は必須small reassembly。optional objectは4096B。大きな周期JSONを高速化の前提にしない。

## 2. IDとhash
MessageId128 = origin incarnation64 + local sequence64。incarnationは起動前の永続boot counterに基づき、store喪失で以前のincarnationを再発行しない。MessageIdは全ネットワークで単独認可せず、DeviceId/assignment_generationと組にする。
intent_hash=SHA-256(deterministic CBOR `[origin DeviceId, target DeviceId, domain, app_port, delivery, storage, priority, effective_root_term, expires_root_ms, payload bytes]`)。effective_root_termはexpires_root_ms=0なら0、それ以外は送信時root_term。期限のないdurable履歴をroot再起動後に同IDで再送できるようにし、有限期限命令は勝手に別termへ書き換えない。同ID異hashはCONFLICT。暗号sessionの更新、MAC、path、送信時刻はhashへ入れない。hashは受信側でもWire値と検証済みsessionから再計算できなければならない。groupは宛先ごとにhashを計算し、別のgroup snapshot hashと混同しない。アプリの世代番号はopaque payload内に置き、SDK headerに重複させない。

## 3. receipt
HOST_COMMITTED（Host DBに保存）、NODE_QUEUED、HOP_ACCEPTED（次hop RAM予約）、END_RECEIVED（終端の宣言された保存条件）、APP_APPLIED（アプリ本人の結果）、EXPIRED、REJECTED、INDETERMINATEを区別する。
送信API OKは受付だけ。END_RECEIVEDはDURABLE指定なら終端journalのcommit後。Host宛ならHostのDB commit後のreceiptを待つ。gatewayで受けただけならGATEWAY_RAM_RECEIVEDでしかない。
APP_APPLIEDはアプリが `lm_report_application_result()` でMessageId/hash/resultを渡した場合だけ発行。結果PENDING→APPLIED/REJECTEDの非同期化を許可。型付きresult<=32B、長い診断は別object。ACK lossでAPPLIEDが不明になった場合、期限切れを「未適用」と断定しない。

## 4. 冪等性と順序
SDKはcallbackの重複抑制と有限receipt cacheを提供する。電源断をまたぐ物理副作用exactly-onceは保証しない。アプリは永続operation ledgerまたは絶対状態+application_revisionで冪等化する。適用直後/receipt保存直前の電源断ではINDETERMINATEからquery/reconciliationを実行する。
一般messageに全網total orderは提供しない。送信順必要なapp streamはport+stream_id+sequenceをpayload契約で定義。最新版だけの状態は古いrevisionを受信アプリが拒否。遅いreceiptは履歴へ追加し、現在stateを巻き戻さない。

## 5. 期限
NORMAL/APPLIEDのdeadlineはroot_termとexpires_root_msで表す。送信前にroot clock boundを取得し、受信側が最遅で期限内と証明できなければTIME_UNCERTAINまたはEXPIRED。期限なしを選べるのは保存event/objectのみ。control commandで期限noneは禁止。
frameは送信Nodeの現在root_termを載せるので、期限のroot_termはNodeの現在termでなければならない（異なればTIME_UNCERTAIN、既に受付済みなら未送出はEXPIRED・送出済みはINDETERMINATE、ARCH2-D1）。アプリは`lm_root_time_get`で現在termの推定を得る。
再送round、path変更、Host再起動で元の期限を延長しない。root再起動で時刻termが変わった既送信commandはINDETERMINATE。新termへ自動で同じ有効時間を付け直さない。Hostがtrusted UTCの元deadlineを保持している場合だけ、同一application operationの別transport attemptを明示的に作り、アプリ冪等性で照合する。UTC不明のままdowntimeを0と仮定しない。

**rootが届け先を扱わなくなった時（HIL-F6, #16）。** rootの台帳が届け先を失効（Blocked）または離脱（Left：自分の離脱、移設のreconcile）とした時点で、そのDeviceId宛ての開いた送信（rootのcontrol送信を除く）を終える：一度も出ていなければREJECTED、出たかもしれなければINDETERMINATE。理由は失効ならREVOKED、離脱ならNOT_FOUND。新しい送信は受付でその理由で拒否する。再起動後にjournalから戻った送信も、台帳のloadと回復の両方が済んだ時点で同じく終える。他のnodeはleaseで知る。再加入してACTIVEに戻れば再び送れる。

## 6. link/E2E retry
1hopはMAC result + link-auth HOP_ACCEPT。HOP_ACCEPTはreceiverが転送/受信bufferを確保してから返す。ACKそのものにACKを返さない。初回含め3link attempts、origin全体3E2E rounds、同じdeadline内。
link RTO初期80ms、SRTT+4*RTTVARの既定clampは20〜500ms。ownerは完了tokenが一致した送信のservice時間の最大値Sを保持する（watchdog以下、UNKNOWNは除外。実機p95ではない）。HOP_ACK待ちは自分のTX完了後に開始し、下限を2*S、上限をmax(500ms, 2*S)へ適応させる。callback前の早いACKは証拠として保持し、frameの解放と次段の待ちはcallback後に行う。E2E/REGISTER/READY/ROUTE_QUERYの待ちは最初のhopの完了後、600ms + 2*残りhop*max(120ms, 2*S)。これは未測定の既定値に観測service時間を足す保守的な予算であり、実機link p95・queue遅延のqualificationを代替しない。下位の正常retry中に上位retryを重ねない。RECEIPT自体もlink retryするがreceipt-of-receiptは出さない。

## 7. group
どの認可済みNodeもgroup送信できる。group_id/revisionをrootが管理し、送信受付時のmember集合をsnapshot化（max64、sorted unique DeviceIdと各assignment/membership generation）。spec0.2はcontrol32のGroupSnapshotV2を用いる。rootはbodyがend-to-endの場合payloadを読まず、送信元にsnapshotを返して対象ごとend sessionでfan-outする。rootで平文展開する方式へ無言でdowngradeしない。
SDKは1 logical operationとper-target resultを返す。新規group加盟が送信途中で対象へ混ざらない。cancelは未送信targetだけ、既送信は不明を残す。並列上限はorigin4、per dest1。必要な複数表示盤の操作は可能だが「30台なら必ず十分速い」と事前保証しない。20hop多数fan-outのairtimeを測り、必要なら別認定のsubtree multicastを将来追加する。

## 8. scheduler
CONTROL/DATA_URGENT/NORMAL/BULKをDRR、重み4:8:4:1で共有。優先は永久独占権でない。CONTROLには毎100ms窓で20%相当の送出機会を最低確保、URGENTは最大2frame連続後に期限の近いcontrolを確認する。airtime tokenは推定PHY時間+測定MAC overheadで課金し、全宛先・group・retry・controlを同じaccountingへ通す。
初期RF総量target300ms/s、短期burst600ms、urgent借越し最大100ms（後で返済）。これは現実のchannel busy率の測定値ではない。APIの受付rateは別：principal20req/s burst40、全体100req/s burst100。保存済み同一idempotent応答はRF予算を消費しない。
RX pool不足はNO_CAPACITY/credit0、古いbulk再組立を先に失効する。critical durableを黙って捨てない。拒否の理由、retry_after、queue_depthを公開し、故障端末1台が他の通信を止めない。

## 副作用と期限の宣言
物理副作用を求める送信はアプリがAPPLIEDを指定し、有限deadlineを付ける。SDKはopaque本文から命令か観測かを推測しない。deadlineなしを許すのはRECEIVED+DURABLEの履歴/保守データだけであり、アプリが副作用命令をその型へ偽装してはならない。root_term変更後の再発行は元アプリ操作IDを保持した明示reconciliationであり、自動的に寿命を延ばさない。

## spec0.2: 一斉配信の進捗と省電力
[22章](22-group-and-sleep.md)がtarget世代、待受、結果集計の追加契約。WAIT_WAKEは結果ではなく待機phaseで、inflight送出枠を占有しない。SUBMITTEDはBEST_EFFORTの送出証拠だけ、PARTIALはgroup集約結果だけで個別targetへ代入しない。parentのRAM保管をDURABLE終端受理へ格上げしない。

### relayの認可待ち
relayの次hopがTIME_UNCERTAINならHOP_ACK BUSY/retry_after 2000msを返す（最大16回）。認可を弱めずcredential/時刻の更新を待ち、NoRouteやRF失敗へ混ぜない。
