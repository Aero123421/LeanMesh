# 22 一斉配信・待受・個別結果の完全な契約

## 1. 提供するものと提供しないもの

提供するのはGroup APIによる**宛先snapshot付きfan-out**。生ESP-NOW broadcastを全relayが再broadcastする方式でも、全端末が同時刻に動くtransactionでもない。最大8group、1group最大64Device、認可された任意Nodeが送信元になれる。

Rootはgroup管理・署名snapshot・経路解決を担当し、**fan-outする主体はorigin**。originがroot/Hostならrootから展開する。一般Node originならそのNodeが各targetとのend sessionで暗号化し、rootが本文を読むことはない。前の口頭説明の「常にrootがfan-out」はこの区別を省略した表現である。

Nodeアプリの実適用結果を要求できるが、64台×20hopが一定時間で終わるとは保証しない。wireのairtimeは概ね各宛先経路の総和に従う。sleepを含むグループでは最終完了が一番遅いwakeやdeadlineまでかかることがある。

## 2. snapshotと機器世代

spec0.2の新規送信は`GroupSnapshotV2`（control type32）を使う。type22は0.1の履歴用予約であり、新実装が意味を変えて再利用しない。旧22を必須機能として送りつけられたらUNSUPPORTED。

snapshotは`domain, group_id, group_revision, token, origin DeviceId, sorted unique targets`を固定し、targetは`[DeviceId, assignment_generation, membership_generation]`。SHA-256(deterministic CBORの上記配列)をsnapshot_hashとする。先にrootが全集合を固定してから最大16targets/pageで返す。ただし1 pageの符号化済みtarget行は700 Bまでとし（世代が2^63近い最悪値で13行、最大5page。page番号は0..4）、各pageの範囲は集合だけから決まる（署名済みpageと封筒が交換の1 KiB領域に収まる）。全pageに同token/hash/total。pageの追加取得で集合を作り直さない。

rootのgroup定義とrevisionはdurable（setはrecordのcommit後に適用・完了、revisionは再起動をまたいで続く）。定義はledger slotでmemberを名指し、名指されたslotは他のDeviceへ再利用しない：離脱したmemberは編集されるまで定義に残り、dispatch時にREJECTEDとなる（同じ番号の新しい機器へ送らない。FIX8-D9/D10）。
snapshot取得は認証済みoriginがcontrol type33でrootへ要求する。SerialのGROUP_SNAPSHOT=8も同じ意味とし、originはUSB sessionのrootアプリIdentityになる。page0/token=nullで新snapshotを予約し、返されたtokenを後続page要求に付ける。各page要求は独立request_idで、再送は同一ID・同一params。rootはtokenをdomain/origin/group/revisionへ結合し、別originのtokenを拒否する。snapshotは最大4件・120秒だけrootに保持し、満杯はNO_CAPACITY、消失/満了はSNAPSHOT_EXPIRED相当のreasonで拒否する。取得が終わるまでは送信受付を完了しない。originが検証済み全集合を保存した後はrootのpage cache満了が送信操作を無効にしない。

64targetsを受け取ったoriginはpage/hashを検証してから受付を完了する。begin時に必要なmessage sequenceブロックとtarget状態を予約する。同じgroup operationにtargetを後から追加しない。空groupはtotal=0の完了でありALLではない。

**snapshotは参加権限を凍結しない。** 実際のdispatch直前と受信時に最新失効floor・membership・assignmentを照合する。移設/revokeしたtargetはREJECTED/REVOKED。グループの編集だけでは送信済み操作の対象は変わらない。DEVICE世代が違うのに「同じ番号だから新しい機器へ送る」を禁止する。

## 3. 状態と結果

宛先ごとに次を持つ。

`WAIT_ROUTE / WAIT_AUTH / WAIT_WAKE / READY / SENDING / WAIT_RECEIPT / FINAL`

outcomeはPENDING、SUBMITTED（BEST_EFFORTの送出のみ）、RECEIVED、APPLIED、REJECTED、EXPIRED、CANCELLED_NOT_SENT、INDETERMINATE、SUPERSEDED。RECEIVEDは要求された終端保存条件の証拠がある時だけ。SUBMITTEDをRECEIVED/APPLIEDに数えない。

GroupProgressはtotal、pending、submitted、received、applied、rejected、expired、cancelled、indeterminate、superseded、snapshot token/hash、各targetのMessageIdと世代を返す。各targetは1つの現在outcomeだけを持ち、総和=total。過去の証拠は別履歴なのでreceived証拠とapplied証拠を二重に対象件数へ足さない。

全targetが終端状態になったらoperation phase=FINAL。要求の証拠を全targetが満たした場合だけ集約成功。混在はPARTIAL、全失敗でも詳細は維持する。late APPLIEDが届いたら歴史上の不明が証拠で更新されたことをrevision付きeventで通知する。アプリの現在状態まで古い結果で巻き戻さない。

## 4. 公平な送信とRAM

originのinflightは最大4、同targetは1。READYな対象からround-robin。WAIT_WAKE/WAIT_AUTHはradio送出slotを占有し続けない。handshakeは既存slow workerのglobal上限を共有する。

元payloadは1copy、target stateは固定配列。64個分の512B本文を複製しない。end session cacheはrole profileの上限を守り、使い終わった相手を適切に退避して次へ進む。全64人と同時にEDHOC contextを作らない。target_id/message_id配列と結果だけは保持し、上限超過は受付前にNO_CAPACITY。

DURABLEなgroupはimmutable body+snapshot+全target MessageIdの予約と進捗をjournalにcommitしてから受付成功。単体message用の16slotを64targetに無言で使い回さず、group1件のcompact recordとして会計する。roleのgroup operation上限（leaf1/relay1/root4）が足りなければ受付拒否。明示的にDURABLE非対応のbuildではUNSUPPORTED。

## 5. 眠るtarget

|状況|扱い|
|---|---|
|起きている対象|通常送信。眠る対象を待たない。|
|deadline内に次wakeがある|WAIT_WAKE。originの原本を保持し、parent RAM mailboxは補助。|
|次wakeが期限より後と証明できる|未送信EXPIRED + DEADLINE_UNREACHABLE。|
|予定不明/外部割込みだけ|WAIT_WAKE + schedule UNKNOWN、deadlineでEXPIREDまたは既送信ならINDETERMINATE。|
|awake後のtargetが失効/移設済み|世代照合で拒否。旧snapshotから新domainへ再配送しない。|
|親mailbox再起動|HOP受理を成功扱いせずorigin再送で回復。|

SLEEPINGは管理上の予定状態。RF packet lossへ加算せず、retry指数を悪化させない。次のwake factはtarget→parentで認証され、必要なpending originへ限定して通知/照会する。全pollを20hop先へ配信しない。

低電力originがgroupを発行して自身も眠りたい場合、DURABLE進捗を自身で保存し、未完了のままresume可能。rootへ勝手に平文payloadを預けたり署名権限を委譲したりしない。終了までawakeにする設定と電力優先設定の違いを公開する。

## 6. Cancel / Latest / 全台同時反映

cancelは未送信targetのみCANCELLED_NOT_SENT。送信境界を跨いだtargetには取消結果不明を残す。取り消した後に届いた適用結果を捨てない。

LATESTは既存のBEST_EFFORT+VOLATILEに限定。group snapshotもcoalesce keyに含めるため、group revision変更後の新しい集合へ古い操作を転用しない。安全操作/履歴をLATESTへ自動変換しない。

`apply_at`の時刻指定による全台同時物理反映は本版で提供しない。各ノードへの事前設定配送と時刻同期があっても、故障・不達時の全台原子性は保証できない。必要なアプリはprepare/arm/executeを上位契約として別途設計し、SDKのAPPLIEDが一斉同時を意味すると説明しない。

## 7. 試験と将来の高速化

3/30/64targets、depth1/5/20、sleepy0/25/75%、背景負荷0/軽負荷/高負荷で、初回反映・最後の反映・送出airtime・再送・個別結果・Join中継遅延を測る。20hop多数fan-outを1hopと同じSLOで認定しない。

subtree multicastは、実測でfan-outが要件を満たさない時に設計判断する。グループ共通暗号鍵、ACK集約、失効、sleep、メモリの追加コストを比較してから採用する。本版で「optionalなら動く」とは記載しない。
