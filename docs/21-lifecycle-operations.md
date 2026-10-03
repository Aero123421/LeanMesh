# 21 設置・在庫・交換・移設の汎用運用契約

**07章を置き換えず、SDKの公開面とイレギュラー時の挙動を補う。KG専用の設備/役割モデルは作らない。**

## 1. lifecycleの3層

製造済みIdentity、domain membership、利用アプリの配置を分離する。`provisioned`は秘密鍵とcredentialがある事実、`ACTIVE`はネットワーク所属の事実、`commissioned`は利用アプリの運用準備が整った事実。Joinだけでセンサー校正や表示確認を完了扱いしない。

工場検査、倉庫試験、本番は別DomainId。試験networkで一度Joinしたことを出荷時の本番許可として流用しない。全機で同一factory private keyを持たない。出荷鍵、許可されたfleet公開anchor、製品のserialとDeviceIdの対応を記録し、通常firmware imageへ個体秘密を焼き込まない。

## 2. 設置モードの選択

|選択|開始条件|認可|
|---|---|---|
|CLOSED|開始しない|管理者が開くまで新Joinなし|
|EXTERNAL|手動APIまたは設定された起動/孤立条件|認証後の外部承認。サービス不在はPENDING|
|PREAPPROVED|同上|署名AssignmentTicket・有効expected entry・最新失効条件が揃う時のみ自動|

「電源投入で開始」「ボタン長押しで開始」「QR選択後5分だけ受入」はこの組合せで表す。ボタンの秒数、QR表示、人の権限名は利用製品が決める。APIから呼んだことを物理ボタンを押した証拠とは呼ばない。

短い受入期間は`CommissioningWindow`（type30）の1つの署名objectで表す。window_id、domain、expected_set_revision、root_term、not_before_root_ms、expires_root_ms、max_new_members、allowed_roles、policy_revisionを固定。最大15分。term変更で有効時間を引き継がず、rootが明示的に再発行する。

windowは許可対象の追加入口であり、IdentityやAssignmentTicketの検査を迂回しない。締切前に認証した要求でも、締切後の新規承認は拒否。締切前にroot ACTIVEをcommitしたものの最終ACK回収は継続できる。max_new_membersはroot durable予約でカウントし、同request_id再送を二重に数えない。予約数はwindowに属し、windowの再投入で0へ戻らない：policy_revisionをwindowのreplay floorとして保存し、同じwindow（id・expected_set_revision・max_new_members・allowed_roles・policy_revisionが同一。term変更時の時刻だけ違う再発行を含む）は数を継続、それより低いpolicy_revision、または同じpolicy_revisionの別windowはCONFLICT。新しい予算は高いpolicy_revisionの新windowとして発行する。

## 3. 事前登録前の電源投入・古いhint

Bに予定がない間はNOT_EXPECTED hintと有限backoff。後からexpected revisionが上がれば次の通常listen/poll/探索で再評価できる。電池端末を即時に起こせるとは言わない。fakeの高revisionで連続handshakeを誘発されないよう、hintはrate-limitし、署名情報を検証するまでpersistent floorや電力予算をリセットしない。

filter false-negative/stale/unavailableは認可拒否の確定ではない。有限予算でrootへの正規照会を選べる。隣接domainのRSSIが強くても正当なassignmentより優先しない。数時間の固定blacklistをアプリに隠して持たない。

## 4. 30〜64台を一度に設置

batch_idはHostの管理単位であり別の無線protocolではない。予定DeviceId集合を固定し、各Deviceのrequest_id/credential hash/assignmentを独立に追う。

`expected / discovered / authenticating / waiting_approval / prepared / active_confirmed / rejected / unknown`を集計する。「27/30台完了」はACTIVE確認の27台だけ。短い番号割当はrootの空きslot管理でよく、発見順・無線の強さでIdentityを決めない。

同時暗号jobsとJoin proxy slotは既存の予算を共有。重要DATAとroute controlの予約枠は残す。1台の不正credential/死んだNodeが全batchをrollbackしない。Host再起動はbatch/request_idを復元するが、root未確認のstateをactiveへ昇格しない。低電池端末は承認待ちの間にsleepできる。

## 5. 07章のcommitを「全装置同時atomic」と呼ばない

root ACTIVE commit後にNodeへJOIN_COMMITが届かないこと、Node ACTIVE後にJOIN_ACTIVEが失われることは起こり得る。二者が同時に同じ状態になった保証ではなく、**片側の永続状態とrequest_id/hashによる再照会で収束する契約**である。

Node PREPAREDだけなら通常DATA不可。root ACTIVEだけならhost観測はactive_unconfirmed。rootは同requestの予約IDを再発行しない。prepared timeout後にCOMMITが遅着しても、対応するdurable request状態がABORTEDなら拒否する。COMMITTEDはtimeoutでABORTEDへ戻さない。曖昧な台帳を推測で回復しない。

## 6. 置き場所変更・同じ個体の再参加・現場間移設

同domain内の移動はroute修復と利用アプリのbinding変更。ネットワーク登録を消さない。取り付け校正の無効化は上位eventで実装する。

A→Bは07章のsigned replacementを使う。A側のPC停止、Aの電源を抜いただけ、A/B双方がまだ稼働、A→B→Aを正式シナリオとする。新しいassignment generationを進め、DeviceIdは維持する。short addressは現場ローカルなので維持を保証しない。

同一機器を一度REVOKEDにした後の再参加は、正当な新ticketと高いmembership/assignment条件でのみ許可。古いgrantを再利用して「復活」させない。fleet LOST/STOLENとdomain REMOVEDを同義にせず、前者を単なるleaveで解除しない。offlineのfreshness情報が不足する場合、新規移設が保留になる限界を明記する。

移設で旧domain向け未ACK履歴が残っていたら、新domainへ勝手に再宛先指定しない。暗号化された旧domain記録を保持/管理回収、または権限付き明示破棄を選び、件数と履歴を残す。旧payloadをBで本日の新しい測定として公開しない。

## 7. 予備機への交換

別DeviceIdへRoleを付け替えるのはアプリ。SDKは旧Device revoke、予備Device Join、各々のevidenceを返すだけ。旧private key、boot counter、session、inflight MessageIdを予備機へコピーしない。

旧機器が後から戻っても、旧membershipで新配置へ影響しない。交換操作の途中で電源断した場合はどちらの個体がactiveかを照会し、両者が同じapplication roleとして操作される二重正本を上位で禁止する。SDKだけで製品のrole所有権まで保証しない。

## 8. Root/Gatewayを交換する

同じUSBポートに挿したから同じrootではない。新しいRoot DeviceIdとfleet署名のRootDelegationを必須にし、**古いroot秘密鍵を新箱へコピーしない**。

`RootHandover`（type31、fleet署名）にdomain、old_root、new_root、old/new delegation generation、new_delegation_hash、new_root_term、handover_id、recovery_modeを固定する。new delegation generationとnew_root_termは既知floorより大きくする。old_root≠new_root、new generation>old generationでなければ無効。旧rootは、new_root_termが自分の現在term（その配下の機器が従うterm）より大きいobjectでのみ退役する（そうでなければ機器が新rootを拒否し、domainが孤立する）。旧rootは起動ごとにtermが一つ進むため、戻ってくる可能性のある旧rootにはそのtermより大きいnew_root_termを名指す。検証済みobjectで旧rootは直ちに退役し（入会・更新・sessionを止める）、recordのcommit結果はその再起動後の保持だけを決める。fleet/バックアップが安全な上限を確定できなければRECOVERY_REQUIREDで止める。時計や乱数から大きそうなtermを作らない。

計画交換は旧root drain→署名objectを配布→各Node stored証拠→新root起動→各Node fresh authentication/route再登録。旧rootが故障している場合も新rootは手順を開始できるが、届いていないNodeは旧rootを待つ場合がある。全域が同時切替したとは言わない。

新rootは検証済み台帳backup/署名assignmentから構成する。old deviceのidentityやinflight命令を無条件再実行しない。

**台帳backupの取得と復元（issue #5）。** Hostは台帳が変わった後（membership event、rootの制御operationの終了、session開始時）にrootからsigned backupを取り、domainごとにsequenceが最も高い1つをSQLiteに保持する（低いsequenceで置き換えない）。旧rootが故障したら、運用者は交換rootを新DeviceIdとfleet署名のdelegation（上位generation）で用意し、fleetが旧→新のRootHandoverを署名する。HostはPOST /v1/control `LEDGER_RESTORE`（`signed_cbor_b64`=そのRootHandover、`expected_revision`=復元するbackupのsequence）で、handover → 旧rootのheader → 全recordをserial 20〜22でrootへ送る。交換rootは各段を検証してから書き（[12章 §5](12-storage.md)）、manifestを最後に書いて準備完了になる。Hostは、この復元が成功した場合に限り、domainに結び付いたrootを旧→新へ付け替える（それ以外の別rootはROOT_MISMATCHのまま）。memberはその後、各自のhandover保存と再認証（上のS18-D9）で新rootに従い、台帳が既に載せているので新しいticket・expected entry・承認は要らない。
限界：復元できるのは最後に取れたbackupまで（それ以降の入会・失効・離脱は含まれない。backup後に旧rootで起きた失効はfleet/Hostの失効記録で再投入する）。backupが無ければ従来どおりRECOVERY_REQUIREDで止まる（空の台帳で再開しない）。Hostはheaderの署名を検証せず（chain整合のみ）、署名の検証は復元される交換rootが行う。root termが変わった有限期限commandは08章のINDETERMINATE→アプリ再照合へ。旧rootの再出現は高いdelegation floorで拒否し、二つのrootをactive運用しない。

backup喪失時は、fleetの現行inventory/失効記録が得られる範囲で再認証する。現行の失効floorを知らないまま全員許可する「簡単復旧」は提供しない。物理的に完全複製されたroot鍵の排除は別のcustody問題であり、ネットワークだけで解決できるとは言わない。

## 9. Resetを2種類に限定する

**ネットワーク離脱**は`lm_leave(IMMEDIATE)`を再利用。membership/session/pendingの処理を行うが、Device Identity、fleet anchor、assignment/revocation floors、boot counter、消費済みgrantは残す。これをfactory credential消去と呼ばない。

**工場再provision**は通常SDK API/HTTPには置かない。物理保守工程と所有者承認、新規credential登録、旧credential失効、記録保全を要求する。ボタン長押しで全floorまで初期化する設計は禁止。アプリ設定だけのresetは上位処理で、SDKのsecurity記録を巻き込まない。

ネットワークreset後も、同domainへ自動で元通り参加してよいかは有効な新しいassignment/設置windowの方針に従う。leaveをリモート攻撃者の任意操作にしない。

## 10. APIと操作結果

既存のJoin/Leave/InstallControl/Policy APIを使い、設置/工場/倉庫ごとの専用gateway serviceを増やさない。追加objectは既存bounded control転送/署名/commit engineを使う。

公開結果は少なくとも`requested / root_stored / device_stored / device_active_confirmed / old_domain_pending / rejected / recovery_required`を区別し、request_id・credential hash・DeviceId・対象domain・generationで照合する。人間向けの「接続できました」は最後の物理適用や製品運用開始と混同しない。
