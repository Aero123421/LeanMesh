# 07 Join・復帰・leave・移設

## 1. 分離する状態
membership: UNASSIGNED / DISCOVERING / AUTHENTICATING / APPROVAL_PENDING / PREPARED / ACTIVE / LEAVING / REVOKED / QUARANTINED。
connectivity: UNKNOWN / REACHABLE / DEGRADED / ISOLATED / SLEEPING。
ACTIVE+ISOLATED、ACTIVE+SLEEPINGは正常に表現できる。通信timeoutだけでUNASSIGNEDに戻さない。full_id、domain、assignment_generation、membership_generation、status_since_mono、last_authenticated_rx、last_root_roundtrip、reasonをC/Host双方へ公開する。

## 2. 事前準備
出荷時はDevice key、DeviceCredential、Fleet trust anchor、DiscoveryScopeKey（任意の探索絞込み用）を用意。Domainごとの秘密を全出荷機へ共通配布しない。rootにはRootDelegation、domain policy、known revocation floor、署名済みexpected entriesを配備する。
expected entryはDeviceId、target domain、assignment generation、grant hash、revision、状態。空間節約のHMAC truncated hintをrelayへ配布できるが、**positiveもnegativeも認可結果ではない**。filter false positiveを許容、stale filterのmissを永久拒否にしない。

## 3. 賢い探索
起動時、保存domain/current channelを800ms listen。既存の認証済み可用peerがあればmembership resumeへ。なければDiscoveryScopeKeyに結合したhint要求をjitter0〜400msで送る。relayはnonceとdomain hint、expected_revision、candidate順位を返し、rootまでのJoin proxy経路を提供する。
DiscoveryScopeKey（任意、32B、配備scope単位で工場投入。domain秘密ではない）を持つ機器・relay・rootは、hello/offerに`HMAC-SHA256(key, "LM1-DISC" || object種別 || helloのnonce16 || offerならdepth u8・revision u32be)`の先頭8Bをtagとして付け、同じscopeのtagを持つhintにだけ応答/追従する。keyの無いnodeは絞込みをしない。tagはkey保持者全員が作れる絞込みで、positive/negativeとも認可結果ではない（認可はhandshakeとcredential）。
1回の探索は最大30秒・候補3・許可channel2周・full handshake候補2。失敗後は1〜60秒指数backoff。期待リスト更新またはアプリ明示requestでbackoffを解除できる。同じ機器をB登録前に一度起動しただけで6時間拒否する固定policyを持たない。
`NOT_EXPECTED`は10〜60秒のhint抑制、`BLOCKED`は署名付き失効情報としてgenerationを記録する。双方を同じタイマーにしない。探索予算切れを機器故障と扱わない。

## 4. Join handshakeとdurable境界
|段階|動作と成立条件|
|---|---|
|DISCOVER|候補/hintのみ。Join成功ではない。|
|EDHOC|device↔rootをrelay proxy経由で相互認証。JOIN_ONLY session。|
|REQUEST|DeviceCredential、AssignmentTicket、nonce、capability、request_idを暗号化送信。rootがfleet/domain/key/generation/失効/期待リストを検査。|
|APPROVAL_PENDING|external modeではHostへ通知。Host不在は保留。preapproved modeは有効な署名ticket+期待entryが揃う場合のみ自動承認。|
|PREPARE|rootがshort addressとmembership_generationを予約しPREPARED ledgerをcommit。MemberCredential（署名64Bを保留＝0、どのpeerも受理しない形）とpolicy hashをNodeへ。PREPARE時点の物はcredentialではない。|
|STORED|Nodeがinactive slotへ全member recordを保存/readbackしJOIN_STORED(request_id, hash)を返す。|
|COMMIT|rootがACTIVE ledgerを保存してから保留署名入りJOIN_COMMIT。Nodeは署名で完成したcredentialを検証してからcommit markerを保存しJOIN_ACTIVEを返す。|
|FINAL|rootがNodeのACTIVE証拠を記録しHostへ反映。ACK喪失時はrequest_id照会で再開。|

準備中のNodeが通常DATAを送っても拒否（PREPARE時の物は署名を欠くので、rootに限らずどのmemberもsessionを張らない）。rootはLink/End sessionを、どちらが開始したかに関わらず、ledgerがそのDevice・address・assignment・membershipをACTIVEとして持つ場合だけ張る。ledgerに無い相手は拒否する。ledgerの読込前（起動直後）と喪失時（RECOVERY_REQUIRED）のrootは判定できないので、handshakeを開始も応答もしない（ローカルBUSY。相手credentialの拒否として数えない）。Nodeがactiveになった直後に最終ACKが落ちた場合はrootが保留とactiveを同一IDで整合させ、2つ目のshort addressを再発行しない。join objectのretryはhash不変。同じrequest_idの別内容はCONFLICT。
承認待ちtimeoutは300秒で、Nodeに再申請可能を返す。prepared予約の期限は120秒。再起動して期限不明なら照会/回復とし、古いticketを勝手に新期限へ延長しない。

## 5. resume
ACTIVE recordがあり同domainなら新規の人間承認は不要。cold/deep bootはcredential/失効snapshotを検証→fresh EDHOC→route再登録。RAM保持休止は20章のsession/時間条件を満たせば既存sessionを再利用する。旧short addressの再利用はroot ledgerが同じDeviceId/generationを確認した場合だけ。session再確立前に古いcounterを使わない。全台停電はDeviceIdとboot nonceに基づくjitterとroot側admissionで分散する。

## 6. 手動leave
`leave(mode=DRAIN|IMMEDIATE, deadline_ms)`。DRAINは新規送信拒否、重要pendingの結果確定、relayなら子の代替到達確認（最大30秒）。期限までに退避できなくてもIMMEDIATEへの変更はアプリ明示のみ。IMMEDIATEは未完了をINDETERMINATE/NOT_SENTへ確定し旧domain key/credentialを論理消去、fleet identityとassignment floorは残す。端末故障でleaveできない場合はroot revocationだけでも実行可能。

## 7. 現場内移設・機器交換
同じdomain内の置き場所変更はネットワーク所属を変えない。上位がapplication binding_revisionを更新し、校正無効化/再学習/以前の命令の拒否を扱う。新Deviceへの交換ではDeviceIdは異なり、上位roleだけ継承。旧session、counter、校正、未完了命令を新機器へコピーしない。

## 8. 別domainへ移設（旧rootが停止していても可能）
ユーザーの移設要望を満たすため、手動leave→joinに加えて**signed replacement**を仕様に含める。自動切替の既定はOFF。active recordを保持したまま探索する `join(mode=TRANSFER_CANDIDATE)` を設ける。isolation-triggeredは明示policyでON、最短隔離600秒+通信予算を満たす場合のみ。
新domain Bはfleet issuerが署名したAssignmentTicketを提示する。DeviceId、source_domain A、target_domain B、target root delegation hash、expected_old_assignment_generation、new_generation、grant_id、Deviceが今回発行したtransfer_nonce16Bを必須とする。new_generationはoldより大きい。事前発行offline ticketはDevice nonceではなく**一回限りの事前登録grant_id**を使い、Device側の消費台帳とfloorで再使用を拒否する。ticket modeで両者を明示的に区別する。rootもledger entryに、そのDeviceがACTIVEにしたassignment generationの最大値を保存し、それ以下のticketはmodeやpolicyに関わらず消費済みとして拒否する（floor表の空きに依存しない）。Device側の消費記録はleaveのtombstone（LEFT record）自体が保持し、1回のcommitでleaveと同時に確定する。
DeviceはBの相互認証とticket確認後、旧Aを使えるままB PREPAREDを書き、B/root・deviceのcommit handoffを行う。B COMMITを受理した時点でAの新規DATA送信と受信を停止し、B membershipをatomic選択する。二つのdomainを同時ACTIVEにしない。
Aへの通知/消去ACKは移設成立の前提でない。Hostに `old_domain_reconciliation=PENDING` を残す。Aのrootが後日戻った時に同ticketの移設事実を伝え、旧authorizationを失効。A→B→Aもより高いassignment generationで許可。Device key/DeviceIdは維持、short addressは変更可。
**旧Aがオフラインで失効情報を知らない間、全ネットワーク上の旧台帳が瞬時に更新されることは保証しない**。Device側はAを拒否し、他のmemberには有限leaseで伝播させる。紛失機器は最新のfleet revoke floorとticket issuer方針で拒否。staleな承認情報しかなければ新規移設はfail-closed。

## 9. 二重操作
membership commit・leave・transfer・root delegation変更はNodeごとに排他的。新channelのPREPARE中は参加準備まで進めても所属commitは延期。COMMITTED channel変更は先に復旧してから移設を再開。policy設定はexpected_revisionのCAS。同ID/同内容は保存済み結果、異内容はCONFLICT。errorは小さい固定reason codeとし人間向け文字列をWireへ載せない。

## 10. spec0.2の運用面
設置window、電源先行、大量設置、工場/倉庫、Root交換、resetは[21章](21-lifecycle-operations.md)。省電力で承認待ちを中断する場合はrequest_idを保持し、次wakeから同じ案件を照会する。sessionを失ったのにJOIN_ONLY traffic keyを復元しない。07章の二者commitは全装置同時の原子的transactionではなく、永続記録と再照会による収束契約である。

## 実装の自動移設とrelay DRAIN

leaf/relayのローカルpolicyをCAS更新して隔離triggerを明示ONにする。最短600秒、既定OFF。冷起動と到達回復で計時をリセットし、予定Sleep時間を除外する。worker、channel移行、確認待ちや通信予算の不足時は有界に延期する。署名付きB ticketが無ければA所属を保持しAUTH_PENDINGのまま。既存TRANSFER_CANDIDATEの検証とatomic activationを共有する。

relay DRAINはrootごとに1件の64member bitmapで配下を固定する。新規子の登録を止め、各子がrelayを含まない有効root経路の現在revisionをREADYしたことを要求する。子の消失・世代変更や不明なtopologyは退避の証拠にしない（無関係な未確定memberがいても保守的に拒否する）。認証済み通知で子は予算内に代替親を探索・登録し、root確認前は旧経路を維持する。最大30秒の期限切れはDEADLINE_UNREACHABLEで所属維持。取消は認証済み応答を待ち最大5回送る。grant後の子受入停止は取消・離脱・世代変更まで保持し、応答紛失で新規依存を作らない。
