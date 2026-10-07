# 19 Serial操作と制御の署名境界
## 1. Wire上の二種類のcontrol
`control-body`の型/CBOR規則は共通。永続的な認可/構成objectだけCOSE_Sign1で署名する。対象typeは1/2/3/4/5/11/12/19/21/26/29/30/31/32/34（うち19 channel-planと21 recovery-beaconは署名形式の定義のみで、本版のchannel planは署名せずroot↔memberのend session内のcompact recordで運ぶ。lm_install_controlは19/21をUNSUPPORTEDにする: FIX10-D11、docs/05 §6。34 LedgerBackupはserial 18〜22（§9）だけで運び、lm_install_controlはUNSUPPORTED）。type22は旧group snapshot予約で新規送信しない。root/fleetの権限と世代を検証する。時間同期/neighbor probe/配送receipt/route requestを送るたびにP-256署名しない。
その他のtypeは検証済みlink/end sessionのAEAD内で運ぶ。issuerはそのsessionの完全Identityと一致しなければ拒否。typeごとのauthority条件（RouteLease/TimeResponseはroot、JoinStoredは対象Device等）も検査する。preauthでは署名済みcredential/hintまたはEDHOC carrier以外を受けない。signed objectを要求する場面にunsigned controlを代入してはならない。

## 2. hashの自己参照を避ける
channel `plan_hash`はdeterministic CBOR `[plan_id,root_term,channel_epoch,old,new,participant_hash,switch_root_ms,max_clock_error_ms,settle_ms,policy_revision]` のSHA256。phaseおよびplan_hash自身を含めない。PREPARE/COMMIT/ABORTは同じplan本体を参照する。request/revisionのouter envelopeは署名に入るがplan_hashへ二重に入れない。
prepare-hashは受信したMemberCredentialのCOSE bytes全体のSHA256。GroupSnapshotV2のsnapshot_hashは22章のdomain/group/revision/token/origin/世代付き全集合を含むcanonical配列のSHA256、各pageだけのhashではない。intent_hashは08/09の定義であり、packet/ciphertext hashとは別。

## 3. Serial種類とcorrelation
headerは09の18B。kind: HELLO1 / EDHOC2 / REQUEST3 / RESPONSE4 / EVENT5 / CREDIT6 / PING7。未認証時に許すのはHELLO/EDHOCのみ。REQUEST/RESPONSE/EVENT/CREDIT/PINGはUSB session AEAD必須。kindとheaderはAADへ入れる。
全REQUESTはrequest_id128、method、typed params。RESPONSEは同じrequest_idとstatus・typed result。SDK operation64は当該gateway boot内だけ、Host operation128と取り違えない。msg IDでの再照会を跨bootの根拠にする。

## 4. Serial method
1 CAPABILITIES / 2 SEND / 3 GET_MESSAGE / 4 CANCEL / 5 JOIN_DECIDE / 6 INSTALL_CONTROL / 7 NODE_QUERY / 8 GROUP_SNAPSHOT / 9 HOST_STORE_ACK / 10 EVENT_ACK / 11 CHANNEL_ACTION / 12 SLEEP_WINDOW / 13 GET_REQUEST / 14 GROUP_SET。
16 DIAGNOSTICS（params=nil。rootの診断snapshotとfeature表を返す。Hostが要求した時だけ実行し、周期pollingは行わない）。17 POLICY_SET（`[join-mode, expected-revision]`。rootの`lm_policy_set`でjoin modeを1項目だけCAS変更し、commit後のOPERATION eventで完了する。NODE_QUERYの結果は`policy`=[revision, join mode]を含む。HIL-F5）。18〜22は台帳のbackupとrestore（§9）。未知methodはUNSUPPORTED。SENDは宛先fullIdentity・MessageId・intent_hash・app_port・flags・root_term・expiry・bytesを含む。HostはrootアプリのIdentityとして送信し、勝手な他端末originは指定できない。
INSTALL_CONTROLは署名bytesの配送であり、API受理でDevice適用済みにはしない。JOIN_DECIDEはrequestの本人/credential hashを再照合。EVENT_ACKは受信通知の進捗でありHOST_STORE_ACKとは別。後者だけHost永続保存を証明する。

## 5. credits / retry
各側が累積grant(frame u64, bytes u64)を送る。新sessionだけ両カウンタ0へ戻す。送信側は累積消費がgrant内のときだけ送る。相手の同じCREDITを二重加算しない。上限16record/32KiB。control返信用に別2record/2KiBを予約しDATAが占有しない。unsigned wrapは拒否。
CRC破損ではrecordを捨ててdelimiter同期。AEAD/counter不一致ではsessionを切りfresh EDHOC。USB切断後の外部write済み操作は自動で成功/未送信にしない。READ/GET_REQUEST/GET_MESSAGEで照合してから必要な再送へ進む。
応答待ち既定5秒。同期処理を5秒blockingするのではない。長いapplyは即PENDING応答後EVENTと照会で決着。PING周期5秒、15秒無受信で切断疑い。起動時HELLOはbounded1秒retryを10回、その後最大30秒backoffし永久停止しない。

## 6. Serial content ceiling
Serial REQUESTは8192B以下のdeterministic CBOR、未認証HELLO/EDHOC objectは1024B以下。RF上の250B上限とは別であり、4096B object+metadataも1 Serial recordに収められる。decoded最大は18+8192+16+4=8230B。root/Hostは1つの固定上限bufferを予約し、さらに無制限な8KiBキューを積まない。
SENDのflagsは0..63：bit0-1 delivery、bit2-3 priority、bit4 durable（09章のflagsと同配置）、bit5 strict_single_frame（rootの局所送信option。RF wireへは載せず、立てば分割せず1 frameに収まらない時PAYLOAD_TOO_LARGE）。SEND payloadは通常512B、object_transfer=trueかつcapability有効時4096Bまで（group宛のobjectはUNSUPPORTED）。INSTALL_CONTROLのCOSE bytesは4096Bまで、EVENT/RESPONSEのtyped payloadは6144Bまで。全envelopeの8192B上限をさらに検査。USB独自のslab転送/分割STARTは作らず、RF送信時だけ09の共通fragment engineを使う。

詳しいshapeは[serial.cddl](../protocol/serial.cddl)。認証・認可・idempotencyは処理前に行う。

## 7. 応答bodyの固定対応
RESPONSE result bstrは次の型をCBOR化したもの。CAPABILITIES/NODE_QUERY/GROUP_SNAPSHOTはそれぞれAPIと同じfield名を持つmap（u64はCBOR uint）、GET_MESSAGEはoperation/evidence、GET_REQUESTはlifecycle state、SEND/CANCEL/INSTALL/CHANNEL/GROUP_SETはoperation_id/phase/reasonのmap。accepted空mapを実適用と扱わない。EVENT payloadもAPI Eventのmapで、CBOR byte stringをJSONではhex/base64規則へ変換する。全mapのsizeと未知field処理はOpenAPI schemaと19のbyte上限に従う。bridgeは自由な文字列JSONをそのまま通すのではなくtyped codecで生成する。

## 8. spec0.2 Power/Group追加
Serial NODE_QUERYはpower snapshotも返せる。結果mapのkeyは長さ→bytes順で`tree`・`nodes`・`power`・`policy`・`channel`・`pending`・`revision`。`tree`=[address, parent address, depth]の配列（FIELD）。rootの承認済み木で今parent linkを持つ（祖先がすべてActiveでlease内の）列挙済みmemberだけを載せ、parentはrootなら（depth 1）rootの短アドレス。短アドレスは`nodes`行のaddressで引く検索ヒントで、Identityではない。行が無いmemberは承認済みparentを持たない。Hostはdepth 1のparentをroot自身のDeviceIdに、それ以外を`nodes`行のDeviceIdに写して`GET /v1/nodes`の`parent_device_id`/`root_depth`にする。親の付け替えにrootはeventを出さないため、Hostは他の更新が10秒無いときだけNODE_QUERYを再実行する（event駆動のrefreshに加える有界timer。切断中は動かさない）。INSTALL_CONTROLに29/30/31を載せ、別の非認証の管理口を作らない。RF Power poll/grantは直結peer向けで、Serialに1窓ごと中継する必要はない。GROUP_SNAPSHOTはtype32のsnapshotを返す。page0のtoken=nilで集合を確定し、後続pageは同tokenを必須とする。RF側の同等要求はAEADで保護したcontrol33（GroupSnapshotRequest）。originはsessionのIdentityであり、他人のorigin指定を受けない。
GROUP_TARGETS=15を追加し、operation_idとsnapshot_token、offset/limit（最大16）を渡す。応答はOpenAPI GroupTargetsPageのCBOR map。未知operation、違うtoken、再起動で無効なlocal operationには正しいエラーを返し、全台成功を捏造しない。

## 9. 台帳のbackupとrestore（methods 18〜22、issue #5）
rootの台帳（member ledger）を署名付きbackupとして取り出し、故障したrootの代わりの**交換rootへ復元**する。内容、整合性、順序は[12章 §5](12-storage.md)と[21章 §8](21-lifecycle-operations.md)、署名headerは`protocol/control.cddl`のtype 34。ここはserial上の手順だけを定める。いずれもHostがpairされたrootのapplicationとして呼ぶ。

**backup（pull）**
- 18 LEDGER_BACKUP_BEGIN（params nil）。rootは台帳をFlashから読んで一貫した断面を取り、次のsequence番号をdurableにしてからheaderへ署名する。受理（operation id）が返り、完了はOPERATION event（reason 0）。BUSY=joinやinstallが台帳のmemoryを持っている／前のbackupを作成中（待ってやり直す）。RECOVERY_REQUIRED=台帳が無い・退役済み・durableでない書込みが残っている・sequence recordが読めない（署名しない）。
- 19 LEDGER_BACKUP_GET（`[seq, index]`）。index 0はsigned header（seq 0は「今保持しているbackupのheader」。sequenceはheaderの中にある）。index 1..countは正規順のrecord。resultは`{id, data, count, index, state}`のmap。recordは1回のFlash読みなので、読み終わるまでBUSY（同じindexをやり直す）。CONFLICT=その後に台帳が書かれた、または別のbackupが作られた（断面は破棄され、もう一度BEGINから）。NOT_FOUND=保持しているbackupが無い。HostはBEGIN→event→index 0..count→chain検証→DB保存とし、検証に失敗したbackupは保存しない。

**restore（push、交換root）**
- 20 LEDGER_RESTORE_HANDOVER（`[handover COSE]`）：交換rootを新rootと名指すfleet署名のRootHandover（type31）。台帳が無い（manifestが無くRECOVERY_REQUIRED）rootだけが受ける（台帳があればCONFLICT）。以前の中断したrestoreが残したrecordはここで中和される。
- 21 LEDGER_RESTORE_HEADER（`[header COSE]`）：旧rootのsigned header。fleet trust → headerの中の旧RootDelegation → 旧rootの署名、domain一致、handoverのold_root・old generation一致、sequenceが交換root自身の知るsequence以上であることを検査する。
- 22 LEDGER_RESTORE_RECORD（`[index, id, state, payload, next]`）：recordをheaderの順に1件ずつ。各recordはheaderのhash chainで検証されてから書かれ、最後のmanifestはsequence recordの後に書かれる。台帳はその後ロードされ、最後のrecordのOPERATION eventはroot準備完了（ready）で終わる。
各手順は受理（operation id）とOPERATION eventで終わる。manifestがdurableになるまでrootはRECOVERY_REQUIREDのままで、途中で電源が切れても「台帳なし」か「完全な台帳」のどちらかしか残らない。HostはCONFLICT/AUTH_REJECTED等をそのままoperationの結果にし、成功を推定しない。
