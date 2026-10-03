# Host API semantic constraints

OpenAPIは形、本文は横断制約。実装は両方を満たす。u63はJSON numberでなく10進文字列、parse後0..2^63-1を検査。DeviceId=64小文字hex、DomainId/operation/clientepoch/request=32小文字hex。base64のpadding/文字/decodedサイズを厳密検査。

## Message
512B以下、object_transfer=trueならcapability有効時4096B。LATESTはBEST_EFFORT+VOLATILEかつcoalesce_key必須。APPLIEDはLATEST不可。deadline noneはRECEIVED+DURABLEな保持event/保守データのみ。副作用命令はAPPLIEDと有限deadlineをアプリが指定する。SDKはopaque payloadの業務意味を推測しない。priority CONTROLは外部message APIで選べない。groupは事前登録revisionと認可集合をsnapshot化。HTTP202はHost DB commitだけ。GET Operationのevidenceで到達段階を判断する。

## Control
すべてexpected_revisionとrequest_idを要求。署名objectが必要な操作でraw JSONの承認だけを代替にしない。
- JOIN_DECISION: device_id/decision必須。APPROVEはactive pending requestのkey/credential hashと一致し、root自身のticket検証も通る。
- LEAVE: schemaには予約されているが、このHost bridgeでは未対応。権限確認後、DB受理前に503/UNSUPPORTED。端末のローカルlm_leaveとは別機能。
- REVOKE: device_id、署名revoke object必須。網側拒否と端末消去は別evidence。
- TRANSFER: device_id、署名AssignmentTicket必須。source/target/generation/nonce検査。
- INSTALL_CONTROL: signed_cbor_b64必須。typeとsender権限を検査。
- POLICY_SET: `join_mode`（CLOSED/EXTERNAL/PREAPPROVED）必須、CONFIGURE権限。rootのpolicy revisionに対するCAS（`GET /v1/policy` の `revision`）で、rootが`lm_policy_set`としてcommitしてから適用する（serial method 17、HIL-F5）。PREAPPROVEDでもfleet署名ticketと署名済みexpected entryの要件は外れない。署名付きpolicy object（type 12）はSDKが未対応で、この操作では使わない。
- LEDGER_RESTORE（issue #5）: `signed_cbor_b64`=交換rootを新rootと名指すfleet署名のRootHandover（type 31。type 31の権限＝CONFIGUREとTRANSFERの両方を要求）、`expected_revision`=復元するbackupのsequence（`GET /v1/ledger/backup`の`sequence`。Hostが保持する最新と違えば409 `details.current_revision`、保持が無ければ404）。任意の`backup_b64`は保持しているものの代わりに使うbackup（chain検証で壊れていれば400、保持より低いsequenceは409、sequenceが`expected_revision`と違えば400）で、通れば保持されるbackupになる。handoverのold_rootはbackupを作ったrootと一致し、domainのrootはそれかnew_root以外に結び付いていないこと（409）。Hostは交換root（台帳なし）へhandover→旧rootのheader→全recordを送り、rootの各段のOPERATION eventで終わる。APPLIED=rootが台帳を載せて準備完了（`ROOT_APPLIED`）。REJECTED=rootが拒否（`ROOT_REFUSED`、理由はrootのstatus名）。INDETERMINATE=途中の中断やrootが保証できない書込み失敗（台帳が無ければ同じ要求をやり直せる）。接続中のrootがdomainに結び付いたrootでない場合、Hostはこの復元が成功した場合に限りその結び付きを旧→新へ移す（それ以外は従来のROOT_MISMATCH）。
- CHANNEL_FREEZE: freeze boolean必須。committed planの取消にはならない。
- CHANNEL_RECALCULATE: root coordinatorへの再評価要求だけ。成功したと偽ってchannelを直接書かない。
不要なmode-specific fieldは400。不正署名403、古いrevision409、unknown mandatory capability503/UNSUPPORTED。error.detailsにはcurrent_revision/required_capability等だけを載せ、secretを返さない。

## Permissions
READ、SEND、APPROVE、REVOKE、TRANSFER、CONFIGURE、UPDATE_FIRMWAREをprincipalごとに保持する。groupのSEND権限は全target集合について照合。更新画像も単なるSENDだけで送れるようにしない。

## Cursor/consumer
GET events after省略は最古保持位置から返す。明示cursor不一致は410と現在journal_id。consumer ACKはmonotonic、存在するjournal+domain範囲、consumer所有者一致を検査。future ACKを拒否する。ACK応答は空events pageとacknowledged位置をnext_cursorに返す。SSEは通知でしかない。

## Operation queries/cancel
GET unknown operationは404。expired query windowは410と区別する。cancel後にもlate APP_APPLIEDを追加可能で、その履歴を削除しない。別principalのID推測で情報を返さない。epoch close/cancel/consumer ACKは単調冪等であり、同じ要求の再実行で仕事を増やさない。

## Policy JSONの署名対象
policy.schema.jsonのrevisionも10進文字列。JSONはUTF-8、key辞書順、空白なし、ensure_ascii=false、float/NaN/重複keyを禁止してcanonical bytesを作る。整数設定はschema上限内、revisionはu63にparseして検査する。policy hashはこのbytes、署名objectのouter revisionはCBOR uintとして同じ数値を表す。JSONの任意表現bytesをそのまま署名hashにしない。

## GROUP_SET
CONFIGURE権限を持つprincipalがgroup_id、members（最大64、重複禁止、同domain所属の完全DeviceId）、expected_revisionを送る。rootは期待revisionを照合してsorted集合をdurable commitし、新しいGroupSnapshotを署名する。最大8group。0人は空集合でありbroadcast全員という意味にしない。送信済みfanout operationは旧snapshotを完走し、編集で対象を増減しない。

## spec0.2 Power/Lifecycle
POWER_POLICY_SETは対象deviceと署名type29必須。CONFIGURE権限、targetのrole/capability、power.schema.jsonと20章の横断条件を検査する。COMMISSIONING_WINDOW_SETは署名type30とAPPROVE権限、ROOT_HANDOVERはfleet署名type31とCONFIGURE/TRANSFER権限を必要とする。HTTP tokenの管理権限だけでfleet署名を生成したふりをしない。
GET node/powerのmeasured_energy_jは未計測ならnull、省電力の推測値を実測にしない。GET operation/targetsは同principal/domain認可、最大16件/page、snapshot_token固定。token違い409、groupでないoperation400、保持期限外410。
Power policyの新revisionはexpected_revision+1とし、u63上限到達時は更新を拒否する。同じrequest_id・同じcanonical内容の再送は保存済み結果を返す。Power policy JSONも既存canonical rule（UTF-8/keys sorted/no whitespace/no floats）を使う。署名hashとCBOR outer revisionとJSON revisionの数値一致を検証する。sleep scheduleやpolicyは任意の業務診断payloadではなくSDK用controlとして扱う。

## GroupSnapshotV2
DeviceIdだけでなくassignment/membership世代を送信snapshotへ含める。detail APIのPARTIALは集約だけ、target outcomeはPARTIALを認めない。SUBMITTEDはBEST_EFFORTの送出、RECEIVED/APPLIEDとは別。現在outcomeの件数の和はtotal。各targetのevidence historyを件数へ二重加算しない。

## Host admissionとdispatch

`destination.kind=root_app` はこのbridgeでは未対応で、DB受理前に503/UNSUPPORTED。
UTC期限を過ぎた未送信QUEUED要求はserial接続無しでも最大64件ずつEXPIREDにし、受付枠を解放する。外部書込みの可能性がある要求はrootとのreconcile対象で、Host時計で終端到達を推定しない。root期限はUTCとして扱わない。LATESTは同principal/domain/destination/port/keyの未送信旧要求だけを同一transactionで置換し、未完了枠の正味増分で受付を判断する。保存・証拠容量不足なら旧要求を残して拒否する。

Host dispatchは永続cursorによる8枠のweighted round robin: CONTROL, URGENT, NORMAL, URGENT, URGENT, BULK, URGENT, NORMAL。空classは飛ばし、class内は既存operationsのrowidによるcommit挿入順（UTC補正や同msの乱数IDで順序を変えない）。継続負荷でも通常・BULK枠を維持する。これはclaim回数の上限であり実無線遅延秒数の保証ではない。

## Ledger backup（issue #5）
`GET /v1/ledger/backup?domain_id=`（CONFIGURE。台帳のmemberとcredentialを列挙するのでREADでは足りない）: そのdomainのrootから取って保持している最新のbackup。domainごとに1つ、sequenceの高いものだけが残り、低いsequenceが高いものを置き換えない。Hostは台帳が変わった後（membership event、rootの制御operationの終了）と、session開始時にrootへ新しいbackupを求める（変更から最短`LEANMESH_BACKUP_DEBOUNCE_S`=5秒後、前回の取得から`LEANMESH_BACKUP_MIN_INTERVAL_S`=30秒以上、いずれも1秒未満にできない。失敗は5/10/20/40/60秒の間隔で最大10回、変更が無い間は何も問い合わせない）。`sequence`はrootが署名前に永続する単調な番号で、交換rootに引き継がれる。`backup_b64`は`[1, signed header (control 34), [[record id, state, payload, next], ...]]`のCBOR。Hostはrecordがheaderのhash chainと一致することまでを確かめ、署名の検証は復元されるrootが行う。保持するbackupが無ければ404。古いfirmwareのrootがserial method 18を答えない場合、そのsessionではbackupを求めない。

