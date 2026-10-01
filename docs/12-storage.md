# 12 永続化、復旧、電源断

## 1. 保存対象
Device: identity credential、fleet trust/floors、membership committed+prepared、assignment高水位、boot incarnation、channel committed plan、policy revision、durable pendingとapplication receipts。
Root: 上記+member ledger、short address割当、group revision、失効floor、expected entries、外部approval決定。topology/traffic sessionは基本RAM。
Host: `db/schema.sql`。操作/冪等性/event/inbox/outbox/consumerを保存。アプリ固有の安全DBは作らない。

## 2. 2slot record
record = magic4 + schema2 + state1 + reserved1 + generation8 + payload_length4 + SHA256(payload)32 + payload + CRC32。
秘密payloadはNVS encryptionまたは固定portのauthenticated sealingで保護。CRC/hashだけで悪意ある改ざんを検出できると説明しない。IDF portは`CONFIG_NVS_ENCRYPTION`のとき`identity`/`state`を登録済みNVS security schemeの鍵で暗号化mountし、鍵が無ければ失敗する（平文mountへ落ちない）。鍵の生成（eFuse/`nvs_keys`への書込み）はprovisioning側の鍵custodyでありSDKは行わない。暗号化なしのbuildは開発用の明示承認（`CONFIG_LEANMESH_ALLOW_PLAINTEXT_SECRETS`）なしにcompileしない（FIX8-D7）。
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
root ledgerを失ったら空member網として同じdomainキーで再起動しない。ledgerはdomainに結び付いたmanifest（domain、一度でも使ったslot、expected setの進捗）を持ち、manifestが無い・別domain・使用済みslotの記録が無い場合はRECOVERY_REQUIREDで入会・session受理を止める。空ledgerを作るのは新規networkのprovisioningだけ。fleet署名recovery objectでroot delegation/authorization世代を更新する。失効情報の完全な復旧ができなければ既存資格の再検証を要求。offline性能と失効の即時性には限界がある。既存認可lease15分を過ぎた通信は期限切れ理由を返し、root不在なのに恒久的な認可更新を合成しない。

## 6. 実記憶容量と物理限界
NVS内部のcopy、page overhead、書込み増幅、GC、brownout挙動はIDF実装に依存する。論理record計算だけでFlash enduranceを保証しない。erase回数/byte量/最大commit latencyをHILで測る。tamper resistant monotonic counterなしの全Flash巻戻しを、2slotだけで防げるとは主張しない。

## Flash書込みと中継の実時間
Flash I/Oをworkerへ移しても、SoC/IDFのflash-cache停止や割込み制約が無線処理へ影響しないとは限らない。IRAM配置、watchdog、最長NVS commit、erase時間とTX callbackの遅延を全4SoCで測る。dirty recordを必要時だけまとめてcommitするが、DURABLE成功をcommit前に返さない。lifecycle/safety receiptの保存と高頻度telemetryを同じ無制限logへ入れない。SDK外のFlash writerとの調停もアプリ統合条件として明記する。

## lifecycle record（S18）とprovisioning
追加record: `root_handover`（17、自rootを退役させたRootHandoverそのもの。存在すれば起動後も入会/session受理をしない。検証済みobjectが自rootを旧rootと名指した時点でRAMは退役し、commit失敗（read-back失敗を含む）でも戻さない。失敗後はrecordを読み直し、あればAPPLIED、無ければRECOVERY_REQUIRED）、`pending_delegation`（18、transfer/handover先のRootDelegation。新MemberCredentialのcommit後にroot_delegationへ移す。二つのcommitの間の電源断は、membershipを検証できるpending側で起動し書き直す）、`commissioning_window`（19、version u8(1) + policy_revision u64 + window_id16 + expected_set_revision u64 + max_new_members u8 + allowed_roles u8 + そのwindowで予約した数u8。予約entryのcommit前に数える。電源断は数え過ぎにしかならない。policy_revisionはwindowのreplay floor：低いrevisionのwindow、同じrevisionの別window（id/予算が違う）はCONFLICT、同じwindowの再投入（term変更時の再発行を含む）は数を継続。読めない/旧形式のrecordは「windowなし」とせずRECOVERY_REQUIRED）。membership recordのstate 5はrevocation通知による離脱tombstone（LEFTと同じfloor、状態はMEMBER_REVOKED）。
ledgerに載るDeviceのfloorはそのentry自身（`consumed`以下のticket、`membership`以下のmembershipは失効）であり、失効・移設の反映はentry 1回のcommitで表の空きを要さない。`revocation_floors`表（rootでは最大10件）はledgerに無いDeviceのfloorと、離脱entryの写し（そのslotを他Deviceへ再利用できる条件。写しは冗長で、ledgerに無いDeviceのfloorに場所を譲る）を持つ（FIX8-D1）。rootの`policy`（8: version u8 | join_mode u8 | 確定変更数 u64。読めなければCLOSEDで`lm_policy_set`はRECOVERY_REQUIRED、FIX8-D12）と`root_groups`（20: version u8 | n u8 | n×(group id u32 | revision u64 | count u8 | ledger slot×count)。setはこのcommit後に適用・報告。groupが名指すslotは再利用しない。読めなければgroup操作はRECOVERY_REQUIRED、FIX8-D9/D10）。
provisioningが書くrecord: 全Device＝boot_incarnation（最初）、identity、fleet_trust、root_delegation、必要ならmembership（ACTIVE credential）、revocation_floors、discovery_scope。新規networkのrootだけが空ledgerのmanifest（root_ledger: domain、used slot、expected進捗）を書き、既存memberの一覧はそのentryとして同じ手順で書く。交換用rootは自分のdelegation（上位generation）とcredential（上位term）だけを持ち、ledgerは検証済みbackupから復元する。backupが無いrootはRECOVERY_REQUIREDで止まり、空ledgerで再開しない。rootの自credentialのleaseは自rootが時刻基準なので遠い将来でよい（rootは自身のleaseで他者を認可しない）。
rootのroot_termはmembership recordの自credentialが正本（ARCH2-D1）：boot毎にidentity load jobがterm+1で自署名し直してcommitし、その後にだけidentityがReadyになる（commit前の電源断は旧recordのまま次bootがその一つ上、commit後は新termが床。同じtermを二度公開しない）。保存値は最後に公開したtermで、新規networkのrootは0、交換用rootは最初に公開するtermの一つ下でprovisionする。u32上限ではRECOVERY_REQUIRED。

power policy/scheduleは既存sealed recordのtyped objectとして保存し、別の汎用設定DBをNodeへ足さない。毎poll/packetでNVS書込みを行わない。group DURABLEはpayload1copy・immutable snapshot・target ID割当・進捗を一つの有界operation journalにまとめる。mid-commit sleep禁止。
Host既存DBへの導入はadditive schema migrationで`node_power/group_targets`を追加し、旧consumerを止めずphaseごとに有効化する。本ZIPのschema.sqlを既存製品DBへそのまま再実行しない。

非rootの `policy` record (8) はversion 2: `version u8 | revision u64 | enabled u8 | isolation_ms u32`（14 B、big endian）。rootのversion 1とはroleで区別し、読み違い・不正値・commit失敗は自動移設を停止してRECOVERY_REQUIREDを報告する。隔離の計時はRAMのみで、毎packetのFlash書込みはしない。
