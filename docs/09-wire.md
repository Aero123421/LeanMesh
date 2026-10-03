# 09 LM1 Wire contract

## 1. 原則
全整数はnetwork byte order（big-endian）、CBORはRFC8949 §4.2.1のcore deterministic encoding（encoded map keyのbytewise lexicographic順）、重複map key/未知必須field/末尾余剰/不正UTF-8を拒否。C structをwireへmemcpyしない。`protocol/registry.json`がoffsetと番号の正本。本versionはproposalとして固定した新WireでありRouteLoom v2とは無関係。

## 2. RF link envelope（24B）
|offset|size|field|
|---:|---:|---|
|0|2|magic ASCII LM|
|2|1|version=1|
|3|1|kind（registry）|
|4|4|domain_hint（DomainIdの先頭4B、認可には使わない）|
|8|4|link_sid（受信側発行、bootstrapは0）|
|12|8|link_counter|
|20|2|body_length（ciphertextと同じ長さ、tagを含まない）|
|22|1|flags、bit0=encrypted、他0|
|23|1|reserved=0|

Encrypted frame=`prefix24 || AESGCM(link_key,nonce,plain_body,AAD=prefix24||ctx_hash32) || tag16`。全長250B以下。通常DATA/ACK/ROUTE/CONTROLのencryptedは必須。SID0のbootstrap/discoveryは1hop budgetつき非認証hintまたはEDHOC objectでありDATAへ渡さない。

## 3. routed body
Link平文は`route_header16 || path[2*N] || end_record`。
route_headerのoffset: origin_short0:u16、final_short2:u16、path_len4:u8、next_index5:u8、remaining_budget6:u8、reserved7:u8=0、root_term8:u32、path_revision12:u32。
path_len=1〜40、pathはoriginの次からfinalまで、各u16。self index/前送信者を04に従い確認。最大hopの変更はroot_depth20を暗黙変更しない。

## 4. end record
固定header42B:
- 0:end_sid u32
- 4:end_counter u64
- 12:message_id bstr16（incarnation64/sequence64）
- 28:app_port u16（0=SDK control、1〜65534=app、65535予約）
- 30:record_kind u8（DATA1 / RECEIPT2 / FRAGMENT3 / CONTROL4 / TRANSFER_BITMAP5）
- 31:flags u8（bits0..1 delivery:0 best,1 received,2 applied; bits2..3 priority:0 bulk,1 normal,2 urgent,3 control; bit4 durable; bits5..7=0）
- 32:expires_root_ms u64（0=許可された期限なし）
- 40:plaintext_length u16

E2E AAD=`"LM1-END" || ctx_hash32 || uint32BE(root_term) || end_header42`。
E2E record=`header42 || AESGCM(end_key,nonce,payload,AAD) || tag16`。
ctx_hashは両DeviceId/domain/assignment/membership/purposeを完全幅で結合。終端ではrouteのorigin/finalが現在のsessionの完全Identityに対応することも検査する。path/index/link counterは終端AADに入れないので正当な中継で再封止不要。root_term変更時のdeadlineは08の不明扱い。

## 5. payload会計（固定）
1frameのdata容量 = `250 -24 -16(link tag) -16(route) -2*N -42(end) -16(end tag) = 136 - 2*N`。
1hop=134B、20hop=96B、40hop=56B。**「16Bheaderだから約200B送れる」とはしない**。20hopの96B上限は新仕様独自の会計で、旧RouteLoomのgateway96Bと同じ構造ではない。
通常128B要求もAPIは受け、必要なら同じfragment engineで2frame以上へ分割。元payloadを黙って切り詰めない。strict single_frameを指定した場合だけPAYLOAD_TOO_LARGEで返す。

## 6. small/object fragmentation（非再帰）
FRAGMENT payloadは固定40B prefixとbytes。prefix = total_len u16、offset u16、fragment_len u16、original_record_kind u8（DATA1/RECEIPT2/CONTROL4だけ）、object_class u8（small0/object1/control2）、intent_hash32。続くbytes長=fragment_len。original_kind=FRAGMENTは禁止。**別STARTを先に分割する再帰構造を作らない**。最初の認証済みfragmentが長さ・意味・hash・キューを予約する。大きいslotを予約できないときBUSYで拒否する。

最小quantumは16B。offsetは16の倍数、最終以外のfragment_lenも16の倍数、送信chunkは経路MTU内で最大の16B倍数を選ぶ。1hopは最大80B、20hopは48B、40hopは16B/chunk。最後だけ端数可。route変更時にはchunkを再分割できるが、同じoffsetの既存byteと異なる場合はCONFLICT。異なる切り方で同じbyteなら重複として扱う。受信bitmapは16B単位の256bit（4096/16）、windowは未確認4frame。bitmap応答を先に予約する。

bitmap応答は**専用record_kind=5**、本文35B = base_offset u16（0）、bitmap32、credit u8。対象MessageIdはend header、origin/assignmentはsessionで照合するため本文に重複しない。最大40hopの56B内に収まり、bitmapの分割やbitmapへのbitmapを要求しない。bitmapはbyte順昇順、各byte bit0からoffset0,16,...の順。正常重複には同じbitmapを返し、異hashの同IDにACKを使い回さない。

通常total<=512、optional object<=4096、認証済み内部ControlObject<=4096。未認証bootstrapは1024Bの別上限。専用control slotとapp object slotを分離し、object機能OFFでもJoin/設定の制御転送は残す。groupは16entry/page、expectedは8entry/page、1ページ1024B以下を目安。policy JSONは3072B以下、COSE封筒込み4096B以下。

再組立のkeyは(full origin, assignment generation, MessageId, intent_hash)。最初のport/flags/root_term/expiry/class/totalと一致しないfragmentは拒否する。全体完成後に08のhashを原kindに応じて検証し、一度だけdispatchする。DATAはアプリへ、RECEIPTはreceipt処理へ、CONTROLは制御処理へ渡す。fragment化したRECEIPTにさらにEND_RECEIPTを作らない。CONTROLは定義された対応control応答を用いる。制御/receiptのintent_hashはSHA-256(deterministic CBOR [origin DeviceId,target DeviceId,domain,app_port,original_record_kind,flags,effective_root_term,expires_root_ms,complete_payload])。effective_root_termは08と同じ正規化。DATAは08の規則を使う。

reassembly timeoutは通常30秒、object/control120秒、元の有限application deadlineを越えない。metadata/全bytes/結果通知を先に予約する。slotの期限は途中fragmentやretryで延長しない。boot後volatile transferは破棄しfresh sessionで再送、durable message ID/hashは保持。bulkはurgent/controlより低優先。大きいpathのfragment効率を単一frameのpayload容量と混同しない。

## 7. HOP_ACK
kind=2、route/end envelopeなし。link平文12B: acked_link_counter u64、status u8（ACCEPTED0 / BUSY1 / REJECTED2）、credit u8、retry_after_ms u16。全長52B。ACK自身にACKしない。
AEAD replayの正常重複DATAについては元queue予約の証拠がある間だけ同じACKを返す。ACKを送るためのslotをDATA受理時に予約する。

## 8. bootstrap carrierとControlObject
bootstrapは1hopで`exchange_id16, object_kind u8, total u16, offset u16, length u16, body<=160`を運ぶ。max total1024、peer2・global4 slots、cookie/DoS budgetあり。認証前に4KiB allocationしない。proxyはend handshake bytesを通常member routeでrootへ運び、inner EDHOCを改変しない。
ControlObjectはprotocol/control.cddl。すべてに公開鍵署名するのではなく、19の永続objectだけ署名、日常controlはsession AEADとissuer権限で保護する。署名する場合のCOSE_Sign1はtag18、protectedにalg=-7とkid32、unprotected空map、payload bstr(deterministic CBOR)、signature64B r||s。External AADはASCII `LM1-CONTROL`。ネットワーク本文typeによる意味の兼用禁止。credential、grant、route request、channel plan、clock、receiptは別type番号。

## 9. Serial
COBS + delimiter0。decoded header: magic2=`LS`, version1, kind1, session_id4, counter8, payload_len2（18B）。payload<=8192、CRC32/ISO-HDLC4、認証後はpayloadをUSB record keyでAEAD16封止。CRCはciphertext/tagを含むprefix全体の末尾、暗号の代わりではない。
HandshakeはHELLO(version/device/boot/caps)→EDHOC USB purpose→ACTIVE。ACTIVE前にsend/config/join decisionは拒否。USB keyはfactory common secretではなくpairごとのkey。session変更時の操作結果はMessageIdで照会、古いcounter/tokenを新sessionへ割当てない。
creditはrecord数とbyte数の二重上限。Hostcommit受信ACKとSerial write完了は別。parserはdecoded最大8230Bで切り、overflow時は次delimiterまで捨てる。EOF/CRCエラーからbounded resync。

## spec0.2追加: PowerとGroupSnapshot
固定link/route/endヘッダーとDATA暗号goldenは変更しない。frame kind8 POWERは認証済み直結link専用で、28B poll/24B grantをlink AEADで保護する。最大frameは68B/64B。protocol/power.cddlとregistryのstruct_formatsを参照。unknown frame kind/capabilityは明示拒否する。
Control28 SleepSchedule、29 PowerPolicy、30 CommissioningWindow、31 RootHandover、32 GroupSnapshotV2を追加（その後、33 GroupSnapshotRequest、34 LedgerBackup＝rootが署名する台帳backupのheader、19章§9。34はserial 18〜22だけで運び、`lm_install_control`はUNSUPPORTED）。type22は旧GroupSnapshot予約となり、新規送信は行わない。version1 envelopeのままでも未対応typeを解釈したふりはしない。

## relay DRAIN compact end-control

node↔rootの認証済みend session CONTROL内に以下のbig endian固定長recordを使用する。ControlObjectのtype IDではない。sequenceは非0、termは現root term、remaining_msは0..30000、cancelは0/1。余剰bytesと範囲外値は拒否する。

|opcode|layout (opcodeを含む)|方向|
|---|---|---|
|0xEF DrainRequest|u8 opcode, u32 sequence, u32 remaining_ms, u8 cancel (10 B)|relay→root|
|0xF0 DrainStatus|u8 opcode, u32 sequence, u32 term, u8 status, u8 cancel (11 B)|root→relay|
|0xF1 DrainNotice|u8 opcode, u32 term, u16 relay (7 B)|root→子|

取消ACKはcancel=1でgrantと区別する。rootは完全Identity/assignment/membership世代を認証済みsessionとledgerで照合してから処理し、beaconは退避の証拠にしない。
