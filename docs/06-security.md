# 06 Security profile LM1

## 1. 攻撃モデルと限界
外部の盗聴、偽造、再送、偽beacon、複製QR、他domainからの命令、古いgrant、relay侵害を考える。終端間の本文秘密と本人性を守り、relayへ端末間のend keyを渡さない。侵害relayのpacket破棄、RF妨害、物理侵襲による鍵抽出、flash全体rollbackの完全防止は本通信仕様だけでは保証しない。製品のSecure Boot/Flash Encryption/鍵custodyは独立gate。

## 2. 1つのハンドシェイク
EDHOC RFC9528、method0（両側signature）、suite3（P-256/ES256/SHA-256、EDHOC内AES-CCM）。message_4を必須とし、完全なmessage消費・unknown critical EAD拒否・秘密消去を検査する。RFC9529の該当traceと独立実装との相互試験を必須にする。[E04,E05]
候補実装はlibedhoc v2.3.2、commit `c8857b62d66be3664d1694bbe4eea37c56c05d9e`。既存RouteLoomのvendored台帳には末尾余剰byte拒否等のpatchがある。**そのままupstreamへ戻して既知の厳密decode検査を失わない**。採用subset/patch/hash/licenseをDependency Gateで固定する。micro-ecc等の別ECC実装を追加せず、IDF crypto backendに統一。Hostは同じC EDHOC engineへの薄いnative bindingを使い、PythonでEDHOCを再実装しない。

EDHOC自体の相互運用と、後述するLM独自record layerの安全性は別に審査する。LMはOSCORE/RPL/RouteLoom Wire互換を主張しない。

## 3. 鍵・Identity
DeviceId = SHA-256(deterministic CBOR COSE_Key)。COSE_KeyはEC2/kty2、crv1、x32、y32だけを含む規定表現。公開鍵の別表現で同じ個体に別IDを作らない。
FleetId128、DomainId128、DeviceId256、RootDeviceId256を短縮せず認可する。無線domain_hint32やshort_address16はlookup hintでありIdentityではない。
DeviceCredentialはfleet issuer署名COSE_Sign1。RootDelegationもfleet署名でdomain、root device、権限、delegation_generationを固定する。rootはこの範囲だけMemberCredentialを発行できる。chainはfleet→root→memberの最大2署名。任意長X.509 chainは持たない。[protocol/control.cddl]

## 4. EDHOCとの結合
ID_CREDはkid=DeviceId全32B。CREDは対応するCCSの決定的CBOR。CCSのcnf内COSE_KeyとDeviceCredentialの公開鍵hashが一致することを署名と併せて検証する。unknown kidはbounded credential転送で解決し、自己申告keyだけで受理しない。
LM session contextはdeterministic CBOR配列 `["LM1", purpose, fleet_id, domain_id, initiator_device_id, responder_device_id, assignment_generation_i, assignment_generation_r, membership_generation_i, membership_generation_r, credential_hash_i, credential_hash_r]`。purpose=1 neighbor link、2 end、3 USB。bootstrap joinでは未割当membership_generation=0で、権限はJOIN_ONLY。正規DATAへ流用不可。
session context全体のSHA-256をctx_hashとする。異なるpurpose/domain/generationで同じsession鍵を使わない。

## 5. record key導出（固定契約）
本SDKのrecordはAES-128-GCM/tag16を使う。これはsuite3が既定で指定するapplication AEAD/OSCOREを流用するのではなく、**LM1専用のprivate-use Exporter用途**である。独立レビュー完了まで実験ラベルを外さない。
`seed = EDHOC_Exporter(label=40000, context=ctx_hash, length=32)`。
`PRK = HKDF-Extract(salt=ctx_hash, IKM=seed)`。
送信方向をinitiator→responder=0、逆=1とし、`info = "LM1-RECORD" || purpose_u8 || direction_u8 || ctx_hash`、HKDF-Expand(PRK,info,20)の先頭16B=key、後4B=nonce_prefix。nonce=prefix4 || uint64BE(counter)。link/end/USBは別EDHOC contextの鍵。counter0は予約、1から開始、wrapしない。
SIDは受信側が割り当てる非zero uint32ローカルhandle。MAC+domain+purpose+peer_generationとの完全な対応でlookupし、衝突時再割当。SIDだけで認可しない。

## 6. replayと再起動
各受信sessionに64packet sliding window。AEAD成功と宛先/長さ検査前にwindowを消費しない。正常重複DATAにはdedup状態に基づくreceiptを返せるがアプリ再適用はしない。許容窓外の古いpacketはREPLAY。
cold bootでtraffic keyとreplay窓を復元しない。既存membershipは維持しfresh EDHOCを実行する。**既存所属への復帰と初回Join承認は別**。これで毎packetのNVS replay書込みをなくす。light sleepでRAM維持したsessionは継続可。deep sleepでsession喪失したら新handshake。RTC resumeの独自ticket protocolはspec0.2でも追加しない。詳細な有効性判定と電力認定は20章§7に従う。
同一ciphertextのlink retryは同じcounter/byte列を再送できる。内容/path変更して再封止する場合はfresh counter。終端ciphertextはpath修復で変えず、end sessionが変わった場合は同じMessageIdでfresh end recordを作る。

## 7. revocation・rotation
rootは対象のmembership_generationを失効floorへ加算し、接続中peerのsessionを閉じ、署名RevokeObjectを配送する。相手への消去通知が未達でも残存網側の拒否を進める。Device自身の鍵消去確認と網側拒否の確認を別に返す。
新sessionには新しいMemberCredentialとrootからの失効snapshotが必要。既存sessionの認可leaseは最大15分、更新はjitter付き10分。sessionは相手MemberCredentialのlease（root時刻）を保持し、その期限までに終わる。root時刻が不明で証明できないまま張ったsessionはSDK制御（時刻同期・経路登録・handshake）だけを運び、アプリDATAは送受しない。時刻推定が更新されるたびに全sessionを再判定し、期限切れが証明されたsessionは閉じる。通信断中の旧credentialをいつまで許すかはこの有限leaseで表し、無期限の失効保証を言わない。
root鍵変更はfleet署名delegationの高世代を配布→stored証拠→切替。旧delegationの新Join発行は切替後拒否。必要な旧record受信猶予は最大60秒で延長しない。通常traffic keyは1時間または2^24packetの先到でfresh EDHOC。group共有暗号鍵は導入しない。

## 8. DoSと秘密
Join proxy slots2、同時P-256 jobs1、1相手full-handshake最短30秒（完了したhandshakeの間隔）。1-hop（link・join）で開始した（message_1でgateを使った）handshakeが失敗した場合だけ、次の試行は5秒、続けて失敗すれば10、20秒…と倍にし30秒で頭打ち、完了で元に戻す（HIL 2026-10-04 F10：再起動したnodeの最初の試行は親が旧sessionを持つため失敗しやすく、失敗でも30秒待たせると再接続に40〜110秒かかった）。1相手あたり最悪でも5秒に1回の公開鍵処理で、同時P-256 jobs1の上限は変わらない。end sessionは経路が整うまで失敗しやすく、早い再試行は1つしかないexchange slotを塞ぐので、従来どおり30秒。root全体4handshakes/秒をadmission上限目標とするが実機の演算完了能力でさらに制限。cookie/期待hintでCPU予算を予約してから高価な演算へ進む。RF jamは解決できない。
ESP32 entropyは公式条件でseedする。Wi-Fi稼働前に適当に乱数を作らない。[E06] テストseedはtest専用targetでのみ受け付け、本番binaryの起動で拒否。key、grant秘密、payload、Wi-Fi秘密を標準ログに出さない。NVS eraseは論理的失効であり、Flash上の全過去copyの物理消去保証ではない。

## 9. Context bindingの正確な順序
RFC9528のEAD labelにprivate-use範囲はない。未登録の独自EAD番号を使わない。送信するEADはpadding label0だけ（通常は省略）。未知critical EADは標準どおり中止する。Exporter label40000は§10.1のprivate-use範囲内であり、EAD番号とは別物である。

EDHOC m1〜m4の認証が完了した後、検証済みcredential・候補domain・purposeから両側が§4のcontextを構成し、§5でtraffic鍵を導出する。最初の保護recordを`SESSION_BIND=[1,ctx_hash,receiver_sid,bind_nonce16]`、応答を`SESSION_BIND_ACK=[1,ctx_hash,receiver_sid,bind_nonce16]`とする。SIDは各側が自分の受信用に予約する。両側のfullIdentity、domain、権限、世代、context hash一致とnonce echoが完了するまで通常DATAを許可しない。異なるcontextは同じ鍵にならず、AEADまたはcontext照合で失敗する。失敗後は候補session/keyを消す。

bootstrap credential取得と候補contextの交換は認証前にはhintにすぎない。credential単体1024B、同時2件、全長/個数/issuer制限を先に確認し、fleet署名を検証する。`JOIN_ONLY` sessionはmembership発行操作にしか使えず、入会後は正規member credentialに結び付いたfresh sessionを作る。session binding recordには共通secretやnetwork group PSKを使わない。

`SESSION_BIND`/ACKはEDHOC carrier内の認証後段階に置き、DATA用sessionの有効化前にも受信できる専用stateを使う。再送は同一ciphertext、IDとnonceを保持し、最大3回/期限30秒。30秒は鍵導出後のbinding段階に適用する。routed endのcredential転送を含む全体期限は開始時に固定し、観測service時間Sが120msを超えるときだけ30秒 + 4*S*h*(2*ceil(1024/C)+6)（h=hop数、C=data_capacity(h)からJoinChunk headerを引いた容量）とする。Sはwatchdog以下の直近完了の実測最大値（docs/08 §6の窓）でUNKNOWNは除外し、fragment到着で全体期限を延長しない。未観測時と1-hop交換は30秒。同時slot/公開鍵job/gateとbinding認証は変更しない。これは鍵交換方式の追加ではなくLM record contextの明示確認であり、独立セキュリティレビュー対象に含める。

## 10. Powerとの横断契約
RAM session再利用はtraffic keyだけでなく送信counter・受信window・完全peer identity・credential世代・authorization/key lifetimeの経過上限が保持できる時だけ。Light Sleepしただけでcounter=0に戻さない。相手のrestartはそのsessionを無効化し、全網Joinへ拡大しない。Deep Sleep復帰に新規人間承認を要求しないが、fresh EDHOCの演算/airtimeは発生する。停電復帰を「認証CPU負荷ゼロ」と呼ばない。
Root/Host停止中の通信継続は既存path/session/有限authorization leaseが有効な範囲であり、無期限ではない。lease終了後は暗号上の認可を維持できない操作を保留し、アプリへ理由を返す。

## 11. 台帳backup（issue #5）の信頼
rootの台帳backup（control type 34）は、**現rootがdevice keyで署名する1つのheader**で成り立つ。headerはdomain、rootのDeviceId、rootのfleet署名RootDelegation（公開鍵への連鎖）、delegation世代、署名時のroot_term、単調なbackup sequence、台帳のchange point、recordの存在と内容のhash chain先頭を固定する。復元先（交換root）は、fleet trust anchor → headerの中の旧RootDelegation → 旧rootの署名と検証し、domain・handoverの旧root・旧generationの一致を要求する。recordはheaderのhash chainで1件ずつ書く前に検証する（署名は1つ、recordごとの署名はしない）。署名はrootのpublic-key worker jobで行い、ownerでは行わない。
- backupに秘密は無い。entryはDeviceId・世代・request id・hash・rootが発行したMemberCredential COSE（公開情報）、floors/groups/policyは数値とid。root秘密鍵、identity、session鍵は入らない。ただしmemberのリストと資格は載るので、Hostの取得APIにはCONFIGURE権限を要求する。
- backupはrootの権限を移さない。交換rootが台帳を受けるには、fleet署名のRootHandoverがそのrootを新rootと名指すこと（旧rootの鍵は使わず、新DeviceIdとdelegationを持つ）が必須で、旧rootの署名だけでは受理されない。古いbackupによる巻き戻し（失効・離脱の取消）は、交換rootが自分の知るsequence以上を要求して拒否し、Hostも最新sequenceだけを保持する。限界：backup後の変更は含まれない。

