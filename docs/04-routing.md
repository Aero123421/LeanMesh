# 04 Routing — root-managed simple paths

## 1. 選んだ方式
隣接の自己発見と親候補は分散、確定経路登録はroot、DATAは明示した**重複ノードのないsource route**で送る。全宛先広告やBabel/RPLの完全実装は採用しない。RPLの概念は参考だがWire互換を名乗らない。

`root_depth`はrootからの無線辺の数で0〜20。端末間はrootが保持する木の最小共通祖先でpathを接合し、0〜40辺。往復はその2倍の辺を通る。pathには送信元を含めず、次の受信先から最終宛先までのshort address列を入れる。path_len=hop数、最大40。root深度20を2つ組み合わせた通信を20hopと表示しない。

## 2. ノード保持情報
自分のDeviceId/short address、rootへのpath（最大20 entries）、path_revision、root_term、親1、予備候補2、近隣16以下、neighborごとのMAC/session/role/品質を保持。アプリ宛先のpath cacheはleaf4/relay4/root全members。全網topologyはrootだけ。経路cacheのentryがなければrootへROUTE_QUERYする。

## 3. 発見・登録の縦経路
1. 未所属機は07のJoin、所属済み機は同じdomainをlistenする。
2. 同じdomainでrelay_allowedかつALWAYS_RXの近隣を候補とする。HMAC付きhintを本物のmember/双方向可用性と混同しない。
3. 近隣認証sessionを確立し、PROBE/PROBE_REPLYで双方向到達と可用creditを確認する。
4. 候補のroot pathへ自分をappendした案を検査。自分や重複addressを含むpath、深度21、別root_term、期限切れは拒否。
5. ROUTE_REGISTERを候補の既知root pathの逆順で送る。rootは親子の直結確認、各addressの所属generation、自己への単純経路、既存topologyの循環を確認する。
6. rootはpath_revisionを増やし、ACKに有効leaseとcanonical pathを返す。自Nodeが適用してROUTE_READYを返すまではroot側pending。ACKを失った場合は同じrequest_idで照会する。
7. 登録済みpathを使った終端往復が成功するとReachable。単に近隣が1台見えるだけならDegraded。

候補1件への取り付けは有界にする。手順3〜6のどの段で失敗しても、失敗は段をまたいで数え、上限（rootとの終端session確立は3回）に達したらその候補を一定時間避けて次の候補へ進む。近隣sessionとPROBEが通ることは、その候補経由で登録できる証拠ではない（短いframeだけが通るlinkがある）。段を移るたびに数え直して同じ候補に留まり続けてはならない（2026-10-10現場: rootの電波が弱く届く階で、近くのrelayを一度も試さなかった）。
手順3の近隣session確立は、始めたhandshakeの終わり（成立・失敗）を受けてすぐ次へ進む。固定の待ち（handshakeの期限30秒）は終わりの知らせが来ないときの上限にだけ使う。失敗したhandshakeが2回になったら、その候補を避けて次の候補へ進む。自分のexchange slotが埋まっている、相手ごとのhandshake間隔（docs/06 §8）を待つ、frameが足りないといった自分側の待ちは候補の失敗に数えない（自分側の待ちが60秒続いたら、候補を責めずに選び直す）。自分側の不足で終わったhandshake（worker、frame pool、radio）も数えない。探索1回のhandshake予算（docs/07 §3: 30秒・2候補）を使い切ったときも候補の失敗に数えず、次の探索で選び直す（失敗に数えると、その候補が避けられている間に次の探索の予算も尽き、500秒の切断のあとlinkが戻っても付け直せなかった、sim）。2026-10-12現場: 親の電源が切れた板で、handshakeの終わりが経路側に伝わらず、失敗のたびに残りの待ち（送信が遅いときは30秒）を空費し、自分側の待ちまで失敗に数えていた。付け直しに162秒かかり、その間にhandshakeは5回失敗した。

候補が同時に互いを親に選んでも、rootが1件ずつ検証することで承認木にcycleを入れない。**`parent.rank < self.rank`だけでは古い広告がある非同期系のloop-free証明にならない**。rankは候補優先度であり安全証拠ではない。

## 4. 各hopの転送条件
- Link AEADとsession/domain/peer generationが有効。
- next_index < path_len、path[next_index] == self。
- previous senderがorigin（index0）またはpath[index-1]に一致。
- path中の全addressは非zero、送信元を含まず重複なし。最終entry == final。
- total_budget > 0、実転送ごとにnext_indexを+1、budgetを-1。変更後hop envelopeを次link鍵で封止。
- next peerが未確立なら無限探索せずROUTE_STALEを終端へ返すか有界repair待ち。

誤ったpathや古いpathはDROP/REPAIRであって通常DATA floodにしない。honest nodeがこの条件を守る限り、1packetが同じnodeへ再転送されない。侵害relayによる破棄・遅延・route改変DoSまで防ぐ保証ではない。E2E本文と宛先の本人性は別に守る。

## 5. 修復
送信中の3回の対象RF失敗で親をSUSPECT。対象RF失敗はMAC ACKが返らなかった試行だけで、MAC ACKは返ったがHOP_ACKが返らなかった試行は数えない（相手の無線は生きていて、別frameの送信で応答が遅れたか、sessionを失っている。PROBEを早めてどちらかを判定する）。pending DATAがあるときは5秒の無応答を追加の修復条件にする。idle時は安定helloが32秒になるため、5秒の無受信だけで断とせず、広告されたhello上限の3倍（既定最大96秒）を不在判定にする。送信が生じれば必要時PROBEを直ちに行う。Sleep予定、BUSY、探索休止は数えない。予備候補へのPROBE→REGISTERを行う。親候補は必要改善20%・最小維持30秒。ただしdead linkからの切替は維持時間を待たない。
READYのnodeは、聞こえている予備候補（最大2）とlink sessionを先に張っておく（修復時にhandshakeを省くため）。張れなかった予備候補への次の試行は30秒後、続けて張れなければ60、120、240秒…と倍にし480秒で頭打ち、張れたら元に戻す。自分側の不足（worker、frame pool、radio）で終わった試行は数えない。beaconは聞こえるがhandshakeの通らない相手（遠い・一方向）に30秒ごとに試し続けると、1つしかないexchange slotの約3割がその試行で塞がる（sim: 10分で試行18回・270 frame、すべてMAC ACKなし）。親を失ったときのattachはこの待ちに関係なくその候補を試す。
rootは子孫のpathを更新する。子孫へ新版が届くまで旧pathは期限付きで残し、下りでstaleが出たら送信元だけが再解決する。relayが無断で次hopを取り替えない。再送は同じMessageId/intent hash、fresh packet counter。rootがいない場合は既存有効path通信を続け、未登録の新木を成立済みとして広告しない。

## 6. control量と親score
qualityは対象RF失敗に基づくEWMA（alpha=1/8）、queue遅延EWMA、auth-session安定性を使う。初期score=256*depth + 256*(ETX-1) + min(queue_ms,500) + instability_penalty。RSSIは候補を落とす粗い補助で、単独選択基準にしない。実装: 最後に聞いたframeのRSSIが`routing.weak_link_rssi_below_neg_dbm`（既定80、−80 dBm未満）で、かつ今選べる候補（直近96秒に聞こえていて、回避中でない候補）の最良より`routing.weak_link_margin_db`（既定6 dB）を超えて低い候補を「弱い候補」とする。絶対値だけにしないのは、全linkが−80 dBm未満の建物でも使えるlink（−84）とかすかなlink（−91）を分けるためで、1件しか聞こえない候補は弱い候補にならない。(1) 探索では弱くない候補を先に試し、弱い候補は弱くない候補が1件も選べないときだけ試す。初めて聞いた候補が弱いときはlistenを打ち切らず、ほかの候補を聞く時間を残す。試行中の候補がまだ近隣sessionを持たないうちに弱い候補になったら（より良い候補が聞こえた）、その試行をやめて選び直す。やめるときは始めていたhandshakeも止め、1つしかないexchange slotを空ける（空けないと、良い候補へのhandshakeがBusyのまま9回で失敗に数えられる）。聞こえた良い候補が回避中（avoid）なら、やめない。最初に聞こえたbeaconの順で親が決まらないようにする。(2) 弱い候補への自発的な付け替えは、現在の親がその候補よりさらに弱く聞こえるときだけ行う（depthが浅くても、それ以外では移らない）。「親が弱い候補なら移ってよい」としていた間は、いなくなった強い候補の古いRSSIが表に残るだけで使える親（−84）まで弱い扱いになり、かすかなroot（−91）へ移れてしまった（レビュー2026-10-12、simで再現）。弱い候補しかなければ従来どおり使い、scoreの式は変えない。RSSIを報告しないmediumでは全候補が弱くない扱いになる。−80は2026-10-10現場（−75〜−79 dBmで損失なし、−84〜−92 dBmで切断と付け替えの往復、−53 dBmのrelayから2秒で−89 dBmのroot直結へ移動）からの初期値で、測定で変える場合は比較結果を残す。弱い親から深い強い候補へ移す条件（scoreの式の変更）はこの版に入れていない。
近隣helloは変化時+Trickle風2〜32秒（安定期最大32秒、検証済みdataをlivenessへ利用）、root lease更新は60秒・有効180秒・jitter10%。緊急packetをhello待ちにしない。64台20hopでのcontrol airtimeを必ず測り、低頻度payloadよりcontrolが支配するprofileを認定しない。

## 7. 異常ケース
address再利用はmembership_generationが変わり、関連link/end sessionとpath cacheを無効化する。root_termはroot bootごとに永続増加。旧termの未確定登録は破棄、新termでsession/pathを再同期。term/generationはwrap前に停止し管理復旧を要求する。rebootで0に戻さない。
実装（ARCH2-D1）: rootのtermは自MemberCredentialのroot_termで、root bootごとにterm+1で自署名し直しcommitしてから何も公開しない（保存値=最後に公開したterm、新規networkのprovisioningは0）。memberはrootの認証済みLEASE（またはroot署名の更新credential）でのみ新termを知り、登録・path・時計を新termで取り直す。beaconのtermはhintで、より新しいtermの候補は試してよいが古いtermの候補は拒否する。route headerのroot_termは転送条件でない（§4）：期限は各hopでそのtermの時計で判定し、知らないtermは不明として運ぶ。旧termのcredentialは、attachを確定するREADYで「今すぐ更新が必要」（lease 0）と示し、rootはその時点で新termへ再発行する。再発行されるまで、root以外の隣とのlinkではアプリDATAが止まる（leaseを新termの時計で証明できない、SEC-D3）。最初のlease更新READY（60秒後）まで更新を待たせていた間は、root再起動後にrelay経由の板のアプリDATAが約75秒止まった（2026-10-12現場）。rootは再発行を1件ずつ、control laneが空いていて、自分の時計がそのCONTROLの期限を付けられる（自termの時計がある）ときに行う。付けられないうちに記録の読込みと署名を始めると、送れずに繰り返すたびにexchangeのscratchを借り続け、memberのhandshakeが入れなくなる（2026-10-15 sim: 時計のないrootが4 msごとに再署名し、relayの先のmemberが終端sessionを作れなかった）。
分断時の両側は同じrootを待つ。独自root選挙で鍵や業務状態を二重発行しない。root交換後のDeviceId同一性は署名付き委任で検証する。

### 整数scoreの固定式
success_q16を初期65536、対象試行ごとに`p += (sample_q16 - p)/8`（signed中間、sample=成功65536/失敗0）。ETX_Q8=`min(4096, max(256, (256*65536)/max(p,4096)))`。queue_msは同じalphaで更新し0..500へclip。instability_penaltyは直近30秒の親変更1回につき128、最大512、30秒経過で1段減衰。score=`256*depth + ETX_Q8 - 256 + queue_ms + penalty`。未知candidateは追加PROBEなしに最良と扱わない。同点は完全DeviceIdの辞書順で安定化。これは初期policyであり測定で変更する場合revisionと比較結果を残す。
