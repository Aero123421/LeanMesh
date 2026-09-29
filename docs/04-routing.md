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
送信中の3回の対象RF失敗で親をSUSPECT。pending DATAがあるときは5秒の無応答を追加の修復条件にする。idle時は安定helloが32秒になるため、5秒の無受信だけで断とせず、広告されたhello上限の3倍（既定最大96秒）を不在判定にする。送信が生じれば必要時PROBEを直ちに行う。Sleep予定、BUSY、探索休止は数えない。予備候補へのPROBE→REGISTERを行う。親候補は必要改善20%・最小維持30秒。ただしdead linkからの切替は維持時間を待たない。
rootは子孫のpathを更新する。子孫へ新版が届くまで旧pathは期限付きで残し、下りでstaleが出たら送信元だけが再解決する。relayが無断で次hopを取り替えない。再送は同じMessageId/intent hash、fresh packet counter。rootがいない場合は既存有効path通信を続け、未登録の新木を成立済みとして広告しない。

## 6. control量と親score
qualityは対象RF失敗に基づくEWMA（alpha=1/8）、queue遅延EWMA、auth-session安定性を使う。初期score=256*depth + 256*(ETX-1) + min(queue_ms,500) + instability_penalty。RSSIは候補を落とす粗い補助で、単独選択基準にしない。
近隣helloは変化時+Trickle風2〜32秒（安定期最大32秒、検証済みdataをlivenessへ利用）、root lease更新は60秒・有効180秒・jitter10%。緊急packetをhello待ちにしない。64台20hopでのcontrol airtimeを必ず測り、低頻度payloadよりcontrolが支配するprofileを認定しない。

## 7. 異常ケース
address再利用はmembership_generationが変わり、関連link/end sessionとpath cacheを無効化する。root_termはroot bootごとに永続増加。旧termの未確定登録は破棄、新termでsession/pathを再同期。term/generationはwrap前に停止し管理復旧を要求する。rebootで0に戻さない。
分断時の両側は同じrootを待つ。独自root選挙で鍵や業務状態を二重発行しない。root交換後のDeviceId同一性は署名付き委任で検証する。

### 整数scoreの固定式
success_q16を初期65536、対象試行ごとに`p += (sample_q16 - p)/8`（signed中間、sample=成功65536/失敗0）。ETX_Q8=`min(4096, max(256, (256*65536)/max(p,4096)))`。queue_msは同じalphaで更新し0..500へclip。instability_penaltyは直近30秒の親変更1回につき128、最大512、30秒経過で1段減衰。score=`256*depth + ETX_Q8 - 256 + queue_ms + penalty`。未知candidateは追加PROBEなしに最良と扱わない。同点は完全DeviceIdの辞書順で安定化。これは初期policyであり測定で変更する場合revisionと比較結果を残す。
