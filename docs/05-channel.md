# 05 自動チャネル最適化と移行

## 1. 意味
「自動」は混雑を疑ったら即scan/即変更することではない。同一domainの全Nodeで1channelを使う。root firmwareが唯一のplan発行者。FastAPIはpolicyと手動freezeを要求できる。root停止時はplanを新規発行しない。channel_epochはrouting root_term・membership generation・鍵世代とは別のuint32。

## 2. 状態とデータ
MONITOR → SURVEY → PREPARING → COMMITTED → SWITCHING → SETTLING → MONITOR。失敗はABORTED（commit前のみ）またはRECOVERING（commit後）。plan_idは16B、policy_revision/root_term/channel_epoch、old/new channel、participant snapshot、switch_root_ms、max_clock_error_ms、settle_ms、plan_hashを保持する。

## 3. 最適化判定（初期policy、可変）
5分間の観測窓、最低32packet samples/評価link。RF損失率>10%またはservice time中央値が同link基準の2倍という悪化が複数独立linkで持続した場合に候補評価へ進む。LOCAL_NO_MEM/REMOTE_BUSY/SLEEPは除外。まず経路を修復する。
候補scoreはnormalized loss0.5 + service_time0.3 + queue_delay0.2。全地点の生RSSIやAP件数を足して「電波が空いている」と断定しない。候補は少なくとも2地点（小網は全地点）で比較可能なsampleが必要。最悪必須linkが悪化しないこと、全体costが25%以上改善することを要求する。成立しないとCURRENT_CHANNEL_RETAINED。
変更後cooldown3600秒。1日に4回を上限（管理者の明示overrideは監査する）。packet lossから無制限に探索する設計は禁止。

## 4. survey
scanは無線がhomeを離れる操作。relayの無断scan禁止。rootがroute依存を確認し、常時給電のleaf scoutまたは冗長経路で覆われたrelayへ1channel当たり最大60msのvisitを配る。直前にownerがdrainし、critical送信中・childに代替がない場合は延期。AP一覧は補助情報だけ。候補channelのpaired probeは両端に同じ試験windowを与え、max 2visits/分/ノード。
冗長経路のない20hop chainでサービス無停止の全地点surveyは保証できない。maintenance_gap許可がなければ探索延期と理由を返す。許可があれば計画された短い測定休止を通知し、測定中の不在を障害判定に入れない。

## 5. clock
rootの単調時計をTIME_REQ/RESP（nonce、t1,t2,t3,t4）で推定。往復遅延全幅を不確かさに含め、非対称経路でも正確だと仮定しない。root_termと共にoffset下限/上限を保持。20hopで上限がpolicy許容誤差を超える場合はREADYを返さずTIME_UNCERTAIN。
root再起動（新term）後、旧termの値（lease、期限、switch_root_ms）は新termの時計で読まない。旧termの推定で証明済みのlink認可はその時に求めた局所期限まで有効のまま、証明できていないものは不明（アプリDATA停止）。旧termでCOMMITTED済みのplanはrootが再起動時に適用済みなので、memberは新termを知った時点でtargetへ切り替え、旧termのCOMMIT/ABORTはそのplanを保持/完了しているNodeだけが受ける（ARCH2-D1）。
新channel切替guardは2*最大誤差 + 最大drain時間 + 500ms。UTC/NTPの有無と混ぜない。

## 6. PREPARE / COMMIT
PREPAREは署名付きControlObject。member relay全台と、アプリがcritical_receiverに指定したNodeのsnapshotを必須参加集合とする。critical sleepy leafが期限まで起床できない場合は延期、または管理者の明示deferred許可を必要とする。通常sleepy leafはdeferred理由を保存し次回探索で追随。未達必須relayを黙って分母から外さない。policy変更・Join/移設commit・OTA install中は開始延期。
各参加者はRF許可・power状態・clock bound・buffer・root署名・epoch新規性を検証し、NVSへPREPARED保存後READYを返す。rootは全必須READYを確認。timeout120秒ならABORT。
rootはCOMMITTED recordをdurable保存してからCOMMITを送る。参加者もCOMMIT保存後COMMIT_STOREDを返す。switch時刻は現在+60秒以上で、20hop制御往復・保存予算で延長してよいが、**一度発行したCOMMITの時刻やhashを変えない**。未受信機が残れば部分到達を記録しRECOVERINGに進む。全員が同時にatomic commitする保証ではない。

## 7. 切替と取り残し
COMMITTEDを持つNodeはguard前に新DATAを止めdrain、目標channelをreadback、元のMessageIdで再配送。rootは新channelで署名付きRECOVERY_BEACONを1秒間隔で60秒出す。通常beaconへplan_id/channel_epoch/hash/root_termを載せる。
commitを取り逃した機器は親の認証livenessを失った後、保存current→pending target→許可channel集合を探索。1channel200ms、1回2周まで、失敗はbackoff1〜60秒。新beaconのroot権限とepochを検証してから追随する。beacon未認証だけで鍵/所属/active channelを永続変更しない。
再起動時PREPAREDだけならold_channelで照会。COMMITTEDならtargetで復帰し、schedule時刻が不明でも旧channelへ自主rollbackしない。root再起動は保存済みcommitted channelを先に適用してから新root_termを公開する。

## 8. rollbackと停止条件
新channelが悪ければrootだけが**さらに大きいchannel_epochでold_channelを目標にした新plan**を発行する。端末単独のtimeout rollback禁止。届かない端末はscanで最新rootへ再合流する。全channel妨害やroot不在では復旧不能を表示し、振動する切替を続けない。
freezeは新しいplan開始を止める。committed planは取り消さず完了/復旧まで進める。APIにはcurrent、pending、committed、required/applied/unreachableの個別集合を返す。単一の「成功」boolは禁止。

## 9. 正規化とclock初期値の固定
loss_q16は対象RF失敗数/対象試行数×65536。service_q16は`min(service_median/home_baseline_median,4)/4`、queue_q16は`min(queue_median_ms,500)/500`を65536倍し整数化。baselineが0/不明ならsample不足として候補比較しない。weighted score=`(5*loss_q16+3*service_q16+2*queue_q16)/10`。sample集合/観測期間を揃え、候補の失敗を集計から除外しない。
clock誤差許容は初期2000ms（policy範囲50..10000ms）。boardの周波数誤差上限は認定値を使う。初期試験条件は500ppmを上限仮定し、時間経過×driftをoffset区間へ加算する。未評価のboardを自動的にこの条件で認定せず、HILで範囲内を確認。20hopで誤差が大きい場合は切替を延期し、精密同期を装わない。

## 10. 電池端末の制約
20章のepisode/radio予算は本章の探索上限より先に適用する。許可channel全周を完遂するために電池予算を延長しない。眠っていることを測定失敗へ加算せず、sleepy対象のjoin/recoveryは通常backboneと別に測る。
