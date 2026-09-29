# 17 実装計画と完了の単位

## 開始時の約束
新repoで作る。旧RouteLoomのWire/C ABI互換は要求しない。旧Repoの不具合再現と必要な安全条件を継承する。以下の順序は実装の依存関係であり、20hopや自動channelを後で削る口実ではない。RFを含む合格まで実験buildとして扱う。

|Task|成果物|依存|完了条件|
|---|---|---|---|
|T01|toolchain/dependency lock、4target CI、ライセンス台帳|なし|IDF pin4target build、EDHOC subset/patch固定|
|T02|wire codecとC ABI値|T01|付属golden/negative+独立decoder一致|
|T03|record crypto/backend/EDHOC job port|T01,T02|RFC vectors、mutation、EAD/purpose分離、secret処理|
|T04|IDF owner/ring/peer/single TX|T01,T02|real callback順序/timeout/NO_MEM試験|
|T05|sealed store+boot counter+journal|T01|全write境界power-cutと満杯|
|T06|factory credential/RootDelegation/AssignmentTicket|T03,T05|key mismatch、低generation、再使用拒否|
|T07|1hop Join/resume/leave|T04,T06|2C3で双方commit、Hostなしpreapproved|
|T08|source path/route registration|T07|sim21node20hop、cycle/重複path拒否|
|T09|delivery/retry/receipt/APPLIED|T03,T05,T08|最終ACK消失、不明、副作用再照合|
|T10|small fragmentation+optional4KiB|T09|順不同/重複/不足/満杯/期限|
|T11|USB authenticated session|T03,T04,T09|偽root/Host拒否、reset再認証、credit|
|T12|FastAPI/SQL/exclusive serial|T05,T11|POST後crash・DBfull・cursor再開|
|T13|smart hint/proxy/expected revision|T07,T08|未登録先初起動後の登録反映、hint偽造|
|T14|transfer A→B→A|T05,T06,T13|A停止/稼働/並走/停電、旧命令拒否|
|T15|scheduler/admission/latest|T09,T12|control非飢餓、key別latest、公平性|
|T16|group snapshot/paged fan-out|T10,T15|全Node origin、部分成功、snapshot固定|
|T17|time bounds/channel survey/plan|T08,T13,T15|sim各phase欠落/遅延、freeze、永続復旧|
|T18|sleep/drain/wake window|T05,T09,T17|新DATAとのrace、sleep≠loss、energy計測|
|T19|diagnostics/health/qualification|T12,T18|不明値、driver/SDK/appを別指標|
|T20|4chip mixed HIL +21radio20hop|T04〜T19|docs18のRF gate、改善差分実測|
|T21|KG adapter/codec/IDF移植|T09,T12,T14|既存Transport意味維持、st/tr区分、2表示盤|
|T22|KG24h/72h pilot|T20,T21|実表示証拠、offline、切戻し|
|T23|optional OTA|T05,T10,T17,T18|4MiB2面/rollback/全write点power-cut|
|T24|独立Security/安定性/資源review|T20,T25,T26,T27|指摘の再現→修正→再試験、release manifest|

## PR設計
Tごとに巨大PR1本と決めない。1つの状態機械や垂直経路でレビュー可能に分割。仕様と実装を同じ担当が独立性なく自己承認しない。レビュー指摘の範囲だけを過剰抽象化で直さず、最小の不変条件を修復する。

## 完了ゲート
G0=spec consistency、G1=host/software properties、G2=4target build、G3=mixed hardware、G4=20hop RF+channel、G5=lifecycle/security/power、G6=application integration、G7=release custody+independent review。
このZIPが実行するのはG0の一部のみ。未完featureはenabled=false。T23を省略したimageはOTA非対応と広告するが、20hop/4chip/Join/autochannelを省略したimageを本SDKの正式baselineとは呼ばない。

## spec0.2追加task
|Task|成果物|依存|完了条件|
|---|---|---|---|
|T25|3 power mode・episode・poll/grant・mailbox・省電力診断|T04,T07,T09,T17,T18|LP01〜LP20、4chip power行列、電流trace|
|T26|commissioning window・batch・root handover・reset境界|T06,T12,T14|LC01〜LC12、途中電源断、旧root拒否|
|T27|世代付きGroupSnapshotV2・targets API・sleep公平性|T16,T25|GS01〜GS12、64target進捗・部分結果|
|T28|電力/性能A-B、低負荷/圏外/20hop、依存lock監査|T20,T25,T26,T27|ME01〜ME08、J/reportと成功率を同時記録|

Powerの予算/owner設計はT01〜T04で導入し、後からsleep関数だけを足さない。T18/T25はその統合gate。T21/T22のKGは重要な利用例だが、汎用SDKのすべてのreleaseをKGのCloud完成待ちにしない。G6は少なくとも二つの異なるアプリ（例:設備状態制御と電池定期計測）のcontract適合で評価できる。KG採用認定は別にT22を要求する。正式baselineはG5のlow powerとT28測定も必須。
