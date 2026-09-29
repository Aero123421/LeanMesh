# 01 要求、範囲、不変条件

## 1. 製品定義
接続を意識せずNodeまたはgroupへ小さなアプリデータを送れる、C/C++向けSDK。通信媒体は2.4GHz ESP-NOW/LR。透過IP、Wi-Fi APを延伸する家庭用Mesh、映像ストリーミング、LoRaWANではない。rootを含め全Nodeはアプリ送受信できる。root経由の経路でも、端末間の本文暗号化は終端間で維持する。

## 2. 必須要求
|ID|契約|
|---|---|
|REQ-01|S3/C3/C5/C6を同一Wire・Security suiteで混在。全組合せの双方向実機試験を出荷gateとする。|
|REQ-02|rootから最大20無線辺。1 root+20端末の強制chainで実証。任意端末間の単純経路は最大40辺。|
|REQ-03|端末追加、移動、relay抜去、全体停電を通常の障害として自動復旧。全員の再Joinを要求しない。|
|REQ-04|チャネル自動選定・移行・取り残し復旧・freeze API。単一radio/単一チャネルを維持。|
|REQ-05|個体鍵による相互認証、承認付きJoin、既存所属での復帰、失効、鍵更新、手動leave、現場間移設。|
|REQ-06|Join proxy、期待機器hint、listen-first、探索予算、長期隔離からの再探索。hintは認可ではない。|
|REQ-07|所属とReachable/Degraded/Isolated/Sleepingを分離し、CとHostへ同じ事実を公開。|
|REQ-08|任意Nodeからunicast、group fan-out、APPLIED要求。受信処理完了を後から非同期報告可能。|
|REQ-09|最新状態と保持すべき履歴の配送を分離。期限・冪等性・再送・満杯・不明結果を公開。|
|REQ-10|通常メッセージ最大512Bの有界分割。任意objectは最大4096Bのoptional機能。|
|REQ-11|Python/FastAPIの1プロセスサービス、SQLite永続化、cursorによる再開。無線中継をPython待ちにしない。|
|REQ-12|電池leaf、通信整理後sleep、復帰、下り受信窓。電池寿命は測定し、sleepy nodeはrelayにしない。|
|REQ-13|安定IDと機器役割の分離。KGuardでの移設/交換/再校正を上位実装できる。|
|REQ-14|コード量・Flash・RAM・計算・無線の予算を継続検査。安全検査は削減対象にしない。|
|REQ-15|電源断、DB/Flash満杯、古いACK、並行Join、移設と鍵変更等の負例を仕様化。|
|REQ-16|USB認証と将来uplink差替え境界。rootとアプリの動作にPCを必須にしない。|
|REQ-17|OTAを追加できる4MiB dual-slot配置、署名・rollback・保存schema契約。OTA機能は独立認定。|
|REQ-18|KG固有の認可、安全ルール、描画確認は上位adapterへ。未認証Routeを本人認証として扱わない。|

## 3. 配置上限
標準small profileは1 domain・64 members（root含む）・16直結の確立済みpeer/ノード。128 membersはroot容量profileで選択する試験目標であり、64の測定から認定を外挿しない。深度を増やしてもleafが64台分のsessionやrouteを持つ設計にしない。

20hopは「距離20倍」「20hopで1hopと同じ応答時間」を意味しない。最短到達経路を優先し、depth>10は運用上の配置見直し情報を出すが利用を拒否しない。可用な隣接がない場所、全relayがsleep、全許可channelの妨害は復旧保証外。

## 4. 非目標とoptional
複数rootの自動選挙/HA、分散合意、任意service discovery、link別multi-channel、LoRa透過化、Rust daemon、TUI、デバイスへのJSON業務engineは入れない。groupは提供するが効率化専用の第二routing protocolを作らない。任意object転送とmesh OTAはoptionalで、無効なら専用bufferを確保しない。
同一radioを通常APへ接続しつつ自在にMesh channelを変える構成はbaseline外。PC-less uplinkはSPI Ethernetまたは別radioを用いる。無線firmwareと同じアプリ内のローカルAPI利用は最初から可能。

## 5. 信頼性の契約
安全な認証・配送が成功する条件を厳密にする。物理表示や弁の実動作をSDKは推測しない。通信が切れた場合の装置のfallbackはアプリが決める。禁止/空室等の最後の値を無期限保持することをSDKの安全保証にしない。
複数端末に対するgroup操作は部分成功を許容するfan-out。全台同時の物理transactionではない。回復不能なら「結果不明」「不足」「隔離」を返すことも正しい動作である。

## 6. spec0.2追加要求

|ID|契約|
|---|---|
|REQ-19|汎用3power modeを同一API/認証/配送engineで提供する。|
|REQ-20|一回のwakeと圏外の通信予算を有限にし、障害で電池を使い切らない。|
|REQ-21|RAM保持sessionとcold/deep再認証を区別し、電力都合でnonce/replayを破らない。|
|REQ-22|有界の受信窓とmailbox、20hop送信結果持越しを提供し、途中RAM受理を永続成功にしない。|
|REQ-23|設置window/大量設置/工場在庫/root交換/resetの汎用lifecycleを定義する。|
|REQ-24|group世代snapshot、個別結果、sleep公平性、cancel・再起動の意味を公開する。|
|REQ-25|4SoCのenergy/成功率/長距離/計算量を同時に測り、推定と実測を分離する。|
