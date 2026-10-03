# 11 Python/FastAPI Host

## 1. 配置
Linuxを最初のサービス認定対象。Python3.12+、FastAPI、Uvicorn、Pydantic、pyserial、crypto用native binding。SQLiteは標準sqlite3（STRICT tableを使うためSQLite 3.37以降が必要。配備時はPython同梱の実SQLite版と既知修正を照合）。バージョンは実装開始時にlock+hash、脆弱性確認、再現環境を固定する。ここで実行していないバージョン組合せをproduction pinとして配らない。
Uvicorn **workers=1、reload禁止**。Unix socket `/run/leanmesh/api.sock`を既定とし0.0.0.0へ公開しない。API tokenはprincipal/権限付きの0600ファイルからロードし、UDS group制限も行う。peer UIDをASGIが必ず提供すると仮定しない。LAN公開は別のTLS/mTLS境界で、CORS任意originや無認証browser管理は提供しない。

## 2. 処理
FastAPI lifespanでDB検査・lock取得・serial管理開始、終了時受付停止→bounded drain→checkpoint→thread停止。async handler内でsqlite commit、serial read、cryptoを同期実行しない。
- event loop 1: request validation、operation調停、event配信。
- serial I/O thread 1: read/write双方をexclusive所有。再接続/COBS/parser/credit。
- storage thread 1: sqlite connectionとwrite transactionを専有。
- crypto executor 1: nativeEDHOC/signature。最大待ち8jobs、完了は世代つきevent。

スレッド数を増やして性能問題を隠さない。globalqueueに上限、subscriberごとのstage128events/256KiB。遅いsubscriberはgap通知後close可能、radio/DBを止めない。HTTP切断で既にcommitした操作をキャンセルしない。

## 3. API
`api/openapi.json`がOpenAPI3.1の契約。RESTは人間向けJSON、payloadはbase64。API request32KiB、payload512B/object4096B、page最大200、long poll最大15秒。wsを必須にせずcursor GET+SSEを提供。
POSTのidempotencyは `(principal_id, domain_id, operation_type, client_epoch, idempotency_key)`。body canonical hashが一致すれば同じoperation。異なれば409。client_epochはHostがdurable発行する16B、終了後は新しい操作に化けずEPOCH_CLOSED。再接続でepochを自動取り直して同じcommandを新規発行しない。

## 4. requestのtransaction
検証→ACL→capacity予約→INSERT operation+idempotency+outbox+eventを1transaction→COMMIT→202。202本文state=HOST_COMMITTED。serial threadへenqueueはcommit後。writer errorは503/507で受付失敗、202を先に返さない。
送信後crash時、再起動はrootへMessageIdを照会。外部writeが起きたか不明な副作用要求を新IDで盲再送しない。deviceのapplication_resultまたはidempotent contractがない場合INDETERMINATE。
rootやadapterの世代は接続path identityの一部。同じUSB port名だけで同じdeviceと認証しない。複数rootが同DeviceIdを名乗ったらquarantine。

## 5. 受信とcursor
root→Host durable requestを読んだら、inbox dedup、event journal、consumer可視化を1commitしてからHOST_STORE_ACK。ACK lossなら同じIDを再受信して保存済みcommitを返す。event cursorは`journal_id:seq`、seqはSQLite AUTOINCREMENT、journal_idはDBのdurable128bitでプロセス再起動では変えない。
consumerは自分のDBへ保存してからconsumer_ack。Host→KGとroot→Hostのcommitは分散transactionではないが、同じIDの再配送でat-least-onceを成立させる。保持下限より古いcursorは410 CURSOR_GAPと最古/最新を返し、黙って現在から続けない。

## 6. SQLite
WAL、synchronous=FULL、foreign_keys=ON、busy_timeout=1000ms、local filesystem。WALはネットワークFSに置かない。[E08,E09] 長いread transactionと放置subscriberでcheckpointを阻害しない。自動checkpointだけに依存せずwriterが低負荷時にPASSIVE、停止時に安全なcheckpointを試す。
ファイルシステムがfsyncを正しく実装する前提でdurabilityを表す。停電・記憶装置の嘘をSQL設定だけで完全に防ぐとは言わない。SQLite既知不具合の修正状況はlock時に確認し、版本固定だけで安全とみなさない。

## 7. 容量・劣化
DB予算1GiB、空き予約128MiB、operation未完最大4096、event最大1,000,000、未ACKcriticalは保護。telemetryは優先削除、latest stateはcoalesce、ACK済み通常eventは保持期間後削除。保護対象で満杯なら新規critical受付を明示拒否し、既存criticalを消して成功を偽らない。
DiskFull/Corruption/ConsumerGapは永続health fault。corruptionを空DB自動再作成して「正常復旧」にしない。原本を隔離し明示recovery。secret storeとDBをバックアップし、rollbackでclient_epoch/失効世代を巻き戻さない手順を12に置く。

## 8. 運用
systemdは専用user/group、Restart=on-failure、RuntimeDirectory、StateDirectory、NoNewPrivileges、UMask0077、API/serial singleton lock。serial unplugは指数backoff0.5〜30s+jitter。readinessはDB/keys/migration正常を示し、root未接続はdegradedとして返す。livenessが正常でも通信到達を証明しない。unattended destructive migrationはしない。

## 9. spec0.2追加
GET `/v1/nodes/{device_id}/power`、GET `/v1/operations/{operation_id}/targets`を追加。変更操作は既存 `/v1/control` に集約する。新しいdaemon、ORM、job brokerを追加しない。power状態は`node_power`、個別group結果は`group_targets`へ既存writerで保存する。sleep待ちtaskをtarget数だけ作らず、既存の期限/待機キューへ入れる。
自動channelとmembershipの実行主体はroot MCUのまま。Pythonがstopしてもrootの既存policy/有限lease内通信は継続可能だが、Host自身へのDURABLE受信・外部承認は保留になる。

## 10. 台帳backup（issue #5）
Hostはrootの台帳のsigned backupを変更後に1回取り（debounce、最短間隔、失敗は有限回の延ばしbackoff。何も変わらない間はpollingしない）、`ledger_backups`にdomainごとの最新sequence 1行だけを保持する（低いsequenceで置き換えない）。既存DBへの導入はadditive migration（`CREATE TABLE IF NOT EXISTS`の文だけを起動時に実行）。`LEDGER_RESTORE`はrootが接続中のdomain rootと違う場合でも、その交換を運ぶ要求（fleet署名のRootHandover＋保持backup）が先に実行され、成功した場合に限りbridgeはその新rootをdomainに結び付ける（[12章 §5](12-storage.md)、[21章 §8](21-lifecycle-operations.md)、[sdk/host.md §7](sdk/host.md)）。
