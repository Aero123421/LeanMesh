# Host（FastAPI）の使い方

契約の正本は [api/openapi.json](../../api/openapi.json) と [api/SEMANTICS.md](../../api/SEMANTICS.md)、設計は [docs/11](../11-host.md)。
Hostは root と USB serial でつながる**1プロセス**（uvicorn `--workers 1`、reload禁止）です。root停止中は新しい外部承認とHost宛のDURABLE受信が保留になりますが、既存のNode間通信はHostに依存しません。

## 1. 起動

```sh
LEANMESH_DB=/var/lib/leanmesh/host.db LEANMESH_TOKENS=/etc/leanmesh/tokens.json \
LEANMESH_SERIAL=/dev/ttyACM0 LEANMESH_USB_KIT=/etc/leanmesh/usb-kit.cbor \
~/.cache/leanmesh/host-venv/bin/python -m uvicorn leanmesh_host.main:app \
  --uds /run/leanmesh/api.sock --workers 1 --app-dir host
```

| 環境変数 | 必須 | 意味 |
|---|---|---|
| `LEANMESH_DB` | はい | SQLiteファイル（ローカルFS。WAL、`synchronous=FULL`）。開く時に `quick_check`、単一プロセスflock |
| `LEANMESH_TOKENS` | はい | tokenファイル（下記）。**0600でなければ起動しない** |
| `LEANMESH_SERIAL` | いいえ | rootのUSB serial device。未設定なら root 未接続（`/v1/health` の `serial: NOT_CONFIGURED`、`ready:false`） |
| `LEANMESH_USB_KIT` | serialに必要 | HostのUSB kit（Host用identity、fleet trust anchor、期待domain）。不正でもservice自体は上がるが degraded、**認証なしserialへは落ちない** |
| `LEANMESH_SCHEMA` | いいえ | `db/schema.sql` の場所（既定はリポジトリ内） |
| `LEANMESH_NATIVE_BUILD` / `LEANMESH_HOSTNATIVE` | いいえ | `libleanmesh_host.so` を探すbuildディレクトリ / 直接パス |
| `LEANMESH_PRINCIPAL_RPS` `_BURST` `LEANMESH_GLOBAL_RPS` `_BURST` | いいえ | rate limit（既定 20/40、100/100。0で無効）。超過は 429 `RATE_LIMITED` + `retry_after_ms` |

- 既定はUnix socket。`0.0.0.0` へ公開しません。LANに出す場合は別途TLS/mTLS境界を置きます。
- 常駐の雛形は [config/leanmesh.service.example](../../config/leanmesh.service.example)（専用user、`Restart=on-failure`、`NoNewPrivileges`）。
- **USB kit の作り方**: 製品用の発行ツールはありません。sim では meshsim の `serial-kit <path> 0` が TEST-ONLY 鍵で作ります（[getting-started §6](getting-started.md)）。
- serial 抜去は指数backoff（0.5〜30 s + jitter）で再接続します。

### tokenファイル

```json
{"principals": [{"id": "ops", "token_sha256": "<sha256 hex of the bearer token>",
                 "permissions": ["READ", "SEND", "CONFIGURE"]}]}
```

権限は `READ SEND APPROVE REVOKE TRANSFER CONFIGURE UPDATE_FIRMWARE`。tokenは `echo -n "$TOKEN" | sha256sum`。ファイルから消したprincipalは無効化されます（行は履歴のため残る）。
groupへのSENDは対象全員について権限を照合します。

## 2. 主なendpoint

以下 `S=api.sock`、`H="Authorization: Bearer $TOKEN"`、`curl --unix-socket $S -H "$H" http://localhost/v1/...`。

| メソッド パス | 権限 | 内容 |
|---|---|---|
| `GET /v1/status` | READ | `root_connected`、`journal_id`、capabilities（build / implemented / **qualified** / enabled） |
| `GET /v1/health` | READ | Host自身の状態（DB、serial、root、ready） |
| `GET /v1/diagnostics` | READ | rootの診断。要求時のみ問い合わせ（1回/秒まで） |
| `POST /v1/epochs`、`POST /v1/epochs/{id}/close` | 書込み権限 | `client_epoch` の発行/終了 |
| `POST /v1/messages` | SEND | 送信（202） |
| `POST /v1/control` | 型による | JOIN_DECISION / LEAVE / REVOKE / TRANSFER / INSTALL_CONTROL / POLICY_SET / CHANNEL_FREEZE / CHANNEL_RECALCULATE / GROUP_SET / POWER_POLICY_SET / COMMISSIONING_WINDOW_SET / ROOT_HANDOVER |
| `GET /v1/operations/{id}`、`POST .../cancel`、`GET .../targets` | READ / 書込み | 状態と証拠 / 取消 / group個別結果（16件/page） |
| `GET /v1/nodes[/{device_id}[/power]]`、`/v1/channel`、`/v1/lifecycle/requests` | READ | rootの報告のmirror（`domain_id` クエリ必須） |
| `GET /v1/events`、`GET /v1/events/stream`、`POST /v1/consumers/{name}/ack` | READ | event journal（§4） |

## 3. 送信とidempotency

```sh
# 1) client_epoch を開く（Hostがdurableに発行する16 B。再接続で勝手に取り直さない）
curl -s --unix-socket $S -H "$H" -H "Idempotency-Key: ep-1" -H 'Content-Type: application/json' \
  -d "{\"request_id\":\"$(openssl rand -hex 16)\"}" http://localhost/v1/epochs      # {"id":"<epoch>","state":"OPEN"}

# 2) 送信。deadline は UTC（mode utc）か root 基準（mode root）か none（RECEIVED+DURABLE のみ）
curl -s --unix-socket $S -H "$H" -H "Idempotency-Key: msg-1" -H 'Content-Type: application/json' \
  -d '{"domain_id":"<32hex>","client_epoch":"<epoch>","destination":{"kind":"node","device_id":"<64hex>"},
       "app_port":100,"payload_b64":"aGVsbG8=","delivery":"APPLIED","storage":"VOLATILE",
       "queue_mode":"FIFO","priority":"NORMAL",
       "deadline":{"mode":"utc","expires_at":"2026-10-01T00:00:00Z"}}' http://localhost/v1/messages
# 202 {"id":"<operation>","state":"HOST_COMMITTED","outcome":"PENDING","evidence":[]}

# 3) 証拠で判断する
curl -s --unix-socket $S -H "$H" http://localhost/v1/operations/<operation>
```

- **202 は「Host DBにcommitした」だけ**です。到達は `evidence[]` と `outcome` で見ます:
  `ROOT_ACCEPTED` → `ROOT_SENT` → `HOP_ACCEPTED`（`LINK_VERIFIED`）→ `END_RECEIVED`（`END_VERIFIED`）→ `APP_APPLIED`。欠けた段階を推定で埋めません。`assurance` は `END_VERIFIED / LINK_VERIFIED / SELF_REPORTED / UNKNOWN`。
- 同じ `Idempotency-Key` + 同じ本文 = 同じoperation（再送は何も書かない）。**本文が違えば 409 `CONFLICT`**。キーは `(principal, domain, 操作型, client_epoch, key)` 単位。
- 制約: payload 512 B（`object_transfer:true` で 4096 B、rootが `OBJECT_4K` を有効化している時のみ）、APPLIEDは有限期限、LATESTは BEST_EFFORT+VOLATILE+`coalesce_key`、groupのDURABLE/LATESTは 503 `UNSUPPORTED`。u63（`revision` 等）は**10進文字列**。
- 主なエラー: 400 検証、401/403 認証/権限、404、409 `CONFLICT`（古いrevision含む。`details.current_revision`）、410 `CURSOR_GAP`/期限外、413、429、503 `UNSUPPORTED`（`details.required_capability`）/`BUSY`、507 `NO_CAPACITY`。本文は `{code, message, request_id, retry_after_ms?, details?}`。

## 4. event・SSE・cursor

- `GET /v1/events?domain_id=..&after=<cursor>&limit=200&wait_ms=15000`: cursor は `journal_id:seq`。`after` 省略は保持している最古から。`wait_ms` はlong poll（最大15 s）。応答の `next_cursor` を次の `after` にします。
- `GET /v1/events/stream?domain_id=..`: SSE。`Last-Event-ID` で再開。stage 128件/256 KiB。遅い読者は `event: gap` の後に接続を閉じます。**SSE配信はACKではありません**（通知）。300秒で切れるので再接続します。
- 保持下限より古い、または別の `journal_id` のcursorは **410 `CURSOR_GAP`**（`details` に `journal_id / oldest_cursor / latest_cursor`）。黙って現在から続けません。
- 消費側は自分のDBに保存してから `POST /v1/consumers/{name}/ack` `{"domain_id","journal_id","sequence":"<u63>"}`。ACKは単調・冪等で、未来の位置は拒否されます。Hostのconsumer数/lease/保持期間には上限があります（`Settings`）。
- ルート発の受信メッセージ（`MESSAGE_RECEIVED`）は、Hostが `inbox` と journal を**1 transactionでcommitしてから**rootへ保存確認（HOST_STORE_ACK）を返します。ACK喪失時の再配送は保存済みの結果を返します（at-least-once）。

## 5. crash・再起動の意味

| 事象 | 動き |
|---|---|
| 202の前に落ちた | 操作は存在しない。同じキーで再送してよい |
| 202の後、送信claimの前に落ちた | outboxに `QUEUED` で残り、rootに繋がれば送られる（HTTP切断でcommit済み操作は取消されない。この境界を狙った試験は無い） |
| claim（`external_write_possible=1`）のcommit後、rootへ送る前に落ちた | 送ったか不明として**再送しない**。再起動後にrootへMessageIdで照会し、rootが知らなければ `INDETERMINATE`（"届かなかった"と"届いて忘れた"を区別できない） |
| rootへ送った後、Hostが応答を記録する前に落ちた | 再起動後にMessageIdで照会して**同じ操作を続ける**（rootの受理は1回、端末への配送も1回） |
| root再起動・セッション断 | rootの起動番号だけで知っている操作は `INDETERMINATE`。USB port名が同じでも同じ端末とは認証しない |
| DB破損・disk満杯 | 永続health fault。空DBを自動再作成して正常を装わない。原本を隔離して明示復旧 |

`INDETERMINATE` の副作用命令は、端末アプリの `application_result` かアプリ側の冪等契約で解決します（[device-api §5](device-api.md)）。
この挙動は `host/tests/e2e/test_bridge_meshsim.py` が、Hostを `kill -9` 相当で落として検証しています（sim上）。
