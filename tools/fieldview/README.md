# fieldview（現地試験ビューア）

`docs/field/protocol.md` §5 の実装。LeanMesh Host の隣で動くノートPC用の1プロセスで、**Host API だけ**（Unix socket + bearer token）と話し、
`127.0.0.1` に1枚のWebページを出す。外部のscript/font/画像は使わない（現地にInternetは無い）。試験用ツールであり製品ではない。
SDK core・Host本体は変更しない。

## 起動

リポジトリのルートで、Host用venv（FastAPI/uvicorn/httpx2 入り）を使う。

```sh
PYTHONPATH=host ~/.cache/leanmesh/host-venv/bin/python -m tools.fieldview
# → http://127.0.0.1:8091/
```

先に `tools/hil/hil.py` の bench と Host（`--uds /tmp/claude-501/lm.sock`）が動いていること。Host がまだ無くても起動でき、ページに警告が出て、
Host が現れると自動でつながる。

| オプション | 既定 | 意味 |
|---|---|---|
| `--socket` | bench の `$LEANMESH_HIL_SOCK` / `/tmp/claude-501/lm.sock`（`--net N` ではその網のsocket） | Host の Unix socket |
| `--token-file` / `$LEANMESH_TOKEN` | `~/.cache/leanmesh/hil/token` | bearer token（READ + SEND が要る） |
| `--domain` / `$LEANMESH_DOMAIN` | bench の `state.json` の domain | domain id（Host API は domain を教えない） |
| `--state-file` | `~/.cache/leanmesh/hil/state.json` | 板の名前（`leaves` の name → device）、root の DeviceId、domain |
| `--net` | なし | `state.json` の追加network（`hil.py --net`） |
| `--port` | 8091 | ページのport（127.0.0.1のみ） |
| `--logs-dir` | `./logs/fieldview` | 記録先。セッションごとに `<UTC時刻>/` |
| `--interval` | 10 | telemetry間隔の仮定（秒）。node が telemetry に自分の間隔を載せていればそちらを使う |
| `--consumer` | `fieldview` | Host の event consumer 名。**同時に2つ動かすなら別名にする**（ACK位置を共有してしまう） |

## 画面

- **Topology**: root と各nodeの木（SVG）。`GET /v1/nodes` の `parent_device_id` / `root_depth` から作る。リンクの色は子nodeの
  親RSSI（telemetry）と直近のtelemetry欠落率の悪い方（RSSI -80以上/-90以上、欠落 5%未満/20%未満で good/fair/poor）。
  rootが列挙するのにtelemetryを出さないnodeは灰色の破線で描く。`parent_device_id` を返さないHostでは、親の分からないnodeは
  すべて「parent unknown」グループの下に置く（推測で別nodeの下に置かない）。Hostが列挙しない親は灰色の代理nodeで示す。
- **Nodes** 表: 名前・chip・role・state（ok / lost / silent / left / unlisted）・membership/connectivity・depth・親・RSSI・
  telemetry age・telemetry欠落率（seqの欠番から。累計と直近）・reboot回数・counter・ping結果・表示状態。
- **Ping**: 「Ping all now」と、1秒以上の間隔でのloop（開始/停止）。1 roundは ACTIVE な node ごとに `POST /v1/messages` 1件。
  結果は alive（APPLIED）/ no answer（root から出たが期限まで返らない: EXPIRED / INDETERMINATE 等）/ rejected（nodeが
  REJECTEDと答えた=到達はしている）/ **not sent**（Host/rootが拒否した・root から出なかった。RF損失とは別に数える）。
  RTT は `APP_APPLIED.observed_mono_ms - ROOT_SENT.observed_mono_ms`（無ければ END_RECEIVED）。
- **Display**: telemetry の role=3 のnodeを選び USABLE / FORBID を送る。「arrived（END_RECEIVED）」と「drawn（APP_APPLIED）」を
  別に表示し、telemetry の flags が報告する表示状態と command_seq の一致も示す。
- **Event log**: join / leave（`/v1/nodes` の差分）、親の変更、depth変更、connectivity変更、telemetry欠落、node lost / back
  （telemetry age > 3周期）、reboot（boot_count / seq の巻き戻り）、Hostの event journal の欠落（CURSOR_GAP）。

## 記録（`<logs-dir>/<UTC時刻>/`）

`telemetry.ndjson` `ping.ndjson` `display.ndjson` `events.ndjson`（各行にノートPCのUTC時刻 `t`）と `summary.csv`（10秒ごとにnode1行:
name, device, depth, parent, rssi, telemetry欠落率, ping sent/alive/lost/not sent, RTT中央値, 最終telemetryからの秒）。
書込みは専用threadの有界queueで行い、ディスクが壊れても画面は止まらず警告を出す。

## Hostとの関係（実装の根拠）

- **telemetry**: app_port 210 の node→root 通信は、Host の event journal に `MESSAGE_RECEIVED`（`origin`, `payload_b64`,
  `evidence.details.app_port`）として出る。`GET /v1/events?after=<cursor>&wait_ms=` のlong pollをconsumer（`POST /v1/consumers/{name}/ack`）
  として読み、取り込んだ後にACKする。再起動後は consumer のACK位置（`ack 0` が現在位置を返す）から続け、起動前の未読は
  baseline にだけ使う。CURSOR_GAP / EVENT_GAP は画面とeventsに出し、telemetry欠落の基準を取り直す（RF損失に数えない）。
  MESSAGE_RECEIVED は journal で保護されるので、fieldview が止まっている間は Host が溜める。ACKしないと溜まり続ける。
- **ping / display**: 期限は **UTC mode**（`expires_at` = ノートPC時刻 + min(間隔, 3 s) / 10 s）。root mode は root の term と時刻が
  要るが API は出さず、UTC mode は Host が root 時計の境界で変換する（`bridge._deadline`。root時計が無いと送らず期限切れ）。
  進捗は `OPERATION_UPDATE` event で知り、`GET /v1/operations/{id}` は終了したoperation（displayは変化ごと）にだけ呼ぶ。
  期限後に1.5秒ごとの安全pollを行い、期限+8秒で見切る。
- **`queue_mode`**: protocol.md §3.2/3.3 は APPLIED + LATEST + coalesce_key と書くが、Host は LATEST を BEST_EFFORT + VOLATILE
  にしか許さず（`api/models.py`, `api/SEMANTICS.md`）400にする。そのため **FIFO・coalesce_keyなし**で送る。短い期限が古い要求を
  残さない。仕様側の修正が必要（未解決の矛盾としてここに残す）。
- **レート制限**: Host は principal ごとに 20 req/s（burst 40、GETを含む全endpoint）。fieldview は自前のtoken bucket
  （14 req/s, burst 24）を通す。ping loopは `2 x node数 / 間隔 + 3` req/s が14を超える間隔では開始を断り、必要な間隔を示す。
  roundの途中で自前の予算が尽きたpingは送らず not sent（`local request budget`）に数える。Hostの429は not sent で、
  `retry_after_ms` の間は全要求を止める。
- **command_seq**（display）: 起動時のUNIX秒から+1ずつ（nodeがNVSに前回値を持つので、起動をまたいで減らさない）。
- `POST` は `X-Fieldview: 1` ヘッダ、`Host` は 127.0.0.1/localhost のみ受ける（別のWebページからの操作を防ぐ）。

## 限界（未検証・既知）

- Host が evidence に `observed_mono_ms` を載せるまで（現状 bridge は載せない）、RTT は **ノートPCが測った値**（POST → 終了event、
  Host処理・serial・event pollの遅れを含む上限）で、表に `*` が付く。root時計のRTTではない。
- 実機・実無線・実Host（`parent_device_id` 付き）では未検証。Host と meshsim での通し試験は `host/tests/e2e/test_fieldview_meshsim.py`
  （ptyで、timingの証拠ではない）。
- journal の critical event が溜まるのは fieldview 停止中だけに限らない。ping/display 1件が数件の OPERATION_UPDATE を残す。
  長時間のloopは Host の event 容量に効く（ACKは取り込み後 2 s ごと）。
- 同時に開ける open operation は512件まで。nodeの上限は Host の `limits.members`（64）。

## テスト

```sh
~/.cache/leanmesh/host-venv/bin/python -m pytest host/tests/unit/test_fieldview_core.py host/tests/unit/test_fieldview_fake_host.py \
    -q -p no:cacheprovider --basetemp=/tmp/claude-501/pt-fv
LEANMESH_NATIVE_BUILD=~/.cache/leanmesh/native ~/.cache/leanmesh/host-venv/bin/python -m pytest \
    host/tests/e2e/test_fieldview_meshsim.py -q -s -p no:cacheprovider --basetemp=/tmp/claude-501/pt-fv
/tmp/claude-501/ruffvenv/bin/ruff check tools/fieldview host
```
