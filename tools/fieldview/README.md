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
- **Ping**: 「Ping all now」と、1秒以上の間隔でのloop（開始/停止）。1 roundは ACTIVE な node ごとに `POST /v1/messages` 1件
  （`delivery RECEIVED`、VOLATILE、FIFO、期限は loop 間隔に関係なく **3 s 固定**。protocol.md §3.2）。結果の種類（Host / root / nodeの
  側の事実だけで分け、足りない証拠を推定で埋めない）:

  | 種類 | 意味 |
  |---|---|
  | **alive** | operation が FINAL `RECEIVED`（evidence `END_RECEIVED`: nodeのSDKが end-to-end で受領を返した）。nodeアプリの生存は telemetry が示す |
  | **no answer** | root から出た（`ROOT_SENT`）が期限まで受領が返らない（EXPIRED / INDETERMINATE 等）。RF損失の候補 |
  | **rejected** | nodeが REJECTED と答えた（到達はしている） |
  | **not sent** | 出ていないと**証明できる**: Hostが拒否（4xx/429/5xx の応答）、root から出なかった、送信前の失敗（connect refused）、自前のrate guardが予算切れで送らなかった。RF損失とは別 |
  | **unknown** | POST の応答が来なかった（read timeout・接続断）。Host が受理したかもしれない。**同じ要求（同じ Idempotency-Key・同じ epoch）を2回再送**して operation id を取り戻そうとし、それでも応答が無ければ unknown。no answer にも not sent にも数えない。ping.ndjson に key を残す |
  | **skipped** | 送らなかった: その node に open な ping が既に3件ある（busy）。1 s loop・3 s 期限では最大3 roundが重なるので、遅い/死んだnodeに積み上げない |
  | **late** | 期限内には no answer だったが、あとで Host の履歴に受領（evidence）が現れた。**on-time の結果は書き換えず**、`noanswer` と `late` を並べて数える（ping.ndjson `event: late`、event log、node表と roundの late 列） |

  RTT は `END_RECEIVED.observed_mono_ms - ROOT_SENT.observed_mono_ms`（root時計）。Host が時刻を載せない間は**ノートPCが測った値**
  （`*` 付き）。skippedや not sent はroundの `open` から外れる。
- **Display**: telemetry の role=3 のnodeを選び USABLE / FORBID を送る（`delivery APPLIED`、期限10 s）。「arrived（END_RECEIVED）」と
  「drawn（APP_APPLIED）」を別に表示し、telemetry の flags が報告する表示状態と command_seq の一致も示す。続けて複数送っても、
  **受理した命令はそれぞれ operation id で自分の evidence と最終結果を記録する**（画面に出るのは最新の1件だけ。display.ndjson の
  `latest` が画面に出ていたかを示す）。arrived だけで drawn でない命令は ping の alive にはならない。
- **Event log**: join / leave（`/v1/nodes` の差分）、親の変更、depth変更、connectivity変更、telemetry欠落、node lost / back
  （telemetry age > 3周期）、reboot（boot_count / seq の巻き戻り）、Hostの event journal の欠落（CURSOR_GAP）。

## 記録（`<logs-dir>/<UTC時刻>/`）

`telemetry.ndjson` `ping.ndjson` `display.ndjson` `events.ndjson`（各行にノートPCのUTC時刻 `t`）と `summary.csv`（10秒ごとにnode1行:
name, device, depth, parent, rssi, telemetry欠落率, ping sent/alive/lost/not sent/unknown/skipped/late, RTT中央値, 最終telemetryからの秒）。
受理した ping は `event: posted`（operation id・epoch）をその場で書くので、結果が書かれる前に落ちても Host から id で読み直せる。
書込みは専用threadの有界queueで行い、ディスクが壊れても画面は止まらず警告を出す。ファイルは回転しない（4 node・1 s loop で
1日に数百MB規模: 長い試験は `--logs-dir` の空きを見ておく）。

**ACK と記録の順序**: Host の event は、その記録が **fsync 済み**になるまで ACK しない（ページ単位）。そのページが FINAL と報告した
ping/display の結果を読んで記録するまでも待つ（最大20 s）。記録が落ちた（queue満杯・書込み失敗）ときは ACK を止め（Host が保持し、
再起動後に読み直す）、ディスクが戻ったら**欠落を明示する `recorder-gap` 行**を events.ndjson に書いて fsync してから ACK を進める
（画面の警告は残る）。ACK が進まない間の警告: 「acknowledgement held: the records are not safely on disk」。

## Hostとの関係（実装の根拠）

- **telemetry**: app_port 210 の node→root 通信は、Host の event journal に `MESSAGE_RECEIVED`（`origin`, `payload_b64`,
  `evidence.details.app_port`）として出る。`GET /v1/events?after=<cursor>&wait_ms=` のlong pollをconsumer（`POST /v1/consumers/{name}/ack`）
  として読み、取り込んだ後にACKする。再起動後は consumer のACK位置（`ack 0` が現在位置を返す）から続け、起動前の未読は
  baseline にだけ使う。CURSOR_GAP / EVENT_GAP は画面とeventsに出し、telemetry欠落の基準を取り直す（RF損失に数えない）。
  MESSAGE_RECEIVED は journal で保護されるので、fieldview が止まっている間は Host が溜める。ACKしないと溜まり続ける。
- **ping / display**: 期限は **UTC mode**（`expires_at` = ノートPC時刻 + min(間隔, 3 s) / 10 s）。root mode は root の term と時刻が
  要るが API は出さず、UTC mode は Host が root 時計の境界で変換する（`bridge._deadline`。root時計が無いと送らず期限切れ）。
  進捗は `OPERATION_UPDATE` event で知り、`GET /v1/operations/{id}` は終了したoperation（displayは変化ごと）にだけ呼ぶ。
  期限後に1.5秒ごとの安全pollを行い、期限+8秒で見切る（見切った operation も、Host がその後その operation について event を出せば
  最大3回まで読み直し、受領が出ていれば late として記録する）。
- **client epoch**: Host は **CLOSED な epoch の** FINAL operation だけを（`operation_retention_ms`、既定7日後に）消す。1つの epoch を
  セッション中開けたままにすると、1 s loop の ping が Host DB を際限なく太らせ（4 node で約34万件/日）、落ちると OPEN の epoch が
  残る（principal あたり64）。fieldview は **30分または5000要求ごとに epoch を回転**する: 新しい epoch を開き、古い方は飛行中の要求
  にだけ使い（要求は作った時の epoch を保ち、同じ key の再送も同じ epoch）、その要求と operation が終わったら close する。
  開いている epoch の id は `<logs-dir>/epochs-<consumer>-<domain先頭8>.json` に（要求を出す前に）書き、**次の起動で前回の取り残しを
  close** する。正常終了は全部 close する。回転しても、閉じた epoch は operation が消える7日後まで Host に残る（約50〜100個/日 x 7日 = 最大およそ700個。Host の
  `max_epochs_per_principal` は1024）。回転の間隔を詰めすぎると、この上限に近づく。epoch を開く POST の応答が無いときも同じ key で再送し、同じ epoch を得る。
- **unknown の根拠**: 同じ key の再送は、Host が保存した operation をそのまま返す（`api/routes.py` → `ops.accept` は保存済みの照会を
  precheck より先に行う）。再送が `400 EXPIRED` / `410 EPOCH_CLOSED` なら Host はその key を持っていない（= not sent）と分かる。
  429/5xx/応答なしでは分からないので unknown のまま。
- **`queue_mode`**: protocol.md §3.2/3.3 は APPLIED + LATEST + coalesce_key と書くが、Host は LATEST を BEST_EFFORT + VOLATILE
  にしか許さず（`api/models.py`, `api/SEMANTICS.md`）400にする。そのため **FIFO・coalesce_keyなし**で送る。短い期限が古い要求を
  残さない。仕様側の修正が必要（未解決の矛盾としてここに残す）。
- **レート制限**: Host は principal ごとに 20 req/s（burst 40、GETを含む全endpoint）。fieldview は自前のtoken bucket
  （14 req/s, burst 24）を通す。ping loopは `2 x node数 / 間隔 + 3` req/s が14を超える間隔では開始を断り、必要な間隔を示す。
  roundの途中で自前の予算が尽きたpingは送らず not sent（`local request budget`）に数える。待ちの上限（`max_wait`）は
  bucket の lock 待ちも含めた絶対時刻で、過ぎた要求は token が空いていても送らない。Hostの429は not sent で、
  `retry_after_ms` の間は全要求を止める。rateは ping 1件あたり POST 1 + GET 1 なので、roundが重なっても1秒あたりは同じ
  （重なるのは open operation の数: 最大 `node数 x min(3, ceil(3 s / 間隔))`）。
- **command_seq**（display）: 起動時のUNIX秒から+1ずつ（nodeがNVSに前回値を持つので、起動をまたいで減らさない）。
- `POST` は `X-Fieldview: 1` ヘッダ、`Host` は 127.0.0.1/localhost のみ受ける（別のWebページからの操作を防ぐ）。

## 限界（未検証・既知）

- Host が evidence に `observed_mono_ms` を載せるまで（現状 bridge は載せない）、RTT は **ノートPCが測った値**（POST → 終了event、
  Host処理・serial・event pollの遅れを含む上限）で、表に `*` が付く。root時計のRTTではない。
- late の検出は **event 駆動**（Host がその operation について event を出したとき）。Host が追記しても event を出さなければ見えない。
  読み直すのは on-time の結果が no answer だった operation だけ（alive の operation を読み直して負荷を倍にしない）。
- unknown の POST が実際に Host に受理されていたか、あとから確かめる手段は fieldview には無い（ping.ndjson の key で Host 側を調べる）。
  epoch を開く POST が unknown のままなら、その epoch は id が分からず fieldview からは閉じられない（Host の open 上限64に数えられる）。
- 実機・実無線・実Host（`parent_device_id` 付き）では未検証。Host と meshsim での通し試験は `host/tests/e2e/test_fieldview_meshsim.py`
  （ptyで、timingの証拠ではない）。
- journal の critical event が溜まるのは fieldview 停止中だけに限らない。ping/display 1件が数件の OPERATION_UPDATE を残す。
  長時間のloopは Host の event 容量に効く（ACKは取り込み後 2 s ごと）。
- 同時に開ける open operation は512件まで（超えると ping は not sent、display は拒否）。nodeの上限は Host の `limits.members`（64）。
  メモリ上の表はすべて有界: node別の表は256件（Host の一覧に無い node から古い順に捨てる）、終了済み operation の履歴は2048件、
  event log 500行、round 30、node別の ping 履歴 20 / RTT 200、未ACKのページ 64（超えると併合）、record queue 20000行。

## テスト

```sh
~/.cache/leanmesh/host-venv/bin/python -m pytest host/tests/unit/test_fieldview_core.py host/tests/unit/test_fieldview_fake_host.py \
    -q -p no:cacheprovider --basetemp=/tmp/claude-501/pt-fv
LEANMESH_NATIVE_BUILD=~/.cache/leanmesh/native ~/.cache/leanmesh/host-venv/bin/python -m pytest \
    host/tests/e2e/test_fieldview_meshsim.py -q -s -p no:cacheprovider --basetemp=/tmp/claude-501/pt-fv
/tmp/claude-501/ruffvenv/bin/ruff check tools/fieldview host
```
