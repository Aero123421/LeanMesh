# アーキテクチャ（1ページ）

設計の正本は [docs/02](../02-architecture.md)。実装での分担と決定は [docs/IMPLEMENTATION.md](../IMPLEMENTATION.md)（§13 に判断の履歴）、
数値の妥協は [ADR-002](../../decisions/ADR-002-budget-status.md)。ここは地図です。

## 1. owner / worker / app

```text
 app task(s)            mesh owner (1 task)                  slow-job worker (1 task)
 ───────────           ─────────────────────────            ───────────────────────────
 lm_send() ─┐          Engine::step(now)                    EDHOC steps, sign/verify,
 lm_next_event()◄─┐      queues, peers, routes, timers        Store (Flash) I/O
            │     │      TX/RX, AES-GCM per frame                   ▲   │ completion
   OwnerCall│     │            │       ▲                            │   ▼ (slot generation + job_id)
   (bounded)▼     │      ports │       │ poll                  Jobs.submit   Jobs.poll
        Engine::execute(Command) ──► Radio::transmit ──► [ radio driver ] ──► SpscRing ──► owner
                  │                    Clock ─ Store ─ Jobs        (callbacks only copy + notify)
                  └─► app event queue (overflow ⇒ one LM_EVENT_GAP)

 root only:  USB serial task ⇄ src/serial bridge ⇄ FastAPI Host ⇄ SQLite
```

| 役 | 仕事 | しないこと |
|---|---|---|
| mesh owner | queue・peer・経路・送受信・timer・frame毎のAES-GCM | P-256、Flash、logging、アプリcallback |
| slow-job worker | EDHOC、署名、Store I/O。1度に公開鍵jobは1つ | ownerの状態を触る、radio |
| app（呼出元task） | `lm_*` と `lm_next_event` | coreのポインタ保持、ACKの捏造 |

- `Engine::step(now)` は次の期限を返して眠ります。固定tickや1/2 ms pollはありません。
- 満杯は `BUSY` / `NO_CAPACITY`で、RF損失とは別扱い。全queue/table/sessionに上限があります。
- jobの完了は `(table_index, job_id)` と slot generation で照合し、遅れて来た結果は捨てます。
- 別々に持つもの: Identity、`assignment_generation`、`membership_generation`、`root_term`、`channel_epoch`、link/end session、アプリbinding。

## 2. 4つのport（テスト差し替え点）

| port | IDF（`src/port/idf`） | sim（`src/port/sim`） |
|---|---|---|
| `Clock` | `esp_timer_get_time` | 仮想時間（任意のppm drift） |
| `Radio` | ESP-NOW（LR250）、callback→ring | `World` 媒体（loss、MAC-ACK loss、遅延、channel） |
| `Store` | NVS `identity`/`state` + 生の `journal` partition | メモリ（電源断で残る、切断注入あり） |
| `Jobs` | worker task、`esp_fill_random` | 仮想遅延、seed付き乱数 |

chipごとの `#ifdef` は `src/port/idf` と radio/OS境界だけです。root専用のUSB serialは第5のI/Oではなくroot限定のadapterです。

## 3. ディレクトリ

| パス | 役割 |
|---|---|
| `api/` | C ABI（`leanmesh.h`）、OpenAPI、意味の契約 |
| `src/core/` | Engine、ports、pool、job、event。`wire` `radio` `link` `member` `route` `delivery` `sched` `group` `channel` `power` `diag` `ota` は**I/Oなし**のfeature module |
| `src/security/` | PSA wrapper、record層、EDHOC suite 3 glue（C）、COSE |
| `src/store/` | 2-slotの封印record、boot incarnation、journal |
| `src/root/`、`src/serial/` | root限定: topology、ledger、group、channel coordinator、lifecycle / USB serial + bridge |
| `src/capi/` | `lm_*` の入口（検証してownerへ渡すだけ） |
| `src/port/{idf,sim}/` | 上記port |
| `src/hostnative/` | Host用のC共有ライブラリ（同じsecurityソース） |
| `components/leanmesh/` | IDF component（Kconfig: profile、RF承認、OTA、object） |
| `firmware/` | `baseline_espnow`、`example_node`、`crypto_link_check` |
| `tools/` | `meshsim`（シミュレータ）、`lmfleet`（TEST-ONLY発行者）、`lmtool`、`budget_probe` |
| `host/leanmesh_host/` | FastAPI: `api/` `db/` `bridge/` `events/` `serial/` `wire/` |
| `tests/native/`、`host/tests/` | ctest / pytest |
| `config/`、`protocol/`、`db/` | profiles・defaults / registry・CDDL / SQLite schema。定数は生成される |

数値・ID・型は `protocol/registry.json`、`config/{profiles,defaults}.json` が正本で、ビルド時に `gen/*.hpp` へ生成されます。手で書き写しません。

## 4. 決定はどこにあるか

| 知りたいこと | 場所 |
|---|---|
| 何を作る・作らない | [docs/01](../01-requirements.md)、[ADR-001](../../decisions/ADR-001-small-by-single-path.md) |
| 所有権・排他 | [docs/02](../02-architecture.md)、IMPLEMENTATION §2〜§4 |
| 暗号（EDHOC suite 3 / PSA） | [docs/06](../06-security.md)、IMPLEMENTATION §5・D1〜D2 |
| 仕様の隙間への判断（D1〜D16、S*-D*、SEC-D*、ARCH-D*） | IMPLEMENTATION §10・§13 |
| 資源の現状と超過の理由 | [ADR-002](../../decisions/ADR-002-budget-status.md)、[docs/16](../16-budgets.md)、`build-records/budget-report.md` |
| 実装ルール | [AGENTS.md](../../AGENTS.md)、[docs/15](../15-coding-standards.md) |
