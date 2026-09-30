# Device API（C）の使い方

正本は [api/leanmesh.h](../../api/leanmesh.h)（ABI 2）と [docs/10](../10-device-api.md)。ここは使い方の要約です。
全 struct は `memset` 0 の後に `struct_size = sizeof` と `abi_version = LM_ABI_VERSION` を入れます（ABIが違えば `UNSUPPORTED`、サイズが違えば `INVALID_ARGUMENT`）。
全 `lm_*` はタスクから呼べる有界の受付で、ISRからは呼べません。ペイロードは復帰前にSDK内へコピーされるので、直後に解放できます。

## 1. 初期化・開始・停止

```c
#include "leanmesh.h"
#include <string.h>

/* IDF の例。firmware/example_node/main/main.c と同じ手順。 */
lm_status_t app_init(lm_context_t **out) {
  lm_config_t cfg;
  lm_workspace_size_t ws;
  lm_status_t st = lm_config_init(&cfg, sizeof cfg); /* role は「このイメージの最大profile」 */
  if (st != LM_STATUS_OK) return st;
  cfg.role = LM_ROLE_LEAF;                            /* LEAF / RELAY / ROOT。build上限を超えると ROLE_NOT_ALLOWED */
  st = lm_workspace_required(&cfg, &ws);
  if (st != LM_STATUS_OK) return st;
  void *mem = platform_alloc_aligned(ws.alignment, ws.bytes); /* IDF: heap_caps_aligned_alloc(..., MALLOC_CAP_INTERNAL) */
  if (mem == NULL) return LM_STATUS_NO_CAPACITY;
  st = lm_init(mem, ws.bytes, &cfg, out);             /* RFは送らない。tasksを作る */
  if (st != LM_STATUS_OK) return st;
  return lm_start(*out);                              /* RF_PROFILE_UNAPPROVED ならradioは起動しない */
}

lm_status_t app_shutdown(lm_context_t *ctx) {
  lm_operation_id_t drain = 0;
  lm_status_t st = lm_stop(ctx, 2000, &drain);        /* drain==0: 待つものは無かった */
  if (st != LM_STATUS_OK) return st;
  return lm_destroy(ctx);                             /* stop後のみ。ctxとworkspaceはここまで有効 */
}
```

- `lm_init` の前に NVS 等の IDF 初期化が必要です。1デバイス1 context（2回目は `BUSY`）。
- Kconfig `LEANMESH_RF_DEPLOYMENT_APPROVED` は既定 n です。**適合記録のある製品ビルドだけ**が y にします。n のとき `lm_start` は `RF_PROFILE_UNAPPROVED`（13）を返し、無線は上がりません。
- `config.object_transfer_enabled=1` は Kconfig `LEANMESH_OBJECT_TRANSFER=y` のビルドだけ（それ以外は `UNSUPPORTED`）。

## 2. 端末の身元（provisioning）

C API に provisioning 関数はありません。端末は `identity` / `state` パーティションの封印record（端末鍵、fleet署名のDeviceCredential、trust anchor、RootDelegation、必要ならMemberCredential）を起動時に読みます。
- **量産用の書込みツールはこのリポジトリにありません。** あるのは sim/bench 専用の `tools/lmfleet`（TEST-ONLY発行者）と meshsim の `provision` コマンドだけで、その鍵を製品へ入れてはいけません。
- 保存領域の読み取り失敗を「未provision」とは扱いません（`lm_init` はStore初期化の失敗をそのまま返し、fail closed）。
- 端末の `DeviceId`、`assignment_generation`、`membership_generation` は別物です（`lm_membership_get`）。

## 3. Join・所属

```c
lm_status_t app_join(lm_context_t *ctx, const uint8_t request_id[16], lm_operation_id_t *op) {
  lm_join_request_t r;
  memset(&r, 0, sizeof r);
  r.struct_size = sizeof r; r.abi_version = LM_ABI_VERSION;
  memcpy(r.request_id.bytes, request_id, 16);  /* 再送しても同じrequest。lm_get_request() で照会できる */
  r.mode = LM_JOIN_NEW;                        /* LM_JOIN_RESUME / LM_JOIN_TRANSFER_CANDIDATE */
  r.search_budget_ms = 30000;                  /* 探索に使う上限 */
  return lm_join(ctx, &r, op);
}

int app_is_active(lm_context_t *ctx) {
  lm_membership_t m;
  memset(&m, 0, sizeof m);
  m.struct_size = sizeof m; m.abi_version = LM_ABI_VERSION;
  return lm_membership_get(ctx, &m) == LM_STATUS_OK && m.state == LM_ACTIVE;
}
```

承認は root 側です（Host の `POST /v1/control` `JOIN_DECISION`、または join-mode preapproved）。`LM_APPROVAL_PENDING` は正常な待ちです。
`lm_leave(ctx, LM_LEAVE_DRAIN|LM_LEAVE_IMMEDIATE, deadline_ms, &op)` で離脱。署名付きobject（移設ticket等）は `lm_install_control(ctx, type, cbor, len, &op)`。移設ticketは先に `lm_transfer_nonce_get()` のnonceを名指す必要があります（RAM保持、再起動で失効）。

## 4. 送信

```c
lm_status_t app_send(lm_context_t *ctx, const lm_device_id_t *to, uint32_t root_term,
                     uint64_t expires_root_ms, const uint8_t *p, size_t n, lm_operation_id_t *op) {
  lm_send_request_t r;
  memset(&r, 0, sizeof r);
  r.struct_size = sizeof r; r.abi_version = LM_ABI_VERSION;
  r.destination.kind = LM_DEST_NODE; r.destination.node = *to;   /* LM_DEST_GROUP / LM_DEST_ROOT_APP */
  r.app_port = 100;                                              /* アプリ定義。SDKは意味を解釈しない */
  r.delivery = LM_APPLIED;                                       /* LM_BEST_EFFORT / LM_RECEIVED / LM_APPLIED */
  r.storage = LM_VOLATILE;                                       /* LM_DURABLE: 送信元journalに保存 */
  r.priority = LM_PRIORITY_NORMAL;                               /* CONTROL は外部アプリ不可 */
  r.queue_mode = LM_FIFO;                                        /* LM_LATEST: BEST_EFFORT+VOLATILE+coalesce_key */
  r.root_term = root_term; r.expires_root_ms = expires_root_ms;  /* root時計基準。APPLIEDは有限期限が必須 */
  return lm_send(ctx, &r, p, n, op);                             /* <=512 B。4096 B は lm_send_object */
}
```

- 受付に失敗した（`!= OK`）なら仕事は存在しません。`OK` は「受理」だけです。
- 期限は初回送信前と再送前に確認されます。判定できないときは `TIME_UNCERTAIN`、過ぎていれば `EXPIRED`。
- 1 frame に入る大きさは `lm_payload_capacity(ctx, &dest, &bytes, &hops)`（未解決の宛先は `NO_ROUTE`）。`strict_single_frame=1` は分割を禁止します。
- 期限は `root_term` + `expires_root_ms`（root時計基準）です。現在のroot時計の推定は `lm_root_time_get` で読みます。`valid=0`（推定なし）の間、期限付き送信は `TIME_UNCERTAIN` になります。rootが再起動して term が変わると旧termの期限は無効です。

```c
lm_status_t app_deadline(lm_context_t *ctx, uint64_t validity_ms, uint32_t *term, uint64_t *expires) {
  lm_root_time_t t;
  memset(&t, 0, sizeof t);
  t.struct_size = sizeof t; t.abi_version = LM_ABI_VERSION;
  lm_status_t st = lm_root_time_get(ctx, &t);
  if (st != LM_STATUS_OK) return st;
  if (!t.valid) return LM_STATUS_TIME_UNCERTAIN;   /* 推定が無い。待つか、期限なしで良い種類のデータだけ送る */
  *term = t.root_term;
  *expires = t.earliest_root_ms + validity_ms;     /* [earliest, latest] の早い側から数える（延ばす側に丸めない） */
  return LM_STATUS_OK;
}
```

- Host経由の送信は UTC 期限も受け付けます（[host.md](host.md)）。

## 5. 結果（証拠）の読み方

```c
const char *app_classify(const lm_operation_t *o) {
  switch (o->outcome) {
    case LM_OUTCOME_APPLIED:        return "相手アプリが適用と報告";
    case LM_OUTCOME_RECEIVED:       return "相手が保存した（適用は未確認）";
    case LM_OUTCOME_REJECTED:       return "相手（網かアプリ）が拒否。o->reason";
    case LM_OUTCOME_EXPIRED:        return "期限切れ";
    case LM_OUTCOME_CANCELLED_NOT_SENT: return "未送信のまま取消";
    case LM_OUTCOME_INDETERMINATE:  return "結果不明。同じ副作用を盲目的に再送しない";
    case LM_OUTCOME_PENDING:        return "まだ";
    default:                        return "SUPERSEDED / PARTIAL / SUBMITTED";
  }
}

lm_status_t app_poll_op(lm_context_t *ctx, lm_operation_id_t op, lm_operation_t *o) {
  memset(o, 0, sizeof *o);
  o->struct_size = sizeof *o; o->abi_version = LM_ABI_VERSION;
  return lm_get_operation(ctx, op, o);   /* 再起動後は lm_get_message(ref) / lm_get_request(id) */
}
```

`outcome` は結論、`evidence_bits` は**実際に観測した事実**です。互いに推定で埋めません。bitはheaderに無く、`src/core/delivery/types.hpp` の `ev::` が定義です（追加のみ・変更しない）。

| bit | 意味 |
|---|---|
| 0 accepted | APIが受理（RAMのみ） |
| 1 persisted | 送信元journalにcommit |
| 2 sent | 少なくとも一度radioへ渡した（出た可能性） |
| 3 hop_accepted | 最初のhopがbufferを確保（HOP_ACK） |
| 4 end_received | 宛先が保存した（終端受領） |
| 5 app_pending / 6 app_applied / 7 app_rejected | 宛先アプリの応答 |
| 8 refused | 宛先の網層が拒否 |

`phase`（Pending0/Sending1/WaitingReceipt2/Final3）も同様に内部定義です。`lm_cancel` は未送信なら `CANCELLED_NOT_SENT`、送信の可能性があれば `CANCEL_TOO_LATE`（遠端のundoではない）。

## 6. 受信と適用の報告

```c
#define PORT 100u
unsigned app_drain_events(lm_context_t *ctx, int (*apply)(const uint8_t *p, size_t n)) {
  unsigned n_done = 0;
  for (;;) {
    lm_event_t ev;
    uint8_t buf[LM_MAX_MESSAGE_BYTES];              /* 小さいと BUFFER_TOO_SMALL でeventは消費されない */
    size_t need = 0;
    memset(&ev, 0, sizeof ev);
    ev.struct_size = sizeof ev; ev.abi_version = LM_ABI_VERSION;
    if (lm_next_event(ctx, &ev, buf, sizeof buf, &need) != LM_STATUS_OK) return n_done; /* NOT_FOUND=空 */
    if (ev.kind == LM_EVENT_GAP) { /* eventを取りこぼした。lm_get_operation等で再同期 */ continue; }
    if (ev.kind != LM_EVENT_MESSAGE || ev.app_port != PORT) continue;
    /* 1. 検証と実I/Oを先に行う  2. その確認が取れてから報告する */
    uint32_t outcome = apply(buf, need) == 0 ? LM_OUTCOME_APPLIED : LM_OUTCOME_REJECTED;
    lm_message_ref_t ref;
    memset(&ref, 0, sizeof ref);
    ref.origin = ev.peer;
    ref.assignment_generation = ev.origin_assignment_generation;
    ref.id = ev.message_id;
    memcpy(ref.intent_hash, ev.intent_hash, sizeof ref.intent_hash);
    if (lm_report_application_result(ctx, &ref, outcome, NULL, 0, NULL) == LM_STATUS_OK) n_done++;
  }
}
```

結果payload（`LM_MAX_APP_RESULT_BYTES`=32）は送信元へ戻ります。完成例（世代番号で古い命令を拒否）は [examples/apps/equipment_control.c](../../examples/apps/equipment_control.c)、[battery_measurement.c](../../examples/apps/battery_measurement.c)。
再送はexactly-onceを保証しません。アプリ側で世代/revisionを検査して冪等にします。

## 7. group・power・channel

```c
lm_status_t app_group_send(lm_context_t *ctx, uint32_t gid, uint64_t rev, uint32_t term, uint64_t exp,
                           const uint8_t *p, size_t n, lm_operation_id_t *op) {
  lm_send_request_t r;
  memset(&r, 0, sizeof r);
  r.struct_size = sizeof r; r.abi_version = LM_ABI_VERSION;
  r.destination.kind = LM_DEST_GROUP; r.destination.group_id = gid; r.destination.group_revision = rev;
  r.app_port = 100; r.delivery = LM_APPLIED; r.storage = LM_VOLATILE;
  r.priority = LM_PRIORITY_NORMAL; r.queue_mode = LM_FIFO;
  r.root_term = term; r.expires_root_ms = exp;
  return lm_send(ctx, &r, p, n, op);   /* 事前登録revisionをsnapshot化。編集しても送信済みfan-outは旧snapshotを完走 */
}

lm_status_t app_group_progress(lm_context_t *ctx, lm_operation_id_t op, lm_group_progress_t *g) {
  memset(g, 0, sizeof *g);
  g->struct_size = sizeof *g; g->abi_version = LM_ABI_VERSION;
  return lm_group_progress(ctx, op, g);  /* 件数の和 == total。個別は lm_group_targets（16件/page） */
}
```

- group構成は `lm_group_set(ctx, gid, expected_revision, members, count, &op)`（最大8 group・64人、管理権限のあるappのみ）。0人は空集合で「全員」ではありません。
- group の DURABLE / LATEST は未対応（`UNSUPPORTED`）。

```c
lm_status_t app_report_only(lm_context_t *ctx, lm_operation_id_t *op) {   /* examples/low_power.c の要約 */
  lm_power_policy_t p;
  memset(&p, 0, sizeof p);
  p.struct_size = sizeof p; p.abi_version = LM_ABI_VERSION;
  lm_status_t st = lm_power_policy_get(ctx, &p);
  if (st != LM_STATUS_OK) return st;
  uint64_t expected = p.revision;
  p.revision = expected + 1u;
  p.mode = LM_POWER_REPORT_ONLY;         /* ALWAYS_RX / WINDOWED_RX / REPORT_ONLY */
  p.wake_interval_ms = 60000; p.rx_window_ms = 250; p.max_rx_window_ms = 1500;
  p.pending_policy = LM_PENDING_SAVE_AND_SLEEP;
  return lm_power_policy_set(ctx, &p, expected, op);
}

lm_status_t app_sleep(lm_context_t *ctx) {
  lm_sleep_request_t q;
  lm_operation_id_t op = 0;
  lm_sleep_ticket_t t;
  memset(&q, 0, sizeof q);
  q.struct_size = sizeof q; q.abi_version = LM_ABI_VERSION;
  q.sleep_kind = LM_SLEEP_DEEP; q.wake_source_mask = LM_WAKE_TIMER;
  q.requested_sleep_ms = 60000; q.awake_budget_ms = 15000;
  q.pending_policy = LM_PENDING_SAVE_AND_SLEEP;
  lm_status_t st = lm_sleep_prepare_ex(ctx, &q, &op);
  if (st != LM_STATUS_OK) return st;
  do {
    st = lm_sleep_ticket_get(ctx, op, &t);   /* BUSY=準備中（drain/Flash保存）。待ち方はappが決める */
    if (st == LM_STATUS_BUSY) platform_delay_ms(5);
  } while (st == LM_STATUS_BUSY);
  if (st != LM_STATUS_OK) return st;          /* 失敗ならticketは無い */
  return lm_sleep_enter(ctx, &t);             /* 新RX/commitでticket失効: SLEEP_TICKET_STALE。その時は眠らない */
}
```

- 変更は必ず `expected_revision` 付き（古ければ `CONFLICT`）。`lm_sleep_abort(ctx, op)` でticketを失効。GPIOなどboard設定は先にappが準備します。
- Deep Sleep復帰は通常fresh EDHOCです（鍵だけのRTC高速復帰は未実装）。`lm_power_get` の値は測定されたものだけ `validity_bits` が立ちます。
- channel: `lm_channel_request(ctx, LM_CHANNEL_FREEZE|LM_CHANNEL_AUTO|LM_CHANNEL_RECALCULATE, expected_revision, &op)` は**root専用**（他は `UNSUPPORTED`）。radioを直接操作せず、rootのcoordinatorへの要求です。op が 0 のときは受理時点で適用済みです。

## 8. 診断・能力・エラー

```c
int app_can_group(lm_context_t *ctx) {
  lm_capabilities_t c;
  memset(&c, 0, sizeof c);
  c.struct_size = sizeof c; c.abi_version = LM_ABI_VERSION;
  if (lm_get_capabilities(ctx, &c) != LM_STATUS_OK) return 0;
  return (c.enabled_bits & LM_FEATURE_GROUP_FANOUT_V2) != 0; /* build / implemented / qualified / enabled は別 */
}
```

`qualified_bits` は現在どのbuildでも0です（実機認定なし）。`lm_diagnostics_get` は `validity_bits` が立った項目だけ有効で、不明は0と区別されます。

| 状態コード | 扱い |
|---|---|
| `BUSY` `NO_CAPACITY` `RATE_LIMITED` | ローカルの一時不足。RF損失ではない。待って再試行 |
| `NO_ROUTE` `AUTH_PENDING` `RX_WINDOW_CLOSED` `PEER_ASLEEP` | 状態待ち。所属は消えていない |
| `EXPIRED` `TIME_UNCERTAIN` `DEADLINE_UNREACHABLE` | 期限。副作用命令は新しい判断で作り直す |
| `CONFLICT` `TARGET_GENERATION_CHANGED` `CURSOR_GAP` | 世代/revisionが古い。読み直してから |
| `REVOKED` `STORAGE_FAILURE` `RECOVERY_REQUIRED` | 自動再試行しない。運用介入 |
| `UNSUPPORTED` `ROLE_NOT_ALLOWED` `INVALID_ARGUMENT` `PAYLOAD_TOO_LARGE` | 呼び出し側の誤り/この構成に無い機能 |

## 9. このbuildで未実装の宣言

`lm_connectivity_get`、`lm_policy_get`、`lm_policy_set` はheaderに宣言がありますが**実装がありません**（呼ぶとリンクエラー。偽の成功は返しません）。
`lm_init` / `lm_destroy` は ESP-IDF port（`src/port/idf`）にあり、native では meshsim の `SimNode` が代わりに context を作ります。
