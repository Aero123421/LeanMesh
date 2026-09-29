# 10 Device API（C ABIを唯一の正本にする）

## 1. 契約
`api/leanmesh.h` はcompile可能な宣言ファイル。実装は含まない。C++ wrapperはこのC APIを呼ぶ薄いinlineで十分で、CだけJoin/APPLIEDが使えない状態を作らない。拡張されるrequest/snapshot structにstruct_size/abi_version。固定幅ID・sleep ticket・workspace寸法のvalue structはその例外としてheaderの定義に固定。integer widthを固定しreserved=0を必須とする。ABI_VERSION=2。v0.2はheaderの既知サイズと完全一致だけを受理する。将来のtail拡張受理は次ABIの互換表で追加するまで行わない。不明な必須flagはUNSUPPORTED。

## 2. 初期化と寿命
`lm_workspace_required(config)`が必要な配置領域size/alignmentを返す。`lm_init(workspace,size,config,&ctx)`は検査と構築だけでRF送信しない。`lm_start`は非同期でSTARTED/FAULTを通知。stopはdeadline付きdrain、destroyはstop完了後のみ。ctxとworkspaceはdestroyまで有効。IDF portは必要なtask/ringを初期化し、それ以降coreでheap allocationをしない。
全通常public APIはtaskから呼ぶthread-safeの有界受付。ISRからの呼出不可。eventは`lm_next_event(ctx,out,payload,capacity,&required)`でcaller側へcopy。容量不足はBUFFER_TOO_SMALL、eventを消費しない。appが遅い場合にもradio ownerを止めずevent_gapを記録しsnapshot/get_operationで再同期。

## 3. 非同期操作
send/join/leave/transfer/group/policy/channel/objectの受付はoperation_id64を返す。受付エラーなら仕事は存在しない。operation_idはctx session内のhandle、再起動をまたぐ照会は完全なlm_message_ref_t（origin DeviceId + assignment_generation + MessageId + intent_hash）またはrequest_id16。異なる送信元のMessageIdが同じでも混同しない。payloadはOK復帰前に固定poolへcopy。callerは復帰直後解放できる。zero-copy寿命管理APIを最初から増やさない。
`lm_get_operation`でphase、evidence、reason、MessageId、outcomeを返す。`lm_cancel`は未送信ならCANCELLED_NOT_SENT、送信の可能性があればCANCEL_TOO_LATE/INDETERMINATE。遠端undoではない。

## 4. send
requestにdestination（DeviceId/group/root app）、port、delivery/storage/priority/queue_mode、coalesce_key64、deadlineを指定。short addressをアプリの永続宛先にしない。最大512B、object API有効時4096B。
DURABLEは予めjournal capacityを予約。APPLIEDは受信アプリの`lm_report_application_result`を待つ。サンプルは`examples/application.c`。副作用を起こす前にアプリpayload内の世代番号を検査し、自分の保存/実機ACKが揃ってからresultを返す。

## 5. lifecycle
- `lm_membership_get` / `lm_connectivity_get`：07の独立状態とfull identityを返す。
- `lm_join`：初回/既存復帰/transfer-candidate、target_domain制約、budget、request_id。
- `lm_leave`：DRAIN/IMMEDIATE。鍵とpendingの扱いは07。
- `lm_install_control`：署名済みAssignmentTicket/ExpectedSet/Policy/ChannelPlan/RootDelegationをtype付きで受ける。署名検査・権限・revision照合を省略不可。
- `lm_policy_get/set`：expected_revision必須。06の暗号条件を低セキュリティへ変えるflagは存在しない。
- `lm_channel_request`：auto/freeze/recalculateはrootへ認可要求。radioを直接操作しない。

## 6. diagnosticsとsleep
`lm_get_capabilities`はbuild/implemented/qualified/enabledを分ける。payload_capacityは最大path条件とsingle-frame現在pathの両方を返す。chip名で推測しない。
`lm_diagnostics_get`はvalidity bitsを持ち、不明は0と別に表す。reset cause、peer使用数、retry、loss、queue、CPU、stack、energy指標、current/pendingchannelと世代を公開する。
`lm_sleep_prepare`は非同期operationを返し、その完了後にpolicyとpending処理に合意した一回限りticketを取得する。新DATA/未終了commitが入ればticketを失効。`lm_sleep_enter`はticket世代を再検証し、直前のpendingを無視して眠らない。

## 7. エラーの互換性
番号はregistry固定。未知のHost response fieldは無視、未知error codeは汎用REMOTE_ERRORとして保持。unknown mandatory feature/悪形式/署名不一致は拒否。未知errorをSUCCESSへ変換しない。C ABIとHostで同じreason意味を使い、任意文字列だけを唯一の根拠にしない。

### Sleepの非同期境界
`lm_sleep_prepare`はoperationを返し、drain/Flash保存を内部workerへ依頼して即returnする。`lm_get_operation`の完了を確認して`lm_sleep_ticket_get`で一度だけticketを取得し、`lm_sleep_enter`へ渡す。準備中はBUSY、失敗ではticketを発行しない。新DATA/commit/role変更でticketを失効する。C APIにsleep中のblocking Flash待機を隠さない。

### 宛先別容量とrequest照会
`lm_payload_capacity(ctx,destination,&bytes,&hops)`は既知の有効経路の容量を返す。groupはsnapshotの最小容量/最大hop、未解決はNO_ROUTE。capabilities.available_single_frame_bytesは全supported pathに共通な下限56Bであり、最後に送った宛先の状態ではない。`lm_get_request`はJoin/移設等のdurable request_id照会、受信/送信messageは完全message_refを使う。保持期限外はNOT_FOUNDと保存範囲を明示する。

### group構成
`lm_group_set`はrootの管理appまたは明示委任された管理主体だけが使える。通常Nodeでも設定済みgroupへのsendは使えるが、管理権限を自動的には得ない。groupに含まれないrelayも中継できる。公開group操作にKGの設備/個室IDを入れない。

## spec0.2: power / group API
`lm_power_policy_get/set`はmode、wake/search/radio予算、受信窓、pending方針を扱う。setはexpected_revisionを照合し非同期operationを返す。`lm_power_get`は診断snapshot、測定されていない値はvalidity bitを立てない。
`lm_sleep_prepare_ex`はLIGHT/DEEP、wake source mask、予定sleep時間、awake budget、pending方針を受ける。GPIO等のboard設定はappが先に準備する。`lm_sleep_abort`はticketを失効し通常状態へ戻す。旧sleep_prepareは設定済みpolicyの薄いwrapperで別実装を持たない。
`lm_group_progress`は対象ごとの現在outcomeを重複なしで集計する。`lm_group_targets`は同snapshot tokenのoffsetから最大16件をcaller配列へcopyする。容量不足はBUFFER_TOO_SMALL、pageの取出しは破壊しない。targetが失効してもsnapshotから消さず拒否結果を残す。
power enumはALWAYS_RX0/WINDOWED_RX1/REPORT_ONLY2。diagnosticsのnext_wake_qualityはUNKNOWN0/ESTIMATED1/BOUNDED2。flags/reservedは0。C ABI2を持たないcallerはUNSUPPORTEDで拒否し、structサイズを推測して読まない。
