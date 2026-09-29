# 20 Low power — 起床から再入眠までを設計する

**規範章 / spec 0.2。13章の省電力を具体化する。数値は設定初期値または認定条件であり、実機の電流・電池寿命の実測値ではない。**

## 1. 運用の選択と不変条件

ネットワーク上のrole（LEAF/RELAY/ROOT）とpower modeを別の型で表す。

|mode|用例|受信・中継契約|
|---|---|---|
|ALWAYS_RX|中継、随時操作する機器|radioを通常受信可能に維持。SDKのidle CPUは休ませる。|
|WINDOWED_RX|定期的に命令も受ける電池端末|認証された起床pollの後の窓で受信。窓外の即時配送は保証しない。|
|REPORT_ONLY|タイマー/外部イベントで起きる計測端末|有限の活動予算内で上りと短い下り窓を処理し、再入眠。|

RELAY/ROOTはALWAYS_RXのみ。LEAFにアプリを載せたままALWAYS_RXも選べる。batteryという機器名からmodeを推測しない。未来の同期sleep中継は本版に入れない。無線電力節約、CPUのDFS、明示Light Sleep、Deep Sleepは異なる仕組みであり、名前を同義にしない。[E-PWR-01,E-PWR-02,E-PWR-03]

power policyは`config/power.schema.json`、初期値例は`config/power.*.json`を正本とする。policy変更はexpected_revisionによるCAS。新policyのrevisionはexpected_revision+1、CBOR outer revisionも同じ値とする。u63上限到達時は更新を拒否し、wrapしない。権限とroleと能力を検査し、適用を完了するまで旧policyが有効。必須capability不足はUNSUPPORTEDであり、黙ってALWAYS_RXへ戻して電池を消耗させない。

## 2. 一回の活動を有界にする

REPORT_ONLYの1episode:

`WAKE → CHECK_STATE → RESTORE_OR_AUTH → SEND → RECEIVE_WINDOW → QUIESCE → SLEEP`

全状態に同じ`episode_end_mono`を渡す。route修復、channel変更検出、暗号再試行で予算をリセットしない。完了しなければ「未送信/不明/次回再試行」を保存する。wakeの原因がセンサーであることはアプリが指定し、SDKは業務的重要度を本文から推測しない。

|設定|REPORT_ONLY初期例|意味|
|---|---:|---|
|awake_budget_ms|15000|SDK開始から通信整理の開始までを含む通常活動予算|
|shutdown_reserve_ms|500|活動予算内に先取りする停止・必要保存時間|
|search_budget_ms|1000|1episode内の追加探索上限。通常の30秒Join探索より厳しい|
|rx_window_ms|250|上り後/起床poll後の初期下り窓|
|max_rx_window_ms|1500|同episode内で許せる連続受信窓の上限|
|retry_min_ms / retry_max_ms|60000 / 3600000|失敗後の再起床間隔の範囲|
|offline_radio_ms_per_hour|60000|圏外探索・再認証に費やすradio-on時間の時間予算|
|shutdown_overrun_limit_ms|2000|入眠を強行できない故障時の検知しきい値。保証上限ではない|

すべて構成可能だがschema上限を超えない。小さい予算でも20hopの認証・往復が必ず完了するとは保証しない。開始前に測定済みp95 job時間と停止予約を照合し、明らかに完了不可な追加jobを始めない。実機のdriver/Flashが停止不能になった場合はbudget_overrunを記録し、watchdog/管理復旧へ進む。原子的な保存の途中で強制sleepして整合性を壊さない。

## 3. 一つの受信窓方式: leaf主導poll

全端末の高精度な時刻同期を必須にしない。leafが起きた時、**認証済み直結parentとのlink**へPOWER/AWAKE_POLLを送り、parentがAWAKE_GRANTを返す。通常のDeep Sleep復帰でlink sessionを失っていれば先にEDHOCを行う。未認証pollを可用性/配送/本人の証拠にしない。

1. leafは自身のlocal monotonic clockで受信窓開始を記録し、window_msと受信creditを通知する。
2. parentはnonceに結合したGRANTで、保管済みframe数、与えるcredit、window durationを返す。
3. parentは少なくとも`guard_ms`を差し引いた窓内に収まるframeだけ送る。送信後のMAC ACKだけで受理完了にしない。
4. leafは窓終了またはepisode予算で整理へ進む。残件数を理由に無期限に延長しない。
5. 失われたGRANTは同じpoll_nonceで初回を含む最大2試行まで照会可能。窓開始・終了は最初のpollのままで延長しない。

POWERの短い固定byte形式は`protocol/power.cddl`およびregistryの`power_poll/power_grant`。frame kind=8、link AEAD必須。全domainへのbroadcastではなく直結parentとの通信で、rootへ毎窓転送しない。

WINDOWED_RXもこの方式を使う。driverのconnectionless wake window機能が認定された構成ではwake eventに合わせてpollし、その窓で処理する。未接続STA向けPM設定、wake interval/window、driverの実際の起床時刻はIDF/SoCごとに検査する。単にAPIがESP_OKだったことを省電力達成の証拠にしない。[E-PWR-01,E-PWR-04]

代替の明示RAM保持Light Sleep portを使う場合も、アプリタイマーでwake→radio起動→pollとする。同じwire/stateを使い、第二のMACスケジューラは増やさない。どちらのportを選んだかは診断へ出す。認定されていない自動切替はしない。

## 4. 予定と事実、時刻の扱い

`SleepSchedule`はDeviceId/assignment/membership、root_term、schedule_revision、power_mode、次回起床のroot時刻区間、interval、window、最大保持期間を含む。時刻が不明なら`next_earliest_root_ms=next_latest_root_ms=0`かつquality=UNKNOWN。0を即時起床の意味にしない。

rootは予定を可用性のヒントとして持つ。実際のAWAKE_POLL受信で直結parentがawake factを更新する。以前のscheduleがあることは「今起きている」の証拠ではない。root term変更、membership変更、予定満了、parent変更でヒントをstaleにする。認証とrouting leaseをscheduleだけで延長しない。

window予測のguardは少なくとも`ceil(elapsed_ms * (local_ppm + peer_ppm) / 1e6) + timestamp_error_ms + measured_wakeup_error_ms`。相互clockのdriftを片側分だけで計算しない。必要guard×2がwindow以上なら精密予約をやめてleaf主導pollを待つ。未知driftを0ppmとしない。

長いDeep Sleep後の時刻誤差が未認定なら、旧authorization/key lifetimeの残りを正しいと推測しない。fresh認証とroot timeの再確認へ戻す。

## 5. 下り保管: RAM受理と永続受理を混ぜない

親はsleepy leafごとのframe mailboxを持てるが、上限は設定の`mailbox_frames_per_child`、全体は`mailbox_frames_total`。既定は1子2frame、全体16frame。専用bufferの無制限追加ではなく共有frame poolから借り、CONTROL予約枠を侵食しない。満杯ではcredit=0/NO_CAPACITY、保持期限超過で明示失効。

**parent mailboxはRAM-only。HOP_ACCEPTEDでしかなく、END_RECEIVED/DURABLE_RECEIVEDではない。** 送信元のjournal/Host DBは終端証拠まで原本を保持する。親が再起動してmailboxを失えば送信元が同じMessageIdで再送する。optionalの中継永続custody protocolは本版に増やさない。

Deep Sleep後にend sessionが変わった場合、親mailbox内の旧end ciphertextは新しい鍵で開けない。leafは認証済みlink上でSESSION_REFRESH_REQUIREDを通知し、親は旧copyを破棄、originが原本を同じMessageIdでfresh end sessionへ再封止する。parentに本文復号やend鍵再発行を許さない。deadlineは延長しない。

期限内の次窓が不可能と分かる場合はDEADLINE_UNREACHABLE。予定が不明ならWAIT_WAKE/UNKNOWNで、可用性が不明なことを不可能と断定しない。今起きているtargetsを眠るtargetの順番待ちにしない。配送先のrevoke/移設は全pendingのdispatch直前にも検査する。

## 6. 20hop報告と「ACK待ちで電池を使う」問題

受信保証を得るまで起き続ける方法だけに固定しない。REPORT_ONLYで`pending_policy=SAVE_AND_SLEEP`を選ぶ場合は、**送信元自身のdurable journal**へmessageをcommitしてから送信し、活動予算が尽きたら未完了のまま眠ってよい。

次回wakeに同一MessageId/intent_hashで再送し、終端のdedup/receipt cache/アプリの冪等ledgerで収束する。前回end keyが失われていればfresh sessionで再封止し、論理IDは変えない。途中relay受理だけで成功通知しない。root宛DURABLE履歴は終端DBの同一ID記録から再ACKできる。任意端末宛のreceipt保持上限を過ぎた場合は結果不明が残り得る。

VOLATILEを指定したmessageには電源断耐性を付与しない。APPLIEDを要求した操作の受信側は、自分が睡眠する前にアプリ結果を確定・保存するかPENDINGとして公開し、未実施のままAPPLIEDを作らない。deadlineが過ぎた命令を、後から起床したことを理由に新しい期限で適用しない。

## 7. セッション保持の安全条件

|状況|許される復帰|
|---|---|
|RAMを保持したLight/Modem Sleep|key・送信counter・受信window・peer identity・membership・有効期限を全部保持し、時間経過を安全に上限評価できる時だけ同session|
|Wi-Fi driverだけを再起動、RAM security stateは保持|peer/rate/channelを再登録し、同sessionのcounter/replayをリセットしない|
|通常Deep Sleep/cold boot/watchdog/brownout|traffic keyを復元せずfresh EDHOC。membership承認とは別|
|相手が再起動・SID消失|必要な相手sessionだけ再確立。全網再Joinをしない|
|authorization/key lease切れ・不明|refreshまたはfresh EDHOC。省電力名目でleaseを無期限化しない|

**spec 0.2は独自resume ticket、Flashから古いtraffic keyを戻す高速復帰、RTCへ鍵だけコピーする方式を追加しない。** `rtc_secure_resume`はreserved/implemented=false。これはlow powerを後回しにする意味ではなく、WINDOWED_RXとfresh-EDHOC型REPORT_ONLYを実測比較する設計判断。必要な電池目標に達しなければpower gate不合格とし、別ADRで完全なkey/counter/replay状態の安全なresumeを設計する。未定義の高速復帰を「対応済み」と広告しない。

## 8. 圏外・一斉復電・敵対的入力

圏外再試行は指数backoff+最大20%jitter。保存channel→予定された移行先→同channel予備parent→許可channelの部分探索の順。毎回全channelを2周しない。探索cursorを保持し次episodeで続ける。誤った探索hintだけでmembershipを消さない。

1時間のradio-on budgetを使い切ったら、次の予算窓まで通常のradio再起床を延期する。生存計測だけのためにradioを起こさない。重要入力用の追加wake回数/日と追加radio-on時間/日も有限に設定する。無線でURGENTを名乗っただけの未認証packetに追加電池予算を与えない。

power会計のhour/dayはUTCでなく経過時間窓。RTC連続性を検証できないcold bootでは起動1episodeだけ許可し、残り予算は保守的に0から開始、経過観測に従って補充する。外部からの連続電源断まで電池寿命を保証しない。budgetのcheckpointはepisode終端でまとめ、packetごとのFlash書込みをしない。

cold bootで64台がfresh EDHOCをするCPU負荷はゼロではない。listen-first、起床jitter、同時暗号job上限、control用frame枠で中継を維持する。承認待ち中はephemeral鍵のRAM保持を無制限にせず、認証済みrequest_idを保存してsleepし、次回fresh sessionから照会できる。承認leaseは更新せず元の期限を守る。

## 9. チャネル最適化との協調

surveyは給電されたRoot/Relayが原則担当。sleepy leafを毎回測定要員にしない。channel planの必須参加集合は現在の中継backbone、awake制御対象、明示critical対象を固定する。眠るleafは別のdeferred集合へ入れる。

critical sleepy leafが切替期限まで起きない場合は、その影響を示してplanを延期するか、管理者が明示的にdeferredを許可する。全台原子的切替と誤記しない。leafは次回wakeに旧channelから有界なrecoveryを行う。rootがchannelを数度変更していた場合も最終署名情報/epochで復帰し、古い計画を順番に全実行しない。

探索予算内で到達できないleafはISOLATEDのままsleepし、次episodeへ持越す。自動channel機能があるからといって電池leafの連続scanを許可しない。無線障害時とhost不在時を分け、root firmwareだけで既存policyを実行する。

## 10. sleep準備のAPIとrace

`lm_power_policy_set`でmodeを選び、`lm_sleep_prepare_ex`で今回のsleep種別、wake source、予定sleep時間、活動予算、pending処理方針を渡す。wake GPIO番号やhold設定はboard/appの責任で、SoC間で互換なGPIO番号を作らない。SDKはwake-source capabilityとradio停止の整合性だけを検査する。

prepareでnode state_generationを捕捉→必要journal commit→slow jobの安全点→radio TX完了→ticket発行。ticketは発行後2000msで失効し1回しか使えない。アプリがセンサー/周辺回路を停止した後、sleep_enterがgenerationとpendingを再検査する。新RX、policy変更、未完control commit、role変更でticketを無効化する。アプリ側のsleep vetoは`lm_sleep_abort`で明示し、radio/PM lockを通常状態へ戻す。

既存`lm_sleep_prepare`は設定済みpower policyと既定DEEP/保存方針を使う薄い入口。内部に別のsleep実装を持たせない。ALWAYS_RXで呼ばれた場合はROLE_NOT_ALLOWEDであり、黙って中継を止めない。

## 11. CPU、Flash、周辺機器

ownerは受信/command/最早deadlineによりwakeし、idleで2ms全表pollをしない。sleepy leafは32秒helloや60秒route refreshのために予定外に起きない。期限切れleaseは次の起床時に更新する。microcontroller内の計測周期とMesh送信周期は分離する。

PM lockを各処理の開始/終了に対応付け、成功、timeout、cancel、例外的driver faultの全経路で解放を検査する。公開鍵jobは低priorityで単一、Flash長時間操作は小分け。low frequency化で暗号計算が長くなり総energyが増えることもあるため、CPU MHzだけを評価しない。[E-PWR-03]

LED、USB-UART、LDO、電圧divider、sensor warm-up、I2C pull-up、GPIO leakageをboard全体で測定する。ESP chipのDeep Sleep値をそのまま製品平均電流と呼ばない。UART wakeの最初の文字喪失などSoC固有の条件はboard evidenceに書く。[E-PWR-02]

## 12. 公開する診断と合格の意味

mode、state、policy_revision、wake_reason、next_wake_quality、remaining_awake_ms、budget_remaining_ms、radio_on_us、cpu_active_us、handshake_count、Flash commits、polls、missed_windows、sleep_veto、overrun、last_failureを返す。

測定されていないenergyはnull/validity=false。電力計なしでJを推定した場合はmeasuredではなくestimatedでモデルと誤差を添える。goalsは23章、schemaはconfig、受入LP01〜を参照。

「low power対応」は、4チップのALWAYS_RX/WINDOWED_RX/REPORT_ONLYのcompileと実機、認証復帰、圏外、下り、group、channel移行、電源断、電力計測を通った機能だけに付ける。未認定SoC/board/modeの一覧をcapabilitiesでそのまま公開する。
