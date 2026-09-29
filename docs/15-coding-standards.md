# 15 コーディング規約

## 1. 小ささの定義
短い行数より、状態の所有者数・独立方式数・実行中の仕事数・動的資源数を減らす。C++17のRAII、enum class、std::array、span相当の長さ付きview、小さなconstexprは使う。最適化のために意味が読めないCへ退化させない。
first-party productionのSLOCと生成物/vendor/testを別集計。巨大ファイルを分割しただけ、コードを詰めた1行化、テスト削除は軽量化として報告しない。

## 2. C/C++
- coreは例外/RTTIなし。全fallible関数は[[nodiscard]] StatusまたはResult。errorをログだけ残して成功へ変換しない。
- uint32/64など固定幅と単位名（_ms/_us/_bytes）。時刻型をUTC/Monotonic/RootTime/Durationに分ける。
- クラスは具体型と所有関係を表す。深い継承、runtime plugin、万能event bus、ServiceLocator禁止。
- 同一失敗規則を共有する処理だけ共通化。2つの似たifを消すために8型のtemplate engineを作らない。
- core初期化後のnew/mallocは禁止。crypto vendor内部allocationは専用arena/上限とpeak計測を付けて明示例外。すべてを「heapゼロ」と虚偽表示しない。
- memcpyは検査済みbounds内のみ。wireはread_u16be等の明示codec、packed struct cast禁止。
- callbackは固定buffer copy+notify。strlen/printf/crypto/Flash/アプリ実行禁止。
- 各slotにgeneration。free/reuse後の遅いjob/receiptで新slotへ作用しない。zeroizationは最適化で消えないbackend関数。
- 外部入力にassertでabortしない。内部不変条件のassertは許可。エラー復帰試験を作る。
- 近隣16等の小集合は線形配列を優先し、必要性を測る前にhashmap/mutexを導入しない。

## 3. Python
- 3.12+、public境界と永続DTOは型注釈。Pydantic requestはextra=forbid、response消費は未知field許容。
- async handlerでblocking I/O禁止。serial/DB/cryptoは所有threadを固定。
- sqlite transactionの境界を関数名/コメントで示す。SQLはparameter binding、文字列連結禁止。
- `except Exception: pass`禁止。最上位で記録してfaultへ移る用途のみ広いcatch可。例外を202成功に変えない。
- dataclass/明示関数を優先。repository/service/controllerを機械的に3重化しない。ORM/Redis/Celery/独自pluginは必要性と予算のADRなしに導入しない。
- retryはdeadline/attempt budget/cancel付き。retryの入れ子を無制限に作らない。
- threadからloopへはboundedな受け口。create_taskをpacket数だけ生成しない。

## 4. 命名とコメント
機器型/会社名で挙動を分岐しない。external、preapproved、closed等の一般語を使う。安全に関わる規則は「何をしているか」より「なぜ必要か」を1〜3行で記す。古いIssue内容を現在仕様としてコメント固定しない。

## 5. code review
各変更は①変える状態、②所有者、③failure/cancel、④容量と期限、⑤永続commit、⑥機密と認可、⑦計測差分、⑧実受入IDを確認。短い機能でもnonce/identity/時刻/generationに関わる変更は独立レビュー必須。テストがmockだけを通る場合は完成にしない。
関数目安60行/module600行、超過自体はバグでない。責務が明瞭なら合理的な例外を許す。固定ファイル数を守るための巨大ファイル化は禁止。

## 6. 変更管理
未実装featureをcapability enabledにしない。feature OFFで専用buffer/scheduler/taskが消えることをmapで確認。全てのifをconfig optionにせず1つの既定方式へ収束させる。旧開発PSKやcompat codeを残す場合は削除期限/ビルド分離を付ける。本新規実装は旧RouteLoom Wire/API互換を要求しない。

## 7. Power規約
- timerは最早deadlineへ集約し、無負荷固定poll・診断heartbeatのためのwakeを追加しない。
- power/membership/routeの状態正本を1つずつ持ち、似たstate enumを層ごとに複製しない。
- 1episodeのbudgetを全subsystemへ渡す。retry/Join/channelで予算を再付与しない。
- PM lock、buffer lease、crypto jobは成功/失敗/cancelで対称に解放。keyだけ保持してcounterを初期化する復帰は禁止。
- mailboxは共有poolの有界予約。最大人数分payload複製・Node数分thread/task生成は禁止。
- 低電力modeが達成できない時はcapability/診断で示し、無言で常時受信へfallbackしない。
- 消費電流のモデル入力は測定と区別。synthetic traceを実測evidenceへ移さない。


## 8. 機械検査設定
`.clang-format`、`.clang-tidy`、`pyproject.toml`を初期設定として同梱する。製品buildでのformatter/linter認定は実装時のtoolchain lockに含める。本ZIPでclang-tidy/ruffが全製品コードに合格したという意味ではない。旧仕様専用toolsと新規製品コードは分けて管理する。
