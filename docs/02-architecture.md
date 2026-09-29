# 02 アーキテクチャと所有権

## 1. 構成
```text
Application (KGuard / 農業 / 設備計測 / その他)
  | C API または local HTTP
  +-- Python FastAPI Host ---- SQLite
  |          | 認証されたSerial
  |          v
  +------ Root MCU / Authority executor / Channel coordinator
                 |
            ESP-NOW/LR source-routed mesh
                 |
          Relay / Application Node / Sleepy Leaf
```

「root」は経路の基点、「gateway」は外部接続機能、「authority」は所属を承認して記録する役割。baselineでは1台のroot MCUにdomain authorityの限定委任鍵を配置する。rootのroutingとauthorityは同じ装置でも別状態/鍵である。FastAPIはfleetの期待リスト・署名済みgrantを与え、外部承認を仲介する。所属台帳のcommit主体はroot。Host DBは操作要求と観測の永続記録で、root membershipを勝手に成立扱いしない。

## 2. 3つの処理所有者
|所有者|仕事|禁止事項|
|---|---|---|
|mesh owner（1task）|queue、peer、route、送信、受信検証の調停、timer、状態遷移|P-256演算待ち、NVS erase、HTTP/SQL、アプリcallback|
|slow-job worker（1task）|EDHOC公開鍵演算、署名検証/署名、NVS commit/erase|mesh状態への直接変更、radio API呼出|
|application executor（呼出元task）|受信event取出し、センサー・UART・適用結果報告|mesh内部ポインタ保持、ACK捏造|

AES-GCMは短いframe単位でowner内に置ける。ただしC3で一巡のCPU予算に収まることを測る。公開鍵演算とFlashが同時に滞留しても既存DATAは継続する。slow workerはセキュリティ状態commitを優先し、OTA eraseは小さく分割。長時間jobは停止不能でも完了を世代照合して捨てられるようにする。

## 3. Host非依存性
Host停止中も既存所属の再接続・Node間転送・局所経路修復・事前承認済み参加・rootの自動channel制御を継続する。外部approvalを要する新JoinはPENDING。Host宛てのdurable messageはHost commitまで未配送であり、root RAM receiptを永続受理へ格上げしない。
Root自体が停止した場合、既存の単純経路と終端sessionが有効なら端末間は通信可能。新経路のroot登録と全体channel変更は停止する。新rootの自動選挙はしない。root交換はfleet署名付きRootDelegationの世代更新で明示的に行う。

## 4. モジュール境界
- core: wire/route/delivery/membership/channel/power。I/Oなし。入力event+now→有限effect。
- port/idf: radio、mono clock、entropy、slow jobs、storage。ビルド時結合。
- security: EDHOC libraryへの小さいglueと1 crypto backend。独自handshakeなし。
- root: topology、membership ledger、policy distribution、fan-out。roleでコンパイル時除去。
- host: FastAPI、serial、SQL writer、event journal。Mesh routingの再実装なし。
- integration: KG等のcodec/DeviceLink。coreが参照してはならない。

汎用Provider frameworkは作らない。ただしClock/Radio/Store/CryptoJobsの4個の小さい固定port契約をテスト差替え用に置く。静的templateでシステム全体を生成せず、単純な関数表または直接リンクを使う。

## 5. 排他・計算量
mesh stateはowner専有。ISR/driver callback→固定ringは短いcritical sectionだけ。command queueはMPSC、event queueはowner→app。queueが満杯なら操作受付を拒否するか専用reserved slotでfaultを報告。eventを失ってもoperation.getから結果を再読できる。
idleは最早期限までsleep、外部eventでwake。fixed tickを使う場合も最小10msかつdeadline集約とし、無負荷で2ms pollしない。近隣探索は最大16件の線形走査、heap priority queueや全グラフ再計算をleafへ持ち込まない。
