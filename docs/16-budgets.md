# 16 資源・性能の設計予算

## 1. 数字の扱い
本書は**未実装の設計目標**。旧RouteLoom #199の約599KiB/203KiB等はIssue報告値で、今回再ビルドして測っていない。リポジトリ全行数（文書/test/vendor含む）と新SDK core SLOCを比較して削減率を宣伝しない。

|項目|初期目標|超過時|
|---|---:|---|
|first-party C/C++（core+idf+root/serial）|16,000 SLOC以下|ADR、mapと原因分析、不要方式を削る|
|Python Host（tests除外）|6,000 SLOC以下|endpoint/層の重複点検|
|新SDK追加Flash（導入で増えるcrypto/vendor含む）|256KiB目標、320KiB審査線|同IDF・同radio基線とのmap差分|
|leaf静的+固定pool+SDK task stack|32KiB目標|crypto peakは別にも合算表示|
|relay同上|48KiB目標|全ノード分table禁止|
|root同上|96KiB目標|64/128member profileを分離|
|crypto scratch/peak追加|24KiB以下目標|予約し高負荷Joinで測定|
|C3 minimum-ever free heap|48KiB以上目標|IDF/Wi-Fi peak・最大連続blockも測る|
|owner処理1回のCPU時間|p99<2ms目標|公開鍵/Flash等blocking切出し|
|steady idle SDK CPU|<1%目標|100ms/1s/60s窓で計測|

実行RAMは静的だけでなく、全task stack、vendor heap、Wi-Fi buffer、NVS peak、callback ring、fragment bufferを合計する。PSRAMがあるS3でC3の不足を隠さない。compile-time roleは**容量だけ**変え、Security/Join/Frame解釈を変えない。

## 2. メモリworksheet
config/profiles.jsonのentry数が唯一の初期値。frame poolは32B metadata+250B bufferにalignし、pool×slotで会計。message poolとframe poolは所有移譲できるが二重解放しない。route40entries=80Bが最長。rootの64×path保存も約5KiBの経路列であり、leafへ64sessionを確保しない。
mapでunused featureの静的bufferが残っていないことを確認する。オブジェクトサイズは`sizeof`で記録し、設計上の足算をコンパイラの実測と混同しない。

## 3. latency/SLOの条件
既存session/route成立、ALWAYS_ON、16〜96Bメッセージ、deadline30秒、低い背景負荷、RF損失条件を明示したベンチで測る。
|経路|目標|
|---|---|
|root↔node 1〜3hop|END_RECEIVED往復p99<2s|
|root↔node 20hop|END_RECEIVED往復p95<5s、p99<10s|
|node↔node 40hop|p99<20s（別測定）|
|20hop故障点に有効な予備隣接あり|route repair p95<10s|
|全21台cold boot|全体形成p95<120s、Join新規/復帰は別計測|
|自動channel切替|COMMITから通常復旧p95<120s、取り残しは最長360s目標|

APP_APPLIEDはこれにアプリ処理時間が加わる。Pico600ms待ちやセンサー退出判定3秒を通信時間0として消さない。HILに失敗すれば目標未達と記録し、値を短い経路の結果へすり替えない。

## 4. 20hopのairtime
PHY rateはapplication throughputではない。`scripts/airtime.py`はDATA、SDK HOP_ACK、END_RECEIPT、各hop数、再送なしのbit送信時間下限を計算する。MAC header/FCSに加え、preamble/CCA/backoff/MAC ACK/radio turnaround/RTOS/cryptoを別に測定する。
全hopが同collision domainなら概算service予算は辺ごとの占有合計に支配される。空間再利用がある場合でも勝手に20倍throughputとして計算しない。30台×毎5秒×20hopの両方向通信を、250kbpsという数字だけで保証しない。API admissionを増やすだけではRF帯域は増えない。

## 5. 省電力の指標
idle wakeups/s、discovery airtime/join、ECDH/verify CPU ms、Flash commits/hour、awake ms/report、joule/report、sleep平均電流を測る。250→500の切替より先に不要packet/全表scan/再認証/flash書込みを削る。圏外時の探索電力に上限を設ける。長距離でRF再送が増える電池寿命を直近端末の値から外挿しない。

## 共通比較の実施方法
比較buildは、同一SoC/IDF/toolchain/最適化/証明書機能で「空のIDF+ESP-NOW」と「SDKをlinkした同一サンプル」を作りmap差分を取る。coreだけを数える指標とvendor込みの製品binaryを両方出す。tests/docs/generated/binding/vendorの行数は別欄、縮小率の分母を混ぜない。C3にrootを載せる場合も32KiBのleaf目標ではなくroot目標を適用する。
親停止の5秒目標はactive traffic/対象RF失敗の検出が可能な条件。idle時の受信監視は最大96秒の別基準を使用し、定期送信を減らした効果と障害検出時間のトレードオフを報告する。Serial最大8230Bの受信buffer1件とcrypto scratchを全RAMに必ず加算する。

## spec0.2追加予算
Power state追加は1Node 1KiBを初期目標、awake mailboxは既存TX poolから借用する。Group progressはpayload1copy+最大64targetのcompact state。専用group operationはleaf1/relay1/root4の上限をconfig/profiles.jsonで持つ。実装のsizeof/mapで総量を再計算し、32/48/96KiB目標を暗黙に増やさない。
電力合格と比較条件は23章、設定検査はscripts/power_contract.py。追加機能をdisabledにした場合に専用task/bufferが残らないことを確認する。RTC secure resumeは本版のimplemented/enabledを必ずfalseにする。

## 実装時の改訂（ADR-002）
RAM目標はleaf 48KiB / relay 56KiB / root 160KiB、first-party SLOC上限は28kへ改訂した（仕様容量の実測コストに基づく）。ESP32-C3のroot構成はHILでminimum-ever free heap ≥48KiBを実測するまで非サポート。根拠と測定表は[ADR-002](../decisions/ADR-002-budget-status.md)。
