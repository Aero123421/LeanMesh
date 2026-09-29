# 23 小ささ・速さ・長距離・電力の同時評価

## 1. 合格は複数軸

機能を減らしたbuildだけで容量比較しない。同じ公開API・認証・配送・20hop・channel・対象roleで、次の軸を一緒に測る。

|軸|測るもの|誤った代替|
|---|---|---|
|Flash|同IDF/radio基線との差、vendor込みimage、OTA slot残量|リポジトリ全行数だけ|
|RAM|静的+固定pool+全stack+driver/vendor peak、最大連続空き|S3 PSRAMだけの結果|
|CPU|owner p99/max、idle wakeups、crypto/Flash stalls|task数が1だから軽い|
|RF|DATA/control/Join/retry総airtime、双方向成功、hop別遅延|PHY250kbps=アプリ帯域|
|Energy|1episodeのJ、mAh、圏外のmAh/h、全周期平均電流|Deep Sleep中の瞬間電流|

16章のSLOC/Flash/RAM目標は維持。新しい機能の安全確認のために必要なコードを1行へ詰めない。テストを減らしてLOC目標を満たさない。modeの違いは容量/動作予算の設定で表し、三つのSDKを作らない。

## 2. 測定境界

MCUの3.3Vレールと基板電源入口を別に測る。ボードSKU/PCB revision、電池/DC-DC、アンテナ、センサー、LED、USB接続、温度、電圧、TX設定、IDF hash、firmware hash、power policyを必須metadataにする。

USB給電/デバッガ接続でsleep電流が変わる場合は、開発条件と電池条件を分ける。電流計の帯域、サンプル周期、shunt、電圧降下、サンプル落ちを記録する。burstの山を測れない計器で総energyを確定しない。

## 3. energyの定義

`Q_mAh = ∫ I_mA(t) dt / 3600`、`E_J = ∫ V(t) * I_mA(t)/1000 dt`。

`I_average_mA = Q_mAh * 3600 / observed_seconds`。計測した1cycleにwake/認証/送受信/停止/sleepを全て入れる。比較する報告間隔は同じにする。

`ideal_days = usable_capacity_mAh / (24 * I_average_mA)`は理想的な試算だけ。電池自己放電、低温、電圧終端、放電特性、DC-DC効率の変化、センサー増分は別。初期値を仮定して「何年使える」と宣伝しない。

`scripts/energy_report.py`はCSVの台形積分と単位検査を行う。入力は`time_s,voltage_v,current_ma`、phaseは任意。負値/NaN/時刻逆行/大きなsample gapは拒否。正負方向の充放電計測を勝手に絶対値化しない。付属サンプルは**SYNTHETIC**で実測ではない。

## 4. A/B行列

各SoC C3/S3/C5/C6、各実ボードについて:

- ① ALWAYS_RX と WINDOWED_RX: 同じpayload/秒、同じ受信締切、同じRF損失で比較。
- ② RAM保持の間欠動作 と DEEP/FRESH_EDHOC: 10秒/60秒/15分/1時間の報告間隔でenergy/cycleを比較。
- ③ strong/edge-of-range/干渉あり: 同じretry/deadlineで比較。
- ④ root1/5/20hop: 次hop受理まで、終端receiptまで、保存して次回回収の各wake時間を比較。
- ⑤ 正常、親不在、root不在、Host不在、全channel探索、資格切れ、counter不明、policy更新を分ける。

短周期でDeep Sleep+EDHOCが高エネルギーなら、認証を削るのでなくWINDOWED_RXを選ぶ。長周期でDeep Sleepが有利でも、その結果を常時操作端末へ外挿しない。

## 5. 初期認定の判定項目

固定仕様: 20hop深度、40hop任意端末経路、250B frame制限、署名/AEAD検査、bounded queues、受理と適用の分離。ここはpower都合で緩和しない。

初期目標: idle SDK CPU<1%、owner p99<2ms、policy上の圏外radio時間を超える追加探索0、セッション保持可能な窓間でfull EDHOC再実行0、packet単位のreplay Flash書込み0、sleepy leafの定期helloだけによる予定外wake0。

電流の絶対値は製品BOMを指定したpower target sheetに設定する。未設定ならenergyを測って公開はできるが電池寿命目標を満たしたとは言わない。J/report、report成功率、下り待ち時間の3つが揃わなければ「低電力化成功」と判定しない。寝続けて送信しないbuildを優秀と数えない。

## 6. 試験の長さ・故障条件

ALWAYS_RXの72h試験に加え、電池modeで少なくとも1,000wake cycle、24h圏外、16組合せの相互送信、20hop先のsleepy leaf、channel切替を取り逃したwakeを実施する。最終的な製品の試験回数は故障リスクと利用周期から決める。物理動作試験とsimulationを混同しない。

P-256 job、NVS commit、UART waitが重なってもradio ownerのprogressが続くか測る。ただしFlash erase中のSoC全体のcache停止などdriver外制約は隠さず観測する。遅延の最大値と失敗件数を報告し、平均だけを提出しない。

## 7. 証拠ファイル

`evidence/power-measurement.schema.json`と`examples/power-measurement.template.json`にmetadataを固定する。templateのmeasurementはnull、status=NOT_MEASURED。推定値の場合はESTIMATEDとmodelを明示し、MEASUREDへ変えるにはtrace hashと測定器/条件が必要。

既存sourcesのリポジトリ参照は2026-09-28の固定snapshotを再利用。本改訂で再びGitHub HEADを調べたとは記載しない。公式PM資料の確認は[E-PWR-01〜04]として区別する。現在のstable URLが返した資料版は6.0.2で、元仕様の実装入力pin6.0.3のbuild成立を示す証拠ではない。
