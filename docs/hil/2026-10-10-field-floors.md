# 階をまたぐ現場試験（root 1階、表示板 3・5・7階）

2026-10-10。docs/04・06・08とcommitが「2026-10-10現場」と引く記録。少数台・1回の試験で、製品の認定でもRFの定量評価でもない。数値はfieldviewの記録とHostのDBから読んだもの。

## 構成

- root: ESP32-S3（`hil_node` ROOT、main `37df3f2`相当）、1階、PCにUSB接続。送信出力は読み戻し10 dBm（40 qdBm）、channel 1、LR。
- 表示板: Seengreat HUB75 ESP32-S3が3枚（`field_node` display、ToFなし、作業ツリーの未コミット版＝後のcommit `bfb8d2e`）。fieldview上の名前は panel3、`f78f2861`、`8d46a509`。
- 中継専用機（XIAO ESP32-C6 3台）は登録済みだが、この試験では電源を入れていない。消去前の表示板1枚ぶんの登録（panel2）も台帳に残っていた。
- 手順: 表示板を1階で電源ONしてから階段で運び、panel3を3階、残り2枚を5階と7階へ置いた。fieldviewから全memberへのPing（期限3秒）を手動で18回。

## 記録（14:57〜15:41 JST）

| 対象 | 記録 |
|---|---|
| panel3（3階）、15:02〜15:09 | 親RSSI −76〜−92 dBm。UNREACHABLE(NO_ROUTE)が5回、telemetryの空き43/41/116/64秒、Ping 5回連続で受領なし |
| panel3、電源入れ直し後 15:09〜15:35 | 親RSSI −77〜−91（中央−87）、depth 1。telemetry 149/149、Ping 11/11（往復441〜2525 ms、中央853 ms）。attachは起動57秒後 |
| panel3、15:20〜15:33 | 送信1666 frameのうちMAC ACKなし1338（約1.7回/秒）。同じ時間のroot宛telemetryは無損失。相手は記録されていない。`tx_done_max_ms` は473→857 |
| `f78f2861` | 上の階にいた約20分でtelemetry 3件（すべてdepth 1、−81〜−86 dBm）。再起動後281秒はpathなし |
| `8d46a509` | 同じく2件（depth 1、−85/−86）。−53 dBmのrelay配下（depth 2）から2秒後に−89 dBmのroot直結（depth 1）へ移動が2回。再起動後219秒・464秒はpathなし |
| K3（表示板→PC） | panel3: 押下46回のうち41回受領、押下から受領まで中央37 ms。上の2枚は6回中3回と6回中1回 |
| reset | すべてPOWERON。SDK再起動・panicの記録なし。最小heap 114 KB前後で変化なし |
| 机上（同日午前） | 電源の切れた登録機が増えるにつれ、生きている1台へのPing往復が136→546→741→1149 ms |

机上では別に、登録直後の表示板がrootへ25分つながらなかった。その板の`debug`: `mesh=3 step=3 probes_tx=30 attach_fail=0 | hs start=1 ok=1 | end start=16 ok=1 fail=15`。PC側Host serviceの再起動から約85秒後につながった。root側の記録はない。

## ここから直したこと（2026-10-10、native simで再現して修正。実機・現場は未検証）

1. 終端sessionが成立しない候補に留まり続ける（上の`attach_fail=0`）: 失敗を段をまたいで数える。docs/04 §3。
2. 無応答の相手への送信で、生きている相手が応答と親を失う: MAC ACKの返った未応答をRF失敗に数えない、無応答を試行ごとに数える。docs/04 §5、docs/08 Issue 19。
3. 応答側がexchange slotを30秒持ち続ける: 開始側が黙ったら空ける。docs/06 §8。
4. 弱い候補を先に選ぶ・弱い候補へ移る: RSSIで候補を落とす。docs/04 §6。
5. 次の試験のための記録: SDKのdebug行をnodeから送る。docs/field/protocol.md 3.6。

## この試験で分からなかったこと

- 3階⇔5階、5階⇔7階の電波の強さと損失（近隣ごとの記録がなかった）。
- panel3の13分間の送信失敗の相手と、机上でrootが終端sessionを断り続けた直接の原因（上の3が有力だが、root側の計数が残っていない）。
- rootの計数の時系列（exchangeのbusy drop、無応答試行）。fieldviewはまだ記録しない。

生の記録: `telemetry/nodelog/ping/k3/presence/events.ndjson`、`summary.csv`、Host DBの写し。リポジトリには入れていない（このPCの `C:\dev\job\LeanMesh-field-logs\2026-10-10\`、4.4 MB）。
