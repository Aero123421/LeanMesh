# 現場試験(2026-10-10)を受けたmesh修正の検証記録

対象: 枝 `fix/mesh-field-robustness`、commit `650182f`〜`83ac082`（基準 `bfb8d2e` = main `37df3f2` + field presence）。
経緯と現場の数値は [docs/hil/2026-10-10-field-floors.md](../docs/hil/2026-10-10-field-floors.md)。

## 実行したもの（WSL2 Ubuntu 24.04、ESP-IDF v6.0.3、2026-10-10）

| 検査 | コマンド | 結果 |
|---|---|---|
| native | `cmake --build <native> && ctest --test-dir <native> -j 6` | 31/31 |
| native ASan/UBSan | `ctest --test-dir <native-asan> -j 6`（`LM_SANITIZE=ON`、`ASAN_OPTIONS=detect_leaks=1`） | 31/31 |
| Host・fieldview・meshsim E2E | `python -m pytest -q -p no:cacheprovider` | 609 passed |
| 仕様検査(G0) | `python scripts/check_spec.py` | PASS |
| lint | `ruff check host tools/fieldview` | 指摘なし |
| firmware build | `scripts/field.sh build display esp32s3` / `relay esp32c6` / `relay esp32s3`、`scripts/hil.sh build root esp32s3`、`scripts/build_targets.sh --app example_node --profile RELAY <4 SoC>` | 8件とも成功 |

追加した回帰試験（`tests/native/test_mesh.cpp` の `FIELD sim:`）は、修正前に失敗することを確認してから実装した。数値はtestが置いたlinkの値によるprotocol benchで、RFの模擬ではない。

| 試験 | 修正前 | 修正後 |
|---|---|---|
| 終端sessionが成立しない候補をあきらめる | 300秒後もattach step 3、attach_failed 0 | relay経由でReady |
| 無応答4台へ10秒ごとのPing（無応答frameに400 ms） | 生きている1台の応答10/40、親なし307秒、rootの無応答試行320 | 40/40、0 ms、156 |
| −50 dBmのrelay配下で−89 dBmのrootが聞こえる | 300秒のうち237秒をrelay以外で過ごす | 0 ms |
| 2階ずつ離れた4台（4階離れは損失60%） | 15分形成せず、報告0/60 | 形成123秒、以後10分は鎖から外れず60/60 |

## 資源差分（app binary / 静的RAM、基準比）

| build | binary | data+bss |
|---|---|---|
| example_node RELAY esp32c3 | +1,216 B | ±0 |
| example_node RELAY esp32c5 | +1,216 B | ±0 |
| example_node RELAY esp32c6 | +1,232 B | ±0 |
| example_node RELAY esp32s3 | +1,104 B | ±0 |
| hil_node ROOT esp32s3 | +1,360 B | ±0 |
| field_node display esp32s3 | +1,376 B | +496 B |
| field_node relay esp32c6 | +1,584 B | +496 B |
| field_node relay esp32s3 | +1,408 B | +496 B |

field_nodeのRAM増は試験アプリのdebug行用buffer（480 B）。SDKの静的RAMは変わらない（追加したfieldは既存structのpaddingとTxFrame.flagsの空きbitに収まった）。docs/16のbudgetに対する超過（SLOC・Flash・固定RAM）は基準の時点から続いており、この変更で解消も悪化の質的変化もしていない。

## 測っていないもの

stack、peak heap、定常CPU、airtime、復帰エネルギーは測定していない。実機・電波・全台・長時間・電源断は未検証。3 mode共通engineの変更だが、WINDOWED_RX/Deep Sleepのwake予算への影響は実機で見ていない（nativeのpower試験は通過）。

## 追加: 返事のない隣へのrotationの繰り返し（2026-10-11）

現場記録のうち原因不明だった「panel3の13分間の送信失敗」を、コードと記録の突き合わせで特定し、simで再現してから直した（経緯は [docs/hil/2026-10-10-field-floors.md](../docs/hil/2026-10-10-field-floors.md)、規則は docs/06 §7）。上の表の後に重ねた変更で、基準は直前のcommit `95b1263`。

| 試験 | 修正前 | 修正後 |
|---|---|---|
| 隣を電源断にしてcredential更新を待つ（`test_lifecycle` の `FIELD sim:`、更新から隣のlease切れまで270秒） | rotation 30回、handshake 449 frame | 4回、60 frame。READYは保ったまま、sessionは従来どおり隣のleaseで終了 |
| 返事のない隣と届く隣を同時にrotation（`test_link` の `S10 rotation: a silent neighbour ...`） | 届く隣のrotationが始まらない | 届く隣は作り直され、返事のない隣は戻って30秒以内に作り直される |

| 検査 | 結果 |
|---|---|
| native（`ctest -j 6`） | 31/31 |
| native ASan/UBSan | 31/31 |
| Host・fieldview・meshsim E2E（pytest） | 609 passed |
| 仕様検査(G0) | PASS（`ruff check host tools/fieldview` も指摘なし） |
| firmware build（上と同じ8件） | 8件とも成功 |

資源差分（`95b1263` 比）: app binaryは +160〜+304 B（example_node RELAY c3 +304、c5 +304、c6 +288、s3 +256、hil_node ROOT s3 +160、field_node display s3 +256、relay c6 +288、relay s3 +240）。data+bssは8件とも±0。neighbourの記録は1件あたり8 B増える見込みだが（表はアプリが渡すworkspace内のlm_contextにある）、lm_contextの大きさそのものは測っていない。stack・CPU・airtime・復帰エネルギーも未測定。実機・電波は未検証。

## 追加: 張れない予備候補への試行の繰り返し（2026-10-11）

上のrotationを調べる途中のsimで見つけた。現場の記録に直接の証拠はない（規則は docs/04 §5）。基準は直前のcommit `f0e131a`。

| 試験 | 修正前 | 修正後 |
|---|---|---|
| beaconは届くがこちらのframeが届かない予備候補が1つ、10分（`test_mesh` の `FIELD sim: a spare candidate ...`） | handshake 18回、270 frame（すべてMAC ACKなし） | 5回、75 frame。READYは保ったまま、届くようになれば次の試行で張れる |

| 検査 | 結果 |
|---|---|
| native（`ctest -j 6`） | 31/31 |
| native ASan/UBSan | 31/31 |
| Host・fieldview・meshsim E2E（pytest） | 609 passed |
| 仕様検査(G0)・ruff | PASS／指摘なし |
| firmware build（上と同じ8件） | 8件とも成功 |

資源差分（`f0e131a` 比）: app binaryは +64〜+272 B（example_node RELAY c3 +64、c5 +80、c6 +80、s3 +256、hil_node ROOT s3 +176、field_node display s3 +272、relay c6 +80、relay s3 +256）。data+bssは8件とも±0。 候補の記録（3件）は1件あたり最大16 B増える見込みで、lm_contextの大きさは測っていない。実機・電波は未検証。

## 追加: 枝全体のコードレビューと、その指摘の修正（2026-10-12）

`bfb8d2e..f21dee3` を2系統（coreの差分／試験アプリ・viewer・sim・試験）で読み直した。指摘のうち、コードを読んで確かめられたものを直した。基準は直前のcommit `f21dee3`。

| 指摘 | 直したこと |
|---|---|
| 応答側の「開始側が黙ったら枠を空ける」待ちが、同じnodeのどの送信完了でも延びていた（送信の絶えないrootでは30秒まで空かない） | 自分のhandshake frameの送信完了だけで延ばす。proxy越しのjoinには再送の遅さ4秒を足す（docs/06 §8） |
| 弱い候補への試行をやめても、始めていたhandshakeがexchange slotを持ったままで、良い候補へのhandshakeがBusyのまま失敗に数えられる | やめるときにhandshakeも止める。良い候補が回避中ならやめない（docs/04 §6） |
| 認証済みHOP_ACKが返っても「MAC ACKなしの連続」が切れず、MAC ACKだけ失われる相手を3 frameごとに待たせる | Accepted のHOP_ACKで連続を切る。HOP_ACKが先に届いたframeの試行は数えない（docs/08 Issue 19） |
| 2回目以降で届いたframeの前の試行を、MAC ACKの有無にかかわらずRF失敗に数えていた | MAC ACKのなかった試行だけ数える（docs/04 §5の規則どおり） |
| 自分側の不足で終わったrotationも、隣の未完了として30〜480秒待たせていた | 自分側の不足は数えず5秒後に試す（docs/06 §7） |
| `lmb_debug`: 文字列が容量を超えたあとの追記に容量検査がなく、範囲外へ書きうる（試験アプリの480 Bで到達しうる） | すべての追記を容量内に限る。候補の一覧を先頭側へ移し、480 Bで切れても候補は残す |
| 試験アプリ: debug行をpathが戻るたびに送る（揺れるlinkで毎回480 B）、全nodeが同時刻に送る | 前回から60秒以内は追加で送らない。3〜7秒にばらす（docs/field/protocol.md 3.6） |
| fieldview: payloadの壊れたdebug eventで読取りloopが同じ頁を読み続ける | 空文字として記録し、loopを進める |
| 試験の弱さ（rotationの2試験が、下限なし・30秒固定の再試行でも通る） | 下限と3段の待ちを検査。応答側の枠解放と、やめたhandshakeの枠解放の試験を追加（前者は修正前に失敗することを確認） |

直していない指摘: `test_mesh` の3試験（「faint shallower」「do not acknowledge」「three boards」）は、狙った状況が起きたことの検査がない／しきい値が乱数の並びに依存する。`lmb_debug` は計数を所有thread外から読む（値が1件ずれて読める程度）。`weak()` の「最良」は回避中・最近聞こえていない候補も含む。

| 検査 | 結果 |
|---|---|
| native（`ctest -j 6`） | 31/31 |
| native ASan/UBSan | 31/31 |
| Host・fieldview・meshsim E2E（pytest） | 609 passed |
| 仕様検査(G0)・ruff | PASS／指摘なし |
| firmware build（上と同じ8件） | 8件とも成功 |

資源差分（`f21dee3` 比）: app binaryは +192〜+368 B（example_node RELAY 4 SoCとも +192、hil_node ROOT s3 +192、field_node display s3 +368、relay c6 +288、relay s3 +352）。data+bssはfield_nodeのs3 2件が +16 B（試験アプリの時刻1つ）、ほか±0。stack・heap・CPU・airtimeは未測定。実機・電波は未検証。
