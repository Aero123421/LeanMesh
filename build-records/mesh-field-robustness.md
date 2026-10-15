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

## 追加: 別モデルによる2回目のレビュー（Codex CLI、gpt-6-astra、reasoning effort max、read-only）とその修正（2026-10-12）

`bfb8d2e..01ddd3a` を対象にした。指摘は5件で、5件ともコードを読んで確かめてから直した。基準は直前のcommit `01ddd3a`。

| 指摘 | 直したこと |
|---|---|
| 経路越し（end）の応答側は、自分の送信が速いと約3.4秒で枠を空け、開始側のhop再送（3回目は約5.4秒後）で届いたmessage_3を捨てる | 応答側は1 hopの送信時間を500 ms以上として1往復を見積もる（1 hopで約10秒、2 hopで約18秒）。docs/06 §8 |
| HOP_ACK(Busy)が先に届いたあとMAC ACKが失われると、その試行が「無応答」に数えられる（BUSYとRF損失の混同） | Accepted・Rejected・Busyのどれでも、先に届いていれば数えない。docs/08 |
| いなくなった強い候補の古いRSSIが表に残り、使える親（−84）まで弱い扱いになって、かすかなroot（−91）へ移れる | 弱いかどうかは今選べる候補（直近96秒に聞こえ、回避中でない）と比べる。弱い候補へ移るのは親がそれよりさらに弱いときだけ。docs/04 §6 |
| 予備候補の待ちが、自分側の不足で終わった試行でも伸びる | 自分側の不足で終わった試行は数えない。docs/04 §5 |
| 相手の待ちで止まっているframeを取り下げても、待ちが明けるまでpoolの枠を持ち続ける | timerで即座に終わらせる（最初の直し方は送信中に空回りし、simのspin guardが止めた。timer側で終わらせる形に改めた） |

追加した回帰試験: `test_mesh` の `FIELD sim: a strong candidate that is gone ...`（修正前: いなくなった後の10分間ずっとroot直結。修正後: 0 ms、使えるrelayの下に付く）。HOP_ACK(Busy)と取り下げframe、end応答側の見積もりには専用の試験を足していない（既存の31件とASanで退行がないことだけ確認）。

| 検査 | 結果 |
|---|---|
| native（`ctest -j 6`） | 31/31 |
| native ASan/UBSan | 31/31 |
| Host・fieldview・meshsim E2E（pytest） | 609 passed |
| 仕様検査(G0)・ruff | PASS／指摘なし |
| firmware build（上と同じ8件） | 8件とも成功 |

資源差分（`01ddd3a` 比）: app binaryは +176〜+320 B（example_node RELAY c3 +288、c5 +288、c6 +304、s3 +176、hil_node ROOT s3 +288、field_node display s3 +192、relay c6 +320、relay s3 +192）。data+bssは8件とも±0。stack・heap・CPU・airtimeは未測定。実機・電波は未検証。

## 追加: 10/12現場再試験の修正（Issue #24、外部レビュー＋Codex CLIの3回目のレビュー、2026-10-15）

基準は `6ded24a`。対象は `0909ba0..862afd3` の7 commit。原因の特定と記録は `docs/hil/2026-10-12-field-retest.md`。

| 変更 | commit | 試験（修正前→後、いずれもsim） |
|---|---|---|
| attachはhandshakeの終わりを受けて進む。自分側の待ちは候補の失敗に数えない（docs/04 §3） | `0909ba0` | 失敗するrelayを2回で諦めて次へ: 36秒→20秒。自分のslotの待ち: attach_failed 2→0 |
| 旧termのcredentialの更新をattachで求める。新しい近隣sessionで待っていた送信を送り直す。rootは時計のないとき更新を始めない（docs/04 §7、docs/08） | `32583c5` | root再起動後のrelay越しのアプリDATA: 91.5秒→33秒。時計のないroot: 形成できず（再署名の延期29896回）→形成 |
| 弱い候補を予備にしない（docs/04 §5） | `ee588b6` | 5分でhandshake 1回（張られた）→0回 |
| `rotations_started` は始まったものだけ | `7928624` | — |
| node logのmessageが起動回を持つ（docs/field/protocol.md 3.4、version 2） | `e91ac4e` | 記録が前の起動に付く誤りを再現して修正 |
| 3回目のレビューの指摘6件 | `6c125e7` | 下表 |
| 再発行は木ができてから（新しいpathの3秒後、最長60秒） | `862afd3` | R07 全台停電20回: 形成の平均 93.9→43.3秒（最大146.6→45.8）、全memberの再発行は形成の91.7→39.6秒後 |

3回目のレビュー（`6ded24a..e91ac4e`、Codex CLI gpt-6-astra、read-only）の指摘7件: 6件を直し、1件（試験の境界）は試験を強めた。自分側の待ちの上限が効かない／connect()内の自分側の不足を数える／glareで譲ったhandshakeの失敗が伝わらない／応答側がsessionを入れた直後に送ると開始側が捨てる／遅れて届いた前の起動の記録を今の番号で書く／boot_count 0を前の起動と読む。glareと応答側の遅らせには専用の試験がない。

途中で見つけて直したもの（レビューより前）: 探索のhandshake予算が尽きたことを候補の失敗に数えると、500秒切断のあと戻ったlinkへ付き直せない（`test_lifecycle` G01が失敗して判明、`0909ba0` に含む）。

見立てを変えたもの: 外部レビューの指摘のうち、親へのPROBEを32秒ごとにしか数えない点は、simで中継の再起動に子が12秒で別経路から付け直したので、この版では変えていない。

| 検査 | 結果 |
|---|---|
| native（`ctest -j 6`） | 31/31 |
| native ASan/UBSan | 31/31 |
| Host・fieldview・meshsim E2E（pytest） | 612 passed |
| 仕様検査(G0)・ruff | PASS／指摘なし |
| firmware build（example_node RELAY c3/c5/c6/s3、hil_node ROOT s3、field_node display s3・relay c6・relay s3） | 8件とも成功 |

資源差分（`6ded24a` 比）: app binaryは +304〜+544 B（example_node RELAY c3 +528、c5 +528、c6 +512、s3 +304、hil_node ROOT s3 +512、field_node display s3 +336、relay c6 +544、relay s3 +336）。data+bssは、s3の4件が −16 B（試験アプリ以外のs3でも同じ。node logの時刻の変数が1つ減った分）、ほか±0。stack・heap・CPU・airtimeは未測定。実機・電波は未検証。
