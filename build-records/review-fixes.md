# REVIEW R01–R06 / G01–G02 対応記録

2026-10-01。対象はこのPRの変更で、比較元は `Aero123421/LeanMesh` main の `f71973dbaa2335dbc381ec5598d13c2d123c926a`。添付REVIEW.mdを不具合の調査資料として用い、ユーザーが追加指定したG01/G02を含めて実装した。添付の部署・配備等の記述を追加の作業指示にはしていない。

## 変更と境界

| ID | 変更 | 主な検証 |
|---|---|---|
| R01 | 同期PM wakeが時刻を進めたらownerを新時刻で再実行。待機時間も現在clockから計算。radio会計の基準を逆行させない。IDFのwall elapsedをCPU時間と表示せず未知にする。 | 1/5/30秒の同期wake seam、既存power suite |
| R02 | fatal原因を保存してactive/queued Futureを失敗完了し、以後のsubmitを即拒否。rollback/COMMIT I/O/closed connection/checkpoint/startup close失敗を処理。DB自動再作成を行わない。 | cancelled Future、health/API 503、再起動、新owner、schema失敗 |
| R03 | serial無しでもUTC期限を処理。indexで最大64件ずつ期限切れの未送信要求をFINAL/EXPIREDにし、受付枠を解放。 | 未接続API期限試験、possible-write除外。root期限はUTC処理しない |
| R04 | Host遠隔LEAVEとroot_app宛先は権限確認後、受理前に503/UNSUPPORTED。schemaの予約値は保持して説明を更新。端末ローカルlm_leaveは別機能。 | API拒否、operationを作らない、既存API契約 |
| R05 | 同principal/domain/destination/app_port/keyの未送信LATESTを同じtransactionで置換し、正味未完了数で受付。保存・履歴不足ならrollbackして旧要求を保持。 | 容量ちょうど、別principal/宛先/port、既送信可能性、容量故障、同時2要求 |
| R06 | 永続cursorの8枠weighted round robin。CONTROL/URGENTを予約し、NORMAL/BULKも前進。class内はcommit挿入順（rowid）。 | URGENT先行、連続claimでも通常/BULKが進む、UTC逆行でもFIFOとpossible-write保存 |
| G01 | leaf/relayの明示opt-in（既定OFF、最短600秒）を14Bのsealed policy recordへCAS保存。隔離の継続だけでは認可しない。既存signed TRANSFER_CANDIDATEとatomic activationを共有。 | OFF、有効ticket、許可なし、到達回復、設定CAS、冷起動保持、保存結果不明 |
| G02 | relay DRAINは子の受入を止め、rootの有界snapshotと認証済み通知で退避。全配下がrelayを含まないlive経路の現在revisionをREADYするまで離脱を許可しない。 | 代替なし期限失敗・所属維持、代替あり離脱、孫の採用確認、世代変化、codec strict bounds |

G01の予定Sleepはwake経路で隔離計時から除外する。worker/channel移行/確認待ち/通信予算不足時は30秒単位で延期し、試行は設定隔離間隔で制限する。設定未読込はAUTH_PENDING、壊れた設定/保存不明はRECOVERY_REQUIREDで自動移設停止。新policy operationは受理から照会可能とし、membershipとstopを同じcontrol operation ID名前空間へ統一した。

G02はrootにつき同時1件・最大64member bitmapで、状態不明のmemberが存在すれば保守的に退避を証明しない。取消はgrant ACKと別のcancel bitを確認して最大5回送る。grant後の受入停止は取消・離脱・世代変更まで保持するため、通信や取消が失われた状態では管理上の復旧が必要になる場合がある。IMMEDIATEへ自動変換しない。新compact CONTROL opcode 0xEF/0xF0/0xF1はregistry・CDDLのbinary注記・wire docsを同期した。

## 実行した検証

```sh
source /workspace/leanmesh-env/activate.sh
cmake --build "$LEANMESH_NATIVE_BUILD" -j4
ctest --test-dir "$LEANMESH_NATIVE_BUILD" --output-on-failure -j2
python -m pytest -q host/tests/unit host/tests/integration
python -m pytest -q host/tests/e2e
python scripts/check_spec.py
python scripts/check_api_defined.py --native-build "$LEANMESH_NATIVE_BUILD"
ruff check host scripts/check_api_defined.py scripts/budget_report.py scripts/scenario_coverage.py
python scripts/budget_report.py --native-build "$LEANMESH_NATIVE_BUILD" --json /workspace/leanmesh-env/logs/review-budget.json
```

- native: 最終27/27スイート合格。
- Host unit/integration: 196件合格（追加回帰13件を含む）。
- E2E: 全53件合格（517.94秒、21node/20hopの全経路を含む）。初回の52合格/1失敗から起動時競合を修正し、失敗ケース単独も合格。最後のHost FIFO変更は196件の試験と関連E2Eを追加で検証した（HTTP→DB→認証USB→実core→結果とLATEST batteryの2件合格、8.08秒）。
- ASan/UBSan: Debug別buildでcodec/route/power/lifecycleの4スイート合格、さらに最終差分のG01/G02/R01をLeakSanitizer有効で再実行。
- spec checker (G0)、公開C API定義チェック、Ruff、git diff --check合格。G0の生成物は過去日付のevidenceを上書きせず、今回のログとして保存。

ASan buildは `cmake -S . -B /workspace/leanmesh-env/asan -G Ninja -DLM_IDF_PATH="$IDF_PATH" -DLM_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug`。4スイートは `ASAN_OPTIONS=detect_leaks=1 ctest --test-dir /workspace/leanmesh-env/asan -R 'test_(lifecycle|power|route|codec)$' --output-on-failure -j2`。最終再試験はそれぞれのbinaryへG01/G02/R01 filterを渡した。

試験で判明した退行と修正: 通常のsubtree pushにも即時READYを追加すると64target配送が1件遅延したため、即時確認をDRAIN通知による退避時に限定。予備リンクの30秒待機は退避時の認証成功/測定済みspareに限って解除。承認待ちdeviceをbootした直後に設定loadが始まるとlm_startがBUSYになったため、identity readyかつstart済みまでloadを待つ。起動前にownerを動かすnative回帰と認証USB E2Eで確認した。関連E2Eのbattery試験は最初の到着を最新値と決めつけていたため、既に送信中の旧値を許し、最新値sequence 3の到着を期限付きで待つよう修正して再試験した。DRAIN通知は64memberの1周を終えてからbitmapを再補充し、1秒のpollで低addressを毎回先頭へ戻さない。新しく追加した試験fixtureのroot mesh無効化、StorageFullのHTTP507等も期待値を正しい契約に合わせた。

## 資源差分

同じnative x86-64コンパイラ/include条件でHEADをgit archiveしたbaselineと現在treeのbudget probeをコンパイルし、nm symbolサイズを比較した。workspaceはplatform tasks/vendor heap等を含まない。

| 指標 | baseline | 今回 | 差分 |
|---|---:|---:|---:|
| LEAF workspace | 41,848 B | 41,936 B | +88 B |
| RELAY workspace | 46,152 B | 46,240 B | +88 B |
| ROOT workspace | 127,160 B | 127,784 B | +624 B |
| SDK first-party C/C++ | 37,347 SLOC | 37,954 SLOC | +607 |
| Python Host（tests除外） | 4,409 SLOC | 4,558 SLOC | +149 |

既存のSDK SLOC/RAM目標超過は残る。これはbaselineからの安全・機能修正の追加分であり、予算内達成やSoCでのRAM測定を意味しない。Flash差分、実SoC静的RAM、stack peak、Wi-Fi起動後peak heap/最大block、定常CPU、airtime、復帰エネルギー/J-reportは未計測。

## 環境と未検証

IDF pin `76f5dedd9950a3012fee8fb7d5586df21fc67802`、GCC 14.2、Python 3.12.14。nativeはpinされたTF-PSA backendとlibedhocを使用。既存のlibedhoc exact-input patchはscripts/third_party.sh setup/verifyの結果で、今回別のvendor改変を加えていない。ログは `/workspace/leanmesh-env/logs/review-*`。環境setupは `/workspace/leanmesh-env/install.sh` とactivate.shに保存し、onboarding draftにも保存済み。

4 SoC firmware buildはIDFの必須constraints取得がプロキシHTTP403で止まり、未実行。依存検査/TLSの迂回はしていない。実機Light Sleep、実NVSの電源断、RF/長距離/20hop、電流、鍵custody/他実装とのEDHOC相互接続は未検証。E2Eの21node/20hopやsim store cutは実coreのプロトコル試験で、実電波・実電源断・電池寿命の証拠ではない。G01の隣接現場・sleep・channel移行・移設途中の実電源断を組み合わせたHILも未実施。

## CI追補（2026-10-01）

`ac20429` のCIでnative jobとE2E jobの失敗をWebの実行一覧から確認。GitHub APIは403、Webの詳細ログは認証が必要で、この環境から取得できない。native job末尾の `python scripts/scenario_coverage.py --out-dir /tmp/leanmesh-ci-coverage` をローカルで実行すると、追加テスト名の先頭にあるレビューID `G01/G02` を未定義の製品scenario IDと誤認してexit 1になることを再現した。前回の検証一覧にこのCI手順が不足していた。

レビューIDの前に `review` を付け、製品scenario名前空間との衝突を解消。同じ規則で、製品scenarioにも存在する `R01` と今回のレビューR01を区別した。テスト本体・製品scenario一覧・coverage gateは変更していない。同じコマンドはexit 0（158 scenarios / 337 references、既存の実機未検証表示を維持）。E2E側の失敗は別途調査対象で、この命名修正で解消したとは扱わない。

修正commit `bfd2482` のGitHub CI run `36830831486` でnative jobの成功を確認した（build、ctest、power-cut matrix、coverage）。通常E2Eは再度失敗し、ローカルでは `python -m pytest -v host/tests/e2e -s` が53件合格（515.53秒）で再現しなかった。元のsanitizers jobもnative ctestは成功し、その後のE2Eで失敗していた。`curl https://api.github.com/...` はCONNECT tunnelをプロキシに403で拒否され、Webログも認証必須のため本文取得不可。

両E2E jobでJUnit XMLを保存し、失敗時だけ `scripts/report_pytest_failures.py` が最大10件・各6000文字の失敗詳細をCIサマリーのannotationへ出すようにした。pytestのexit code、timeout、テスト集合は維持。XMLはartifactにも残す。実行可能なstdlibのみの処理で、ローカルの失敗/成功XML fixtureで出力と改行エスケープを確認し、Ruff・git diff --checkも合格。この診断変更をE2E不具合の修正とは扱わない。

診断commit `6201fef` のCI run `36832469562` で `test_host_restart_mid_operation_reconciles_by_message_id_and_never_resends` の `GROUP_SET applied` 待ちが失敗する詳細を取得できた。テストのpoll predicateが毎回 `control(...)` を呼び、新しいrequest_idの設定要求を作ってからその直後の状態だけを見ていた。同じ誤りは取消試験にも存在した。遅い環境では常に新しい未完了要求を見てtimeoutし、速い環境でも後続のCONFLICTをFINALと見て初期設定の成功と誤認し得た。

rootのworkerへ200 msの遅延を設定し、設定要求が1件だけであることを検査する回帰条件を追加。修正前はローカルでも失敗（69.52秒、3要求 != 1）。設定のPOSTを待機ループの外で一度だけ実行し、固定operation IDを照会してAPPLIEDを確認するよう2箇所を修正した。元の20秒の待機期限は維持し、後続のgroup fan-out/restart/reconcile前にworker latencyを通常値へ戻す。

この調査でローカルの通常E2E 53件（515.53秒）とASan/UBSan E2E 53件（584.61秒、strict simulator exit有効）が合格したが、上記の回帰条件を追加する前の結果である。変更後の関連試験とCI結果は別途確認する。

修正後は `python -m pytest -v host/tests/e2e/test_group_meshsim.py -s` の3件が合格（191.73秒）。同じ3件を `LEANMESH_MESHSIM_BUILD=/workspace/leanmesh-env/asan LEANMESH_SIM_STRICT_EXIT=1 ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:print_stacktrace=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1` で実行して合格（195.75秒）。200 ms worker遅延・設定要求1件・APPLIED確認に加え、取消/遅延結果、Host再起動後のreconcileと非再送を実core経路で確認した。Ruff・git diff --checkも合格。製品コードや期限の緩和は今回のCI追補で追加していない。
