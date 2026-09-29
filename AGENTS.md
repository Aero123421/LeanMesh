# LeanMesh implementation rules

## 目的
汎用ESP32長距離Meshを、小さく、低負荷で、障害時にも説明可能に実装する。KGuardの語彙、Cloud URL、固有ID、表示色、安全ルールはcoreへ入れない。

## 正本と作業
- README → docs/01〜23 → protocol/registry.json / control.cddl / api/leanmesh.h / api/openapi.json / db/schema.sql を読む。
- 数値・ID・型を変更するときは正本と利用側を同じ変更で更新する。仕様間の矛盾を実装者の推測で隠さない。
- 1変更=1つの不変条件または1本の縦経路。大規模なフォーマット変更と機能変更を混ぜない。
- 調査→最小変更→失敗する回帰テスト→実経路の試験→差分/資源測定→レビュー。実行していないテストを成功扱いしない。
- 今回のZIPは仕様。既存KG/RouteLoomへのmerge、機器書込み、鍵削除、現場配備は別の明示指示を必要とする。

## 必ず守ること
- Identity、assignment_generation、membership_generation、root_term、channel_epoch、link_session、end_session、application bindingを兼用しない。
- 単一Mesh owner。RX/TX callback内で暗号、ログ整形、Flash、アプリcallbackを実行しない。
- 重い公開鍵演算/Flash jobをownerへ戻さない。完了はslot_generation + job_idで照合する。
- 全queue/table/session/reassembly/discovery/retryに上限・所有者・満杯時動作があること。
- 初回送信前と再送前に期限を確認。古いframeの再送でnonceを再利用して再暗号化しない。
- BUSY/予定Sleep/ローカル不足をRF損失と混ぜない。到達不能だけで所属を消さない。
- 受理、永続化、送信、終端受領、APP_APPLIEDを別証拠として扱う。欠けた証拠を推定で埋めない。
- 暗号は指定したEDHOC/COSEとIDF crypto backendを使う。安全検査の省略、共有固定秘密、テスト鍵の製品への残存は禁止。
- RouteLoom実装の大量コピーやvtable/codec/profileの機械移植はしない。バグ再現条件と必要な不変条件を持ち込む。
- radio/OS境界以外にchip #ifdefを増殖させない。C3の小容量を前提に全機能の意味を共通化する。
- 診断とテスト機能を本番で常時走らせない。1ms/2msの無条件pollを追加しない。

## 規模管理
docs/16のbudgetに対してfirst-party SLOC、Flash差分、静的RAM、stack、peak heap、定常CPU、airtime、復帰エネルギーを報告する。SLOCのために多文を1行へ押し込まない。テスト数やコード行数を達成指標にしない。
共通化は同じ不変条件にだけ行う。小さな意味の違う処理を万能engineへ統合しない。RAII、短い型付きhelper、std::arrayは歓迎。巨大継承、runtime plugin、無制限コンテナ、例外/RTTIはcoreで禁止。

## 完了報告
変更目的、実際のコマンド、対象commit、失敗ケース、測定差分、未検証を示す。外部資料の「設計予定」を実装証拠にしない。電波試験、電源断試験、鍵custody審査をhost modelで代替しない。

## 省電力を壊さない変更条件
20〜23章を参照。3mode共通の1つの通信/認証engineを使う。wake予算、RF失敗とsleepの区別、counter/replay保持、secret消去、PM lock解放、sleep ticket race、個別group結果をPRで点検する。Deep Sleepの鍵だけ復元や、署名省略を「高速化」として入れない。
仕様検査: `python scripts/check_spec.py`。これはG0のみ。実装後は同じ4SoCのnative/build/HILとJ/report・idle CPU・Flash/RAMの差分を報告する。未実装を埋めるダミーの成功関数や、synthetic電流を実測にする行為は禁止。
