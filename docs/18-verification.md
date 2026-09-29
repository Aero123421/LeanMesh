# 18 試験仕様と検証の区別

## 1. テストデータ
`tests/scenarios.json`は前提・fault injection・期待結果・level・要求IDの一覧。`tests/traceability.csv`が要求→source→spec→testの対応。`tests/golden.json`はこの仕様の機械生成vector。**実装試験ではなく、実装が照合すべきfixture**。付属checkerはcodec/暗号recordの例、SQL/JSON/schema/header/配列サイズの整合だけを検査する。

## 2. softwareで検査する性質
- 全frame境界0..250、切断、末尾、uint overflow、unknownflags、UTF-8/CBOR異常。
- origin→final単純pathとindex/peer照合、古いroute、parent simultaneous switch、packet寿命上限。
- AEAD tag/header/nonce/context変更は拒否。same counter異payload、他domain、旧generationは受理しない。
- Join/transfer/channelのcommit前後の全停電点。late job completionはslot generationに一致する場合だけ作用。
- 正常重複は同じresult、異payloadはconflict。queue/DB/pool満杯はfalse successなし。
- congestion下でも有限期限のcontrolが進み、group/duplicate/clientごとの迂回rate loopholeなし。

property-based/model testsはseed、event log、最小反例、production state machineのバージョンを保存する。テスト専用に別実装した便利なstate machineだけが成功しても製品の証明にならない。

## 3. RF/HIL
4SoC×4SoC方向16cell、20hopはroot含む21台以上。到達関係はHIL neighbor allowlistだけの試験と、物理attenuator/配置での試験を区別する。allowlist試験はprotocol/driverの実RF経路の検査だが、実到達距離の測定ではない。
各runにSoC/board/antenna/firmwarehash/IDFhash/country/channel/power/配置/距離/障害物/payload/送信頻度/台数/実hop/電源/温度を記録。loss0/5/10/20%、MAC ACKloss、SDK ACKloss、20/100/500ms callback遅延、USB切断、隠れ端末を分ける。

## 4. 長時間・電源
24h PoC→72h pilot。全台20回resetだけで長期認定しない。電源断はhost強制終了に加え実Flash write中の機器電源断を別runとする。maxheap/stack/energy、最大連続遅延、未完operation数、journal残量、reset原因を取得。平均だけで外れ値を隠さない。

## 5. channel専用
必須relayがREADYを落とす、COMMITを落とす、commit直後root停電、clock skew、sleepy leafが24h後に復帰、新channelが一部地点だけ悪い、scanによりchildを孤立させる、root不在、全許可channel jam。結果はSTORED/APPLIED/RECOVERINGを区別。全妨害から有限秒以内復旧という不可能な合格条件を置かない。

## 6. release証拠
各featureにimplemented/build_tested/host_tested/hardware_tested/qualified/enabled。未実施をfalseのまま配る。四半期のstatic分析結果ではなく対象commitの証拠を参照。Security independent review、鍵配備/保管/失効手順、source license、SBOM、OTA rollback、C3資源差分をrelease manifestへ。

## 7. 本ZIPの実行範囲
SQLを一時DBへ適用しintegrity/FK/重複を検査、JSON Schema/JSONとOpenAPI internal ref確認、C/C++header構文検査、Wire fieldのoffset/size、packet AEAD fixtureのtamper rejection、path拒否、partition上限、test/requirementリンクを検査する。
**EDHOC library実行、FastAPI server起動、ESP-IDF build、radio、電源断、Pico、KG本番DB操作は実施しない。** OpenAPI内部参照検査はOpenAPI全規格のconformance suiteではない。validation.jsonのpassed項目をこれらへ外挿しない。

## spec0.2追加gate
LP/LC/GS/MEの全シナリオをtests/scenarios.json/SCENARIOS.mdに追加した。これらは製品の受入条件であり、本ZIPでは未実行。仕様checkerのpower policy/model/CSV積分テストがPASSでも、電力測定、20hop RF、real-owner interop、電源断に合格したとは数えない。
