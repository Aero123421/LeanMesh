# 調査結果と設計判断
## 現在の事実と旧説明の訂正
現在のKGはGoのsitecoreで現場安全判断を持ち、displaylinkのTransportは未認証frame/送信書込/経路を扱う。Portの検証と`st`世代・内容・drawnの確認を壊してはならない。[KG-CODE-01,KG-CODE-02]
9/28の追加計画ではS3/C3/C5/C6、C/C++ Device API、最新値送信、4KiB object、手動移設、Go clientが要求される。「C6を今後も正式対象外」「SDK受理=表示成功」「occは全部履歴保存」は採らない。[KG-112-NEW]

## RouteLoomから学ぶもの
SiteStoreの高世代/floor、RAM公開はdurable後、未知/不明を維持する実装思想は残す。site変更拒否を削るだけではなく、署名付き新assignmentを別transactionで入れる。[RL-CODE-02]
単一radio owner、短いcallback、返信peerの先予約、driverのBUSY/NO_MEM/RF失敗の分離を採る。[RL-CODE-03]
CとC++の公開機能差や、開発/本番securityの多重経路は新設計ではなくす。EDHOCは1engine/1profile、backendも1つ。公開鍵/Flashの遅い仕事だけowner外へ出す。[RL-CODE-01,RL-CODE-04,RL-191,RL-199]

## 持ち込まないもの
旧wire互換、Rust daemon、複数routing方式、常設複数rootの合意、汎用driver/plugin framework、KG固有のCloud・校正・業務schema。代わりにdomain内任意originのnode/group配送、typed API、有限objectを提供する。[RL-194]

## 前段案から修正した点
1. root深度20と任意端末間40を区別。20peerや20台の試験で代用しない。
2. parent.rankだけではstale情報のloopを証明できない。root検証済み単純pathを転送単位の不変条件にする。
3. channel COMMITは全機同時の原子transactionではない。取り残し、clock bound、再起動、さらに大きいepochでの復旧を規定。
4. 独自署名ECDHを作らない。EDHOC Exporter private40000は使えるがEADに同番号を勝手に割当てない。context bindingは標準handshake後の保護recordで行う。
5. 1workerへの固執でECC/Flashが中継を止めない。slow workerと結果generation照合を使う。
6. 同一無線でAP上り+自由channel最適化を当然に両立するとしない。USBまたは別uplinkで分離。
7. 全recordを公開鍵署名しない。永続認可objectは署名、日常controlは認証済みsessionのAEADにする。
8. 小さいMTUでSTARTの送信自体が再帰的に分割を要求する設計を避け、自己記述fragmentと56B内のbitmapに固定。
9. header16B/約200B payloadという楽観値ではなく、2層AEADと最長pathを含めて会計する。

## 数値と非保証
本ZIPにあるflash/RAM/CPU/電流/遅延は設計予算・試験目標。RouteLoom #199に報告された実装規模は今回ローカルbuildで再測定していないため、削減率を成果として掲げない。全repositoryを複製/総行数測定/実機全レビューしたものでもない。[RL-199]
仕様検査ツールはWire長、標準暗号primitiveを用いたfixture、C宣言、SQL/OpenAPI整合を検査する。EDHOC全実装、C3/S3/C5/C6 build、FastAPI実製品、RF/HIL、セキュリティ監査を実行したとは扱わない。

## spec0.2で再点検した境界
- 元の54ファイルを読み、口頭説明と仕様の差（root/origin fan-out、二者commitの非原子性、Deep Sleepのfresh EDHOC負荷）を明文化。
- root20hop/最大path40、単一radio、C ABI/Host、認証世代を維持。Group snapshotへassignment/membership世代を追加。
- 3 power mode、起床poll、圏外予算、有限mailbox、sleep後の再配送を追加。custom fast resumeの安全性を証明したふりはしない。
- 工場/倉庫/設置window、root交換、resetでfleet floorを消す抜け道を禁止。
- 本改訂ではKG/RouteLoomのHEADを再取得していない。上記の固定commitと日付付き要望を引き続き根拠とする。4つのEspressif公式power資料を追加で確認した。
