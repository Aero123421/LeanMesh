# Changelog

## 0.2 — 2026-09-28 / 統合改訂

全54ファイルの0.1を土台にした**全量版**。差分パッチだけではない。SDK firmware/製品FastAPI実装は含まない。

- powerをALWAYS_RX/WINDOWED_RX/REPORT_ONLYに整理。有限episode、圏外radio budget、leaf主導poll、親RAM mailbox、下り待ち、session保持可否を具体化。
- sleep requestにwake source、duration、保存方針を追加。policy/diagnostics、C ABI2、OpenAPI、control/binary契約と試験を連動。
- 設置window、一斉設置、工場/倉庫、本番移設、root交換、resetの境界を追加。既存07章のcommitが全装置同時atomicではないことを明記。
- groupのorigin fan-out、世代込みsnapshot、sleepy target、per-target result、cancel、容量の会計を固定。
- 電力CSV積分ツール、power schema/fixture、mode別の受入試験を追加。実機測定値は一切捏造しない。
- 4SoC・20hop・自動channel・個体認証・機器移設・FastAPI・小ささの目標は維持。
- Deep Sleepの高速鍵復帰は未定義機能を約束しない。RAM保持session再利用とfresh EDHOCを明確化し、電池目標未達ならpower gateを落とす。

## 互換性

文書0.1→0.2、C ABI1→2（既存structはサイズ完全一致、再compileが必要）。Wire envelopeは1のまま、Power frame kind8とcontrol28〜33をcapability交渉で追加する。GroupSnapshot22を新しい意味へ上書きしない。0.2のgroupは新32を用い、旧22をUNSUPPORTEDとして拒否する。既存golden DATA frameは変更しない。

## 0.1

元仕様一式。manifest/SHA256/validationは0.2用に再生成。参照元KG/RouteLoomのcommit hashは変更していない。
