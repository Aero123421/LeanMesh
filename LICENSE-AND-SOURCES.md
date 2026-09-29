# ライセンス・第三者素材
本ZIPは新規に作成した仕様・宣言・検査ツールです。既存RouteLoom/KG/ESP-IDFのソース一式、第三者ライブラリ、フォントは同梱していません。新SDKの配布licenseは利用者/権利者が選定してください。
参考にしたRouteLoomは公開README上Apache-2.0、libedhoc候補はMIT（参照manifest）です。将来コードを取り込む場合は原典のlicense/NOTICE/copyright、local patches、依存hashをその時点で確認し同梱する必要があります。URL参照だけで再配布権を得たとは扱いません。
検査用鍵はすべて公開されたsynthetic test-only scalarから生成し、秘密として扱うものではありません。利用者の実機鍵・token・SSID・証明書は含みません。本番でtestkeyを使ってはいけません。
