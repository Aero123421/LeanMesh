# ライセンス・第三者素材
本ZIPは新規に作成した仕様・宣言・検査ツールです。既存RouteLoom/KG/ESP-IDFのソース一式、第三者ライブラリ、フォントは同梱していません。新SDKの配布licenseは利用者/権利者が選定してください。
参考にしたRouteLoomは公開README上Apache-2.0、libedhoc候補はMIT（参照manifest）です。将来コードを取り込む場合は原典のlicense/NOTICE/copyright、local patches、依存hashをその時点で確認し同梱する必要があります。URL参照だけで再配布権を得たとは扱いません。
検査用鍵はすべて公開されたsynthetic test-only scalarから生成し、秘密として扱うものではありません。利用者の実機鍵・token・SSID・証明書は含みません。本番でtestkeyを使ってはいけません。
例外(bench/field試験用 `firmware/field_node` のdisplay buildだけ): 東雲フォント(Public Domain)の5字のbitmapを `firmware/field_node/main/field_render.c` に埋め込み、64x32 HUB75 panelのライブラリ ESP32-HUB75-MatrixPanel-DMA 3.0.14 (MIT) をgit依存として取得する(ソースは同梱せず、ESP-IDF v6用の小patchと、GDMAエラー伝播・frame計数のpatchを `third_party/patches/` に置く)。出典・license・hash・patchは `THIRD-PARTY-LICENSES.md` の1bと2。product imageには入れない。
