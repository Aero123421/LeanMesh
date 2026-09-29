# 第三者ライセンス台帳 (T01)

対象commit時点で実物のファイルを確認した記録。`LICENSE-AND-SOURCES.md` の「新SDK配布licenseは権利者が選定」は変更しない。
法的助言ではない。再配布可否の最終判断は権利者。バイナリ(製品image)に入る物と、開発環境だけの物を分けて記す。

## 1. 製品imageに入りうるもの
| 名称 | 版/固定点 | 実物のlicense file | SPDX(確認元) | sha256(license file) | 備考 |
|---|---|---|---|---|---|
| ESP-IDF | v6.0.3 / 76f5dedd9950a3012fee8fb7d5586df21fc67802 (`~/esp/esp-idf-v6.0.3/LICENSE`) | Apache License 2.0全文 | Apache-2.0 | cfc7749b96f63bd3... | IDF内の個別component/第三者コード(例: lwip, mbedtls, wpa_supplicant)は各自のlicenseを持つ。imageに入るcomponent単位の集計は未実施(SBOM=T24/G7)。 |
| esp_wifi / esp_phy / esp_coex 事前ビルドlib | IDF同梱 | `components/{esp_wifi,esp_phy,esp_coex}/lib/LICENSE` | ファイル内容はApache-2.0全文(IDF直下と同一sha256) | 同上 | 中身はバイナリlib。ソースは無く、LICENSE文面以上の検証はしていない。baseline imageにlinkされる。 |
| libedhoc | v2.3.2 / c8857b62d66be3664d1694bbe4eea37c56c05d9e (submodule `third_party/libedhoc`) | `third_party/libedhoc/LICENSE` "MIT License, Copyright (c) 2024, Kamil Kielbasa and others" | MIT | 336aa7972285e910... | 現時点でどのfirmwareにもlinkしていない。チェックアウトは LICENSE/include/library/backends のみ(sparse)。libedhocの他のexternals(mbedtls, compact25519, Unity, liboqs, XKCP)は取得せず、未確認。 |
| zcbor | 0.8.1相当 / d3093b5684f62268c7f27f8a5079f166772619de (libedhoc `externals/zcbor` の固定点) | `.../externals/zcbor/LICENSE` Apache License 2.0全文 | Apache-2.0 | cfc7749b96f63bd3... | 同上、LICENSE/include/srcのみ。NOTICEファイルの有無は未確認(sparseで取得していない)。 |

## 2. ローカルpatch(第三者コードの改変)
| 対象 | 状態 | 内容 |
|---|---|---|
| libedhoc `library/core/classic/edhoc_classic_message_{2,3,4}.c` | **適用済み** (`third_party/patches/libedhoc-2.3.2-exact-input-consumption.patch`) | CBOR decode後の消費長が入力長と一致しなければ `EDHOC_ERROR_CBOR_FAILURE`。適用後のblob idはRouteLoom 77b5792のvendored版と一致(b1ba890.., f84231d.., 48ac46c..)。 |
| zcbor `src/zcbor_encode.c` | **未適用** | RouteLoomは長さ0のmemmoveでnullを渡さないguardを入れている(`input->len != 0 &&`)。本タスクの要求外、consumerも未実装のため適用せず記録のみ。T03でlibedhocをlinkするとき再判断。 |

## 3. 開発環境(製品imageに入らない)
| 名称 | 版 | license(確認元) | 備考 |
|---|---|---|---|
| xtensa-esp-elf / riscv32-esp-elf | esp-15.2.0_20251204 | GPL-3.0 with GCC exception (`tools/tools.json`) | コンパイラ。ランタイムlibは例外条項の下。libgcc等がimageに入る点の精査は未実施。 |
| openocd-esp32 | v0.12.0-esp32-20260703 | GPL-2.0-only (tools.json) | 未使用(書込み/debugしない)。 |
| esp-rom-elfs | 20260528 | Apache-2.0 (tools.json) | |
| cmake / ninja | 3.28.3 / 1.11.1 (Ubuntu apt。実ビルドで使用。IDF管理のcmake 4.0.3/ninja 1.12.1は未導入) | 未確認(upstreamは通常BSD-3-Clause / Apache-2.0) | |
| IDF Python env (esptool 5.4.0, idf-component-manager 3.1.2 等) | `~/.espressif/python_env/idf6.0_py3.12_env` | 個別確認は未実施 | IDF管理。 |
| clang-format / clang-tidy | apt導入(Ubuntu 24.04) | Apache-2.0 WITH LLVM-exception (パッケージ記載、未検証) | |

## 4. Host Python (`host/requirements.lock`、hash付き)
License file欄は、インストール済みwheelの `*.dist-info` 内で確認した物。SPDXはwheel METADATAの `License-Expression`(pyserialのみ旧式 `License:`)。

| package | 版 | license (METADATA) | license file(先頭16桁sha256) |
|---|---|---|---|
| fastapi | 0.141.1 | MIT | LICENSE 4ec89ffc81485b97 |
| starlette | 1.7.0 | BSD-3-Clause | LICENSE.md dcb95677a0224024 |
| uvicorn | 0.54.0 | BSD-3-Clause | LICENSE.md efe1acf3e62fb99c |
| pydantic | 2.13.5 | MIT | LICENSE a9e186f3ca16b5ee |
| pydantic-core | 2.46.5 | MIT | LICENSE 2afdd30d54b4d62b (wheelは静的リンクしたRust crateを含む。crate別licenseは未確認) |
| pyserial | 3.5 | "BSD" (Classifier: BSD License) | wheelにlicense fileなし。SPDX(BSD-3-Clause)は未確認 |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause | LICENSE 3e0c7c091a948b82 / LICENSE.APACHE aac73b3148f6d1d7 / LICENSE.BSD 602c4c7482de6479 (wheelは静的リンクのOpenSSLを含みうる。同梱licenseの精査は未実施) |
| cffi | 2.1.1 | MIT-0 | LICENSE 5ba24ddc57067f92 |
| pycparser | 3.0 | BSD-3-Clause | LICENSE 0c846399369ea76d |
| anyio | 4.15.1 | MIT | LICENSE 5361ac9dc58f2ef5 |
| idna | 3.20 | BSD-3-Clause | LICENSE.md 1a9a4f0e3d479a27 |
| h11 | 0.16.0 | MIT | LICENSE.txt 37db5bb85926db28 |
| click | 8.5.0 | BSD-3-Clause | LICENSE.txt 9a8ad106a394e853 |
| annotated-types | 0.8.0 | MIT | LICENSE fe1049884b1a0d93 |
| annotated-doc | 0.0.5 | MIT | LICENSE fff170779a6acbf6 |
| typing-extensions | 4.16.0 | PSF-2.0 | LICENSE 3b2f81fe21d181c4 |
| typing-inspection | 0.4.4 | MIT | LICENSE 804b59b25f2c31bd |

`scripts/requirements-check.txt`(仕様検査用 jsonschema/cryptography)はHost runtime lockとは別で、本台帳の対象外。

## 5. 未確認
IDF imageに入るcomponent別license集計、SBOM、libgcc/newlib等のimage内容、pyserial/OpenSSL/Rust crateの再配布条件、NOTICE要件、zcbor/libedhocの非取得external。これらはT24のrelease manifestまで持ち越し。
