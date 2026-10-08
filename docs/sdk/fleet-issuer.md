# オフライン fleet 署名ツール

Issue [#3](https://github.com/Aero123421/LeanMesh/issues/3) の最初の経路です。
`host/leanmesh_fleet` は初回 Join の署名 object を発行する独立 CLI です。
通常の Host サービスはこのモジュールを import せず、HTTP token に署名権限を追加しません。
既存の LM1 CBOR/COSE 契約を使い、firmware の検証条件を変更しません。

## 今回の範囲

| 操作 | 出力・条件 |
|---|---|
| `init` | OS の暗号乱数で P-256 fleet 鍵と fleet id を新規生成。seed・既存秘密鍵の import はない |
| `device` | 外部から渡された P-256 公開鍵に DeviceCredential（type 1）を発行 |
| `root` | 非ゼロ domain と Root 公開鍵に RootDelegation（type 2）を発行 |
| `admit` | 1〜64台分の初回 AssignmentTicket（type 3）と ExpectedSet（type 5）を一括発行 |
| `transfer` | 1台分の移設 AssignmentTicket（type 3、source = 現在の domain）と、任意で移設先 root の ExpectedSet 1 page |

署名は ES256、kid は SHA-256（既存の deterministic COSE_Key）、external AAD は
`LM1-CONTROL` です。DeviceCredential の CCS hash と、参加券の device credential hash / root
delegation hash は入力 object の実際のバイト列から計算します。

`admit` は同じ fleet の署名・公開鍵・DeviceId・CCS・domain・generation を検証してから発行します。
RootDelegation に approve 権限が必要です。重複機器と Root 自身の参加登録を拒否します。
既定の隠れた権限はなく、`root --permissions` を明示します。
この版で発行できる権限は SDK が実装済みの approve=1 / revoke=2 / channel=4 / groups=8 だけです。

**機器への書込みは未実装です。** 機器鍵の生成・所有証明・暗号化 NVS の書込み、eFuse、Root の
初期 membership/ledger、USB paired_host/Host kit は後続です。TRANSFER、commissioning window、
revoke、RootHandover の発行 CLI も後続です（TRANSFER は下の「移設参加券」）。#3 の実機完了条件は満たしていません。

## 鍵の保管と署名権限

fleet 鍵を保有するオフライン署名担当者だけが CLI を実行します。現場 Host と機器へ fleet 秘密鍵を
配布しません。fleet 公開鍵・fleet id は、次段階の provisioning で trust anchor に固定します。
Device/Root 秘密鍵は CLI に入力せず、それぞれの機器の custody 工程で管理します。
公開鍵の入力だけでは所有証明にはならないため、署名担当者が公開鍵と製造個体の対応を確認します。

fleet store は所有ユーザーの `0700` ディレクトリです。`fleet-key.pem` はパスフレーズで暗号化した
PKCS#8、`fleet.json` は format 1 / environment / fleet id / key id / PEM 公開鍵です。
両ファイルを `0600` にし、所有者・regular file・hard link 数も確認します。
directory inode を固定して読み、store や鍵ファイルの symlink を拒否します。
平文 PEM、鍵と metadata の不一致、破損、不明 format は拒否します。

パスフレーズは端末上の非表示 prompt から入力します。コマンド引数や環境変数には入れません。
自動化の場合だけ `--password-file` を使えます。そのファイルも所有ユーザーの regular file / `0600` /
hard link なしを要求し、末尾の CR/LF を除いて16〜1024 byteです。秘密を含む backend 例外は表示せず、
標準出力には id、出力先、hash、件数だけを出します。
端末なし・echo を無効にできない端末では prompt を拒否します。`getpass` の標準入力への
fallback は使わず、非対話実行では保護された password file を必須にします。

この PEM backend は OS ユーザーが署名者の境界です。HSM、複数人承認、署名監査サーバー、Python
プロセスの秘密メモリ消去の保証はありません。署名担当者は専用オフライン端末を管理し、暗号化した
store の backup とパスフレーズを別の管理先へ保管してください。custody 審査は未実施です。

## 試験用と本番用

全 command で `--environment test` または `--environment production` が必須です。
store の用途と一致しないと発行できません。試験も毎回新しい鍵を生成し、`tools/lmfleet` の
公開 seed/固定鍵を import する command はありません。本番 store を実験に使わないでください。

environment はローカル運用上の guard であり、LM1 の wire field ではありません。metadata を編集
できる所有ユーザーまで隔離する仕組みではなく、機器が「試験鍵」を自動判別することもありません。
本番 provisioning は独立した本番 trust anchor の id を照合し、試験 anchor を書き込まないことが必要です。

## 実行

Python 3.12 と、既存の hash 付き Host dependency lock を使います。新しい依存は追加していません。

```sh
scripts/setup_host_venv.sh sync
export PYTHONPATH="$PWD/host"
PY="${LEANMESH_VENV:-$HOME/.cache/leanmesh/host-venv}/bin/python"

# 専用端末の保護された親 directory 内。各 command でパスフレーズを prompt する。
$PY -m leanmesh_fleet init --store /secure/fleet-a --environment production

# leaf-01.pub.pem / leaf-02.pub.pem / root.pub.pem は custody 工程で確認した公開鍵。
$PY -m leanmesh_fleet device --store /secure/fleet-a --environment production \
  --public-key leaf-01.pub.pem --serial leaf-01 --generation 1 --output leaf-01.cose
$PY -m leanmesh_fleet device --store /secure/fleet-a --environment production \
  --public-key leaf-02.pub.pem --serial leaf-02 --generation 1 --output leaf-02.cose
$PY -m leanmesh_fleet device --store /secure/fleet-a --environment production \
  --public-key root.pub.pem --serial root-01 --generation 1 --output root-device.cose
$PY -m leanmesh_fleet root --store /secure/fleet-a --environment production \
  --public-key root.pub.pem --domain 1234567890abcdef1234567890abcdef \
  --generation 1 --permissions 15 --output root-delegation.cose
$PY -m leanmesh_fleet admit --store /secure/fleet-a --environment production \
  --device-credential leaf-01.cose --device-credential leaf-02.cose \
  --root-delegation root-delegation.cose --assignment 1 --expected-revision 1 \
  --output-dir admission-0001
```

各出力を新規作成し、既存のファイル・directory・symlink は上書きしません。`admit` の directory
を `0700`、各 file を `0600` にして fsync します。最後に hash 一覧の `manifest.json` を書きます。
途中で失敗した directory は再利用せず、completion marker のない batch を配備しません。
manifest は運搬時の整合確認用で、署名 object の検証や権限確認を代替しません。

参加券は **初回専用**（source=zero16、expected-old=0）。mode1 の一回限り grant を暗号乱数で生成し、
機器への事前登録を前提とします。入力を変えずに再実行しても新しい grant と署名になります。
配備の再試行では完成済み batch をそのまま使い、参加券を再発行しないでください。
参加済み・離脱済み機器の再加入や移設は、`admit` の対象ではありません（次節の `transfer`）。

## 移設参加券（`transfer`）

domain A の ACTIVE な member を、旧 root A が止まっていても domain B へ動かす fleet 署名の AssignmentTicket
（docs/07 §8、docs/21 §6）。SDK の移設（`lm_join(LM_JOIN_TRANSFER_CANDIDATE)`、`lm_transfer_nonce_get`、
`lm_install_control(3, ...)`）が受け取る object を発行します。**発行するだけで、機器への投入は行いません。**

```sh
# 機器の DeviceCredential、移設先 B の root の RootDelegation（B の domain を持つ。approve 権限が必要）は発行済みの入力。
$PY -m leanmesh_fleet transfer --store /secure/fleet-a --environment production \
  --device-credential leaf-01.cose --source-domain 1234567890abcdef1234567890abcdef \
  --root-delegation root-b-delegation.cose --expected-old 1 --new-generation 2 \
  --nonce 00112233445566778899aabbccddeeff --expected-revision 3 --output-dir transfer-0001
# --nonce の代わりに --grant（mode 1）。どちらか一方が必須。--expected-revision は省略可。
```

| 入力 | 意味 |
|---|---|
| `--source-domain` | 機器が**今いる** domain（非ゼロ16 B）。移設先と同じは拒否 |
| `--root-delegation` | 移設先 root の RootDelegation。target domain はこれから取る。この object の SHA-256 が参加券に入る |
| `--expected-old` / `--new-generation` | 機器の現在の assignment generation（1 以上）と、移設後の generation（それより大きい）。後者は機器と B の root が持つ消費済み generation の floor より上であること（下回ると機器か root が拒否）。この版は inventory も floor も永続管理しない |
| `--nonce HEX` | mode 0。機器が `lm_transfer_nonce_get` で出した 16 B。その機器・その nonce にだけ効く |
| `--grant` | mode 1。暗号乱数の一回限り grant id。事前に発行でき、機器の nonce は要らない |
| `--expected-revision` | 指定すると移設先 B の ExpectedSet 1 page（`expected-00.cose`）も発行（PREAPPROVED の root B 用） |

出力は `ticket-<device id hex>.cose`（と `expected-00.cose`）と、最後に書く `manifest.json`（種別 `transfer`、
source/target domain、generation、mode、各 object の SHA-256）。directory は新規 `0700`、file は `0600`、
上書きせず、失敗した入力では directory を作りません。`admit` と同じ検証（fleet・kid・DeviceCredential の
CCS/credential hash・RootDelegation の意味 binding・サイズ上限）に加え、B の root 自身を B へ移す指定も拒否します。

参加券の field（`tools/lmfleet/fleet.cpp` の `Fleet::ticket` と同じ順序。CBOR array 11）:
`[device, fleet, source_domain, target_domain, sha256(target RootDelegation), expected_old, new_generation,
grant_id16, mode, nonce16, sha256(DeviceCredential)]`。envelope の domain は target、revision は new_generation。
mode 0 の nonce16 は機器の nonce、mode 1 の nonce16 は埋め草の乱数で、grant_id は mode によらず新規乱数です。

**mode 0 と mode 1 の違い（SDK の実際の動作）。** 機器側に移設 grant の登録台帳はありません。機器は
`lm_install_control(3)` で「source / expected_old が自分の現在の domain / assignment と一致する移設」だけを受け、
mode 0 では ticket の nonce16 が自分の未使用の nonce と一致することを要求します（nonce は `lm_transfer_nonce_get` の
最初の呼出しで作られ RAM にだけ残り、再起動か、それで得た membership で失効）。mode 1 の「一回限り」は
**generation の floor**（機器の消費済み assignment と root の `consumed`）と、PREAPPROVED の root B が持つ
ExpectedSet の entry（grant hash = ticket COSE 全体の SHA-256、assignment = new_generation）で守られます。
EXTERNAL の root B なら operator の承認で通ります。使い分け: 機器が手元にあって nonce を取れるなら mode 0
（別の機器・別の時点の ticket として使えない）、事前に配る・機器に触れないなら mode 1。

移設 ticket は **旧 root A にも `lm_install_control(3, ...)` で渡せます**。A が戻ったとき、同じ ticket で
ledger の ACTIVE entry が LEFT になり、旧 generation が floor されます（`old_domain_reconciliation`）。
A が止まっている間は A の ledger は更新されず、機器側が A を拒否します。紛失機器は revoke floor で拒否します。

ExpectedSet は DeviceId 順に8件ずつ、最大8 pageです。全 page で共通の set hash は
SHA-256（CBOR `[domain, expected_revision, 全 entry]`）です。entry の grant hash は
**参加券 COSE 全体の SHA-256** です。最大 u63 generation でも各 page は SDK の1024 byte以内に収まります。
これは発行側の一貫した hash 規則であり、SDK が全 page を再結合してこの hash を計算するとは言いません。

generation/revision は管理 inventory から指定します。この版は署名 inventory や global floor を
永続管理しません。同じ domain の違う batch に同じ expected revision を割り当てないでください。
Root は古い revision や同 revision の違う内容を既存の永続 manifest で拒否します。

## ソフトウェア検証と残る検証

```sh
cmake --build "$LEANMESH_NATIVE_BUILD" --target issuer_driver
$PY -m pytest -q host/tests/integration/test_fleet_issuer.py
```

`tests/native/issuer_driver.cpp` は test-only driver です。Python/cryptography の出力を既存 SDK/PSA
で検証し、SimStore に設定して EDHOC → durable membership → Root ACTIVE confirmed まで動かします。
CLI 自体の出力も同じ Join 経路に渡します。署名改ざん、正しく署名されても誤った device/CCS/hash/fleet、
鍵用途・権限・password・symlink/hard link の異常、最大64台の全 page を検査します。
移設は同じ driver の `transfer`（mode 1）/ `transfer-nonce`（mode 0。driver が出す nonce に対して Python が発行）で、
A の member を root A 停止中に B の root へ移し、B で ACTIVE（A と B の同時 ACTIVE なし）、古い・別 nonce・別 source の
ticket と使用済み ticket の再 install は機器が拒否、A が戻ると同じ ticket で ledger が LEFT になり A は機器と session を
持たない、までを検査します。
マージ前の確認（[testing.md](testing.md) §2）の Host と sanitizer の試験で実行し、build output がなければ失敗します。

driver の平文 device scalar は一時的な `0700` pytest directory の fixture だけに置き、
製品の生成・輸出・書込み経路としては提供しません。RF、実 NVS、実電源断、鍵 custody、独立 EDHOC
実装との相互接続は未検証です。[試験](testing.md) と Issue #3〜#6 の実機条件を参照してください。
