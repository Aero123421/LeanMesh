# ベンチ手順: 移設（TRANSFER）— 2 つの root

domain A の ACTIVE な leaf を、fleet 署名の移設 ticket で domain B へ移す手順（docs/07 §8、[発行ツール](../sdk/fleet-issuer.md)）。
**ソフトウェア側は sim で検証済み（`tests/native/issuer_driver.cpp` の `transfer`）。実機での移設は未実施**で、
この手順を実機で通した結果は別に記録する。ベンチ用のツールであり、製品の provisioning ではない。

## 構成

| 役割 | ボード | 備考 |
|---|---|---|
| root A | ESP32-S3（`scripts/hil.sh build root esp32s3`） | 既存のベンチ。Host A の USB serial |
| root B | もう 1 枚の ESP32-S3（同じ build） | **別の USB port、別の Host プロセス** |
| leaf | C3 / C6（`build leaf <target>`） | console は leaf だけ（root は provisioning 後は console なし） |

root A と root B は同じ fleet（`hil.py init` の fleet 鍵）が署名する別 domain。Host は 1 台の root に 1 プロセスなので、
**B 用にもう 1 つ Host を起動**する（別の DB、USB kit、Unix socket）。両 root と leaf は同じ RF 範囲に置く。
leaf が B を探すのは、leaf に入れた ticket の target domain の root だけ。

## 手順

```sh
PY=~/.cache/leanmesh/host-venv/bin/python; export PYTHONPATH=host
HIL="$PY tools/hil/hil.py"

# 1. 今までの 1 network（A）。root と leaf を provision し、leaf を A に join させる。
$HIL init
$HIL provision root --port <root A port>
$HIL provision leaf --port <leaf port> --name leaf1
$HIL host-env                       # 出力の export と uvicorn 行で Host A を起動（root A の port を LEANMESH_SERIAL に）
$HIL cmd --port <leaf port> join ; $HIL approve        # leaf1 が A の ACTIVE になる

# 2. 2 つ目の network B（同じ fleet、新しい domain、Host の鍵と USB kit）と root B。
$HIL init --name netB
$HIL provision root --port <root B port> --net netB
$HIL host-env --net netB            # Host B 用。socket は別（既定: lm-netB.sock）、DB は host-netB.db、kit は usb-kit-netB.cbor
#    別の端末で Host B を起動（Host A とは別プロセス。root B の port を LEANMESH_SERIAL に）
$HIL policy --net netB              # B の join mode を確認

# 3. 移設。board の nonce を取り、ticket を発行して install し、`join transfer` で B を探させ、B の ACTIVE を待つ。
$HIL transfer leaf1 --to netB       # B が EXTERNAL: B の承認待ちはこのコマンドが Host B 経由で承認する
$HIL transfer leaf1 --to netB --grant --preapproved
                                    # mode 1 の ticket + B の ExpectedSet（先に `policy --net netB PREAPPROVED`）
$HIL cmd --port <leaf port> status  # domain= が B の domain、assign= が 1 つ上がる
$HIL host-send leaf1 "hello B"      # leaf1 は B の network のものとして Host B で扱う
$HIL reconcile leaf1                # 旧 root（A）に同じ ticket を渡す: A の ledger の ACTIVE が LEFT になる
```

旧 root が止まっていても移設できることの確認は、手順 3 の前に root A の USB を抜く（または電源を切る）。
その間 leaf は A の membership を持ったまま ticket を保持し、B へ移る。A を戻した後に `reconcile leaf1`
（Host A を再起動してから）を実行する。

leaf の console は `nonce`（機器の transfer nonce。RAM のみ。**再起動すると失効**するので、`transfer` の最中に
board を再起動しない）、`ticket <hex>`（`lm_install_control(3, ...)`。結果は `op <id>` / `EV kind=3`）、
`join transfer`（`LM_JOIN_TRANSFER_CANDIDATE`。`join` と同じく EXPIRED/BUSY/RATE_LIMITED なら最大 5 回やり直す）を持つ。
`hil.py transfer` はこの 3 つを順に使う。手で行うなら `cmd --port <leaf> nonce` → `python -m leanmesh_fleet transfer ...` →
`cmd ... "ticket <hex>"` → `cmd ... "join transfer"`。

## bench の状態

`$LEANMESH_HIL_DIR`（既定 `~/.cache/leanmesh/hil`）。最初の network は従来のまま（top-level の `fleet_id domain host_id root leaves
assignment expected_revision epoch window_revision revoke_revision`）、追加した network は `state.json` の `nets.<name>` に同じ
key で入る。file は network 名を前置する（最初の network は従来の名前）。

| 物 | 最初の network | `netB` |
|---|---|---|
| USB kit（Host の鍵、fleet trust anchor、domain） | `usb-kit.cbor` | `usb-kit-netB.cbor` |
| Host の DB | `host.db` | `host-netB.db` |
| Host の Unix socket（`--uds`） | `$LEANMESH_HIL_SOCK`（既定 `/tmp/claude-501/lm.sock`） | 同じ stem に `-netB`（`LEANMESH_HIL_SOCK_NETB` で変更） |
| root の object | `objects/root-{device,delegation}.cose` | `objects/netB-root-{device,delegation}.cose` |
| tokens / token | `tokens.json` / `token`（全 network 共通） | 同左 |

`transfer` は ticket を `objects/<leaf>-transfer-to-<net>.cose`（`--preapproved` では `...-expected.cose` も）に残し、
成功したら leaf の record を移設先 network へ移して `transfer` の履歴（from / to / ticket）を付ける。
`init --name` は同じ fleet の 2 つ目の domain を作るだけで、既存の network には触れない。

## 見るところ

- `ticket` が `ERR` なら ticket を機器が拒否している（`status` の assign / domain と ticket の source / expected_old が合わない、
  mode 0 の nonce が違う、など。LM status は api/leanmesh.h）。移設の途中で leaf を再起動した場合は `nonce` からやり直す。
- B が ACTIVE にならない: `policy --net netB`（CLOSED は admit しない）、B の承認待ち（`approve --net netB`）、
  `--preapproved` なら ExpectedSet の revision が B の現在より上か、`--grant` と対で発行されたものか。
- `reconcile` は Host A の INSTALL_CONTROL（type 3、`TRANSFER` 権限）を使う。root が移設 ticket で ledger の entry を LEFT に
  することは sim（`lm_install_control`）で確認済みだが、Host の serial 経由と実機は未確認。
- B の join mode は新しい root では EXTERNAL（既定）。`--preapproved` の前に `policy --net netB PREAPPROVED`。
