# はじめに（ビルド・試験・シミュレータ実行）

このページのコマンドは、リポジトリのルートで実際に実行したものです（結果は末尾の「確認した内容」）。書込み（flash）は一度も行いません。

## 1. 前提

| 必要なもの | バージョン | 用途 |
|---|---|---|
| ESP-IDF | **v6.0.3**（`config/dependencies.json` のcommitに固定）を `~/esp/esp-idf-v6.0.3` へ | native buildがTF-PSA-Cryptoのソースを借りる、firmware build |
| CMake / Ninja / g++ | 3.28 / 1.11 / C++17対応 | native build |
| Python | 3.12 | Host、試験、`scripts/` |
| git | submodule対応 | libedhoc（固定commit + patch） |

IDFは `install.sh esp32s3,esp32c3,esp32c5,esp32c6` 済みであること。`scripts/build_targets.sh` はIDFのHEADが固定commitと違う、または未コミットの変更があると**拒否**します。
ビルド出力・venvは `~/.cache/leanmesh/` の下に作ります（リポジトリ内に置くと `check_spec.py` がjson/mdを拾うため禁止）。

## 2. 取得と第三者コード

```sh
git clone <repo> LeanMesh && cd LeanMesh && git checkout feat/sdk-impl
scripts/third_party.sh setup     # libedhoc v2.3.2 + zcbor の submodule と exact-input patch（冪等）
scripts/third_party.sh verify    # commit と blob id を検証。1つでも違えば exit 1
```

## 3. native build と ctest

```sh
cmake -S . -B ~/.cache/leanmesh/native -G Ninja      # IDF_PATH か -DLM_IDF_PATH=... を参照
cmake --build ~/.cache/leanmesh/native
ctest --test-dir ~/.cache/leanmesh/native --output-on-failure -j4
```

成果物: `meshsim`（シミュレータ）、`libleanmesh_host.so`（Hostが使うEDHOC/record C library）、`tests/native/test_*`。
Sanitizer（ASan+UBSan）: 別ディレクトリで `-DLM_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug`。

```sh
cmake -S . -B ~/.cache/leanmesh/native-asan -G Ninja -DLM_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build ~/.cache/leanmesh/native-asan
ctest --test-dir ~/.cache/leanmesh/native-asan --output-on-failure -j2
```

## 4. Hostのvenvとpytest

```sh
scripts/setup_host_venv.sh sync-dev                        # hash固定のlockから ~/.cache/leanmesh/host-venv
~/.cache/leanmesh/host-venv/bin/python -m pytest           # unit + integration + E2E
```

E2Eは `$LEANMESH_NATIVE_BUILD`（既定 `~/.cache/leanmesh/native`）の `meshsim` を起動し、無ければ**skipせず失敗**します。
一部だけ実行する場合は、`... -m pytest host/tests/unit host/tests/integration`（meshsim不要）、`... -m pytest host/tests/e2e -k fullstack -s`（21 node / 20 hop）。E2E全体は実時間で動くため数分かかります。

## 5. ESP-IDF build（4 SoC、LEAF / RELAY / ROOT）

```sh
scripts/build_targets.sh --app example_node esp32c3                     # LEAF、1 SoC
scripts/build_targets.sh --app example_node --profile RELAY esp32c3
scripts/build_targets.sh --app example_node --profile ROOT  esp32c3     # root専用コード（topology/ledger/USB bridge）を含む
scripts/build_targets.sh                                                # 全app × esp32s3/c3/c5/c6（LEAF）
```

| app | 内容 |
|---|---|
| `baseline_espnow` | ESP-NOWだけの空firmware。サイズ比較の基準（SDK差分 = example_node − baseline） |
| `example_node` | 同じ起動処理 + SDK。`lm_init` → `lm_start` を呼ぶ |
| `crypto_link_check` | libedhoc と IDF PSA がリンクできることの確認（書込まない） |

profileはKconfig `LEANMESH_PROFILE_{LEAF,RELAY,ROOT}`（固定poolの大きさとroot専用コードの有無）で、`--profile` が選びます。
出力: `~/.cache/leanmesh/build/<app>[-PROFILE]/<soc>/`（`LEANMESH_BUILD_ROOT` で変更）。**flashは行いません**。
ROOT を C3 に載せる構成は、実機の空きheap未測定のため**未対応扱い**です（[ADR-002](../../decisions/ADR-002-budget-status.md)）。
`LEANMESH_RF_DEPLOYMENT_APPROVED` が既定 n のため、このビルドをそのまま書込んでも `lm_start` は `RF_PROFILE_UNAPPROVED` を返し、無線は動きません（意図した安全側）。

## 6. meshsim と Host を動かす

meshsim は「実際のC++ coreを載せたN台 + 仮想電波」のプロセスです。stdinへ1行1コマンド、stdoutへ1行1 JSONで答えます。
root（node 0）のUSB serialは pty で公開され、本物のHostが認証済みUSBセッションで接続します。
下は E2E が使う手順（`host/tests/e2e/bridge_bench.py`）をそのまま書いた3 node（root - relay - leaf）の例です。

```python
# run_demo.py  (venv の python で:  python run_demo.py . /tmp/lm-demo)
import os, subprocess, sys, time
from pathlib import Path
REPO, WORK = Path(sys.argv[1]).resolve(), Path(sys.argv[2]); WORK.mkdir(parents=True, exist_ok=True)
sys.path[:0] = [str(REPO / "host"), str(REPO / "host/tests")]
from harness import MeshSim, HostProcess, meshsim_binary   # MeshSim: process + JSON-lines control

sim = MeshSim.start(meshsim_binary(), "--nodes", "3", "--topology", "chain", "--clock", "realtime",
                    "--serial-pty", "--serial-bridge", "--mesh", "--leaf-last", "--seed", "1")
kit = WORK / "kit.cbor"
sim.ok("provision 0 1 root")             # TEST-ONLY 鍵と資格情報を node 0 のStoreへ
sim.ok(f"serial-kit {kit} 0")            # Hostが使うUSB kit（Host用identity + trust anchor）
sim.ok("serial-pair 0 0")
sim.ok("provision 1 2 relay"); sim.ok("provision 2 3 leaf")
for i in range(3): sim.ok(f"start {i}")
time.sleep(1)
sim.ok(f"root-time all 1 {int(sim.ok('status')['now_us']) // 1000}")
while not all(sim.ok(f"mesh {i}")["state"] == "ready" for i in (1, 2)): time.sleep(0.5)
m = sim.ok("membership 2")                 # domain / device id を得る
HostProcess.write_tokens(WORK / "tokens.json", "demo-token", ["READ", "SEND", "CONFIGURE"])
env = dict(os.environ, LEANMESH_DB=str(WORK / "host.db"), LEANMESH_TOKENS=str(WORK / "tokens.json"),
           LEANMESH_SERIAL=sim.ready["serial_pty"], LEANMESH_USB_KIT=str(kit))
sock = WORK / "api.sock"; sock.unlink(missing_ok=True)
host = subprocess.Popen([sys.executable, "-m", "uvicorn", "leanmesh_host.main:app", "--uds", str(sock),
                         "--workers", "1", "--app-dir", str(REPO / "host")], env=env)
print("domain", m["domain"], "leaf", m["device"], "socket", sock, flush=True)
try: time.sleep(10**6)
except KeyboardInterrupt: host.terminate(); sim.close()
```

別の端末から:

```sh
S=/tmp/lm-demo/api.sock; H="Authorization: Bearer demo-token"
curl -s --unix-socket $S -H "$H" http://localhost/v1/status     # root_connected: true, capabilities
curl -s --unix-socket $S -H "$H" http://localhost/v1/health
```

送信の例は [host.md](host.md)。`--clock realtime` はHostが実時間で動くために必要です（`virtual` は `run <ms>` で進める）。
meshsimはプロトコル試験台で、RSSI・RF・電力を持ちません。**この結果を実機の性能の根拠にしません**。

## 7. 出力の場所

| 何 | どこ |
|---|---|
| native build | `~/.cache/leanmesh/native*`（`LEANMESH_NATIVE_BUILD`） |
| Host venv | `~/.cache/leanmesh/host-venv`（`LEANMESH_VENV`） |
| firmware build | `~/.cache/leanmesh/build`（`LEANMESH_BUILD_ROOT`） |
| Hostの状態 | `LEANMESH_DB` のSQLite（demoでは `$WORK/host.db`） |
| 予算・網羅の記録 | `build-records/`（[testing.md](testing.md)） |

仕様検査は `python scripts/check_spec.py` のあと `git checkout evidence/VALIDATION.json`（検査が再生成するため）。

## 確認した内容（2026-09-30、FIX13の作業中のtree〈`57a2b66` + 未commitの変更〉、Linux x86-64、IDF v6.0.3）

ローカルの実行結果です。マージ前に流す確認の一覧は [testing.md](testing.md) §2。数と日付はこの実行のもので、以降のtreeでは変わります。

| コマンド | 結果 |
|---|---|
| native `cmake` + build、`ctest -j3` | 27/27 passed |
| ASan+UBSan build の `ctest -j3` | 26/27 passed、`test_power` がtimeout（3並列 + 他の作業と同時のため）。単独の `ctest -R test_power` は passed（約77 s） |
| `test_model`（`LM_MODEL_SEEDS=1600` = 1600 seed + 回帰5） | 1605 seeds、0 invariant failures |
| `pytest host/tests`（unit + integration + E2E、約9分） | 236 passed。初回の1回だけ `test_fix11_root_binding_follows_a_completed_handover_and_nothing_else` が失敗し（並行して編集中のHost側と重なった疑い、原因は未特定）、単独と全体の再実行では passed |
| `build_targets.sh --app example_node`（esp32c3 の LEAF と ROOT） | 2 build成功。他のSoC・RELAYはこの作業では再buildしていない |
| `check_spec.py`（後に `git checkout evidence/VALIDATION.json`） | PASS |

**実行していないもの**: flash、実機での起動、RF。`baseline_espnow` と `crypto_link_check` のbuildは今回の実行に含めていません（[testing.md](testing.md) §2 の対象）。
