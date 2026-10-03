"""Start-up: options, the bench state file (board names), the Host client, the engine and the local web server.

    PYTHONPATH=host ~/.cache/leanmesh/host-venv/bin/python -m tools.fieldview     (from the repository root)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from .engine import Config, FieldView, load_bench
from .hostclient import HostClient
from .recorder import Recorder, session_dir
from .web import make_app

HIL_DIR = Path(os.environ.get("LEANMESH_HIL_DIR", Path.home() / ".cache/leanmesh/hil"))
DEFAULT_SOCKET = "/tmp/claude-501/lm.sock"


def net_socket(net: str | None) -> str:
    """The Host socket of a bench network, by the rule of tools/hil/hil.py (Net.sock)."""
    first = os.environ.get("LEANMESH_HIL_SOCK", DEFAULT_SOCKET)
    if net is None:
        return first
    return os.environ.get(f"LEANMESH_HIL_SOCK_{net.upper()}", f"{first.removesuffix('.sock')}-{net}.sock")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="fieldview", description="Field test viewer: one local page next to the LeanMesh Host.")
    p.add_argument("--socket", help="the Host's Unix socket (default: the bench's, $LEANMESH_HIL_SOCK or "
                                    f"{DEFAULT_SOCKET}; with --net the network's)")
    p.add_argument("--token-file", type=Path, help=f"bearer token file (default {HIL_DIR / 'token'}; or $LEANMESH_TOKEN)")
    p.add_argument("--domain", help="domain id, 32 hex (default: $LEANMESH_DOMAIN, else the bench state file)")
    p.add_argument("--net", help="a further bench network of the state file (hil.py --net)")
    p.add_argument("--state-file", type=Path, default=HIL_DIR / "state.json",
                   help="bench state file for board names, the root id and the domain")
    p.add_argument("--port", type=int, default=8091, help="local web port on 127.0.0.1 (default 8091)")
    p.add_argument("--logs-dir", type=Path, default=Path("logs/fieldview"),
                   help="records go to <logs-dir>/<UTC timestamp>/ (default ./logs/fieldview)")
    p.add_argument("--interval", type=float, default=10.0, help="telemetry interval assumed, s (default 10)")
    p.add_argument("--consumer", default="fieldview", help="Host event consumer name (default fieldview)")
    return p.parse_args(argv)


def build(args: argparse.Namespace) -> tuple[Config, HostClient, Recorder]:
    bench = load_bench(args.state_file, args.net)
    domain = args.domain or os.environ.get("LEANMESH_DOMAIN") or bench.get("domain")
    if not domain:
        raise SystemExit("no domain: pass --domain, set $LEANMESH_DOMAIN or have a bench state file")
    token = os.environ.get("LEANMESH_TOKEN")
    if not token:
        path = args.token_file or HIL_DIR / "token"
        try:
            token = path.read_text().strip()
        except OSError as exc:
            raise SystemExit(f"no token: {exc} (--token-file or $LEANMESH_TOKEN)") from exc
    sock = args.socket or net_socket(args.net)
    cfg = Config(socket=sock, token=token, domain=domain, logs_dir=args.logs_dir, interval_s=args.interval,
                 consumer=args.consumer, names=bench.get("names", {}), root_id=bench.get("root_id"))
    recorder = Recorder(session_dir(args.logs_dir))
    return cfg, HostClient(sock, token, domain), recorder


async def amain(args: argparse.Namespace) -> int:
    import uvicorn

    cfg, client, recorder = build(args)
    fv = FieldView(cfg, client, recorder)
    await fv.start()
    server = uvicorn.Server(uvicorn.Config(make_app(fv, args.port), host="127.0.0.1", port=args.port,
                                           log_level="warning", access_log=False))
    print(f"fieldview: http://127.0.0.1:{args.port}/  Host socket {cfg.socket}  records {recorder.directory}",
          flush=True)
    try:
        await server.serve()
    finally:
        await fv.stop()
        await client.aclose()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not 0 < args.port < 65536 or args.interval <= 0:
        print("fieldview: bad --port or --interval", file=sys.stderr)
        return 2
    try:
        return asyncio.run(amain(args))
    except KeyboardInterrupt:
        return 130
