"""uvicorn factory for the bridge crash tests: the real Host with the storage fault seam armed by env.

LEANMESH_BRIDGE_CRASH="<stage>:<function>" (stage before_commit|after_commit) -> os._exit(9) inside the
first storage transaction of that function at that boundary: what kill -9 or a power cut leaves behind.
Functions of the bridge: claim_batch (the claim committed, nothing sent yet), apply_send (the root has
the request, the Host has not recorded its answer), commit_inbox (a root message is being stored).
"""

from __future__ import annotations

import os

from leanmesh_host.main import create_app
from leanmesh_host.settings import Settings


def make():  # type: ignore[no-untyped-def]
    settings = Settings.from_env()
    spec = os.environ.get("LEANMESH_BRIDGE_CRASH")
    stage, _, name = (spec or "").partition(":")

    def hook(where: str, fn_name: str) -> None:
        if spec and where == stage and fn_name == name:
            os._exit(9)

    return create_app(settings, hook if spec else None)
