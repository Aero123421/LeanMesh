"""uvicorn factory for the crash tests: the real Host with the storage fault seam armed by env.

LEANMESH_CRASH=before_commit|after_commit  -> os._exit(9) inside the first `accept` transaction
at that boundary (no flush, no cleanup: what a kill -9 or power cut leaves behind).
"""

from __future__ import annotations

import os

from leanmesh_host.main import create_app
from leanmesh_host.settings import Settings


def make():  # type: ignore[no-untyped-def]
    base = Settings.from_env()
    extra = {k: int(os.environ[v]) for k, v in (("max_events", "T_MAX_EVENTS"),
                                                ("max_page_count", "T_MAX_PAGES"))
             if v in os.environ}
    settings = Settings(**{**base.__dict__, **extra})
    stage = os.environ.get("LEANMESH_CRASH")

    def hook(where: str, fn_name: str) -> None:
        if stage == where and fn_name == "accept":
            os._exit(9)

    return create_app(settings, hook if stage else None)
