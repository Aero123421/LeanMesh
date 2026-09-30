"""One storage budget for every externally-driven insert (S7-D15).

Called inside the storage transaction by operation admission, root->Host inbox commits, epoch
opening and consumer registration. Pages on SQLite's freelist are reusable, so they do not count.
Reads, replays and terminal evidence of already accepted work never pass through here.
"""

from __future__ import annotations

import os
import shutil
import sqlite3

from ..api.errors import no_capacity
from ..settings import Settings


def room(conn: sqlite3.Connection, cfg: Settings) -> None:
    used = (conn.execute("PRAGMA page_count").fetchone()[0] - conn.execute("PRAGMA freelist_count").fetchone()[0]
            ) * conn.execute("PRAGMA page_size").fetchone()[0]
    if used >= cfg.max_db_bytes:
        raise no_capacity("db_bytes")
    if shutil.disk_usage(os.path.dirname(os.path.abspath(cfg.db_path))).free < cfg.free_reserve_bytes:
        raise no_capacity("disk_free")
