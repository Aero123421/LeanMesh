"""Process settings from the environment (no config DB, no hidden defaults for secrets)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


class SettingsError(RuntimeError):
    """A required setting is missing or invalid; the service must not start."""


@dataclass(frozen=True)
class Settings:
    db_path: Path
    tokens_path: Path
    schema_path: Path
    serial_device: str | None = None
    # Capacity (docs/11 §7). Tests shrink these to reach the limits with a few requests.
    max_events: int = 1_000_000
    # Progress events of accepted operations may exceed max_events by this margin. Admission keeps
    # op_event_reserve slots free per open operation, so the margin must cover
    # max_open_operations * op_event_reserve (S7-D14).
    event_margin: int = 4096 * 4
    op_event_reserve: int = 4  # journal events one operation may ever use: HOST_COMMITTED, progress, terminal
    max_open_operations: int = 4096
    max_db_bytes: int = 1 << 30
    free_reserve_bytes: int = 128 << 20
    event_retention_ms: int = 7 * 24 * 3600 * 1000  # acknowledged events are kept this long
    # SQLite hard page limit: 25 % above the soft max_db_bytes budget, so a transaction that slips
    # past the soft check fails with SQLITE_FULL (-> 507), never fills the disk (S7-D15).
    max_page_count: int | None = (1 << 30) * 5 // 4 // 4096
    max_epochs_per_principal: int = 1024  # open + closed epochs kept per principal
    epoch_retention_ms: int = 24 * 3600 * 1000  # closed epochs without operations are dropped after this
    max_consumers: int = 64
    max_consumers_per_principal: int = 8
    consumer_lease_ms: int = 7 * 24 * 3600 * 1000  # every ACK renews it; an expired consumer pins nothing
    max_subscribers: int = 64  # long-poll waiters + SSE streams

    @staticmethod
    def from_env() -> Settings:
        def required(name: str) -> str:
            value = os.environ.get(name)
            if not value:
                raise SettingsError(f"{name} is required")
            return value

        return Settings(
            db_path=Path(required("LEANMESH_DB")),
            tokens_path=Path(required("LEANMESH_TOKENS")),
            # db/schema.sql is the normative schema; packaging copies it next to the package.
            schema_path=Path(os.environ.get("LEANMESH_SCHEMA", _REPO_ROOT / "db" / "schema.sql")),
            serial_device=os.environ.get("LEANMESH_SERIAL") or None,
        )
