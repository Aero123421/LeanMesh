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
    event_margin: int = 1000  # progress events of already accepted operations may exceed max_events
    max_open_operations: int = 4096
    max_db_bytes: int = 1 << 30
    free_reserve_bytes: int = 128 << 20
    event_retention_ms: int = 7 * 24 * 3600 * 1000  # acknowledged events are kept this long
    max_page_count: int | None = None  # SQLite hard page limit (real SQLITE_FULL in tests)
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
