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
