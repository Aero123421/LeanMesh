"""Host foundation against a real SQLite file: auth, schema, journal identity, singleton lock."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from leanmesh_host.auth import TokenFileError
from leanmesh_host.main import create_app
from leanmesh_host.settings import Settings
from leanmesh_host.storage import StorageFault

REPO = Path(__file__).resolve().parents[3]


def settings(tmp_path: Path, token: str = "t0k3n", perms: tuple[str, ...] = ("READ",),
             mode: int = 0o600) -> Settings:
    tokens = tmp_path / "tokens.json"
    tokens.write_text(json.dumps({"principals": [{
        "id": "ops", "permissions": list(perms),
        "token_sha256": hashlib.sha256(token.encode()).hexdigest()}]}))
    os.chmod(tokens, mode)
    return Settings(db_path=tmp_path / "host.db", tokens_path=tokens,
                    schema_path=REPO / "db" / "schema.sql")


def test_status_requires_a_known_bearer_token(tmp_path: Path) -> None:
    with TestClient(create_app(settings(tmp_path))) as c:
        assert c.get("/v1/status").status_code == 401
        r = c.get("/v1/status", headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401
        body = r.json()
        assert body["code"] == "UNAUTHENTICATED" and len(body["request_id"]) == 32
        r = c.get("/v1/status", headers={"Authorization": "Bearer t0k3n"})
        assert r.status_code == 200
        status = r.json()
        # No root session exists: nothing is claimed about the mesh.
        assert status["root_connected"] is False and status["ready"] is False
        assert status["capabilities"]["implemented"] == []


def test_permission_is_checked(tmp_path: Path) -> None:
    with TestClient(create_app(settings(tmp_path, perms=("SEND",)))) as c:
        r = c.get("/v1/status", headers={"Authorization": "Bearer t0k3n"})
        assert r.status_code == 403 and r.json()["details"]["required"] == "READ"


def test_journal_id_is_durable_across_restarts(tmp_path: Path) -> None:
    s = settings(tmp_path)
    auth = {"Authorization": "Bearer t0k3n"}
    with TestClient(create_app(s)) as c:
        first = c.get("/v1/status", headers=auth).json()["journal_id"]
    with TestClient(create_app(s)) as c:
        assert c.get("/v1/status", headers=auth).json()["journal_id"] == first


@pytest.mark.scenario("H07")
def test_second_host_on_the_same_database_is_refused(tmp_path: Path) -> None:
    s = settings(tmp_path)
    with TestClient(create_app(s)):
        with pytest.raises(StorageFault):
            with TestClient(create_app(s)):
                pass


def test_world_readable_token_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(TokenFileError):
        with TestClient(create_app(settings(tmp_path, mode=0o644))):
            pass
