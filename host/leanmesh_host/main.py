"""FastAPI application: lifespan, authentication, error envelope and GET /v1/status.

Run exactly one worker on the Unix socket (docs/11 §1):
    uvicorn leanmesh_host.main:app --uds /run/leanmesh/api.sock --workers 1
`app` is created lazily from the environment (Settings.from_env) so that importing this module in
tests has no side effects; tests use create_app(Settings(...)).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from . import SPEC_VERSION
from .auth import Principal, authenticate, load_principals, sync_principals
from .settings import Settings
from .storage import StorageBusy, StorageThread


class ApiError(Exception):
    """Maps to the OpenAPI Error schema. `code` uses registry/status names or HTTP-level codes."""

    def __init__(self, http_status: int, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.code = code
        self.message = message
        self.details = details


def _request_id() -> str:
    return os.urandom(16).hex()


def create_app(settings: Settings) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        principals = load_principals(settings.tokens_path)
        storage = StorageThread(settings.db_path, settings.schema_path)
        storage.start()
        try:
            await storage.run(lambda conn: sync_principals(conn, principals))
            app.state.storage = storage
            app.state.principals = principals
            # Set by the serial I/O thread once the authenticated USB session is ACTIVE
            # (USB-SERIAL slice). No serial thread exists yet, so the root is not connected.
            app.state.root_connected = False
            yield
        finally:
            storage.stop()

    app = FastAPI(title="LeanMesh Host", version=SPEC_VERSION, lifespan=lifespan)

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        body: dict[str, Any] = {"code": exc.code, "message": exc.message[:256],
                                "request_id": _request_id()}
        if exc.details:
            body["details"] = exc.details
        return JSONResponse(status_code=exc.http_status, content=body)

    @app.exception_handler(StorageBusy)
    async def _storage_busy(_: Request, exc: StorageBusy) -> JSONResponse:
        return JSONResponse(status_code=503, content={"code": "BUSY", "message": str(exc),
                                                      "request_id": _request_id()})

    def principal(permission: str) -> Any:
        def dependency(request: Request) -> Principal:
            header = request.headers.get("authorization", "")
            scheme, _, token = header.partition(" ")
            if scheme.lower() != "bearer" or not token:
                raise ApiError(401, "UNAUTHENTICATED", "bearer token required")
            found = authenticate(request.app.state.principals, token)
            if found is None:
                raise ApiError(401, "UNAUTHENTICATED", "unknown token")
            if permission not in found.permissions:
                raise ApiError(403, "FORBIDDEN", "permission required", required=permission)
            return found

        return Depends(dependency)

    @app.get("/v1/status")
    async def get_status(request: Request, _: Principal = principal("READ")) -> dict[str, Any]:
        state = request.app.state
        # Capabilities are facts reported by the authenticated root; none are known while it is
        # not connected, so every list is empty (never a guessed "supported").
        return {
            "spec_version": SPEC_VERSION,
            # ready = DB + host USB credential + migrations OK. The USB credential does not exist
            # until the USB-SERIAL slice, so the host is not ready (docs/11 §8).
            "ready": False,
            "root_connected": state.root_connected,
            "journal_id": state.storage.journal_id.hex(),
            "capabilities": {
                "build": [], "implemented": [], "qualified": [], "enabled": [],
                "max_root_depth": 20, "max_path_hops": 40, "max_message_bytes": 512,
                "max_object_bytes": 0,
            },
        }

    return app


def __getattr__(name: str) -> Any:
    # PEP 562: `leanmesh_host.main:app` for uvicorn/systemd (config/leanmesh.service.example).
    if name == "app":
        return create_app(Settings.from_env())
    raise AttributeError(name)
