"""FastAPI application: lifespan, error envelope, GET /v1/status; endpoints live in api/routes.py.

Run exactly one worker on the Unix socket (docs/11 §1):
    uvicorn leanmesh_host.main:app --uds /run/leanmesh/api.sock --workers 1
`app` is created lazily from the environment (Settings.from_env) so that importing this module in
tests has no side effects; tests use create_app(Settings(...)).

Where the serial bridge plugs in (S13): `app.state.hub` (Hub.write/read, Hub.set_root,
Hub.outbox_ready) and the outbox/inbox functions in db/outbox.py and events/journal.py.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import SPEC_VERSION
from .api import routes
from .api.deps import require
from .api.errors import ApiError
from .api.limits import BodyLimit
from .auth import Principal, load_principals, sync_principals
from .db import startup
from .events.hub import Hub
from .settings import Settings
from .storage import StorageBusy, StorageFull, StorageThread

log = logging.getLogger(__name__)
__all__ = ["ApiError", "create_app"]


def _request_id() -> str:
    return os.urandom(16).hex()


def _envelope(status: int, code: str, message: str, retry_after_ms: int | None = None,
              details: dict[str, Any] | None = None) -> JSONResponse:
    body: dict[str, Any] = {"code": code, "message": message[:256], "request_id": _request_id()}
    if retry_after_ms is not None:
        body["retry_after_ms"] = retry_after_ms
    if details:
        body["details"] = details
    return JSONResponse(status_code=status, content=body)


def create_app(settings: Settings, fault_hook: Any = None) -> FastAPI:
    """`fault_hook` is the storage test seam (crash tests); production passes nothing."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        principals = load_principals(settings.tokens_path)
        storage = StorageThread(settings.db_path, settings.schema_path,
                                max_page_count=settings.max_page_count)
        floor_file = startup.FloorFile(settings.db_path.with_name(settings.db_path.name + ".floor"))
        storage.start()
        try:
            hub = Hub(storage, settings)
            found = floor_file.read()
            await storage.run(lambda conn: sync_principals(conn, principals))
            rollback = await storage.run(lambda conn: startup.recover(conn, settings, found))
            if rollback:
                log.error("database is older than the rollback floor (%s): unfinished operations "
                          "are quarantined as INDETERMINATE, epochs closed", rollback)
            floor = await storage.run(startup.current_floor)
            storage.journal_id = floor.journal_id  # recovery may have rotated it
            floor_file.write(floor, sync=True)
            storage.after_commit = lambda conn: floor_file.write(startup.current_floor(conn))
            storage.fault_hook = fault_hook
            app.state.storage = storage
            app.state.hub = hub
            app.state.principals = principals
            yield
        finally:
            if "hub" in locals():
                hub.close()
            storage.stop()
            floor_file.close()

    app = FastAPI(title="LeanMesh Host", version=SPEC_VERSION, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)  # no unauthenticated surface
    app.add_middleware(BodyLimit)
    app.include_router(routes.router)

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return _envelope(exc.http_status, exc.code, exc.message, exc.retry_after_ms, exc.details)

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Field paths only: the offending input may be a payload or a secret and is never echoed.
        fields = [".".join(str(p) for p in e["loc"]) for e in exc.errors()][:8]
        return _envelope(400, "INVALID_ARGUMENT", "request does not match the contract",
                         details={"fields": fields})

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "NOT_FOUND", 405: "INVALID_ARGUMENT"}.get(exc.status_code, "INVALID_ARGUMENT")
        return _envelope(exc.status_code, code, str(exc.detail))

    @app.exception_handler(StorageBusy)
    async def _busy(_: Request, exc: StorageBusy) -> JSONResponse:
        return _envelope(503, "BUSY", str(exc), retry_after_ms=500)

    @app.exception_handler(StorageFull)
    async def _full(request: Request, exc: StorageFull) -> JSONResponse:
        # Not accepted, so no false 202. The fault is persisted best-effort (the write itself may
        # fail on a full database) and stays visible in the log either way.
        hub: Hub = request.app.state.hub
        if not hub.full_reported:
            log.error("storage full: %s", exc)
            hub.full_reported = True
        try:
            hub.storage.submit(lambda conn: startup.set_fault(conn, "DISK_FULL", {"error": str(exc)[:120]}))
        except StorageBusy:
            log.error("could not queue the DISK_FULL health fault")
        return _envelope(507, "NO_CAPACITY", "database is full", details={"resource": "db"})

    @app.exception_handler(sqlite3.Error)
    async def _sqlite(_: Request, exc: sqlite3.Error) -> JSONResponse:
        log.error("sqlite error: %s", exc)
        return _envelope(503, "STORAGE_FAILURE", "database error")

    @app.get("/v1/status")
    async def get_status(request: Request, _: Principal = require("READ")) -> dict[str, Any]:
        hub: Hub = request.app.state.hub
        # Capabilities are facts reported by the authenticated root; none are known while it is
        # not connected, so every list is empty (never a guessed "supported").
        return {
            "spec_version": SPEC_VERSION,
            # ready = DB + host USB credential + migrations OK. The USB credential does not exist
            # until the USB-SERIAL slice, so the host is not ready (docs/11 §8).
            "ready": False,
            "root_connected": hub.root_connected,
            "journal_id": hub.storage.journal_id.hex(),
            "capabilities": {
                "build": [], "implemented": [], "qualified": [], "enabled": sorted(hub.capabilities),
                "max_root_depth": 20, "max_path_hops": 40, "max_message_bytes": 512,
                "max_object_bytes": 4096 if "OBJECT_4K" in hub.capabilities else 0,
            },
        }

    return app


def __getattr__(name: str) -> Any:
    # PEP 562: `leanmesh_host.main:app` for uvicorn/systemd (config/leanmesh.service.example).
    if name == "app":
        return create_app(Settings.from_env())
    raise AttributeError(name)
