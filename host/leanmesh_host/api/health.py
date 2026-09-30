"""GET /v1/health (the Host's own state) and GET /v1/diagnostics (the root's, on request). S19 / T19.

Neither endpoint runs by itself, keeps a timer or asks the root more than once a second (Bridge.diagnostics). Health
answers from committed Host state and the link/bridge flags; it never claims a root fact the root did not report.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from ..auth import Principal
from ..events.hub import Hub
from .deps import require
from .errors import ApiError

router = APIRouter(prefix="/v1")


@router.get("/health")
async def get_health(request: Request, _: Principal = require("READ")) -> dict[str, Any]:
    hub: Hub = request.app.state.hub
    link = getattr(request.app.state, "serial", None)
    bridge = getattr(request.app.state, "bridge", None)
    try:
        await hub.read(lambda conn: conn.execute("SELECT 1").fetchone())
        database = "OK"
    except Exception:  # any failure to answer a trivial read is reported, not hidden (the details are in the log)
        database = "FAILED"
    serial = "NOT_CONFIGURED" if link is None else ("CONNECTED" if link.connected else "DISCONNECTED")
    root = "NOT_CONFIGURED" if bridge is None else ("READY" if bridge.ready else "NOT_READY")
    return {"ready": link is not None and database == "OK", "database": database, "serial": serial, "root": root,
            "root_connected": hub.root_connected, "journal_id": hub.storage.journal_id.hex()}


@router.get("/diagnostics")
async def get_diagnostics(request: Request, _: Principal = require("READ")) -> dict[str, Any]:
    bridge = getattr(request.app.state, "bridge", None)
    if bridge is None:
        raise ApiError(503, "ROOT_UNAVAILABLE", "no root bridge is configured")
    return await bridge.diagnostics()
