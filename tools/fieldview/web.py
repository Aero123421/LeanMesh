"""The one local page and its small JSON API (127.0.0.1 only). No external script, font or image: the page is the
three files in static/. State-changing requests need a custom header and a local Host header, so another web page in
the same browser cannot press the buttons (CSRF / DNS rebinding)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .engine import FieldView

STATIC = Path(__file__).with_name("static")
GUARD_HEADER = "x-fieldview"


def make_app(fv: FieldView, port: int) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    local_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", "127.0.0.1", "localhost"}
    send_lock = asyncio.Lock()

    @app.middleware("http")
    async def guard(request: Request, call_next: Any) -> Response:
        if request.headers.get("host", "") not in local_hosts:
            return JSONResponse({"error": "this page answers on 127.0.0.1 only"}, status_code=403)
        if request.method != "GET" and request.headers.get(GUARD_HEADER) != "1":
            return JSONResponse({"error": "missing X-Fieldview header"}, status_code=403)
        resp = await call_next(request)
        resp.headers["Cache-Control"] = "no-store"
        return resp  # type: ignore[no-any-return]

    def static(name: str, media: str) -> Response:
        return Response((STATIC / name).read_bytes(), media_type=media)

    @app.get("/")
    async def index() -> Response:
        return static("index.html", "text/html; charset=utf-8")

    @app.get("/app.js")
    async def script() -> Response:
        return static("app.js", "text/javascript; charset=utf-8")

    @app.get("/style.css")
    async def style() -> Response:
        return static("style.css", "text/css; charset=utf-8")

    @app.get("/api/state")
    async def state() -> dict[str, Any]:
        return fv.snapshot()

    @app.post("/api/ping/now")
    async def ping_now() -> Any:
        if send_lock.locked():
            return JSONResponse({"error": "a round is still being sent"}, status_code=409)
        async with send_lock:
            return await fv.ping_round(3.0, max_wait=6.0)

    @app.post("/api/ping/loop")
    async def ping_loop(request: Request) -> Any:
        body = await _json(request)
        action = body.get("action")
        if action == "stop":
            await fv.stop_ping_loop()
            return fv.ping_status()
        if action != "start":
            return JSONResponse({"error": "action is start or stop"}, status_code=400)
        try:
            interval = float(body.get("interval_s"))
        except (TypeError, ValueError):
            return JSONResponse({"error": "interval_s must be a number"}, status_code=400)
        try:
            await fv.start_ping_loop(interval)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        return fv.ping_status()

    @app.post("/api/display")
    async def display(request: Request) -> Any:
        body = await _json(request)
        device, state = body.get("device"), body.get("state")
        if not isinstance(device, str) or not isinstance(state, str):
            return JSONResponse({"error": "device and state are required"}, status_code=400)
        try:
            return await fv.send_display(device, state)
        except LookupError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        except RuntimeError as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)

    return app


async def _json(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}
