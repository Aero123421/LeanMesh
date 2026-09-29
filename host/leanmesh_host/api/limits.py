"""ASGI guard for the 32 KiB request cap (docs/11 §3). Rejects before the body is buffered."""

from __future__ import annotations

import os
from typing import Any

MAX_REQUEST_BYTES = 32 * 1024


class BodyLimit:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_REQUEST_BYTES:
            await self._reject(send)
            return
        seen = 0
        rejected = False

        async def counted() -> Any:
            nonlocal seen, rejected
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > MAX_REQUEST_BYTES:
                    rejected = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def guarded_send(message: Any) -> None:
            if rejected:
                return
            await send(message)

        await self.app(scope, counted, guarded_send)
        if rejected:
            await self._reject(send)

    @staticmethod
    async def _reject(send: Any) -> None:
        body = (b'{"code":"PAYLOAD_TOO_LARGE","message":"request exceeds 32 KiB","request_id":"'
                + os.urandom(16).hex().encode() + b'"}')
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
