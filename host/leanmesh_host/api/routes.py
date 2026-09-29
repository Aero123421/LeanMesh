"""All /v1 endpoints except GET /v1/status. Handlers validate, authorise, then run exactly one
storage transaction (Hub.write) whose function is named `accept`/... so crash tests can target it.
Responses are plain dicts shaped by api/openapi.json (the tests validate them against it).
"""

from __future__ import annotations

import asyncio
import json
import re
import sqlite3
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import StreamingResponse

from ..auth import Principal
from ..db import mirror, ops
from ..events import journal
from ..events.hub import Hub
from . import codec
from .deps import WRITE_PERMISSIONS, need_all, require
from .errors import ApiError, invalid
from .models import (CONTROL_RULES, MAX_MESSAGE_BYTES, MAX_OBJECT_BYTES, ConsumerAck, ControlRequest,
                     DeadlineUtc, DestGroup, DestNode, EpochRequest, MessageRequest)

router = APIRouter(prefix="/v1")
_IDEM = re.compile(r"^[\x21-\x7e]{1,128}$")
_CONSUMER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SSE_STAGE_EVENTS = 128
_SSE_STAGE_BYTES = 256 * 1024
_SSE_LIFETIME_S = 300.0  # clients reconnect with Last-Event-ID; bounds a stalled connection
_SSE_KEEPALIVE_S = 15.0
_LONG_POLL_MAX_MS = 15000

IdemKey = Annotated[str, Header(alias="Idempotency-Key")]
Domain = Annotated[str, Query()]


def _hub(request: Request) -> Hub:
    return request.app.state.hub  # type: ignore[no-any-return]


def _idem(key: str) -> str:
    if not _IDEM.match(key):
        raise invalid("Idempotency-Key must be 1..128 printable ASCII characters")
    return key


def _dump(body: Any, *drop: str) -> tuple[dict[str, Any], bytes]:
    """(stored request document without large blobs, canonical hash over the full request)."""
    full = body.model_dump(mode="json", exclude_none=True)
    return {k: v for k, v in full.items() if k not in drop}, codec.request_hash(full)


# ---- epochs -------------------------------------------------------------------------------------
@router.post("/epochs", status_code=201)
async def open_epoch(body: EpochRequest, request: Request, idempotency_key: IdemKey,
                     p: Principal = require(*WRITE_PERMISSIONS)) -> dict[str, str]:
    key = _idem(idempotency_key)

    def open_(conn: sqlite3.Connection) -> dict[str, str]:
        return ops.open_epoch(conn, _hub(request).cfg, p.id, key, body.request_id)

    return await _hub(request).write(open_)


@router.post("/epochs/{epoch_id}/close")
async def close_epoch(epoch_id: str, request: Request,
                      p: Principal = require(*WRITE_PERMISSIONS)) -> dict[str, str]:
    epoch = codec.hex_bytes(epoch_id, 16, "epoch_id")
    return await _hub(request).write(lambda conn: ops.close_epoch(conn, p.id, epoch))


# ---- messages -----------------------------------------------------------------------------------
@router.post("/messages", status_code=202)
async def submit_message(body: MessageRequest, request: Request, idempotency_key: IdemKey,
                         p: Principal = require("SEND")) -> dict[str, Any]:
    hub = _hub(request)
    payload = body.payload()
    if len(payload) > (MAX_OBJECT_BYTES if body.object_transfer else MAX_MESSAGE_BYTES):
        raise ApiError(413, "PAYLOAD_TOO_LARGE", "payload exceeds the message limit")
    dest = body.destination
    if isinstance(dest, DestGroup) and (body.storage == "DURABLE" or body.queue_mode == "LATEST"):
        # No compact durable group record and no LATEST group (docs/22 §4, §6): an explicit UNSUPPORTED.
        raise ApiError(503, "UNSUPPORTED", "durable or LATEST group operations are not available",
                       required_capability="GROUP_FANOUT_V2")
    expiry = body.deadline.expiry_ms() if isinstance(body.deadline, DeadlineUtc) else None
    domain = codec.hex_bytes(body.domain_id, 16)
    target = bytes.fromhex(dest.device_id) if isinstance(dest, DestNode) else None
    request_doc, digest = _dump(body, "payload_b64")
    sub = ops.Submission(
        principal=p.id, domain=domain, epoch=codec.hex_bytes(body.client_epoch, 16),
        idem_key=_idem(idempotency_key), op_type="MESSAGE", request=request_doc, request_hash=digest,
        payload=payload, target=target, expiry_utc_ms=expiry,
        critical=ops.is_critical("MESSAGE", request_doc),
        latest_key=body.coalesce_key if body.queue_mode == "LATEST" else None)

    def precheck(conn: sqlite3.Connection) -> None:
        # Mutable admission state: checked for NEW operations only. An exact retry after a lost
        # response returns the stored operation even if the root or the clock moved on (S7-D8).
        if isinstance(dest, DestGroup) and "GROUP_FANOUT_V2" not in hub.capabilities:
            raise ApiError(503, "UNSUPPORTED", "the root has no group fan-out", required_capability="GROUP_FANOUT_V2")
        if body.object_transfer and "OBJECT_4K" not in hub.capabilities:
            raise ApiError(503, "UNSUPPORTED", "object transfer is not enabled", required_capability="OBJECT_4K")
        if expiry is not None and expiry <= journal.now_ms():
            raise ApiError(400, "EXPIRED", "deadline is already in the past")
        if target is not None and conn.execute("SELECT 1 FROM nodes WHERE domain=? AND device=?",
                                               (domain, target)).fetchone() is None:
            raise ApiError(404, "NOT_FOUND", "destination node not found")

    def accept(conn: sqlite3.Connection) -> dict[str, Any]:
        # Replay (same key + same request) returns the stored operation and writes nothing.
        return ops.accept(conn, hub.cfg, sub, precheck)[0]

    return await hub.write(accept)


# ---- control ------------------------------------------------------------------------------------
@router.post("/control", status_code=202)
async def submit_control(body: ControlRequest, request: Request, idempotency_key: IdemKey,
                         p: Principal = require(*WRITE_PERMISSIONS)) -> dict[str, Any]:
    hub = _hub(request)
    need_all(p, body.permissions())
    rule = CONTROL_RULES[body.type]
    domain = codec.hex_bytes(body.domain_id, 16)
    request_doc, digest = _dump(body, "signed_cbor_b64")
    signed = codec.decode_b64(body.signed_cbor_b64) if body.signed_cbor_b64 else None
    expected = codec.parse_u63(body.expected_revision)
    target = bytes.fromhex(body.device_id) if body.device_id else None
    # The Host checks base64/size/permission/revision it can know. Signatures, delegation and
    # target-side rules are verified by the root; its rejection arrives as REJECTED evidence.
    sub = ops.Submission(
        principal=p.id, domain=domain, epoch=codec.hex_bytes(body.client_epoch, 16),
        idem_key=_idem(idempotency_key), op_type=body.type, request=request_doc, request_hash=digest,
        payload=signed, target=target, expiry_utc_ms=None, critical=True)

    def precheck(conn: sqlite3.Connection) -> None:
        if rule.capability and not hub.capabilities.intersection(rule.capability):  # new operations only (S7-D8)
            raise ApiError(503, "UNSUPPORTED", "control type needs a capability the root has not enabled",
                           required_capability=rule.capability[0])
        current = None
        if body.type == "POLICY_SET":
            current = conn.execute("SELECT policy_revision FROM domains WHERE id=?", (domain,)).fetchone()[0]
        elif body.type == "POWER_POLICY_SET":
            row = conn.execute("SELECT policy_revision FROM node_power WHERE domain=? AND device=?",
                               (domain, target)).fetchone()
            current = row[0] if row else None
        if current is not None and current != expected:
            raise ApiError(409, "CONFLICT", "expected_revision is stale", current_revision=str(current))

    def accept(conn: sqlite3.Connection) -> dict[str, Any]:
        # Replay (same key + same request) returns the stored operation and writes nothing.
        return ops.accept(conn, hub.cfg, sub, precheck)[0]

    return await hub.write(accept)


# ---- operations ---------------------------------------------------------------------------------
@router.get("/operations/{operation_id}")
async def get_operation(operation_id: str, request: Request,
                        p: Principal = require("READ")) -> dict[str, Any]:
    op = codec.hex_bytes(operation_id, 16, "operation_id")
    return await _hub(request).read(lambda conn: ops.get_operation(conn, p.id, op))


@router.post("/operations/{operation_id}/cancel", status_code=202)
async def cancel_operation(operation_id: str, request: Request,
                           p: Principal = require(*WRITE_PERMISSIONS)) -> dict[str, Any]:
    hub = _hub(request)
    op = codec.hex_bytes(operation_id, 16, "operation_id")
    return await hub.write(lambda conn: ops.cancel(conn, hub.cfg, p.id, op))


@router.get("/operations/{operation_id}/targets")
async def get_group_targets(operation_id: str, request: Request, offset: int = Query(0, ge=0),
                            limit: int = Query(16, ge=1, le=16), snapshot_token: str | None = None,
                            p: Principal = require("READ")) -> dict[str, Any]:
    op = codec.hex_bytes(operation_id, 16, "operation_id")
    if snapshot_token is not None:
        codec.hex_bytes(snapshot_token, 16, "snapshot_token")
    return await _hub(request).read(
        lambda conn: mirror.group_targets(conn, p.id, op, offset, limit, snapshot_token))


# ---- nodes / channel / lifecycle ------------------------------------------------------------------
@router.get("/nodes")
async def list_nodes(request: Request, domain_id: Domain, _: Principal = require("READ")) -> dict[str, Any]:
    domain = codec.hex_bytes(domain_id, 16, "domain_id")
    return await _hub(request).read(lambda conn: mirror.list_nodes(conn, domain))


@router.get("/nodes/{device_id}")
async def get_node(device_id: str, request: Request, domain_id: Domain,
                   _: Principal = require("READ")) -> dict[str, Any]:
    device = codec.hex_bytes(device_id, 32, "device_id")
    domain = codec.hex_bytes(domain_id, 16, "domain_id")
    return await _hub(request).read(lambda conn: mirror.get_node(conn, domain, device))


@router.get("/nodes/{device_id}/power")
async def get_node_power(device_id: str, request: Request, domain_id: Domain,
                         _: Principal = require("READ")) -> dict[str, Any]:
    device = codec.hex_bytes(device_id, 32, "device_id")
    domain = codec.hex_bytes(domain_id, 16, "domain_id")
    return await _hub(request).read(lambda conn: mirror.get_power(conn, domain, device))


@router.get("/channel")
async def get_channel(request: Request, domain_id: Domain, _: Principal = require("READ")) -> dict[str, Any]:
    domain = codec.hex_bytes(domain_id, 16, "domain_id")
    return await _hub(request).read(lambda conn: mirror.get_channel(conn, domain))


@router.get("/lifecycle/requests")
async def list_lifecycle(request: Request, domain_id: Domain,
                         _: Principal = require("READ")) -> dict[str, Any]:
    domain = codec.hex_bytes(domain_id, 16, "domain_id")
    return await _hub(request).read(lambda conn: mirror.list_lifecycle(conn, domain))


# ---- events / consumers -------------------------------------------------------------------------
@router.get("/events")
async def read_events(request: Request, domain_id: Domain, after: str | None = None,
                      limit: int = Query(100, ge=1, le=200),
                      wait_ms: int = Query(0, ge=0, le=_LONG_POLL_MAX_MS),
                      _: Principal = require("READ")) -> dict[str, Any]:
    hub = _hub(request)
    domain = codec.hex_bytes(domain_id, 16, "domain_id")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_ms / 1000
    seen = hub.version
    page = await hub.read(lambda conn: journal.read_page(conn, domain, after, limit))
    if page["events"] or wait_ms == 0:
        return page
    with hub.subscription():
        while not hub.closing and loop.time() < deadline:
            await hub.wait(seen, deadline - loop.time())
            seen = hub.version
            page = await hub.read(lambda conn: journal.read_page(conn, domain, after, limit))
            if page["events"]:
                break
    return page


@router.get("/events/stream")
async def stream_events(request: Request, domain_id: Domain,
                        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
                        _: Principal = require("READ")) -> StreamingResponse:
    """SSE carrying the same events as GET /v1/events, in stages of <=128 events / 256 KiB.
    Delivery over SSE is not an acknowledgement (that is POST /v1/consumers/{name}/ack). A reader
    that fell behind retention receives one `gap` event and the stream ends."""
    hub = _hub(request)
    domain = codec.hex_bytes(domain_id, 16, "domain_id")
    hub.check_subscriber_capacity()
    seen = hub.version
    first = await hub.read(lambda conn: journal.read_page(
        conn, domain, last_event_id, _SSE_STAGE_EVENTS, _SSE_STAGE_BYTES))  # 4xx before streaming

    async def frames() -> AsyncIterator[bytes]:
        loop = asyncio.get_running_loop()
        end = loop.time() + _SSE_LIFETIME_S
        nonlocal seen
        page = first
        with hub.subscription():
            while True:
                for event in page["events"]:
                    data = json.dumps(event, separators=(",", ":"))
                    yield f"id: {event['cursor']}\nevent: {event['kind']}\ndata: {data}\n\n".encode()
                cursor = page["next_cursor"]
                if hub.closing or loop.time() >= end:
                    return
                if not page["events"]:
                    await hub.wait(seen, min(_SSE_KEEPALIVE_S, end - loop.time()))
                    if hub.version == seen:
                        yield b": keepalive\n\n"
                seen = hub.version  # taken before the read: a commit in between wakes the next wait
                try:
                    page = await hub.read(lambda conn: journal.read_page(
                        conn, domain, cursor, _SSE_STAGE_EVENTS, _SSE_STAGE_BYTES))
                except ApiError as err:  # retention overtook this reader: tell it, then close
                    body = {"code": err.code, "message": err.message, "details": err.details}
                    yield f"event: gap\ndata: {json.dumps(body)}\n\n".encode()
                    return

    return StreamingResponse(frames(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store"})


@router.post("/consumers/{name}/ack")
async def ack_consumer(name: str, body: ConsumerAck, request: Request,
                       p: Principal = require("READ")) -> dict[str, Any]:
    if not _CONSUMER.match(name):
        raise invalid("consumer name must match [A-Za-z0-9._-]{1,64}")
    hub = _hub(request)
    domain = codec.hex_bytes(body.domain_id, 16)
    sequence = codec.parse_u63(body.sequence)

    def ack(conn: sqlite3.Connection) -> dict[str, Any]:
        page = journal.ack(conn, hub.cfg, p.id, name, domain, body.journal_id, sequence)
        journal.prune_acknowledged(conn, hub.cfg)
        return page

    return await hub.write(ack)
