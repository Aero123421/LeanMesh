"""Pure mapping between the root's serial results and the Host's operation model (no I/O).

Nothing here invents evidence: a fact is added only for a bit the root reported, with the assurance
that fact really has (docs/08 §3): root-local facts are SELF_REPORTED by the root, HOP_ACK is
LINK_VERIFIED, destination receipts are END_VERIFIED.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..wire import cbor_encode

# api/leanmesh.h LM_STATUS_* (checked against protocol/registry.json by the bridge unit test).
STATUS_NAMES = (
    "OK", "INVALID_ARGUMENT", "UNSUPPORTED", "BUSY", "NO_CAPACITY", "NO_ROUTE", "AUTH_PENDING",
    "AUTH_REJECTED", "REVOKED", "CONFLICT", "EXPIRED", "TIME_UNCERTAIN", "RX_WINDOW_CLOSED",
    "RF_PROFILE_UNAPPROVED", "STORAGE_FAILURE", "RECOVERY_REQUIRED", "DRIVER_RESULT_UNKNOWN",
    "BUFFER_TOO_SMALL", "CANCEL_TOO_LATE", "CURSOR_GAP", "EPOCH_CLOSED", "PAYLOAD_TOO_LARGE",
    "NETWORK_MISMATCH", "ROLE_NOT_ALLOWED", "NOT_FOUND", "BAD_FRAME", "REPLAY", "RATE_LIMITED",
    "ROOT_UNAVAILABLE", "DEADLINE_UNREACHABLE", "POWER_BUDGET_EXHAUSTED", "SLEEP_TICKET_STALE",
    "SESSION_REFRESH_REQUIRED", "PEER_ASLEEP", "TARGET_GENERATION_CHANGED",
)
OK, UNSUPPORTED, CONFLICT, EXPIRED, NOT_FOUND, CANCEL_TOO_LATE = 0, 2, 9, 10, 24, 18
# Local, temporary shortages of the root: nothing was accepted, the same request may be repeated.
TRANSIENT = frozenset({3, 4, 5, 6, 11, 28})


def status_name(code: int) -> str:
    return STATUS_NAMES[code] if 0 <= code < len(STATUS_NAMES) else f"STATUS_{code}"


# lm_operation_t.evidence_bits (src/core/delivery/types.hpp ev::*): what the root observed.
EVIDENCE_BITS = (
    (1 << 0, "ROOT_ACCEPTED", "SELF_REPORTED"),
    (1 << 1, "ROOT_PERSISTED", "SELF_REPORTED"),
    (1 << 2, "ROOT_SENT", "SELF_REPORTED"),
    (1 << 3, "HOP_ACCEPTED", "LINK_VERIFIED"),
    (1 << 4, "END_RECEIVED", "END_VERIFIED"),
    (1 << 5, "APP_PENDING", "END_VERIFIED"),
    (1 << 6, "APP_APPLIED", "END_VERIFIED"),
    (1 << 7, "APP_REJECTED", "END_VERIFIED"),
    (1 << 8, "DESTINATION_REFUSED", "END_VERIFIED"),
)
PHASES = ("PENDING", "SENDING", "WAITING_RECEIPT", "FINAL")
OUTCOMES = ("PENDING", "RECEIVED", "APPLIED", "REJECTED", "EXPIRED", "CANCELLED_NOT_SENT",
            "INDETERMINATE", "SUPERSEDED", "PARTIAL", "SUBMITTED")
MEMBERSHIP = {0: "UNASSIGNED", 4: "PREPARED", 5: "ACTIVE"}  # lm_membership state numbers the root reports

_DELIVERY = {"BEST_EFFORT": 0, "RECEIVED": 1, "APPLIED": 2}
_STORAGE = {"VOLATILE": 0, "DURABLE": 1}
_PRIORITY = {"BULK": 0, "NORMAL": 1, "URGENT": 2}


def send_flags(request: dict[str, Any]) -> int:
    """docs/09 §2 flags: bits 0..1 delivery, bits 2..3 priority, bit 4 durable."""
    return (_DELIVERY[request["delivery"]] | _PRIORITY[request["priority"]] << 2
            | _STORAGE[request["storage"]] << 4)


def intent_hash(root: bytes, target: bytes, domain: bytes, request: dict[str, Any], term: int,
                expires_root_ms: int, payload: bytes) -> bytes:
    """docs/08 §2: SHA-256 of deterministic CBOR [origin, target, domain, port, delivery, storage,
    priority, effective_root_term, expires_root_ms, payload]. The origin is the root (the Host sends
    as the root's application); the root recomputes it and refuses another value."""
    fields = [root, target, domain, request["app_port"], _DELIVERY[request["delivery"]],
              _STORAGE[request["storage"]], _PRIORITY[request["priority"]],
              term if expires_root_ms else 0, expires_root_ms, payload]
    return hashlib.sha256(cbor_encode(fields)).digest()


def snapshot_evidence(root: bytes, snap: dict[str, Any], have: set[str]) -> list[dict[str, Any]]:
    """Evidence entries for the reported bits that the operation does not hold yet, in bit order."""
    bits = int(snap.get("evidence_bits", 0))
    return [{"kind": kind, "assurance": assurance, "observer": root.hex()}
            for bit, kind, assurance in EVIDENCE_BITS if bits & bit and kind not in have]


def outcome_evidence(root: bytes, snap: dict[str, Any]) -> dict[str, Any] | None:
    """The root's final word on an operation, only when it reports one (phase FINAL)."""
    if snap.get("phase") != 3 or OUTCOMES[snap["outcome"]] == "PENDING":
        return None
    details: dict[str, Any] = {"outcome": OUTCOMES[snap["outcome"]]}
    if snap.get("reason"):
        details["reason"] = status_name(int(snap["reason"]))
    return {"kind": "ROOT_OUTCOME", "assurance": "SELF_REPORTED", "observer": root.hex(),
            "details": details}
