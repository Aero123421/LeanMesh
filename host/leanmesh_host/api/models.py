"""Request bodies (extra=forbid, strict types) and the cross-field rules of api/SEMANTICS.md.

Anything the Host can decide from the request alone is rejected here with 400. Anything that needs
root state (signatures, current revisions, capabilities) is checked later or left to the root.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .codec import U63_MAX, decode_b64, parse_u63

Id16 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
DeviceIdStr = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
U63Str = Annotated[str, StringConstraints(pattern=r"^(0|[1-9][0-9]{0,18})$"),
                   AfterValidator(lambda v: (parse_u63(v), v)[1])]
Base64Str = Annotated[str, StringConstraints(max_length=5500),
                      AfterValidator(lambda v: (decode_b64(v), v)[1])]

MAX_MESSAGE_BYTES = 512
MAX_OBJECT_BYTES = 4096


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EpochRequest(Strict):
    request_id: Id16


class ConsumerAck(Strict):
    domain_id: Id16
    journal_id: Id16
    sequence: U63Str


class DestNode(Strict):
    kind: Literal["node"]
    device_id: DeviceIdStr


class DestGroup(Strict):
    kind: Literal["group"]
    group_id: Annotated[int, Field(ge=1, le=0xFFFFFFFF)]
    revision: U63Str


class DestRootApp(Strict):
    kind: Literal["root_app"]


class DeadlineRoot(Strict):
    mode: Literal["root"]
    root_term: Annotated[int, Field(ge=1, le=0xFFFFFFFF)]
    expires_root_ms: U63Str


class DeadlineUtc(Strict):
    mode: Literal["utc"]
    expires_at: str

    def expiry_ms(self) -> int:
        try:
            when = datetime.fromisoformat(self.expires_at)
        except ValueError as exc:
            raise ValueError("expires_at is not an RFC 3339 date-time") from exc
        if when.tzinfo is None:
            raise ValueError("expires_at needs a UTC offset")
        return int(when.astimezone(UTC).timestamp() * 1000)


class DeadlineNone(Strict):
    mode: Literal["none"]


Destination = Annotated[DestNode | DestGroup | DestRootApp, Field(discriminator="kind")]
Deadline = Annotated[DeadlineRoot | DeadlineUtc | DeadlineNone, Field(discriminator="mode")]


class MessageRequest(Strict):
    domain_id: Id16
    client_epoch: Id16
    destination: Destination
    app_port: Annotated[int, Field(ge=1, le=65534)]
    payload_b64: Base64Str
    delivery: Literal["BEST_EFFORT", "RECEIVED", "APPLIED"]
    storage: Literal["VOLATILE", "DURABLE"]
    queue_mode: Literal["FIFO", "LATEST"]
    priority: Literal["BULK", "NORMAL", "URGENT"]  # CONTROL is not selectable from the API
    coalesce_key: U63Str | None = None
    deadline: Deadline
    strict_single_frame: bool = False
    object_transfer: bool = False

    @model_validator(mode="after")
    def _rules(self) -> MessageRequest:
        latest = self.queue_mode == "LATEST"
        if latest and (self.delivery != "BEST_EFFORT" or self.storage != "VOLATILE"):
            raise ValueError("LATEST requires BEST_EFFORT + VOLATILE")
        if latest != (self.coalesce_key is not None):
            raise ValueError("coalesce_key is required for LATEST and forbidden otherwise")
        # deadline none is only for retained events / maintenance data (RECEIVED + DURABLE);
        # side-effect commands (APPLIED) need a finite deadline (SEMANTICS 'Message').
        if self.deadline.mode == "none" and (self.delivery != "RECEIVED" or self.storage != "DURABLE"):
            raise ValueError("deadline none needs delivery=RECEIVED and storage=DURABLE")
        if self.deadline.mode == "root" and parse_u63(self.deadline.expires_root_ms) == 0:
            raise ValueError("expires_root_ms 0 means no deadline: use mode none")
        if self.deadline.mode == "utc":
            self.deadline.expiry_ms()
        return self

    def payload(self) -> bytes:
        return decode_b64(self.payload_b64)


class ControlRule:
    """Fields a control type requires (all others are 400) and the permissions it needs."""

    def __init__(self, fields: tuple[str, ...], permissions: tuple[str, ...],
                 capability: str | tuple[str, ...] | None = None) -> None:
        self.fields = fields
        self.permissions = permissions
        self.capability = (capability,) if isinstance(capability, str) else capability


CONTROL_RULES = {
    "JOIN_DECISION": ControlRule(("device_id", "decision"), ("APPROVE",)),
    "LEAVE": ControlRule(("device_id", "leave_mode"), ("APPROVE",)),  # IMMEDIATE: see leave_permissions
    "REVOKE": ControlRule(("device_id", "signed_cbor_b64"), ("REVOKE",)),
    "TRANSFER": ControlRule(("device_id", "signed_cbor_b64"), ("TRANSFER",), "SIGNED_TRANSFER"),
    "INSTALL_CONTROL": ControlRule(("signed_cbor_b64",), ("CONFIGURE",)),
    "POLICY_SET": ControlRule(("signed_cbor_b64",), ("CONFIGURE",)),
    "CHANNEL_FREEZE": ControlRule(("freeze",), ("CONFIGURE",), "AUTO_CHANNEL"),
    "CHANNEL_RECALCULATE": ControlRule((), ("CONFIGURE",), "AUTO_CHANNEL"),
    "GROUP_SET": ControlRule(("group_id", "members"), ("CONFIGURE",), "GROUP_FANOUT_V2"),
    "POWER_POLICY_SET": ControlRule(("device_id", "signed_cbor_b64"), ("CONFIGURE",),
                                    ("POWER_REPORT_ONLY", "POWER_WINDOWED_RX")),
    "COMMISSIONING_WINDOW_SET": ControlRule(("signed_cbor_b64",), ("APPROVE",),
                                            "COMMISSIONING_WINDOW"),
    "ROOT_HANDOVER": ControlRule(("signed_cbor_b64",), ("CONFIGURE", "TRANSFER"), "ROOT_HANDOVER"),
}
_OPTIONAL = ("device_id", "signed_cbor_b64", "decision", "leave_mode", "freeze", "group_id", "members")


class ControlRequest(Strict):
    domain_id: Id16
    client_epoch: Id16
    expected_revision: U63Str
    type: Literal["JOIN_DECISION", "LEAVE", "REVOKE", "TRANSFER", "INSTALL_CONTROL", "POLICY_SET",
                  "CHANNEL_FREEZE", "CHANNEL_RECALCULATE", "GROUP_SET", "POWER_POLICY_SET",
                  "COMMISSIONING_WINDOW_SET", "ROOT_HANDOVER"]
    request_id: Id16
    device_id: DeviceIdStr | None = None
    signed_cbor_b64: Base64Str | None = None
    decision: Literal["APPROVE", "REJECT"] | None = None
    leave_mode: Literal["DRAIN", "IMMEDIATE"] | None = None
    freeze: bool | None = None
    group_id: Annotated[int, Field(ge=1, le=0xFFFFFFFF)] | None = None
    members: Annotated[list[DeviceIdStr], Field(max_length=64)] | None = None

    @model_validator(mode="after")
    def _mode_specific_fields(self) -> ControlRequest:
        rule = CONTROL_RULES[self.type]
        present = {f for f in _OPTIONAL if getattr(self, f) is not None}
        if present != set(rule.fields):
            raise ValueError(f"{self.type} takes exactly the fields {sorted(rule.fields)}")
        if self.members is not None and len(set(self.members)) != len(self.members):
            raise ValueError("members must be unique")  # an empty set is valid and means nobody
        if self.signed_cbor_b64 is not None:
            size = len(decode_b64(self.signed_cbor_b64))
            if size == 0 or size > MAX_OBJECT_BYTES:
                raise ValueError("signed object must be 1..4096 bytes")
        if parse_u63(self.expected_revision) == U63_MAX and self.type == "POWER_POLICY_SET":
            raise ValueError("revision would overflow u63")
        return self

    def permissions(self) -> tuple[str, ...]:
        if self.type == "LEAVE" and self.leave_mode == "IMMEDIATE":
            return ("REVOKE",)  # immediate removal is an explicit, stronger authority
        return CONTROL_RULES[self.type].permissions


# ---- signed control objects: what the decoded object requires (FIX11-D13) ----------------------------------
# The permission of a signed object is that of the type INSIDE it, not of the HTTP operation type that carries it:
# a CONFIGURE principal must not install a RevokeObject through INSTALL_CONTROL. Types 1, 4 and 32 (credentials and
# group snapshots) are never installed by an operator. `subject` is the index of the DeviceId the object names.
SIGNED_OBJECT_PERMISSIONS: dict[int, tuple[str, ...]] = {
    2: ("CONFIGURE",), 3: ("TRANSFER",), 5: ("CONFIGURE",), 11: ("REVOKE",), 12: ("CONFIGURE",), 19: ("CONFIGURE",),
    21: ("CONFIGURE",), 26: ("UPDATE_FIRMWARE",), 29: ("CONFIGURE",), 30: ("APPROVE",), 31: ("CONFIGURE", "TRANSFER"),
}
SIGNED_OBJECT_TYPE_OF = {"REVOKE": 11, "TRANSFER": 3, "POLICY_SET": 12, "POWER_POLICY_SET": 29,
                         "COMMISSIONING_WINDOW_SET": 30, "ROOT_HANDOVER": 31}
SIGNED_OBJECT_SUBJECT = frozenset({3, 11, 29})  # the first DeviceId of the object data is the device it is about
