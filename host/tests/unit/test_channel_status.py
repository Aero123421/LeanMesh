"""S17: the root's channel report (NODE_QUERY `channel`, short addresses) becomes the OpenAPI ChannelStatus (device ids)."""

from __future__ import annotations

import pytest
from leanmesh_host.bridge.channel import STATES, status


def test_status_maps_addresses_to_devices_and_state_numbers() -> None:
    devices = {2: bytes([1]) * 32, 3: bytes([2]) * 32}
    report = {"current": 11, "epoch": 3, "state": 7, "plan_id": bytes(16), "required": [2, 3, 9], "applied": [2],
              "unreachable": [3]}
    out = status(report, devices)
    assert out == {"current_channel": 11, "channel_epoch": 3, "state": "RECOVERING",
                   "required": [devices[2].hex(), devices[3].hex()],  # an address the ledger does not list is left out
                   "applied": [devices[2].hex()], "unreachable": [devices[3].hex()]}


def test_plan_id_only_when_a_plan_exists() -> None:
    report = {"current": 6, "epoch": 1, "state": 0, "plan_id": bytes(range(16)), "required": [], "applied": [],
              "unreachable": []}
    assert status(report, {})["plan_id"] == bytes(range(16)).hex()
    assert "plan_id" not in status({**report, "plan_id": bytes(16)}, {})


@pytest.mark.parametrize("number", range(len(STATES)))
def test_every_coordinator_state_has_a_name(number: int) -> None:
    report = {"current": 6, "epoch": 0, "state": number, "plan_id": bytes(16), "required": [], "applied": [],
              "unreachable": []}
    assert status(report, {})["state"] == STATES[number]
