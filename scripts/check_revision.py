"""Spec0.2 checks. Pure models and static contracts, never production/HIL tests."""
from __future__ import annotations

import copy
import csv
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

from jsonschema import Draft202012Validator
from power_contract import (validate_policy, can_start_work, required_guard_ms,
                            session_path, target_wait, group_counts,
                            validate_poll, validate_grant, POLL, GRANT)
from energy_report import integrate
from wire_fixture import cbor
import hashlib

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    return json.loads((ROOT / name).read_text())

def rejects(fn):
    try:
        fn()
    except Exception as exc:
        # Called only for explicit, bounded invalid specification inputs.
        return type(exc).__name__
    raise AssertionError("invalid input accepted")


def power_policy_contract():
    count = 0
    for name in ("always-rx", "windowed", "report-only"):
        value = load(f"config/power.{name}.json")
        validate_policy(value)
        count += 1
        if name != "always-rx":
            for role in ("RELAY", "ROOT"):
                rejects(lambda: validate_policy(value, role))
                count += 1
    valid = load("config/power.report-only.json")
    for change in ({"revision": str(1 << 63)}, {"shutdown_reserve_ms": 15000},
                   {"search_budget_ms": 15000}, {"retry_max_ms": 1000},
                   {"mailbox_frames_total": 1}, {"rx_window_ms": 20},
                   {"mode": "INVALID"}, {"session_policy": "RESTORE_KEY_ONLY"}):
        bad = copy.deepcopy(valid)
        bad.update(change)
        rejects(lambda: validate_policy(bad))
        count += 1
    assert can_start_work(valid, 14000, 500)
    assert not can_start_work(valid, 14000, 501)
    return {"positive_negative_cases": count + 2, "product_power_manager_executed": False}


def power_wire_contract():
    fixtures = load("tests/power_golden.json")
    poll = bytes.fromhex(fixtures["poll_hex"])
    grant = bytes.fromhex(fixtures["grant_hex"])
    validate_poll(poll)
    validate_grant(grant, poll)
    r = load("protocol/registry.json")
    assert len(poll) == POLL.size == 28 == struct.calcsize(r["struct_formats"]["power_poll"])
    assert len(grant) == GRANT.size == 24 == struct.calcsize(r["struct_formats"]["power_grant"])
    assert sum(size for _, size in r["power_frames"]["poll"]["fields"]) == 28
    assert sum(size for _, size in r["power_frames"]["grant"]["fields"]) == 24
    rejects(lambda: validate_poll(poll + b"\0"))
    bad = bytearray(poll); bad[-1] = 1
    rejects(lambda: validate_poll(bytes(bad)))
    fields = list(GRANT.unpack(grant)); fields[3] += 1
    rejects(lambda: validate_grant(GRANT.pack(*fields), poll))
    fields = list(GRANT.unpack(grant)); fields[4] = 251
    rejects(lambda: validate_grant(GRANT.pack(*fields), poll))
    return {"poll_frame_bytes_with_link_aead": 68, "grant_frame_bytes_with_link_aead": 64,
            "scope": "fixed binary shapes and semantic bounds; no RF send"}


def power_state_models():
    fixtures = load("tests/power_golden.json")
    for row in fixtures["session_cases"]:
        case = dict(row); expected = case.pop("expected")
        assert session_path(**case) == expected
    guard = dict(fixtures["guard_example"]); expected = guard.pop("expected_ms")
    assert required_guard_ms(**guard) == expected
    base = dict(now_ms=1000, deadline_ms=5000, next_wake_earliest_ms=60000,
                awake=False, previously_sent=False, generation_matches=True)
    assert target_wait(**base) == "DEADLINE_UNREACHABLE"
    assert target_wait(**(base | {"next_wake_earliest_ms": None})) == "WAIT_WAKE"
    assert target_wait(**(base | {"awake": True})) == "READY"
    assert target_wait(**(base | {"previously_sent": True})) == "INDETERMINATE"
    assert target_wait(**(base | {"generation_matches": False})) == "REJECTED"
    assert target_wait(**(base | {"now_ms": 5000})) == "EXPIRED"
    return {"session_cases": len(fixtures["session_cases"]), "sleep_target_cases": 6,
            "two_clock_drift_guard_ms": expected, "scope": "specification decision model only"}


def group_contract():
    values = ["APPLIED"] * 29 + ["PENDING"]
    counts = group_counts(values)
    assert counts["APPLIED"] == 29 and counts["PENDING"] == 1
    assert sum(v for k, v in counts.items() if k != "total") == counts["total"] == 30
    rejects(lambda: group_counts(["PARTIAL"]))
    rejects(lambda: group_counts(["PENDING"] * 65))
    original = [bytes(16), 1, 1, bytes([1]) * 16, bytes([2]) * 32,
                [[bytes([3]) * 32, 1, 1], [bytes([4]) * 32, 2, 1]]]
    changed = copy.deepcopy(original); changed[-1][0][1] = 2
    assert hashlib.sha256(cbor(original)).digest() != hashlib.sha256(cbor(changed)).digest()
    reg = load("protocol/registry.json")
    assert reg["control_types"]["GroupSnapshotV2"] == 32
    assert 22 in reg["reserved_control_types"] and 22 not in reg["signed_control_types"]
    assert reg["control_types"]["GroupSnapshotRequest"] == 33
    assert 33 not in reg["signed_control_types"]
    return {"target_generations_hash_bound": True, "counts_are_current_outcomes": True,
            "product_group_dispatch_executed": False}


def energy_contract():
    out = integrate(ROOT / "examples/power-trace.SYNTHETIC.csv", max_gap_s=0.11)
    assert abs(out["energy_j"] - 0.033) < 1e-12
    assert abs(out["charge_mah"] - 10 / 3600) < 1e-12
    assert abs(out["average_current_ma"] - 10) < 1e-12
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "bad.csv"
        for bad in ("0,3.3,10\n0,3.3,10", "0,3.3,10\n1,3.3,-1",
                    "0,3.3,NaN\n1,3.3,10", "0,3.3,10\n10,3.3,10"):
            p.write_text("time_s,voltage_v,current_ma\n" + bad + "\n")
            rejects(lambda: integrate(p, max_gap_s=1))
    schema = load("evidence/power-measurement.schema.json")
    Draft202012Validator.check_schema(schema)
    template = load("examples/power-measurement.template.json")
    Draft202012Validator(schema).validate(template)
    bad = dict(template); bad["status"] = "MEASURED"
    rejects(lambda: Draft202012Validator(schema).validate(bad))
    return {"synthetic_integral_energy_j": out["energy_j"], "measured_trace_count": 0,
            "invalid_trace_cases": 4, "measurement_provenance_negative": True}


def new_c_syntax():
    runs = []
    for name, std, lang in (("cc", "c11", "c"), ("c++", "c++17", "c++")):
        exe = shutil.which(name)
        if not exe:
            raise RuntimeError(f"{name} compiler required")
        command = [exe, "-x", lang, f"-std={std}", "-Wall", "-Wextra", "-Werror",
                   "-fsyntax-only", "-I", str(ROOT / "api"), str(ROOT / "examples/low_power.c")]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=20)
        runs.append(lang)
    return {"power_example": runs, "sdk_linked": False}


def full_bundle_inventory():
    entries = load("evidence/BASELINE.json")["source_files"]
    for item in entries:
        assert (ROOT / item["path"]).is_file(), item["path"]
    source_ids = {x["id"] for x in load("evidence/source_registry.json")["sources"]}
    assert {f"E-PWR-{n:02d}" for n in range(1, 5)} <= source_ids
    assert "#define LM_ABI_VERSION 2u" in (ROOT / "api/leanmesh.h").read_text()
    assert load("protocol/registry.json")["abi_version"] == 2
    assert load("api/openapi.json")["info"]["version"] == "0.2.0"
    cap = load("config/capability-manifest.json")
    assert len(cap["features"]) == len(load("protocol/registry.json")["capability_bits"])
    for item in cap["features"]:
        assert not any(item[key] for key in ("implemented", "build_tested", "hardware_tested", "qualified", "default_enabled"))
    scripts = list((ROOT / "scripts").glob("*.py"))
    for path in scripts:
        compile(path.read_text(), str(path), "exec")
    return {"original_paths_retained": len(entries), "python_syntax_files": len(scripts),
            "new_product_tests_run": 0}


CHECKS = [
    ("power_policy_contract", power_policy_contract),
    ("power_wire_contract", power_wire_contract),
    ("power_state_models", power_state_models),
    ("group_generation_and_outcome_contract", group_contract),
    ("energy_integrator_and_provenance", energy_contract),
    ("power_c_and_cpp_syntax", new_c_syntax),
    ("full_bundle_inventory", full_bundle_inventory),
]
