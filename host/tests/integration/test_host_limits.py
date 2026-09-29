"""API request-rate admission (docs/08 §8): 429 per principal and for the whole service, through the
real FastAPI app (S14). The clock of the limiter is replaced by a manual one so the buckets are exact."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from host_util import check, make_settings, message, rows, running

REPO = Path(__file__).resolve().parents[3]
DEFAULTS = json.loads((REPO / "config" / "defaults.json").read_text())["scheduler"]


LIMITS = dict(principal_rps=float(DEFAULTS["principal_requests_per_second"]), principal_burst=DEFAULTS["principal_burst"],
              global_rps=float(DEFAULTS["global_requests_per_second"]), global_burst=DEFAULTS["global_burst"])


class ManualClock:
    def __init__(self) -> None:
        self.t = time.monotonic()

    def __call__(self) -> float:
        return self.t


def status_codes(h, who: str, n: int) -> list[int]:  # noqa: ANN001
    return [h.http.get("/v1/status", headers={"Authorization": f"Bearer tok-{who}"}).status_code for _ in range(n)]


def test_settings_carry_the_configured_limits() -> None:
    from leanmesh_host.settings import Settings

    s = Settings(db_path=Path("x"), tokens_path=Path("y"), schema_path=Path("z"))
    assert (s.principal_rps, s.principal_burst) == (DEFAULTS["principal_requests_per_second"], DEFAULTS["principal_burst"])
    assert (s.global_rps, s.global_burst) == (DEFAULTS["global_requests_per_second"], DEFAULTS["global_burst"])


@pytest.mark.scenario("Q01")
def test_principal_over_its_rate_gets_429_with_retry_after_and_others_are_unaffected(tmp_path: Path) -> None:
    with running(make_settings(tmp_path, **LIMITS), domain=False) as h:
        clock = ManualClock()
        h.http.app.state.limiter.clock = clock
        burst = DEFAULTS["principal_burst"]
        assert status_codes(h, "alice", burst) == [200] * burst  # the burst passes
        r = h.http.get("/v1/status", headers={"Authorization": "Bearer tok-alice"})
        assert r.status_code == 429
        check("get_status", r)  # the envelope is the OpenAPI Error
        body = r.json()
        assert body["code"] == "RATE_LIMITED" and body["details"] == {"scope": "principal"}
        assert 1 <= body["retry_after_ms"] <= 1000 // DEFAULTS["principal_requests_per_second"]  # one token: 50 ms
        # another principal has its own bucket: the noisy client does not slow it
        assert status_codes(h, "bob", 5) == [200] * 5
        # after retry_after_ms one request passes again, then the bucket is empty again
        clock.t += body["retry_after_ms"] / 1000
        assert status_codes(h, "alice", 2) == [200, 429]
        # a full second refills rate tokens (20), not the whole burst
        clock.t += 1.0
        assert status_codes(h, "alice", DEFAULTS["principal_requests_per_second"] + 1)[-2:] == [200, 429]
        # unauthenticated garbage never spends anyone's tokens (and is not a 429)
        assert h.http.get("/v1/status", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_the_whole_service_has_its_own_budget(tmp_path: Path) -> None:
    principals = {f"p{i}": ["READ"] for i in range(5)}
    with running(make_settings(tmp_path, principals, **LIMITS), domain=False) as h:
        clock = ManualClock()
        h.http.app.state.limiter.clock = clock
        # 5 principals * 40 burst > the global 100: the service, not any principal, runs dry first
        codes = [c for i in range(5) for c in status_codes(h, f"p{i}", 30)]
        assert codes.count(200) == DEFAULTS["global_burst"] and codes.count(429) == 150 - DEFAULTS["global_burst"]
        r = h.http.get("/v1/status", headers={"Authorization": "Bearer tok-p0"})
        assert r.status_code == 429 and r.json()["details"] == {"scope": "global"}
        clock.t += 1.0  # 100 tokens/s
        assert status_codes(h, "p4", 30).count(200) == 30


@pytest.mark.scenario("Q02")
def test_a_hundred_replays_of_one_idempotency_key_are_one_operation_and_no_new_rf_work(tmp_path: Path) -> None:
    with running(make_settings(tmp_path, **LIMITS)) as h:
        clock = ManualClock()
        h.http.app.state.limiter.clock = clock
        epoch = h.epoch()
        first = h.post("/v1/messages", message(epoch), "same-key")
        assert first.status_code == 202
        op = first.json()["id"]
        outcomes = []
        for i in range(100):
            r = h.post("/v1/messages", message(epoch), "same-key")
            outcomes.append((r.status_code, r.json().get("id")))
            if i % 10 == 9:
                clock.t += 0.6  # the client keeps retrying while its bucket refills
        assert {code for code, _ in outcomes} <= {202, 429}
        assert all(i == op for code, i in outcomes if code == 202) and any(code == 202 for code, _ in outcomes)
        # one operation and one outbox row: the replays are answered from the stored response
        assert rows(tmp_path / "host.db", "SELECT COUNT(*) FROM operations WHERE type='MESSAGE'")[0][0] == 1
        assert rows(tmp_path / "host.db", "SELECT COUNT(*) FROM outbox")[0][0] == 1
