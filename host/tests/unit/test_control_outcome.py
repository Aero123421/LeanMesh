"""SEC-D7 follow-up (S18): a membership/control operation whose reason is RECOVERY_REQUIRED or STORAGE_FAILURE ends
INDETERMINATE at the Host, never REJECTED: the root's own state is in question (an ExpectedSet page may be half
applied, a commit may or may not be durable), so "it did not happen" would be a false claim. Pure mapping, no I/O."""

from __future__ import annotations

from leanmesh_host.bridge import mapping

APPLIED, REJECTED, INDETERMINATE = 2, 3, 6


def test_recovery_required_and_storage_failure_are_indeterminate_not_rejected() -> None:
    for reason in (mapping.RECOVERY_REQUIRED, mapping.STORAGE_FAILURE):
        assert mapping.control_outcome(REJECTED, reason) == ("INDETERMINATE", "ROOT_OUTCOME_UNKNOWN")  # an older root
        assert mapping.control_outcome(INDETERMINATE, reason) == ("INDETERMINATE", "ROOT_OUTCOME_UNKNOWN")


def test_other_control_outcomes_keep_their_meaning() -> None:
    assert mapping.control_outcome(APPLIED, 0) == ("APPLIED", "ROOT_APPLIED")
    assert mapping.control_outcome(REJECTED, mapping.CONFLICT) == ("REJECTED", "ROOT_REFUSED")
    assert mapping.control_outcome(INDETERMINATE, 3) == ("INDETERMINATE", "ROOT_OUTCOME_UNKNOWN")
