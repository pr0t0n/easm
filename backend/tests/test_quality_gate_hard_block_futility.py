"""Scan #89 sat in status=blocked for ~14h: the P21 quality gate's only two
remaining blockers (test_depth surfaces genuinely absent from an
informational target, and a runner_egress_consistency mismatch) have no
wired remediation generator, so every hard-block round produced an
identical, empty-actions result and burned all 3 backoff retries (~35min)
before permanently blocking. quality_gate_hard_block_is_futile lets the
retry loop recognize "nothing changed and nothing was scheduled" without
waiting out the remaining backoff.
"""
from app.services.scan_quality import (
    quality_gate_blocker_fingerprint,
    quality_gate_hard_block_is_futile,
)


def _gate(blockers, requires_remediation=False):
    return {"blockers": blockers, "requires_remediation": requires_remediation}


def test_fingerprint_is_stable_regardless_of_blocker_order():
    a = [{"area": "test_depth", "title": "X"}, {"area": "runner_egress_consistency", "title": "Y"}]
    b = [{"area": "runner_egress_consistency", "title": "Y"}, {"area": "test_depth", "title": "X"}]

    assert quality_gate_blocker_fingerprint(_gate(a)) == quality_gate_blocker_fingerprint(_gate(b))


def test_first_hard_block_is_never_futile():
    """No prior fingerprint stored yet -- always give the first retry a chance,
    since it may be waiting on async work already in flight."""
    state = {}
    gate = _gate([{"area": "runner_egress_consistency", "title": "P02/P06 mismatch"}])

    assert quality_gate_hard_block_is_futile(state, gate) is False


def test_identical_blockers_with_no_new_action_is_futile():
    gate = _gate([{"area": "runner_egress_consistency", "title": "P02/P06 mismatch"}])
    state = {"quality_gate_hard_block_fingerprint": list(quality_gate_blocker_fingerprint(gate))}

    assert quality_gate_hard_block_is_futile(state, gate) is True


def test_changed_blockers_is_not_futile():
    state = {
        "quality_gate_hard_block_fingerprint": list(
            quality_gate_blocker_fingerprint(_gate([{"area": "test_depth", "title": "A"}]))
        )
    }
    gate = _gate([{"area": "test_depth", "title": "B"}])

    assert quality_gate_hard_block_is_futile(state, gate) is False


def test_pending_remediation_action_is_never_futile():
    """If this round DID schedule a remediation action, the next round might
    genuinely resolve the blocker -- never short-circuit that."""
    gate = _gate(
        [{"area": "phase_coverage", "title": "P06 weak"}],
        requires_remediation=True,
    )
    state = {"quality_gate_hard_block_fingerprint": list(quality_gate_blocker_fingerprint(gate))}

    assert quality_gate_hard_block_is_futile(state, gate) is False
