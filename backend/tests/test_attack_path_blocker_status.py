"""Marco 5: attack-path correlation used to only ever report "proven" or
"candidate" -- a chain whose next required step was explicitly tested and
found blocked by a missing precondition (e.g. a second identity for a
horizontal IDOR check; record_validation() marks that hypothesis
"blocked_precondition") looked identical to a chain that simply hasn't been
tested yet. These tests cover the new "blocker" status in
attack_path_correlation.py, and the tightened P20 quality gate in
scan_quality.py that used to accept unrelated tools (nuclei/gitleaks/
trufflehog) as proof the correlator ran.
"""
from __future__ import annotations

from types import SimpleNamespace

from app.services.attack_path_correlation import _normalize_signal, correlate_attack_signals
from app.services.scan_quality import _build_aggressive_depth_requirements


# ── _normalize_signal ───────────────────────────────────────────────────────

def test_normalize_signal_marks_blocked_precondition_as_blocked():
    signal = _normalize_signal({"status": "blocked_precondition"})
    assert signal["blocked"] is True
    assert signal["verified"] is False


def test_normalize_signal_marks_skipped_as_blocked():
    signal = _normalize_signal({"status": "skipped"})
    assert signal["blocked"] is True


def test_normalize_signal_confirmed_is_not_blocked():
    signal = _normalize_signal({"status": "confirmed"})
    assert signal["blocked"] is False
    assert signal["verified"] is True


def test_normalize_signal_open_candidate_is_not_blocked():
    """"Just untested" (status=candidate/open) must NOT read as blocked --
    that's the whole point of the distinction: blocked means a validator
    tried and hit a missing precondition, not "nobody got to it yet"."""
    signal = _normalize_signal({"status": "candidate"})
    assert signal["blocked"] is False


# ── correlate_attack_signals: proven / blocker / candidate ─────────────────

_HOST = "https://x.test/api/1"


def _signal(id_, family, status, evidence=True):
    return {
        "id": id_,
        "family": family,
        "target": _HOST,
        "title": f"{family} on {_HOST}",
        "severity": "high",
        "status": status,
        "confidence": 0.8,
        "evidence_ids": ["E-" + id_] if evidence else [],
    }


def test_chain_with_blocked_next_step_reports_blocker_status():
    signals = [
        _signal("1", "exposed_git", "confirmed"),
        # idor_bola is the higher-stage step needed to reach the objective --
        # a validator tried it and hit a missing precondition.
        _signal("2", "idor_bola", "blocked_precondition", evidence=False),
    ]

    paths = correlate_attack_signals(signals)

    assert len(paths) == 1
    path = paths[0]
    assert path["status"] == "blocker"
    assert path["chain_blocked"] is True
    assert path["chain_proven"] is False
    assert path["blocking_step"]["family"] == "idor_bola"


def test_chain_with_merely_untested_next_step_stays_candidate():
    signals = [
        _signal("1", "exposed_git", "confirmed"),
        _signal("2", "idor_bola", "candidate", evidence=False),
    ]

    paths = correlate_attack_signals(signals)

    assert len(paths) == 1
    path = paths[0]
    assert path["status"] == "candidate"
    assert path["chain_blocked"] is False
    assert path["blocking_step"] is None


def test_chain_fully_confirmed_with_evidence_reports_proven():
    signals = [
        _signal("1", "exposed_git", "confirmed"),
        _signal("2", "idor_bola", "confirmed"),
    ]

    paths = correlate_attack_signals(signals)

    assert len(paths) == 1
    path = paths[0]
    assert path["status"] == "proven"
    assert path["chain_proven"] is True
    assert path["chain_blocked"] is False
    assert path["blocking_step"] is None


# ── scan_quality.py: P20 gate requires real correlation evidence ───────────

def _p08_met_work_item():
    return SimpleNamespace(
        phase_id="P08", status="completed", tool_name="katana",
        target="https://example.test/main.js", item_metadata={}, result={}, last_error=None,
    )


def test_p20_gate_missing_when_only_unrelated_tools_completed():
    """Previously nuclei/gitleaks/trufflehog completing alone satisfied P20
    -- the correlator never had to run at all."""
    state = {"scan_level": "aggressive", "javascript_bundles": ["https://example.test/main.js"]}
    work_items = [
        _p08_met_work_item(),
        SimpleNamespace(phase_id="P20", status="completed", tool_name="nuclei", target="x", item_metadata={}, result={}, last_error=None),
        SimpleNamespace(phase_id="P20", status="completed", tool_name="gitleaks", target="x", item_metadata={}, result={}, last_error=None),
    ]

    requirements = _build_aggressive_depth_requirements(
        state=state,
        profile={"id": "aggressive", "depth": "aggressive"},
        expected_phase_ids=["P08", "P20"],
        work_items=work_items,
        artifacts=[],
        valid_sessions=[],
        endpoints=[],
        auth_required=False,
    )

    by_id = {row["id"]: row for row in requirements["requirements"]}
    assert by_id["p20_attack_path_correlation_for_discovered_primitives"]["status"] == "missing"


def test_p20_gate_met_when_correlation_state_populated():
    state = {
        "scan_level": "aggressive",
        "javascript_bundles": ["https://example.test/main.js"],
        "attack_path_correlation": {"paths": [{"attack_path_id": "AP-1"}]},
    }
    work_items = [_p08_met_work_item()]

    requirements = _build_aggressive_depth_requirements(
        state=state,
        profile={"id": "aggressive", "depth": "aggressive"},
        expected_phase_ids=["P08", "P20"],
        work_items=work_items,
        artifacts=[],
        valid_sessions=[],
        endpoints=[],
        auth_required=False,
    )

    by_id = {row["id"]: row for row in requirements["requirements"]}
    assert by_id["p20_attack_path_correlation_for_discovered_primitives"]["status"] == "met"


def test_p20_gate_met_when_correlator_tool_specifically_completed():
    state = {"scan_level": "aggressive", "javascript_bundles": ["https://example.test/main.js"]}
    work_items = [
        _p08_met_work_item(),
        SimpleNamespace(phase_id="P20", status="completed", tool_name="attack-path-correlator", target="x", item_metadata={}, result={}, last_error=None),
    ]

    requirements = _build_aggressive_depth_requirements(
        state=state,
        profile={"id": "aggressive", "depth": "aggressive"},
        expected_phase_ids=["P08", "P20"],
        work_items=work_items,
        artifacts=[],
        valid_sessions=[],
        endpoints=[],
        auth_required=False,
    )

    by_id = {row["id"]: row for row in requirements["requirements"]}
    assert by_id["p20_attack_path_correlation_for_discovered_primitives"]["status"] == "met"
