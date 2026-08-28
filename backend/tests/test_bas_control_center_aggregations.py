"""New BAS Control Center aggregations added alongside the 4-tab frontend
rewrite: category_coverage, resilience_score, score_trend, kill_chain_stages,
protection_layers, and the CIDR/domain segment-tag resolution they depend on.

Every one of these follows the module's existing honesty rule (see
bas_reporting.py's module docstring): no fabricated "detected" state, no
score/delta when there's genuinely no resolved data, no percentage
attributed to a control nobody declared.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.services import bas_reporting
from app.api import routes_bas


def _query_chain(rows):
    q = MagicMock()
    q.filter.return_value = q
    q.join.return_value = q
    q.distinct.return_value = q
    q.order_by.return_value = q
    q.limit.return_value = q
    q.all.return_value = rows
    return q


def _proof(valid=True):
    return {"valid": valid, "status": "validated" if valid else "refuted"}


def _tag(match_type, match_value, controls=None, business_unit="", criticality="medium"):
    return SimpleNamespace(
        match_type=match_type, match_value=match_value, controls=controls or [],
        business_unit=business_unit, criticality=criticality,
    )


# ── Segment tag resolution ───────────────────────────────────────────────────

def test_resolve_segment_tag_prefers_domain_over_cidr():
    tags = [
        _tag("cidr", "10.0.0.0/8", business_unit="Infra"),
        _tag("domain", "valid.local", business_unit="Identity core"),
    ]
    tag = bas_reporting._resolve_segment_tag("10.42.8.13", "valid.local", tags)
    assert tag.business_unit == "Identity core"


def test_resolve_segment_tag_falls_back_to_cidr_when_no_domain_match():
    tags = [_tag("cidr", "10.42.0.0/16", business_unit="Corp IT")]
    tag = bas_reporting._resolve_segment_tag("10.42.8.13", "", tags)
    assert tag.business_unit == "Corp IT"


def test_resolve_segment_tag_none_when_nothing_matches():
    tags = [_tag("cidr", "192.168.0.0/24")]
    assert bas_reporting._resolve_segment_tag("10.42.8.13", "other.local", tags) is None


def test_segment_tag_view_unclassified_when_no_tag():
    view = bas_reporting._segment_tag_view(None)
    assert view == {"business_unit": None, "criticality": None, "controls": [], "classified": False}


def test_control_center_payload_includes_control_matrix(monkeypatch):
    db = MagicMock()
    current_user = SimpleNamespace(is_admin=True)
    monkeypatch.setattr(bas_reporting, "resilience_score", lambda db, **kwargs: {"score": None})
    monkeypatch.setattr(bas_reporting, "score_trend", lambda db, **kwargs: [])
    monkeypatch.setattr(bas_reporting, "category_coverage", lambda db, **kwargs: [])
    monkeypatch.setattr(bas_reporting, "control_matrix", lambda db, **kwargs: {"summary": {"cells": 1}, "frameworks": [], "cells": []})
    monkeypatch.setattr(bas_reporting, "kill_chain_stages", lambda db, **kwargs: [])
    monkeypatch.setattr(bas_reporting, "attack_heatmap", lambda db, **kwargs: [])
    monkeypatch.setattr(bas_reporting, "protection_layers", lambda db, **kwargs: [])
    monkeypatch.setattr(bas_reporting, "attack_path_inventory", lambda db, **kwargs: {})
    monkeypatch.setattr(bas_reporting, "bas_findings_view", lambda db, **kwargs: [])

    payload = routes_bas.control_center(db=db, current_user=current_user)

    assert payload["control_matrix"]["summary"]["cells"] == 1


# ── category_coverage ────────────────────────────────────────────────────────

def test_category_coverage_counts_real_agent_dispatches_only():
    db = MagicMock()

    def side_effect(*args):
        if args and args[0] is bas_reporting.BasJob.technique_key:
            return _query_chain([("smb_enum_cme",)])  # a real-agent dispatch of one smb technique
        return _query_chain([])

    db.query.side_effect = side_effect
    rows = bas_reporting.category_coverage(db)
    smb_row = next(r for r in rows if r["category"] == "smb")
    assert smb_row["tested"] >= 1
    assert smb_row["total"] >= smb_row["tested"]
    assert smb_row["safe"] + smb_row["elevated"] + smb_row["high_risk"] == smb_row["tested"]


# ── kill_chain_stages ─────────────────────────────────────────────────────────

def test_kill_chain_stages_are_a_real_2_state_split(monkeypatch):
    def fake_heatmap(db, *, group_ids=None, schedule_id=None):
        return [
            {"technique_key": "smb_enum_cme", "outcome": "proven"},
            {"technique_key": "network_share_discovery", "outcome": "blocked"},
        ]

    monkeypatch.setattr(bas_reporting, "attack_heatmap", fake_heatmap)
    db = MagicMock()
    stages = bas_reporting.kill_chain_stages(db)

    lateral = next(s for s in stages if s["stage"] == "lateral_movement")
    assert lateral["proven_pct"] > 0
    # No "detected" key anywhere -- only the 2 real resolved states + blocked.
    for stage in stages:
        assert set(stage) == {"stage", "label", "total", "tested", "proven_pct", "unproven_pct", "blocked_pct"}


# ── resilience_score / score_trend ──────────────────────────────────────────

def test_resilience_score_computes_a_real_delta_between_two_windows():
    db = MagicMock()
    current_jobs = [SimpleNamespace(status="completed", result={"bas_proof": _proof(True)})] * 3
    previous_jobs = [SimpleNamespace(status="completed", result={"bas_proof": _proof(True)})] * 1 + \
        [SimpleNamespace(status="failed", result={})] * 3
    calls = iter([_query_chain(current_jobs), _query_chain(previous_jobs)])
    db.query.side_effect = lambda *a, **k: next(calls)

    result = bas_reporting.resilience_score(db, window_days=7)

    assert result["score"] == 100  # 3/3 proven this window
    assert result["previous_score"] == 25  # 1/4 proven previous window
    assert result["delta"] == 75
    assert "score_trend" not in result  # no accidental leakage between functions


def test_resilience_score_none_when_nothing_resolved_either_window():
    db = MagicMock()
    db.query.side_effect = lambda *a, **k: _query_chain([])

    result = bas_reporting.resilience_score(db)

    assert result["score"] is None
    assert result["previous_score"] is None
    assert result["delta"] is None


def test_score_trend_reports_none_not_zero_for_a_quiet_week():
    db = MagicMock()
    db.query.side_effect = lambda *a, **k: _query_chain([])

    points = bas_reporting.score_trend(db, weeks=3)

    assert len(points) == 3
    assert all(p["score"] is None for p in points)
    assert all(p["resolved"] == 0 for p in points)


# ── protection_layers ────────────────────────────────────────────────────────

def test_protection_layers_empty_when_no_segment_tags_declare_controls():
    db = MagicMock()
    db.query.side_effect = lambda *a, **k: _query_chain([])
    assert bas_reporting.protection_layers(db) == []


def test_protection_layers_aggregates_real_outcomes_per_declared_control():
    tag = _tag("cidr", "10.42.0.0/16", controls=[{"name": "EDR / XDR", "vendor": "CrowdStrike Falcon"}])
    job_proven = SimpleNamespace(target="10.42.8.13", status="completed", result={"bas_proof": _proof(True)})
    agent = SimpleNamespace(local_network_cidr="10.42.0.0/16")

    def side_effect(*args, **kwargs):
        if args and args[0] is bas_reporting.BasNetworkSegmentTag:
            return _query_chain([tag])
        return _query_chain([(job_proven, agent)])

    db = MagicMock()
    db.query.side_effect = side_effect

    rows = bas_reporting.protection_layers(db)

    assert len(rows) == 1
    assert rows[0]["name"] == "EDR / XDR"
    assert rows[0]["missed_pct"] == 100.0  # proof-validated success == the control missed it
    assert rows[0]["prevented_pct"] == 0.0
    assert rows[0]["low_confidence"] is True  # only 1 sample


def test_protection_layers_ignores_jobs_outside_any_tagged_segment():
    tag = _tag("cidr", "10.42.0.0/16", controls=[{"name": "WAF", "vendor": "Cloudflare"}])
    job_elsewhere = SimpleNamespace(target="192.168.1.5", status="completed", result={"bas_proof": _proof(True)})
    agent = SimpleNamespace(local_network_cidr=None)

    def side_effect(*args, **kwargs):
        if args and args[0] is bas_reporting.BasNetworkSegmentTag:
            return _query_chain([tag])
        return _query_chain([(job_elsewhere, agent)])

    db = MagicMock()
    db.query.side_effect = side_effect

    assert bas_reporting.protection_layers(db) == []
