from types import SimpleNamespace


def test_quality_state_persists_preflight_and_precondition_summaries() -> None:
    from app.services.scan_quality import _persist_quality_state

    added = []

    class Db:
        def add(self, row):
            added.append(row)

    job = SimpleNamespace(id=13, state_data={})
    state = {}
    gate = {"status": "completed_with_gaps", "last_score": 64.9}
    quality = {
        "score": 64.9,
        "grade": "C",
        "runtime_visibility": {"heavy": "omitted from snapshot"},
        "phase_monitor_issues": ["omitted from snapshot"],
        "preflight_summary": {"p02": {"complete_targets": 37}},
        "auth_precondition_summary": {"blocked": True, "reason": "missing_valid_identity_pair"},
        "business_logic_precondition_summary": {"blocked_endpoints": 4},
    }

    result = _persist_quality_state(Db(), job, state, quality, gate)

    assert result["quality_snapshot"]["score"] == 64.9
    assert result["quality_snapshot"]["quality_gate"] == gate
    assert "runtime_visibility" not in result["quality_snapshot"]
    assert "phase_monitor_issues" not in result["quality_snapshot"]
    assert result["preflight_summary"]["p02"]["complete_targets"] == 37
    assert result["auth_precondition_summary"]["reason"] == "missing_valid_identity_pair"
    assert result["business_logic_precondition_summary"]["blocked_endpoints"] == 4
    assert added == [job]


def test_auth_precondition_summary_explains_missing_identity_pair() -> None:
    from app.services.scan_quality import _build_auth_precondition_summary

    summary = _build_auth_precondition_summary(
        external_preconditions={
            "identity_pair_required": True,
            "valid_auth_sessions": 0,
            "auth_required_endpoints": 12,
            "jwt_required_items": 0,
        },
        components={
            "test_depth": {
                "endpoints_auth_classified": 3,
                "endpoints_auth_classifiable": 12,
                "endpoints_auth_unknown": 9,
            }
        },
    )

    assert summary["blocked"] is True
    assert summary["reason"] == "missing_valid_identity_pair"
    assert summary["evidence"]["valid_auth_sessions"] == 0
    assert summary["evidence"]["required_valid_sessions_for_horizontal_tests"] == 2
    assert "duas identidades" in summary["operator_message"]


def test_business_logic_precondition_summary_keeps_blocker_counts() -> None:
    from app.services.scan_quality import _build_business_logic_precondition_summary

    summary = _build_business_logic_precondition_summary({
        "relevant_endpoints": 8,
        "contracted_endpoints": 8,
        "high_risk_endpoints": 4,
        "ready_read_only": 4,
        "blocked_endpoints": 4,
        "blocked": {"missing_observed_parameter": 4},
        "execution_guardrails": {"object_id_guessing": False},
    })

    assert summary["blocked_endpoints"] == 4
    assert summary["blockers"] == {"missing_observed_parameter": 4}
    assert summary["guardrails"]["object_id_guessing"] is False
