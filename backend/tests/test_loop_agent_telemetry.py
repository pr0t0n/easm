from types import SimpleNamespace

import pytest

from app.services.loop_agent_telemetry import (
    build_bas_loop_summary,
    build_finding_evidence_lifecycle,
    build_loop_agent_quality_summary,
    build_methodology_planner_trace,
    build_operational_observability,
    record_loop_event,
    summarize_quality_gate_loop,
)
from app.services.vulnerability_learning_service import update_learning_review


def test_finding_evidence_lifecycle_covers_every_severity():
    findings = [
        SimpleNamespace(severity="critical", verification_status="confirmed", retest_status=None, details={}, is_false_positive=False),
        SimpleNamespace(severity="high", verification_status="candidate", retest_status=None, details={}, is_false_positive=False),
        SimpleNamespace(severity="medium", verification_status="candidate", retest_status=None, details={}, is_false_positive=False),
        SimpleNamespace(severity="low", verification_status=None, retest_status="refuted", details={}, is_false_positive=False),
        SimpleNamespace(severity="info", verification_status=None, retest_status=None, details={}, is_false_positive=False),
    ]

    result = build_finding_evidence_lifecycle(findings)

    assert result["by_severity"]["critical"]["validated"] == 1
    assert result["by_severity"]["high"]["candidate"] == 1
    assert result["by_severity"]["medium"]["candidate"] == 1
    assert result["by_severity"]["low"]["refuted"] == 1
    assert result["by_severity"]["info"]["informational_only"] == 1
    assert result["candidate_by_severity"]["medium"] == 1


def test_quality_gate_loop_shows_round_delta_and_actions():
    state = {
        "quality_gate": {
            "status": "passed",
            "rounds": 2,
            "history": [
                {"round": 1, "score": 57.5, "grade": "C", "actions": [{"type": "schedule_p21_validation"}]},
                {"round": 2, "score": 78.5, "grade": "B", "actions": []},
            ],
            "passed": True,
        }
    }

    result = summarize_quality_gate_loop(state)

    assert result["rounds"] == 2
    assert result["first_score"] == 57.5
    assert result["last_score"] == 78.5
    assert result["score_delta"] == 21.0
    assert result["actions_scheduled"] == 1
    assert result["action_types"]["schedule_p21_validation"] == 1


def test_record_loop_event_preserves_steps_and_counters():
    state = record_loop_event({}, loop_type="pentest", step="validate", reason="quality_gate_round")

    assert state["loop_agent"]["latest"]["step"] == "validate"
    assert state["loop_agent"]["steps"] == ["observe", "decide", "act", "validate", "learn", "stop"]
    assert state["loop_agent"]["counters"]["pentest:validate"] == 1


def test_operational_observability_flags_terminal_waiting_finalization():
    job = SimpleNamespace(
        id=123,
        status="running",
        current_step="P22",
        mission_progress=99,
        state_data={"quality_gate_active": False},
    )
    work_items = [
        SimpleNamespace(status="completed", phase_id="P01"),
        SimpleNamespace(status="failed", phase_id="P21"),
    ]

    result = build_operational_observability(job, work_items)

    assert result["work_items"]["terminal"] == 2
    assert result["work_items"]["active"] == 0
    assert result["finalization"]["terminal_waiting_finalization"] is True


def test_loop_agent_quality_summary_combines_gate_evidence_and_queue():
    job = SimpleNamespace(id=8, status="completed", current_step="P22", mission_progress=100, state_data={})
    findings = [SimpleNamespace(severity="medium", verification_status="candidate", retest_status=None, details={}, is_false_positive=False)]
    work_items = [SimpleNamespace(status="completed", phase_id="P21")]
    state = {
        "quality_gate": {
            "status": "passed",
            "rounds": 1,
            "history": [{"round": 1, "score": 75, "grade": "B", "actions": []}],
        }
    }

    result = build_loop_agent_quality_summary(
        state=state,
        quality_gate=state["quality_gate"],
        findings=findings,
        work_items=work_items,
        job=job,
    )

    assert result["quality_gate_loop"]["status"] == "passed"
    assert result["finding_evidence_lifecycle"]["by_severity"]["medium"]["candidate"] == 1
    assert result["operational_observability"]["work_items"]["terminal"] == 1


def test_methodology_planner_trace_separates_rag_mcp_llm_and_fallback():
    result = build_methodology_planner_trace(
        phase_context={
            "P01": {"rag": [{"skill_id": "skill.recon"}]},
            "P02": {"rag": []},
        },
        llm_meta={"fallback": True, "fallback_reason": "ValueError:invalid_methodology_json"},
    )

    assert result["rag_consulted"] is True
    assert result["rag_hit_count"] == 1
    assert result["mcp_consulted"] is True
    assert result["llm_attempted"] is True
    assert result["llm_available"] is False
    assert result["llm_response_valid"] is False
    assert result["fallback_reason"] == "ValueError:invalid_methodology_json"


def test_bas_loop_summary_marks_retest_need_for_missed_or_unproven():
    result = build_bas_loop_summary(
        score={"resolved_total": 2, "blocked": 0, "unproven": 1},
        coverage={"summary": {"prevented": 1, "detected": 1, "missed": 1}},
        exposure={"total_dispatches": 3},
        heatmap=[{"times_tested": 1}, {"times_tested": 0}],
        findings=[
            {"simulated": False, "proof_valid": True},
            {"simulated": False, "proof_valid": False},
        ],
        priorities=[{"priority": "P1"}],
        port_scan={"scans": [{"target": "10.0.0.1"}]},
    )

    assert result["execution"]["dispatches"] == 3
    assert result["evidence"]["proof_validated_findings"] == 1
    assert result["detection"]["missed"] == 1
    assert result["learn"]["techniques_tested"] == 1
    assert result["stop"]["requires_retest"] is True


def test_learning_review_rejects_unsynthesized_crawler_acceptance():
    db = SimpleNamespace(commit=lambda: None, refresh=lambda row: None)
    row = SimpleNamespace(
        source_kind="github_hackerone_crawler",
        raw_llm_response="",
        status="pending_review",
        review_notes=None,
        updated_at=None,
    )
    reviewer = SimpleNamespace(id=1)

    with pytest.raises(ValueError, match="aprendizado_candidato_sem_sintese"):
        update_learning_review(db, row, reviewer, "accepted")

    assert row.status == "pending_review"
