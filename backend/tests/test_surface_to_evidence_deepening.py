from types import SimpleNamespace

from app.services.skill_activity_materializer import (
    build_skill_activity_plan,
    materialize_skill_execution,
    summarize_skill_activity_execution,
)


def test_api_skill_playbook_materializes_evidence_and_validation_activities():
    plan = build_skill_activity_plan(
        {
            "id": "skill.api.bola_idor",
            "objective": "Validar autorização por objeto",
            "evidence_required": ["positive_identity_response", "negative_identity_response"],
            "requires_two_identities_for_confirmation": True,
        },
        phase_id="P16",
        target="https://api.example.test/api/orders/1",
    )

    names = {row["name"] for row in plan}
    assert {"baseline", "collect_positive_identity_response", "collect_negative_identity_response", "cross_identity_validation", "independent_validation"} <= names
    assert all(row["activity_id"] and row["phase_id"] == "P16" for row in plan)


def test_skill_execution_records_evidence_and_validation_counts():
    plan = build_skill_activity_plan(
        {
            "id": "skill.api.sql_injection",
            "objective": "SQL injection",
            "evidence_required": ["baseline_response", "injected_response"],
        },
        phase_id="P16",
        target="https://api.example.test/api/search?q=1",
    )
    metric = materialize_skill_execution(
        {
            "skill_id": "skill.api.sql_injection",
            "skill_activity_plan": plan,
            "skill_consultation_ids": ["SC-1"],
        },
        {
            "status": "completed",
            "stdout": "response",
            "parsed_result": {"response_observations": [{"ok": True, "status_code": 200}]},
            "findings_extracted": [],
        },
        validation_ids=[4],
    )

    assert metric["materialized"] is True
    assert metric["activity_count"] == len(plan)
    assert metric["executed_count"] > 0
    assert metric["validated_count"] == 1
    assert all(row["evidence_artifact_ids"] == [] for row in metric["activities"])


def test_activity_summary_detects_generic_skill_items_without_playbook():
    summary = summarize_skill_activity_execution([
        SimpleNamespace(
            item_metadata={"skill_id": "skill.api.bola_idor", "skill_consultation_ids": ["SC-1"]},
            status="completed",
        ),
        SimpleNamespace(
            item_metadata={
                "skill_id": "skill.api.sqli",
                "skill_activity_plan": [{"activity_id": "a1"}],
                "skill_activity_execution": {"executed_count": 1, "evidence_complete_count": 1, "validated_count": 1},
            },
            status="completed",
        ),
    ])

    assert summary["consulted"] == 2
    assert summary["materialized_items"] == 1
    assert summary["generic_only_items"] == 1
    assert summary["activities_executed"] == 1
