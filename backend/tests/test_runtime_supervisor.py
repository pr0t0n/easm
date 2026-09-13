from types import SimpleNamespace
from unittest.mock import MagicMock

from app.services.runtime_supervisor import evaluate_runtime_outcome


def test_runtime_supervisor_corrects_recoverable_missing_context_in_flight():
    db = MagicMock()
    job = SimpleNamespace(id=7, state_data={})
    item = SimpleNamespace(
        id=8,
        attempts=1,
        phase_id="P21",
        tool_name="validator",
        status="skipped",
        last_error="required_evidence_absent:exact_request_contract",
        result={"status": "skipped"},
        item_metadata={"skill_id": "skill.test", "validation_resolution": {"status": "awaiting_evidence", "reason": "required_evidence_absent:exact_request_contract"}},
    )

    decision = evaluate_runtime_outcome(db, job, item)

    assert decision["action"] == "correct_in_flight"
    assert decision["recovery"]["type"] == "recollect_context"
    assert job.state_data["runtime_supervisor"]["status"] == "correct_in_flight"
    db.add.assert_called_once()


def test_runtime_supervisor_continues_with_observable_success():
    db = MagicMock()
    job = SimpleNamespace(id=7, state_data={})
    item = SimpleNamespace(
        id=8,
        attempts=1,
        phase_id="P21",
        tool_name="validator",
        status="completed",
        last_error=None,
        result={"status": "completed", "stdout_preview": "ok"},
        item_metadata={},
    )

    decision = evaluate_runtime_outcome(db, job, item)

    assert decision["action"] == "continue"
    assert decision["quality_score"] == 1.0
