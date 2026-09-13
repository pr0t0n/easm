from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.services import work_item_attempts
from app.services.runtime_supervisor import apply_recovery_decision, materialize_replan


def item(**values):
    defaults = {
        "id": 10,
        "status": "queued",
        "attempts": 2,
        "max_attempts": 2,
        "lease_until": None,
        "finished_at": None,
        "last_error": None,
        "updated_at": datetime.now(),
        "item_metadata": {},
        "result": {},
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def test_unconfirmed_queue_cycle_does_not_consume_technical_attempt(monkeypatch):
    db = MagicMock()
    target = item()
    monkeypatch.setattr(work_item_attempts, "latest_attempt", lambda *_: None)

    outcome = work_item_attempts.reconcile_expired_item(db, target, datetime.now())

    assert outcome == "requeued_unconfirmed"
    assert target.status == "queued"
    assert target.attempts == 0
    assert target.last_error == "dispatch_not_acknowledged_requeued"


def test_confirmed_attempt_exhaustion_requires_supervisor_instead_of_tool_failure(monkeypatch):
    db = MagicMock()
    target = item(status="running")
    attempt = SimpleNamespace(started_at=datetime.now(), state="execution_started")
    monkeypatch.setattr(work_item_attempts, "latest_attempt", lambda *_: attempt)
    transition = MagicMock()
    monkeypatch.setattr(work_item_attempts, "transition_attempt", transition)

    outcome = work_item_attempts.reconcile_expired_item(db, target, datetime.now())

    assert outcome == "blocked"
    assert target.status == "blocked"
    assert target.last_error == "supervisor_review_required:execution_interrupted"
    transition.assert_called_once()


def test_recovery_decision_is_forwarded_to_replanner():
    target = item(status="failed", attempts=2, item_metadata={})
    decision = {"action": "correct_in_flight", "work_item_id": target.id, "diagnosis": {"category": "transient_error"}, "recovery": {"type": "redispatch"}}

    recovery = apply_recovery_decision(target, decision)

    assert recovery["applied"] is True
    assert recovery["state"] == "replan"
    assert decision["recovery"] == recovery


def test_replan_creates_versioned_work_item():
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = []
    target = item(
        scan_job_id=4,
        execution_context="external",
        auth_session_revision=0,
        phase_id="P03",
        target="https://example.test",
        tool_name="ffuf",
        profile="ffuf",
        resource_class="medium",
        priority=100,
    )
    decision = {"action": "correct_in_flight", "recovery": {"applied": True, "state": "replan", "type": "redispatch"}}

    clone = materialize_replan(db, target, decision)

    assert clone is not None
    assert clone.execution_context == "recovery-1"
    assert clone.status == "queued"
    assert clone.attempts == 0
    assert clone.item_metadata["recovery_root"] == target.id
    assert target.status == "skipped"


def test_running_legacy_item_is_adopted_without_consuming_attempt(monkeypatch):
    db = MagicMock()
    target = item(status="submitted", attempts=1, started_at=datetime.now())
    monkeypatch.setattr(work_item_attempts, "latest_attempt", lambda *_: None)

    attempt = work_item_attempts.transition_attempt(db, target, "runner_started", runner_job_id="runner-1")

    assert target.attempts == 1
    assert attempt.state == "runner_started"
    assert attempt.runner_job_id == "runner-1"
    assert attempt.state_history[0]["adopted"] is True


def test_submitted_legacy_item_with_runner_id_remains_under_polling(monkeypatch):
    db = MagicMock()
    target = item(status="submitted", attempts=1, result={"kali_job_id": "runner-1", "mcp_request_id": "mcp-1"})
    monkeypatch.setattr(work_item_attempts, "latest_attempt", lambda *_: None)
    transition = MagicMock()
    monkeypatch.setattr(work_item_attempts, "transition_attempt", transition)

    outcome = work_item_attempts.reconcile_expired_item(db, target, datetime.now())

    assert outcome == "poll"
    assert target.status == "submitted"
    assert target.attempts == 1
    transition.assert_called_once()


def test_authoritative_runner_state_recovers_only_matching_broken_glass_item(monkeypatch):
    db = MagicMock()
    now = datetime.now()
    job = SimpleNamespace(status="blocked", state_data={"broken_glass": {"status": "required"}}, current_step="", last_error="blocked")
    target = item(
        status="blocked",
        phase_id="P21",
        result={"kali_job_id": "runner-1", "timeout": 3600},
        last_error="supervisor_broken_glass:recovery_generations_exhausted",
    )
    transition = MagicMock()
    monkeypatch.setattr(work_item_attempts, "transition_attempt", transition)

    adopted = work_item_attempts.adopt_authoritative_runner_state(db, job, target, {"job_id": "runner-1", "status": "done", "timeout": 3600}, now)

    assert adopted is True
    assert target.status == "submitted"
    assert target.last_error == "runner_status_reconciliation_required"
    assert job.status == "running"
    assert job.current_step == "P21"
    assert job.state_data["broken_glass"]["status"] == "recovered"
    transition.assert_called_once()


def test_authoritative_runner_state_rejects_mismatched_job(monkeypatch):
    db = MagicMock()
    job = SimpleNamespace(status="blocked", state_data={"broken_glass": {"status": "required"}})
    target = item(status="blocked", result={"kali_job_id": "runner-1"}, last_error="supervisor_broken_glass:recovery_generations_exhausted")
    transition = MagicMock()
    monkeypatch.setattr(work_item_attempts, "transition_attempt", transition)

    adopted = work_item_attempts.adopt_authoritative_runner_state(db, job, target, {"job_id": "runner-2", "status": "done"})

    assert adopted is False
    assert target.status == "blocked"
    transition.assert_not_called()


def test_replan_selects_alternate_capability(monkeypatch):
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = []
    target = item(
        scan_job_id=4,
        execution_context="external",
        auth_session_revision=0,
        phase_id="P12",
        target="https://example.test",
        tool_name="sqlmap",
        profile="sqlmap_basic",
        resource_class="heavy",
        priority=100,
    )
    decision = {"action": "correct_in_flight", "recovery": {"applied": True, "state": "replan", "type": "alternate_capability"}}

    clone = materialize_replan(db, target, decision)

    assert clone.tool_name == "nuclei-sqli"
    assert clone.tool_name != target.tool_name
    assert clone.item_metadata["alternate_capability"] == {"from": "sqlmap", "to": "nuclei-sqli"}


def test_verified_recovery_does_not_replan_successful_item():
    db = MagicMock()
    target = item(status="completed", item_metadata={"plan_generation": 2})
    decision = {
        "action": "continue",
        "recovery": {
            "applied": True,
            "state": "retry",
            "type": "replan_with_supervisor",
            "verification": "verified",
        },
    }

    clone = materialize_replan(db, target, decision)

    assert clone is None
    assert target.status == "completed"
    db.add.assert_not_called()
