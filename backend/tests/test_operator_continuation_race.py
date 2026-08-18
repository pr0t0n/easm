"""Regression tests for the phase-continuation vs completion-check race.

_enqueue_operator_continuation schedules a future celery task (e.g. "start P02
in 60s") but the SAME synchronous run_scan_job_unit call can reach its own
completion check (has_pending_work) a few lines later, see an empty
scan_work_items queue (the tiny P01 batch already finished), and declare the
scan complete -- triggering the quality gate, which blocks the scan. When the
scheduled P02 continuation fires later, it sees status=blocked and correctly
self-skips, permanently starving P02+ of any real work. Confirmed live on a
real scan: P01 seeded exactly 1 item across 3 live targets, that item
completed in seconds, and the scan sat "blocked" at 99% forever with 21 of 22
phases never seeded.

The fix: _enqueue_operator_continuation records when a scheduled continuation
is due; the completion check treats a still-pending continuation the same as
"work_queue has pending work" (reschedule a wait) instead of finalizing.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def test_pending_continuation_active_true_before_fires_at():
    from app.services.offensive_operator_runner import _pending_continuation_active

    state = {
        "_pending_phase_continuation": {
            "phase_id": "P02",
            "fires_at": (datetime.now() + timedelta(seconds=45)).isoformat(),
        }
    }
    assert _pending_continuation_active(state) is True


def test_pending_continuation_active_false_after_fires_at():
    """Self-expiring: a continuation that should already have fired (ran, or
    was lost) must not block finalization forever."""
    from app.services.offensive_operator_runner import _pending_continuation_active

    state = {
        "_pending_phase_continuation": {
            "phase_id": "P02",
            "fires_at": (datetime.now() - timedelta(seconds=5)).isoformat(),
        }
    }
    assert _pending_continuation_active(state) is False


def test_pending_continuation_active_false_when_absent_or_malformed():
    from app.services.offensive_operator_runner import _pending_continuation_active

    assert _pending_continuation_active({}) is False
    assert _pending_continuation_active({"_pending_phase_continuation": {}}) is False
    assert _pending_continuation_active(
        {"_pending_phase_continuation": {"fires_at": "not-a-timestamp"}}
    ) is False


def test_enqueue_continuation_with_countdown_records_pending_marker():
    from app.services import offensive_operator_runner as runner

    job = SimpleNamespace(id=11, state_data={})
    db = MagicMock()
    fake_task = MagicMock()
    fake_task.apply_async.return_value = SimpleNamespace(id="task-abc")
    fake_redis = MagicMock()
    fake_redis.set.return_value = True  # not deduped

    with (
        patch("app.workers.tasks.run_scan_job_unit", fake_task),
        patch("app.workers.tasks.run_scan_job_scheduled", fake_task),
        patch("app.services.scan_work_queue._redis_client", return_value=fake_redis),
    ):
        result = runner._enqueue_operator_continuation(
            db, job, "unit", "P02", countdown=60, reason="parallel_checkpoint_after_p01",
        )

    assert result["task_id"] == "task-abc"
    pending = job.state_data.get("_pending_phase_continuation")
    assert pending is not None
    assert pending["phase_id"] == "P02"
    assert runner._pending_continuation_active(job.state_data) is True


def test_enqueue_continuation_without_countdown_sets_no_marker():
    """countdown=0 fires essentially immediately -- no meaningful race window,
    and no marker should be left behind that could stall a later check."""
    from app.services import offensive_operator_runner as runner

    job = SimpleNamespace(id=12, state_data={})
    db = MagicMock()
    fake_task = MagicMock()
    fake_task.apply_async.return_value = SimpleNamespace(id="task-xyz")
    fake_redis = MagicMock()
    fake_redis.set.return_value = True

    with (
        patch("app.workers.tasks.run_scan_job_unit", fake_task),
        patch("app.workers.tasks.run_scan_job_scheduled", fake_task),
        patch("app.services.scan_work_queue._redis_client", return_value=fake_redis),
    ):
        runner._enqueue_operator_continuation(db, job, "unit", "P01", countdown=0, reason="phase_queue_start")

    assert "_pending_phase_continuation" not in job.state_data
