"""Regression test: every terminal branch of dispatch_scan_work_items
(quality-gate-exhausted auto-completion, and normal 'completed_with_gaps'
completion) must clear both next_retry_at and last_error.

Before this fix a scan could reach a terminal status while still carrying a
stale next_retry_at/last_error from an earlier retry round, which the
scans API then displayed for a scan that was actually done -- see
docs/JUICE_SHOP_STATEFUL_APP_PENTEST_CAPABILITY_PLAN.md Épico 1 item 7.

The quality-gate-exhausted branch used to set status="blocked" and stop,
leaving the scan to rot forever unless an operator noticed and called
POST /scans/{id}/finalize (confirmed live: scan #89, 14+ hours, blockers
with no wired remediation generator). It now auto-completes as
completed_with_gaps -- same outcome /finalize would give, without requiring
anyone to notice.

Mirrors the source-inspection style already used by
test_completion_synthesis_safety.py::test_dispatcher_commits_terminal_state_before_pentest_synthesis
for this same (very large) function, rather than driving a full execution.
"""
import inspect

from app.workers import tasks
from app.services import offensive_operator_runner


def test_quality_gate_exhausted_branch_clears_next_retry_at_and_last_error() -> None:
    source = inspect.getsource(tasks.dispatch_scan_work_items)
    exhausted_pos = source.index('job.status = "completed_with_gaps"')
    return_pos = source.index("return {", exhausted_pos)
    segment = source[exhausted_pos:return_pos]

    assert "job.last_error = None" in segment
    assert "job.next_retry_at = None" in segment


def test_completed_with_gaps_branch_clears_next_retry_at_and_last_error() -> None:
    source = inspect.getsource(tasks.dispatch_scan_work_items)
    completion_pos = source.index("SCAN CONCLUÍDO via work_queue_dispatcher")
    # The completion-status assignment sits just above the log message.
    status_assign_pos = source.rindex('job.status = str(_quality_gate.get("completion_status")', 0, completion_pos)
    segment = source[status_assign_pos:completion_pos]

    assert "job.last_error = None" in segment
    assert "job.next_retry_at = None" in segment


def test_operator_action_only_quality_gate_does_not_schedule_hard_retry() -> None:
    source = inspect.getsource(tasks.dispatch_scan_work_items)
    guard_pos = source.index("_operator_action_only =")
    retry_pos = source.index("hard_retry_count < QUALITY_GATE_HARD_BLOCK_MAX_RETRIES", guard_pos)
    retry_segment = source[retry_pos:source.index("hard_retry_count += 1", retry_pos)]

    assert "and not _operator_action_only" in retry_segment


def test_offensive_operator_work_queue_completion_uses_terminal_work_items() -> None:
    source = inspect.getsource(offensive_operator_runner.run_offensive_operator_scan)

    assert "work_queue_completed_phases = _work_queue_successful_phase_ids(db, job.id) if _wq_all_done else []" in source
    assert "execution_success_count = completed_count + partial_count + len(work_queue_completed_phases)" in source
    assert 'job.status = "completed" if execution_success_count > 0 else "failed"' in source
