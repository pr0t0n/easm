"""Regression test: every terminal branch of dispatch_scan_work_items
(quality-gate-exhausted 'blocked', and normal 'completed_with_gaps'
completion) must clear both next_retry_at and last_error.

Before this fix a scan could reach a terminal status while still carrying a
stale next_retry_at/last_error from an earlier retry round, which the
scans API then displayed for a scan that was actually done -- see
docs/JUICE_SHOP_STATEFUL_APP_PENTEST_CAPABILITY_PLAN.md Épico 1 item 7.

Mirrors the source-inspection style already used by
test_completion_synthesis_safety.py::test_dispatcher_commits_terminal_state_before_pentest_synthesis
for this same (very large) function, rather than driving a full execution.
"""
import inspect

from app.workers import tasks


def test_blocked_branch_clears_next_retry_at_and_last_error() -> None:
    source = inspect.getsource(tasks.dispatch_scan_work_items)
    blocked_pos = source.index('job.status = "blocked"')
    return_pos = source.index("return {", blocked_pos)
    segment = source[blocked_pos:return_pos]

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
