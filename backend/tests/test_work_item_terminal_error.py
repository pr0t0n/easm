from __future__ import annotations


def test_terminal_error_prefers_runner_detail() -> None:
    from app.workers.tasks import _terminal_result_error

    assert _terminal_result_error(
        {"error": "", "stderr": "connection refused"},
        "failed",
        1,
    ) == "connection refused"


def test_terminal_failure_without_detail_is_still_explainable() -> None:
    from app.workers.tasks import _terminal_result_error

    assert _terminal_result_error({}, "failed", 2) == "runner_failed_without_detail exit_code=2"
    assert _terminal_result_error({}, "timeout", None) == "runner_timeout_without_detail exit_code=unknown"
    assert _terminal_result_error({}, "done", 0) is None


def test_backend_local_precondition_is_not_a_tool_failure() -> None:
    from app.workers.tasks import _backend_local_terminal_status

    assert _backend_local_terminal_status("blocked_precondition", 0) == "skipped"
    assert _backend_local_terminal_status("not_applicable", 0) == "skipped"
    assert _backend_local_terminal_status("partial", 0) == "completed"
    assert _backend_local_terminal_status("failed", 0) == "failed"
