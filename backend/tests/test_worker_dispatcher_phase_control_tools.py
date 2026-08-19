"""P18-P22 backend-local reviewers (phase_control_tools.py) have no real
kali-runner profile -- there's no target traffic to send, so MCP correctly
(but uselessly) reports tool_or_profile_not_found for them. The ScanWorkItem
work-queue only calls execute_tool_with_workers for a hardcoded tool-name
set (tasks.py) that never included these 5 names, so a live scan silently
skipped every one of them instead of running the real backend reviewer.
This locks in the interception both tasks.py and worker_dispatcher.py need.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.services.worker_dispatcher import _PHASE_CONTROL_TOOLS, execute_tool_with_workers


def test_phase_control_tool_names_match_the_real_reviewer_set():
    assert _PHASE_CONTROL_TOOLS == {
        "credential-boundary-review",
        "post-exploitation-boundary-review",
        "attack-path-correlator",
        "evidence-adjudicator",
        "report-snapshot-builder",
    }


def test_execute_tool_with_workers_routes_phase_control_tools_to_the_real_handler():
    fake_result = {"status": "success", "exit_code": 0, "stdout": "{}", "parsed": {}}

    with patch("app.services.phase_control_tools.run_phase_control_tool", return_value=dict(fake_result)) as mock_run, \
         patch("app.services.worker_dispatcher._resolve_auth_context", return_value={}), \
         patch("app.services.worker_dispatcher._persist_result_artifact"):
        result = execute_tool_with_workers(
            "attack-path-correlator", "https://valid.com", scan_id=13,
        )

    mock_run.assert_called_once_with("attack-path-correlator", 13, "https://valid.com")
    assert result["status"] == "success"


def test_execute_tool_with_workers_never_falls_through_to_mcp_for_phase_control_tools():
    with patch("app.services.phase_control_tools.run_phase_control_tool", return_value={"status": "success"}), \
         patch("app.services.worker_dispatcher._resolve_auth_context", return_value={}), \
         patch("app.services.worker_dispatcher._persist_result_artifact"), \
         patch("app.services.worker_dispatcher.execute_via_kali") as mock_kali:
        execute_tool_with_workers("evidence-adjudicator", "https://valid.com", scan_id=13)

    mock_kali.assert_not_called()


def test_execute_tool_with_workers_blocks_phase_control_tool_without_scan_id():
    with patch("app.services.worker_dispatcher._resolve_auth_context", return_value={}):
        result = execute_tool_with_workers("report-snapshot-builder", "https://valid.com", scan_id=None)

    assert result["status"] == "blocked"
    assert result["error"] == "phase_control_scan_id_required"
