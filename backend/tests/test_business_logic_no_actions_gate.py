"""Regression tests for the "no observed actions" branch of business_logic_test.

Guards two things at once:
  1. CORS-reflection and rate-limit-absence checks must run even when no
     mutation-action contract was observed (they were previously suppressed
     as collateral damage by the "no plan, no request" guard).
  2. The genuinely mutating checks bundled in analyze_business_logic's full
     battery (test_mass_assignment registers a real account, test_file_upload
     uploads a real file) must NOT run in that same branch -- only
     run_read_only_checks may fire, never analyze_business_logic.
"""
from __future__ import annotations

from unittest.mock import patch

from app.services.business_logic_test import run_as_tool


def test_no_actions_runs_read_only_checks_not_full_battery() -> None:
    with (
        patch(
            "app.services.business_logic_analyzer.run_read_only_checks",
            return_value=[{"title": "CORS permissivo", "severity": "high"}],
        ) as mock_read_only,
        patch("app.services.business_logic_analyzer.analyze_business_logic") as mock_full_battery,
    ):
        result = run_as_tool(
            "https://example.services-valid.com.br",
            execution_plan={"actions": [], "blocked": []},
        )

    assert result["status"] == "blocked_precondition"
    assert result["business_logic_findings"] == [{"title": "CORS permissivo", "severity": "high"}]
    mock_read_only.assert_called_once()
    mock_full_battery.assert_not_called()


def test_no_actions_battery_disabled_flag_still_short_circuits() -> None:
    """run_business_logic_battery=False (skill-probe reuse) must still no-op,
    exactly as it already does for the actions-present path."""
    with patch("app.services.business_logic_analyzer.run_read_only_checks") as mock_read_only:
        result = run_as_tool(
            "https://example.services-valid.com.br",
            execution_plan={"actions": [], "blocked": []},
            run_business_logic_battery=False,
        )

    assert result["business_logic_findings"] == []
    mock_read_only.assert_not_called()


def test_run_read_only_checks_never_touches_mutating_tests() -> None:
    from app.services.business_logic_analyzer import run_read_only_checks

    with (
        patch("app.services.business_logic_analyzer.test_open_cors", return_value=[]) as mock_cors,
        patch("app.services.business_logic_analyzer.test_rate_limit_absent", return_value=[]) as mock_rl,
        patch("app.services.business_logic_analyzer.test_mass_assignment") as mock_mass_assign,
        patch("app.services.business_logic_analyzer.test_file_upload") as mock_upload,
    ):
        findings = run_read_only_checks("https://example.com", "example.com")

    assert findings == []
    mock_cors.assert_called_once()
    mock_rl.assert_called_once()
    mock_mass_assign.assert_not_called()
    mock_upload.assert_not_called()
