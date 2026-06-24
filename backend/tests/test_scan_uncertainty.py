from types import SimpleNamespace

from app.services.scan_uncertainty import build_uncertainty_from_records


def _job():
    return SimpleNamespace(id=7, target_query="example.test", status="completed")


def _item(phase_id, tool_name, status="completed"):
    return SimpleNamespace(phase_id=phase_id, tool_name=tool_name, profile="", status=status)


def _finding(title, tool="nuclei", verification_status="candidate", severity="medium"):
    return SimpleNamespace(
        title=title,
        tool=tool,
        verification_status=verification_status,
        severity=severity,
        details={},
        is_false_positive=False,
    )


def test_missing_auth_surface_creates_exploration_debt():
    result = build_uncertainty_from_records(
        _job(),
        work_items=[_item("P01", "subfinder"), _item("P03", "katana")],
        findings=[],
        logs=[],
    )

    debt_surfaces = {item["surface"] for item in result["exploration_debt"]}
    assert "auth_session" in debt_surfaces
    assert "api_surface" in debt_surfaces
    assert any("Authenticated/role-based testing did not run" in msg for msg in result["autopsy"])


def test_successful_validation_and_confirmed_finding_raise_coverage():
    result = build_uncertainty_from_records(
        _job(),
        work_items=[
            _item("P10", "nuclei", "completed"),
            _item("P21", "sqlmap", "completed"),
            _item("P19", "multi-identity-tester", "completed"),
        ],
        findings=[
            _finding("SQL Injection confirmed on /api/users", "sqlmap", "confirmed", "high"),
            _finding("BOLA confirmed on /api/orders", "multi-identity-tester", "confirmed", "high"),
        ],
        logs=[],
    )

    surfaces = {item["surface"]: item for item in result["uncertainty_map"]}
    assert surfaces["vuln_validation"]["coverage"] == "high"
    assert surfaces["auth_session"]["coverage"] == "high"
    assert result["coverage_score"] > 0


def test_failures_and_waf_logs_appear_in_autopsy():
    result = build_uncertainty_from_records(
        _job(),
        work_items=[_item("P10", "nuclei", "timeout")],
        findings=[],
        logs=[SimpleNamespace(message="WAF returned 429 rate limit during scan")],
    )

    assert result["status_counts"]["timeout"] == 1
    assert any("failed or timed out" in msg for msg in result["autopsy"])
    assert any("WAF/rate-limit" in msg for msg in result["autopsy"])
