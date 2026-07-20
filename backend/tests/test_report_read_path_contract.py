import inspect

from app.api import routes_scans


def test_report_read_path_never_generates_ai_recommendations():
    source = inspect.getsource(routes_scans.scan_report)
    assert "generate_portuguese_recommendations" not in source
    assert "Reports are read paths" in source


def test_cockpit_has_bounded_findings_page():
    signature = inspect.signature(routes_scans.get_cockpit)
    assert "finding_limit" in signature.parameters
    assert "finding_offset" in signature.parameters


def test_dashboard_control_plane_reuses_cockpit_contract():
    source = inspect.getsource(routes_scans.dashboard_control_plane)
    assert "get_cockpit(" in source
    assert '"verification"' in source
    assert '"crown_jewels"' in source
