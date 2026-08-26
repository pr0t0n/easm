"""`state["discovered_endpoints"]`/`state["internal_discovered_endpoints"]` are
the keys js_analyzer.py and every other endpoint producer actually write.
`javascript_bundles`/`discovered_js_routes`/`api_routes` (checked by the
P08 depth requirement and the P08 tool-missing gap) have no writer anywhere
in the codebase, so js_surface detection was permanently blind to real JS
analysis output. `_discovered_endpoints_indicate_js_api_surface` closes that
gap without treating every generic discovered endpoint as "JS/API surface".
"""
from app.services.scan_quality import (
    _build_p08_tool_missing_gap,
    _discovered_endpoints_indicate_js_api_surface,
)


def test_no_surface_when_discovered_endpoints_is_empty():
    assert _discovered_endpoints_indicate_js_api_surface({}) is False
    assert _discovered_endpoints_indicate_js_api_surface({"discovered_endpoints": []}) is False


def test_no_surface_when_endpoints_are_plain_pages():
    state = {"discovered_endpoints": ["http://target/", "http://target/about", "http://target/contact"]}

    assert _discovered_endpoints_indicate_js_api_surface(state) is False


def test_surface_detected_from_discovered_endpoints_api_marker():
    state = {"discovered_endpoints": ["http://target/rest/products/search?q=test"]}

    assert _discovered_endpoints_indicate_js_api_surface(state) is True


def test_surface_detected_from_internal_discovered_endpoints():
    state = {"internal_discovered_endpoints": ["http://target/api/Login"]}

    assert _discovered_endpoints_indicate_js_api_surface(state) is True


def test_p08_tool_missing_gap_now_fires_from_discovered_endpoints_alone(monkeypatch):
    from app.services import scan_quality

    monkeypatch.setattr(
        scan_quality,
        "_tool_health_status_map",
        lambda: {"linkfinder": "missing_binary", "paramspider": "missing_binary"},
    )

    gaps = _build_p08_tool_missing_gap(
        state={"discovered_endpoints": ["http://target/rest/products/search"]},
        work_items=[],
        artifacts=[],
    )

    assert len(gaps) == 1
    assert gaps[0]["area"] == "tool_missing"
