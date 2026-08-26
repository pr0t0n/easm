"""P08 (client-side route/API discovery) must surface an explicit,
profile-independent 'tool_missing' gap when linkfinder/paramspider are
operationally absent from the kali-runner -- as opposed to having run and
found nothing. Before this fix that distinction only existed inside
_build_aggressive_depth_requirements, gated on profile == 'aggressive'.
"""
from types import SimpleNamespace

from app.services import scan_quality
from app.services.scan_quality import _build_p08_tool_missing_gap


def _work_item(phase_id="P08", tool_name="linkfinder", status="failed"):
    return SimpleNamespace(phase_id=phase_id, tool_name=tool_name, status=status)


def test_no_gap_when_no_js_surface_observed(monkeypatch):
    monkeypatch.setattr(scan_quality, "_tool_health_status_map", lambda: {"linkfinder": "missing_binary"})

    gaps = _build_p08_tool_missing_gap(state={}, work_items=[], artifacts=[])

    assert gaps == []


def test_gap_raised_when_js_surface_present_and_tools_missing_binary(monkeypatch):
    monkeypatch.setattr(
        scan_quality,
        "_tool_health_status_map",
        lambda: {"linkfinder": "missing_binary", "paramspider": "missing_binary"},
    )

    gaps = _build_p08_tool_missing_gap(
        state={"js_bundles": ["main.js"]},
        work_items=[],
        artifacts=[],
    )

    assert len(gaps) == 1
    gap = gaps[0]
    assert gap["area"] == "tool_missing"
    assert gap["severity"] == "high"
    assert "linkfinder" in gap["detail"]
    assert "paramspider" in gap["detail"]


def test_no_gap_when_p08_already_completed_with_a_discovery_tool(monkeypatch):
    monkeypatch.setattr(
        scan_quality,
        "_tool_health_status_map",
        lambda: {"linkfinder": "missing_binary", "paramspider": "missing_binary"},
    )

    gaps = _build_p08_tool_missing_gap(
        state={"js_bundles": ["main.js"]},
        work_items=[_work_item(tool_name="katana", status="completed")],
        artifacts=[],
    )

    assert gaps == []


def test_no_gap_when_tools_are_ready_not_missing(monkeypatch):
    monkeypatch.setattr(
        scan_quality,
        "_tool_health_status_map",
        lambda: {"linkfinder": "ready", "paramspider": "ready"},
    )

    gaps = _build_p08_tool_missing_gap(
        state={"js_bundles": ["main.js"]},
        work_items=[],
        artifacts=[],
    )

    assert gaps == []
