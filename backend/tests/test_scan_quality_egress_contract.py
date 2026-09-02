from __future__ import annotations

from pathlib import Path

from app.services.scan_quality import (
    _recon_egress_consistency,
    _recon_egress_mode_for_quality,
)


ROOT = Path(__file__).resolve().parents[1]


def test_scan_quality_exposes_recon_egress_consistency() -> None:
    source = (ROOT / "app" / "services" / "scan_quality.py").read_text(encoding="utf-8")

    assert "egress_modes" in source
    assert "p02_egress_modes" in source
    assert "p06_egress_modes" in source
    assert "mixed_recon_egress" in source
    assert "runner_egress_consistency" in source
    assert "missing_tool_binary_items" in source


def test_p02_unknown_egress_is_direct_tcp_for_quality() -> None:
    assert _recon_egress_mode_for_quality("P02", {}, {}) == "direct"


def test_p02_direct_and_p06_proxy_are_expected_transport_contract() -> None:
    consistency = _recon_egress_consistency(["direct"], ["proxy"])

    assert consistency["consistent"] is True
    assert consistency["cross_transport_difference"] is True
    assert consistency["phase_conflicts"] == {}


def test_same_phase_mixed_egress_still_blocks_quality() -> None:
    consistency = _recon_egress_consistency(["direct"], ["direct", "proxy"])

    assert consistency["consistent"] is False
    assert consistency["phase_conflicts"] == {"P06": ["direct", "proxy"]}
