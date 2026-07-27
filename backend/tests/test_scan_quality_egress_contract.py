from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_scan_quality_exposes_recon_egress_consistency() -> None:
    source = (ROOT / "app" / "services" / "scan_quality.py").read_text(encoding="utf-8")

    assert "egress_modes" in source
    assert "p02_egress_modes" in source
    assert "p06_egress_modes" in source
    assert "mixed_recon_egress" in source
    assert "runner_egress_consistency" in source
    assert "missing_tool_binary_items" in source
