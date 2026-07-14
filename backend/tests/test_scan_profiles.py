from __future__ import annotations

from app.services.scan_profiles import phases_for_scan_level, scan_profile, normalize_scan_level


def test_recon_profile_limits_phase_coverage_and_depth() -> None:
    profile = scan_profile("asm")

    assert profile["id"] == "asm"
    assert profile["depth"] == "low"
    assert phases_for_scan_level("asm") == set(profile["phase_ids"])
    assert "P12" not in phases_for_scan_level("asm")


def test_full_profile_runs_all_phases_with_medium_depth() -> None:
    profile = scan_profile("full")

    assert profile["depth"] == "medium"
    assert phases_for_scan_level("full") is None
    assert profile["tool_depth_limit"] < scan_profile("aggressive")["tool_depth_limit"]


def test_aggressive_profile_is_not_normalized_to_full() -> None:
    profile = scan_profile("aggressive")

    assert normalize_scan_level("aggressive") == "aggressive"
    assert profile["id"] == "aggressive"
    assert profile["depth"] == "high"
    assert profile["noise_profile"] == "aggressive"
    assert profile["post_exploitation"] is True
    assert phases_for_scan_level("aggressive") is None
