from __future__ import annotations

from app.services.scan_profiles import phases_for_scan_level, scan_profile, normalize_scan_level
from app.services.scan_work_queue import work_queue_profile_policy


def test_recon_profile_limits_phase_coverage_and_depth() -> None:
    profile = scan_profile("asm")

    assert profile["id"] == "asm"
    assert profile["depth"] == "low"
    assert phases_for_scan_level("asm") == set(profile["phase_ids"])
    assert "P12" not in phases_for_scan_level("asm")
    assert profile["complete_phase_tool_coverage"] is True


def test_full_profile_runs_all_phases_with_medium_depth() -> None:
    profile = scan_profile("full")

    assert profile["depth"] == "medium"
    assert phases_for_scan_level("full") is None
    assert profile["complete_phase_tool_coverage"] is True


def test_aggressive_profile_is_not_normalized_to_full() -> None:
    profile = scan_profile("aggressive")

    assert normalize_scan_level("aggressive") == "aggressive"
    assert profile["id"] == "aggressive"
    assert profile["depth"] == "high"
    assert profile["noise_profile"] == "aggressive"
    assert profile["post_exploitation"] is True
    assert phases_for_scan_level("aggressive") is None


def test_work_queue_uses_profile_phase_and_tool_depth_policy() -> None:
    recon = work_queue_profile_policy({"scan_level": "asm"})
    full = work_queue_profile_policy({"scan_level": "full"})
    aggressive = work_queue_profile_policy({"scan_level": "aggressive"})

    assert "P12" not in recon["allowed_phases"]
    assert full["allowed_phases"] is None
    assert recon["complete_phase_tool_coverage"] is True
    assert full["complete_phase_tool_coverage"] is True
    assert aggressive["complete_phase_tool_coverage"] is True


def test_explicit_optional_override_does_not_reduce_coverage() -> None:
    policy = work_queue_profile_policy(
        {"scan_level": "aggressive"},
        max_optional_per_phase=3,
    )

    assert policy["optional_override"] is None
    assert policy["complete_phase_tool_coverage"] is True
