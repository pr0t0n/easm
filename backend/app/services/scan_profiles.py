"""Scan profile policy: phase coverage plus depth/intensity knobs.

Platform contract for the 3 user-facing depths (locked in by
test_active_exploit_authorization.py::test_platform_profile_contract):
  - Recon (asm):        no active exploitation, ever.
  - Padrao (full):      no active exploitation, ever.
  - Agressivo:           active exploitation runs once authorization is
                         approved (see resolve_active_exploit_authorization
                         in strategy_runtime.py).
`post_exploitation` is the single switch this contract reads — do not add a
second, independently-settable "active exploitation" input; changing which
profile enables it IS the platform's intended control surface.
"""
from __future__ import annotations

from typing import Any


ASM_PHASES = {"P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08", "P18", "P21", "P22"}

SCAN_PROFILES: dict[str, dict[str, Any]] = {
    "asm": {
        "id": "asm",
        "label": "Recon",
        "coverage": "surface_recon",
        "depth": "low",
        "phase_ids": sorted(ASM_PHASES),
        "max_iterations": 24,
        "tool_depth_limit": 2,
        "max_risk_allowed": "low",
        "noise_profile": "stealth",
        "post_exploitation": False,
        "description": "Descoberta e inventario de superficie sem exploracao profunda.",
    },
    "full": {
        "id": "full",
        "label": "Padrao",
        "coverage": "p01_p22",
        "depth": "medium",
        "phase_ids": None,
        "max_iterations": 45,
        "tool_depth_limit": 6,
        "max_risk_allowed": "medium",
        "noise_profile": "balanced",
        "post_exploitation": False,
        "description": "Pentest completo P01-P22 com validacao segura e evidence gate.",
    },
    "aggressive": {
        "id": "aggressive",
        "label": "Agressivo",
        "coverage": "p01_p22",
        "depth": "high",
        "phase_ids": None,
        "max_iterations": 70,
        "tool_depth_limit": 12,
        "max_risk_allowed": "high",
        "noise_profile": "aggressive",
        "post_exploitation": True,
        "description": "P01-P22 com mais budget, mais ferramentas por skill e validacao profunda controlada.",
    },
}


def normalize_scan_level(scan_level: str | None) -> str:
    level = str(scan_level or "full").lower().strip()
    aliases = {
        "recon": "asm",
        "standard": "full",
        "padrao": "full",
        "padrão": "full",
        "agressivo": "aggressive",
    }
    return aliases.get(level, level) if aliases.get(level, level) in SCAN_PROFILES else "full"


def scan_profile(scan_level: str | None) -> dict[str, Any]:
    return dict(SCAN_PROFILES[normalize_scan_level(scan_level)])


def phases_for_scan_level(scan_level: str | None) -> set[str] | None:
    profile = scan_profile(scan_level)
    phase_ids = profile.get("phase_ids")
    return set(phase_ids) if phase_ids else None
