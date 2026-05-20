"""Offensive State — campaign, stage progression, and attacker-like reasoning primitives.

The platform operates as an iterative attacker oriented by offensive objectives.
Every finding must be evaluated through this lens, not as an isolated vulnerability.

Execution model:
  Initial Access → Surface Expansion → Credential Access → Session Abuse →
  Internal Discovery → Lateral Movement → Privilege Escalation → Objective Completion

Each stage unlocks new hypotheses, attack paths, and tool priorities.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4


# ─────────────────────────────────────────────────────────────────────────────
# Offensive stages — progression model
# ─────────────────────────────────────────────────────────────────────────────

OFFENSIVE_STAGES: list[str] = [
    "initial_access",        # First foothold in the attack surface
    "surface_expansion",     # Expand known attack surface from first findings
    "credential_access",     # Obtain credentials, tokens, API keys, hashes
    "session_abuse",         # Exploit active sessions, cookies, JWT
    "internal_discovery",    # Enumerate internal services, trusts, relationships
    "lateral_movement",      # Move between discovered assets/services
    "privilege_escalation",  # Escalate from low to high privilege context
    "objective_completion",  # Reach final objective (data, access, persistence)
]

STAGE_LABELS: dict[str, str] = {
    "initial_access": "Initial Access",
    "surface_expansion": "Surface Expansion",
    "credential_access": "Credential Access",
    "session_abuse": "Session Abuse",
    "internal_discovery": "Internal Discovery",
    "lateral_movement": "Lateral Movement",
    "privilege_escalation": "Privilege Escalation",
    "objective_completion": "Objective Completion",
}


# ─────────────────────────────────────────────────────────────────────────────
# Offensive objectives — ranked by priority
# ─────────────────────────────────────────────────────────────────────────────

OFFENSIVE_OBJECTIVES: list[dict[str, Any]] = [
    {"id": "surface_expansion",      "priority": 1, "label": "Expand attack surface", "stage": "surface_expansion"},
    {"id": "credential_harvesting",  "priority": 2, "label": "Obtain credentials",    "stage": "credential_access"},
    {"id": "trust_breaking",         "priority": 3, "label": "Break trust relationships", "stage": "internal_discovery"},
    {"id": "session_exploitation",   "priority": 4, "label": "Exploit active sessions", "stage": "session_abuse"},
    {"id": "remote_execution",       "priority": 5, "label": "Achieve remote execution", "stage": "privilege_escalation"},
    {"id": "lateral_movement",       "priority": 6, "label": "Move laterally",         "stage": "lateral_movement"},
    {"id": "persistence",            "priority": 7, "label": "Establish persistence",  "stage": "objective_completion"},
    {"id": "privilege_escalation",   "priority": 8, "label": "Escalate privilege",     "stage": "privilege_escalation"},
    {"id": "exfiltration_simulation","priority": 9, "label": "Simulate data exfiltration", "stage": "objective_completion"},
    {"id": "attack_path_construction","priority":10, "label": "Build attack paths",    "stage": "surface_expansion"},
]


# ─────────────────────────────────────────────────────────────────────────────
# Offensive questions — asked of every finding
# ─────────────────────────────────────────────────────────────────────────────

OFFENSIVE_QUESTIONS: list[dict[str, Any]] = [
    {
        "id": "enables_access",
        "question": "What does this allow me to access?",
        "maps_to_objective": "surface_expansion",
        "elevates_stage": "surface_expansion",
    },
    {
        "id": "enables_pivot",
        "question": "Does this allow pivot to another asset or service?",
        "maps_to_objective": "lateral_movement",
        "elevates_stage": "lateral_movement",
    },
    {
        "id": "enables_enum",
        "question": "Does this enable additional enumeration?",
        "maps_to_objective": "surface_expansion",
        "elevates_stage": "surface_expansion",
    },
    {
        "id": "enables_privesc",
        "question": "Does this allow privilege escalation?",
        "maps_to_objective": "privilege_escalation",
        "elevates_stage": "privilege_escalation",
    },
    {
        "id": "enables_lateral",
        "question": "Does this allow lateral movement?",
        "maps_to_objective": "lateral_movement",
        "elevates_stage": "lateral_movement",
    },
    {
        "id": "enables_credential_harvest",
        "question": "Does this allow credential harvesting?",
        "maps_to_objective": "credential_harvesting",
        "elevates_stage": "credential_access",
    },
    {
        "id": "enables_bypass",
        "question": "Does this allow bypassing security controls?",
        "maps_to_objective": "trust_breaking",
        "elevates_stage": "session_abuse",
    },
    {
        "id": "enables_chaining",
        "question": "Can this be chained with other findings?",
        "maps_to_objective": "attack_path_construction",
        "elevates_stage": "surface_expansion",
    },
    {
        "id": "reduces_unknown",
        "question": "Does this reduce unknown attack surface?",
        "maps_to_objective": "surface_expansion",
        "elevates_stage": "surface_expansion",
    },
    {
        "id": "increases_offensive_capability",
        "question": "Does this increase offensive capability?",
        "maps_to_objective": "attack_path_construction",
        "elevates_stage": "surface_expansion",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Noise profiles — stealth vs. aggressive
# ─────────────────────────────────────────────────────────────────────────────

NOISE_PROFILES: dict[str, dict[str, Any]] = {
    "aggressive": {
        "id": "aggressive",
        "label": "Aggressive",
        "max_concurrent_tools": 6,
        "rate_limit_delay_ms": 0,
        "payload_variation": "full",
        "thread_count": "max",
        "description": "No WAF detected, maximize speed and coverage",
        "trigger_conditions": ["no_waf", "low_sensitivity", "ctf_target"],
    },
    "balanced": {
        "id": "balanced",
        "label": "Balanced",
        "max_concurrent_tools": 3,
        "rate_limit_delay_ms": 500,
        "payload_variation": "moderate",
        "thread_count": "medium",
        "description": "Default profile — moderate speed, WAF-aware",
        "trigger_conditions": ["default", "unknown_protection"],
    },
    "stealthy": {
        "id": "stealthy",
        "label": "Stealthy",
        "max_concurrent_tools": 1,
        "rate_limit_delay_ms": 2000,
        "payload_variation": "minimal",
        "thread_count": "low",
        "description": "WAF or IDS detected, minimize detection risk",
        "trigger_conditions": ["waf_detected", "ids_suspected", "rate_limited"],
    },
    "evasive": {
        "id": "evasive",
        "label": "Evasive",
        "max_concurrent_tools": 1,
        "rate_limit_delay_ms": 5000,
        "payload_variation": "encoded",
        "thread_count": "minimal",
        "description": "Active blocking detected, maximum evasion mode",
        "trigger_conditions": ["blocked_requests", "honeypot_suspected", "active_mitigation"],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Phase injection — offensive signals that promote phases
# Phase promotion means the supervisor may execute a phase earlier
# when strong offensive signals warrant it (e.g., creds found → P14 immediately)
# ─────────────────────────────────────────────────────────────────────────────

PHASE_PROMOTION_RULES: list[dict[str, Any]] = [
    {
        "trigger": "credentials_found",
        "promote_phases": ["P14"],
        "reason": "Credentials found — immediately test authentication bypass",
        "priority_boost": 10,
    },
    {
        "trigger": "git_exposed",
        "promote_phases": ["P21"],
        "reason": ".git exposed — immediately scan for secrets and credentials",
        "priority_boost": 9,
    },
    {
        "trigger": "ssrf_found",
        "promote_phases": ["P13", "P10"],
        "reason": "SSRF found — probe internal services and cloud metadata",
        "priority_boost": 9,
    },
    {
        "trigger": "jwt_found",
        "promote_phases": ["P14"],
        "reason": "JWT token found — test weak signing, none algorithm, key confusion",
        "priority_boost": 8,
    },
    {
        "trigger": "api_endpoints_found",
        "promote_phases": ["P16", "P19"],
        "reason": "API endpoints discovered — test IDOR and rate limiting",
        "priority_boost": 7,
    },
    {
        "trigger": "admin_panel_found",
        "promote_phases": ["P14", "P15"],
        "reason": "Admin panel found — brute-force and path enumeration priority",
        "priority_boost": 8,
    },
    {
        "trigger": "upload_endpoint_found",
        "promote_phases": ["P17"],
        "reason": "Upload endpoint found — immediately test webshell bypass",
        "priority_boost": 9,
    },
    {
        "trigger": "cms_detected",
        "promote_phases": ["P20"],
        "reason": "CMS detected — run CMS-specific scan immediately",
        "priority_boost": 7,
    },
    {
        "trigger": "subdomain_takeover_candidate",
        "promote_phases": ["P09"],
        "reason": "Dangling CNAME detected — confirm takeover immediately",
        "priority_boost": 10,
    },
    {
        "trigger": "sql_injection_parameter",
        "promote_phases": ["P12"],
        "reason": "Parameter looks injectable — run SQLi/injection tests immediately",
        "priority_boost": 9,
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Campaign builder
# ─────────────────────────────────────────────────────────────────────────────

def build_campaign(target: str, objective: str | None = None) -> dict[str, Any]:
    """Creates a new offensive campaign structure."""
    return {
        "campaign_id": f"CAMP-{uuid4().hex[:8].upper()}",
        "target": target,
        "objective": objective or f"Obtain administrative access to {target}",
        "created_at": datetime.utcnow().isoformat(),
        "current_stage": "initial_access",
        "stage_history": [],
        "active_hypotheses": [],
        "attack_paths": [],
        "validated_chains": [],
        "offensive_state": {
            "compromised_assets": [],
            "known_assets": [],
            "credentials_found": [],
            "sessions_found": [],
            "trust_relationships": [],
            "pivot_opportunities": [],
            "internal_services": [],
            "high_value_targets": [],
        },
        "known_assets": [],
        "compromised_assets": [],
        "next_objectives": [obj["id"] for obj in OFFENSIVE_OBJECTIVES[:3]],
        "noise_profile": "balanced",
        "noise_profile_reason": "default",
        "phase_promotions": [],
        "post_exploitation_queue": [],
        "chaining_candidates": [],
        "offensive_observations": [],
    }


def advance_offensive_stage(
    campaign: dict[str, Any],
    new_stage: str,
    reason: str,
) -> dict[str, Any]:
    """Advances campaign to a new offensive stage and records history."""
    campaign = dict(campaign)
    current = str(campaign.get("current_stage") or "initial_access")

    if new_stage not in OFFENSIVE_STAGES:
        return campaign

    current_idx = OFFENSIVE_STAGES.index(current) if current in OFFENSIVE_STAGES else 0
    new_idx = OFFENSIVE_STAGES.index(new_stage)

    if new_idx <= current_idx:
        return campaign

    history = list(campaign.get("stage_history") or [])
    history.append({
        "from_stage": current,
        "to_stage": new_stage,
        "reason": reason,
        "ts": datetime.utcnow().isoformat(),
    })
    campaign["current_stage"] = new_stage
    campaign["stage_history"] = history
    return campaign


def get_next_offensive_stage(current_stage: str) -> str | None:
    """Returns the next stage in the offensive progression."""
    if current_stage not in OFFENSIVE_STAGES:
        return OFFENSIVE_STAGES[0]
    idx = OFFENSIVE_STAGES.index(current_stage)
    if idx + 1 < len(OFFENSIVE_STAGES):
        return OFFENSIVE_STAGES[idx + 1]
    return None


def select_noise_profile(campaign: dict[str, Any], waf_detected: bool, rate_limited: bool, blocked: bool) -> str:
    """Selects the appropriate noise profile based on current conditions."""
    if blocked:
        return "evasive"
    if waf_detected and rate_limited:
        return "stealthy"
    if waf_detected:
        return "balanced"
    return "aggressive"
