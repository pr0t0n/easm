"""BAS authorization gate — SSOT for which technique risk tiers a BasSchedule
may actually run.

Mirrors the same shape as guardrail_policy.py's deny-list and
scan_scope.py's authorization_attested pattern: a technique's risk_tier comes
from the code-defined bas_technique_catalog.py (never admin-editable), and a
schedule may only run a technique whose risk_tier is at or below the
schedule's own attested ceiling. Even though Phase 1 technique bodies only
ever produce a simulated result, this gate is enforced for real now so a
later phase that fills in real poisoning/intruder technique bodies never has
to retrofit authorization onto schedules that already exist.
"""
from __future__ import annotations

from typing import Any

from app.services.bas_technique_catalog import RISK_TIER_ORDER, get_technique


def check_bas_authorization(schedule: Any, technique_key: str) -> dict[str, Any]:
    """Returns {"allowed": bool, "reason": str}.

    `schedule` needs `.max_authorized_risk_tier` and `.authorization_attested`
    (a BasSchedule ORM row, or anything duck-typed the same way for tests).
    """
    technique = get_technique(technique_key)
    if technique is None:
        return {"allowed": False, "reason": "unknown_technique"}

    if technique["availability"] not in {"available", "simulated"}:
        return {"allowed": False, "reason": f"technique_not_executable:{technique['availability']}"}

    risk_tier = str(technique.get("risk_tier") or "safe")
    if risk_tier not in RISK_TIER_ORDER:
        return {"allowed": False, "reason": "unknown_risk_tier"}

    if RISK_TIER_ORDER[risk_tier] == 0:
        return {"allowed": True, "reason": "safe_tier_always_allowed"}

    ceiling = str(getattr(schedule, "max_authorized_risk_tier", "safe") or "safe")
    if ceiling not in RISK_TIER_ORDER:
        ceiling = "safe"
    if RISK_TIER_ORDER[risk_tier] > RISK_TIER_ORDER[ceiling]:
        return {"allowed": False, "reason": "tier_not_authorized"}

    if not bool(getattr(schedule, "authorization_attested", False)):
        return {"allowed": False, "reason": "attestation_missing"}
    if not getattr(schedule, "authorization_attested_by_id", None):
        return {"allowed": False, "reason": "attestation_missing"}

    return {"allowed": True, "reason": "tier_authorized_and_attested"}
