"""Phase exit-criteria validator.

Reads phase_ledger state and decides whether a phase has produced sufficient
evidence to be marked 'completed' and allow advancement to the next phase.
Never calls external tools or LLMs — pure state inspection.
"""
from __future__ import annotations

from typing import Any

# Minimum evidence items required for each phase before advancing.
# Overridden by the skill's exit_criteria.minimum_evidence_items when present.
_PHASE_MIN_EVIDENCE: dict[str, int] = {
    "P01": 1,  # subdomain list
    "P02": 1,  # open ports
    "P03": 1,  # discovered paths
    "P04": 1,  # discovered parameters
    "P05": 1,
    "P06": 1,
    "P07": 1,
    "P08": 1,
    "P09": 1,
    "P10": 1,
    "P11": 1,
    "P12": 1,
    "P13": 1,
    "P14": 1,
    "P15": 1,
    "P16": 1,
    "P17": 1,
    "P18": 1,
    "P19": 1,
    "P20": 1,
    "P21": 1,
    "P22": 1,
}

# Phases where evidence is required to be non-trivial (not just tool_attempted).
_PHASES_REQUIRING_EVIDENCE: frozenset[str] = frozenset({
    "P01", "P02", "P03", "P04",
    "P12", "P13", "P14",
})

# Phases that can advance even with partial evidence (e.g. passive recon phases).
_PARTIAL_OK_PHASES: frozenset[str] = frozenset({
    "P05", "P06", "P07", "P08", "P09", "P10",
    "P11", "P15", "P16", "P17", "P18", "P19", "P20", "P21", "P22",
})


def _get_ledger_entry(phase_ledger: dict[str, Any], phase_id: str) -> dict[str, Any]:
    return dict(phase_ledger.get(phase_id) or {})


def validate_phase_exit_criteria(
    phase_id: str,
    phase_ledger: dict[str, Any],
    skill_contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate whether a phase has met its exit criteria.

    Returns a dict with:
      status: "completed" | "partial" | "blocked" | "skipped"
      can_advance: bool
      reason: str
      evidence_count: int
      tools_attempted: int
      tools_succeeded: int
    """
    entry = _get_ledger_entry(phase_ledger, phase_id)
    current_status = str(entry.get("status") or "pending")

    # Already finalized — don't override
    if current_status in ("completed", "skipped"):
        return {
            "status": current_status,
            "can_advance": True,
            "reason": f"phase_already_{current_status}",
            "evidence_count": len(entry.get("evidence_ids") or []),
            "tools_attempted": len(entry.get("tools_attempted") or []),
            "tools_succeeded": len(entry.get("tools_succeeded") or []),
        }

    evidence_ids: list[str] = list(entry.get("evidence_ids") or [])
    tools_attempted: list[str] = list(entry.get("tools_attempted") or [])
    tools_succeeded: list[str] = list(entry.get("tools_succeeded") or [])
    skip_reason: str = str(entry.get("skip_reason") or "")

    # Phase was explicitly marked as skipped
    if skip_reason:
        return {
            "status": "skipped",
            "can_advance": True,
            "reason": f"explicit_skip: {skip_reason}",
            "evidence_count": len(evidence_ids),
            "tools_attempted": len(tools_attempted),
            "tools_succeeded": len(tools_succeeded),
        }

    # Determine minimum evidence threshold
    min_evidence = _PHASE_MIN_EVIDENCE.get(phase_id, 1)
    if skill_contract:
        exit_criteria = dict(skill_contract.get("exit_criteria") or {})
        sc_min = exit_criteria.get("minimum_evidence_items")
        if isinstance(sc_min, int) and sc_min >= 0:
            min_evidence = sc_min
        sc_min_tools = exit_criteria.get("minimum_tools_attempted")
        if isinstance(sc_min_tools, int) and sc_min_tools > 0:
            if len(tools_attempted) < sc_min_tools:
                return {
                    "status": "blocked",
                    "can_advance": False,
                    "reason": f"minimum_tools_not_attempted: need {sc_min_tools}, have {len(tools_attempted)}",
                    "evidence_count": len(evidence_ids),
                    "tools_attempted": len(tools_attempted),
                    "tools_succeeded": len(tools_succeeded),
                }

    evidence_count = len(evidence_ids)

    # No tool was even attempted
    if not tools_attempted:
        if phase_id in _PARTIAL_OK_PHASES:
            return {
                "status": "partial",
                "can_advance": True,
                "reason": "no_tools_attempted_but_partial_ok",
                "evidence_count": 0,
                "tools_attempted": 0,
                "tools_succeeded": 0,
            }
        return {
            "status": "blocked",
            "can_advance": False,
            "reason": "no_tools_attempted",
            "evidence_count": 0,
            "tools_attempted": 0,
            "tools_succeeded": 0,
        }

    # All tools failed
    if tools_attempted and not tools_succeeded:
        if phase_id in _PARTIAL_OK_PHASES:
            return {
                "status": "partial",
                "can_advance": True,
                "reason": "all_tools_failed_but_partial_ok",
                "evidence_count": evidence_count,
                "tools_attempted": len(tools_attempted),
                "tools_succeeded": 0,
            }
        retry_count = int(entry.get("retry_count") or 0)
        max_retries = 2
        if skill_contract:
            rp = dict(skill_contract.get("retry_policy") or {})
            max_retries = int(rp.get("max_attempts") or 2)
        if retry_count >= max_retries:
            return {
                "status": "blocked",
                "can_advance": False,
                "reason": f"all_tools_failed_max_retries_{retry_count}",
                "evidence_count": evidence_count,
                "tools_attempted": len(tools_attempted),
                "tools_succeeded": 0,
            }
        return {
            "status": "blocked",
            "can_advance": False,
            "reason": f"all_tools_failed_retry_available_{retry_count}/{max_retries}",
            "evidence_count": evidence_count,
            "tools_attempted": len(tools_attempted),
            "tools_succeeded": 0,
        }

    # Evidence threshold check
    if phase_id in _PHASES_REQUIRING_EVIDENCE and evidence_count < min_evidence:
        return {
            "status": "partial",
            "can_advance": False,
            "reason": f"insufficient_evidence: have {evidence_count}, need {min_evidence}",
            "evidence_count": evidence_count,
            "tools_attempted": len(tools_attempted),
            "tools_succeeded": len(tools_succeeded),
        }

    # Validator required but not run
    validator_required = False
    if skill_contract:
        exit_criteria = dict(skill_contract.get("exit_criteria") or {})
        validator_required = bool(exit_criteria.get("validator_required"))
    validation_result = dict(entry.get("validation_result") or {})
    if validator_required and not validation_result:
        return {
            "status": "partial",
            "can_advance": False,
            "reason": "validator_required_but_not_run",
            "evidence_count": evidence_count,
            "tools_attempted": len(tools_attempted),
            "tools_succeeded": len(tools_succeeded),
        }
    if validator_required and validation_result.get("status") == "FAILURE":
        return {
            "status": "blocked",
            "can_advance": False,
            "reason": f"validator_failed: {validation_result.get('reason', '')}",
            "evidence_count": evidence_count,
            "tools_attempted": len(tools_attempted),
            "tools_succeeded": len(tools_succeeded),
        }

    # Partial: tools ran, some succeeded, but not all evidence types collected
    if tools_succeeded and evidence_count >= 1:
        status = "completed" if evidence_count >= min_evidence else "partial"
        can_advance = status in ("completed",) or phase_id in _PARTIAL_OK_PHASES
        return {
            "status": status,
            "can_advance": can_advance,
            "reason": f"tools_succeeded_{len(tools_succeeded)}_evidence_{evidence_count}",
            "evidence_count": evidence_count,
            "tools_attempted": len(tools_attempted),
            "tools_succeeded": len(tools_succeeded),
        }

    return {
        "status": "partial",
        "can_advance": phase_id in _PARTIAL_OK_PHASES,
        "reason": "inconclusive_state",
        "evidence_count": evidence_count,
        "tools_attempted": len(tools_attempted),
        "tools_succeeded": len(tools_succeeded),
    }


def finalize_phase(
    phase_id: str,
    phase_ledger: dict[str, Any],
    validation_result: dict[str, Any],
) -> dict[str, Any]:
    """Apply validation result to the phase ledger entry and return updated ledger."""
    from datetime import datetime, timezone

    ledger = dict(phase_ledger)
    entry = dict(ledger.get(phase_id) or {})

    entry["status"] = validation_result.get("status", "partial")
    entry["exit_criteria_met"] = validation_result.get("can_advance", False)
    entry["can_advance"] = validation_result.get("can_advance", False)
    entry["validation_result"] = {
        "status": validation_result.get("status"),
        "reason": validation_result.get("reason"),
        "can_advance": validation_result.get("can_advance"),
        "evidence_count": validation_result.get("evidence_count"),
        "validated_at": datetime.now(timezone.utc).isoformat(),
    }
    if entry["status"] in ("completed", "partial", "blocked"):
        entry.setdefault("completed_at", datetime.now(timezone.utc).isoformat())

    ledger[phase_id] = entry
    return ledger


def should_retry_phase(
    phase_id: str,
    phase_ledger: dict[str, Any],
    skill_contract: dict[str, Any] | None = None,
) -> bool:
    """Return True if the phase should be retried (tools failed, retries remaining)."""
    entry = _get_ledger_entry(phase_ledger, phase_id)
    retry_count = int(entry.get("retry_count") or 0)
    max_retries = 2
    if skill_contract:
        rp = dict(skill_contract.get("retry_policy") or {})
        max_retries = int(rp.get("max_attempts") or 2)
    tools_attempted = list(entry.get("tools_attempted") or [])
    tools_succeeded = list(entry.get("tools_succeeded") or [])
    all_failed = bool(tools_attempted) and not tools_succeeded
    return all_failed and retry_count < max_retries


def get_next_phase_id(current_phase_id: str, phase_ledger: dict[str, Any]) -> str | None:
    """Return the next phase ID after the given one, or None if at end."""
    from app.graph.mission import PENTEST_PHASES

    all_ids = [str(p.get("id") or "") for p in PENTEST_PHASES]
    try:
        idx = all_ids.index(current_phase_id.upper())
    except ValueError:
        return None
    next_idx = idx + 1
    if next_idx >= len(all_ids):
        return None
    # Skip phases already completed/skipped
    while next_idx < len(all_ids):
        next_id = all_ids[next_idx]
        entry = _get_ledger_entry(phase_ledger, next_id)
        if str(entry.get("status") or "pending") not in ("completed", "skipped"):
            return next_id
        next_idx += 1
    return None
