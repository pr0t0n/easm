"""Utilities to keep ScanJob.state_data small enough for hot-path updates.

``scan_jobs.state_data`` is updated by the dispatcher, workers and reporting
paths many times during a scan.  It must hold coordination state, not full
telemetry payloads.  Large append-only lists here turn every status update into
a multi-megabyte JSONB rewrite, creating lock/statement timeouts under load.
Durable verbose telemetry belongs in dedicated tables such as AgentTraceEvent.
"""

from __future__ import annotations

from typing import Any


MAX_HOT_SKILL_CONSULTATIONS = 250
MAX_HOT_SKILL_INVOCATIONS = 300


def _compact_skill_consultation(value: Any) -> dict[str, Any]:
    item = dict(value or {}) if isinstance(value, dict) else {}
    return {
        "consultation_id": item.get("consultation_id"),
        "phase_id": item.get("phase_id"),
        "target": item.get("target"),
        "skill_id": item.get("skill_id"),
        "consulted": bool(item.get("consulted", True)),
        "selected": bool(item.get("selected")),
        "applicability_score": item.get("applicability_score"),
        "recommended_tools": list(item.get("recommended_tools") or [])[:8],
        "learning_used": bool(item.get("learning_used")),
        "source": item.get("source"),
        "created_at": item.get("created_at"),
    }


def _compact_skill_invocation(value: Any) -> dict[str, Any]:
    item = dict(value or {}) if isinstance(value, dict) else {}
    return {
        "phase_id": item.get("phase_id"),
        "skill_id": item.get("skill_id"),
        "target": item.get("target"),
        "source": item.get("source"),
        "recommended_tools": list(item.get("recommended_tools") or [])[:8],
        "learning_used": bool(item.get("learning_used")),
        "created_at": item.get("created_at"),
    }


def sanitize_scan_state_for_hot_update(state: dict[str, Any] | None) -> dict[str, Any]:
    """Return a copy of state_data safe for frequent JSONB rewrites.

    The function intentionally preserves execution-critical coordination keys
    and only compacts append-only telemetry that already has a durable verbose
    home elsewhere.
    """
    result = dict(state or {})

    consultations = result.get("skill_consultations")
    if isinstance(consultations, list):
        compacted = [
            _compact_skill_consultation(item)
            for item in consultations[-MAX_HOT_SKILL_CONSULTATIONS:]
            if isinstance(item, dict)
        ]
        result["skill_consultations"] = compacted
        result["skill_consultations_hot_compacted"] = True
        result["skill_consultations_hot_limit"] = MAX_HOT_SKILL_CONSULTATIONS

    invocations = result.get("skill_invocation")
    if isinstance(invocations, list):
        result["skill_invocation"] = [
            _compact_skill_invocation(item)
            for item in invocations[-MAX_HOT_SKILL_INVOCATIONS:]
            if isinstance(item, dict)
        ]
        result["skill_invocation_hot_compacted"] = True
        result["skill_invocation_hot_limit"] = MAX_HOT_SKILL_INVOCATIONS

    return result
