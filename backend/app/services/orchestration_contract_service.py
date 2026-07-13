"""Single-source orchestration contract helpers."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.graph.mission import PENTEST_PHASES
from app.models.models import ScanJob


def phase_order() -> list[str]:
    return [str(item.get("id") or "") for item in PENTEST_PHASES if item.get("id")]


def normalize_phase_ledgers(state: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Return phase_ledger_v2-style list from any historical ledger shape."""
    state = dict(state or {})
    raw = state.get("phase_ledger_v2")
    if isinstance(raw, list):
        return [dict(item) for item in raw if isinstance(item, dict)]
    raw = state.get("phase_ledger")
    if isinstance(raw, dict):
        return [dict(value or {}, phase_id=str(key)) for key, value in raw.items()]
    if isinstance(raw, list):
        return [dict(item) for item in raw if isinstance(item, dict)]
    return []


def build_execution_contract(job: ScanJob) -> dict[str, Any]:
    state = dict(job.state_data or {})
    ledgers = normalize_phase_ledgers(state)
    by_phase: dict[str, list[dict[str, Any]]] = {}
    for ledger in ledgers:
        phase_id = str(ledger.get("phase_id") or "")
        if phase_id:
            by_phase.setdefault(phase_id, []).append(ledger)
    phases: list[dict[str, Any]] = []
    for phase in PENTEST_PHASES:
        phase_id = str(phase.get("id") or "")
        entries = by_phase.get(phase_id, [])
        phases.append(
            {
                "phase_id": phase_id,
                "title": phase.get("title") or phase.get("name") or phase_id,
                "node": phase.get("node") or "",
                "expected_tools": list(phase.get("tools") or []),
                "entries": entries,
                "status": _rollup_status(entries),
                "selected_skills": sorted({s for e in entries for s in list(e.get("selected_skills") or []) if str(s)}),
                "tools_attempted": sorted({t for e in entries for t in list(e.get("tools_attempted") or []) if str(t)}),
                "tools_success": sorted({t for e in entries for t in list(e.get("tools_success") or e.get("tools_succeeded") or []) if str(t)}),
                "evidence_ids": sorted({str(ev) for e in entries for ev in list(e.get("evidence_ids") or []) if str(ev)}),
            }
        )
    completed = sum(1 for phase in phases if phase["status"] == "completed")
    blocked = sum(1 for phase in phases if phase["status"] == "blocked")
    partial = sum(1 for phase in phases if phase["status"] == "partial")
    return {
        "scan_id": job.id,
        "target": job.target_query,
        "ledger_source": "phase_ledger_v2",
        "phases_total": len(phases),
        "phases_completed": completed,
        "phases_partial": partial,
        "phases_blocked": blocked,
        "progress": round(completed / max(1, len(phases)) * 100, 2),
        "phases": phases,
        "updated_at": datetime.now().isoformat(),
    }


def persist_official_ledger(db: Session, job: ScanJob) -> list[dict[str, Any]]:
    """Ensure state_data.phase_ledger_v2 exists and is the write target."""
    state = dict(job.state_data or {})
    ledgers = normalize_phase_ledgers(state)
    state["phase_ledger_v2"] = ledgers
    state["ledger_contract_version"] = "phase_ledger_v2"
    job.state_data = state
    db.add(job)
    db.flush()
    return ledgers


def append_agent_flow_event(
    db: Session,
    job: ScanJob,
    *,
    phase_id: str,
    activity_type: str,
    skill_id: str = "",
    tool_name: str = "",
    status: str = "reported",
    approved: bool | None = None,
    report: dict[str, Any] | None = None,
    evaluation: dict[str, Any] | None = None,
) -> None:
    from app.models.models import AgentActivityLog

    current_max = (
        db.query(AgentActivityLog.iteration)
        .filter(AgentActivityLog.scan_job_id == job.id)
        .order_by(AgentActivityLog.iteration.desc())
        .first()
    )
    iteration = int(current_max[0] if current_max else 0) + 1
    db.add(
        AgentActivityLog(
            scan_job_id=job.id,
            iteration=iteration,
            activity_demand={
                "activity_id": phase_id,
                "activity_type": activity_type,
                "skill_category": skill_id,
                "kill_chain_phases": [phase_id] if phase_id else [],
                "objective": activity_type,
                "target": job.target_query,
                "demanded_at": datetime.now().isoformat(),
            },
            skill_found={
                "skill_name": skill_id,
                "skill_category": skill_id,
                "tools": [{"tool_name": tool_name, "score": 1.0}] if tool_name else [],
            },
            skill_lookup_source="orchestration_contract",
            tool_selected=tool_name,
            tool_score=1.0 if tool_name else None,
            agent_report=report or {},
            supervisor_evaluation=evaluation or {},
            approved=approved,
            status=status,
        )
    )
    db.flush()


def _rollup_status(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return "pending"
    statuses = {str(entry.get("status") or "pending").lower() for entry in entries}
    if "blocked" in statuses:
        return "blocked"
    if statuses and statuses.issubset({"completed", "skipped", "skipped_with_justification"}):
        return "completed"
    if "completed" in statuses or "partial" in statuses:
        return "partial"
    if "running" in statuses:
        return "running"
    return sorted(statuses)[0] if statuses else "pending"
