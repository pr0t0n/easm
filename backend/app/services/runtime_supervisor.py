from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.models import AgentTraceEvent, ScanLog, ScanWorkItem


def build_execution_timeline(db: Session, job_id: int, item_id: int | None = None) -> list[dict[str, Any]]:
    events = list(db.scalars(select(AgentTraceEvent).where(AgentTraceEvent.scan_id == job_id).order_by(AgentTraceEvent.created_at, AgentTraceEvent.id)))
    logs = list(db.scalars(select(ScanLog).where(ScanLog.scan_job_id == job_id).order_by(ScanLog.created_at, ScanLog.id)))
    timeline = [{"at": event.created_at.isoformat(), "source": "agent", "type": event.event_type, "status": event.status, "payload": event.payload or {}, "item_id": (event.payload or {}).get("work_item_id")} for event in events]
    timeline.extend({"at": log.created_at.isoformat(), "source": log.source, "type": "log", "status": log.level, "message": log.message} for log in logs)
    if item_id is not None:
        timeline = [row for row in timeline if row.get("item_id") in (None, item_id)]
    return sorted(timeline, key=lambda row: row["at"])[-500:]


def diagnose_execution(item: Any) -> dict[str, Any]:
    result = dict(getattr(item, "result", None) or {})
    metadata = dict(getattr(item, "item_metadata", None) or {})
    resolution = dict(metadata.get("validation_resolution") or {})
    error = str(getattr(item, "last_error", None) or "").lower()
    if resolution.get("status") == "awaiting_evidence":
        category = "data_missing"
    elif "contradict" in error or resolution.get("status") == "contradictory":
        category = "data_contradictory"
    elif "timeout" in error or "connection" in error or "temporar" in error:
        category = "transient_error"
    elif "capacity" in error or "resource" in error:
        category = "capacity_unavailable"
    elif str(getattr(item, "status", "")).lower() in {"failed", "timeout"}:
        category = "contract_degraded" if result.get("mcp_error") else "inconclusive_result"
    elif str(getattr(item, "status", "")).lower() == "completed" and not any(result.get(key) for key in ("stdout_full", "stdout_preview", "parsed_result", "evidence_path")):
        category = "inconclusive_result"
    else:
        category = "ok"
    return {"category": category, "confidence": 0.9 if category != "ok" else 1.0, "evidence": {"status": getattr(item, "status", None), "error": getattr(item, "last_error", None), "resolution": resolution}}


def apply_recovery_decision(item: Any, decision: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(getattr(item, "item_metadata", None) or {})
    category = str((decision.get("diagnosis") or {}).get("category") or "")
    recovery = dict(decision.get("recovery") or {})
    if decision.get("action") == "continue":
        return {"applied": False, "state": getattr(item, "status", None), "verification": "not_required"}
    attempts = int(getattr(item, "attempts", 0) or 0)
    max_attempts = int(getattr(item, "max_attempts", 1) or 1)
    safe_recovery = category in {"data_missing", "data_contradictory", "transient_error", "capacity_unavailable", "inconclusive_result"}
    if safe_recovery and attempts < max_attempts:
        item.status = "retry"
        item.lease_until = None
        recovery["applied"] = True
        recovery["state"] = "retry"
        recovery["verification_attempt"] = attempts + 1
    else:
        item.status = "blocked"
        item.lease_until = None
        recovery["applied"] = True
        recovery["state"] = "blocked"
        item.last_error = f"supervisor_broken_glass:{category}"[:2000]
    recovery["verification"] = "pending"
    metadata["runtime_recovery"] = recovery
    metadata["runtime_recovery_source"] = decision.get("work_item_id")
    item.item_metadata = metadata
    return recovery


def materialize_replan(db: Session, item: Any, decision: dict[str, Any]) -> Any | None:
    recovery = dict(decision.get("recovery") or {})
    if not recovery.get("applied") or recovery.get("state") != "retry":
        return None
    metadata = dict(getattr(item, "item_metadata", None) or {})
    generation = int(metadata.get("plan_generation") or 0) + 1
    existing = next((row for row in db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == item.scan_job_id, ScanWorkItem.execution_context == "recovery").all() if int((row.item_metadata or {}).get("recovery_of") or 0) == int(item.id)), None)
    if existing is not None:
        return existing
    clone = ScanWorkItem(scan_job_id=item.scan_job_id, execution_context="recovery", auth_session_revision=item.auth_session_revision, phase_id=item.phase_id, target=item.target, tool_name=item.tool_name, profile=item.profile, resource_class=item.resource_class, priority=max(1, int(item.priority or 100) - 1), status="queued", max_attempts=item.max_attempts, item_metadata={**metadata, "recovery_of": int(item.id), "plan_generation": generation})
    item.status = "blocked"
    item.last_error = f"superseded_by_replan:{generation}"
    db.add(clone)
    db.flush()
    recovery["new_work_item_id"] = clone.id
    metadata["runtime_recovery"] = recovery
    item.item_metadata = metadata
    return clone


def evaluate_runtime_outcome(db: Session, job: Any, item: Any) -> dict[str, Any]:
    result = dict(getattr(item, "result", None) or {})
    metadata = dict(getattr(item, "item_metadata", None) or {})
    status = str(getattr(item, "status", "") or "").lower()
    resolution = dict(metadata.get("validation_resolution") or {})
    diagnosis = diagnose_execution(item)
    reasons: list[str] = []
    if resolution.get("status") == "awaiting_evidence":
        reasons.append(str(resolution.get("reason") or "context_quality_below_threshold"))
    if status in {"failed", "timeout"}:
        reasons.append(str(getattr(item, "last_error", None) or "execution_failed")[:300])
    if status == "completed" and not any(result.get(key) for key in ("stdout_full", "stdout_preview", "parsed_result", "evidence_path")):
        reasons.append("completed_without_observable_evidence")
    quality = 1.0 if not reasons else max(0.0, 1.0 - min(0.9, 0.25 * len(reasons)))
    action = "continue" if quality >= 0.8 and diagnosis["category"] == "ok" else "open_broken_glass"
    recovery = {"type": "none" if action == "continue" else ("recollect_context" if diagnosis["category"] == "data_missing" else "replan_with_supervisor"), "verification_required": action != "continue"}
    decision = {
        "status": "satisfactory" if action == "continue" else "unsatisfactory",
        "quality_score": quality,
        "action": action,
        "reasons": reasons,
        "diagnosis": diagnosis,
        "recovery": recovery,
        "work_item_id": int(item.id),
        "phase_id": str(item.phase_id),
        "evaluated_at": datetime.now().isoformat(),
    }
    decision["timeline"] = build_execution_timeline(db, int(job.id), int(item.id))
    previous_recovery = dict(metadata.get("runtime_recovery") or {})
    if previous_recovery and action == "continue":
        previous_recovery["verification"] = "verified"
        metadata["runtime_recovery"] = previous_recovery
        item.item_metadata = metadata
        decision["recovery"] = previous_recovery
    state = dict(getattr(job, "state_data", None) or {})
    supervisor = dict(state.get("runtime_supervisor") or {})
    history = [row for row in list(supervisor.get("history") or []) if isinstance(row, dict)]
    history.append(decision)
    supervisor.update({"status": action, "last_decision": decision, "history": history[-100:]})
    state["runtime_supervisor"] = supervisor
    job.state_data = state
    db.add(AgentTraceEvent(
        scan_id=job.id,
        iteration=int(getattr(item, "attempts", 0) or 0),
        event_type="runtime_quality_decision",
        from_node="execution",
        to_node="supervisor",
        skill_id=str(metadata.get("skill_id") or "")[:120] or None,
        tool_name=str(getattr(item, "tool_name", "") or "")[:100] or None,
        capability=str(getattr(item, "phase_id", "") or "")[:100] or None,
        status=decision["status"],
        payload=decision,
        created_at=datetime.now(),
    ))
    return decision
