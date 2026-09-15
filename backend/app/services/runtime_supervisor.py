from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.services.work_item_contract import build_scan_work_item
from app.models.models import AgentTraceEvent, EvidenceArtifact, ScanLog, ScanWorkItem, WorkItemAttempt, is_post_scan_revalidation_item


def build_execution_timeline(db: Session, job_id: int, item_id: int | None = None) -> list[dict[str, Any]]:
    events = list(db.scalars(select(AgentTraceEvent).where(AgentTraceEvent.scan_id == job_id).order_by(AgentTraceEvent.created_at, AgentTraceEvent.id)))
    logs = list(db.scalars(select(ScanLog).where(ScanLog.scan_job_id == job_id).order_by(ScanLog.created_at, ScanLog.id)))
    timeline = [{"at": event.created_at.isoformat(), "source": "agent", "type": event.event_type, "status": event.status, "payload": event.payload or {}, "item_id": (event.payload or {}).get("work_item_id")} for event in events]
    timeline.extend({"at": log.created_at.isoformat(), "source": log.source, "type": "log", "status": log.level, "message": log.message} for log in logs)
    if item_id is not None:
        attempts = list(db.scalars(select(WorkItemAttempt).where(WorkItemAttempt.work_item_id == item_id).order_by(WorkItemAttempt.created_at, WorkItemAttempt.id)))
        timeline.extend({"at": attempt.created_at.isoformat(), "source": "execution_attempt", "type": attempt.state, "status": attempt.state, "item_id": item_id, "payload": {"attempt_id": attempt.id, "attempt_key": attempt.attempt_key, "worker_id": attempt.worker_id, "mcp_request_id": attempt.mcp_request_id, "runner_job_id": attempt.runner_job_id, "error_class": attempt.error_class}} for attempt in attempts)
        item = db.query(ScanWorkItem).filter(ScanWorkItem.id == item_id).first()
        if item is not None:
            artifacts = db.query(EvidenceArtifact).filter(EvidenceArtifact.scan_job_id == job_id, EvidenceArtifact.phase_id == item.phase_id, EvidenceArtifact.tool_name == item.tool_name).order_by(EvidenceArtifact.created_at, EvidenceArtifact.id).all()
            timeline.extend({"at": artifact.created_at.isoformat(), "source": "evidence", "type": artifact.artifact_type, "status": artifact.validation_status, "item_id": item_id, "payload": {"artifact_id": artifact.id, "target": artifact.target, "confidence_score": artifact.confidence_score}} for artifact in artifacts)
    if item_id is not None:
        timeline = [row for row in timeline if row.get("item_id") in (None, item_id)]
    return sorted(timeline, key=lambda row: row["at"])[-500:]


def diagnose_execution(db: Session, item: Any) -> dict[str, Any]:
    result = dict(getattr(item, "result", None) or {})
    metadata = dict(getattr(item, "item_metadata", None) or {})
    resolution = dict(metadata.get("validation_resolution") or {})
    error = str(getattr(item, "last_error", None) or "").lower()
    if resolution.get("status") == "awaiting_evidence":
        category = "data_missing"
    elif "contradict" in error or resolution.get("status") == "contradictory":
        category = "data_contradictory"
    elif "supervisor_review_required" in error or "impossible" in error:
        category = "impossible_state"
    elif "dispatch_not_acknowledged" in error or "timeout" in error or "connection" in error or "temporar" in error:
        category = "transient_error"
    elif "contract_degraded" in error:
        category = "contract_degraded"
    elif "capacity" in error or "resource" in error:
        category = "capacity_unavailable"
    elif str(getattr(item, "status", "")).lower() in {"failed", "timeout"}:
        category = "contract_degraded" if result.get("mcp_error") or "mcp" in error else "inconclusive_result"
    elif str(getattr(item, "status", "")).lower() == "completed" and not any(result.get(key) for key in ("stdout_full", "stdout_preview", "parsed_result", "evidence_path")):
        category = "inconclusive_result"
    else:
        category = "ok"
    from app.services.work_item_attempts import attempt_summary

    return {"category": category, "confidence": 0.9 if category != "ok" else 1.0, "evidence": {"status": getattr(item, "status", None), "error": getattr(item, "last_error", None), "resolution": resolution, "attempt": attempt_summary(db, item)}}


def apply_recovery_decision(item: Any, decision: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(getattr(item, "item_metadata", None) or {})
    category = str((decision.get("diagnosis") or {}).get("category") or "")
    recovery = dict(decision.get("recovery") or {})
    if decision.get("action") == "continue":
        return {"applied": False, "state": getattr(item, "status", None), "verification": "not_required"}
    attempts = int(getattr(item, "attempts", 0) or 0)
    max_attempts = int(getattr(item, "max_attempts", 1) or 1)
    safe_recovery = category in {"data_missing", "data_contradictory", "transient_error", "capacity_unavailable", "contract_degraded", "inconclusive_result"}
    if safe_recovery:
        item.status = "retry" if attempts < max_attempts else "blocked"
        item.lease_until = None
        recovery["applied"] = True
        recovery["state"] = "retry" if attempts < max_attempts else "replan"
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
    decision["recovery"] = recovery
    return recovery


def materialize_replan(db: Session, item: Any, decision: dict[str, Any], *, job: Any | None = None) -> Any | None:
    if decision.get("action") != "correct_in_flight":
        return None
    recovery = dict(decision.get("recovery") or {})
    if not recovery.get("applied") or recovery.get("state") not in {"retry", "replan"}:
        return None
    metadata = dict(getattr(item, "item_metadata", None) or {})
    scan_status = str(getattr(job, "status", "") or "").lower()
    if scan_status in {"completed", "completed_with_gaps", "failed", "stopped", "cancelled", "canceled"} and not is_post_scan_revalidation_item(item, scan_status):
        recovery.update({
            "verification": "aborted",
            "reason": "scan_closed_before_replan",
            "scan_status": scan_status,
        })
        metadata["runtime_recovery"] = recovery
        item.item_metadata = metadata
        item.status = "skipped"
        item.lease_until = None
        item.finished_at = datetime.now()
        item.last_error = "supervisor_replan_suppressed:scan_closed"
        return None
    generation = int(metadata.get("plan_generation") or 0) + 1
    recovery_root = int(metadata.get("recovery_root") or metadata.get("recovery_of") or item.id)
    if generation > int(item.max_attempts or 1):
        item.status = "blocked"
        item.last_error = "supervisor_broken_glass:recovery_generations_exhausted"
        return None
    existing = next((row for row in db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == item.scan_job_id).all() if int((row.item_metadata or {}).get("recovery_root") or 0) == recovery_root and int((row.item_metadata or {}).get("plan_generation") or 0) == generation), None)
    if existing is not None:
        return existing
    clone_metadata = {**metadata, "recovery_of": int(item.id), "recovery_root": recovery_root, "plan_generation": generation}
    clone_metadata["runtime_recovery"] = {**recovery, "verification": "pending", "source_work_item_id": int(item.id)}
    tool_name = str(item.tool_name or "")
    profile = str(item.profile or "")
    resource_class = str(item.resource_class or "light")
    if recovery.get("type") == "alternate_capability":
        from app.services.scan_quality import _fallback_candidates_for_item
        from app.services.scan_work_queue import _tool_profile, apply_phase_tool_metadata, resource_class_for_tool

        candidates = _fallback_candidates_for_item(item)
        if not candidates:
            item.status = "blocked"
            item.last_error = "supervisor_broken_glass:no_alternate_capability"
            return None
        tool_name = candidates[0]
        profile = _tool_profile(tool_name)
        resource_class = resource_class_for_tool(tool_name)
        clone_metadata = apply_phase_tool_metadata(clone_metadata, str(item.phase_id or ""), tool_name, source="runtime_supervisor")
        clone_metadata["alternate_capability"] = {"from": str(item.tool_name or ""), "to": tool_name}
    if recovery.get("type") == "change_capacity":
        clone_metadata["capacity_recovery"] = {"source_resource_class": resource_class, "priority_boost": 1}
    clone = build_scan_work_item(parent_work_item=item, derivation_kind="recovery", scan_job_id=item.scan_job_id, execution_context=f"recovery-{generation}", auth_session_revision=item.auth_session_revision, phase_id=item.phase_id, target=item.target, tool_name=tool_name, profile=profile, resource_class=resource_class, priority=max(1, int(item.priority or 100) - 1), status="queued", attempts=0, max_attempts=item.max_attempts, item_metadata=clone_metadata)
    item.status = "skipped"
    item.last_error = f"superseded_by_replan:{generation}"
    item.lease_until = None
    item.finished_at = datetime.now()
    item.result = {**dict(getattr(item, "result", None) or {}), "status": "superseded", "superseded_by_generation": generation}
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
    diagnosis = diagnose_execution(db, item)
    reasons: list[str] = []
    if resolution.get("status") == "awaiting_evidence":
        reasons.append(str(resolution.get("reason") or "context_quality_below_threshold"))
    if status in {"failed", "timeout"}:
        reasons.append(str(getattr(item, "last_error", None) or "execution_failed")[:300])
    if status == "completed" and not any(result.get(key) for key in ("stdout_full", "stdout_preview", "parsed_result", "evidence_path")):
        reasons.append("completed_without_observable_evidence")
    quality = 1.0 if not reasons else max(0.0, 1.0 - min(0.9, 0.25 * len(reasons)))
    recovery_types = {
        "data_missing": "recollect_context",
        "data_contradictory": "rehydrate_authoritative_context",
        "transient_error": "redispatch",
        "capacity_unavailable": "change_capacity",
        "contract_degraded": "alternate_capability",
        "inconclusive_result": "alternate_capability",
        "impossible_state": "broken_glass",
    }
    if quality >= 0.8 and diagnosis["category"] == "ok":
        action = "continue"
    elif diagnosis["category"] == "impossible_state":
        action = "open_broken_glass"
    else:
        action = "correct_in_flight"
    recovery = {"type": recovery_types.get(diagnosis["category"], "none"), "verification_required": action != "continue"}
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
