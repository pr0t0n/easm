from __future__ import annotations

import hashlib
import re
from typing import Any


TERMINAL_STATUSES = {"completed", "done", "refuted", "confirmed", "validated"}
BLOCKED_STATUSES = {"blocked", "skipped", "not_applicable", "tool_failure", "parser_failure"}


def _slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_") or "step"


def _activity_id(skill_id: str, name: str) -> str:
    digest = hashlib.sha256(f"{skill_id}:{name}".encode()).hexdigest()[:10]
    return f"{_slug(skill_id)}:{_slug(name)}:{digest}"


def _activity(skill_id: str, name: str, objective: str, evidence: list[str], validator: str, *, destructive: bool = False) -> dict[str, Any]:
    return {
        "activity_id": _activity_id(skill_id, name),
        "name": name,
        "objective": objective,
        "required_evidence": list(dict.fromkeys(str(item) for item in evidence if str(item))),
        "validator": validator,
        "destructive": bool(destructive),
        "status": "planned",
        "evidence_artifact_ids": [],
        "validation_ids": [],
        "blocking_reason": None,
    }


def build_skill_activity_plan(skill: dict[str, Any], *, phase_id: str = "", target: str = "") -> list[dict[str, Any]]:
    skill_id = str(skill.get("id") or skill.get("skill_id") or "").strip()
    if not skill_id:
        return []
    evidence = [str(item) for item in list(skill.get("evidence_required") or []) if str(item)]
    objective = str(skill.get("objective") or skill.get("name") or skill_id)
    activities = [
        _activity(skill_id, "baseline", f"Estabelecer baseline para {objective}.", ["baseline_response"], "baseline-comparator"),
    ]
    for evidence_name in evidence:
        activities.append(
            _activity(
                skill_id,
                f"collect_{_slug(evidence_name)}",
                f"Coletar evidência {evidence_name} para {objective}.",
                [evidence_name],
                "evidence-contract-validator",
            )
        )
    if bool(skill.get("requires_two_identities_for_confirmation")):
        activities.append(
            _activity(
                skill_id,
                "cross_identity_validation",
                "Comparar o mesmo objeto entre contextos de identidade distintos.",
                ["positive_identity_response", "negative_identity_response", "object_attribution"],
                "multi-identity-validator",
            )
        )
    if bool(skill.get("mutating_confirmation_requires_fixture")):
        activities.append(
            _activity(
                skill_id,
                "mutation_guard",
                "Verificar fixture ou plano de mutação reversível antes de qualquer alteração de estado.",
                ["fixture_or_mutation_plan"],
                "mutation-precondition-validator",
            )
        )
    activities.append(
        _activity(
            skill_id,
            "independent_validation",
            "Revalidar o sinal com o validador definido pela skill.",
            ["validation_result"],
            str(skill.get("validator") or "independent-evidence-validator"),
        )
    )
    for activity in activities:
        activity["phase_id"] = str(phase_id or "")
        activity["target"] = str(target or "")
    return activities


def build_activity_plans_for_catalog(catalog: dict[str, Any], *, phase_id: str = "", target: str = "") -> dict[str, list[dict[str, Any]]]:
    return {
        str(skill.get("id")): build_skill_activity_plan(skill, phase_id=phase_id, target=target)
        for skill in list(catalog.get("skills") or [])
        if isinstance(skill, dict) and str(skill.get("id") or "").strip()
    }


def materialize_skill_execution(
    metadata: dict[str, Any] | None,
    result: dict[str, Any] | None,
    *,
    artifact_ids: list[int] | None = None,
    validation_ids: list[int] | None = None,
) -> dict[str, Any]:
    source = dict(metadata or {})
    execution = dict(result or {})
    plans = [dict(item) for item in list(source.get("skill_activity_plan") or []) if isinstance(item, dict)]
    if not plans:
        return {
            "consulted": bool(source.get("skill_consultation_ids") or source.get("skill_id")),
            "selected": bool(source.get("skill_id")),
            "materialized": False,
            "activity_count": 0,
            "executed_count": 0,
            "evidence_complete_count": 0,
            "validated_count": 0,
            "blocked_count": 0,
            "activities": [],
        }
    status = str(execution.get("status") or execution.get("execution_status") or "").lower()
    parsed = execution.get("parsed_result") if isinstance(execution.get("parsed_result"), dict) else execution
    observations = list(parsed.get("response_observations") or parsed.get("observations") or [])
    findings = list(execution.get("findings_extracted") or parsed.get("findings") or [])
    errors = list(parsed.get("observation_error_counts") or {})
    blocked_reason = str(parsed.get("blocked_reason") or execution.get("blocked_reason") or "").strip()
    has_observation = bool(observations)
    has_evidence = bool(
        observations
        or findings
        or execution.get("stdout")
        or execution.get("stdout_full")
        or execution.get("stdout_preview")
        or execution.get("stdout_path")
        or execution.get("evidence_path")
    )
    status_terminal = status in TERMINAL_STATUSES
    artifact_ids = [int(item) for item in list(artifact_ids or []) if str(item).isdigit()]
    validation_ids = [int(item) for item in list(validation_ids or []) if str(item).isdigit()]
    executed_count = 0
    evidence_complete_count = 0
    validated_count = 0
    blocked_count = 0
    for index, activity in enumerate(plans):
        row = dict(activity)
        if blocked_reason and ("fixture" in blocked_reason or "identity" in blocked_reason):
            row["status"] = "blocked"
            row["blocking_reason"] = blocked_reason
            blocked_count += 1
        elif not status_terminal:
            row["status"] = "tool_failure" if status in {"failed", "timeout"} else "inconclusive"
        elif index == 0:
            row["status"] = "completed" if has_observation or has_evidence else "inconclusive"
        elif row.get("name") == "independent_validation":
            row["status"] = "validated" if validation_ids or findings or (status_terminal and has_evidence) else "inconclusive"
        else:
            row["status"] = "completed" if has_observation or has_evidence else "inconclusive"
        row["evidence_artifact_ids"] = artifact_ids
        row["validation_ids"] = validation_ids if row.get("name") == "independent_validation" else []
        row["observation_count"] = len(observations)
        row["finding_count"] = len(findings)
        row["error_count"] = len(errors)
        if row["status"] in {"completed", "validated"}:
            executed_count += 1
        if row["status"] in {"completed", "validated"} and has_evidence:
            evidence_complete_count += 1
        if row["status"] == "validated":
            validated_count += 1
        plans[index] = row
    return {
        "consulted": bool(source.get("skill_consultation_ids") or source.get("skill_id")),
        "selected": bool(source.get("skill_id")),
        "materialized": True,
        "activity_count": len(plans),
        "executed_count": executed_count,
        "evidence_complete_count": evidence_complete_count,
        "validated_count": validated_count,
        "blocked_count": blocked_count,
        "activities": plans,
    }


def summarize_skill_activity_execution(work_items: list[Any]) -> dict[str, Any]:
    consultations = 0
    selected = 0
    materialized = 0
    planned = 0
    executed = 0
    evidence_complete = 0
    validated = 0
    blocked = 0
    generic_only = 0
    by_skill: dict[str, dict[str, int]] = {}
    for item in list(work_items or []):
        metadata = dict(getattr(item, "item_metadata", None) or {})
        skill_ids = [str(value) for value in list(metadata.get("skill_ids") or []) if str(value)]
        if metadata.get("skill_id"):
            skill_ids.append(str(metadata["skill_id"]))
        metric = dict(metadata.get("skill_activity_execution") or {})
        plan = list(metadata.get("skill_activity_plan") or [])
        if metadata.get("skill_consultation_ids") or skill_ids:
            consultations += 1
        if metadata.get("skill_id"):
            selected += 1
        if plan:
            materialized += 1
            planned += len(plan)
        elif metadata.get("api_skill_id") or metadata.get("skill_id"):
            generic_only += 1
        executed += int(metric.get("executed_count") or 0)
        evidence_complete += int(metric.get("evidence_complete_count") or 0)
        validated += int(metric.get("validated_count") or 0)
        blocked += int(metric.get("blocked_count") or 0)
        for skill_id in set(skill_ids):
            row = by_skill.setdefault(skill_id, {"items": 0, "planned": 0, "executed": 0, "evidence_complete": 0, "validated": 0, "blocked": 0})
            row["items"] += 1
            row["planned"] += len(plan)
            row["executed"] += int(metric.get("executed_count") or 0)
            row["evidence_complete"] += int(metric.get("evidence_complete_count") or 0)
            row["validated"] += int(metric.get("validated_count") or 0)
            row["blocked"] += int(metric.get("blocked_count") or 0)
    return {
        "consulted": consultations,
        "selected": selected,
        "materialized_items": materialized,
        "generic_only_items": generic_only,
        "activities_planned": planned,
        "activities_executed": executed,
        "activities_with_evidence": evidence_complete,
        "activities_validated": validated,
        "activities_blocked": blocked,
        "materialization_ratio": materialized / max(1, selected),
        "execution_ratio": executed / max(1, planned),
        "evidence_ratio": evidence_complete / max(1, planned),
        "validation_ratio": validated / max(1, planned),
        "by_skill": by_skill,
    }


def materialize_existing_skill_activity_plans(db: Any, job: Any) -> dict[str, int]:
    from app.models.models import AgentTraceEvent, ScanWorkItem

    items = db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == int(job.id)).all()
    catalog_by_id: dict[str, dict[str, Any]] = {}
    try:
        from app.services.api_skill_top20_runner import load_api_top20_skills

        catalog_by_id = {
            str(item.get("id")): dict(item)
            for item in list(load_api_top20_skills().get("skills") or [])
            if isinstance(item, dict) and str(item.get("id") or "")
        }
    except Exception:
        catalog_by_id = {}
    created = 0
    refreshed = 0
    for item in items:
        metadata = dict(item.item_metadata or {})
        skill_id = str(metadata.get("api_skill_id") or metadata.get("skill_id") or "").strip()
        if not skill_id:
            continue
        if metadata.get("skill_activity_plan"):
            execution = materialize_skill_execution(metadata, dict(item.result or {}))
            if execution != dict(metadata.get("skill_activity_execution") or {}):
                metadata["skill_activity_execution"] = execution
                item.item_metadata = metadata
                result = dict(item.result or {})
                if result:
                    result["skill_activity_execution"] = execution
                    item.result = result
                db.add(item)
                refreshed += 1
            continue
        skill = catalog_by_id.get(skill_id) or {
            "id": skill_id,
            "name": skill_id,
            "objective": f"Executar objetivo {skill_id}",
            "evidence_required": list(metadata.get("expected_evidence") or []),
        }
        plan = build_skill_activity_plan(
            skill,
            phase_id=str(item.phase_id or ""),
            target=str(metadata.get("execution_target") or item.target or ""),
        )
        if not plan:
            continue
        metadata["skill_activity_plan"] = plan
        metadata["skill_activity_contract"] = {
            "version": "surface-to-evidence-v1",
            "skill_id": skill_id,
            "phase_id": str(item.phase_id or ""),
            "surface_target": str(metadata.get("execution_target") or item.target or ""),
            "activity_ids": [str(row.get("activity_id")) for row in plan],
            "required_evidence": list(skill.get("evidence_required") or []),
            "validator": str(skill.get("validator") or "independent-evidence-validator"),
        }
        execution = materialize_skill_execution(metadata, dict(item.result or {}))
        metadata["skill_activity_execution"] = execution
        item.item_metadata = metadata
        result = dict(item.result or {})
        if result:
            result["skill_activity_execution"] = execution
            item.result = result
            refreshed += 1
        db.add(item)
        db.add(AgentTraceEvent(
            scan_id=int(job.id),
            event_type="skill_activity_materialized",
            from_node="quality_gate",
            to_node="executor",
            skill_id=skill_id[:120],
            tool_name=str(item.tool_name or "")[:100],
            capability=str(item.phase_id or "")[:100],
            status="backfilled",
            payload={
                "work_item_id": int(item.id),
                "activity_count": len(plan),
                "activity_ids": [str(row.get("activity_id")) for row in plan],
                "source": "quality_gate_backfill",
            },
        ))
        created += 1
    if created:
        db.flush()
    return {"items_materialized": created, "completed_items_refreshed": refreshed}


def requeue_incomplete_skill_activity_items(db: Any, job: Any, *, limit: int = 100) -> int:
    from datetime import datetime
    from app.models.models import ScanWorkItem

    items = (
        db.query(ScanWorkItem)
        .filter(ScanWorkItem.scan_job_id == int(job.id))
        .filter(ScanWorkItem.status.in_(["completed", "done", "failed", "timeout"]))
        .order_by(ScanWorkItem.priority.asc(), ScanWorkItem.id.asc())
        .limit(max(1, int(limit)))
        .all()
    )
    requeued = 0
    for item in items:
        metadata = dict(item.item_metadata or {})
        plan = list(metadata.get("skill_activity_plan") or [])
        metric = dict(metadata.get("skill_activity_execution") or {})
        if not plan or int(metric.get("blocked_count") or 0) > 0:
            continue
        if int(metric.get("executed_count") or 0) >= len(plan):
            continue
        retries = int(metadata.get("skill_activity_retries") or 0)
        if retries >= 1:
            continue
        metadata["skill_activity_retries"] = retries + 1
        metadata["skill_activity_retry_reason"] = "activity_execution_incomplete"
        item.item_metadata = metadata
        item.status = "queued"
        item.attempts = 0
        item.finished_at = None
        item.lease_until = None
        item.last_error = None
        item.updated_at = datetime.now()
        db.add(item)
        requeued += 1
    if requeued:
        db.flush()
    return requeued


def reconcile_completed_skill_activity_requeues(db: Any, job: Any) -> int:
    from datetime import datetime
    from app.models.models import ScanWorkItem

    items = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == int(job.id),
            ScanWorkItem.status == "queued",
        )
        .all()
    )
    reconciled = 0
    for item in items:
        metadata = dict(item.item_metadata or {})
        if metadata.get("skill_activity_retry_reason") != "activity_execution_incomplete":
            continue
        plan = list(metadata.get("skill_activity_plan") or [])
        result = dict(item.result or {})
        if not plan or str(result.get("status") or "").lower() not in TERMINAL_STATUSES:
            continue
        execution = materialize_skill_execution(metadata, result)
        if int(execution.get("executed_count") or 0) < len(plan):
            continue
        metadata["skill_activity_execution"] = execution
        metadata["skill_activity_retry_reconciled_at"] = datetime.now().isoformat()
        item.item_metadata = metadata
        result["skill_activity_execution"] = execution
        item.result = result
        item.status = "completed"
        item.finished_at = item.finished_at or datetime.now()
        item.lease_until = None
        item.last_error = None
        item.updated_at = datetime.now()
        db.add(item)
        reconciled += 1
    if reconciled:
        db.flush()
    return reconciled
