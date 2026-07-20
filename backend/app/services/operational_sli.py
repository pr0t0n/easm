from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import EASMAlert, ScanJob


QUEUE_WAIT_P95_MAX_SECONDS = float(os.getenv("SLI_QUEUE_WAIT_P95_MAX_SECONDS", "300"))
SUCCESS_RATE_MIN_PERCENT = float(os.getenv("SLI_SUCCESS_RATE_MIN_PERCENT", "75"))
QUALITY_SCORE_MIN = float(os.getenv("SLI_QUALITY_SCORE_MIN", "70"))


def evaluate_scan_slis(quality: dict[str, Any]) -> dict[str, Any]:
    execution = dict(quality.get("execution_metrics") or {})
    checks = [
        {
            "id": "queue_wait_p95",
            "value": float(execution.get("queue_wait_p95_seconds") or 0),
            "threshold": QUEUE_WAIT_P95_MAX_SECONDS,
            "passed": float(execution.get("queue_wait_p95_seconds") or 0) <= QUEUE_WAIT_P95_MAX_SECONDS,
            "operator": "lte",
        },
        {
            "id": "execution_success",
            "value": float(execution.get("success_pct") or 0),
            "threshold": SUCCESS_RATE_MIN_PERCENT,
            "passed": float(execution.get("success_pct") or 0) >= SUCCESS_RATE_MIN_PERCENT,
            "operator": "gte",
        },
        {
            "id": "quality_score",
            "value": float(quality.get("score") or 0),
            "threshold": QUALITY_SCORE_MIN,
            "passed": float(quality.get("score") or 0) >= QUALITY_SCORE_MIN,
            "operator": "gte",
        },
    ]
    return {
        "status": "healthy" if all(check["passed"] for check in checks) else "degraded",
        "checks": checks,
        "failed": [check for check in checks if not check["passed"]],
        "evaluated_at": datetime.now().isoformat(),
    }


def persist_scan_sli_alerts(db: Session, job: ScanJob, quality: dict[str, Any]) -> dict[str, Any]:
    evaluation = evaluate_scan_slis(quality)
    state = dict(job.state_data or {})
    state["operational_sli"] = evaluation
    if isinstance(state.get("quality_snapshot"), dict):
        snapshot = dict(state["quality_snapshot"])
        snapshot["operational_sli"] = evaluation
        state["quality_snapshot"] = snapshot
    job.state_data = state
    db.add(job)
    existing = (
        db.query(EASMAlert)
        .filter(EASMAlert.owner_id == job.owner_id, EASMAlert.is_resolved.is_(False))
        .all()
    )
    existing_keys = {
        (str(row.alert_type or ""), int((row.webhook_payload or {}).get("scan_id") or 0)): row
        for row in existing
    }
    failed_ids = {str(check["id"]) for check in evaluation["failed"]}
    created = 0
    resolved = 0
    for check in evaluation["checks"]:
        alert_type = f"scan_sli_{check['id']}"
        key = (alert_type, int(job.id))
        current = existing_keys.get(key)
        if check["passed"]:
            if current:
                current.is_resolved = True
                current.resolved_at = datetime.now()
                current.resolved_notes = "SLI returned within threshold"
                db.add(current)
                resolved += 1
            continue
        if current:
            current.trigger_value = check["value"]
            current.threshold_value = check["threshold"]
            current.description = f"Scan #{job.id}: {check['id']}={check['value']} threshold={check['threshold']}"
            db.add(current)
            continue
        db.add(EASMAlert(
            owner_id=job.owner_id,
            alert_type=alert_type,
            severity="high" if check["id"] == "quality_score" else "medium",
            title=f"SLI degradado no scan #{job.id}: {check['id']}",
            description=f"Valor {check['value']} fora do limite {check['threshold']} ({check['operator']}).",
            trigger_value=check["value"],
            threshold_value=check["threshold"],
            webhook_payload={"scan_id": job.id, "target": job.target_query, "sli": check},
        ))
        created += 1
    return {**evaluation, "alerts_created": created, "alerts_resolved": resolved, "failed_ids": sorted(failed_ids)}
