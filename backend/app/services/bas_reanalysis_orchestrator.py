from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import BasJob, BasSchedule, ScanJob, ScanLog
from app.services.bas_technique_catalog import get_technique


_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "skipped"}


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _jobs_for_scan(db: Session, scan_id: int) -> list[BasJob]:
    try:
        return list(
            db.query(BasJob)
            .filter(BasJob.scan_job_id == int(scan_id))
            .order_by(BasJob.id.asc())
            .all()
            or []
        )
    except Exception:
        return []


def _expected_techniques(schedule: BasSchedule) -> list[str]:
    keys = ["port_service_scan"]
    for key in list(getattr(schedule, "technique_keys", None) or []):
        clean = str(key or "").strip()
        if clean and clean not in keys:
            keys.append(clean)
    return keys


def _technique_category(key: str) -> str:
    technique = get_technique(key)
    return str((technique or {}).get("category") or "unknown")


def _result_status(job: BasJob) -> str:
    result = dict(getattr(job, "result", None) or {})
    proof = dict(result.get("bas_proof") or {})
    status = str(
        result.get("bas_control_status")
        or result.get("control_status")
        or proof.get("status")
        or ""
    ).strip().lower()
    return status or str(getattr(job, "status", "") or "unknown").lower()


def run_bas_reanalysis(
    db: Session,
    schedule: BasSchedule,
    shadow: ScanJob,
    *,
    trigger: str,
    source_job_id: int | None = None,
    skipped: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    jobs = _jobs_for_scan(db, shadow.id)
    expected = _expected_techniques(schedule)
    status_counts = Counter(str(job.status or "unknown") for job in jobs)
    terminal_jobs = [job for job in jobs if str(job.status or "") in _TERMINAL_STATUSES]
    tested_techniques = sorted({str(job.technique_key or "") for job in terminal_jobs if str(job.technique_key or "")})
    expected_set = set(expected)
    missing = [key for key in expected if key not in set(tested_techniques)]
    failed = [
        {"job_id": _safe_int(job.id), "technique_key": str(job.technique_key or ""), "target": str(job.target or ""), "error": str(job.last_error or "")[:240]}
        for job in terminal_jobs
        if str(job.status or "") == "failed"
    ]
    skipped_rows = list(skipped or [])
    result_statuses = Counter(_result_status(job) for job in terminal_jobs)
    category_expected = Counter(_technique_category(key) for key in expected)
    category_tested = Counter(_technique_category(key) for key in tested_techniques)
    findings = [job for job in terminal_jobs if getattr(job, "finding_id", None)]
    coverage_percent = round(100 * len(set(tested_techniques) & expected_set) / max(1, len(expected_set)), 1)
    next_actions: list[dict[str, Any]] = []
    if missing:
        next_actions.append({"type": "dispatch_missing_techniques", "technique_keys": missing})
    if failed:
        next_actions.append({"type": "review_failed_jobs", "count": len(failed)})
    if skipped_rows:
        next_actions.append({"type": "review_skipped_targets", "count": len(skipped_rows)})
    if not next_actions:
        next_actions.append({"type": "ready_for_control_reporting"})

    event = {
        "trigger": str(trigger or "unknown")[:120],
        "source_job_id": source_job_id,
        "schedule_id": int(schedule.id),
        "agent_id": int(schedule.agent_id),
        "scan_job_id": int(shadow.id),
        "expected_techniques": expected,
        "tested_techniques": tested_techniques,
        "missing_techniques": missing,
        "coverage_percent": coverage_percent,
        "jobs": {
            "total": len(jobs),
            "terminal": len(terminal_jobs),
            "statuses": dict(status_counts),
            "failed": failed[:25],
            "skipped": skipped_rows[-25:],
        },
        "categories": {
            "expected": dict(category_expected),
            "tested": dict(category_tested),
        },
        "control_outcomes": dict(result_statuses),
        "findings": {
            "linked": len(findings),
            "job_ids": [_safe_int(job.id) for job in findings[-25:] if _safe_int(job.id) is not None],
        },
        "next_actions": next_actions,
        "created_at": datetime.now().isoformat(),
    }
    state = dict(getattr(shadow, "state_data", None) or {})
    events = list(state.get("bas_reanalysis_events") or [])
    events.append(event)
    state["bas_reanalysis_events"] = events[-50:]
    state["bas_reanalysis_latest"] = event
    shadow.state_data = state
    db.add(shadow)
    db.add(ScanLog(
        scan_job_id=shadow.id,
        source="bas-reanalysis",
        level="INFO",
        message=(
            f"bas_reanalysis trigger={event['trigger']} coverage={coverage_percent} "
            f"jobs={len(jobs)} terminal={len(terminal_jobs)} next={next_actions[:3]}"
        )[:2000],
    ))
    db.flush()
    return event
