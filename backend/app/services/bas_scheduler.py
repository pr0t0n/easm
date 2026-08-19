"""BAS schedule firing + periodic tick (celery beat), mirroring
workers/tasks.py::scheduler_tick()'s ScheduledScan -> ScanJob shape, but for
BasSchedule -> BasJob (dispatched through bas_dispatcher, never through the
generic ScanWorkItem/execute_scan_work_item queue)."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import BasAgent, BasJob, BasSchedule, Finding, ScanJob
from app.services.bas_dispatcher import dispatch_bas_technique
from app.services.bas_guardrail_policy import check_bas_authorization
from app.services.bas_technique_catalog import get_technique

logger = logging.getLogger(__name__)


def _create_shadow_scan_job(db: Session, schedule: BasSchedule) -> ScanJob:
    # target_query must be the REAL target_hint, not a synthetic label --
    # kali_runner requires a non-empty authorized_scope on every dispatch
    # (SEC-001), and resolve_authorized_scope_for_dispatch derives that scope
    # from this ScanJob's target_query via authorized_scope_from_target_query.
    # A label like "bas:schedule#1" parses to no valid root at all, so every
    # dispatch through this shadow job would fail closed with 400.
    target_query = schedule.target_hint or f"bas-unset-target-schedule-{schedule.id}"
    shadow = ScanJob(
        owner_id=schedule.owner_id,
        access_group_id=schedule.access_group_id,
        target_query=target_query,
        mode="bas",
        status="running",
    )
    db.add(shadow)
    db.flush()
    return shadow


def _finding_from_job_result(
    db: Session, job: BasJob, schedule: BasSchedule, technique: dict[str, Any], agent: BasAgent,
) -> Finding | None:
    """`simulated` (and everything that follows from it -- score/attack-path
    counting, bas_exclusion.py's aggregation filter, the UI's "SIMULADO"
    badge) is keyed off `agent.kind`, never a blanket constant: a stub-kind
    agent (bas_agent_stub) always fabricates its tunnel's response content,
    but a real-kind agent (cryptographically proven via its CA-signed mTLS
    cert -- see bas_ca.py) actually relayed to a real destination, so its
    result is real and counts like any other Finding."""
    result = job.result or {}
    is_stub = agent.kind != "real"
    finding = Finding(
        scan_job_id=job.scan_job_id,
        title=f"BAS: {technique['display_name']}" + (" (simulado)" if is_stub else ""),
        severity="info",
        tool="bas-agent",
        verification_status="hypothesis",
        confidence_score=min(20, 20),
        details={
            "source_module": "bas",
            "simulated": is_stub,
            "counts_towards_score": not is_stub,
            "counts_towards_attack_path": not is_stub,
            "bas_job_id": job.id,
            "bas_schedule_id": schedule.id,
            "bas_agent_id": agent.id,
            "bas_agent_kind": agent.kind,
            "technique_key": technique["technique_key"],
            "category": technique["category"],
            "mode": technique["mode"],
            "risk_tier": technique["risk_tier"],
            "phase": "phase_1_stub" if is_stub else "real_agent",
            "command": result.get("command"),
            "status": result.get("status"),
        },
    )
    db.add(finding)
    db.flush()
    return finding


def fire_schedule(db: Session, schedule: BasSchedule) -> dict[str, Any]:
    """Runs every technique in a schedule right now: creates a shadow
    ScanJob, dispatches each authorized technique through bas_dispatcher,
    persists the (stub) result as a Finding, and updates last_run_at."""
    agent = db.query(BasAgent).filter(BasAgent.id == schedule.agent_id).first()
    if not agent:
        return {"error": "agent_not_found"}

    shadow = _create_shadow_scan_job(db, schedule)
    # Commit (not just flush) before any dispatch: resolve_authorized_scope_
    # for_dispatch opens its OWN SessionLocal() to read this ScanJob by id --
    # a separate connection can't see a row this transaction has only
    # flushed, so every dispatch would fail closed with "authorized_scope is
    # required" until this row is actually committed.
    db.commit()
    job_ids: list[int] = []
    skipped: list[dict[str, str]] = []

    for technique_key in schedule.technique_keys:
        technique = get_technique(technique_key)
        if technique is None:
            skipped.append({"technique_key": technique_key, "reason": "unknown_technique"})
            continue
        decision = check_bas_authorization(schedule, technique_key)
        if not decision["allowed"]:
            skipped.append({"technique_key": technique_key, "reason": decision["reason"]})
            logger.info("bas_scheduler: skipped technique=%s reason=%s schedule=%s", technique_key, decision["reason"], schedule.id)
            continue

        job = BasJob(
            schedule_id=schedule.id,
            agent_id=agent.id,
            owner_id=schedule.owner_id,
            access_group_id=schedule.access_group_id,
            scan_job_id=shadow.id,
            technique_key=technique_key,
            risk_tier=technique["risk_tier"],
            status="dispatched_to_kali",
            dispatched_at=datetime.now(),
        )
        db.add(job)
        db.flush()

        outcome = dispatch_bas_technique(
            technique_key=technique_key,
            target_hint=schedule.target_hint or agent.hostname or "internal-target",
            bas_agent=agent,
            scan_id=shadow.id,
            schedule=schedule,
        )
        if not outcome["dispatched"]:
            job.status = "skipped"
            job.last_error = outcome["reason"]
            job.finished_at = datetime.now()
            db.commit()
            skipped.append({"technique_key": technique_key, "reason": outcome["reason"]})
            continue

        result = outcome["result"]
        job.kali_job_id = str(result.get("dispatch_task_id") or "")
        job.result = result
        job.status = "completed" if result.get("status") == "executed" else "failed"
        job.finished_at = datetime.now()
        db.flush()

        finding = _finding_from_job_result(db, job, schedule, technique, agent)
        if finding:
            job.finding_id = finding.id
        job_ids.append(job.id)
        db.commit()

    shadow.status = "completed"
    schedule.last_run_at = datetime.now()
    db.commit()

    return {"scan_job_id": shadow.id, "job_ids": job_ids, "skipped": skipped}


_FREQUENCY_MINUTES = {
    "every_3_hours": 180,
    "every_6_hours": 360,
    "every_12_hours": 720,
}


def _is_due(schedule: BasSchedule, now: datetime) -> bool:
    if schedule.frequency in _FREQUENCY_MINUTES:
        if not schedule.last_run_at:
            return True
        return now >= schedule.last_run_at + timedelta(minutes=_FREQUENCY_MINUTES[schedule.frequency])

    try:
        run_hour, run_minute = (int(part) for part in str(schedule.run_time or "00:00").split(":", 1))
    except ValueError:
        run_hour, run_minute = 0, 0
    if now.hour != run_hour or now.minute != run_minute:
        return False
    if schedule.last_run_at and schedule.last_run_at.date() == now.date():
        return False  # already fired this slot today

    if schedule.frequency == "daily":
        return True
    if schedule.frequency == "weekly":
        return str(schedule.day_of_week or "").lower() == now.strftime("%A").lower()
    if schedule.frequency == "monthly":
        return schedule.day_of_month == now.day
    return False


def bas_scheduler_tick(db: Session) -> dict[str, Any]:
    """Celery-beat entry point (registered as task "bas_scheduler.tick" in
    workers/tasks.py). Mirrors scheduler_tick()'s due-check/idempotency
    logic 1:1 against BasSchedule instead of ScheduledScan."""
    now = datetime.now()
    fired = 0
    for schedule in db.query(BasSchedule).filter(BasSchedule.enabled.is_(True)).all():
        if not _is_due(schedule, now):
            continue
        fire_schedule(db, schedule)
        fired += 1
    return {"ok": True, "fired": fired, "checked_at": now.isoformat()}


_HEARTBEAT_STALE_MINUTES = 5
_JOB_STUCK_MINUTES = 15


def bas_watchdog_tick(db: Session) -> dict[str, Any]:
    """Mirrors the existing kali watchdog's recovery pattern: mark stale
    agents offline, and fail BasJob rows stuck past a reasonable timeout
    instead of leaving them silently hung forever."""
    now = datetime.now()
    stale_cutoff = now - timedelta(minutes=_HEARTBEAT_STALE_MINUTES)
    marked_offline = (
        db.query(BasAgent)
        .filter(BasAgent.status == "online", BasAgent.last_heartbeat_at < stale_cutoff)
        .update({"status": "offline"}, synchronize_session=False)
    )

    stuck_cutoff = now - timedelta(minutes=_JOB_STUCK_MINUTES)
    stuck_jobs = (
        db.query(BasJob)
        .filter(BasJob.status.in_(["queued", "dispatched_to_kali", "running"]), BasJob.created_at < stuck_cutoff)
        .all()
    )
    for job in stuck_jobs:
        job.status = "failed"
        job.last_error = "tunnel_timeout"
        job.finished_at = now
    db.commit()

    return {"ok": True, "agents_marked_offline": marked_offline, "jobs_failed": len(stuck_jobs)}
