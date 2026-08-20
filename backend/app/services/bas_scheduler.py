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


def _extract_key_findings(technique_key: str, category: str, result: dict[str, Any]) -> list[str]:
    """Pulls the actually meaningful lines out of a real tool's raw stdout
    instead of leaving the report to show just a title/status -- this is
    what "mostrar as vulnerabilidades" needs: what the tool actually
    observed, not that it merely ran. Deliberately conservative/best-effort
    per output shape; falls back to a short, honest "no signal" message
    rather than guessing when a tool's output doesn't match any known
    pattern here."""
    stdout = str(result.get("stdout") or "")
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    if not lines:
        return []

    if technique_key == "owasp_web_app_scan":
        return [ln for ln in lines if ln.startswith("+ [")][:15]
    if technique_key in ("port_service_scan", "firewall_segmentation_test", "network_share_discovery"):
        return [ln for ln in lines if "open" in ln.lower() and ("/tcp" in ln or "share" in ln.lower())][:15]
    if technique_key in ("pipeline_secrets_harvesting", "source_code_secrets_scan"):
        hits = [ln for ln in lines if not ln.upper().startswith("EXIT_CODE") and "no leaks found" not in ln.lower()]
        return hits[:15]
    if technique_key == "netlogon_zerologon_check":
        return [ln for ln in lines if "vulnerable" in ln.lower()][:5]
    # Generic fallback: last few non-boilerplate lines, so the report never
    # shows literally nothing for a technique with no dedicated extractor.
    return [ln for ln in lines if not ln.upper().startswith("EXIT_CODE")][-5:]


def _derive_severity(technique_key: str, key_findings: list[str]) -> str:
    """Real content in, real severity out -- never a blanket "info" once
    there's an actual positive signal in what the tool observed. Stays
    "info" (no issue found / nothing to escalate) when key_findings is
    empty or the technique has no severity-worthy signal defined here."""
    if not key_findings:
        return "info"
    if technique_key == "netlogon_zerologon_check":
        return "critical"  # a real, unauthenticated domain-controller takeover primitive
    if technique_key in ("pipeline_secrets_harvesting", "source_code_secrets_scan"):
        return "high"  # a real exposed credential/token
    if technique_key == "owasp_web_app_scan":
        return "medium"  # real misconfiguration-class findings (headers, CORS, etc.)
    if technique_key in ("port_service_scan", "firewall_segmentation_test", "network_share_discovery"):
        return "low"  # real reachability/exposure, not itself a vulnerability
    return "info"


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
    # Real content in, real severity/findings out -- a stub dispatch never
    # had real content to begin with, so it never gets to claim a real
    # vulnerability was observed regardless of what its canned text says.
    key_findings = [] if is_stub else _extract_key_findings(technique["technique_key"], technique["category"], result)
    severity = "info" if is_stub else _derive_severity(technique["technique_key"], key_findings)
    finding = Finding(
        scan_job_id=job.scan_job_id,
        title=f"BAS: {technique['display_name']}" + (" (simulado)" if is_stub else ""),
        severity=severity,
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
            "mitre_refs": technique.get("mitre_refs", []),
            "recommendation": technique.get("recommendation", ""),
            "key_findings": key_findings,
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

        if schedule.stop_on_failure and job.status == "failed":
            remaining = schedule.technique_keys[schedule.technique_keys.index(technique_key) + 1:]
            for remaining_key in remaining:
                skipped.append({"technique_key": remaining_key, "reason": "chain_stopped_after_failure"})
            logger.info(
                "bas_scheduler: chain stopped after technique=%s failed, skipping %d remaining step(s) schedule=%s",
                technique_key, len(remaining), schedule.id,
            )
            break

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
