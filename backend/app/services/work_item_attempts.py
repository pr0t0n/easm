from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import ScanWorkItem, WorkItemAttempt


ACTIVE_ATTEMPT_STATES = {"execution_started", "mcp_accepted", "runner_started"}
TERMINAL_ATTEMPT_STATES = {"completed", "failed", "timeout", "skipped", "cancelled"}


def latest_attempt(db: Session, work_item_id: int) -> WorkItemAttempt | None:
    query = db.query(WorkItemAttempt).filter(WorkItemAttempt.work_item_id == int(work_item_id))
    if hasattr(query, "order_by"):
        query = query.order_by(WorkItemAttempt.id.desc())
    attempt = query.first()
    return attempt if attempt is not None and hasattr(attempt, "attempt_key") else None


def start_attempt(db: Session, item: ScanWorkItem, worker_id: str | None = None) -> WorkItemAttempt:
    active = latest_attempt(db, item.id)
    if active is not None and active.state in ACTIVE_ATTEMPT_STATES:
        return active
    item.attempts = int(item.attempts or 0) + 1
    attempt = WorkItemAttempt(
        work_item_id=item.id,
        attempt_key=f"wi-{item.id}-{item.attempts}-{uuid.uuid4().hex[:12]}",
        state="execution_started",
        worker_id=str(worker_id or "")[:120] or None,
        state_history=[{"state": "execution_started", "at": datetime.now().isoformat()}],
        heartbeat_at=datetime.now(),
        started_at=datetime.now(),
    )
    db.add(attempt)
    db.flush()
    return attempt


def transition_attempt(
    db: Session,
    item: ScanWorkItem,
    state: str,
    *,
    mcp_request_id: Any = None,
    runner_job_id: Any = None,
    error_class: str | None = None,
) -> WorkItemAttempt | None:
    attempt = latest_attempt(db, item.id)
    if attempt is None:
        attempt = WorkItemAttempt(
            work_item_id=item.id,
            attempt_key=f"wi-{item.id}-adopted-{uuid.uuid4().hex[:12]}",
            state="execution_started",
            state_history=[{"state": "execution_started", "at": (getattr(item, "started_at", None) or datetime.now()).isoformat(), "adopted": True}],
            heartbeat_at=datetime.now(),
            started_at=getattr(item, "started_at", None) or datetime.now(),
        )
        db.add(attempt)
    next_state = str(state)[:40]
    history = [row for row in list(attempt.state_history or []) if isinstance(row, dict)]
    if attempt.state != next_state or (error_class and attempt.error_class != str(error_class)[:80]):
        history.append({"state": next_state, "at": datetime.now().isoformat(), "error_class": str(error_class or "")[:80] or None})
    attempt.state = next_state
    attempt.state_history = history[-100:]
    attempt.heartbeat_at = datetime.now()
    if mcp_request_id:
        attempt.mcp_request_id = str(mcp_request_id)[:160]
    if runner_job_id:
        attempt.runner_job_id = str(runner_job_id)[:160]
    attempt.error_class = str(error_class or "")[:80] or None
    if state in TERMINAL_ATTEMPT_STATES:
        attempt.finished_at = datetime.now()
    db.add(attempt)
    return attempt


def execution_was_confirmed(db: Session, item: ScanWorkItem) -> bool:
    attempt = latest_attempt(db, item.id)
    return bool(attempt and attempt.started_at and attempt.state != "claimed")


def attempt_summary(db: Session, item: ScanWorkItem) -> dict[str, Any]:
    attempt = latest_attempt(db, item.id)
    if attempt is None:
        return {"confirmed": False, "state": "missing"}
    return {
        "attempt_id": attempt.id,
        "attempt_key": attempt.attempt_key,
        "confirmed": execution_was_confirmed(db, item),
        "state": attempt.state,
        "mcp_request_id": attempt.mcp_request_id,
        "runner_job_id": attempt.runner_job_id,
        "error_class": attempt.error_class,
        "heartbeat_at": attempt.heartbeat_at.isoformat() if attempt.heartbeat_at else None,
        "state_history": list(attempt.state_history or []),
    }


def reconcile_terminal_attempt_states(db: Session, scan_id: int) -> int:
    items = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == int(scan_id),
            ScanWorkItem.status.in_(["completed", "done", "failed", "timeout", "skipped", "cancelled", "canceled"]),
        )
        .all()
    )
    reconciled = 0
    for item in items:
        attempt = latest_attempt(db, item.id)
        if attempt is None or attempt.state not in ACTIVE_ATTEMPT_STATES:
            continue
        status = str(item.status or "").lower()
        terminal_state = {
            "completed": "completed",
            "done": "completed",
            "failed": "failed",
            "timeout": "timeout",
            "skipped": "skipped",
            "cancelled": "cancelled",
            "canceled": "cancelled",
        }[status]
        result = dict(item.result or {})
        transition_attempt(
            db,
            item,
            terminal_state,
            mcp_request_id=result.get("mcp_request_id"),
            runner_job_id=result.get("kali_job_id") or result.get("dispatch_task_id"),
            error_class=str(item.last_error or "")[:80] or None,
        )
        reconciled += 1
    return reconciled


def reconcile_expired_item(db: Session, item: ScanWorkItem, now: datetime) -> str:
    attempt = latest_attempt(db, item.id)
    result = dict(getattr(item, "result", None) or {})
    durable_runner_id = result.get("kali_job_id") or result.get("dispatch_task_id")
    if item.status == "submitted" and durable_runner_id:
        transition_attempt(
            db,
            item,
            "runner_started",
            mcp_request_id=result.get("mcp_request_id"),
            runner_job_id=durable_runner_id,
        )
        item.last_error = "runner_status_reconciliation_required"
        item.updated_at = now
        return "poll"
    confirmed = bool(attempt and attempt.started_at and attempt.state != "claimed")
    if item.status == "submitted" and attempt and attempt.state in {"mcp_accepted", "runner_started"}:
        item.last_error = "runner_status_reconciliation_required"
        item.updated_at = now
        return "poll"
    if not confirmed:
        item.attempts = 0
        item.status = "queued"
        item.lease_until = None
        item.finished_at = None
        item.last_error = "dispatch_not_acknowledged_requeued"
        item.updated_at = now
        return "requeued_unconfirmed"
    transition_attempt(db, item, "failed", error_class="lease_expired_without_terminal_ack")
    item.status = "retry" if int(item.attempts or 0) < int(item.max_attempts or 1) else "blocked"
    item.lease_until = None
    item.finished_at = None if item.status == "retry" else now
    item.last_error = "execution_interrupted_retry" if item.status == "retry" else "supervisor_review_required:execution_interrupted"
    item.updated_at = now
    return item.status


def adopt_authoritative_runner_state(db: Session, job: Any, item: ScanWorkItem, payload: dict[str, Any], now: datetime | None = None) -> bool:
    observed_at = now or datetime.now()
    result = dict(item.result or {})
    durable_runner_id = str(result.get("kali_job_id") or result.get("dispatch_task_id") or "")
    payload_runner_id = str(payload.get("job_id") or payload.get("kali_job_id") or "")
    runner_status = str(payload.get("status") or "").lower()
    if not durable_runner_id or durable_runner_id != payload_runner_id:
        return False
    if runner_status not in {"queued", "running", "done", "failed", "timeout", "skipped"}:
        return False
    if item.status == "blocked" and not str(item.last_error or "").startswith("supervisor_broken_glass:"):
        return False
    transition_attempt(
        db,
        item,
        "runner_started",
        mcp_request_id=result.get("mcp_request_id"),
        runner_job_id=durable_runner_id,
    )
    timeout = max(60, int(payload.get("timeout") or result.get("timeout") or 300))
    item.status = "submitted"
    item.lease_until = observed_at + timedelta(seconds=max(600, timeout + 300))
    item.finished_at = None
    item.last_error = "runner_status_reconciliation_required"
    item.updated_at = observed_at
    state = dict(getattr(job, "state_data", None) or {})
    broken_glass = dict(state.get("broken_glass") or {})
    if str(getattr(job, "status", "")).lower() == "blocked" and broken_glass.get("status") == "required":
        broken_glass.update({"status": "recovered", "recovered_at": observed_at.isoformat(), "runner_job_id": durable_runner_id})
        state["broken_glass"] = broken_glass
        job.state_data = state
        job.status = "running"
        job.current_step = str(item.phase_id or "")
        job.last_error = None
        job.updated_at = observed_at
    return True
