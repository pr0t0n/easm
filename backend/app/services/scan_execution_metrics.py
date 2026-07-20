from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable

from app.models.models import ExecutedToolRun, ScanJob, ScanWorkItem


SUCCESS_STATUSES = {"completed", "done"}
FAILURE_STATUSES = {"failed", "timeout"}
SKIPPED_STATUSES = {"skipped"}
ACTIVE_STATUSES = {"dispatched", "running", "submitted"}
QUEUED_STATUSES = {"queued", "retry"}
BLOCKED_STATUSES = {"blocked"}
TERMINAL_STATUSES = SUCCESS_STATUSES | FAILURE_STATUSES | SKIPPED_STATUSES
ATTEMPTED_STATUSES = TERMINAL_STATUSES | ACTIVE_STATUSES


def _pct(value: int | float, total: int | float) -> float:
    return round((float(value) / max(1.0, float(total))) * 100.0, 1)


def _duration_seconds(item: ScanWorkItem) -> float:
    started = getattr(item, "started_at", None)
    finished = getattr(item, "finished_at", None)
    if not started or not finished:
        return 0.0
    return max(0.0, (finished - started).total_seconds())


def _queue_ready_at(item: ScanWorkItem) -> datetime | None:
    raw = dict(getattr(item, "item_metadata", None) or {}).get("queue_ready_at")
    if raw:
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).replace(tzinfo=None)
        except (TypeError, ValueError):
            pass
    return getattr(item, "created_at", None)


def summarize_work_items(items: Iterable[ScanWorkItem], job: ScanJob | None = None) -> dict[str, Any]:
    """Canonical execution accounting used by API, quality and reports.

    A work item is the scheduling unit. Tool ledgers remain useful evidence, but
    must not be mixed into the denominator because batch runs and retries make
    those ledgers non-equivalent.
    """
    rows = list(items)
    statuses = Counter(str(getattr(row, "status", "") or "unknown").lower() for row in rows)
    total = len(rows)
    succeeded = sum(statuses[s] for s in SUCCESS_STATUSES)
    failed = sum(statuses[s] for s in FAILURE_STATUSES)
    skipped = sum(statuses[s] for s in SKIPPED_STATUSES)
    active = sum(statuses[s] for s in ACTIVE_STATUSES)
    queued = sum(statuses[s] for s in QUEUED_STATUSES)
    blocked = sum(statuses[s] for s in BLOCKED_STATUSES)
    terminal = succeeded + failed + skipped
    attempted = terminal + active
    worker_seconds = sum(_duration_seconds(row) for row in rows)
    queue_waits = sorted(
        max(0.0, (row.started_at - ready_at).total_seconds())
        for row in rows
        if getattr(row, "started_at", None) and (ready_at := _queue_ready_at(row))
    )

    created = [getattr(row, "created_at", None) for row in rows if getattr(row, "created_at", None)]
    finished = [getattr(row, "finished_at", None) for row in rows if getattr(row, "finished_at", None)]
    start = min(created) if created else getattr(job, "created_at", None)
    end = max(finished) if finished else (getattr(job, "updated_at", None) if job else None)
    wall_seconds = max(0.0, (end - start).total_seconds()) if start and end else 0.0
    throughput_per_minute = (terminal / wall_seconds) * 60.0 if wall_seconds else 0.0
    remaining = max(0, total - terminal)
    eta_seconds = (remaining / throughput_per_minute) * 60.0 if throughput_per_minute else None

    dimensions: dict[str, dict[str, Counter[str]]] = {
        "phases": defaultdict(Counter),
        "tools": defaultdict(Counter),
        "resource_classes": defaultdict(Counter),
    }
    for row in rows:
        status = str(getattr(row, "status", "") or "unknown").lower()
        dimensions["phases"][str(getattr(row, "phase_id", "") or "unknown")][status] += 1
        dimensions["tools"][str(getattr(row, "tool_name", "") or "unknown")][status] += 1
        dimensions["resource_classes"][str(getattr(row, "resource_class", "") or "unknown")][status] += 1

    def dimension_rows(values: dict[str, Counter[str]]) -> list[dict[str, Any]]:
        result = []
        for name, counts in values.items():
            dim_total = sum(counts.values())
            dim_success = sum(counts[s] for s in SUCCESS_STATUSES)
            dim_failed = sum(counts[s] for s in FAILURE_STATUSES)
            dim_skipped = sum(counts[s] for s in SKIPPED_STATUSES)
            result.append({
                "name": name,
                "total": dim_total,
                "succeeded": dim_success,
                "failed": dim_failed,
                "skipped": dim_skipped,
                "success_pct": _pct(dim_success, dim_total),
                "statuses": dict(counts),
            })
        return sorted(result, key=lambda row: (-int(row["total"]), str(row["name"])))

    return {
        "source": "scan_work_items",
        "total": total,
        "attempted": attempted,
        "terminal": terminal,
        "succeeded": succeeded,
        "failed": failed,
        "skipped": skipped,
        "active": active,
        "queued": queued,
        "blocked": blocked,
        "progress_pct": _pct(terminal, total),
        "success_pct": _pct(succeeded, attempted),
        "failure_pct": _pct(failed, attempted),
        "skip_pct": _pct(skipped, attempted),
        "worker_seconds": round(worker_seconds, 1),
        "wall_seconds": round(wall_seconds, 1),
        "average_parallelism": round(worker_seconds / wall_seconds, 2) if wall_seconds else 0.0,
        "throughput_per_minute": round(throughput_per_minute, 2),
        "queue_wait_avg_seconds": round(sum(queue_waits) / len(queue_waits), 1) if queue_waits else 0.0,
        "queue_wait_p95_seconds": round(queue_waits[min(len(queue_waits) - 1, int(len(queue_waits) * 0.95))], 1) if queue_waits else 0.0,
        "queue_wait_semantics": "actionable_ready_to_started",
        "eta_seconds": round(eta_seconds, 1) if eta_seconds is not None else None,
        "distinct_targets": len({str(getattr(row, "target", "") or "") for row in rows}),
        "distinct_tools": len({str(getattr(row, "tool_name", "") or "") for row in rows}),
        "distinct_phases": len({str(getattr(row, "phase_id", "") or "") for row in rows}),
        "statuses": dict(statuses),
        "by_phase": dimension_rows(dimensions["phases"]),
        "by_tool": dimension_rows(dimensions["tools"]),
        "by_resource_class": dimension_rows(dimensions["resource_classes"]),
        "generated_at": datetime.now().isoformat(),
    }


def build_scan_execution_metrics(db: Any, job: ScanJob) -> dict[str, Any]:
    items = db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == job.id).all()
    return summarize_work_items(items, job)


def reconcile_tool_run_ledger(db: Any, job: ScanJob) -> dict[str, int]:
    """Close stale submitted tool ledgers from their canonical work item."""
    items = db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == job.id).all()
    index: dict[tuple[str, str, str], ScanWorkItem] = {}
    for item in items:
        phase = str(item.phase_id or "")
        tool = str(item.tool_name or "")
        index[(phase, tool, str(item.target or ""))] = item
        if str(item.target or "") == "__batch__":
            for target in list((item.item_metadata or {}).get("batch_targets") or []):
                index[(phase, tool, str(target))] = item

    runs = (
        db.query(ExecutedToolRun)
        .filter(ExecutedToolRun.scan_job_id == job.id, ExecutedToolRun.status.in_(["submitted", "running"]))
        .all()
    )
    updated = 0
    unmatched = 0
    status_map = {
        "completed": "success",
        "done": "success",
        "failed": "failed",
        "timeout": "timeout",
        "skipped": "skipped",
    }
    for run in runs:
        item = index.get((str(run.phase_id or ""), str(run.tool_name or ""), str(run.target or "")))
        mapped = status_map.get(str(getattr(item, "status", "") or "").lower()) if item else None
        if not mapped:
            unmatched += 1
            continue
        run.status = mapped
        run.error_message = getattr(item, "last_error", None)
        run.execution_time_seconds = _duration_seconds(item)
        db.add(run)
        updated += 1
    return {"updated": updated, "unmatched": unmatched, "stale_seen": len(runs)}
