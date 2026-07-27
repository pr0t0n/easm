#!/usr/bin/env python3
"""Persistent scan monitor.

This is intentionally outside the UI request/response cycle.  It records one
JSON snapshot per interval until the scan reaches a terminal status, so a long
scan cannot silently stop while a human/operator is away.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.session import SessionLocal
from app.models.models import Finding, ScanJob, ScanLog, ScanWorkItem
from app.services.scan_work_queue import work_queue_counts


TERMINAL = {"completed", "completed_with_gaps", "failed", "cancelled", "canceled", "stopped"}


def _age_seconds(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return max(0.0, (datetime.now() - value.replace(tzinfo=None)).total_seconds())
    except Exception:
        return None


def _kali_active(scan_id: int) -> tuple[int, list[dict[str, Any]]]:
    base = os.getenv("KALI_RUNNER_URL", "http://kali_runner:8088").rstrip("/")
    try:
        rows: list[dict[str, Any]] = []
        for status in ("running", "queued"):
            query = urllib.parse.urlencode({"status": status, "limit": 1000})
            with urllib.request.urlopen(f"{base}/jobs?{query}", timeout=8) as response:
                payload = json.loads(response.read().decode("utf-8") or "{}")
            for item in payload.get("items") or payload.get("jobs") or []:
                if int(item.get("scan_id") or -1) == int(scan_id):
                    rows.append({
                        "status": item.get("status"),
                        "tool": item.get("tool"),
                        "profile": item.get("profile"),
                        "target": item.get("target"),
                        "started_at": item.get("started_at"),
                        "timeout": item.get("timeout"),
                    })
        return len(rows), rows[:50]
    except Exception as exc:  # noqa: BLE001
        return -1, [{"error": f"{type(exc).__name__}: {exc}"}]


def snapshot(scan_id: int, stale_seconds: int) -> dict[str, Any]:
    db = SessionLocal()
    try:
        job = db.get(ScanJob, int(scan_id))
        if not job:
            return {"scan_id": scan_id, "missing": True, "at": datetime.now().isoformat()}
        job_status = str(job.status or "")
        current_step = str(job.current_step or "")
        mission_progress = job.mission_progress
        updated_age = _age_seconds(job.updated_at)
        counts = work_queue_counts(db, int(scan_id))
        last_log = (
            db.query(func.max(ScanLog.created_at))
            .filter(ScanLog.scan_job_id == int(scan_id))
            .scalar()
        )
        log_age = _age_seconds(last_log)
        finding_count = db.query(func.count(Finding.id)).filter(Finding.scan_job_id == int(scan_id)).scalar() or 0
        idle_tx = db.execute(text("""
            SELECT count(*)
              FROM pg_stat_activity
             WHERE datname = current_database()
               AND state = 'idle in transaction'
               AND xact_start IS NOT NULL
               AND xact_start < now() - interval '60 seconds'
        """)).scalar() or 0
        state = dict(job.state_data or {})
        profiles = dict((state.get("preflight") or {}).get("targets") or {})
        expanded_targets = len(state.get("expanded_targets") or [])
        preflight_targets = len(profiles)
        http_live = sum(1 for p in profiles.values() if isinstance(p, dict) and p.get("p06_http_live"))
        # End the implicit SELECT transaction before any network call.
        db.rollback()
    finally:
        db.close()

    kali_count, kali_jobs = _kali_active(int(scan_id))
    alerts: list[str] = []
    if updated_age is not None and updated_age > stale_seconds:
        alerts.append("job_updated_stale")
    if log_age is not None and log_age > stale_seconds:
        alerts.append("scan_log_stale")
    if kali_count == 0 and int(counts.get("submitted") or 0) > 0:
        alerts.append("kali_idle_with_submitted_items")
    if kali_count == 0 and int(counts.get("queued") or 0) > 0 and int(counts.get("submitted") or 0) == 0:
        alerts.append("kali_idle_with_queued_items")
    if int(idle_tx) > 0:
        alerts.append("idle_transactions_present")
    return {
        "at": datetime.now().isoformat(),
        "scan_id": int(scan_id),
        "status": job_status,
        "current_step": current_step,
        "mission_progress": mission_progress,
        "updated_age_seconds": updated_age,
        "last_log_age_seconds": log_age,
        "expanded_targets": expanded_targets,
        "preflight_targets": preflight_targets,
        "http_live": http_live,
        "findings": int(finding_count),
        "counts": counts,
        "kali_active": kali_count,
        "kali_jobs": kali_jobs,
        "idle_transactions_over_60s": int(idle_tx),
        "alerts": alerts,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-id", type=int, required=True)
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--stale-seconds", type=int, default=180)
    parser.add_argument("--out-dir", default="/app/scripts/monitor_reports")
    parser.add_argument("--max-seconds", type=int, default=0, help="0 means until terminal")
    parser.add_argument("--pid-file", default="", help="optional path that receives the monitor process id")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if args.pid_file:
        Path(args.pid_file).write_text(str(os.getpid()), encoding="utf-8")
    report_path = out_dir / f"scan_{args.scan_id}_monitor.jsonl"
    heartbeat_path = out_dir / f"scan_{args.scan_id}_monitor.heartbeat.json"
    started = time.monotonic()
    while True:
        row = snapshot(args.scan_id, args.stale_seconds)
        with report_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        heartbeat_path.write_text(json.dumps(row, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(row, ensure_ascii=False, sort_keys=True), flush=True)
        if str(row.get("status") or "").lower() in TERMINAL:
            return 0
        if args.max_seconds and time.monotonic() - started >= args.max_seconds:
            return 2
        time.sleep(max(5, int(args.interval)))


if __name__ == "__main__":
    raise SystemExit(main())
