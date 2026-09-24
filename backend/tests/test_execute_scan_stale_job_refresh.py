"""Regression: _execute_scan must not call db.refresh(job) on the reference it
captured before run_offensive_operator_scan(...), because that function
releases/recreates the DB session around every external tool wait
(_release_db_session_before_external_wait -> db.close()), clearing the
session's identity map. Refreshing the pre-call `job` object after that raises
SQLAlchemy's "Instance '<ScanJob at 0x...>' is not persistent within this
Session" -- which _run_scan_with_retry's generic exception handler treats as a
retryable failure, burning through all 3 attempts and failing the whole scan
when a tool wait happens to straddle the call.

Confirmed live: scan #42 (Juice Shop aggressive) failed at 50% this way, at
the P11->P12 phase-budget handoff -- the exact same error/mechanism
documented (and partially fixed for the *inner* runner, not this outer
caller) in offensive_operator_runner.py's _refresh_scan_job_after_wait
docstring.
"""
from __future__ import annotations

import sys
from pathlib import Path


_HERE = Path(__file__).resolve()
ROOT = next(
    (
        candidate
        for candidate in [_HERE.parents[2], _HERE.parents[1]]
        if (candidate / "app" / "services").is_dir() or (candidate / "backend" / "app" / "services").is_dir()
    ),
    _HERE.parents[2],
)
BACKEND = ROOT / "backend" if (ROOT / "backend" / "app").is_dir() else ROOT
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _tasks_source() -> str:
    return (BACKEND / "app/workers/tasks.py").read_text(encoding="utf-8")


def test_execute_scan_refetches_job_by_id_instead_of_refreshing_stale_reference():
    source = _tasks_source()
    call_index = source.index("result = run_offensive_operator_scan(")
    # Look at the next ~1600 chars after the call for how `job` gets updated.
    window = source[call_index : call_index + 1600]
    code_lines = [ln for ln in window.splitlines() if not ln.strip().startswith("#")]
    code_only = "\n".join(code_lines)

    assert "db.refresh(job)" not in code_only, (
        "db.refresh(job) right after run_offensive_operator_scan() refreshes a "
        "reference that call may have already detached from the session -- "
        "re-fetch by id instead (db.get(ScanJob, scan_id))"
    )
    assert "db.get(ScanJob, scan_id)" in code_only
