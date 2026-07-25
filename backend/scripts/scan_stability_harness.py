#!/usr/bin/env python3
"""
Scan stability harness.

Runs the SAME target N times back-to-back (direct in-process call, same
pattern as test_full_scan.py) and measures whether the platform produces
congruent, reproducible results run-to-run:

  - finding set stability   (Jaccard similarity of normalized signatures)
  - final status stability  (completed / completed_with_gaps / failed)
  - phase-ledger stability  (same phases completed/blocked/skipped every run)
  - P02/P06 qualification stability (same targets qualified every run)
  - congruence              (Finding Intelligence v2 contradictions +
                              scan-uncertainty autopsy notes, per run)

By default it calls the offensive operator runner directly in-process, same as
test_full_scan.py. Use --mode celery for the slower but more realistic path that
creates a ScanJob, submits it via the same admission/chain entry point used by
the API, and waits for Celery/work-queue/dispatcher/workers to finish. The
celery mode is the one that can expose claim_work_items, watchdog/redrive and
chain-lock races.

Usage (inside container):
    python /app/scripts/scan_stability_harness.py --target valid.com.br --runs 3
    python /app/scripts/scan_stability_harness.py --target valid.com.br --runs 3 --mode celery

Re-run this after each round of fixes and compare stability_history.jsonl
to see whether the metrics are actually improving.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "/app")

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import Finding, ScanJob, User
from app.services.offensive_operator_runner import run_offensive_operator_scan
from app.services.offensive_operator_core import PHASE_ORDER
from app.services.findings_extractor import _finding_dedup_title_key
from app.services.finding_experiment import build_finding_intelligence
from app.services.scan_uncertainty import build_scan_uncertainty


REPORTS_DIR = Path(__file__).resolve().parent / "stability_reports"
HISTORY_FILE = REPORTS_DIR / "stability_history.jsonl"
TERMINAL_STATUSES = {"completed", "completed_with_gaps", "failed", "stopped", "paused"}


def _git_commit() -> str:
    try:
        return (
            subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=str(Path(__file__).resolve().parents[2]),
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )
    except Exception:
        return "unknown"


def _hr(char: str = "─", width: int = 78) -> None:
    print(char * width)


def _create_scan_job(SessionMaker, owner_id: int, target: str, mode: str) -> int:
    db = SessionMaker()
    try:
        job = ScanJob(
            owner_id=owner_id,
            target_query=target,
            mode="unit",
            status="queued",
            compliance_status="approved",
            current_step=f"stability harness ({mode})",
            state_data={
                "execution_mode": "controlled_pentest",
                "offensive_operator_enabled": True,
                "scan_level": "full",
                "scan_profile": {"label": "Full", "depth": "full"},
                "parallelize": bool(settings.scan_parallelize_default),
                "parallel_target_batch_size": int(settings.scan_parallel_target_batch_size or 1024),
                "parallel_wait_seconds": int(settings.scan_parallel_wait_seconds or 60),
                "authorization_gate": {
                    "approved": True,
                    "reason": "stability_harness_attested",
                    "mode": "harness",
                    "authorization_attested": True,
                    "authorized_scope": [target],
                },
            },
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return int(job.id)
    finally:
        db.close()


def _run_direct(SessionMaker, job_id: int, verbose: bool) -> None:
    db = SessionMaker()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            raise RuntimeError(f"job {job_id} not found")
        run_offensive_operator_scan(db, job, scan_mode="unit")
    except Exception as exc:
        print(f"  [ERRO FATAL direct job_id={job_id}] {exc}")
        if verbose:
            import traceback

            traceback.print_exc()
    finally:
        db.close()


def _run_celery(SessionMaker, job_id: int, poll_seconds: float, timeout_seconds: int) -> None:
    from app.workers.tasks import admit_or_defer_scan

    submit = admit_or_defer_scan(job_id, mode="unit")
    print(f"  celery_submit={submit}")
    started = time.time()
    last_line = ""
    while True:
        db = SessionMaker()
        try:
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if not job:
                raise RuntimeError(f"job {job_id} disappeared")
            status = str(job.status or "")
            line = f"status={status} progress={int(job.mission_progress or 0)}% step={str(job.current_step or '')[:120]}"
            if line != last_line:
                print(f"  {line}")
                last_line = line
            if status in TERMINAL_STATUSES:
                return
        finally:
            db.close()
        if time.time() - started > timeout_seconds:
            raise TimeoutError(f"scan {job_id} did not finish within {timeout_seconds}s")
        time.sleep(max(1.0, float(poll_seconds or 5.0)))


def run_once(
    SessionMaker,
    owner_id: int,
    target: str,
    run_index: int,
    verbose: bool,
    *,
    mode: str,
    poll_seconds: float,
    timeout_seconds: int,
) -> dict:
    job_id = _create_scan_job(SessionMaker, owner_id, target, mode)

    print(f"\n  ── run {run_index}  job_id={job_id}  target={target}  mode={mode}  ({len(PHASE_ORDER)} fases previstas) ──")
    t0 = time.time()
    try:
        if mode == "celery":
            _run_celery(SessionMaker, job_id, poll_seconds, timeout_seconds)
        else:
            _run_direct(SessionMaker, job_id, verbose)
    except Exception as exc:
        print(f"  [ERRO FATAL run {run_index}] {exc}")
        if verbose:
            import traceback

            traceback.print_exc()
    elapsed = time.time() - t0
    db = SessionMaker()
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        raise RuntimeError(f"job {job_id} not found after run")
    db.refresh(job)

    # ── phase ledger snapshot ──────────────────────────────────────────────
    state = dict(job.state_data or {})
    ledger_raw = state.get("phase_ledger_v2") or state.get("phase_ledger") or {}
    phase_ledger: dict[str, str | None] = {}
    if isinstance(ledger_raw, dict):
        for pid, entry in ledger_raw.items():
            if isinstance(entry, dict):
                phase_ledger[str(pid)] = entry.get("status")
    elif isinstance(ledger_raw, list):
        for entry in ledger_raw:
            if isinstance(entry, dict) and entry.get("phase_id"):
                phase_ledger[str(entry["phase_id"])] = entry.get("status")

    # ── P02/P06 qualification snapshot ─────────────────────────────────────
    preflight_targets = (state.get("preflight") or {}).get("targets") or {}
    qualification = {
        str(t): {
            "p02_positive_evidence": bool(p.get("p02_positive_evidence")),
            "p06_positive_evidence": bool(p.get("p06_positive_evidence") or p.get("p06_http_live")),
            "status": p.get("status"),
        }
        for t, p in preflight_targets.items()
        if isinstance(p, dict)
    }

    # ── findings snapshot + congruence check ───────────────────────────────
    findings = db.query(Finding).filter(Finding.scan_job_id == job.id).all()
    finding_rows = []
    contradiction_hits = []
    for f in findings:
        details = dict(f.details or {})
        sig_key = details.get("dedup_title_key") or _finding_dedup_title_key(f.title or "", details)
        signature = f"{sig_key}|{f.domain or ''}|{f.tool or ''}"
        finding_rows.append(
            {
                "id": f.id,
                "signature": signature,
                "title": f.title,
                "severity": f.severity,
                "domain": f.domain,
                "tool": f.tool,
                "is_false_positive": f.is_false_positive,
                "verification_status": f.verification_status,
            }
        )
        if (f.severity or "").lower() in {"high", "critical"} and not f.is_false_positive:
            try:
                intel = build_finding_intelligence(db, f)
                contradictions = intel.get("contradictions") or []
            except Exception as exc:  # congruence checker itself must never crash the harness
                contradictions = [{"reason": f"congruence_check_crashed: {exc}"}]
            if contradictions:
                contradiction_hits.append(
                    {"finding_id": f.id, "title": f.title, "severity": f.severity, "contradictions": contradictions}
                )

    try:
        uncertainty = build_scan_uncertainty(db, job)
    except Exception as exc:
        uncertainty = {"autopsy": [f"congruence_check_crashed: {exc}"], "exploration_debt": []}

    snapshot = {
        "run_index": run_index,
        "job_id": job.id,
        "target": target,
        "mode": mode,
        "status": job.status,
        "mission_progress": job.mission_progress,
        "elapsed_s": round(elapsed, 1),
        "phase_ledger": phase_ledger,
        "qualification": qualification,
        "findings": finding_rows,
        "finding_signatures": sorted({r["signature"] for r in finding_rows}),
        "contradictions": contradiction_hits,
        "autopsy": uncertainty.get("autopsy", []),
        "exploration_debt": uncertainty.get("exploration_debt", []),
    }

    print(
        f"  status={job.status}  progress={job.mission_progress}%  "
        f"findings={len(finding_rows)}  contradictions={len(contradiction_hits)}  "
        f"autopsy_notes={len(snapshot['autopsy'])}  elapsed={elapsed:.0f}s"
    )

    db.close()
    return snapshot


def _jaccard(a: set, b: set) -> float:
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


def compare_runs(snapshots: list[dict]) -> dict:
    n = len(snapshots)
    sig_sets = [set(s["finding_signatures"]) for s in snapshots]
    pairwise = [_jaccard(sig_sets[i], sig_sets[j]) for i in range(n) for j in range(i + 1, n)]
    avg_jaccard = round(sum(pairwise) / len(pairwise), 4) if pairwise else 1.0
    min_jaccard = round(min(pairwise), 4) if pairwise else 1.0

    statuses = sorted({s["status"] for s in snapshots})

    all_phase_ids = sorted({pid for s in snapshots for pid in s["phase_ledger"]})
    phase_divergence = {
        pid: [s["phase_ledger"].get(pid) for s in snapshots]
        for pid in all_phase_ids
        if len({s["phase_ledger"].get(pid) for s in snapshots}) > 1
    }

    all_targets = sorted({t for s in snapshots for t in s["qualification"]})
    qual_divergence = {
        t: [s["qualification"].get(t) for s in snapshots]
        for t in all_targets
        if len({json.dumps(s["qualification"].get(t), sort_keys=True) for s in snapshots}) > 1
    }

    total_contradictions = sum(len(s["contradictions"]) for s in snapshots)
    total_autopsy = sum(len(s["autopsy"]) for s in snapshots)

    return {
        "runs": n,
        "finding_set_avg_jaccard": avg_jaccard,
        "finding_set_min_jaccard": min_jaccard,
        "status_set": statuses,
        "status_stable": len(statuses) == 1,
        "phase_divergence": phase_divergence,
        "phase_set_stable": not phase_divergence,
        "qualification_divergence": qual_divergence,
        "qualification_stable": not qual_divergence,
        "total_contradictions": total_contradictions,
        "total_autopsy_notes": total_autopsy,
        "congruent": total_contradictions == 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan stability harness")
    parser.add_argument("--target", default="valid.com.br")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--mode", choices=["direct", "celery"], default="direct")
    parser.add_argument("--user-email", default="admin@example.com")
    parser.add_argument("--poll-seconds", type=float, default=10.0)
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    engine = create_engine(settings.database_url)
    SessionMaker = lambda: Session(engine)  # noqa: E731

    db0 = SessionMaker()
    owner = db0.query(User).filter(User.email == args.user_email).first()
    if not owner:
        print(f"ERROR: user {args.user_email} not found")
        sys.exit(1)
    owner_id = owner.id
    db0.close()

    commit = _git_commit()
    _hr("━")
    print(f"  STABILITY HARNESS  |  alvo={args.target}  |  runs={args.runs}  |  mode={args.mode}  |  commit={commit}")
    _hr("━")

    snapshots = [
        run_once(
            SessionMaker,
            owner_id,
            args.target,
            i,
            args.verbose,
            mode=args.mode,
            poll_seconds=args.poll_seconds,
            timeout_seconds=args.timeout_seconds,
        )
        for i in range(1, args.runs + 1)
    ]
    comparison = compare_runs(snapshots)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = {
        "timestamp": datetime.now().isoformat(),
        "git_commit": commit,
        "target": args.target,
        "mode": args.mode,
        "runs": args.runs,
        "comparison": comparison,
        "snapshots": snapshots,
    }
    out_path = REPORTS_DIR / f"stability_{ts}.json"
    out_path.write_text(json.dumps(report, indent=2, default=str))

    with HISTORY_FILE.open("a") as hf:
        hf.write(
            json.dumps(
                {
                    "timestamp": report["timestamp"],
                    "git_commit": commit,
                    "target": args.target,
                    "mode": args.mode,
                    "runs": args.runs,
                    "finding_set_avg_jaccard": comparison["finding_set_avg_jaccard"],
                    "status_stable": comparison["status_stable"],
                    "phase_set_stable": comparison["phase_set_stable"],
                    "qualification_stable": comparison["qualification_stable"],
                    "total_contradictions": comparison["total_contradictions"],
                    "total_autopsy_notes": comparison["total_autopsy_notes"],
                }
            )
            + "\n"
        )

    phase_msg = "✓ ESTÁVEL" if comparison["phase_set_stable"] else f"✗ VARIOU em {list(comparison['phase_divergence'].keys())}"
    qual_msg = "✓ ESTÁVEL" if comparison["qualification_stable"] else f"✗ VARIOU em {list(comparison['qualification_divergence'].keys())}"
    finding_msg = "✓ ESTÁVEL" if comparison["finding_set_avg_jaccard"] == 1.0 else "✗ VARIOU"

    _hr("═")
    print(f"  RESULTADO  |  {args.runs} execuções contra {args.target}  mode={args.mode}  (commit {commit})")
    _hr("═")
    print(f"  Conjunto de findings   : jaccard médio={comparison['finding_set_avg_jaccard']}  mínimo={comparison['finding_set_min_jaccard']}  {finding_msg}")
    print(f"  Status final           : {comparison['status_set']}  {'✓ ESTÁVEL' if comparison['status_stable'] else '✗ VARIOU'}")
    print(f"  Conclusão de fases     : {phase_msg}")
    print(f"  Qualificação P02/P06   : {qual_msg}")
    print(f"  Congruência (contrad.) : {comparison['total_contradictions']} contradições em findings high/critical  {'✓' if comparison['congruent'] else '✗'}")
    print(f"  Notas de autopsy       : {comparison['total_autopsy_notes']}")
    print()
    print(f"  Relatório completo : {out_path}")
    print(f"  Histórico (append) : {HISTORY_FILE}")
    _hr("━")

    stable = (
        comparison["finding_set_avg_jaccard"] == 1.0
        and comparison["status_stable"]
        and comparison["phase_set_stable"]
        and comparison["qualification_stable"]
        and comparison["congruent"]
    )
    sys.exit(0 if stable else 1)


if __name__ == "__main__":
    main()
