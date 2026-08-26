#!/usr/bin/env python3
"""
Juice Shop stateful-pentest baseline harness (Épico 0 of
docs/JUICE_SHOP_STATEFUL_APP_PENTEST_CAPABILITY_PLAN.md).

Unlike scan_stability_harness.py (which measures run-to-run reproducibility
of the SAME scan), this harness exports the specific capability metrics the
plan tracks for a single scan, and compares two scans (e.g. an old baseline
vs a new run after a fix) to catch regression in endpoint inventory or
auth/session capture.

Does NOT read or report the Juice Shop scoreboard/"challenges solved" number
-- the plan explicitly forbids scraping it. That figure stays a number the
operator types in manually when archiving a baseline (--challenges-solved).

Usage (inside container):
    # fire a new aggressive scan against a local Juice Shop and export it
    python /app/scripts/juice_shop_baseline_harness.py run --target http://localhost:3000 --mode direct

    # export metrics for a scan that already ran (e.g. archiving scan 73 as
    # the initial baseline, per the plan: 7/186 challenges, score 36.9)
    python /app/scripts/juice_shop_baseline_harness.py export --scan-id 73 --challenges-solved 7 --challenges-total 186

    # compare two exported scans and flag regression
    python /app/scripts/juice_shop_baseline_harness.py compare --a baseline_reports/scan_73.json --b baseline_reports/scan_140.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "/app")

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import (
    EndpointObservation,
    Finding,
    OffensiveEndpoint,
    ScanAuthSession,
    ScanIdentity,
    ScanJob,
    ScanWorkItem,
    User,
)
from app.services.scan_quality import build_scan_quality

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_stability_harness import (  # noqa: E402
    TERMINAL_STATUSES,
    _create_scan_job,
    _git_commit,
    _run_celery,
    _run_direct,
)

REPORTS_DIR = Path(__file__).resolve().parent / "baseline_reports"

# These are the exact supplemental profile names offensive_operator_runner.py
# assigns to real body-request attacks against captured parameterized
# requests for P10/P12 (see `_body_profile` in offensive_operator_runner.py).
_BODY_REQUEST_PROFILES = {"sqlmap_body", "dalfox_body"}


def _work_item_has_body_request(item: ScanWorkItem) -> bool:
    return str(item.profile or "").lower() in _BODY_REQUEST_PROFILES


def export_scan_metrics(db: Session, scan_id: int) -> dict:
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise RuntimeError(f"scan {scan_id} not found")

    quality = build_scan_quality(db, job)
    components = quality.get("components") or {}
    test_depth = components.get("test_depth") or {}

    endpoints_count = db.query(OffensiveEndpoint).filter(OffensiveEndpoint.scan_job_id == scan_id).count()
    observations_count = db.query(EndpointObservation).filter(EndpointObservation.scan_job_id == scan_id).count()
    identities_count = db.query(ScanIdentity).filter(ScanIdentity.scan_job_id == scan_id).count()
    valid_sessions_count = (
        db.query(ScanAuthSession)
        .filter(ScanAuthSession.scan_job_id == scan_id, ScanAuthSession.status == "valid")
        .count()
    )

    work_items = db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == scan_id).all()
    body_requests_by_phase: dict[str, int] = {}
    for item in work_items:
        if str(item.phase_id or "").upper() not in {"P10", "P12"}:
            continue
        if _work_item_has_body_request(item):
            body_requests_by_phase[item.phase_id] = body_requests_by_phase.get(item.phase_id, 0) + 1

    blockers_by_phase: dict[str, list[str]] = {}
    for gap in list(quality.get("gaps") or []):
        title_upper = str(gap.get("title") or "").upper()
        area = str(gap.get("area") or "")
        for phase_id in (
            "P08",
            "P10",
            "P11",
            "P12",
            "P13",
            "P14",
            "P15",
            "P16",
            "P17",
            "P18",
            "P19",
            "P20",
        ):
            if phase_id in title_upper:
                blockers_by_phase.setdefault(phase_id, []).append(f"{area}: {gap.get('detail')}")

    findings_by_severity: dict[str, int] = {}
    for f in db.query(Finding).filter(Finding.scan_job_id == scan_id, Finding.is_false_positive.is_(False)).all():
        sev = str(f.severity or "unknown").lower()
        findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

    return {
        "exported_at": datetime.now().isoformat(),
        "scan_id": scan_id,
        "target": job.target_query,
        "status": job.status,
        "score": quality.get("score"),
        "grade": quality.get("grade"),
        "phase_coverage": (components.get("phase_coverage") or {}).get("score"),
        "test_depth": test_depth.get("score"),
        "validation_depth": (components.get("validation_depth") or {}).get("score"),
        "depth_requirements_met": test_depth.get("depth_requirements_met") or (quality.get("depth_requirements") or {}).get("met"),
        "depth_requirements_applicable": (quality.get("depth_requirements") or {}).get("applicable"),
        "endpoints_persisted": endpoints_count,
        "observed_requests": observations_count,
        "valid_auth_sessions": valid_sessions_count,
        "identities": identities_count,
        "body_requests_by_phase": body_requests_by_phase,
        "findings_by_severity": findings_by_severity,
        "gaps": quality.get("gaps"),
        "blockers_by_phase": blockers_by_phase,
    }


def cmd_export(args: argparse.Namespace) -> dict:
    engine = create_engine(settings.database_url)
    db = Session(engine)
    try:
        metrics = export_scan_metrics(db, args.scan_id)
    finally:
        db.close()
    if args.challenges_solved is not None:
        metrics["challenges_solved"] = args.challenges_solved
    if args.challenges_total is not None:
        metrics["challenges_total"] = args.challenges_total
    if args.label:
        metrics["label"] = args.label

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_DIR / f"scan_{args.scan_id}.json"
    out_path.write_text(json.dumps(metrics, indent=2, default=str))
    print(json.dumps(metrics, indent=2, default=str))
    print(f"\nSaved to {out_path}")
    return metrics


def cmd_run(args: argparse.Namespace) -> dict:
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
    print(f"BASELINE RUN  target={args.target}  mode={args.mode}  commit={commit}")

    job_id = _create_scan_job(SessionMaker, owner_id, args.target, args.mode)
    print(f"  job_id={job_id}")
    t0 = time.time()
    if args.mode == "celery":
        _run_celery(SessionMaker, job_id, args.poll_seconds, args.timeout_seconds)
    else:
        _run_direct(SessionMaker, job_id, args.verbose)
    print(f"  elapsed={time.time() - t0:.0f}s")

    args.scan_id = job_id
    args.challenges_solved = args.challenges_solved
    args.challenges_total = args.challenges_total
    return cmd_export(args)


def _regression_checks(a: dict, b: dict) -> list[str]:
    issues = []
    if int(b.get("endpoints_persisted") or 0) < int(a.get("endpoints_persisted") or 0):
        issues.append(
            f"endpoints_persisted regrediu: {a.get('endpoints_persisted')} -> {b.get('endpoints_persisted')}"
        )
    if int(b.get("valid_auth_sessions") or 0) < int(a.get("valid_auth_sessions") or 0):
        issues.append(
            f"valid_auth_sessions regrediu: {a.get('valid_auth_sessions')} -> {b.get('valid_auth_sessions')}"
        )
    if int(b.get("identities") or 0) < int(a.get("identities") or 0):
        issues.append(f"identities regrediu: {a.get('identities')} -> {b.get('identities')}")
    if int(b.get("observed_requests") or 0) < int(a.get("observed_requests") or 0):
        issues.append(
            f"observed_requests regrediu: {a.get('observed_requests')} -> {b.get('observed_requests')}"
        )
    a_score = float(a.get("score") or 0.0)
    b_score = float(b.get("score") or 0.0)
    if b_score < a_score - 1.0:
        issues.append(f"score regrediu: {a_score} -> {b_score}")
    return issues


def cmd_compare(args: argparse.Namespace) -> dict:
    a = json.loads(Path(args.a).read_text())
    b = json.loads(Path(args.b).read_text())
    issues = _regression_checks(a, b)
    result = {
        "a": {"scan_id": a.get("scan_id"), "label": a.get("label")},
        "b": {"scan_id": b.get("scan_id"), "label": b.get("label")},
        "regressions": issues,
        "regressed": bool(issues),
        "delta": {
            key: (b.get(key), a.get(key))
            for key in (
                "score",
                "grade",
                "endpoints_persisted",
                "observed_requests",
                "valid_auth_sessions",
                "identities",
                "depth_requirements_met",
            )
        },
    }
    print(json.dumps(result, indent=2, default=str))
    if issues:
        print("\nREGRESSAO DETECTADA:")
        for issue in issues:
            print(f"  - {issue}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Juice Shop baseline harness")
    sub = parser.add_subparsers(dest="command", required=True)

    p_export = sub.add_parser("export", help="Export metrics for an existing scan_id")
    p_export.add_argument("--scan-id", type=int, required=True)
    p_export.add_argument("--challenges-solved", type=int, default=None)
    p_export.add_argument("--challenges-total", type=int, default=None)
    p_export.add_argument("--label", default=None)
    p_export.set_defaults(func=cmd_export)

    p_run = sub.add_parser("run", help="Fire a new scan and export its metrics")
    p_run.add_argument("--target", required=True)
    p_run.add_argument("--mode", choices=["direct", "celery"], default="direct")
    p_run.add_argument("--user-email", default="admin@example.com")
    p_run.add_argument("--poll-seconds", type=float, default=10.0)
    p_run.add_argument("--timeout-seconds", type=int, default=7200)
    p_run.add_argument("--verbose", action="store_true")
    p_run.add_argument("--challenges-solved", type=int, default=None)
    p_run.add_argument("--challenges-total", type=int, default=None)
    p_run.add_argument("--label", default=None)
    p_run.set_defaults(func=cmd_run)

    p_compare = sub.add_parser("compare", help="Compare two exported metric JSON files")
    p_compare.add_argument("--a", required=True, help="Path to the earlier export (baseline)")
    p_compare.add_argument("--b", required=True, help="Path to the later export (candidate)")
    p_compare.set_defaults(func=cmd_compare)

    args = parser.parse_args()
    result = args.func(args)
    if args.command == "compare" and result.get("regressed"):
        sys.exit(1)


if __name__ == "__main__":
    main()
