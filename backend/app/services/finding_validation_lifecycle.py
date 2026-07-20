"""Mandatory validation and retest lifecycle for high-impact findings."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import CoverageItem, Finding, RetestRun, ScanJob, ValidationRun
from app.services.evidence_contract_service import evaluate_finding_promotion
from app.services.pentest_outcome_learning import record_outcome
from app.services.poc_validator import _select_validation_tool, schedule_poc_validation
from app.services.retest_service import create_retest, run_retest


def enforce_high_risk_lifecycle(db: Session, job: ScanJob, *, limit: int = 50) -> dict[str, Any]:
    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == job.id,
            Finding.severity.in_(["critical", "high"]),
            Finding.is_false_positive.is_(False),
        )
        .order_by(Finding.risk_score.desc(), Finding.cvss.desc().nullslast(), Finding.id.asc())
        .limit(max(1, int(limit)))
        .all()
    )
    result = {
        "seen": len(findings),
        "ready": 0,
        "scheduled": 0,
        "blocked_no_validator": 0,
        "retests_completed": 0,
        "retests_confirmed": 0,
        "retests_refuted": 0,
    }
    for finding in findings:
        decision = evaluate_finding_promotion(db, finding)
        target = str(finding.url or finding.domain or f"finding:{finding.id}")[:1000]
        coverage = _coverage_row(db, job, finding, target)
        details = dict(finding.details or {})
        lifecycle = dict(details.get("validation_lifecycle") or {})
        lifecycle.update({
            "required": True,
            "required_artifacts": list(decision.required_artifacts),
            "missing_artifacts": list(decision.missing_artifacts),
            "evaluated_at": datetime.now().isoformat(),
        })

        if decision.can_promote and decision.status == "confirmed":
            coverage.status = "validated"
            coverage.blocking_reason = None
            completed_retest = (
                db.query(RetestRun)
                .filter(
                    RetestRun.scan_job_id == job.id,
                    RetestRun.finding_id == finding.id,
                    RetestRun.status == "completed",
                )
                .order_by(RetestRun.completed_at.desc().nullslast())
                .first()
            )
            if completed_retest is None:
                retest = create_retest(db, job, finding)
                retest_result = run_retest(db, retest)
                result["retests_completed"] += int(bool(retest_result.get("ok")))
                status = str(retest_result.get("new_status") or "failed")
                result[f"retests_{status}"] = int(result.get(f"retests_{status}") or 0) + 1
                lifecycle["retest"] = retest_result
                if status == "refuted":
                    coverage.status = "refuted"
                    coverage.blocking_reason = "finding_not_reproduced"
                elif status == "inconclusive":
                    coverage.status = "blocked"
                    coverage.blocking_reason = "finding_not_replayable"
                elif status == "confirmed":
                    result["ready"] += 1
                record_outcome(
                    db, job, dimension="retest", metric_key=str(finding.tool or "unknown"),
                    outcome=status,
                    metadata={"finding_id": finding.id, "severity": finding.severity},
                )
            else:
                completed_status = str(completed_retest.new_status or "inconclusive")
                lifecycle["retest"] = {
                    "retest_id": completed_retest.id,
                    "status": completed_status,
                    "completed_at": completed_retest.completed_at.isoformat() if completed_retest.completed_at else None,
                }
                if completed_status == "confirmed":
                    result["ready"] += 1
                elif completed_status == "refuted":
                    coverage.status = "refuted"
                    coverage.blocking_reason = "finding_not_reproduced"
                else:
                    coverage.status = "blocked"
                    coverage.blocking_reason = "finding_not_replayable"
        else:
            existing_validation = (
                db.query(ValidationRun.id)
                .filter(ValidationRun.scan_job_id == job.id, ValidationRun.finding_id == finding.id)
                .first()
            )
            tool, _ = _select_validation_tool(finding)
            scheduled = bool(tool and not existing_validation and schedule_poc_validation(db, finding, job))
            if scheduled:
                result["scheduled"] += 1
                coverage.status = "queued"
                coverage.blocking_reason = "p21_validation_queued"
                lifecycle["status"] = "validation_queued"
            elif not tool:
                result["blocked_no_validator"] += 1
                coverage.status = "blocked"
                coverage.blocking_reason = "missing_finding_validator"
                lifecycle["status"] = "blocked_missing_validator"
            else:
                coverage.status = "tested" if existing_validation else "blocked"
                coverage.blocking_reason = "validation_inconclusive" if existing_validation else "validation_not_scheduled"
                lifecycle["status"] = coverage.blocking_reason

        coverage.coverage_metadata = {
            **dict(coverage.coverage_metadata or {}),
            "finding_id": finding.id,
            "severity": finding.severity,
            "verification_status": finding.verification_status,
            "required_artifacts": list(decision.required_artifacts),
            "missing_artifacts": list(decision.missing_artifacts),
        }
        coverage.updated_at = datetime.now()
        details["validation_lifecycle"] = lifecycle
        finding.details = details
        db.add(coverage)
        db.add(finding)
    db.flush()
    return result


def _coverage_row(db: Session, job: ScanJob, finding: Finding, target: str) -> CoverageItem:
    row = (
        db.query(CoverageItem)
        .filter(
            CoverageItem.scan_job_id == job.id,
            CoverageItem.coverage_type == "high_risk_finding",
            CoverageItem.target_ref == target,
            CoverageItem.test_class == "validation_retest_lifecycle",
        )
        .first()
    )
    if row is None:
        row = CoverageItem(
            scan_job_id=job.id,
            coverage_type="high_risk_finding",
            target_ref=target,
            test_class="validation_retest_lifecycle",
            finding_id=finding.id,
            status="not_tested",
        )
    return row
