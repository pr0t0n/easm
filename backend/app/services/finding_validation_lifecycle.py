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
        details = dict(finding.details or {})
        if str(details.get("test_type") or "") == "cache_deception":
            from app.services.cache_deception_validator import adjudicate_cache_deception

            adjudication = adjudicate_cache_deception(details)
            existing_adjudication = (
                db.query(ValidationRun)
                .filter(
                    ValidationRun.scan_job_id == job.id,
                    ValidationRun.finding_id == finding.id,
                    ValidationRun.validator_name == "cache-deception-evidence-contract",
                )
                .first()
            )
            if existing_adjudication is None:
                db.add(ValidationRun(
                    scan_job_id=job.id,
                    finding_id=finding.id,
                    validator_name="cache-deception-evidence-contract",
                    result=str(adjudication["result"]),
                    reason=str(adjudication["reason"]),
                    run_metadata=adjudication,
                ))
            details["cache_deception_adjudication"] = adjudication
            finding.details = details
            finding.verification_status = str(adjudication["result"])
            finding.is_false_positive = adjudication["result"] == "refuted"
            cache_target = str(finding.url or finding.domain or f"finding:{finding.id}")[:1000]
            cache_coverage = _coverage_row(db, job, finding, cache_target)
            cache_coverage.status = str(adjudication["result"])
            cache_coverage.blocking_reason = None
            cache_coverage.coverage_metadata = {
                **dict(cache_coverage.coverage_metadata or {}),
                "finding_id": finding.id,
                "asset_target": cache_target,
                "validator": "cache-deception-evidence-contract",
                "adjudication": adjudication,
            }
            cache_coverage.updated_at = datetime.now()
            db.add(cache_coverage)
            db.add(finding)
            if adjudication["result"] == "refuted":
                result["retests_refuted"] += 1
                continue

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
            "asset_target": target,
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
    # CoverageItem is unique by (scan, coverage_type, target_ref, test_class).
    # A target may legitimately have several independent high-risk findings,
    # therefore the covered object is the finding itself, not the shared asset.
    # Using the asset as target_ref caused duplicate INSERTs in autoflush=False
    # sessions and made the final quality gate fail after all tools had finished.
    coverage_ref = f"finding:{finding.id}"
    for pending in db.new:
        if (
            isinstance(pending, CoverageItem)
            and pending.scan_job_id == job.id
            and pending.coverage_type == "high_risk_finding"
            and pending.target_ref == coverage_ref
            and pending.test_class == "validation_retest_lifecycle"
        ):
            return pending

    row = (
        db.query(CoverageItem)
        .filter(
            CoverageItem.scan_job_id == job.id,
            CoverageItem.coverage_type == "high_risk_finding",
            CoverageItem.target_ref == coverage_ref,
            CoverageItem.test_class == "validation_retest_lifecycle",
        )
        .first()
    )
    if row is None:
        # Compatibility with rows produced before coverage_ref became
        # finding-scoped.
        row = (
            db.query(CoverageItem)
            .filter(
                CoverageItem.scan_job_id == job.id,
                CoverageItem.coverage_type == "high_risk_finding",
                CoverageItem.finding_id == finding.id,
                CoverageItem.test_class == "validation_retest_lifecycle",
            )
            .first()
        )
    if row is None:
        from app.services.offensive_inventory_service import OffensiveInventoryService

        row = OffensiveInventoryService(db, job).upsert_coverage(
            coverage_type="high_risk_finding",
            target_ref=coverage_ref,
            test_class="validation_retest_lifecycle",
            finding_id=finding.id,
            status="not_tested",
            metadata={
                "finding_id": int(finding.id),
                "asset_target": target,
                "created_by": "high_risk_lifecycle",
            },
        )
    return row
