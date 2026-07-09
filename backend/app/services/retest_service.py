"""Reteste de findings usando artefatos/validações existentes."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import EvidenceArtifact, Finding, RetestRun, ScanJob, ValidationRun
from app.services.artifact_store import create_request_response_artifact, replay_artifact


def create_retest(db: Session, scan: ScanJob, finding: Finding) -> RetestRun:
    validation = (
        db.query(ValidationRun)
        .filter(ValidationRun.scan_job_id == scan.id, ValidationRun.finding_id == finding.id)
        .order_by(ValidationRun.created_at.desc())
        .first()
    )
    row = RetestRun(
        scan_job_id=scan.id,
        finding_id=finding.id,
        validation_run_id=validation.id if validation else None,
        status="queued",
        old_status=finding.verification_status or "candidate",
        retest_metadata={"finding_title": finding.title, "validator": validation.validator_name if validation else ""},
    )
    db.add(row)
    db.flush()
    return row


def run_retest(db: Session, retest: RetestRun) -> dict[str, Any]:
    finding = db.query(Finding).filter(Finding.id == retest.finding_id).first()
    if not finding:
        retest.status = "failed"
        retest.summary = "finding_not_found"
        retest.completed_at = datetime.now()
        db.add(retest)
        db.flush()
        return {"ok": False, "error": "finding_not_found"}
    artifact = (
        db.query(EvidenceArtifact)
        .filter(EvidenceArtifact.finding_id == finding.id)
        .order_by(EvidenceArtifact.created_at.desc())
        .first()
    )
    if not artifact:
        artifact = create_request_response_artifact(
            db,
            finding.scan_job,
            target=finding.url or finding.domain or "",
            tool_name="retest",
            baseline_response={"note": "no_prior_artifact"},
            validation_status="candidate",
            diff_summary="no_prior_artifact",
            metadata={"finding_id": finding.id},
        )
    replay = replay_artifact(db, artifact)
    still_reachable = bool(replay.get("ok") and int(replay.get("status_code") or 0) < 500)
    new_status = "confirmed" if still_reachable and str(finding.verification_status or "") == "confirmed" else "refuted"
    retest.status = "completed"
    retest.new_status = new_status
    retest.artifact_id = artifact.id
    retest.summary = "finding_still_observable" if new_status == "confirmed" else "finding_not_reproduced"
    retest.completed_at = datetime.now()
    finding.retest_status = "confirmed" if new_status == "refuted" else "pending_retest"
    db.add(retest)
    db.add(finding)
    db.flush()
    return {"ok": True, "retest_id": retest.id, "new_status": new_status, "replay": replay}
