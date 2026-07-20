"""Reteste de findings usando artefatos/validações existentes."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import EvidenceArtifact, Finding, RetestRun, ScanAuthSession, ScanIdentity, ScanJob, ValidationRun
from app.services.artifact_store import create_request_response_artifact, replay_artifact_pair


def create_retest(db: Session, scan: ScanJob, finding: Finding) -> RetestRun:
    existing = (
        db.query(RetestRun)
        .filter(
            RetestRun.scan_job_id == scan.id,
            RetestRun.finding_id == finding.id,
            RetestRun.status.in_(["queued", "running"]),
        )
        .order_by(RetestRun.created_at.desc())
        .first()
    )
    if existing:
        return existing
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
    retest.status = "running"
    db.add(retest)
    db.flush()
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
    materials: dict[str, tuple[dict[str, str], dict[str, str]]] = {}
    if artifact.identity_key:
        material_rows = (
            db.query(ScanIdentity, ScanAuthSession)
            .join(ScanAuthSession, ScanIdentity.id == ScanAuthSession.scan_identity_id)
            .filter(
                ScanAuthSession.scan_job_id == finding.scan_job_id,
                ScanIdentity.identity_key.in_([part.strip() for part in artifact.identity_key.split(",") if part.strip()]),
                ScanAuthSession.status.in_(["valid", "static"]),
            )
            .order_by(ScanAuthSession.id.asc())
            .all()
        )
        for identity, material in material_rows:
            materials[str(identity.identity_key)] = (
                {str(k): str(v) for k, v in dict(material.headers or {}).items()},
                {str(k): str(v) for k, v in dict(material.cookies or {}).items()},
            )
    baseline_identity = str((artifact.baseline_request or {}).get("identity") or "")
    exploit_identity = str((artifact.exploit_request or {}).get("identity") or "")
    fallback_material = next(iter(materials.values()), ({}, {}))
    baseline_headers, baseline_cookies = materials.get(baseline_identity, fallback_material)
    exploit_headers, exploit_cookies = materials.get(exploit_identity, fallback_material)
    missing_identities = [
        key for key in {baseline_identity, exploit_identity}
        if key and key not in materials
    ]
    if missing_identities:
        replay = {
            "ok": False,
            "confirmed": False,
            "error": "retest_identity_material_unavailable",
            "missing_identities": sorted(missing_identities),
        }
    else:
        replay = replay_artifact_pair(
            db,
            artifact,
            baseline_operational_headers=baseline_headers,
            baseline_operational_cookies=baseline_cookies,
            exploit_operational_headers=exploit_headers,
            exploit_operational_cookies=exploit_cookies,
        )
    replay_executed = bool(replay.get("ok"))
    new_status = "confirmed" if replay.get("confirmed") else ("refuted" if replay_executed else "inconclusive")
    retest.status = "completed"
    retest.new_status = new_status
    retest.artifact_id = artifact.id
    retest.summary = {
        "confirmed": "finding_still_observable",
        "refuted": "finding_not_reproduced",
        "inconclusive": "finding_not_replayable",
    }[new_status]
    retest.completed_at = datetime.now()
    finding.retest_status = new_status
    details = dict(finding.details or {})
    details["latest_retest"] = {
        "retest_id": retest.id,
        "status": new_status,
        "differential_persisted": bool(replay.get("differential_persisted")),
        "indicator_match": bool(replay.get("indicator_match")),
        "negative_control_distinct": bool(replay.get("negative_control_distinct")),
        "completed_at": retest.completed_at.isoformat(),
    }
    finding.details = details
    db.add(retest)
    db.add(finding)
    db.flush()
    return {"ok": True, "retest_id": retest.id, "new_status": new_status, "replay": replay}
