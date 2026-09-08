"""Reteste de findings usando artefatos/validações existentes."""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

import requests
from sqlalchemy.orm import Session

from app.models.models import EvidenceArtifact, Finding, RetestRun, ScanAuthSession, ScanIdentity, ScanJob, ValidationRun
from app.services.artifact_store import create_request_response_artifact, replay_artifact_pair


def _run_api_skill_anonymous_retest(db: Session, artifact: EvidenceArtifact, finding: Finding) -> dict[str, Any]:
    request_data = dict(artifact.exploit_request or artifact.baseline_request or {})
    method = str(request_data.get("method") or "GET").upper()
    url = str(request_data.get("url") or artifact.target or finding.url or "")
    metadata = dict(artifact.artifact_metadata or {})
    expected_status = int(metadata.get("expected_status_code") or 0)
    expected_hash = str(metadata.get("expected_body_sha256") or "")
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return {"ok": False, "confirmed": False, "error": "mutation_retest_requires_family_validator"}
    if not url.startswith("http"):
        return {"ok": False, "confirmed": False, "error": "artifact_has_no_replayable_url"}
    try:
        response = requests.request(
            method,
            url,
            headers={"User-Agent": "ValidCyber-API-SkillTop20-Retest/1.0", "Accept": "application/json, text/plain, */*"},
            timeout=20,
            verify=False,
            allow_redirects=False,
        )
        body = response.text or ""
        body_hash = hashlib.sha256(body[:160_000].encode("utf-8", errors="ignore")).hexdigest()
        status_match = expected_status > 0 and int(response.status_code) == expected_status
        hash_match = bool(expected_hash and body_hash == expected_hash)
        still_exposed = int(response.status_code) in range(200, 300)
        confirmed = bool(still_exposed and status_match and (not expected_hash or hash_match))
        refuted = bool(expected_status and int(response.status_code) in {401, 403, 404, 405})
        replay = {
            "ok": True,
            "confirmed": confirmed,
            "refuted": refuted,
            "status_code": int(response.status_code),
            "content_type": response.headers.get("content-type", ""),
            "body_sha256": body_hash,
            "body_length": len(body),
            "expected_status_code": expected_status,
            "expected_body_sha256": expected_hash,
            "status_match": status_match,
            "body_hash_match": hash_match,
            "anonymous_access_still_observable": still_exposed,
        }
    except Exception as exc:
        replay = {"ok": False, "confirmed": False, "refuted": False, "error": type(exc).__name__, "detail": str(exc)[:500]}
    metadata.setdefault("retests", []).append({"created_at": datetime.now().isoformat(), "result": replay})
    artifact.artifact_metadata = metadata
    artifact.validation_status = "confirmed" if replay.get("confirmed") else "refuted" if replay.get("refuted") else "candidate"
    db.add(artifact)
    db.flush()
    return replay


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
    if bool((artifact.artifact_metadata or {}).get("api_skill_top20_anonymous_exposure")):
        replay = _run_api_skill_anonymous_retest(db, artifact, finding)
        replay_executed = bool(replay.get("ok"))
        new_status = "confirmed" if replay.get("confirmed") else ("refuted" if replay.get("refuted") else "inconclusive")
        retest.status = "completed"
        retest.new_status = new_status
        retest.artifact_id = artifact.id
        retest.summary = {
            "confirmed": "anonymous_api_exposure_still_observable",
            "refuted": "anonymous_api_exposure_not_reproduced",
            "inconclusive": "anonymous_api_exposure_not_replayable",
        }[new_status]
        retest.completed_at = datetime.now()
        finding.retest_status = new_status
        details = dict(finding.details or {})
        details["latest_retest"] = {
            "retest_id": retest.id,
            "status": new_status,
            "completed_at": retest.completed_at.isoformat(),
            "api_skill_top20_retest": True,
            "anonymous_access_still_observable": bool(replay.get("anonymous_access_still_observable")),
        }
        finding.details = details
        db.add(retest)
        db.add(finding)
        db.flush()
        return {"ok": replay_executed, "retest_id": retest.id, "new_status": new_status, "replay": replay}
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
