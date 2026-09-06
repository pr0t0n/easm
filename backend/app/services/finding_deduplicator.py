from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm.attributes import flag_modified

from app.models.models import (
    BasJob,
    CoverageItem,
    EvidenceArtifact,
    Finding,
    FindingAdjudication,
    FindingIntelligenceSnapshot,
    RetestRun,
    ValidationRun,
    ValidationWire,
    Vulnerability,
)
from app.services.findings_extractor import _finding_dedup_title_key
from app.services.offensive_inventory_service import normalize_url


HEADER_ALIASES = {
    "content security policy": "content-security-policy",
    "csp": "content-security-policy",
    "strict transport security": "strict-transport-security",
    "hsts": "strict-transport-security",
    "x content type options": "x-content-type-options",
    "x-content-type-options": "x-content-type-options",
    "x frame options": "x-frame-options",
    "x-frame-options": "x-frame-options",
    "referrer policy": "referrer-policy",
    "permissions policy": "permissions-policy",
    "cross origin opener policy": "cross-origin-opener-policy",
    "cross-origin-opener-policy": "cross-origin-opener-policy",
    "cross origin resource policy": "cross-origin-resource-policy",
    "cross-origin-resource-policy": "cross-origin-resource-policy",
}

STATUS_RANK = {
    "confirmed": 80,
    "validated": 75,
    "needs_human_review": 60,
    "candidate": 50,
    "blocked": 40,
    "hypothesis": 30,
    "inconclusive": 20,
    "invalid_evidence": 10,
    "refuted": 0,
}

SEVERITY_RANK = {"critical": 50, "high": 40, "medium": 30, "low": 20, "info": 10}


def _clean_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _title_key(finding: Finding, details: dict[str, Any]) -> str:
    title = _clean_text(finding.title)
    for marker, header in HEADER_ALIASES.items():
        if marker in title:
            return f"missing_header:{header}"
    if details.get("finding_class"):
        return str(details.get("finding_class")).lower()
    return _finding_dedup_title_key(str(finding.title or ""), details)


def _location_key(finding: Finding, details: dict[str, Any]) -> str:
    url = str(finding.url or details.get("url") or details.get("matched_at") or details.get("matched-at") or "").strip()
    if url.startswith(("http://", "https://")):
        normalized = normalize_url(url)
        parsed = urlparse(normalized)
        if parsed.path and parsed.path != "/":
            return normalized
        return parsed.netloc.lower()
    return str(finding.domain or details.get("asset") or "").strip().lower()


def finding_dedup_signature(finding: Finding) -> tuple[str, str, str]:
    details = dict(finding.details or {})
    family = str(details.get("vuln_family") or details.get("owasp_category") or "").strip().lower()
    return family, _title_key(finding, details), _location_key(finding, details)


def _artifact_count(db: Any, finding_id: int) -> int:
    return int(db.query(EvidenceArtifact.id).filter(EvidenceArtifact.finding_id == finding_id).count() or 0)


def _score(db: Any, finding: Finding) -> tuple[int, int, int, int]:
    return (
        STATUS_RANK.get(str(finding.verification_status or "").lower(), 0),
        SEVERITY_RANK.get(str(finding.severity or "").lower(), 0),
        _artifact_count(db, int(finding.id)),
        int(finding.confidence_score or 0),
    )


def _merge_details(kept: Finding, duplicate: Finding) -> None:
    kept_details = dict(kept.details or {})
    dup_details = dict(duplicate.details or {})
    sources = list(kept_details.get("deduplicated_sources") or [])
    sources.append({
        "finding_id": duplicate.id,
        "tool": duplicate.tool,
        "title": duplicate.title,
        "severity": duplicate.severity,
        "verification_status": duplicate.verification_status,
        "url": duplicate.url or dup_details.get("url") or dup_details.get("matched_at"),
        "deduplicated_at": datetime.now().isoformat(),
    })
    kept_details["deduplicated_sources"] = sources[-50:]
    for key in ("evidence_artifact_id", "evidence_artifact_path", "api_tested_via", "api_skill_id", "api_skill_name"):
        if not kept_details.get(key) and dup_details.get(key):
            kept_details[key] = dup_details[key]
    kept.details = kept_details
    try:
        flag_modified(kept, "details")
    except Exception:
        pass


def _relink_dependencies(db: Any, kept: Finding, duplicate: Finding) -> None:
    duplicate_id = int(duplicate.id)
    kept_id = int(kept.id)
    db.query(EvidenceArtifact).filter(EvidenceArtifact.finding_id == duplicate_id).update({EvidenceArtifact.finding_id: kept_id}, synchronize_session=False)
    db.query(ValidationRun).filter(ValidationRun.finding_id == duplicate_id).update({ValidationRun.finding_id: kept_id}, synchronize_session=False)
    db.query(ValidationWire).filter(ValidationWire.finding_id == duplicate_id).update({ValidationWire.finding_id: kept_id}, synchronize_session=False)
    db.query(FindingIntelligenceSnapshot).filter(FindingIntelligenceSnapshot.finding_id == duplicate_id).update({FindingIntelligenceSnapshot.finding_id: kept_id}, synchronize_session=False)
    db.query(CoverageItem).filter(CoverageItem.finding_id == duplicate_id).update({CoverageItem.finding_id: kept_id}, synchronize_session=False)
    db.query(RetestRun).filter(RetestRun.finding_id == duplicate_id).update({RetestRun.finding_id: kept_id}, synchronize_session=False)
    db.query(BasJob).filter(BasJob.finding_id == duplicate_id).update({BasJob.finding_id: kept_id}, synchronize_session=False)
    db.query(Vulnerability).filter(Vulnerability.finding_id == duplicate_id).update({Vulnerability.finding_id: kept_id}, synchronize_session=False)
    for adjudication in db.query(FindingAdjudication).filter(FindingAdjudication.finding_id == duplicate_id).all():
        existing = (
            db.query(FindingAdjudication)
            .filter(FindingAdjudication.finding_id == kept_id, FindingAdjudication.cycle == adjudication.cycle)
            .first()
        )
        if existing:
            db.query(ValidationWire).filter(ValidationWire.adjudication_id == adjudication.id).update({ValidationWire.adjudication_id: existing.id}, synchronize_session=False)
            db.delete(adjudication)
        else:
            adjudication.finding_id = kept_id


def run_p21_finding_deduplication(db: Any, job: Any) -> dict[str, Any]:
    findings = db.query(Finding).filter(Finding.scan_job_id == int(job.id)).order_by(Finding.created_at.asc(), Finding.id.asc()).all()
    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for finding in findings:
        signature = finding_dedup_signature(finding)
        if not all(signature):
            continue
        groups.setdefault(signature, []).append(finding)
    removed = 0
    merged_groups = 0
    retained: list[int] = []
    for signature, rows in groups.items():
        if len(rows) < 2:
            continue
        rows = sorted(rows, key=lambda item: (_score(db, item), -int(item.id)), reverse=True)
        kept = rows[0]
        retained.append(int(kept.id))
        for duplicate in rows[1:]:
            _merge_details(kept, duplicate)
            _relink_dependencies(db, kept, duplicate)
            db.delete(duplicate)
            removed += 1
        merged_groups += 1
    if removed:
        state = dict(job.state_data or {})
        runs = list(state.get("p21_finding_deduplication_runs") or [])
        run = {
            "phase_id": "P21",
            "removed": removed,
            "merged_groups": merged_groups,
            "retained_finding_ids": retained[-100:],
            "executed_at": datetime.now().isoformat(),
        }
        runs.append(run)
        state["p21_finding_deduplication"] = run
        state["p21_finding_deduplication_runs"] = runs[-20:]
        job.state_data = state
        try:
            flag_modified(job, "state_data")
        except Exception:
            pass
    return {"removed": removed, "merged_groups": merged_groups, "retained_finding_ids": retained[-100:]}
