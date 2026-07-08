"""Persistent evidence contracts and promotion rules."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models.models import EvidenceArtifact, Finding, ScanJob
from app.services.evidence_gate import get_verification_status
from app.services.pentest_contracts import EvidenceContract, ValidationDecision


HIGH_IMPACT_SEVERITIES = {"critical", "high"}
REPRO_REQUIRED_KEYWORDS = {
    "sql injection",
    "sqli",
    "xss",
    "ssrf",
    "rce",
    "remote code",
    "idor",
    "bola",
    "access control",
    "authorization",
    "auth bypass",
}
AUTH_REQUIRED_KEYWORDS = {"idor", "bola", "access control", "authorization", "auth bypass", "session", "jwt", "oauth"}


def create_evidence_artifact(db: Session, contract: EvidenceContract) -> EvidenceArtifact:
    artifact = EvidenceArtifact(
        scan_job_id=contract.scan_job_id,
        finding_id=contract.finding_id,
        phase_id=contract.phase_id or None,
        skill_id=contract.skill_id or None,
        tool_name=contract.tool_name or None,
        target=contract.target or None,
        identity_key=contract.identity_key or None,
        artifact_type=contract.artifact_type,
        validation_status=contract.validation_status,
        confidence_score=contract.confidence_score,
        baseline_request=contract.baseline_request,
        baseline_response_ref=contract.baseline_response_ref or None,
        exploit_request=contract.exploit_request,
        exploit_response_ref=contract.exploit_response_ref or None,
        payload=contract.payload or None,
        diff_summary=contract.diff_summary or None,
        reproduction_steps=contract.reproduction_steps,
        workspace_path=contract.workspace_path or None,
        artifact_metadata=contract.metadata,
    )
    db.add(artifact)
    db.flush()
    return artifact


def create_artifact_from_tool_result(
    db: Session,
    *,
    scan_job_id: int,
    result: dict[str, Any],
    finding_id: int | None = None,
    phase_id: str = "",
    skill_id: str = "",
    identity_key: str = "",
) -> EvidenceArtifact:
    details = dict(result.get("parsed") or {})
    contract = EvidenceContract(
        scan_job_id=scan_job_id,
        finding_id=finding_id,
        phase_id=phase_id,
        skill_id=skill_id or str(result.get("skill_id") or ""),
        tool_name=str(result.get("tool") or ""),
        target=str(result.get("target") or ""),
        identity_key=identity_key,
        artifact_type="tool_result",
        validation_status="confirmed" if str(result.get("status") or "") == "executed" else "candidate",
        confidence_score=80 if str(result.get("status") or "") == "executed" else 40,
        payload=str(details.get("payload") or ""),
        diff_summary=str(details.get("diff") or result.get("stderr") or "")[:4000],
        reproduction_steps=_steps_from_result(result),
        workspace_path=str(result.get("evidence_path") or ""),
        metadata={
            "command": result.get("command") or "",
            "return_code": result.get("return_code"),
            "stdout_ref": result.get("evidence_path") or "",
            "status": result.get("status"),
            "dispatch_task_id": result.get("dispatch_task_id"),
        },
    )
    return create_evidence_artifact(db, contract)


def evaluate_finding_promotion(db: Session, finding: Finding) -> ValidationDecision:
    details = dict(finding.details or {})
    title = str(finding.title or "").lower()
    tool = str(finding.tool or details.get("tool") or "").lower()
    severity = str(finding.severity or "info").lower()
    status = str(finding.verification_status or details.get("verification_status") or "").lower()
    if not status:
        status = get_verification_status(tool, {"title": finding.title, "details": details})

    artifacts = (
        db.query(EvidenceArtifact)
        .filter(EvidenceArtifact.finding_id == finding.id)
        .order_by(EvidenceArtifact.created_at.desc())
        .all()
    )
    confirmed_artifacts = [a for a in artifacts if str(a.validation_status or "") == "confirmed"]
    has_repro_pair = any(_artifact_has_repro_pair(a) for a in artifacts)
    missing: list[str] = []
    required: list[str] = []

    if severity in HIGH_IMPACT_SEVERITIES:
        required.append("proof_pack")
        if not artifacts:
            missing.append("proof_pack")

    needs_repro = any(token in title for token in REPRO_REQUIRED_KEYWORDS)
    if severity in HIGH_IMPACT_SEVERITIES and needs_repro:
        required.append("baseline_vs_exploit")
        if not has_repro_pair and not confirmed_artifacts:
            missing.append("baseline_vs_exploit")

    needs_auth = any(token in title for token in AUTH_REQUIRED_KEYWORDS)
    if needs_auth:
        required.append("authenticated_identity")
        if not any(str(a.identity_key or "") for a in artifacts) and not details.get("identity_key"):
            missing.append("authenticated_identity")

    if status == "hypothesis":
        return ValidationDecision(
            status="hypothesis",
            can_promote=False,
            severity_cap="medium",
            reason="hypothesis_source_requires_independent_validation",
            required_artifacts=required,
            missing_artifacts=missing,
        )
    if missing:
        return ValidationDecision(
            status="candidate",
            can_promote=False,
            severity_cap="high" if severity == "critical" else "",
            reason="missing_required_evidence",
            required_artifacts=required,
            missing_artifacts=missing,
        )
    if status == "confirmed" or confirmed_artifacts or (artifacts and not needs_repro):
        return ValidationDecision(
            status="confirmed",
            can_promote=True,
            reason="required_evidence_present",
            required_artifacts=required,
            missing_artifacts=[],
        )
    return ValidationDecision(
        status="candidate",
        can_promote=False,
        reason="candidate_requires_validation",
        required_artifacts=required,
        missing_artifacts=missing,
    )


def link_artifacts_to_findings(db: Session, job: ScanJob) -> dict[str, Any]:
    """Best-effort correlation of unlinked tool artifacts to findings.

    Correlation is intentionally conservative: same scan, same tool when known,
    and overlapping target/url/domain text. It never overwrites an existing
    finding_id.
    """
    findings = db.query(Finding).filter(Finding.scan_job_id == job.id).all()
    artifacts = (
        db.query(EvidenceArtifact)
        .filter(EvidenceArtifact.scan_job_id == job.id, EvidenceArtifact.finding_id.is_(None))
        .all()
    )
    linked = 0
    for artifact in artifacts:
        best = _best_finding_match(artifact, findings, job)
        if not best:
            continue
        artifact.finding_id = best.id
        artifact.validation_status = _artifact_status_for_finding(artifact, best)
        db.add(artifact)
        linked += 1
    db.flush()
    return {"scan_id": job.id, "unlinked_seen": len(artifacts), "linked": linked}


def apply_finding_validation(db: Session, finding: Finding) -> ValidationDecision:
    decision = evaluate_finding_promotion(db, finding)
    details = dict(finding.details or {})
    details["validation_decision"] = decision.to_dict()
    details["proof_pack_required"] = bool(decision.required_artifacts)
    details["proof_pack_missing"] = list(decision.missing_artifacts)
    finding.verification_status = decision.status
    if decision.severity_cap:
        finding.severity = _cap_severity(str(finding.severity or "info"), decision.severity_cap)
    finding.details = details
    db.add(finding)
    return decision


def build_evidence_readiness(db: Session, job: ScanJob) -> dict[str, Any]:
    link_artifacts_to_findings(db, job)
    findings = db.query(Finding).filter(Finding.scan_job_id == job.id, Finding.is_false_positive.is_(False)).all()
    blockers: list[str] = []
    warnings: list[str] = []
    counts = {"confirmed": 0, "candidate": 0, "hypothesis": 0, "refuted": 0}
    for finding in findings:
        decision = evaluate_finding_promotion(db, finding)
        counts[decision.status] = counts.get(decision.status, 0) + 1
        severity = str(finding.severity or "info").lower()
        if severity in HIGH_IMPACT_SEVERITIES and not decision.can_promote:
            blockers.append(f"F-{finding.id}: {finding.title} missing {', '.join(decision.missing_artifacts or ['validation'])}")
        elif not decision.can_promote:
            warnings.append(f"F-{finding.id}: {finding.title} remains {decision.status}")
    return {
        "scan_id": job.id,
        "counts": counts,
        "blockers": blockers,
        "warnings": warnings,
        "ready": not blockers,
    }


def _artifact_has_repro_pair(artifact: EvidenceArtifact) -> bool:
    metadata = dict(artifact.artifact_metadata or {})
    return bool(
        artifact.baseline_request
        and artifact.exploit_request
        and (artifact.baseline_response_ref or metadata.get("baseline_response"))
        and (artifact.exploit_response_ref or metadata.get("exploit_response"))
    )


def _steps_from_result(result: dict[str, Any]) -> list[str]:
    command = str(result.get("command") or "")
    target = str(result.get("target") or "")
    steps = []
    if target:
        steps.append(f"Target: {target}")
    if command:
        steps.append(f"Run: {command}")
    if result.get("evidence_path"):
        steps.append(f"Review evidence path: {result.get('evidence_path')}")
    return steps


def _cap_severity(severity: str, cap: str) -> str:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if order.get(severity.lower(), 0) > order.get(cap.lower(), 4):
        return cap.lower()
    return severity.lower()


def _best_finding_match(artifact: EvidenceArtifact, findings: list[Finding], job: ScanJob) -> Finding | None:
    artifact_tool = str(artifact.tool_name or "").strip().lower()
    artifact_target_tokens = _target_tokens(artifact.target or "", job.target_query)
    best: tuple[int, Finding] | None = None
    for finding in findings:
        score = 0
        finding_tool = str(finding.tool or (finding.details or {}).get("tool") or "").strip().lower()
        if artifact_tool and finding_tool and artifact_tool == finding_tool:
            score += 4
        elif artifact_tool and finding_tool and (artifact_tool in finding_tool or finding_tool in artifact_tool):
            score += 2
        finding_tokens = _target_tokens(
            " ".join(
                str(v or "")
                for v in [
                    finding.domain,
                    finding.url,
                    (finding.details or {}).get("target"),
                    (finding.details or {}).get("url"),
                    (finding.details or {}).get("asset"),
                    (finding.details or {}).get("matched-at"),
                ]
            ),
            job.target_query,
        )
        if artifact_target_tokens & finding_tokens:
            score += 4
        if artifact.phase_id and str((finding.details or {}).get("phase_id") or "") == artifact.phase_id:
            score += 1
        if score >= 4 and (best is None or score > best[0]):
            best = (score, finding)
    return best[1] if best else None


def _artifact_status_for_finding(artifact: EvidenceArtifact, finding: Finding) -> str:
    if str(artifact.validation_status or "") == "confirmed":
        return "confirmed"
    status = str(finding.verification_status or (finding.details or {}).get("verification_status") or "candidate")
    if status == "confirmed":
        return "confirmed"
    return str(artifact.validation_status or "candidate")


def _target_tokens(*values: str) -> set[str]:
    from urllib.parse import urlparse

    tokens: set[str] = set()
    for value in values:
        raw = str(value or "").strip().lower()
        if not raw:
            continue
        tokens.add(raw)
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        if parsed.hostname:
            tokens.add(parsed.hostname.lower())
        if parsed.netloc:
            tokens.add(parsed.netloc.lower())
    return {token for token in tokens if token}
