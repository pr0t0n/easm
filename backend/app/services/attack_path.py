"""Evidence-aware attack paths across assets, hypotheses and crown jewels."""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy.orm import Session

from app.services.attack_path_correlation import correlate_attack_signals
from app.services.framework_mapping import FAMILY_ATTACK, _TACTIC_NAME
from app.services.vuln_family import classify_family, family_label


STAGE_TACTICS = {
    "credential_access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "initial_access": ("TA0001", "Initial Access"),
    "collection": ("TA0009", "Collection"),
    "lateral_movement": ("TA0008", "Lateral Movement"),
    "privilege_escalation": ("TA0004", "Privilege Escalation"),
    "execution": ("TA0002", "Execution"),
    "impact": ("TA0040", "Impact"),
}


def build_attack_paths(db: Session, scan_id: int, job=None, max_paths: int = 20) -> dict:
    from app.models.models import EvidenceArtifact, Finding, OffensiveHypothesis, ScanJob

    if job is None:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if job is None:
        return {"scan_id": scan_id, "objectives_total": 0, "paths_with_findings": 0, "objectives_reachable": 0, "paths": []}

    artifacts_by_finding: dict[int, list[str]] = defaultdict(list)
    for artifact in db.query(EvidenceArtifact).filter(EvidenceArtifact.scan_job_id == scan_id).all():
        if artifact.finding_id is not None:
            artifacts_by_finding[int(artifact.finding_id)].append(str(artifact.id))

    signals: list[dict] = []
    findings = (
        db.query(Finding)
        .filter(Finding.scan_job_id == scan_id, Finding.is_false_positive.is_(False))
        .all()
    )
    for finding in findings:
        details = dict(finding.details or {})
        family = classify_family(
            title=finding.title,
            tool=finding.tool,
            owasp=str(details.get("owasp_category") or ""),
            cve=finding.cve,
            learning_family=(details.get("learning_source") or {}).get("vuln_family"),
        )
        signals.append({
            "id": f"F-{finding.id}",
            "family": family,
            "target": finding.url or finding.domain or details.get("target") or "",
            "title": finding.title,
            "severity": finding.severity,
            "verification_status": finding.verification_status,
            "confidence_score": finding.confidence_score,
            "evidence_ids": artifacts_by_finding.get(int(finding.id), []),
        })

    hypotheses = db.query(OffensiveHypothesis).filter(OffensiveHypothesis.scan_job_id == scan_id).all()
    for hypothesis in hypotheses:
        signals.append({
            "id": f"H-{hypothesis.id}",
            "family": hypothesis.hypothesis_type,
            "target": hypothesis.target_ref,
            "title": hypothesis.title,
            "status": hypothesis.status,
            "confidence": hypothesis.confidence,
            "evidence_ids": [],
        })

    state = dict(job.state_data or {})
    objectives = list(state.get("crown_jewels") or [])
    paths = correlate_attack_signals(signals, objectives, max_paths=max_paths)
    for path in paths:
        max_rank = 9
        for step in path["steps"]:
            family = str(step.get("family") or "")
            framework = FAMILY_ATTACK.get(family) or {}
            tactic, tactic_name = STAGE_TACTICS.get(str(step.get("stage") or ""), ("", str(step.get("stage") or "")))
            step["tactic"] = framework.get("tactic") or tactic
            step["tactic_name"] = _TACTIC_NAME.get(step["tactic"], tactic_name)
            step["technique"] = framework.get("technique") or "evidence-correlation"
            step["family_label"] = family_label(family) if family in FAMILY_ATTACK else str(step.get("description") or family)
            severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(step.get("severity") or ""), 9)
            max_rank = min(max_rank, severity_rank)
        path["max_severity"] = max_rank

    return {
        "scan_id": scan_id,
        "objectives_total": len([row for row in objectives if isinstance(row, dict) and (row.get("target") or row.get("subdomain"))]),
        "paths_with_findings": len(paths),
        "objectives_reachable": sum(1 for path in paths if path.get("objective_reachable")),
        "paths": paths,
    }
