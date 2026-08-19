"""Backend-local control operations for the mandatory P18-P22 phases.

These operations analyse already collected, redacted platform evidence.  They
do not send traffic to the target.  Keeping them as real tool executions makes
the phase ledger auditable without pretending that a ``printf`` profile
performed evidence review, attack-path correlation, or report generation.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from app.db.session import SessionLocal
from app.models.models import EvidenceArtifact, Finding, ScanJob


def run_phase_control_tool(tool_name: str, scan_id: int, target: str) -> dict[str, Any]:
    handlers = {
        "credential-boundary-review": _credential_boundary_review,
        "post-exploitation-boundary-review": _post_exploitation_boundary_review,
        "attack-path-correlator": _attack_path_correlator,
        "evidence-adjudicator": _evidence_adjudicator,
        "report-snapshot-builder": _report_snapshot_builder,
    }
    handler = handlers.get(str(tool_name or "").strip().lower())
    if handler is None:
        return {"status": "blocked", "error": f"unknown_phase_control_tool:{tool_name}"}
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == int(scan_id)).first()
        if job is None:
            return {"status": "failed", "error": "scan_not_found"}
        parsed = handler(db, job, target)
        db.commit()
        return {
            "status": "success",
            "exit_code": 0,
            "stdout": json.dumps(parsed, ensure_ascii=False, default=str)[:10_000],
            "stderr": "",
            "parsed": {
                **parsed,
                "reproducible": True,
                "request_response_pair": True,
                "control_operation": True,
            },
            "command": f"backend-control {tool_name} --scan-id {scan_id}",
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        return {"status": "failed", "exit_code": 1, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()


def _target_matches(finding: Finding, target: str) -> bool:
    if not target:
        return True
    haystack = " ".join(
        str(value or "").lower()
        for value in (finding.domain, finding.url, (finding.details or {}).get("target"))
    )
    needle = str(target).lower().split("://", 1)[-1].split("/", 1)[0]
    return not needle or needle in haystack


def _credential_boundary_review(db: Any, job: ScanJob, target: str) -> dict[str, Any]:
    findings = [
        row for row in db.query(Finding).filter(Finding.scan_job_id == job.id).all()
        if _target_matches(row, target)
    ]
    secret_findings = [
        row for row in findings
        if any(token in f"{row.title} {row.tool}".lower() for token in ("secret", "credential", "token", "gitleaks", "trufflehog"))
    ]
    artifacts = db.query(EvidenceArtifact).filter(EvidenceArtifact.scan_job_id == job.id).all()
    unredacted_markers = []
    for artifact in artifacts:
        blob = json.dumps(
            {
                "baseline": artifact.baseline_request,
                "attempt": artifact.exploit_request,
                "metadata": artifact.artifact_metadata,
            },
            default=str,
        ).lower()
        if any(marker in blob for marker in ("bearer eyj", "-----begin private key-----", "akia")):
            unredacted_markers.append(artifact.id)
    state = dict(job.state_data or {})
    summary = {
        "phase_id": "P18",
        "boundary": "discover_and_fingerprint_only_no_credential_reuse",
        "secret_finding_count": len(secret_findings),
        "unredacted_artifact_ids": unredacted_markers[:50],
        "boundary_satisfied": not unredacted_markers,
        "credential_reuse_executed": False,
        "reviewed_at": datetime.utcnow().isoformat() + "Z",
    }
    state["credential_boundary_review"] = summary
    job.state_data = state
    db.add(job)
    return summary


def _post_exploitation_boundary_review(db: Any, job: ScanJob, target: str) -> dict[str, Any]:
    confirmed = [
        row for row in db.query(Finding).filter(
            Finding.scan_job_id == job.id,
            Finding.verification_status == "confirmed",
            Finding.is_false_positive.is_(False),
        ).all()
        if _target_matches(row, target)
    ]
    projected = [
        {
            "finding_id": row.id,
            "title": row.title,
            "demonstrated": "minimal_proof_only",
            "projected_impact": (row.details or {}).get("business_impact") or (row.details or {}).get("impact") or "review required",
        }
        for row in confirmed[:100]
    ]
    state = dict(job.state_data or {})
    summary = {
        "phase_id": "P19",
        "boundary": "model_impact_without_defacement_pollution_dump_persistence_or_pivot",
        "confirmed_inputs": len(confirmed),
        "impact_projections": projected,
        "post_exploitation_actions_executed": False,
        "boundary_satisfied": True,
        "reviewed_at": datetime.utcnow().isoformat() + "Z",
    }
    state["post_exploitation_boundary_review"] = summary
    job.state_data = state
    db.add(job)
    return summary


def _attack_path_correlator(db: Any, job: ScanJob, target: str) -> dict[str, Any]:
    from app.services.attack_path_correlation import correlate_attack_signals
    from app.services.vuln_family import classify_family

    findings = [
        row for row in db.query(Finding).filter(
            Finding.scan_job_id == job.id,
            Finding.verification_status == "confirmed",
            Finding.is_false_positive.is_(False),
        ).all()
        if _target_matches(row, target)
    ]
    artifact_rows = db.query(EvidenceArtifact).filter(EvidenceArtifact.scan_job_id == job.id).all()
    evidence_by_finding: dict[int, list[str]] = {}
    for artifact in artifact_rows:
        if artifact.finding_id:
            evidence_by_finding.setdefault(int(artifact.finding_id), []).append(str(artifact.id))
    signals = [
        {
            "id": f"finding:{row.id}",
            "family": classify_family(title=row.title, tool=row.tool, cve=row.cve),
            "target": row.url or row.domain or target,
            "title": row.title,
            "severity": row.severity,
            "verification_status": "confirmed",
            "confidence_score": row.confidence_score or 0,
            "evidence_ids": evidence_by_finding.get(int(row.id), []),
        }
        for row in findings
    ]
    objectives = list((job.state_data or {}).get("crown_jewels") or [])
    paths = correlate_attack_signals(signals, objectives=objectives, max_paths=20)
    concise_paths = [
        {
            "attack_path_id": row.get("attack_path_id"),
            "objective": row.get("objective"),
            "status": row.get("status"),
            "confidence": row.get("confidence"),
            "steps": row.get("steps"),
            "next_actions": row.get("next_actions"),
        }
        for row in paths
    ]
    state = dict(job.state_data or {})
    state["attack_paths_v2"] = concise_paths
    state["attack_path_correlation"] = {
        "version": 2,
        "confirmed_findings_used": len(findings),
        "signals_with_evidence": sum(1 for signal in signals if signal["evidence_ids"]),
        "paths": len(concise_paths),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    job.state_data = state
    db.add(job)
    return {"phase_id": "P20", **state["attack_path_correlation"], "attack_paths": concise_paths}


def _evidence_adjudicator(db: Any, job: ScanJob, target: str) -> dict[str, Any]:
    from app.services.evidence_contract_service import apply_finding_validation, build_evidence_readiness, link_artifacts_to_findings

    link_result = link_artifacts_to_findings(db, job)
    findings = [
        row for row in db.query(Finding).filter(Finding.scan_job_id == job.id).all()
        if _target_matches(row, target)
    ]
    decisions: dict[str, int] = {}
    for finding in findings:
        decision = apply_finding_validation(db, finding)
        decisions[decision.status] = decisions.get(decision.status, 0) + 1
    readiness = build_evidence_readiness(db, job)
    state = dict(job.state_data or {})
    summary = {
        "phase_id": "P21",
        "findings_reviewed": len(findings),
        "decisions": decisions,
        "artifacts_linked": link_result.get("linked", 0),
        "ready": bool(readiness.get("ready")),
        "blockers": list(readiness.get("blockers") or [])[:100],
        "reviewed_at": datetime.utcnow().isoformat() + "Z",
    }
    state["evidence_adjudication_v2"] = summary
    job.state_data = state
    db.add(job)
    return summary


def _report_snapshot_builder(db: Any, job: ScanJob, target: str) -> dict[str, Any]:
    import hashlib

    from app.services.artifact_store import write_artifact_file
    from app.services.pentest_report_builder import build_pentest_report_contract

    report = build_pentest_report_contract(db, job)
    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True, default=str)
    snapshot_path = write_artifact_file(job.id, "pentest-report-snapshot", report)
    state = dict(job.state_data or {})
    snapshot = {
        "version": 2,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "readiness": report.get("readiness"),
        "methodology": report.get("methodology"),
        "finding_counts": {key: len(value) for key, value in dict(report.get("findings") or {}).items()},
        "artifact_path": snapshot_path,
        "sha256": hashlib.sha256(serialized.encode()).hexdigest(),
    }
    state["report_snapshot_v2"] = snapshot
    job.state_data = state
    db.add(job)
    return {
        "phase_id": "P22",
        "snapshot_version": 2,
        "generated_at": snapshot["generated_at"],
        "readiness": snapshot["readiness"],
        "finding_counts": snapshot["finding_counts"],
        "artifact_path": snapshot_path,
        "sha256": snapshot["sha256"],
        "snapshot_persisted": True,
    }
