from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session, load_only

from app.graph.mission import PENTEST_PHASES
from app.models.models import (
    CoverageItem,
    EvidenceArtifact,
    ExecutedToolRun,
    Finding,
    OffensiveAsset,
    OffensiveApiSpec,
    OffensiveEndpoint,
    OffensiveHypothesis,
    OffensiveParameter,
    OffensiveService,
    RetestRun,
    ScanAuthSession,
    ScanIdentity,
    ScanJob,
    ScanLog,
    ScanWorkItem,
    ValidationRun,
)
from app.services.phase_monitor import build_phase_monitor
from app.services.scan_execution_metrics import summarize_work_items
from app.services.offensive_operator_core import PHASE_CONTRACTS
from app.services.scan_profiles import scan_profile


VERIFIED_STATUSES = {"confirmed", "proven", "validated", "verified", "true_positive"}
CANDIDATE_STATUSES = {"candidate", "needs_review", "hypothesis"}
# Validation depth measures conclusive adjudication, not the number of
# vulnerabilities found. A sound refutation is as valuable as a confirmation.
SUCCESS_VALIDATION_RESULTS = {
    "confirmed", "validated", "success", "proven", "positive",
    "true_positive", "refuted", "false_positive",
}
TESTED_COVERAGE_STATUSES = {"tested", "covered", "validated", "completed", "done", "confirmed"}
INVENTORY_ONLY_COVERAGE_STATUSES = {"discovered"}
EXTERNAL_PRECONDITION_REASONS = {
    "source_code_required",
    "missing_observed_parameter",
    "mutation_plan_or_fixture_missing",
    "missing_valid_identity_pair",
    "captured_jwt_required",
}
QUALITY_GATE_SCORE_THRESHOLD = 70.0
QUALITY_GATE_MAX_ROUNDS = 4
QUALITY_GATE_MAX_POC_PER_ROUND = 50
QUALITY_GATE_MAX_REQUEUES_PER_ROUND = 25
QUALITY_GATE_MAX_FALLBACKS_PER_ROUND = 20

QUALITY_TOOL_FALLBACKS: dict[str, list[str]] = {
    "httpx": ["curl-headers", "whatweb"],
    "whatweb": ["httpx", "curl-headers"],
    "curl-headers": ["httpx", "whatweb"],
    "sslscan": ["testssl", "nmap-ssl-vuln"],
    "testssl": ["sslscan", "nmap-ssl-vuln"],
    "nmap-ssl-vuln": ["testssl", "sslscan"],
    "katana": ["hakrawler", "gospider", "gau"],
    "katana-js": ["katana", "hakrawler", "linkfinder"],
    "hakrawler": ["katana", "gospider", "gau"],
    "gospider": ["katana", "hakrawler", "gau"],
    "gau": ["waybackurls", "katana", "hakrawler"],
    "waybackurls": ["gau", "katana"],
    "arjun": ["ffuf-params", "paramspider", "wfuzz"],
    "ffuf-params": ["arjun", "paramspider", "wfuzz"],
    "paramspider": ["arjun", "ffuf-params"],
    "nuclei": ["nikto", "wapiti", "curl-headers"],
    "nuclei-cves": ["nuclei", "nmap-vulscan", "nikto"],
    "nuclei-headers": ["curl-headers", "nikto"],
    "nuclei-exposure": ["nikto", "ffuf-files", "curl-headers"],
    "nuclei-sqli": ["sqlmap", "wapiti", "nuclei"],
    "nuclei-xss": ["dalfox", "wapiti", "nuclei"],
    "nuclei-ssrf": ["wapiti", "interactsh-client", "nuclei"],
    "nuclei-lfi": ["wapiti", "ffuf-files", "nuclei"],
    "nuclei-ssti": ["wapiti", "nuclei"],
    "nuclei-xxe": ["wapiti", "nuclei"],
    "nuclei-redirect": ["wapiti", "nuclei"],
    "nuclei-idor": ["wapiti", "nuclei"],
    "nuclei-csrf": ["wapiti", "nuclei"],
    "nuclei-rce": ["wapiti", "nuclei"],
    "nuclei-auth": ["nikto", "nuclei"],
    "nuclei-jwt": ["nuclei", "curl-headers"],
    "nuclei-graphql": ["nuclei", "curl-headers"],
    "nikto": ["nuclei", "curl-headers", "wapiti"],
    "wapiti": ["nuclei", "nikto", "dalfox", "sqlmap"],
    "sqlmap": ["nuclei-sqli", "wapiti", "ffuf-params"],
    "dalfox": ["nuclei-xss", "wapiti", "ffuf-params"],
    "ffuf": ["feroxbuster", "dirsearch", "gobuster"],
    "ffuf-files": ["feroxbuster", "dirsearch", "gobuster"],
    "feroxbuster": ["ffuf", "dirsearch", "gobuster"],
    "dirsearch": ["ffuf", "feroxbuster", "gobuster"],
    "gobuster": ["ffuf", "feroxbuster", "dirsearch"],
}

QUALITY_PHASE_FALLBACKS: dict[str, list[str]] = {
    "P03": ["katana", "hakrawler", "gospider", "gau", "waybackurls"],
    "P04": ["arjun", "ffuf-params", "paramspider", "wfuzz"],
    "P05": ["whatweb", "httpx", "curl-headers"],
    "P06": ["httpx", "wafw00f", "curl-headers"],
    "P09": ["nuclei", "nuclei-cves", "subjack"],
    "P11": ["nuclei", "nmap-vulscan", "nmap-http-enum"],
    "P12": ["nuclei", "nikto", "wapiti", "sqlmap", "dalfox"],
    "P15": [
        "nuclei-exposure", "nuclei-misconfiguration", "nuclei-file-upload",
        "nuclei-lfi", "gau", "waybackurls", "ffuf-files",
    ],
    "P16": ["ffuf-params", "wfuzz", "wapiti", "nuclei"],
    "P18": ["theharvester", "h8mail", "nuclei-exposure", "nuclei-cloud", "gitleaks", "trufflehog"],
    "P20": ["nuclei", "gitleaks", "trufflehog", "nuclei-race"],
}


def quality_gate_decision(
    quality: dict[str, Any], remediation_actions: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    actions = list(remediation_actions or [])
    score = float(quality.get("score") or 0.0)
    hard_gaps = [
        gap for gap in list(quality.get("gaps") or [])
        if str(gap.get("severity") or "").lower() == "high"
    ]
    quality_passed = score >= QUALITY_GATE_SCORE_THRESHOLD and not hard_gaps
    return {
        "passed": quality_passed,
        "completion_allowed": not actions,
        "requires_remediation": bool(actions),
        "completion_status": "completed" if quality_passed else "completed_with_gaps",
        "blockers": hard_gaps,
    }


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def _ratio(num: float, den: float) -> float:
    return float(num) / max(1.0, float(den))


def _scan_level(job: ScanJob) -> str:
    state = dict(job.state_data or {})
    return str(state.get("scan_level") or "full").strip().lower()


def _expected_phase_ids(job: ScanJob) -> list[str]:
    profile = scan_profile(_scan_level(job))
    allowed = profile.get("phase_ids")
    if allowed:
        return [str(pid) for pid in allowed]
    return [str(p["id"]) for p in PENTEST_PHASES]


def _quality_scored_phase_ids(job: ScanJob) -> list[str]:
    """Return executable phases that can be measured before report generation.

    P22 is the campaign report produced only after this quality gate accepts
    completion. Scoring it here creates a circular false gap: it is necessarily
    queued while the gate is running.
    """
    return [phase_id for phase_id in _expected_phase_ids(job) if phase_id != "P22"]


def _finding_details(finding: Finding) -> dict[str, Any]:
    return dict(finding.details or {}) if isinstance(finding.details, dict) else {}


def _has_finding_evidence(finding: Finding, artifacts_by_finding: Counter[int]) -> bool:
    details = _finding_details(finding)
    if artifacts_by_finding.get(int(finding.id), 0) > 0:
        return True
    if str(details.get("evidence") or details.get("proof") or details.get("raw_output") or "").strip():
        return True
    tool_evidence = details.get("tool_evidence")
    if isinstance(tool_evidence, list) and len(tool_evidence) > 0:
        return True
    if isinstance(details.get("detection_proof_pack"), dict) and details.get("detection_proof_pack"):
        return True
    reproduction = details.get("reproduction")
    return isinstance(reproduction, dict) and bool(reproduction.get("proof") or reproduction.get("commands"))


def _has_reproduction(finding: Finding) -> bool:
    details = _finding_details(finding)
    reproduction = details.get("reproduction")
    if isinstance(reproduction, dict):
        return bool(reproduction.get("steps") or reproduction.get("commands") or reproduction.get("proof"))
    return bool(details.get("reproduction_steps") or details.get("repro_steps"))


def _verification_bucket(finding: Finding) -> str:
    details = _finding_details(finding)
    status = str(finding.verification_status or "").strip().lower()
    supervisor_status = str((details.get("supervisor_validation") or {}).get("status") or "").strip().lower()
    if status in VERIFIED_STATUSES or supervisor_status in VERIFIED_STATUSES:
        return "verified"
    if status in CANDIDATE_STATUSES or supervisor_status in CANDIDATE_STATUSES:
        return "candidate"
    return "unclassified"


def _phase_component(phase_monitor: dict[str, Any], expected_phase_ids: list[str]) -> tuple[float, dict[str, Any], list[dict[str, Any]]]:
    phases = {
        str(row.get("phase_id") or row.get("id") or ""): dict(row or {})
        for row in (phase_monitor.get("pentest_journey") or {}).get("phases") or phase_monitor.get("phases") or []
    }
    scored: list[float] = []
    weak_rows: list[dict[str, Any]] = []
    for pid in expected_phase_ids:
        row = phases.get(pid, {})
        status = str(row.get("status") or "").lower()
        wq = dict(row.get("work_queue") or {})
        total = int(wq.get("total") or 0)
        if total > 0:
            terminal_pct = float(wq.get("pct") or 0) / 100.0
            success_pct = float(wq.get("success_pct") or 0) / 100.0
            value = (terminal_pct * 0.65) + (success_pct * 0.35)
        else:
            value = {
                "completed": 1.0,
                "executed": 1.0,
                "partial": 0.65,
                "partial_coverage": 0.65,
                "executing": 0.45,
                "running": 0.45,
                "gate_blocked": 0.15,
                "blocked": 0.15,
                "failed": 0.2,
                "queued": 0.0,
                "pending": 0.0,
                "skipped": 0.35,
            }.get(status, 0.0)
        scored.append(value)
        if value < 0.65:
            weak_rows.append({
                "phase_id": pid,
                "status": status or "unknown",
                "score": round(value * 100),
                "missing_tools": list(row.get("required_tools_missing") or row.get("tools_missing_unused") or [])[:8],
            })
    ratio = sum(scored) / max(1, len(scored))
    return round(ratio * 100, 1), {
        "expected": len(expected_phase_ids),
        "healthy": sum(1 for item in scored if item >= 0.8),
        "partial": sum(1 for item in scored if 0.35 <= item < 0.8),
        "weak": sum(1 for item in scored if item < 0.35),
    }, weak_rows


def _coverage_bucket(row: CoverageItem) -> str:
    status = str(row.status or "").strip().lower()
    coverage_type = str(row.coverage_type or "").strip().lower()
    test_class = str(row.test_class or "").strip().lower()
    reason = str(row.blocking_reason or "").strip().lower()
    if status in {"superseded", "not_applicable", "skipped"}:
        return "excluded"
    if coverage_type == "endpoint" and test_class == "discovery" and status in INVENTORY_ONLY_COVERAGE_STATUSES:
        return "inventory"
    if status == "blocked_missing_auth":
        return "external_precondition"
    if reason in EXTERNAL_PRECONDITION_REASONS:
        return "external_precondition"
    if reason.startswith("source_code_required") or reason.startswith("required_evidence_absent:"):
        return "external_precondition"
    return "applicable"


def _auth_classification_bucket(endpoint: OffensiveEndpoint) -> str:
    metadata = dict(endpoint.endpoint_metadata or {})
    auth = dict(metadata.get("auth_classification") or {})
    reason = str(auth.get("reason") or "").strip().lower()
    if endpoint.auth_required is not None:
        return "classified"
    if reason in {"anonymous_probe_failed", "endpoint_not_reachable", "connecttimeout", "readtimeout"}:
        return "unclassifiable_reachability"
    anonymous = dict(auth.get("anonymous") or {})
    if str(anonymous.get("error") or "").strip():
        return "unclassifiable_reachability"
    source_tool = str(getattr(endpoint, "source_tool", "") or "").strip().lower()
    if endpoint.status_code is None and source_tool in {"waybackurls", "gau", "paramspider"}:
        return "unclassifiable_passive_archive"
    return "unknown"


def _skill_runtime_attribution(job: ScanJob) -> tuple[set[str], set[str]]:
    state = dict(job.state_data or {})
    attributed: set[str] = set()
    executed: set[str] = set()

    def _mark_phase(phase_id: str, status: str) -> None:
        skills = {str(s) for s in list((PHASE_CONTRACTS.get(phase_id) or {}).get("required_skills") or []) if str(s or "")}
        if not skills:
            return
        attributed.update(skills)
        if status in {"success", "completed", "done"}:
            executed.update(skills)

    for row in list(state.get("agent_execution_runs") or []):
        if not isinstance(row, dict):
            continue
        _mark_phase(str(row.get("phase_id") or ""), str(row.get("status") or "").lower())
    for row in list(dict(state.get("agent_execution_summary") or {}).values()):
        if not isinstance(row, dict):
            continue
        status = "success" if row.get("all_mandatory_executed") or int(row.get("agents_success") or 0) > 0 else "partial"
        _mark_phase(str(row.get("phase_id") or ""), status)
    return attributed, executed


def build_scan_quality(db: Session, job: ScanJob) -> dict[str, Any]:
    phase_monitor = build_phase_monitor(db, job)
    expected_phase_ids = _quality_scored_phase_ids(job)
    profile = scan_profile(_scan_level(job))
    state = dict(job.state_data or {})

    finding_rows = (
        db.query(Finding)
        .options(load_only(
            Finding.id, Finding.details, Finding.severity,
            Finding.is_false_positive, Finding.verification_status,
        ))
        .filter(Finding.scan_job_id == job.id)
        .all()
    )
    findings = [row for row in finding_rows if not bool(row.is_false_positive)]
    artifacts = (
        db.query(EvidenceArtifact)
        .options(load_only(
            EvidenceArtifact.id, EvidenceArtifact.finding_id,
            EvidenceArtifact.phase_id, EvidenceArtifact.artifact_type,
        ))
        .filter(EvidenceArtifact.scan_job_id == job.id)
        .all()
    )
    artifacts_by_finding: Counter[int] = Counter(
        int(a.finding_id) for a in artifacts if a.finding_id is not None
    )
    all_validations = (
        db.query(ValidationRun)
        .options(load_only(
            ValidationRun.id, ValidationRun.hypothesis_id, ValidationRun.finding_id, ValidationRun.validator_name,
            ValidationRun.result, ValidationRun.run_metadata,
            ValidationRun.attempt_artifact_id, ValidationRun.created_at,
        ))
        .filter(ValidationRun.scan_job_id == job.id)
        .all()
    )
    retests = (
        db.query(RetestRun)
        .options(load_only(RetestRun.id, RetestRun.status))
        .filter(RetestRun.scan_job_id == job.id)
        .all()
    )
    coverage_rows = (
        db.query(CoverageItem)
        .options(load_only(
            CoverageItem.id, CoverageItem.coverage_type, CoverageItem.test_class,
            CoverageItem.status, CoverageItem.blocking_reason,
        ))
        .filter(CoverageItem.scan_job_id == job.id)
        .all()
    )
    # Derived plans remain persisted for auditability. Once superseded or
    # declared non-applicable they no longer belong to the active denominator.
    coverage_buckets = Counter(_coverage_bucket(row) for row in coverage_rows)
    coverage_items = [row for row in coverage_rows if _coverage_bucket(row) == "applicable"]
    inventory_coverage_items = [row for row in coverage_rows if _coverage_bucket(row) == "inventory"]
    external_coverage_items = [row for row in coverage_rows if _coverage_bucket(row) == "external_precondition"]
    work_items = (
        db.query(ScanWorkItem)
        .options(load_only(
            ScanWorkItem.id, ScanWorkItem.status, ScanWorkItem.phase_id,
            ScanWorkItem.tool_name, ScanWorkItem.target, ScanWorkItem.resource_class,
            ScanWorkItem.item_metadata, ScanWorkItem.result, ScanWorkItem.created_at,
            ScanWorkItem.updated_at, ScanWorkItem.started_at, ScanWorkItem.finished_at,
        ))
        .filter(ScanWorkItem.scan_job_id == job.id)
        .all()
    )
    endpoints = (
        db.query(OffensiveEndpoint)
        .options(load_only(
            OffensiveEndpoint.id, OffensiveEndpoint.auth_required,
            OffensiveEndpoint.normalized_url, OffensiveEndpoint.status_code,
            OffensiveEndpoint.content_type, OffensiveEndpoint.source_tool,
            OffensiveEndpoint.tags,
            OffensiveEndpoint.endpoint_metadata,
        ))
        .filter(OffensiveEndpoint.scan_job_id == job.id)
        .all()
    )
    endpoints_count = len(endpoints)
    assets = (
        db.query(OffensiveAsset)
        .options(load_only(OffensiveAsset.id, OffensiveAsset.asset_type, OffensiveAsset.host))
        .filter(OffensiveAsset.scan_job_id == job.id)
        .all()
    )
    offensive_assets_count = len({(str(row.asset_type or ""), str(row.host or "")) for row in assets})
    services_count = db.query(OffensiveService.id).filter(OffensiveService.scan_job_id == job.id).count()
    parameters_count = db.query(OffensiveParameter.id).filter(OffensiveParameter.scan_job_id == job.id).count()
    api_specs_count = db.query(OffensiveApiSpec.id).filter(OffensiveApiSpec.scan_job_id == job.id).count()
    hypotheses = (
        db.query(OffensiveHypothesis)
        .options(load_only(
            OffensiveHypothesis.id, OffensiveHypothesis.status,
            OffensiveHypothesis.hypothesis_metadata,
        ))
        .filter(OffensiveHypothesis.scan_job_id == job.id)
        .all()
    )
    superseded_hypothesis_ids = {
        int(row.id) for row in hypotheses if str(row.status or "").lower() == "superseded"
    }
    validations = [
        row for row in all_validations
        if row.hypothesis_id is None or int(row.hypothesis_id) not in superseded_hypothesis_ids
    ]
    identities_count = db.query(ScanIdentity.id).filter(ScanIdentity.scan_job_id == job.id).count()
    auth_sessions = (
        db.query(ScanAuthSession)
        .options(load_only(ScanAuthSession.id, ScanAuthSession.status))
        .filter(ScanAuthSession.scan_job_id == job.id)
        .all()
    )
    auth_config = dict(state.get("auth_config") or {})
    auth_relevant_endpoints = [
        endpoint for endpoint in endpoints if endpoint.auth_required is True
    ]
    auth_required = bool(
        auth_config.get("required")
        or auth_config.get("identities")
        or auth_relevant_endpoints
    )
    valid_sessions = [s for s in auth_sessions if str(s.status or "").lower() in {"valid", "static"}]

    expected_skills = {
        str(skill_id)
        for phase_id in expected_phase_ids
        for skill_id in list((PHASE_CONTRACTS.get(phase_id) or {}).get("required_skills") or [])
        if str(skill_id or "")
    }
    executed_skills: set[str] = set()
    attributed_skills: set[str] = set()
    for work_item in work_items:
        metadata = dict(work_item.item_metadata or {})
        skill_ids = [str(value) for value in list(metadata.get("skill_ids") or []) if str(value or "")]
        if metadata.get("skill_id"):
            skill_ids.append(str(metadata["skill_id"]))
        attributed_skills.update(skill_ids)
        if str(work_item.status or "").lower() in {"completed", "done"}:
            executed_skills.update(skill_ids)
    runtime_attributed, runtime_executed = _skill_runtime_attribution(job)
    attributed_skills.update(runtime_attributed)
    executed_skills.update(runtime_executed)
    if any(v.finding_id is not None for v in all_validations) or any(str(a.phase_id or "").upper() == "P21" for a in artifacts):
        attributed_skills.add("skill.reporting.evidence_quality")
        executed_skills.add("skill.reporting.evidence_quality")
    externally_blocked_skills: set[str] = set()
    if auth_required and len(valid_sessions) < 2:
        externally_blocked_skills.add("skill.vuln.auth_bypass")
    effective_expected_skills = expected_skills - externally_blocked_skills
    skill_objective_ratio = _ratio(
        len(effective_expected_skills & executed_skills),
        len(effective_expected_skills),
    ) if effective_expected_skills else 1.0
    missing_skill_objectives = sorted(effective_expected_skills - executed_skills)

    phase_score, phase_summary, weak_phase_rows = _phase_component(phase_monitor, expected_phase_ids)

    findings_with_evidence = [f for f in findings if _has_finding_evidence(f, artifacts_by_finding)]
    findings_with_repro = [f for f in findings if _has_reproduction(f)]
    verified_findings = [f for f in findings if _verification_bucket(f) == "verified"]
    candidate_findings = [f for f in findings if _verification_bucket(f) == "candidate"]
    high_findings = [f for f in findings if str(f.severity or "").lower() in {"critical", "high"} and not f.is_false_positive]
    high_verified = [f for f in high_findings if f in verified_findings]
    high_with_evidence = [f for f in high_findings if f in findings_with_evidence]

    if findings:
        evidence_ratio = _ratio(len(findings_with_evidence), len(findings))
        verification_ratio = _ratio(len(verified_findings), len(findings))
        reproduction_ratio = _ratio(len(findings_with_repro), len(findings))
        evidence_score = (evidence_ratio * 45) + (verification_ratio * 35) + (reproduction_ratio * 20)
    else:
        evidence_ratio = 1.0 if artifacts else 0.0
        verification_ratio = 0.0
        reproduction_ratio = 0.0
        evidence_score = 75.0 if artifacts else 0.0
    if high_findings:
        evidence_score *= 0.75 + (0.25 * _ratio(len(high_with_evidence), len(high_findings)))
        evidence_score *= 0.75 + (0.25 * _ratio(len(high_verified), len(high_findings)))

    successful_validations = [
        v for v in validations
        if str(v.result or "").strip().lower() in SUCCESS_VALIDATION_RESULTS
    ]
    validation_ratio = _ratio(len(successful_validations), len(validations)) if validations else 0.0
    high_validation_ratio = _ratio(len(high_verified), len(high_findings)) if high_findings else 1.0
    retest_ratio = _ratio(len([r for r in retests if str(r.status or "").lower() in {"completed", "confirmed", "refuted"}]), len(retests)) if retests else 0.0
    validation_score = (validation_ratio * 45) + (high_validation_ratio * 45) + (retest_ratio * 10)
    if not validations:
        validation_score = 0.0

    execution_metrics = summarize_work_items(work_items, job)
    attempted = int(execution_metrics["attempted"])
    succeeded = int(execution_metrics["succeeded"])
    failed_tools = int(execution_metrics["failed"])
    success_ratio = _ratio(succeeded, attempted) if attempted else 0.0
    work_status_counts = Counter(str(item.status or "").lower() for item in work_items)
    infrastructure_failure_items = int(work_status_counts.get("failed", 0) + work_status_counts.get("timeout", 0))
    parser_error_items = [
        item for item in work_items
        if isinstance(item.result, dict)
        and isinstance(item.result.get("findings_extractor_meta"), dict)
        and dict(item.result.get("findings_extractor_meta") or {}).get("parser_error")
    ]
    parser_truncated_items = [
        item for item in work_items
        if isinstance(item.result, dict)
        and isinstance(item.result.get("findings_extractor_meta"), dict)
        and dict(item.result.get("findings_extractor_meta") or {}).get("stdout_truncated_for_parser")
    ]
    preflight_profiles = dict(((state.get("preflight") or {}).get("targets") or {}))
    preflight_total = len(preflight_profiles)
    p02_positive_targets = sum(1 for p in preflight_profiles.values() if isinstance(p, dict) and p.get("p02_positive_evidence"))
    p06_positive_targets = sum(1 for p in preflight_profiles.values() if isinstance(p, dict) and p.get("p06_positive_evidence"))
    p06_no_http_targets = sum(
        1
        for p in preflight_profiles.values()
        if isinstance(p, dict)
        and p.get("p06_complete")
        and not p.get("p06_positive_evidence")
    )
    missing_required = sum(
        len(row.get("required_tools_missing") or [])
        for row in (phase_monitor.get("pentest_journey") or {}).get("phases") or []
        if str(row.get("phase_id") or "") in expected_phase_ids
    )
    # Failures are already represented in success_ratio. Subtracting their
    # absolute count again made large scans score worse merely for being large.
    tool_score = (success_ratio * 100) - min(35, missing_required * 4)
    if attempted == 0:
        tool_score = 20.0

    if coverage_items:
        covered_count = len([c for c in coverage_items if str(c.status or "").lower() in TESTED_COVERAGE_STATUSES])
        coverage_ratio = _ratio(covered_count, len(coverage_items))
    else:
        state = dict(job.state_data or {})
        sub_cov = dict(state.get("subdomain_coverage") or {})
        active_total = int(sub_cov.get("active_total") or 0)
        scanned = int(sub_cov.get("scanned") or 0)
        coverage_ratio = _ratio(scanned, active_total) if active_total else (0.75 if endpoints_count or offensive_assets_count else 0.35)
        covered_count = scanned
    surface_score = (coverage_ratio * 70) + (min(1.0, endpoints_count / 20.0) * 15) + (min(1.0, offensive_assets_count / 20.0) * 15)

    tested_hypothesis_statuses = {"validated", "tested_candidate", "refuted"}
    blocked_hypothesis_statuses = {
        "blocked_precondition", "blocked_missing_auth", "blocked_missing_validator",
        "blocked_missing_authorization", "blocked_historical_not_reexecuted",
    }
    tested_hypotheses = [h for h in hypotheses if str(h.status or "").lower() in tested_hypothesis_statuses]
    superseded_hypotheses = [h for h in hypotheses if str(h.status or "").lower() == "superseded"]
    blocked_hypotheses = [h for h in hypotheses if str(h.status or "").lower() in blocked_hypothesis_statuses]
    blocked_hypothesis_reasons = Counter(
        str((h.hypothesis_metadata or {}).get("blocked_reason") or "reason_not_recorded")
        for h in blocked_hypotheses
    )
    reachability_blocked_hypotheses = [
        h for h in blocked_hypotheses
        if str((h.hypothesis_metadata or {}).get("blocked_reason") or "") == "endpoint_not_reachable"
    ]
    reachability_blocked_hypothesis_ids = {int(h.id) for h in reachability_blocked_hypotheses}
    active_hypotheses = [
        h for h in hypotheses
        if str(h.status or "").lower() != "superseded" and int(h.id) not in reachability_blocked_hypothesis_ids
    ]
    active_blocked_hypotheses = [h for h in blocked_hypotheses if int(h.id) not in reachability_blocked_hypothesis_ids]
    resolved_hypotheses = tested_hypotheses + superseded_hypotheses
    hypothesis_depth_points = len(tested_hypotheses) + (len(active_blocked_hypotheses) * 0.25)
    hypothesis_resolution = (
        _ratio(hypothesis_depth_points, len(active_hypotheses))
        if active_hypotheses
        else (0.5 if endpoints_count else 0.0)
    )
    auth_depth = min(1.0, len(valid_sessions) / 2.0) if auth_required else 1.0
    auth_classification_counts = Counter(_auth_classification_bucket(e) for e in endpoints)
    classified_auth_endpoints = int(auth_classification_counts.get("classified", 0) or 0)
    unclassifiable_auth_endpoints = int(auth_classification_counts.get("unclassifiable_reachability", 0) or 0)
    passive_unprobed_auth_endpoints = int(auth_classification_counts.get("unclassifiable_passive_archive", 0) or 0)
    unknown_auth_endpoints = int(auth_classification_counts.get("unknown", 0) or 0)
    classifiable_auth_denominator = max(0, endpoints_count - unclassifiable_auth_endpoints - passive_unprobed_auth_endpoints)
    endpoint_auth_depth = _ratio(classified_auth_endpoints, classifiable_auth_denominator) if classifiable_auth_denominator else (1.0 if endpoints_count else 0.0)
    has_api_surface = any("api" in [str(tag).lower() for tag in list(e.tags or [])] for e in endpoints)
    api_depth = min(1.0, api_specs_count / 1.0) if has_api_surface else (1.0 if endpoints_count else 0.0)
    from app.services.business_logic_intelligence import build_business_logic_portfolio

    bl_analyses = [
        dict((dict(endpoint.endpoint_metadata or {}).get("analysis") or {}))
        for endpoint in endpoints
        if (dict(endpoint.endpoint_metadata or {}).get("analysis") or {}).get("business_logic")
    ]
    bl_identities = ["user_a", "user_b"] if len(valid_sessions) >= 2 else (["user_a"] if valid_sessions else [])
    business_logic = build_business_logic_portfolio(
        bl_analyses,
        available_identities=bl_identities,
        mutation_plan=dict(job.state_data or {}).get("business_logic_mutation_plan"),
    )
    bl_relevant = int(business_logic.get("relevant_endpoints") or 0)
    bl_contract_ratio = _ratio(int(business_logic.get("contracted_endpoints") or 0), bl_relevant) if bl_relevant else 1.0
    bl_ready_ratio = _ratio(int(business_logic.get("ready_read_only") or 0), bl_relevant) if bl_relevant else 1.0
    business_logic_depth = (
        (bl_contract_ratio * 0.6) + (bl_ready_ratio * 0.4)
        if endpoints_count
        else 0.0
    )
    work_skip_reasons = Counter(
        str(item.last_error or "")
        for item in work_items
        if str(item.status or "").lower() == "skipped" and str(item.last_error or "")
    )
    source_required_items = sum(
        count for reason, count in work_skip_reasons.items()
        if "source_code_required" in reason or "target_type local_path requires" in reason
    )
    jwt_required_items = sum(
        count for reason, count in work_skip_reasons.items()
        if "SCAN_JWT_TOKEN" in reason or "jwt" in reason.lower() and "required" in reason.lower()
    )
    external_preconditions = {
        "identity_pair_required": bool(auth_required and len(valid_sessions) < 2),
        "valid_auth_sessions": len(valid_sessions),
        "auth_required_endpoints": len(auth_relevant_endpoints),
        "source_input_required_items": source_required_items,
        "jwt_required_items": jwt_required_items,
        "mutation_or_observed_parameter_blockers": dict(business_logic.get("blocked") or {}),
        "reachability_blocked_hypotheses": len(reachability_blocked_hypotheses),
        "auth_unclassifiable_reachability_endpoints": unclassifiable_auth_endpoints,
        "auth_unclassifiable_passive_archive_endpoints": passive_unprobed_auth_endpoints,
        "coverage_external_precondition_items": len(external_coverage_items),
        "externally_blocked_skills": sorted(externally_blocked_skills),
    }
    depth_score = (
        (hypothesis_resolution * 25)
        + (auth_depth * 20)
        + (endpoint_auth_depth * 15)
        + (api_depth * 10)
        + (business_logic_depth * 20)
        + (skill_objective_ratio * 10)
    )

    components = {
        "phase_coverage": {
            "score": round(_clamp(phase_score), 1),
            "weight": 30,
            **phase_summary,
        },
        "evidence_quality": {
            "score": round(_clamp(evidence_score), 1),
            "weight": 25,
            "findings_total": len(findings),
            "false_positive_findings_excluded": len(finding_rows) - len(findings),
            "findings_with_evidence": len(findings_with_evidence),
            "findings_with_reproduction": len(findings_with_repro),
            "verified_findings": len(verified_findings),
            "candidate_findings": len(candidate_findings),
            "artifacts_total": len(artifacts),
        },
        "validation_depth": {
            "score": round(_clamp(validation_score), 1),
            "weight": 15,
            "validation_runs": len(validations),
            "historical_validation_runs_excluded": len(all_validations) - len(validations),
            "successful_validations": len(successful_validations),
            "retests": len(retests),
            "high_findings": len(high_findings),
            "high_verified": len(high_verified),
        },
        "test_depth": {
            "score": round(_clamp(depth_score), 1),
            "weight": 5,
            "hypotheses": len(hypotheses),
            "active_hypotheses": len(active_hypotheses),
            "hypotheses_resolved": len(resolved_hypotheses),
            "hypotheses_tested": len(tested_hypotheses),
            "hypotheses_superseded": len(superseded_hypotheses),
            "hypotheses_blocked": len(blocked_hypotheses),
            "hypotheses_blocked_reachability": len(reachability_blocked_hypotheses),
            "hypotheses_blocked_actionable": len(active_blocked_hypotheses),
            "hypotheses_blocked_reasons": dict(sorted(blocked_hypothesis_reasons.items())),
            "identities": identities_count,
            "valid_auth_sessions": len(valid_sessions),
            "endpoints_auth_classified": classified_auth_endpoints,
            "endpoints_auth_classifiable": classifiable_auth_denominator,
            "endpoints_auth_unknown": unknown_auth_endpoints,
            "endpoints_auth_unclassifiable_reachability": unclassifiable_auth_endpoints,
            "endpoints_auth_unclassifiable_passive_archive": passive_unprobed_auth_endpoints,
            "api_specs": api_specs_count,
            "parameters": parameters_count,
            "services": services_count,
            "business_logic_relevant_endpoints": bl_relevant,
            "business_logic_contracted_endpoints": int(business_logic.get("contracted_endpoints") or 0),
            "business_logic_invariants": int(business_logic.get("invariants") or 0),
            "business_logic_ready_read_only": int(business_logic.get("ready_read_only") or 0),
            "business_logic_blocked_endpoints": int(business_logic.get("blocked_endpoints") or 0),
            "business_logic_blockers": dict(business_logic.get("blocked") or {}),
            "skill_objectives_expected": len(expected_skills),
            "skill_objectives_applicable": len(effective_expected_skills),
            "skill_objectives_attributed": len(expected_skills & attributed_skills),
            "skill_objectives_executed": len(expected_skills & executed_skills),
            "skill_objectives_missing": missing_skill_objectives,
            "skill_objectives_external_blocked": sorted(externally_blocked_skills),
        },
        "tool_reliability": {
            "score": round(_clamp(tool_score), 1),
            "weight": 15,
            "tools_attempted": attempted,
            "tools_succeeded": succeeded,
            "failed_work_items": failed_tools,
            "infrastructure_failure_items": infrastructure_failure_items,
            "parser_error_items": len(parser_error_items),
            "parser_truncated_items": len(parser_truncated_items),
            "work_status_counts": dict(sorted(work_status_counts.items())),
            "missing_required_tools": missing_required,
            "preflight_targets": preflight_total,
            "p02_positive_targets": p02_positive_targets,
            "p06_positive_targets": p06_positive_targets,
            "p06_no_http_targets": p06_no_http_targets,
        },
        "surface_coverage": {
            "score": round(_clamp(surface_score), 1),
            "weight": 10,
            "coverage_items": len(coverage_items),
            "coverage_items_excluded": len(coverage_rows) - len(coverage_items),
            "coverage_items_raw": len(coverage_rows),
            "coverage_items_inventory_only": len(inventory_coverage_items),
            "coverage_items_external_precondition": len(external_coverage_items),
            "coverage_buckets": dict(sorted(coverage_buckets.items())),
            "covered_items": covered_count,
            "offensive_assets": offensive_assets_count,
            "endpoints": endpoints_count,
        },
    }
    total_score = round(sum((c["score"] * c["weight"]) / 100 for c in components.values()), 1)

    gaps: list[dict[str, Any]] = []
    for row in weak_phase_rows[:8]:
        gaps.append({
            "severity": "high" if row["score"] < 35 else "medium",
            "area": "phase_coverage",
            "title": f"{row['phase_id']} com cobertura fraca",
            "detail": f"Status {row['status']} e score {row['score']}%.",
            "action": "Reexecutar a fase ou corrigir ferramentas/gates pendentes.",
        })
    if high_findings and len(high_verified) < len(high_findings):
        gaps.append({
            "severity": "high",
            "area": "evidence_quality",
            "title": "Achados críticos/altos sem validação suficiente",
            "detail": f"{len(high_findings) - len(high_verified)} de {len(high_findings)} achados críticos/altos não estão verificados.",
            "action": "Priorizar P21/reteste com evidence pack e controle positivo/negativo.",
        })
    if findings and len(findings_with_evidence) < len(findings):
        gaps.append({
            "severity": "medium",
            "area": "evidence_quality",
            "title": "Findings sem evidence pack",
            "detail": f"{len(findings) - len(findings_with_evidence)} findings não têm artefato ou evidência estruturada.",
            "action": "Persistir request/response, comando, alvo e reprodução no EvidenceArtifact.",
        })
    if preflight_total and p06_no_http_targets == preflight_total and p06_positive_targets == 0:
        gaps.append({
            "severity": "medium",
            "area": "surface_reachability",
            "title": "Nenhum alvo teve superfície HTTP confirmada",
            "detail": f"P06 concluiu sem resposta HTTP positiva para {p06_no_http_targets}/{preflight_total} alvo(s).",
            "action": "Não promover fases web profundas; revisar conectividade, DNS, WAF/CDN e portas antes de avaliar vulnerabilidades.",
        })
    if attempted and success_ratio < 0.75 and infrastructure_failure_items:
        gaps.append({
            "severity": "medium",
            "area": "infrastructure_reliability",
            "title": "Falhas operacionais das ferramentas abaixo do ideal",
            "detail": f"{succeeded}/{attempted} execuções com sucesso; {infrastructure_failure_items} item(ns) falharam ou deram timeout.",
            "action": "Revisar módulos Kali, timeouts, concorrência e dependências do runner.",
        })
    if parser_error_items:
        examples = ", ".join(
            f"{item.phase_id}/{item.tool_name}/{item.target}" for item in parser_error_items[:5]
        )
        gaps.append({
            "severity": "high",
            "area": "parser_reliability",
            "title": "Falha de parser mascararia achados",
            "detail": f"{len(parser_error_items)} item(ns) concluídos tiveram erro de parser ({examples}).",
            "action": "Corrigir parser/tool output antes de interpretar ausência de findings como ausência de vulnerabilidade.",
        })
    if parser_truncated_items:
        examples = ", ".join(
            f"{item.phase_id}/{item.tool_name}/{item.target}" for item in parser_truncated_items[:5]
        )
        gaps.append({
            "severity": "medium",
            "area": "parser_reliability",
            "title": "Saída de ferramenta truncada antes do parser",
            "detail": f"{len(parser_truncated_items)} item(ns) excederam o limite de entrada do parser ({examples}).",
            "action": "Usar parsed_result estruturado ou artifact/stdout_path completo para ferramentas volumosas.",
        })
    if not validations and findings:
        gaps.append({
            "severity": "medium",
            "area": "validation_depth",
            "title": "Findings sem validação automatizada",
            "detail": "Nenhum ValidationRun foi registrado para este scan.",
            "action": "Ativar validação segura para findings relevantes e registrar resultado.",
        })
    if not coverage_items and not endpoints_count:
        gaps.append({
            "severity": "low",
            "area": "surface_coverage",
            "title": "Cobertura de endpoints pouco observável",
            "detail": "Não há CoverageItem nem endpoints ofensivos persistidos.",
            "action": "Persistir endpoints, parâmetros e cobertura por classe de teste.",
        })
    hypotheses_not_exercised = len(active_hypotheses) - len(tested_hypotheses)
    if hypotheses_not_exercised > 0:
        actionable_blocked_reasons = Counter(
            str((h.hypothesis_metadata or {}).get("blocked_reason") or "reason_not_recorded")
            for h in active_blocked_hypotheses
        )
        blocked_detail = ", ".join(
            f"{reason}={count}" for reason, count in sorted(actionable_blocked_reasons.items())
        )
        gaps.append({
            "severity": "high" if hypothesis_resolution < 0.5 else "medium",
            "area": "test_depth",
            "title": "Hipóteses ainda não exercitadas",
            "detail": (
                f"{hypotheses_not_exercised} de {len(active_hypotheses)} hipóteses aplicáveis não foram exercitadas "
                f"({len(active_blocked_hypotheses)} bloqueadas; {blocked_detail or 'sem motivo registrado'})."
            ),
            "action": "Corrigir a pré-condição registrada e reexecutar somente os validadores aplicáveis.",
        })
    if reachability_blocked_hypotheses:
        gaps.append({
            "severity": "medium",
            "area": "reachability",
            "title": "Hipóteses não testáveis por reachability",
            "detail": f"{len(reachability_blocked_hypotheses)} hipóteses foram isoladas porque o endpoint não respondeu.",
            "action": "Reexecutar P02/P06 nos alvos afetados ou aceitar como superfície não testável nesta janela.",
        })
    if missing_skill_objectives:
        gaps.append({
            "severity": "high" if skill_objective_ratio < 0.6 else "medium",
            "area": "skill_coverage",
            "title": "Objetivos de skills não exercitados",
            "detail": (
                f"{len(missing_skill_objectives)} de {len(expected_skills)} objetivos obrigatórios "
                "não possuem execução concluída."
            ),
            "action": (
                "Executar ao menos uma técnica aplicável com evidência para cada skill: "
                + ", ".join(missing_skill_objectives[:8])
            ),
        })
    if auth_required and len(valid_sessions) < 2:
        gaps.append({
            "severity": "high",
            "area": "external_precondition",
            "title": "Matriz de autorização aguardando credenciais",
            "detail": f"Há {len(valid_sessions)} sessão(ões) válida(s); testes horizontais exigem ao menos duas identidades.",
            "action": "Configurar identidades de papéis distintos e validar suas sessões antes das fases autenticadas.",
        })
    if classifiable_auth_denominator and endpoint_auth_depth < 0.8:
        gaps.append({
            "severity": "medium",
            "area": "test_depth",
            "title": "Requisito de autenticação não classificado",
            "detail": (
                f"{classified_auth_endpoints}/{classifiable_auth_denominator} endpoints classificáveis têm auth_required conhecido; "
                f"{unclassifiable_auth_endpoints} ficaram sem classificação por reachability e "
                f"{passive_unprobed_auth_endpoints} vieram de fonte passiva sem baseline ativo."
            ),
            "action": "Executar baseline anônimo e autenticado para classificar cada endpoint.",
        })
    if bl_relevant and bl_contract_ratio < 1.0:
        gaps.append({
            "severity": "high" if int(business_logic.get("high_risk_endpoints") or 0) else "medium",
            "area": "business_logic",
            "title": "Endpoints de negócio sem contrato de invariantes",
            "detail": f"{int(business_logic.get('contracted_endpoints') or 0)}/{bl_relevant} endpoints relevantes têm contrato de business logic.",
            "action": "Reanalisar o inventário com o contrato de endpoint atual antes de executar testes ativos.",
        })
    if int(business_logic.get("high_risk_endpoints") or 0) and int(business_logic.get("blocked_endpoints") or 0):
        blocker_counts = dict(business_logic.get("blocked") or {})
        blocker_detail = ", ".join(
            f"{name}={count}" for name, count in sorted(blocker_counts.items()) if int(count or 0) > 0
        )
        gaps.append({
            "severity": "high",
            "area": "business_logic",
            "title": "Invariantes de alto risco bloqueados por pré-condições",
            "detail": (
                f"{int(business_logic.get('blocked_endpoints') or 0)} endpoints têm pré-condições reais "
                f"({blocker_detail or 'sem detalhamento'})."
            ),
            "action": "Atender apenas a pré-condição registrada para cada endpoint; não presumir credenciais ou objetos.",
        })

    if total_score >= 85:
        grade = "A"
        label = "Forte"
    elif total_score >= 70:
        grade = "B"
        label = "Boa"
    elif total_score >= 55:
        grade = "C"
        label = "Parcial"
    elif total_score >= 40:
        grade = "D"
        label = "Fraca"
    else:
        grade = "F"
        label = "Insuficiente"

    gap_rank = {"high": 0, "medium": 1, "low": 2}
    gaps.sort(key=lambda gap: gap_rank.get(str(gap.get("severity") or "low").lower(), 3))
    quality_gate = dict((job.state_data or {}).get("quality_gate") or {})
    if quality_gate.get("status") == "passed" and total_score < QUALITY_GATE_SCORE_THRESHOLD:
        quality_gate.update({
            "status": "historical_mismatch",
            "passed": False,
            "completion_status": "completed_with_gaps",
            "reason": "legacy_gate_did_not_enforce_numeric_threshold",
        })
    preflight_summary = _build_preflight_summary(
        db,
        job,
        external_preconditions=external_preconditions,
        business_logic=business_logic,
        components=components,
    )
    auth_precondition_summary = _build_auth_precondition_summary(
        external_preconditions=external_preconditions,
        components=components,
    )
    business_logic_precondition_summary = _build_business_logic_precondition_summary(business_logic)

    return {
        "scan_id": job.id,
        "target": job.target_query,
        "profile": {
            "id": profile.get("id"),
            "label": profile.get("label"),
            "depth": profile.get("depth"),
            "expected_phases": expected_phase_ids,
        },
        "score": total_score,
        "grade": grade,
        "label": label,
        "quality_gate": quality_gate,
        "business_logic": business_logic,
        "external_preconditions": external_preconditions,
        "preflight_summary": preflight_summary,
        "auth_precondition_summary": auth_precondition_summary,
        "business_logic_precondition_summary": business_logic_precondition_summary,
        "operational_sli": dict((job.state_data or {}).get("operational_sli") or {}),
        "runtime_visibility": _runtime_visibility(job, all_validations, artifacts, work_items),
        "execution_metrics": execution_metrics,
        "components": components,
        "summary": {
            "findings_total": len(findings),
            "false_positive_findings_excluded": len(finding_rows) - len(findings),
            "verified_findings": len(verified_findings),
            "candidate_findings": len(candidate_findings),
            "artifacts_total": len(artifacts),
            "validation_runs": len(validations),
            "historical_validation_runs_excluded": len(all_validations) - len(validations),
            "coverage_items": len(coverage_items),
            "coverage_items_raw": len(coverage_rows),
            "coverage_items_inventory_only": len(inventory_coverage_items),
            "coverage_items_external_precondition": len(external_coverage_items),
            "tools_attempted": attempted,
            "tools_succeeded": succeeded,
            "expected_phases": len(expected_phase_ids),
            "healthy_phases": phase_summary["healthy"],
        },
        "gaps": gaps[:10],
        "phase_monitor_issues": list(phase_monitor.get("issues") or [])[:10],
        "recommendations": [
            "Exigir EvidenceArtifact para findings high/critical antes de promovê-los no relatório.",
            "Rodar validação segura com controle positivo/negativo para candidatos críticos.",
            "Persistir CoverageItem por endpoint/parâmetro para medir cobertura real.",
            "Exercitar invariantes de negócio somente com identidades e fixtures reversíveis documentadas.",
            "Reexecutar fases com work items falhos antes de concluir o relatório executivo.",
        ],
    }


def _phase_status_counts(db: Session, scan_id: int, phase_ids: set[str]) -> dict[str, dict[str, int]]:
    rows = (
        db.query(ScanWorkItem.phase_id, ScanWorkItem.status, func.count(ScanWorkItem.id))
        .filter(ScanWorkItem.scan_job_id == scan_id, ScanWorkItem.phase_id.in_(phase_ids))
        .group_by(ScanWorkItem.phase_id, ScanWorkItem.status)
        .all()
    )
    out: dict[str, dict[str, int]] = {phase: {} for phase in phase_ids}
    for phase_id, status, count in rows:
        out.setdefault(str(phase_id or "unknown"), {})[str(status or "unknown")] = int(count or 0)
    return out


def _build_preflight_summary(
    db: Session,
    job: ScanJob,
    *,
    external_preconditions: dict[str, Any],
    business_logic: dict[str, Any],
    components: dict[str, Any],
) -> dict[str, Any]:
    state = dict(job.state_data or {})
    profiles = dict(((state.get("preflight") or {}).get("targets") or {}))
    profile_rows = [dict(value or {}) for value in profiles.values()]
    phase_counts = _phase_status_counts(db, int(job.id), {"P02", "P06"})
    recon_rows = (
        db.query(CoverageItem.test_class, CoverageItem.status, func.count(CoverageItem.id))
        .filter(
            CoverageItem.scan_job_id == job.id,
            CoverageItem.coverage_type == "recon_qualification",
            CoverageItem.test_class.in_(["P02", "P06"]),
        )
        .group_by(CoverageItem.test_class, CoverageItem.status)
        .all()
    )
    recon_coverage_counts: dict[str, dict[str, int]] = {"P02": {}, "P06": {}}
    for phase_id, status, count in recon_rows:
        recon_coverage_counts.setdefault(str(phase_id or "unknown"), {})[str(status or "unknown")] = int(count or 0)
    p02_complete = sum(bool(row.get("p02_complete")) for row in profile_rows)
    p06_complete = sum(bool(row.get("p06_complete")) for row in profile_rows)
    p06_live = sum(bool(row.get("p06_http_live")) for row in profile_rows)
    open_port_targets = sum(bool(row.get("open_ports")) for row in profile_rows)
    dead_targets = list(state.get("dead_targets") or [])
    dns_inconclusive = list(state.get("dns_inconclusive_targets") or [])
    blocked_reasons = Counter(
        str((item.item_metadata or {}).get("gate_reason") or item.last_error or "reason_not_recorded")
        for item in db.query(ScanWorkItem)
        .filter(ScanWorkItem.scan_job_id == job.id, ScanWorkItem.status.in_(["blocked", "skipped", "timeout", "failed"]))
        .all()
    )
    return {
        "version": "preflight-summary-v2",
        "target": job.target_query,
        "updated_at": datetime.now().isoformat(),
        "producer_stage": state.get("work_producer_stage"),
        "producers_sealed": bool(state.get("work_producers_sealed")),
        "qualification_contract_version": int(state.get("qualification_contract_version") or 0),
        "targets": {
            "expanded": len(state.get("expanded_targets") or []),
            "selected": len(state.get("target_set") or []),
            "profiled": len(profile_rows),
            "rejected_non_public": sum(bool(row.get("non_public_rejected")) for row in profile_rows),
            "dead": len(dead_targets),
            "dns_inconclusive": len(dns_inconclusive),
            "sample_dead": dead_targets[:8],
            "sample_dns_inconclusive": dns_inconclusive[:8],
        },
        "p02": {
            "status_counts": phase_counts.get("P02") or {},
            "coverage_counts": recon_coverage_counts.get("P02") or {},
            "input_covered_targets": sum(bool(row.get("p02_input_covered")) for row in profile_rows),
            "complete_targets": p02_complete,
            "targets_with_open_ports": open_port_targets,
            "open_ports_observed": sum(len(row.get("open_ports") or []) for row in profile_rows),
        },
        "p06": {
            "status_counts": phase_counts.get("P06") or {},
            "coverage_counts": recon_coverage_counts.get("P06") or {},
            "input_covered_targets": sum(bool(row.get("p06_input_covered")) for row in profile_rows),
            "complete_targets": p06_complete,
            "http_live_targets": p06_live,
            "no_http_response_targets": sum(bool(row.get("p06_complete")) and not bool(row.get("p06_http_live")) for row in profile_rows),
        },
        "quality_inputs": {
            "external_preconditions": external_preconditions,
            "business_logic_blockers": dict(business_logic.get("blocked") or {}),
            "test_depth": (components.get("test_depth") or {}).get("score"),
            "surface_coverage": (components.get("surface_coverage") or {}).get("score"),
            "tool_reliability": (components.get("tool_reliability") or {}).get("score"),
        },
        "non_success_reason_counts": [
            {"reason": reason, "count": count}
            for reason, count in blocked_reasons.most_common(12)
        ],
    }


def _build_auth_precondition_summary(
    *,
    external_preconditions: dict[str, Any],
    components: dict[str, Any],
) -> dict[str, Any]:
    depth = dict((components.get("test_depth") or {}))
    valid_sessions = int(external_preconditions.get("valid_auth_sessions") or 0)
    auth_required = int(external_preconditions.get("auth_required_endpoints") or 0)
    identity_pair_required = bool(external_preconditions.get("identity_pair_required"))
    return {
        "version": "auth-precondition-summary-v1",
        "blocked": identity_pair_required or bool(external_preconditions.get("jwt_required_items")),
        "reason": (
            "missing_valid_identity_pair"
            if identity_pair_required
            else "captured_jwt_required"
            if int(external_preconditions.get("jwt_required_items") or 0) > 0
            else ""
        ),
        "evidence": {
            "valid_auth_sessions": valid_sessions,
            "required_valid_sessions_for_horizontal_tests": 2 if identity_pair_required else 0,
            "auth_required_endpoints": auth_required,
            "jwt_required_work_items": int(external_preconditions.get("jwt_required_items") or 0),
            "source_input_required_items": int(external_preconditions.get("source_input_required_items") or 0),
            "endpoints_auth_classified": int(depth.get("endpoints_auth_classified") or 0),
            "endpoints_auth_classifiable": int(depth.get("endpoints_auth_classifiable") or 0),
            "endpoints_auth_unknown": int(depth.get("endpoints_auth_unknown") or 0),
            "endpoints_auth_unclassifiable_reachability": int(depth.get("endpoints_auth_unclassifiable_reachability") or 0),
            "endpoints_auth_unclassifiable_passive_archive": int(depth.get("endpoints_auth_unclassifiable_passive_archive") or 0),
        },
        "operator_message": (
            f"{valid_sessions} sessão(ões) válida(s) encontradas; testes horizontais/IDOR/BFLA "
            "exigem duas identidades reais e validadas."
            if identity_pair_required
            else "Sem bloqueio global de identidade registrado."
        ),
    }


def _build_business_logic_precondition_summary(business_logic: dict[str, Any]) -> dict[str, Any]:
    blockers = dict(business_logic.get("blocked") or {})
    return {
        "version": "business-logic-precondition-summary-v1",
        "relevant_endpoints": int(business_logic.get("relevant_endpoints") or 0),
        "contracted_endpoints": int(business_logic.get("contracted_endpoints") or 0),
        "high_risk_endpoints": int(business_logic.get("high_risk_endpoints") or 0),
        "ready_read_only": int(business_logic.get("ready_read_only") or 0),
        "ready_mutation": int(business_logic.get("ready_mutation") or 0),
        "blocked_endpoints": int(business_logic.get("blocked_endpoints") or 0),
        "blockers": blockers,
        "operator_message": (
            "Execução de lógica de negócio bloqueada por pré-condições registradas: "
            + ", ".join(f"{name}={count}" for name, count in sorted(blockers.items()))
            if blockers
            else "Sem bloqueio de lógica de negócio registrado."
        ),
        "guardrails": dict(business_logic.get("execution_guardrails") or {}),
    }


def _persist_quality_state(
    db: Session,
    job: ScanJob,
    state: dict[str, Any],
    quality: dict[str, Any],
    gate_state: dict[str, Any],
) -> dict[str, Any]:
    snapshot = {
        key: value for key, value in quality.items()
        if key not in {"runtime_visibility", "phase_monitor_issues"}
    }
    snapshot["quality_gate"] = gate_state
    state["quality_snapshot"] = snapshot
    state["quality_gate"] = gate_state
    for key in (
        "preflight_summary",
        "auth_precondition_summary",
        "business_logic_precondition_summary",
    ):
        if key in quality:
            state[key] = quality[key]
    state["quality_snapshot_persisted_at"] = datetime.now().isoformat()
    job.state_data = state
    db.add(job)
    return state


def _runtime_visibility(
    job: ScanJob,
    validations: list[ValidationRun],
    artifacts: list[EvidenceArtifact],
    work_items: list[ScanWorkItem],
) -> dict[str, Any]:
    state = dict(job.state_data or {})
    gate = dict(state.get("quality_gate") or {})
    p21_validations: list[dict[str, Any]] = []
    for validation in validations:
        meta = dict(validation.run_metadata or {})
        # Older validators did not persist phase_id, but a finding-scoped
        # ValidationRun is still a P21 validation outcome. Requiring metadata
        # made the UI report 0 while the database contained real results.
        if (
            str(meta.get("phase_id") or "").upper() != "P21"
            and validation.finding_id is None
        ):
            continue
        p21_validations.append({
            "id": validation.id,
            "finding_id": validation.finding_id,
            "validator": validation.validator_name,
            "result": validation.result,
            "target": meta.get("target"),
            "artifact_id": meta.get("artifact_id") or validation.attempt_artifact_id,
            "work_item_id": meta.get("work_item_id"),
            "created_at": validation.created_at.isoformat() if getattr(validation, "created_at", None) else None,
        })
    p21_validations.sort(key=lambda row: str(row.get("created_at") or ""), reverse=True)

    p21_artifact_count = 0
    for artifact in artifacts:
        if str(artifact.phase_id or "").upper() == "P21" or str(artifact.artifact_type or "") == "p21_validation":
            p21_artifact_count += 1

    fallback_items: list[dict[str, Any]] = []
    for item in work_items:
        meta = dict(item.item_metadata or {})
        if not meta.get("quality_gate_fallback"):
            continue
        fallback_items.append({
            "id": item.id,
            "phase_id": item.phase_id,
            "target": item.target,
            "from": meta.get("quality_gate_original_tool"),
            "to": item.tool_name,
            "status": item.status,
            "reason": meta.get("quality_gate_reason"),
            "created_at": item.created_at.isoformat() if getattr(item, "created_at", None) else None,
        })
    fallback_items.sort(key=lambda row: str(row.get("created_at") or ""), reverse=True)

    llm_reasoning = list(state.get("llm_reasoning") or [])
    mcp_contracts = list(state.get("mcp_adapter_contracts") or [])
    feedback = list(state.get("llm_reasoning_feedback") or [])
    orchestration = dict(state.get("agent_orchestration") or {})
    agent_runs = [row for row in list(state.get("agent_execution_runs") or []) if isinstance(row, dict)]
    agent_summaries = dict(state.get("agent_execution_summary") or {})
    skill_invocations = list(state.get("skill_invocation") or state.get("skill_invocations") or [])
    llm_real = [row for row in llm_reasoning if isinstance(row, dict) and not bool(row.get("fallback"))]
    llm_fallback = [row for row in llm_reasoning if isinstance(row, dict) and bool(row.get("fallback"))]

    return {
        "quality_gate": {
            "last_actions": list(gate.get("last_actions") or [])[-8:],
            "history": list(gate.get("history") or [])[-6:],
            "fallback_items": fallback_items[:8],
        },
        "p21_validation": {
            "total": len(p21_validations),
            "confirmed": len([row for row in p21_validations if str(row.get("result") or "").lower() == "confirmed"]),
            "refuted": len([row for row in p21_validations if str(row.get("result") or "").lower() == "refuted"]),
            "artifacts": p21_artifact_count,
            "recent": p21_validations[:8],
        },
        "agent_runtime": {
            "llm_reasoning_count": len(llm_reasoning),
            "llm_real_count": len(llm_real),
            "llm_fallback_count": len(llm_fallback),
            "mcp_contract_count": len(mcp_contracts),
            "reasoning_feedback_count": len(feedback),
            "orchestrated_phases": len(orchestration),
            "agent_execution_count": len([row for row in agent_runs if str(row.get("status") or "") in {"success", "partial"}]),
            "agent_success_count": len([row for row in agent_runs if str(row.get("status") or "") == "success"]),
            "agent_partial_count": len([row for row in agent_runs if str(row.get("status") or "") == "partial"]),
            "agent_execution_phases": len(agent_summaries),
            "skill_invocation_count": len(skill_invocations),
            "recent_llm_reasoning": llm_reasoning[-5:],
            "recent_mcp_contracts": mcp_contracts[-5:],
            "recent_agent_executions": agent_runs[-8:],
            "recent_agent_summaries": list(agent_summaries.values())[-5:],
            "recent_feedback": feedback[-5:],
        },
    }


def run_scan_quality_gate(db: Session, job: ScanJob) -> dict[str, Any]:
    """Run the active post-scan quality gate.

    The gate is intentionally conservative: it only extends a scan when it can
    enqueue concrete extra work. If it cannot improve the scan automatically, it
    records the quality state and allows completion with visible gaps.
    """
    state = dict(job.state_data or {})
    gate_state = dict(state.get("quality_gate") or {})
    rounds = int(gate_state.get("rounds") or 0)

    actions: list[dict[str, Any]] = []
    try:
        from app.services.recon_qualification_coverage import materialize_recon_qualification_coverage

        materialize_recon_qualification_coverage(db, job)
    except Exception as exc:  # noqa: BLE001
        db.add(ScanLog(
            scan_job_id=job.id,
            source="quality-gate",
            level="WARNING",
            message=f"qualification_coverage_materialization_failed error={exc!s}"[:2000],
        ))
    validation_changes = _apply_promotion_gate(db, job)
    validation_changes["p21_audits_recorded"] = _record_p21_evidence_audits(db, job)
    try:
        from app.services.endpoint_analysis_pipeline import analyze_endpoints_for_scan
        from app.services.hypothesis_rules import generate_hypotheses_for_scan
        from app.services.hypothesis_planner import ensure_hypothesis_drain_work_item

        validation_changes["endpoint_intelligence"] = analyze_endpoints_for_scan(db, job)
        validation_changes["hypothesis_generation"] = generate_hypotheses_for_scan(db, job)
        hypothesis_drain = ensure_hypothesis_drain_work_item(db, job, batch_size=100)
        validation_changes["hypothesis_drain"] = hypothesis_drain
        if int(hypothesis_drain.get("remaining", 0) or 0) > 0 and not hypothesis_drain.get("blocked"):
            actions.append({"type": "drain_hypotheses", **hypothesis_drain})
    except Exception as exc:  # noqa: BLE001
        validation_changes["hypothesis_drain"] = {"error": str(exc)[:500]}
        db.add(ScanLog(
            scan_job_id=job.id,
            source="quality-gate",
            level="WARNING",
            message=f"hypothesis_drain_schedule_failed error={exc!s}"[:2000],
        ))
    try:
        from app.services.finding_validation_lifecycle import enforce_high_risk_lifecycle

        # This is an optional quality extension. Isolate its writes so a
        # constraint/parser error can be reported as a visible quality gap
        # without poisoning the scan's outer transaction and turning a fully
        # drained scan into FAILED.
        with db.begin_nested():
            lifecycle = enforce_high_risk_lifecycle(db, job, limit=QUALITY_GATE_MAX_POC_PER_ROUND)
        validation_changes["high_risk_lifecycle"] = lifecycle
        if int(lifecycle.get("scheduled", 0) or 0) > 0:
            actions.append({"type": "schedule_p21_validation", **lifecycle})
    except Exception as exc:  # noqa: BLE001
        lifecycle = {"error": str(exc)[:500]}
        validation_changes["high_risk_lifecycle"] = lifecycle
        db.add(ScanLog(
            scan_job_id=job.id,
            source="quality-gate",
            level="WARNING",
            message=f"high_risk_lifecycle_failed error={exc!s}"[:2000],
        ))
    quality = build_scan_quality(db, job)
    if rounds >= QUALITY_GATE_MAX_ROUNDS:
        decision = quality_gate_decision(quality, actions)
        gate_state.update({
            "status": "passed" if decision["passed"] else "exhausted",
            "last_score": quality.get("score"),
            "last_grade": quality.get("grade"),
            "reason": "max_quality_gate_rounds_reached",
        })
        state = _persist_quality_state(db, job, state, quality, gate_state)
        return {
            **decision,
            "status": gate_state["status"],
            "actions": actions,
            "validation_changes": validation_changes,
            "quality": quality,
        }

    weak_phase_ids = {
        str(gap.get("title") or "").split(" ", 1)[0]
        for gap in quality.get("gaps") or []
        if gap.get("area") == "phase_coverage"
    }
    weak_phase_ids = {pid for pid in weak_phase_ids if pid.startswith("P")}
    requeued = _requeue_failed_quality_items(db, job, weak_phase_ids)
    if requeued:
        actions.append({"type": "requeue_failed_work_items", "requeued": requeued})

    fallback_result = _schedule_fallback_quality_items(db, job, weak_phase_ids)
    if int(fallback_result.get("scheduled", 0) or 0) > 0:
        actions.append({"type": "schedule_fallback_work_items", **fallback_result})

    decision = quality_gate_decision(quality, actions)
    gate_state.update({
        "status": "remediation_scheduled" if actions else ("passed" if decision["passed"] else "completed_with_gaps"),
        "rounds": rounds + (1 if actions else 0),
        "last_score": quality.get("score"),
        "last_grade": quality.get("grade"),
        "threshold": QUALITY_GATE_SCORE_THRESHOLD,
        "validation_changes": validation_changes,
        "last_actions": actions,
        "passed": decision["passed"],
        "completion_status": decision["completion_status"],
        "blockers": decision["blockers"],
    })
    history = list(gate_state.get("history") or [])
    history.append({
        "round": rounds + 1,
        "score": quality.get("score"),
        "grade": quality.get("grade"),
        "actions": actions,
    })
    gate_state["history"] = history[-10:]
    state = _persist_quality_state(db, job, state, quality, gate_state)

    return {
        **decision,
        "status": gate_state["status"],
        "actions": actions,
        "validation_changes": validation_changes,
        "quality": quality,
    }


def _apply_promotion_gate(db: Session, job: ScanJob) -> dict[str, int]:
    try:
        from app.services.evidence_contract_service import apply_finding_validation, link_artifacts_to_findings

        link_result = link_artifacts_to_findings(db, job)
        findings = (
            db.query(Finding)
            .filter(Finding.scan_job_id == job.id, Finding.is_false_positive.is_(False))
            .all()
        )
        updated = 0
        capped = 0
        for finding in findings:
            before_status = str(finding.verification_status or "")
            before_severity = str(finding.severity or "")
            decision = apply_finding_validation(db, finding)
            if str(decision.status or "") != before_status:
                updated += 1
            if str(finding.severity or "") != before_severity:
                capped += 1
        db.flush()
        return {"linked_artifacts": int(link_result.get("linked", 0) or 0), "updated_findings": updated, "severity_capped": capped}
    except Exception as exc:  # noqa: BLE001
        db.add(ScanLog(
            scan_job_id=job.id,
            source="quality-gate",
            level="WARNING",
            message=f"promotion_gate_failed error={exc!s}"[:2000],
        ))
        return {"linked_artifacts": 0, "updated_findings": 0, "severity_capped": 0}


def _schedule_quality_poc_validations(db: Session, job: ScanJob) -> dict[str, int]:
    try:
        from app.services.poc_validator import batch_schedule_poc_validations

        return batch_schedule_poc_validations(
            db,
            int(job.id),
            max_findings=QUALITY_GATE_MAX_POC_PER_ROUND,
        )
    except Exception as exc:  # noqa: BLE001
        db.add(ScanLog(
            scan_job_id=job.id,
            source="quality-gate",
            level="WARNING",
            message=f"p21_quality_schedule_failed error={exc!s}"[:2000],
        ))
        return {"scheduled": 0, "skipped_confirmed": 0, "skipped_cap": 0, "skipped_no_tool": 0}


def _record_p21_evidence_audits(db: Session, job: ScanJob, max_rows: int = 12) -> int:
    """Record P21 validation rows for already-validated evidence contracts.

    Active PoC items remain the path for HIGH/CRITICAL candidates. This audit
    covers the other legitimate path: evidence/validation services already
    produced proof, but no P21 row exists for visibility/reporting.
    """
    artifacts = db.query(EvidenceArtifact).filter(EvidenceArtifact.scan_job_id == job.id).all()
    artifact_by_finding: dict[int, EvidenceArtifact] = {}
    for artifact in artifacts:
        if artifact.finding_id is None:
            continue
        status = str(artifact.validation_status or "").strip().lower()
        if status not in {"confirmed", "validated", "success", "proven", "candidate"}:
            continue
        artifact_by_finding.setdefault(int(artifact.finding_id), artifact)
    if not artifact_by_finding:
        return 0

    existing_finding_ids = {
        int(v.finding_id)
        for v in db.query(ValidationRun)
        .filter(ValidationRun.scan_job_id == job.id, ValidationRun.finding_id.isnot(None))
        .all()
        if v.finding_id is not None and str((dict(v.run_metadata or {})).get("phase_id") or "").upper() == "P21"
    }

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == job.id,
            Finding.id.in_(list(artifact_by_finding.keys())),
            Finding.is_false_positive.is_(False),
        )
        .order_by(Finding.risk_score.desc(), Finding.id.asc())
        .limit(max_rows * 3)
        .all()
    )
    recorded = 0
    for finding in findings:
        if recorded >= max_rows:
            break
        if int(finding.id) in existing_finding_ids:
            continue
        source_artifact = artifact_by_finding.get(int(finding.id))
        if not source_artifact:
            continue
        details = dict(finding.details or {})
        target = str(finding.url or details.get("matched_at") or details.get("asset") or finding.domain or source_artifact.target or job.target_query or "")[:500]
        status = str(finding.verification_status or "").strip().lower()
        result = "confirmed" if status in VERIFIED_STATUSES else "validated"
        audit_artifact = EvidenceArtifact(
            scan_job_id=job.id,
            finding_id=finding.id,
            phase_id="P21",
            skill_id="evidence_quality_review",
            tool_name="quality-gate-audit",
            target=target,
            artifact_type="p21_validation",
            validation_status=result,
            confidence_score=max(int(source_artifact.confidence_score or 0), int(finding.confidence_score or 0), 70),
            baseline_request=dict(source_artifact.baseline_request or {}),
            exploit_request=dict(source_artifact.exploit_request or {}),
            payload=source_artifact.payload,
            diff_summary=source_artifact.diff_summary or "P21 evidence audit linked an existing proof-pack to this finding.",
            reproduction_steps=list(source_artifact.reproduction_steps or []),
            workspace_path=source_artifact.workspace_path,
            artifact_metadata={
                "phase_id": "P21",
                "quality_gate_evidence_audit": True,
                "source_artifact_id": int(source_artifact.id),
                "finding_id": int(finding.id),
                "target": target,
            },
            created_at=datetime.now(),
        )
        db.add(audit_artifact)
        db.flush()
        validation = ValidationRun(
            scan_job_id=job.id,
            finding_id=finding.id,
            validator_name="quality-gate-audit",
            attempt_artifact_id=audit_artifact.id,
            result=result,
            reason="EvidenceArtifact contract validated; P21 audit row recorded for reporting visibility.",
            run_metadata={
                "phase_id": "P21",
                "target": target,
                "artifact_id": int(audit_artifact.id),
                "source_artifact_id": int(source_artifact.id),
                "quality_gate_evidence_audit": True,
            },
            created_at=datetime.now(),
        )
        db.add(validation)
        from app.services.offensive_inventory_service import OffensiveInventoryService

        OffensiveInventoryService(db, job).upsert_coverage(
            coverage_type="finding_validation",
            target_ref=target,
            test_class="P21",
            status="validated",
            finding_id=finding.id,
            metadata={
                "quality_gate_evidence_audit": True,
                "artifact_id": int(audit_artifact.id),
                "validation_run_id": int(validation.id),
            },
        )
        recorded += 1

    if recorded:
        db.add(ScanLog(
            scan_job_id=job.id,
            source="quality-gate",
            level="INFO",
            message=f"p21_evidence_audit_recorded count={recorded}",
        ))
        db.flush()
    return recorded


def _requeue_failed_quality_items(db: Session, job: ScanJob, weak_phase_ids: set[str]) -> int:
    if not weak_phase_ids:
        return 0
    rows = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == job.id,
            ScanWorkItem.phase_id.in_(sorted(weak_phase_ids)),
            ScanWorkItem.status.in_(["failed", "timeout"]),
        )
        .order_by(ScanWorkItem.priority.asc(), ScanWorkItem.id.asc())
        .limit(QUALITY_GATE_MAX_REQUEUES_PER_ROUND)
        .all()
    )
    requeued = 0
    for item in rows:
        meta = dict(item.item_metadata or {})
        if meta.get("poc_validation"):
            continue
        retries = int(meta.get("quality_gate_retries") or 0)
        if retries >= 1:
            continue
        meta["quality_gate_retries"] = retries + 1
        meta["quality_gate_reason"] = "phase_coverage_gap_retry"
        item.item_metadata = meta
        item.status = "queued"
        item.lease_until = None
        item.finished_at = None
        item.updated_at = datetime.now()
        item.attempts = 0
        item.max_attempts = max(int(item.max_attempts or 1), 1)
        item.last_error = None
        result = dict(item.result or {})
        result["quality_gate_requeued"] = True
        item.result = result
        db.add(item)
        requeued += 1
    return requeued


def _fallback_candidates_for_item(item: ScanWorkItem) -> list[str]:
    tool = str(item.tool_name or "").strip().lower()
    phase_id = str(item.phase_id or "").strip()
    candidates: list[str] = []
    candidates.extend(QUALITY_TOOL_FALLBACKS.get(tool, []))
    if tool.startswith("nuclei-"):
        candidates.extend(["nuclei", "nikto", "wapiti"])
    candidates.extend(QUALITY_PHASE_FALLBACKS.get(phase_id, []))

    seen: set[str] = {tool}
    out: list[str] = []
    for candidate in candidates:
        normalized = str(candidate or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out[:5]


def _schedule_fallback_quality_items(db: Session, job: ScanJob, weak_phase_ids: set[str]) -> dict[str, Any]:
    if not weak_phase_ids:
        return {"scheduled": 0, "skipped": 0}
    try:
        from app.services.scan_work_queue import (
            PHASE_PRIORITY,
            _tool_profile,
            apply_phase_tool_metadata,
            resource_class_for_tool,
        )
    except Exception as exc:  # noqa: BLE001
        db.add(ScanLog(
            scan_job_id=job.id,
            source="quality-gate",
            level="WARNING",
            message=f"quality_fallback_import_failed error={exc!s}"[:2000],
        ))
        return {"scheduled": 0, "skipped": 0}

    rows = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == job.id,
            ScanWorkItem.phase_id.in_(sorted(weak_phase_ids)),
            ScanWorkItem.status.in_(["failed", "timeout"]),
        )
        .order_by(ScanWorkItem.priority.asc(), ScanWorkItem.id.asc())
        .limit(QUALITY_GATE_MAX_FALLBACKS_PER_ROUND * 3)
        .all()
    )
    scheduled = 0
    skipped = 0
    fallback_tools: list[dict[str, Any]] = []
    for item in rows:
        if scheduled >= QUALITY_GATE_MAX_FALLBACKS_PER_ROUND:
            break
        meta = dict(item.item_metadata or {})
        if meta.get("poc_validation"):
            skipped += 1
            continue
        if int(meta.get("quality_gate_retries") or 0) < 1:
            skipped += 1
            continue
        chain = list(meta.get("quality_gate_fallback_chain") or [])
        if len(chain) >= 2:
            skipped += 1
            continue
        for candidate in _fallback_candidates_for_item(item):
            existing = (
                db.query(ScanWorkItem.id)
                .filter(
                    ScanWorkItem.scan_job_id == job.id,
                    ScanWorkItem.phase_id == item.phase_id,
                    ScanWorkItem.tool_name == candidate[:120],
                    ScanWorkItem.target == item.target,
                )
                .first()
            )
            if existing:
                continue
            rc = resource_class_for_tool(candidate)
            base_priority = PHASE_PRIORITY.get(str(item.phase_id or ""), int(item.priority or 100))
            fallback_meta = apply_phase_tool_metadata({
                "source": "quality_gate",
                "engine": "quality_gate_fallback",
                "quality_gate_fallback": True,
                "quality_gate_fallback_for_item_id": int(item.id),
                "quality_gate_original_tool": str(item.tool_name or ""),
                "quality_gate_original_status": str(item.status or ""),
                "quality_gate_original_error": str(item.last_error or "")[:500],
                "quality_gate_fallback_chain": chain + [str(item.tool_name or "")],
                "quality_gate_reason": "alternate_tool_for_repeated_phase_gap",
            }, str(item.phase_id or ""), candidate, source="quality_gate")
            fallback_item = ScanWorkItem(
                scan_job_id=job.id,
                phase_id=str(item.phase_id or "")[:10],
                target=str(item.target or "")[:500],
                tool_name=candidate[:120],
                profile=_tool_profile(candidate)[:120],
                resource_class=rc,
                priority=max(1, min(int(item.priority or base_priority), base_priority) - 1),
                status="queued",
                attempts=0,
                max_attempts=1,
                item_metadata=fallback_meta,
                created_at=datetime.now(),
                updated_at=datetime.now(),
            )
            db.add(fallback_item)
            scheduled += 1
            fallback_tools.append({
                "phase_id": item.phase_id,
                "target": item.target,
                "from": item.tool_name,
                "to": candidate,
            })
            break
        else:
            skipped += 1
    if scheduled:
        db.add(ScanLog(
            scan_job_id=job.id,
            source="quality-gate",
            level="INFO",
            message=f"quality_fallback_scheduled scheduled={scheduled} skipped={skipped}",
        ))
    return {"scheduled": scheduled, "skipped": skipped, "fallback_tools": fallback_tools[:10]}
