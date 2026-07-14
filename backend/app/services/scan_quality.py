from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.graph.mission import PENTEST_PHASES
from app.models.models import (
    CoverageItem,
    EvidenceArtifact,
    ExecutedToolRun,
    Finding,
    OffensiveAsset,
    OffensiveEndpoint,
    RetestRun,
    ScanJob,
    ScanLog,
    ScanWorkItem,
    ValidationRun,
)
from app.services.phase_monitor import build_phase_monitor
from app.services.scan_profiles import scan_profile


VERIFIED_STATUSES = {"confirmed", "proven", "validated", "verified", "true_positive"}
CANDIDATE_STATUSES = {"candidate", "needs_review", "hypothesis"}
SUCCESS_VALIDATION_RESULTS = {"confirmed", "validated", "success", "proven", "positive", "true_positive"}
TESTED_COVERAGE_STATUSES = {"tested", "covered", "validated", "completed", "done", "confirmed"}
QUALITY_GATE_SCORE_THRESHOLD = 70.0
QUALITY_GATE_MAX_ROUNDS = 2
QUALITY_GATE_MAX_POC_PER_ROUND = 12
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
    "P15": ["ffuf", "ffuf-files", "feroxbuster", "dirsearch", "gobuster"],
    "P16": ["ffuf-params", "wfuzz", "wapiti", "nuclei"],
    "P18": ["sslscan", "testssl", "nmap-ssl-vuln"],
    "P20": ["wpscan", "nuclei", "nikto"],
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


def build_scan_quality(db: Session, job: ScanJob) -> dict[str, Any]:
    phase_monitor = build_phase_monitor(db, job)
    expected_phase_ids = _expected_phase_ids(job)
    profile = scan_profile(_scan_level(job))

    findings = db.query(Finding).filter(Finding.scan_job_id == job.id).all()
    finding_ids = [int(f.id) for f in findings]
    artifacts = db.query(EvidenceArtifact).filter(EvidenceArtifact.scan_job_id == job.id).all()
    artifacts_by_finding: Counter[int] = Counter(
        int(a.finding_id) for a in artifacts if a.finding_id is not None
    )
    validations = db.query(ValidationRun).filter(ValidationRun.scan_job_id == job.id).all()
    retests = db.query(RetestRun).filter(RetestRun.scan_job_id == job.id).all()
    coverage_items = db.query(CoverageItem).filter(CoverageItem.scan_job_id == job.id).all()
    work_items = db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == job.id).all()
    endpoints_count = db.query(OffensiveEndpoint.id).filter(OffensiveEndpoint.scan_job_id == job.id).count()
    offensive_assets_count = db.query(OffensiveAsset.id).filter(OffensiveAsset.scan_job_id == job.id).count()
    tool_runs = db.query(ExecutedToolRun).filter(ExecutedToolRun.scan_job_id == job.id).all()

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
        evidence_ratio = 1.0 if artifacts else 0.35
        verification_ratio = 1.0 if not high_findings else 0.0
        reproduction_ratio = 0.0
        evidence_score = 75.0 if artifacts else 45.0
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
    if not validations and findings:
        validation_score = min(validation_score, 45.0)

    monitor_metrics = dict(phase_monitor.get("metrics") or {})
    attempted = max(
        int(monitor_metrics.get("tools_attempted") or 0),
        len(tool_runs),
        len([w for w in work_items if str(w.status or "").lower() not in {"queued", "blocked"}]),
    )
    succeeded = max(
        int(monitor_metrics.get("tools_success") or 0),
        len([r for r in tool_runs if str(r.status or "").lower() == "success"]),
        len([w for w in work_items if str(w.status or "").lower() in {"completed", "done"}]),
    )
    failed_tools = len([w for w in work_items if str(w.status or "").lower() in {"failed", "timeout"}])
    success_ratio = _ratio(succeeded, attempted) if attempted else 0.0
    missing_required = sum(
        len(row.get("required_tools_missing") or [])
        for row in (phase_monitor.get("pentest_journey") or {}).get("phases") or []
        if str(row.get("phase_id") or "") in expected_phase_ids
    )
    tool_score = (success_ratio * 100) - min(35, missing_required * 4) - min(20, failed_tools * 0.25)
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
            "findings_with_evidence": len(findings_with_evidence),
            "findings_with_reproduction": len(findings_with_repro),
            "verified_findings": len(verified_findings),
            "candidate_findings": len(candidate_findings),
            "artifacts_total": len(artifacts),
        },
        "validation_depth": {
            "score": round(_clamp(validation_score), 1),
            "weight": 20,
            "validation_runs": len(validations),
            "successful_validations": len(successful_validations),
            "retests": len(retests),
            "high_findings": len(high_findings),
            "high_verified": len(high_verified),
        },
        "tool_reliability": {
            "score": round(_clamp(tool_score), 1),
            "weight": 15,
            "tools_attempted": attempted,
            "tools_succeeded": succeeded,
            "failed_work_items": failed_tools,
            "missing_required_tools": missing_required,
        },
        "surface_coverage": {
            "score": round(_clamp(surface_score), 1),
            "weight": 10,
            "coverage_items": len(coverage_items),
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
    if attempted and success_ratio < 0.75:
        gaps.append({
            "severity": "medium",
            "area": "tool_reliability",
            "title": "Taxa de sucesso das ferramentas abaixo do ideal",
            "detail": f"{succeeded}/{attempted} execuções com sucesso.",
            "action": "Revisar módulos Kali, timeouts, concorrência e dependências do runner.",
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
        "quality_gate": dict((job.state_data or {}).get("quality_gate") or {}),
        "components": components,
        "summary": {
            "findings_total": len(findings),
            "verified_findings": len(verified_findings),
            "candidate_findings": len(candidate_findings),
            "artifacts_total": len(artifacts),
            "validation_runs": len(validations),
            "coverage_items": len(coverage_items),
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
            "Reexecutar fases com work items falhos antes de concluir o relatório executivo.",
        ],
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

    validation_changes = _apply_promotion_gate(db, job)
    quality = build_scan_quality(db, job)
    actions: list[dict[str, Any]] = []

    if rounds >= QUALITY_GATE_MAX_ROUNDS:
        gate_state.update({
            "status": "exhausted",
            "last_score": quality.get("score"),
            "last_grade": quality.get("grade"),
            "reason": "max_quality_gate_rounds_reached",
        })
        state["quality_gate"] = gate_state
        job.state_data = state
        db.add(job)
        return {
            "passed": True,
            "status": "exhausted",
            "actions": actions,
            "validation_changes": validation_changes,
            "quality": quality,
        }

    poc_result = _schedule_quality_poc_validations(db, job)
    if int(poc_result.get("scheduled", 0) or 0) > 0:
        actions.append({"type": "schedule_p21_validation", **poc_result})

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

    passed = not actions
    gate_state.update({
        "status": "passed" if passed else "remediation_scheduled",
        "rounds": rounds + (0 if passed else 1),
        "last_score": quality.get("score"),
        "last_grade": quality.get("grade"),
        "threshold": QUALITY_GATE_SCORE_THRESHOLD,
        "validation_changes": validation_changes,
        "last_actions": actions,
    })
    history = list(gate_state.get("history") or [])
    history.append({
        "round": rounds + 1,
        "score": quality.get("score"),
        "grade": quality.get("grade"),
        "actions": actions,
    })
    gate_state["history"] = history[-10:]
    state["quality_gate"] = gate_state
    job.state_data = state
    db.add(job)

    return {
        "passed": passed,
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
