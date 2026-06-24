"""Scan uncertainty map, exploration debt and scan autopsy.

The goal is to make scan quality explicit. A scan that finds nothing is not
automatically "clean"; it may have untested auth, API, JS, cloud, CVE or proof
surfaces. This module turns existing work items/findings/logs into a concise
coverage and uncertainty contract.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


_TERMINAL = {"completed", "done", "failed", "timeout", "skipped", "not_applicable", "blocked"}
_SUCCESS = {"completed", "done"}
_ACTIVE = {"queued", "running", "submitted", "dispatched", "retry"}


SURFACES: dict[str, dict[str, Any]] = {
    "external_surface": {
        "label": "Superfície externa",
        "phases": {"P01", "P02"},
        "tools": {"subfinder", "amass", "httpx", "naabu", "nmap", "shodan-cli"},
        "finding_terms": ("subdomain", "port", "http ativo", "host http", "tls"),
        "expected": "subdomains, live hosts, open ports and protocol baseline",
    },
    "web_content": {
        "label": "Conteúdo web",
        "phases": {"P03", "P04", "P05", "P06"},
        "tools": {"katana", "gospider", "hakrawler", "ffuf", "gobuster", "feroxbuster", "dirsearch"},
        "finding_terms": ("path", "endpoint", "directory", "url", "admin"),
        "expected": "paths, routes, forms and hidden endpoints",
    },
    "api_surface": {
        "label": "API",
        "phases": {"P16", "P17", "P19"},
        "tools": {"arjun", "paramspider", "nuclei-graphql", "curl-headers", "business_logic_backend"},
        "finding_terms": ("api", "graphql", "swagger", "openapi", "parameter"),
        "expected": "API endpoints, parameters, GraphQL/OpenAPI and object boundaries",
    },
    "auth_session": {
        "label": "Autenticação e sessão",
        "phases": {"P18", "P19", "P20"},
        "tools": {"multi-identity-tester", "jwt_tool", "nuclei-auth", "nuclei-jwt", "zap-active-scan-auth"},
        "finding_terms": ("auth", "jwt", "session", "cookie", "idor", "bola", "bfla"),
        "expected": "role comparison, session controls, JWT/OAuth and BOLA/BFLA checks",
    },
    "vuln_validation": {
        "label": "Validação de vulnerabilidade",
        "phases": {"P10", "P11", "P12", "P13", "P14", "P21"},
        "tools": {"nuclei", "sqlmap", "dalfox", "wapiti", "interactsh-client", "wpscan"},
        "finding_terms": ("xss", "sqli", "ssrf", "rce", "cve", "injection", "confirmed"),
        "expected": "active non-destructive validation and PoC replay for high-value claims",
    },
    "cloud_secrets": {
        "label": "Cloud e segredos",
        "phases": {"P15", "P22"},
        "tools": {"gitleaks", "trufflehog", "semgrep", "nuclei-exposure", "git-dumper"},
        "finding_terms": ("secret", "credential", ".git", ".env", "aws", "token"),
        "expected": "exposed repositories, secrets, buckets and deployment artifacts",
    },
    "business_logic": {
        "label": "Lógica de negócio",
        "phases": {"P19", "P20"},
        "tools": {"business_logic_probe", "business_logic_analyzer", "business_logic_backend", "multi-identity-tester"},
        "finding_terms": ("business_logic", "negative", "workflow", "price", "coupon", "payment", "tenant"),
        "expected": "invariants, workflow abuse and tenant/role logic",
    },
    "reporting_evidence": {
        "label": "Evidência e relatório",
        "phases": {"P21", "P22"},
        "tools": {"evidence_gate", "reporting", "poc_validation"},
        "finding_terms": ("proof", "evidence", "verification_status", "reproduction"),
        "expected": "proof packs, verification status and reproducible evidence",
    },
}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _surface_for_item(item: Any) -> str | None:
    phase = str(getattr(item, "phase_id", "") or "")
    tool = _norm(getattr(item, "tool_name", "") or getattr(item, "tool", ""))
    profile = _norm(getattr(item, "profile", ""))
    priority = [
        "auth_session", "business_logic", "vuln_validation", "cloud_secrets",
        "api_surface", "web_content", "external_surface", "reporting_evidence",
    ]
    for key in priority:
        cfg = SURFACES[key]
        if tool in cfg["tools"] or profile in cfg["tools"]:
            return key
    for key, cfg in SURFACES.items():
        if phase in cfg["phases"]:
            return key
    return None


def _surface_for_finding(finding: Any) -> str | None:
    blob = " ".join([
        _norm(getattr(finding, "title", "")),
        _norm(getattr(finding, "tool", "")),
        _norm(getattr(finding, "severity", "")),
        _norm(getattr(finding, "verification_status", "")),
        _norm(getattr(finding, "details", "")),
    ])
    priority = [
        "auth_session", "business_logic", "vuln_validation", "cloud_secrets",
        "api_surface", "web_content", "external_surface", "reporting_evidence",
    ]
    for key in priority:
        cfg = SURFACES[key]
        if any(term in blob for term in cfg["finding_terms"]):
            return key
    return None


def _confidence_from_counts(total: int, success: int, failed: int, findings: int) -> tuple[str, int]:
    if total == 0:
        return "unknown", 0
    completion = success / max(1, total)
    if success == 0 and failed > 0:
        return "low", 20
    if completion >= 0.75 and findings > 0:
        return "high", 85
    if completion >= 0.5:
        return "medium", 65
    if completion > 0:
        return "low", 40
    return "unknown", 15


def build_uncertainty_from_records(job: Any, work_items: list[Any], findings: list[Any], logs: list[Any] | None = None) -> dict[str, Any]:
    logs = logs or []
    per_surface = {
        key: {
            "surface": key,
            "label": cfg["label"],
            "expected": cfg["expected"],
            "work_items_total": 0,
            "work_items_success": 0,
            "work_items_failed": 0,
            "work_items_active": 0,
            "findings": 0,
            "confirmed_findings": 0,
            "coverage": "unknown",
            "confidence": 0,
            "gaps": [],
        }
        for key, cfg in SURFACES.items()
    }

    status_counts = Counter()
    phase_counts = defaultdict(Counter)
    for item in work_items:
        status = _norm(getattr(item, "status", ""))
        phase = str(getattr(item, "phase_id", "") or "")
        status_counts[status] += 1
        if phase:
            phase_counts[phase][status] += 1
        surface = _surface_for_item(item)
        if not surface:
            continue
        slot = per_surface[surface]
        slot["work_items_total"] += 1
        if status in _SUCCESS:
            slot["work_items_success"] += 1
        elif status in {"failed", "timeout"}:
            slot["work_items_failed"] += 1
        elif status in _ACTIVE:
            slot["work_items_active"] += 1

    for finding in findings:
        if getattr(finding, "is_false_positive", False):
            continue
        surface = _surface_for_finding(finding)
        if not surface:
            continue
        per_surface[surface]["findings"] += 1
        if _norm(getattr(finding, "verification_status", "")) == "confirmed":
            per_surface[surface]["confirmed_findings"] += 1

    exploration_debt = []
    for key, slot in per_surface.items():
        coverage, confidence = _confidence_from_counts(
            slot["work_items_total"],
            slot["work_items_success"],
            slot["work_items_failed"],
            slot["findings"],
        )
        slot["coverage"] = coverage
        slot["confidence"] = confidence
        if slot["work_items_total"] == 0:
            slot["gaps"].append("no_tests_executed")
            exploration_debt.append({
                "surface": key,
                "label": slot["label"],
                "reason": "No work items mapped to this surface.",
                "recommended_action": f"Run coverage for: {slot['expected']}.",
                "severity": "medium" if key in {"auth_session", "api_surface", "vuln_validation"} else "low",
            })
        elif slot["work_items_success"] == 0:
            slot["gaps"].append("no_successful_tests")
            exploration_debt.append({
                "surface": key,
                "label": slot["label"],
                "reason": "Tests were scheduled but none completed successfully.",
                "recommended_action": "Inspect failed/timeout tools and rerun with adjusted rate/timeouts.",
                "severity": "high" if key in {"auth_session", "vuln_validation"} else "medium",
            })
        elif slot["work_items_active"] > 0:
            slot["gaps"].append("work_still_active")

        if key == "auth_session" and slot["work_items_total"] > 0 and slot["confirmed_findings"] == 0:
            slot["gaps"].append("no_role_boundary_evidence")
        if key == "reporting_evidence" and slot["confirmed_findings"] == 0:
            slot["gaps"].append("no_confirmed_proof_pack")

    log_blob = "\n".join(_norm(getattr(log, "message", "")) for log in logs[-200:])
    autopsy = []
    if not findings:
        autopsy.append("Scan produced no findings; interpret result as coverage-dependent, not clean.")
    if any(status_counts.get(st, 0) for st in ("failed", "timeout")):
        autopsy.append("Some work items failed or timed out; coverage may be incomplete.")
    if "waf" in log_blob or "429" in log_blob or "rate" in log_blob:
        autopsy.append("Logs suggest WAF/rate-limit friction; lower rate or use adaptive noise control.")
    if per_surface["auth_session"]["work_items_total"] == 0:
        autopsy.append("Authenticated/role-based testing did not run; IDOR/BOLA/BFLA confidence is low.")
    if per_surface["reporting_evidence"]["confirmed_findings"] == 0:
        autopsy.append("No confirmed proof-pack evidence was observed; promote findings cautiously.")

    total_surfaces = len(per_surface)
    high_or_medium = sum(1 for s in per_surface.values() if s["coverage"] in {"high", "medium"})
    coverage_score = round((high_or_medium / max(1, total_surfaces)) * 100)

    return {
        "scan_id": getattr(job, "id", None),
        "target": getattr(job, "target_query", None),
        "status": getattr(job, "status", None),
        "coverage_score": coverage_score,
        "surface_count": total_surfaces,
        "covered_surface_count": high_or_medium,
        "status_counts": dict(status_counts),
        "uncertainty_map": list(per_surface.values()),
        "exploration_debt": exploration_debt,
        "autopsy": autopsy,
        "phase_status": {phase: dict(counts) for phase, counts in sorted(phase_counts.items())},
    }


def build_scan_uncertainty(db: Any, job: Any) -> dict[str, Any]:
    """Load records from DB and build uncertainty projection for a scan."""
    from app.models.models import Finding, ScanLog, ScanWorkItem

    scan_id = int(getattr(job, "id", 0))
    work_items = db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == scan_id).all()
    findings = db.query(Finding).filter(Finding.scan_job_id == scan_id).all()
    logs = (
        db.query(ScanLog)
        .filter(ScanLog.scan_job_id == scan_id)
        .order_by(ScanLog.created_at.asc())
        .limit(500)
        .all()
    )
    return build_uncertainty_from_records(job, work_items, findings, logs)
