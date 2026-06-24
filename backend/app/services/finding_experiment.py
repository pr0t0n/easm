"""Finding Intelligence v2: formal experiment + confidence ledger.

This module does not change the persistence model. It projects an existing
Finding into an auditable contract that other surfaces can consume:

- experiment: claim/preconditions/expected/observed/verdict
- proof_pack: normalized proof fields from details/reproduction metadata
- confidence_ledger: evidence signals that add/subtract confidence
- evidence_genealogy: source finding -> tool runs -> PoC validation items
- contradictions: explicit reasons a finding should not be over-trusted
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any


_SELF_VALIDATING_TOOLS = {
    "sqlmap", "dalfox", "wpscan", "hydra", "jwt_tool", "interactsh-client",
    "gitleaks", "trufflehog", "semgrep", "js_pollution_analyzer",
}


def _text(value: Any, limit: int = 1600) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        value = str(value)
    value = str(value).strip()
    if len(value) > limit:
        return value[:limit].rstrip() + "..."
    return value


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _pick(details: dict[str, Any], *keys: str, limit: int = 1600) -> str:
    for key in keys:
        value = details.get(key)
        if value not in (None, "", [], {}):
            return _text(value, limit=limit)
    return ""


def _severity_rank(severity: str | None) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
        str(severity or "info").lower(), 0
    )


def _clamp_score(value: float) -> int:
    return int(max(0, min(100, round(value))))


def _finding_family(title: str, tool: str, details: dict[str, Any]) -> str:
    blob = " ".join([
        title,
        tool,
        _text(details.get("vuln_family")),
        _text(details.get("owasp_category")),
        _text(details.get("type")),
    ]).lower()
    patterns = [
        ("sqli", r"sql injection|sqli|sqlmap"),
        ("xss", r"\bxss\b|cross.site scripting|dalfox"),
        ("ssrf", r"ssrf|server-side request forgery|interactsh"),
        ("idor_bola", r"idor|bola|broken object|access control"),
        ("auth_session", r"auth|jwt|oauth|session|cookie|token"),
        ("rce", r"\brce\b|remote code|command injection|os command"),
        ("path_traversal", r"path traversal|lfi|local file|directory traversal"),
        ("exposure", r"\.git|\.env|secret|credential|api key|information disclosure"),
        ("takeover", r"takeover|dangling cname"),
        ("misconfiguration", r"cors|clickjacking|header|hsts|csp|tls|ssl"),
    ]
    for family, pattern in patterns:
        if re.search(pattern, blob):
            return family
    return "generic"


def _expected_secure_result(family: str) -> str:
    return {
        "sqli": "Input is treated as data; no SQL behavior change, error leak or time-based delta is observed.",
        "xss": "Payload is encoded or rejected; no script execution or dangerous DOM sink is reached.",
        "ssrf": "Server rejects external/internal callback targets and no OOB interaction is observed.",
        "idor_bola": "A non-owner or lower-privileged identity receives 401/403/404 and no foreign object data.",
        "auth_session": "Session/token controls reject replay, tampering, fixation and cross-account reuse.",
        "rce": "Command payload is rejected or sandboxed; no command output or callback occurs.",
        "path_traversal": "Traversal sequence is normalized/rejected and protected files are not returned.",
        "exposure": "Sensitive file, secret or repository artifact is not publicly retrievable.",
        "takeover": "DNS target is claimed by the legitimate owner or does not resolve to a claimable service.",
        "misconfiguration": "Control is configured according to policy and cannot be bypassed by the tested request.",
    }.get(family, "The tested behavior should fail safely without exposing data or increasing privileges.")


def _observed_result(finding: Any, details: dict[str, Any]) -> str:
    observed = _pick(
        details,
        "observed_result", "observed_behavior", "evidence", "proof", "stdout",
        "output", "response", "description", "match_reason",
        limit=1200,
    )
    if observed:
        return observed
    status = str(getattr(finding, "verification_status", "") or details.get("verification_status") or "").lower()
    if status:
        return f"Finding recorded with verification_status={status}, but no detailed observed result was attached."
    return "No observed result was attached to this finding."


def _extract_reproduction(details: dict[str, Any]) -> dict[str, Any]:
    reproduction = _as_dict(details.get("reproduction"))
    commands = _as_list(reproduction.get("commands"))
    proof = _as_list(reproduction.get("proof"))
    payloads = _as_list(reproduction.get("payloads") or details.get("payloads"))

    command = _pick(details, "command", "curl_command", "proof_command", limit=1200)
    if command and not commands:
        commands = [{"tool": _text(details.get("tool"), 80), "command": command}]

    evidence = _pick(details, "evidence", "proof", "stdout", "output", "response", "banner", limit=1800)
    if evidence and not proof:
        proof = [{"summary": "finding evidence", "output": evidence}]

    return {
        "discovery_method": reproduction.get("discovery_method") or _pick(details, "source", "step", "tool", limit=160),
        "commands": commands[:8],
        "payloads": [_text(item, 400) for item in payloads[:20]],
        "proof": proof[:8],
        "steps": _as_list(reproduction.get("steps"))[:12],
        "verifiable": bool(reproduction.get("verifiable") or (commands and proof)),
    }


def _build_experiment(finding: Any, details: dict[str, Any]) -> dict[str, Any]:
    title = _text(getattr(finding, "title", ""), 500)
    tool = _text(getattr(finding, "tool", ""), 120)
    family = _finding_family(title, tool, details)
    target = (
        _text(getattr(finding, "url", ""), 500)
        or _pick(details, "url", "matched_at", "matched-at", "asset", limit=500)
        or _text(getattr(finding, "domain", ""), 255)
    )
    reproduction = _extract_reproduction(details)
    status = str(getattr(finding, "verification_status", "") or details.get("verification_status") or "").lower()
    verdict = (
        "confirmed" if status == "confirmed"
        else "refuted" if status == "refuted"
        else "hypothesis" if status == "hypothesis"
        else "candidate"
    )
    return {
        "claim": details.get("claim") or f"{title} affects {target or 'the target'}",
        "family": family,
        "target": target,
        "preconditions": _as_list(details.get("preconditions")) or _default_preconditions(family),
        "experiment": {
            "tool": tool,
            "commands": reproduction["commands"],
            "payloads": reproduction["payloads"],
            "steps": reproduction["steps"],
        },
        "expected_secure_result": details.get("expected_secure_result") or _expected_secure_result(family),
        "observed_result": _observed_result(finding, details),
        "verdict": verdict,
        "verifiable": bool(reproduction["verifiable"]),
    }


def _default_preconditions(family: str) -> list[str]:
    if family == "idor_bola":
        return ["Two authorized test identities exist", "Target object identifiers are known from the owner account"]
    if family == "auth_session":
        return ["Authorized test account/session exists", "No real user account or production secret is used"]
    if family in {"sqli", "xss", "ssrf", "rce", "path_traversal"}:
        return ["Target endpoint is in approved scope", "Payload is non-destructive and proof-oriented"]
    return ["Target is in approved scope", "Evidence collection is non-destructive"]


def _ledger_entry(signal: str, delta: int, reason: str, evidence: Any = None) -> dict[str, Any]:
    return {
        "signal": signal,
        "delta": delta,
        "reason": reason,
        "evidence": _text(evidence, 900) if evidence is not None else "",
    }


def _build_confidence_ledger(finding: Any, proof_pack: dict[str, Any], poc_items: list[Any]) -> tuple[list[dict[str, Any]], int]:
    base = int(getattr(finding, "confidence_score", None) or 50)
    status = str(getattr(finding, "verification_status", "") or _as_dict(getattr(finding, "details", {})).get("verification_status") or "").lower()
    tool = str(getattr(finding, "tool", "") or "").lower()
    severity = str(getattr(finding, "severity", "") or "info").lower()

    ledger = [_ledger_entry("base_confidence", 0, f"Stored confidence_score={base}")]
    score = float(base)

    if status == "confirmed":
        ledger.append(_ledger_entry("verification_confirmed", 18, "Evidence gate marked the finding as confirmed"))
        score += 18
    elif status == "refuted":
        ledger.append(_ledger_entry("verification_refuted", -45, "Verification/retest refuted the finding"))
        score -= 45
    elif status == "hypothesis":
        ledger.append(_ledger_entry("hypothesis_only", -22, "Finding is still a hypothesis"))
        score -= 22
    elif status == "candidate":
        ledger.append(_ledger_entry("candidate_needs_replay", -10, "Finding needs independent replay"))
        score -= 10

    if proof_pack["has_reproducible_proof"]:
        ledger.append(_ledger_entry("reproducible_proof", 16, "Commands and proof artifacts are present"))
        score += 16
    else:
        penalty = -18 if _severity_rank(severity) >= 3 else -8
        ledger.append(_ledger_entry("missing_reproducible_proof", penalty, "Proof pack is incomplete for replay"))
        score += penalty

    if tool in _SELF_VALIDATING_TOOLS:
        ledger.append(_ledger_entry("self_validating_tool", 8, f"{tool} usually proves the condition directly"))
        score += 8

    if getattr(finding, "is_false_positive", False):
        ledger.append(_ledger_entry("false_positive_marked", -80, "Human or system marked this finding as false positive"))
        score -= 80

    retest = str(getattr(finding, "retest_status", "") or "").lower()
    if retest == "confirmed":
        ledger.append(_ledger_entry("retest_confirmed", 18, "Retest confirmed the issue"))
        score += 18
    elif retest == "refuted":
        ledger.append(_ledger_entry("retest_refuted", -45, "Retest refuted the issue"))
        score -= 45
    elif retest == "pending_retest":
        ledger.append(_ledger_entry("pending_retest", -6, "Retest is pending"))
        score -= 6

    if poc_items:
        terminal = [str(getattr(item, "status", "") or "").lower() for item in poc_items]
        if any(st in {"completed", "done"} for st in terminal):
            ledger.append(_ledger_entry("poc_validation_completed", 14, "A PoC validation work item completed"))
            score += 14
        if any(st in {"failed", "timeout"} for st in terminal):
            ledger.append(_ledger_entry("poc_validation_failed", -14, "A PoC validation item failed or timed out"))
            score -= 14

    return ledger, _clamp_score(score)


def _tool_run_matches(finding: Any, run: Any) -> bool:
    f_tool = str(getattr(finding, "tool", "") or "").lower()
    r_tool = str(getattr(run, "tool_name", "") or "").lower()
    if f_tool and r_tool and (f_tool == r_tool or f_tool in r_tool or r_tool in f_tool):
        return True
    f_domain = str(getattr(finding, "domain", "") or "").lower()
    r_target = str(getattr(run, "target", "") or "").lower()
    return bool(f_domain and r_target and f_domain in r_target)


def _collect_genealogy(db: Any, finding: Any) -> tuple[dict[str, Any], list[Any]]:
    scan_id = int(getattr(finding, "scan_job_id", 0) or 0)
    genealogy = {
        "finding": {
            "id": getattr(finding, "id", None),
            "tool": getattr(finding, "tool", None),
            "created_at": _serialize_dt(getattr(finding, "created_at", None)),
        },
        "tool_runs": [],
        "poc_validation_items": [],
    }
    poc_items: list[Any] = []
    if db is None or not scan_id:
        return genealogy, poc_items

    try:
        from app.models.models import ExecutedToolRun, ScanWorkItem

        runs = (
            db.query(ExecutedToolRun)
            .filter(ExecutedToolRun.scan_job_id == scan_id)
            .order_by(ExecutedToolRun.created_at.desc())
            .limit(80)
            .all()
        )
        for run in runs:
            if _tool_run_matches(finding, run):
                genealogy["tool_runs"].append({
                    "id": run.id,
                    "tool": run.tool_name,
                    "phase_id": run.phase_id,
                    "skill_id": run.skill_id,
                    "target": run.target,
                    "status": run.status,
                    "created_at": _serialize_dt(run.created_at),
                })

        items = (
            db.query(ScanWorkItem)
            .filter(ScanWorkItem.scan_job_id == scan_id, ScanWorkItem.phase_id == "P21")
            .all()
        )
        fid = str(getattr(finding, "id", "") or "")
        for item in items:
            meta = _as_dict(getattr(item, "item_metadata", None))
            if str(meta.get("verifies_finding_id") or "") == fid:
                poc_items.append(item)
                genealogy["poc_validation_items"].append({
                    "id": item.id,
                    "tool": item.tool_name,
                    "target": item.target,
                    "status": item.status,
                    "attempts": item.attempts,
                    "last_error": item.last_error,
                    "updated_at": _serialize_dt(item.updated_at),
                })
    except Exception:
        return genealogy, poc_items

    return genealogy, poc_items


def _serialize_dt(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return None


def _build_proof_pack(finding: Any, details: dict[str, Any]) -> dict[str, Any]:
    reproduction = _extract_reproduction(details)
    evidence = _pick(details, "evidence", "proof", "stdout", "output", "response", "banner", limit=1800)
    request = _pick(details, "request", "http_request", "curl_command", "command", limit=1200)
    response = _pick(details, "response", "http_response", "body", "stdout", "output", limit=1800)
    artifact = _pick(details, "artifact", "output_file", "evidence_path", "workspace_path", limit=600)
    has_repro = bool(
        reproduction["verifiable"]
        or (reproduction["commands"] and (reproduction["proof"] or evidence or response))
        or (request and response)
    )
    return {
        "has_reproducible_proof": has_repro,
        "request": request,
        "response": response,
        "evidence": evidence,
        "artifact": artifact,
        "reproduction": reproduction,
    }


def _build_contradictions(finding: Any, proof_pack: dict[str, Any], poc_items: list[Any], final_confidence: int) -> list[dict[str, Any]]:
    contradictions: list[dict[str, Any]] = []
    status = str(getattr(finding, "verification_status", "") or "").lower()
    severity = str(getattr(finding, "severity", "") or "info").lower()

    if _severity_rank(severity) >= 3 and not proof_pack["has_reproducible_proof"]:
        contradictions.append({
            "type": "severity_without_replayable_proof",
            "message": "High/critical finding lacks a replayable proof pack.",
            "recommended_action": "Schedule controlled PoC validation or degrade to hypothesis.",
        })

    if status == "confirmed" and final_confidence < 70:
        contradictions.append({
            "type": "confirmed_low_confidence",
            "message": "Verification status is confirmed, but confidence ledger remains below promotion threshold.",
            "recommended_action": "Review evidence quality and tool output.",
        })

    if status in {"candidate", "hypothesis", ""} and proof_pack["has_reproducible_proof"]:
        contradictions.append({
            "type": "proof_present_but_not_promoted",
            "message": "Replayable proof exists, but the finding was not promoted to confirmed.",
            "recommended_action": "Run evidence adjudication for this finding.",
        })

    if any(str(getattr(item, "status", "") or "").lower() in {"failed", "timeout"} for item in poc_items):
        contradictions.append({
            "type": "poc_validation_failed",
            "message": "At least one validation work item failed or timed out.",
            "recommended_action": "Inspect P21 item output before relying on this finding.",
        })

    if getattr(finding, "is_false_positive", False) and status == "confirmed":
        contradictions.append({
            "type": "confirmed_marked_false_positive",
            "message": "Finding is confirmed but also marked as false positive.",
            "recommended_action": "Resolve lifecycle conflict manually.",
        })

    return contradictions


def build_finding_intelligence(db: Any, finding: Any) -> dict[str, Any]:
    """Build the Finding Intelligence v2 projection for one finding."""
    details = _as_dict(getattr(finding, "details", None))
    proof_pack = _build_proof_pack(finding, details)
    genealogy, poc_items = _collect_genealogy(db, finding)
    ledger, final_confidence = _build_confidence_ledger(finding, proof_pack, poc_items)
    experiment = _build_experiment(finding, details)
    contradictions = _build_contradictions(finding, proof_pack, poc_items, final_confidence)

    return {
        "finding_id": getattr(finding, "id", None),
        "scan_job_id": getattr(finding, "scan_job_id", None),
        "title": getattr(finding, "title", None),
        "severity": getattr(finding, "severity", None),
        "verification_status": getattr(finding, "verification_status", None),
        "experiment": experiment,
        "proof_pack": proof_pack,
        "confidence_ledger": ledger,
        "final_confidence": final_confidence,
        "evidence_genealogy": genealogy,
        "contradictions": contradictions,
        "promotion": {
            "can_promote": final_confidence >= 70 and proof_pack["has_reproducible_proof"] and not contradictions,
            "minimum_confidence": 70,
            "missing": [
                "replayable_proof" if not proof_pack["has_reproducible_proof"] else "",
                "contradiction_resolution" if contradictions else "",
            ],
        },
    }
