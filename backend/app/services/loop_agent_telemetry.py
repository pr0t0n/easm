from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any, Iterable


LOOP_STEPS = ("observe", "decide", "act", "validate", "learn", "stop")
TERMINAL_WORK_STATUSES = {"completed", "done", "failed", "skipped", "timeout", "cancelled"}
ACTIVE_WORK_STATUSES = {"queued", "retry", "blocked", "dispatched", "running", "submitted"}
VERIFIED_STATUSES = {"confirmed", "proven", "validated", "verified", "true_positive", "success"}
REFUTED_STATUSES = {"refuted", "false_positive", "invalid_evidence", "not_applicable"}
ACCEPTED_RISK_STATUSES = {"accepted_risk", "risk_accepted", "accepted"}


def record_loop_event(
    state: dict[str, Any],
    *,
    loop_type: str,
    step: str,
    reason: str = "",
    action: dict[str, Any] | None = None,
    outcome: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    next_state = dict(state or {})
    normalized_step = str(step or "").strip().lower()
    if normalized_step not in LOOP_STEPS:
        normalized_step = "observe"
    event = {
        "loop_type": str(loop_type or "unknown")[:80],
        "step": normalized_step,
        "reason": str(reason or "")[:500],
        "action": dict(action or {}),
        "outcome": dict(outcome or {}),
        "evidence": dict(evidence or {}),
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    loop = dict(next_state.get("loop_agent") or {})
    events = [row for row in list(loop.get("events") or []) if isinstance(row, dict)]
    events.append(event)
    counters = dict(loop.get("counters") or {})
    counter_key = f"{event['loop_type']}:{normalized_step}"
    counters[counter_key] = int(counters.get(counter_key) or 0) + 1
    loop.update({
        "version": "loop-agent-v1",
        "steps": list(LOOP_STEPS),
        "latest": event,
        "events": events[-100:],
        "counters": counters,
    })
    next_state["loop_agent"] = loop
    return next_state


def summarize_quality_gate_loop(state: dict[str, Any], quality_gate: dict[str, Any] | None = None) -> dict[str, Any]:
    gate = dict(quality_gate or (state or {}).get("quality_gate") or {})
    history = [dict(row) for row in list(gate.get("history") or []) if isinstance(row, dict)]
    first = history[0] if history else {}
    last = history[-1] if history else gate
    first_score = _float_or_none(first.get("score"))
    last_score = _float_or_none(last.get("score") if history else gate.get("last_score"))
    observed_rounds = [
        int(row.get("round") or 0)
        for row in history
        if isinstance(row.get("round"), int) or str(row.get("round") or "").isdigit()
    ]
    rounds = max([int(gate.get("rounds") or 0), len(history), *observed_rounds] or [0])
    actions = [
        action
        for row in history
        for action in list(row.get("actions") or [])
        if isinstance(action, dict)
    ]
    return {
        "version": "quality-loop-v1",
        "steps": list(LOOP_STEPS),
        "status": str(gate.get("status") or "not_started"),
        "rounds": rounds,
        "first_score": first_score,
        "last_score": last_score,
        "score_delta": round((last_score or 0.0) - (first_score or 0.0), 2) if first_score is not None and last_score is not None else None,
        "first_grade": first.get("grade"),
        "last_grade": last.get("grade") if history else gate.get("last_grade"),
        "actions_scheduled": len(actions),
        "action_types": dict(Counter(str(action.get("type") or "unknown") for action in actions)),
        "blockers": list(gate.get("blockers") or []),
        "passed": bool(gate.get("passed") or gate.get("status") == "passed"),
        "last_actions": list(gate.get("last_actions") or [])[-10:],
    }


def classify_finding_evidence_status(finding: Any) -> str:
    details = dict(getattr(finding, "details", None) or {})
    values = {
        str(getattr(finding, "verification_status", "") or "").strip().lower(),
        str(getattr(finding, "retest_status", "") or "").strip().lower(),
        str(details.get("verification_status") or "").strip().lower(),
        str(details.get("evidence_status") or "").strip().lower(),
        str(details.get("validation_status") or "").strip().lower(),
        str(details.get("lifecycle_status") or "").strip().lower(),
    }
    if bool(getattr(finding, "is_false_positive", False)) or values & REFUTED_STATUSES:
        return "refuted"
    if values & ACCEPTED_RISK_STATUSES:
        return "accepted_risk"
    if values & VERIFIED_STATUSES:
        return "validated"
    if str(getattr(finding, "severity", "") or "").strip().lower() == "info":
        return "informational_only"
    return "candidate"


def build_finding_evidence_lifecycle(findings: Iterable[Any]) -> dict[str, Any]:
    severity_order = ("critical", "high", "medium", "low", "info")
    status_order = ("validated", "candidate", "refuted", "accepted_risk", "informational_only")
    matrix: dict[str, dict[str, int]] = {
        severity: {status: 0 for status in status_order}
        for severity in severity_order
    }
    total = Counter()
    for finding in findings:
        severity = str(getattr(finding, "severity", "") or "info").strip().lower()
        if severity not in matrix:
            severity = "info"
        status = classify_finding_evidence_status(finding)
        matrix[severity][status] += 1
        total[status] += 1
    return {
        "version": "finding-evidence-lifecycle-v1",
        "statuses": list(status_order),
        "by_severity": matrix,
        "totals": {status: int(total.get(status) or 0) for status in status_order},
        "candidate_by_severity": {
            severity: matrix[severity]["candidate"]
            for severity in severity_order
        },
    }


def build_operational_observability(job: Any, work_items: Iterable[Any]) -> dict[str, Any]:
    rows = list(work_items or [])
    status_counts = Counter(str(getattr(item, "status", "") or "unknown").lower() for item in rows)
    phase_counts: dict[str, Counter[str]] = {}
    for item in rows:
        phase = str(getattr(item, "phase_id", "") or "unknown").upper()
        phase_counts.setdefault(phase, Counter())[str(getattr(item, "status", "") or "unknown").lower()] += 1
    active_total = sum(status_counts.get(status, 0) for status in ACTIVE_WORK_STATUSES)
    terminal_total = sum(status_counts.get(status, 0) for status in TERMINAL_WORK_STATUSES)
    state = dict(getattr(job, "state_data", None) or {})
    return {
        "version": "operational-observability-v1",
        "scan_id": getattr(job, "id", None),
        "scan_status": str(getattr(job, "status", "") or ""),
        "work_items": {
            "total": len(rows),
            "active": int(active_total),
            "terminal": int(terminal_total),
            "by_status": dict(status_counts),
            "by_phase": {phase: dict(counts) for phase, counts in sorted(phase_counts.items())},
        },
        "quality_gate": {
            "active": bool(state.get("quality_gate_active")),
            "blocked": bool(state.get("quality_gate_blocked")),
            "pending_p21": int(phase_counts.get("P21", Counter()).get("queued", 0) or 0)
            + int(phase_counts.get("P21", Counter()).get("retry", 0) or 0)
            + int(phase_counts.get("P21", Counter()).get("running", 0) or 0)
            + int(phase_counts.get("P21", Counter()).get("dispatched", 0) or 0)
            + int(phase_counts.get("P21", Counter()).get("submitted", 0) or 0),
            "retry_scheduled_until": state.get("quality_gate_retry_scheduled_until"),
        },
        "finalization": {
            "terminal_waiting_finalization": str(getattr(job, "status", "") or "").lower() in {"running", "retrying"}
            and active_total == 0
            and terminal_total > 0,
            "completion_source": state.get("completion_source"),
            "current_step": getattr(job, "current_step", None),
            "mission_progress": int(getattr(job, "mission_progress", 0) or 0),
        },
    }


def build_loop_agent_quality_summary(
    *,
    state: dict[str, Any],
    quality_gate: dict[str, Any],
    findings: Iterable[Any],
    work_items: Iterable[Any],
    job: Any,
) -> dict[str, Any]:
    persisted_loop = dict(state.get("loop_agent") or {}) if isinstance(state.get("loop_agent"), dict) else {}
    return {
        "version": "loop-agent-quality-v1",
        "steps": list(LOOP_STEPS),
        "quality_gate_loop": summarize_quality_gate_loop(state, quality_gate),
        "finding_evidence_lifecycle": build_finding_evidence_lifecycle(findings),
        "operational_observability": build_operational_observability(job, work_items),
        "events": list(persisted_loop.get("events") or [])[-20:],
    }


def build_methodology_planner_trace(
    *,
    phase_context: dict[str, dict[str, Any]],
    llm_meta: dict[str, Any],
) -> dict[str, Any]:
    rag_hits = sum(len(list(row.get("rag") or [])) for row in phase_context.values())
    fallback = bool(llm_meta.get("fallback"))
    return {
        "version": "methodology-planner-trace-v1",
        "rag_consulted": True,
        "rag_hit_count": int(rag_hits),
        "mcp_consulted": True,
        "llm_attempted": True,
        "llm_available": not fallback,
        "llm_response_valid": not fallback and not bool(llm_meta.get("error")),
        "fallback_reason": str(llm_meta.get("fallback_reason") or llm_meta.get("error") or "")[:300] if fallback else "",
        "source": "deterministic_mcp_rag_fallback" if fallback else "llm_mcp_rag",
    }


def build_learning_triage_status(rows: Iterable[Any]) -> dict[str, Any]:
    status_counts = Counter(str(getattr(row, "status", "") or "unknown").lower() for row in rows)
    accepted_without_synthesis = 0
    pending_ready = 0
    for row in rows:
        status = str(getattr(row, "status", "") or "").lower()
        raw = str(getattr(row, "raw_llm_response", "") or "").strip()
        source = str(getattr(row, "source_kind", "") or "")
        if status == "accepted" and source != "curated_learning_seed" and not raw:
            accepted_without_synthesis += 1
        if status == "pending_review" and _has_learning_synthesis(row):
            pending_ready += 1
    return {
        "version": "learning-triage-status-v1",
        "by_status": dict(status_counts),
        "pending_review": int(status_counts.get("pending_review") or 0),
        "pending_ready_for_review": int(pending_ready),
        "accepted_without_synthesis": int(accepted_without_synthesis),
        "promotion_policy": "only_accept_synthesized_or_curated_rows",
    }


def build_bas_loop_summary(
    *,
    score: dict[str, Any],
    coverage: dict[str, Any],
    exposure: dict[str, Any],
    heatmap: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    priorities: list[dict[str, Any]],
    port_scan: dict[str, Any],
) -> dict[str, Any]:
    real_findings = [row for row in findings if not row.get("simulated") and row.get("proof_valid")]
    unproven_findings = [row for row in findings if not row.get("simulated") and not row.get("proof_valid")]
    missed_cells = int(dict(coverage.get("summary") or {}).get("missed") or 0)
    detected_cells = int(dict(coverage.get("summary") or {}).get("detected") or 0)
    prevented_cells = int(dict(coverage.get("summary") or {}).get("prevented") or 0)
    return {
        "version": "bas-loop-v1",
        "steps": list(LOOP_STEPS),
        "execution": {
            "dispatches": int(exposure.get("total_dispatches") or 0),
            "resolved": int(score.get("resolved_total") or 0),
            "blocked": int(score.get("blocked") or 0),
            "unproven": int(score.get("unproven") or 0),
        },
        "evidence": {
            "proof_validated_findings": len(real_findings),
            "unproven_findings": len(unproven_findings),
            "port_scan_observations": len(list(port_scan.get("scans") or [])),
        },
        "detection": {
            "prevented": prevented_cells,
            "detected": detected_cells,
            "missed": missed_cells,
        },
        "learn": {
            "techniques_tested": sum(1 for row in heatmap if int(row.get("times_tested") or 0) > 0),
            "priorities": len(priorities),
        },
        "stop": {
            "ready_for_report": int(score.get("resolved_total") or 0) > 0 and int(score.get("blocked") or 0) == 0,
            "requires_retest": bool(missed_cells or unproven_findings or int(score.get("blocked") or 0) > 0),
        },
    }


def _has_learning_synthesis(row: Any) -> bool:
    summary = str(getattr(row, "summary", "") or "").strip()
    techniques = list(getattr(row, "learned_techniques", None) or [])
    phases = list(getattr(row, "affected_phases", None) or [])
    skills = list(getattr(row, "affected_skills", None) or [])
    return bool(summary and techniques and (phases or skills))


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
