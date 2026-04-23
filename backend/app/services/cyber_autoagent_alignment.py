from __future__ import annotations

from typing import Any


CYBER_AUTOAGENT_PROMPT_PRINCIPLES = {
    "mission_stance": [
        "GOAL-FIRST: toda acao deve ter ligacao direta com o objetivo.",
        "EVIDENCE-FIRST: sem prova reproduzivel, tratar como hipotese.",
        "MINIMAL ACTION: menor acao que maximize aprendizado.",
        "ASK-ENABLE-RETRY: quando faltar capacidade, habilitar o minimo e validar.",
    ],
    "cognitive_framework": [
        "KNOW: fatos confirmados e restricoes observadas.",
        "THINK: hipotese com confianca numerica 0..100.",
        "TEST: proxima acao minima para validar a hipotese.",
        "VALIDATE: esperado vs observado, com evidencia.",
    ],
    "confidence_driven_execution": {
        "high": ">=80 -> validacao tecnica focada e confirmacao de impacto",
        "medium": "50..79 -> teste de hipotese e correlacao",
        "low": "<50 -> coleta de contexto e pivot",
    },
    "evidence_policy": {
        "critical_high_requires_proof_pack": True,
        "proof_pack_fields": [
            "validation_status",
            "artifacts",
            "rationale",
            "repro_steps",
        ],
        "default_without_proof": "hypothesis",
    },
    "checkpoints": [20, 40, 60, 80],
    "termination_policy": "Somente encerrar quando objetivo+evidencia for satisfeito ou budget esgotado.",
}


CYBER_AUTOAGENT_RUBRIC = {
    "dimensions": ["methodology", "tooling", "evidence", "outcome"],
    "weights": {
        "methodology": 0.30,
        "tooling": 0.20,
        "evidence": 0.30,
        "outcome": 0.20,
    },
}


def build_supervisor_prompt_contract(target: str, objective: str, max_iterations: int) -> dict[str, Any]:
    return {
        "persona": "Senior Cyber Analyst - evidence-first, mission-focused",
        "target": str(target or ""),
        "objective": str(objective or f"Assess external attack surface for {target}"),
        "max_iterations": int(max_iterations),
        "principles": CYBER_AUTOAGENT_PROMPT_PRINCIPLES,
        "expected_loop": ["know", "think", "test", "validate"],
    }


def evaluate_execution_quality(final_state: dict[str, Any]) -> dict[str, Any]:
    findings = list(final_state.get("vulnerabilidades_encontradas") or [])
    logs = list(final_state.get("logs_terminais") or [])
    metrics = dict(final_state.get("mission_metrics") or {})

    tools_attempted = int(metrics.get("tools_attempted", 0) or 0)
    tools_success = int(metrics.get("tools_success", 0) or 0)
    success_ratio = (tools_success / tools_attempted) if tools_attempted > 0 else 0.0

    verified = 0
    critical_high = 0
    for finding in findings:
        sev = str(finding.get("severity") or "").lower()
        details = dict(finding.get("details") or {})
        if sev in {"critical", "high"}:
            critical_high += 1
        if str(details.get("validation_status") or "").lower() == "verified":
            verified += 1

    has_supervisor_logs = any(str(line).startswith("Supervisor:") for line in logs)
    has_adjudication = any("EvidenceAdjudication" in str(line) for line in logs)
    methodology_score = 1.0 if (has_supervisor_logs and has_adjudication) else 0.6

    tooling_score = min(1.0, success_ratio + 0.1)
    evidence_score = (verified / max(1, critical_high)) if critical_high > 0 else (1.0 if findings else 0.5)

    objective_met = bool(final_state.get("objective_met"))
    termination_reason = str(final_state.get("termination_reason") or "")
    outcome_score = 1.0 if objective_met else (0.7 if termination_reason == "max_iterations_reached" else 0.5)

    weights = CYBER_AUTOAGENT_RUBRIC["weights"]
    overall = (
        methodology_score * float(weights["methodology"])
        + tooling_score * float(weights["tooling"])
        + evidence_score * float(weights["evidence"])
        + outcome_score * float(weights["outcome"])
    )
    overall_score = round(overall * 100, 2)

    risk_flags: list[str] = []
    if success_ratio < 0.4:
        risk_flags.append("low_tool_success_ratio")
    if critical_high > 0 and verified == 0:
        risk_flags.append("critical_high_without_verified_evidence")
    if not objective_met and not termination_reason:
        risk_flags.append("termination_without_explicit_reason")

    return {
        "rubric": CYBER_AUTOAGENT_RUBRIC,
        "scores": {
            "methodology": round(methodology_score * 100, 2),
            "tooling": round(tooling_score * 100, 2),
            "evidence": round(evidence_score * 100, 2),
            "outcome": round(outcome_score * 100, 2),
            "overall": overall_score,
        },
        "summary": {
            "findings_total": len(findings),
            "critical_high_total": critical_high,
            "verified_total": verified,
            "tools_attempted": tools_attempted,
            "tools_success": tools_success,
            "objective_met": objective_met,
            "termination_reason": termination_reason,
        },
        "risk_flags": risk_flags,
    }