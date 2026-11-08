"""JEV prioriza a ordem de validação de candidates (Fase 3 do plano).

O JEV pontua (Score 1-10) a urgência de validar um candidate, com contexto
do framework operacional (fase PXX, estágio da campanha) e da biblioteca de
skills ativas. Guardrails duros permanecem no código: o escore só define a
PRIORIDADE do work item P21 — a allowlist de tools, budgets e escopo não são
decididos pelo JEV.
"""
from __future__ import annotations

from typing import Any


def jev_validation_priority(db: Any, job: Any, finding: Any, dossier: dict[str, Any], action: dict[str, Any]) -> int | None:
    """Score 1-10 de prioridade de validação via decision_port (JEV).

    Retorna None se o JEV não responder (caller cai na prioridade padrão).
    """
    try:
        from app.services.decision_port import decide
        from app.services.candidate_validators import classify_candidate_family

        details = dict(getattr(finding, "details", None) or {})
        state = dict(getattr(job, "state_data", None) or {})
        offensive = dict(state.get("offensive_state") or {})
        skills = state.get("selected_skills") or []
        if not skills:
            skills = [str((c or {}).get("skill_id") or "") for c in list(state.get("skill_consultations") or [])[:6]]
        skills = [str(s) for s in skills if str(s)][:8]

        cand_family = classify_candidate_family(
            str(getattr(finding, "title", "") or ""),
            str(getattr(finding, "tool", "") or ""),
            details,
        ) or "unknown"

        jev_state = {
            "finding": {
                "title": str(getattr(finding, "title", "") or "")[:200],
                "severity": str(getattr(finding, "severity", "") or "info"),
                "tool": str(getattr(finding, "tool", "") or ""),
                "candidate_family": cand_family,
                "action_id": str((action or {}).get("action_id") or ""),
            },
            "framework": {
                "phase_id": str(details.get("phase_id") or ""),
                "campaign_stage": str(offensive.get("current_stage") or "scope"),
                "scan_level": str(state.get("scan_level") or ""),
            },
            "skills_active": skills,
        }
        result = decide(
            question_id="wire_validation_priority",
            kind="score",
            question=(
                "Rate 1-10 how urgent it is to validate this candidate security finding. "
                "Consider: severity, exploitability family, tool reliability, and campaign stage. "
                "10 = critical to validate now; 1 = low value."
            ),
            state=jev_state,
            scale_max=10,
            scan_id=int(getattr(job, "id", 0) or 0) or None,
            context={"finding_id": int(getattr(finding, "id", 0) or 0), "candidate_family": cand_family},
        )
        if result.get("below_threshold") or result.get("source") != "jev":
            return None
        value = int(result.get("value") or 0)
        return value if 1 <= value <= 10 else None
    except Exception:  # noqa: BLE001 — priorização é otimização, nunca bloqueia
        return None
