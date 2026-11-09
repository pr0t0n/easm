"""Seleção de skill/hipótese pelo JEV (Estágio 3 do fluxo).

`Choice` dentro do espaço proposto pelo código: as opções são exatamente as
skills que o engine já ordenou (approved para a fase). O JEV recebe o
ambiente (Estágio 2: recuperação semântica + tech stack + ATT&CK da família)
e escolhe qual deve ir primeiro. Abaixo do limiar ou JEV indisponível → a
ordem do engine (heurística atual) permanece.
"""
from __future__ import annotations

from typing import Any


def jev_select_next_skill(
    ordered_sids: list[str],
    *,
    phase_id: str,
    offensive_state: dict[str, Any] | None = None,
    scan_id: int | None = None,
    threshold: float | None = None,
) -> str | None:
    """Escolhe a skill que melhor corresponde ao ambiente. None = manter ordem."""
    options = [str(s) for s in list(ordered_sids or []) if str(s).strip()][:8]
    if len(options) < 2:
        return None
    state = dict(offensive_state or {})
    try:
        from app.services.decision_port import decide
        from app.services.skill_environment_retrieval import retrieve_skills_for_environment
        from app.services.framework_mapping import attack_for_family

        tech = [str(t) for t in list(state.get("technologies") or state.get("tech_stack") or [])[:8]]
        findings = list(state.get("findings") or [])[:6]
        retrieved = retrieve_skills_for_environment(
            tech_stack=tech, phase_id=phase_id, surface="web", findings=findings, top_k=6,
        )
        fam = str(state.get("candidate_family") or "")
        attack = attack_for_family(fam) if fam else None
        jev_state = {
            "environment": {"tech": tech, "phase": phase_id},
            "retrieved_skills_semantically": [r["skill_id"] for r in retrieved[:6]],
            "engine_ordered_skills": options,
            "family_attack_context": (attack or {}).get("technique") or "",
        }
        result = decide(
            question_id="skill_selection",
            kind="choice",
            question=(
                "Which of the engine-ordered skills best matches this environment? "
                "Consider the technology stack, the phase, and the attack technique context. "
                "Choose exactly one of the engine_ordered_skills."
            ),
            options=options,
            state=jev_state,
            scan_id=scan_id,
            context={"phase_id": phase_id, "stage": "selection"},
            threshold=threshold,
        )
        if result.get("source") != "jev" or result.get("below_threshold"):
            return None
        value = str(result.get("value") or "")
        return value if value in set(ordered_sids) else None
    except Exception:  # noqa: BLE001 — seleção é otimização, nunca bloqueia
        return None


def rerank_sids_with_jev(
    ordered_sids: list[str],
    *,
    phase_id: str,
    offensive_state: dict[str, Any] | None = None,
    scan_id: int | None = None,
) -> tuple[list[str], str | None]:
    """Aplica a escolha do JEV: skill escolhida vai para frente. Retorna
    (nova_ordem, skill_escolhida_ou_None)."""
    chosen = jev_select_next_skill(
        ordered_sids, phase_id=phase_id, offensive_state=offensive_state, scan_id=scan_id,
    )
    if not chosen or chosen == ordered_sids[0]:
        return list(ordered_sids), None
    return [chosen] + [s for s in ordered_sids if s != chosen], chosen
