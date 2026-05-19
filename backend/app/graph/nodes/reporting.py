from __future__ import annotations

import logging
from typing import Any

from app.graph.state import AgentState

logger = logging.getLogger(__name__)


def governance_node(state: AgentState) -> AgentState:
    from app.graph.workflow import _metric_start, _metric_end, _sync_step_to_db
    from app.graph.nodes.supervisor import _complete_delegation_task
    from app.services.risk_service import (
        build_fair_decomposition,
        compute_easm_rating,
        compute_asset_risk,
        METHODOLOGY_VERSION,
    )

    state["routing_next_node"] = "executive_analyst"
    started_at = _metric_start()
    _sync_step_to_db(state, "4. Governance")
    state["logs_terminais"].append("Governance: calculando FAIR+AGE rating")

    findings = state.get("vulnerabilidades_encontradas") or []
    discovered = state.get("lista_ativos") or [state["target"]]
    n_assets = max(1, len(discovered))

    # Computa Ra por finding e coleta para o rating global
    risk_per_asset: list[dict[str, Any]] = []
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        if sev in {"info"}:
            continue
        details = f.get("details") or {}
        asset = str(details.get("asset") or state["target"])
        days = int(details.get("known_in_environment_days") or details.get("age_days") or 0)
        cvss = details.get("cvss_score") or details.get("cvss")
        port = details.get("port")
        ra = compute_asset_risk(
            asset_url=asset,
            severity=sev,
            days_open=days,
            cvss=float(cvss) if cvss is not None else None,
            port=int(port) if port is not None else None,
        )
        risk_per_asset.append(ra)

    # Score global normalizado pela superfície digital
    easm_rating = compute_easm_rating(risk_per_asset, n_assets=n_assets)

    # Decomposição formal por 3 pilares FAIR
    fair_decomp = build_fair_decomposition(findings, n_assets=n_assets)

    state["easm_rating"] = {
        **easm_rating,
        "methodology": f"{METHODOLOGY_VERSION}/easm_fair_age_v1",
        "n_assets_scanned": n_assets,
    }
    state["fair_decomposition"] = fair_decomp
    state["logs_terminais"].append(
        f"Governance: score={easm_rating['score']} grade={easm_rating['grade']} "
        f"n_assets={n_assets} total_ra={easm_rating['total_ra']}"
    )
    _complete_delegation_task(state, "governance", f"score={easm_rating.get('score', 0)}")
    # mission_index já foi incrementado pelos agentes paralelos (threat_intel + risk_assessment)
    _metric_end(state, "governance", started_at)
    # Sincronizar novamente apos _metric_end para garantir node_history atualizado
    _sync_step_to_db(state, "4. Governance")
    return state


def executive_analyst_node(state: AgentState) -> AgentState:
    from app.graph.workflow import _metric_start, _metric_end, _sync_step_to_db
    from app.graph.nodes.supervisor import _complete_delegation_task

    state["routing_next_node"] = "END"
    started_at = _metric_start()
    _sync_step_to_db(state, "5. ExecutiveAnalysis")
    state["logs_terminais"].append("ExecutiveAnalyst: gerando narrativa executiva")

    easm_rating = state.get("easm_rating") or {}
    fair_decomp = state.get("fair_decomposition") or {}
    target = state.get("target", "alvo")
    score = easm_rating.get("score", 0)
    grade = easm_rating.get("grade", "F")
    pillars = fair_decomp.get("pillars") or []
    n_assets = easm_rating.get("n_assets_scanned", 1)

    # Tenta gerar narrativa via Ollama; se falhar, usa template estruturado
    try:
        import httpx
        from app.core.config import settings

        pillar_lines = ""
        for p in pillars:
            pillar_lines += (
                f"  - {p['name']} ({p['weight_pct']}): "
                f"score={p['score']}, impact=-{p['impact_pts']}pts, "
                f"{p['finding_count']} findings\n"
            )
        top_pilar = max(pillars, key=lambda x: x.get("impact_pts", 0), default={}) if pillars else {}

        prompt = (
            f"Atue como CISO. Converta os dados técnicos abaixo em uma análise executiva em português. "
            f"Seja direto, use impacto financeiro e mencione urgência de remediação.\n\n"
            f"Alvo: {target}\n"
            f"Rating: {score}/100 (Grau {grade})\n"
            f"Ativos mapeados: {n_assets}\n"
            f"Decomposição FAIR:\n{pillar_lines}"
            f"Principal detrator: {top_pilar.get('name', 'N/A')} (-{top_pilar.get('impact_pts', 0)}pts)\n\n"
            f"Gere: (1) Resumo executivo 2 frases, (2) Principal risco com impacto de negócio, "
            f"(3) Ação imediata recomendada. Máximo 150 palavras."
        )
        resp = httpx.post(
            f"{settings.ollama_base_url}/api/generate",
            json={"model": settings.ollama_model, "prompt": prompt, "stream": False},
            timeout=20.0,
        )
        if resp.status_code == 200:
            narrative = str(resp.json().get("response") or "").strip()
            state["executive_summary"] = narrative if narrative else _fallback_executive_summary(easm_rating, fair_decomp, target)
        else:
            state["executive_summary"] = _fallback_executive_summary(easm_rating, fair_decomp, target)
    except Exception as exc:
        state["logs_terminais"].append(f"ExecutiveAnalyst: ollama_unavailable ({exc.__class__.__name__}), usando template")
        state["executive_summary"] = _fallback_executive_summary(easm_rating, fair_decomp, target)

    state["logs_terminais"].append(f"ExecutiveAnalyst: narrative_length={len(state.get('executive_summary', ''))}")

    # Append phase execution journey to executive summary
    _attach_phase_journey_to_state(state)

    _complete_delegation_task(state, "executive_analyst", "executive_summary_generated")
    state["mission_index"] += 1
    _metric_end(state, "executive_analyst", started_at)
    # Sincronizar novamente apos _metric_end para garantir node_history atualizado
    _sync_step_to_db(state, "5. ExecutiveAnalysis")
    return state


def _fallback_executive_summary(easm_rating: dict, fair_decomp: dict, target: str) -> str:
    """Template estruturado usado quando o Ollama não está disponível."""
    score = easm_rating.get("score", 0)
    grade = easm_rating.get("grade", "F")
    pillars = fair_decomp.get("pillars") or []
    top_pilar = max(pillars, key=lambda x: x.get("impact_pts", 0), default={}) if pillars else {}
    main_detractor = top_pilar.get("name", "vulnerabilidades não remediadas")
    main_pts = top_pilar.get("impact_pts", 0)
    finding_count = sum(p.get("finding_count", 0) for p in pillars)
    return (
        f"A postura de segurança externa de '{target}' recebeu rating {score}/100 (Grau {grade}). "
        f"Foram identificados {finding_count} issues técnicos distribuídos em {len(pillars)} dimensões de risco. "
        f"O principal detrator é '{main_detractor}', responsável por {main_pts} pontos de impacto no rating. "
        f"Ação imediata: priorizar remediação dos findings críticos/altos — a penalidade AGE "
        f"aumenta logaritmicamente a cada dia sem correção, amplificando o risco de exploração."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase Journey Report — appended to executive_summary and saved in state
# ─────────────────────────────────────────────────────────────────────────────

def build_phase_journey_report(state: AgentState) -> str:
    """Build a structured offensive campaign journey from phase_ledger state.

    Returns a text block suitable for inclusion in the executive summary or
    stored separately in the report. Never raises — returns empty string on error.
    """
    try:
        from app.graph.mission import PENTEST_PHASES
    except ImportError:
        return ""

    phase_ledger = dict(state.get("phase_ledger") or {})
    attack_paths = list(state.get("attack_paths") or [])
    active_hypotheses = list(state.get("active_hypotheses") or [])
    validated_chains = list(state.get("validated_chains") or [])
    target = str(state.get("target") or "unknown")

    lines: list[str] = [
        "",
        "═══════════════════════════════════════════════════════",
        "  OFFENSIVE CAMPAIGN JOURNEY — PHASE EXECUTION REPORT",
        "═══════════════════════════════════════════════════════",
        f"  Target: {target}",
        f"  Phases in plan: {len(PENTEST_PHASES)}",
        "",
        "  ── PHASE EXECUTION LEDGER ──────────────────────────",
    ]

    completed_count = 0
    partial_count = 0
    skipped_count = 0
    blocked_count = 0

    for phase in PENTEST_PHASES:
        phase_id = str(phase.get("id") or "")
        phase_title = str(phase.get("title") or phase_id)
        entry = dict(phase_ledger.get(phase_id) or {})
        status = str(entry.get("status") or "not_started")
        tools_attempted = list(entry.get("tools_attempted") or [])
        tools_succeeded = list(entry.get("tools_succeeded") or [])
        evidence_ids = list(entry.get("evidence_ids") or [])
        skill_ctx = dict(entry.get("skill_context") or {})
        skill_id = str(skill_ctx.get("skill_id") or "—")
        skip_reason = str(entry.get("skip_reason") or "")
        validation_result = dict(entry.get("validation_result") or {})
        can_advance = bool(validation_result.get("can_advance", False))

        status_icon = {
            "completed": "✓",
            "partial": "~",
            "skipped": "⊘",
            "blocked": "✗",
            "failed": "✗",
            "not_started": "·",
            "pending": "·",
        }.get(status, "?")

        if status == "completed":
            completed_count += 1
        elif status == "partial":
            partial_count += 1
        elif status in ("skipped",):
            skipped_count += 1
        elif status in ("blocked", "failed"):
            blocked_count += 1

        line = (
            f"  [{status_icon}] {phase_id} {phase_title[:40]:<40} "
            f"status={status:<10} "
            f"tools={len(tools_attempted)}/{len(tools_succeeded)} "
            f"evidence={len(evidence_ids)}"
        )
        if skill_id != "—":
            line += f"  skill={skill_id}"
        if skip_reason:
            line += f"  ({skip_reason[:50]})"
        lines.append(line)

    lines += [
        "",
        f"  Summary: completed={completed_count} partial={partial_count} "
        f"skipped={skipped_count} blocked={blocked_count}",
    ]

    # Attack chains
    if validated_chains:
        lines += ["", "  ── VALIDATED ATTACK CHAINS ────────────────────────"]
        for chain in validated_chains[:5]:
            chain_name = str(chain.get("name") or chain.get("chain_id") or "unknown")
            cvss = chain.get("cvss_estimate") or "N/A"
            confidence = chain.get("confidence") or 0
            lines.append(
                f"  ► {chain_name} "
                f"cvss={cvss} confidence={confidence:.0%}"
            )

    # Attack paths
    if attack_paths:
        lines += ["", "  ── ATTACK PATHS ────────────────────────────────────"]
        for path in attack_paths[:5]:
            if isinstance(path, dict):
                path_desc = str(path.get("description") or path.get("signal") or str(path))
            else:
                path_desc = str(path)
            lines.append(f"  → {path_desc[:100]}")

    # Hypotheses summary
    if active_hypotheses:
        open_h = [h for h in active_hypotheses if str(h.get("status") or "open") == "open"]
        validated_h = [h for h in active_hypotheses if str(h.get("status") or "") == "validated"]
        lines += [
            "",
            f"  ── HYPOTHESES: total={len(active_hypotheses)} "
            f"open={len(open_h)} validated={len(validated_h)} ──",
        ]
        for h in validated_h[:3]:
            lines.append(f"  ✓ [validated] {str(h.get('statement') or h.get('hypothesis') or '')[:80]}")
        for h in open_h[:3]:
            lines.append(f"  · [open]      {str(h.get('statement') or h.get('hypothesis') or '')[:80]}")

    lines += [
        "",
        "═══════════════════════════════════════════════════════",
        "",
    ]

    return "\n".join(lines)


def _attach_phase_journey_to_state(state: AgentState) -> None:
    """Build phase journey report and attach it to executive_summary and logs."""
    try:
        journey = build_phase_journey_report(state)
        if not journey:
            return
        current_summary = str(state.get("executive_summary") or "")
        state["executive_summary"] = current_summary + "\n" + journey
        state["logs_terminais"].append(
            f"PhaseJourney: appended {len(journey)} chars to executive_summary"
        )
    except Exception as exc:
        logger.warning("reporting: failed to build phase journey: %s", exc)
