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
