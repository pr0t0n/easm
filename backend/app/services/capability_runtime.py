from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


CAPABILITY_CONTRACT: dict[str, dict[str, Any]] = {
    "strategic_planning": {
        "label": "Strategic Planning",
        "definition": "Define objetivo, rota, orçamento, kill-chain stage, próximos nós e restrições antes de executar ferramentas.",
        "aliases": ["supervisor", "skill_planner"],
        "required_evidence": ["supervisor_route", "selected_skill", "operation_plan", "pentest_strategy"],
    },
    "asset_discovery": {
        "label": "Asset Discovery",
        "definition": "Mapeia ativos, serviços, URLs, tecnologias, parâmetros e sinais de superfície de ataque.",
        "aliases": ["asset_discovery", "reconnaissance"],
        "required_evidence": ["recon_graph", "executed_tool_runs", "discovered_ports", "lista_ativos"],
    },
    "threat_intel": {
        "label": "Threat Intel",
        "definition": "Correlaciona OSINT, CVE, takeover, secrets e exposição externa com ativos em escopo.",
        "aliases": ["threat_intel", "weaponization"],
        "required_evidence": ["executed_tool_runs", "pentest_strategy", "vulnerabilidades_encontradas"],
    },
    "adversarial_hypothesis": {
        "label": "Adversarial Hypothesis",
        "definition": "Converte sinais do RECON em hipóteses testáveis e seleciona skills/ferramentas por evidência.",
        "aliases": ["skill_selector", "skill_planner", "tool_selector"],
        "required_evidence": ["pentest_hypotheses", "skill_invocation", "tool_selection_contract", "recon_skill_recommendations"],
    },
    "risk_assessment": {
        "label": "Risk Assessment",
        "definition": "Executa validação técnica controlada para confirmar ou refutar risco explorável.",
        "aliases": ["risk_assessment", "exploitation"],
        "required_evidence": ["executed_tool_runs", "tool_execution_results", "vulnerabilidades_encontradas"],
    },
    "evidence_adjudication": {
        "label": "Evidence Adjudication",
        "definition": "Separa hipótese de finding validado usando proof-pack, confiança e reprodutibilidade.",
        "aliases": ["evidence_gate"],
        "required_evidence": ["validation_backlog", "vulnerabilidades_encontradas"],
    },
    "governance": {
        "label": "Governance",
        "definition": "Consolida risco, FAIR/AGE, score, exceções e visão de postura.",
        "aliases": ["governance"],
        "required_evidence": ["easm_rating", "fair_decomposition"],
    },
    "executive_analyst": {
        "label": "Executive Analyst",
        "definition": "Gera narrativa executiva e prioridades a partir das evidências e score.",
        "aliases": ["executive_analyst"],
        "required_evidence": ["executive_summary"],
    },
}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def capability_ids() -> list[str]:
    return list(CAPABILITY_CONTRACT.keys())


def mark_capability(
    state: dict[str, Any],
    capability: str,
    *,
    source: str,
    status: str = "completed",
    evidence: dict[str, Any] | None = None,
) -> None:
    cap = str(capability or "").strip()
    if cap not in CAPABILITY_CONTRACT:
        return
    ledger = dict(state.get("capability_ledger") or {})
    current = dict(ledger.get(cap) or {})
    events = list(current.get("events") or [])
    event = {
        "source": str(source or ""),
        "status": str(status or "completed"),
        "evidence": dict(evidence or {}),
        "ts": _now_iso(),
    }
    events.append(event)
    completed = status == "completed" or bool(current.get("completed"))
    visited = True
    ledger[cap] = {
        "id": cap,
        "label": CAPABILITY_CONTRACT[cap]["label"],
        "definition": CAPABILITY_CONTRACT[cap]["definition"],
        "visited": visited,
        "completed": completed,
        "last_source": event["source"],
        "last_status": event["status"],
        "last_evidence": event["evidence"],
        "events": events[-20:],
        "updated_at": event["ts"],
    }
    state["capability_ledger"] = ledger

    if completed:
        completed_caps = list(state.get("completed_capabilities") or [])
        if cap not in completed_caps:
            completed_caps.append(cap)
            state["completed_capabilities"] = completed_caps


def infer_capability_ledger(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Best-effort ledger for old scans that lack explicit capability_ledger."""
    ledger = dict(state.get("capability_ledger") or {})
    node_history = {str(item or "") for item in list(state.get("node_history") or [])}
    completed = {str(item or "") for item in list(state.get("completed_capabilities") or [])}

    def _has_any(*keys: str) -> bool:
        for key in keys:
            value = state.get(key)
            if value not in (None, "", [], {}):
                return True
        return False

    inference_rules = {
        "strategic_planning": bool(node_history.intersection({"supervisor", "skill_planner"})) or _has_any("selected_skill", "pentest_strategy", "operation_plan"),
        "asset_discovery": "asset_discovery" in completed or _has_any("recon_graph", "lista_ativos", "discovered_ports"),
        "threat_intel": "threat_intel" in completed,
        "adversarial_hypothesis": bool(node_history.intersection({"skill_selector", "skill_planner", "tool_selector"})) or _has_any("pentest_hypotheses", "skill_invocation", "tool_selection_contract", "recon_skill_recommendations"),
        "risk_assessment": "risk_assessment" in completed or _has_any("tool_execution_results", "vulnerabilidades_encontradas"),
        "evidence_adjudication": bool(node_history.intersection({"evidence_gate"})) or _has_any("validation_backlog"),
        "governance": "governance" in completed or _has_any("easm_rating", "fair_decomposition"),
        "executive_analyst": "executive_analyst" in completed or _has_any("executive_summary"),
    }
    for cap, matched in inference_rules.items():
        if cap in ledger:
            continue
        if matched:
            mark_capability(
                state,
                cap,
                source="phase_monitor_inference",
                status="completed" if cap in completed or cap in {"strategic_planning", "adversarial_hypothesis"} else "visited",
                evidence={"inferred": True},
            )
            ledger = dict(state.get("capability_ledger") or {})
    return ledger
