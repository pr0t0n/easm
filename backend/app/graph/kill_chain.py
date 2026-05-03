"""Cyber Kill Chain phase taxonomy + aliases for the existing graph nodes.

We keep the original capability-node names (`asset_discovery`, `risk_assessment`
etc.) for back-compat with persisted state and the LangGraph wiring, while
also exposing a Kill Chain narrative (`SCOPE_VALIDATION → RECONNAISSANCE →
WEAPONIZATION_SIMULATION → DELIVERY_MAPPING → EXPLOITATION_VALIDATION →
INSTALLATION_RISK_ANALYSIS → COMMAND_AND_CONTROL_RISK → ACTIONS_ON_OBJECTIVES
→ REPORTING`) that drives the executive frontend.

This file is the single mapping point so the rest of the codebase stays
unchanged.
"""
from __future__ import annotations

from typing import Any


# Canonical phase ids (UPPER_SNAKE_CASE, stable for DB/UI)
KILL_CHAIN_PHASES: list[str] = [
    "SCOPE_VALIDATION",
    "RECONNAISSANCE",
    "WEAPONIZATION_SIMULATION",
    "DELIVERY_MAPPING",
    "EXPLOITATION_VALIDATION",
    "INSTALLATION_RISK_ANALYSIS",
    "COMMAND_AND_CONTROL_RISK",
    "ACTIONS_ON_OBJECTIVES",
    "REPORTING",
]


# Map graph node → Kill Chain phase
NODE_TO_PHASE: dict[str, str] = {
    "strategic_planning":     "SCOPE_VALIDATION",
    "asset_discovery":        "RECONNAISSANCE",
    "threat_intel":           "WEAPONIZATION_SIMULATION",
    "adversarial_hypothesis": "DELIVERY_MAPPING",
    "risk_assessment":        "EXPLOITATION_VALIDATION",
    "evidence_adjudication":  "INSTALLATION_RISK_ANALYSIS",
    "governance":             "COMMAND_AND_CONTROL_RISK",
    "executive_analyst":      "REPORTING",
    # ACTIONS_ON_OBJECTIVES is computed implicitly from
    # finding severity + exposure (no dedicated node yet — see KILL_CHAIN.md).
}

# Reverse lookup
PHASE_TO_NODE: dict[str, str] = {v: k for k, v in NODE_TO_PHASE.items()}


def phase_for_node(node_name: str) -> str:
    return NODE_TO_PHASE.get(str(node_name or "").strip().lower(), "REPORTING")


def node_for_phase(phase_id: str) -> str:
    return PHASE_TO_NODE.get(str(phase_id or "").strip().upper(), "executive_analyst")


# Human-readable + audience-tailored copy per phase
PHASE_META: dict[str, dict[str, Any]] = {
    "SCOPE_VALIDATION": {
        "label": "Validação de Escopo",
        "summary": "Validar autorização, alvos, allowlist e contrato de execução.",
        "executive_pitch": "Antes de qualquer probe, garantimos que cada alvo testado está dentro do escopo aprovado e auditado.",
        "node": "strategic_planning",
    },
    "RECONNAISSANCE": {
        "label": "Reconhecimento",
        "summary": "Mapeamento da superfície externa: subdomínios, portas, tecnologias, TLS, parâmetros.",
        "executive_pitch": "Inventário do que está exposto antes de mensurar risco.",
        "node": "asset_discovery",
    },
    "WEAPONIZATION_SIMULATION": {
        "label": "Simulação de Armamentização",
        "summary": "Correlação CVE/EPSS, leaks de credencial, fingerprint OSINT — sem disparo de exploit.",
        "executive_pitch": "Estimamos o que um adversário conseguiria preparar a partir do que está visível.",
        "node": "threat_intel",
    },
    "DELIVERY_MAPPING": {
        "label": "Mapeamento de Entrega",
        "summary": "Identificação de vetores de entrega: paths web, formulários, parâmetros, takeover, OOB.",
        "executive_pitch": "Vias por onde o ataque chegaria à aplicação ou ao funcionário.",
        "node": "adversarial_hypothesis",
    },
    "EXPLOITATION_VALIDATION": {
        "label": "Validação de Exploração",
        "summary": "Probes ativos read-only que provam injeções, XSS, SSRF e CMS-known-vulns.",
        "executive_pitch": "Confirmação técnica de que cada finding crítico/high é reproduzível.",
        "node": "risk_assessment",
    },
    "INSTALLATION_RISK_ANALYSIS": {
        "label": "Risco de Instalação",
        "summary": "Avalia se um atacante poderia obter persistência (auth fraca, config exposta).",
        "executive_pitch": "O blast radius caso o vetor seja explorado.",
        "node": "evidence_adjudication",
    },
    "COMMAND_AND_CONTROL_RISK": {
        "label": "Risco de C2",
        "summary": "Postura governance + canais que poderiam servir de comando e controle.",
        "executive_pitch": "Capacidade do adversário manter contato após a invasão inicial.",
        "node": "governance",
    },
    "ACTIONS_ON_OBJECTIVES": {
        "label": "Ações sobre Objetivos",
        "summary": "Estimativa de exfiltração/data damage com base em SAST + secrets + dependency CVEs.",
        "executive_pitch": "Dano financeiro esperado se a cadeia for completada.",
        "node": "evidence_adjudication",
    },
    "REPORTING": {
        "label": "Relatório Executivo",
        "summary": "Narrativa, FAIR breakdown, rating ScriptKidd.o e recomendações priorizadas.",
        "executive_pitch": "Material assinável para o board e o PRA do cliente.",
        "node": "executive_analyst",
    },
}


def render_kill_chain_summary(state: dict) -> dict:
    """Given a workflow state, returns one item per Kill Chain phase with
    completion status. Drives the frontend Kill Chain widget."""
    completed_caps: list[str] = list(state.get("completed_capabilities") or [])
    visited_nodes: list[str] = list(state.get("node_history") or [])
    out: list[dict[str, Any]] = []
    for phase in KILL_CHAIN_PHASES:
        meta = PHASE_META.get(phase, {})
        node = meta.get("node")
        out.append({
            "phase": phase,
            "label": meta.get("label", phase),
            "summary": meta.get("summary", ""),
            "executive_pitch": meta.get("executive_pitch", ""),
            "node": node,
            "completed": bool(node and node in completed_caps),
            "visited": bool(node and node in visited_nodes),
        })
    return {"phases": out, "total": len(KILL_CHAIN_PHASES)}
