"""Fase 1 (LANGGRAPH_BRAIN_PLAN): chaves de estado do walker/kill-chain devem
sobreviver ao merge entre nós do grafo.

Regressão scan #39: pentest_phase_index/current_pentest_phase_id/phase_ledger
NÃO eram declarados no AgentState (TypedDict), então o LangGraph as descartava
no merge — o supervisor decidia sobre state que nunca chegava ao pipeline
(fases travadas em P02, ledger vazio, kill-chain parado).
"""
from __future__ import annotations

from app.graph.state import AgentState
from app.graph.workflow import build_graph, initial_state

_PHASE_WALKER_KEYS = {
    "pentest_phase_index": int,
    "current_pentest_phase_id": str,
    "phase_ledger": dict,
    "last_routed_phase_id": str,
    "kill_chain_stage": str,
    "current_activity_demand": dict,
    "noise_profile": str,
    "campaign": dict,
    "active_hypotheses": list,
    "validated_chains": list,
    "offensive_priority_queue": list,
    # Segundo passe (Fase 1) — top-level keys usadas mas ausentes do schema
    "max_iterations": int,
    "scan_profile": dict,
    "detected_tech_stack": list,
    "authorization_gate": dict,
    "agent_report": dict,
    "attack_paths": list,
    "pentest_hypotheses": list,
    "recon_graph": dict,
    "recon_skill_recommendations": list,
    "completed_activity_types": list,
}


def test_phase_walker_keys_are_declared_in_agent_state():
    for key, expected_type in _PHASE_WALKER_KEYS.items():
        assert key in AgentState.__annotations__, f"{key} não declarado no AgentState"
        annotation = AgentState.__annotations__[key]
        # __future__ annotations → compara pelo nome do tipo
        assert expected_type.__name__ in str(annotation), f"{key}: tipo inesperado {annotation}"


def test_phase_ledger_survives_graph_checkpoint_merge():
    """Kill switch no primeiro supervisor (loop_iteration > max_iterations) faz
    o grafo rodar rag_enrichment→supervisor→END. As chaves declaradas devem
    estar no state final; antes do fix, phase_ledger sumia do resultado."""
    graph = build_graph()
    state = initial_state(scan_id=0, owner_id=1, target="http://juice_shop:3000")
    state["loop_iteration"] = 99
    state["max_iterations"] = 12
    result = graph.invoke(state, config={"configurable": {"thread_id": "smoke-phase-keys"}})
    for key in _PHASE_WALKER_KEYS:
        assert key in result, f"{key} não sobreviveu ao merge do grafo"
    ledger = result.get("phase_ledger") or {}
    assert len(ledger) == 22, f"phase_ledger deveria ter 22 fases, tem {len(ledger)}"
    assert result.get("termination_reason") == "max_iterations_reached"


def test_initial_state_budget_by_profile_depth():
    """Orçamento de iterações por profundidade do perfil (Fase 1, item 3):
    asm/low=10, full/medium=24, aggressive/high=48 (standard=agressivo do sponsor)."""
    assert initial_state(0, 1, "http://x", scan_level="asm")["max_iterations"] == 10
    assert initial_state(0, 1, "http://x", scan_level="full")["max_iterations"] == 24
    assert initial_state(0, 1, "http://x", scan_level="aggressive")["max_iterations"] == 48


def test_walker_marks_skipped_phase_in_ledger():
    """Fase sem ferramentas instaladas deve virar 'skipped' no ledger com motivo
    (definition-of-done visível), não sumir do contrato."""
    from app.graph.nodes.supervisor import _phase_walker_tactic

    state = initial_state(0, 1, "http://juice_shop:3000")
    # Simula uma fase sem nenhuma ferramenta instalada esvaziando o catálogo
    # de tools da fase corrente via monkeypatch de is_tool_installed.
    import app.graph.nodes.supervisor as sup
    from app.graph.mission import PENTEST_PHASES

    original = sup._phase_walker_tactic.__globals__["is_tool_installed"] if "is_tool_installed" in sup._phase_walker_tactic.__globals__ else None
    # is_tool_installed é importado dentro da função — patch no módulo de origem
    from app.services import tool_catalog
    real = tool_catalog.is_tool_installed
    tool_catalog.is_tool_installed = lambda t: False
    try:
        tactic = _phase_walker_tactic(state)
    finally:
        tool_catalog.is_tool_installed = real
    assert tactic is None  # todas as fases sem tools → walker esgota
    ledger = state.get("phase_ledger") or {}
    skipped = [pid for pid, e in ledger.items() if str(e.get("status")) == "skipped"]
    assert len(skipped) == len(PENTEST_PHASES), f"{len(skipped)}/{len(PENTEST_PHASES)} skipped"


def test_walker_respects_profile_phase_contract(monkeypatch):
    """Perfil com phase_ids explícito (asm/api) restringe o walk: fases fora do
    contrato viram 'skipped' com motivo — cobertura previsível por perfil."""
    from app.graph.nodes.supervisor import _phase_walker_tactic
    from app.services import tool_catalog

    state = initial_state(0, 1, "http://juice_shop:3000", scan_level="asm")
    assert state["scan_profile"]["phase_ids"], "asm deve declarar phase_ids"
    monkeypatch.setattr(tool_catalog, "is_tool_installed", lambda t: False)
    tactic = _phase_walker_tactic(state)
    assert tactic is None
    ledger = state.get("phase_ledger") or {}
    in_contract = set(state["scan_profile"]["phase_ids"])
    for pid, entry in ledger.items():
        if pid in in_contract:
            continue
        assert entry.get("status") == "skipped", f"{pid} fora do contrato deveria ser skipped"
        assert "perfil" in str(entry.get("skip_reason") or ""), f"{pid} sem motivo de perfil"
