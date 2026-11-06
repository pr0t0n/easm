"""Smoke/regression tests for supervisor_node.

Regression context: the e1c3d65 split (mai/2026) extracted supervisor_node from
workflow.py and lost (a) the max_iterations kill switch, (b) the
remaining_iterations computation in _update_execution_guardrails, and (c) the
`ctrl`/`remaining` locals used by the budget guard — a guaranteed NameError on
every supervisor execution, caught only because the offensive operator path
never reaches the graph. These tests pin the restored behavior.
"""
from __future__ import annotations

from langgraph.graph import END

from app.graph.nodes.supervisor import _update_execution_guardrails, supervisor_node


def _minimal_state(**over):
    state = {
        "trace_id": "t-1",
        "scan_id": 0,  # falsy: _sync_step_to_db / _emit_activity_demand skip DB
        "owner_id": 1,
        "target": "http://juice-shop:3000",
        "scan_mode": "unit",
        "target_type": "url",
        "input_targets": [],
        "lista_ativos": [],
        "discovered_ports": [],
        "vulnerabilidades_encontradas": [],
        "mission_items": [],
        "mission_metrics": {},
        "node_history": [],
        "completed_capabilities": [],
        "kill_chain_stage": "RECONNAISSANCE",
        "loop_iteration": 0,
        "objective_met": False,
        "termination_reason": "",
        "max_iterations": 12,
        "confidence_state": {"global_confidence": 60},
        "validation_backlog": [],
        "pentest_strategy": {"queue": []},
        "delegated_tasks": [],
        "delegation_log": [],
        "autonomy_notes": [],
        "autonomy_todos": [],
        "autonomy_actions": [],
        "autonomy_observations": [],
        "autonomy_errors": [],
        "execution_control": {},
        "executed_tool_runs": [],
        "phase_ledger": {},
        "detected_tech_stack": [],
        "logs_terminais": [],
        "offensive_priority_queue": [],
        "active_hypotheses": [],
        "validated_chains": [],
        "campaign": {},
        "activity_metrics": [],
    }
    state.update(over)
    return state


def test_supervisor_executes_without_crash_on_fresh_state():
    """A primeira iteração deve rotear para a primeira capability sem NameError."""
    state = supervisor_node(_minimal_state())
    assert state["loop_iteration"] == 1
    assert state["routing_next_node"] == "skill_selector"
    assert state["pending_capability_node"] == "asset_discovery"
    assert state["termination_reason"] == ""


def test_supervisor_kill_switch_stops_past_max_iterations():
    state = supervisor_node(_minimal_state(loop_iteration=12, max_iterations=12))
    assert state["routing_next_node"] == END
    assert state["termination_reason"] == "max_iterations_reached"
    assert state["objective_met"] is True


def test_supervisor_budget_guard_forces_finalize_when_remaining_low():
    """Com remaining<=2 o supervisor deve pivotar para governance/executive."""
    state = supervisor_node(_minimal_state(loop_iteration=10, max_iterations=12))
    # remaining = 12 - 11 = 1 → forced_finalize_guardrail
    assert state["routing_next_node"] == "governance"
    assert "forced_finalize_guardrail" in state["termination_reason"]


def test_guardrails_compute_remaining_iterations():
    state = _minimal_state(loop_iteration=3, max_iterations=12)
    _update_execution_guardrails(state)
    ctrl = state["execution_control"]
    assert ctrl["remaining_iterations"] == 9
    assert ctrl["approaching_limit"] is False


def test_guardrails_approaching_limit_near_budget_end():
    state = _minimal_state(loop_iteration=11, max_iterations=12)
    _update_execution_guardrails(state)
    ctrl = state["execution_control"]
    assert ctrl["approaching_limit"] is True
    assert ctrl["remaining_iterations"] == 1


def test_supervisor_survives_checkpointed_legacy_state_without_remaining():
    """State carregado de checkpoint pode carregar remaining_iterations=None
    (era o placeholder da versão quebrada). Não pode lançar TypeError."""
    state = _minimal_state(execution_control={"remaining_iterations": None})
    # também sem max_iterations → default 12
    del state["max_iterations"]
    state = supervisor_node(state)
    assert state["routing_next_node"]  # roteou para algum lugar, sem exceção


def test_supervisor_tolerates_max_iterations_none_from_initial_state():
    """initial_state() materializa max_iterations=None — a chave existe, então
    state.get('max_iterations', 12) retorna None e int(None) seria TypeError."""
    state = _minimal_state(max_iterations=None)
    state = supervisor_node(state)
    assert state["loop_iteration"] == 1
    assert state["execution_control"]["remaining_iterations"] == 11


def test_same_capability_with_advanced_phase_is_progress_not_loop():
    """Regressão scan #38: asset_discovery cobria P01→P02, mas o guard de loop
    comparava só capability e abortava com loop_on_same_phase no meio do recon.
    Mesma capability + fase técnica avançada = progresso."""
    state = _minimal_state(
        current_phase="asset_discovery",
        current_pentest_phase_id="P02",
        last_routed_phase_id="P01",
    )
    state = supervisor_node(state)
    assert state["termination_reason"] != "loop_on_same_phase"
    assert state["routing_next_node"] not in (END, "END")


def test_loop_guard_tolerates_working_through_same_phase():
    """Regressão scan #43: fase profunda com dispatch incremental (1 tool por
    iteração) executa várias ferramentas na MESMA fase — é progresso. O guard
    só aborta quando NENHUMA ferramenta nova executou (no-op real)."""
    state = _minimal_state(
        current_phase="asset_discovery",
        current_pentest_phase_id="P02",
        last_routed_phase_id="P02",
        executed_tool_runs=["p02|t|httpx", "p02|t|naabu"],
        loop_guard_runs_at_route=0,
        pentest_tactics_completed=[{"tactic_id": "phase:P02:remaining-3"}],
        pending_pentest_tactic={"tactic_id": "phase:P02:remaining-3"},
    )
    state = supervisor_node(state)
    assert state["termination_reason"] != "loop_on_same_phase"
    assert state["routing_next_node"] not in (END, "END")
