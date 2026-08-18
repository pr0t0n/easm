"""SEC-005 regression test.

skill_planner_node's execution_context fed the LLM a hardcoded
`"authorized_scope": True` regardless of the real Scope Contract, so the
system prompt's own "if no authorized scope -> block execution" rule was
structurally unreachable. It must now reflect the real authorization_gate.
"""
from __future__ import annotations

from unittest.mock import patch


def _base_state(target: str, authorized_scope: list[str]) -> dict:
    return {
        "target": target,
        "target_type": "site",
        "current_phase": "risk_assessment",
        "pending_capability_node": "risk_assessment",
        "skill_selector_gate": {"group": "risk_assessment", "phase": "risk_assessment"},
        "skill_contract": {"skill_id": "vuln-injection"},
        "skill_invocation": {"skill_id": "vuln-injection", "techniques": []},
        "authorization_gate": {"authorized_scope": authorized_scope},
        "logs_terminais": [],
        "autonomy_actions": [],
        "activity_metrics": [],
        "node_history": [],
        "mission_index": 0,
        "last_completed_node": "",
    }


def test_execution_context_reflects_real_in_scope_target(monkeypatch):
    from app.graph.nodes.skill_pipeline import skill_planner_node

    monkeypatch.setattr("app.core.config.settings.llm_reasoning_enabled", True)
    captured = {}

    def _fake_decide(*, playbook, execution_context, tool_catalog, skill_memory, timeout):
        captured["execution_context"] = execution_context
        return {"selected_technique": {}, "signals_to_validate": [], "constraints": []}

    with patch("app.agents.supervisor_runtime.decide_next_technique", _fake_decide):
        skill_planner_node(_base_state("https://example.com/", ["example.com"]))

    assert captured["execution_context"]["authorized_scope"] is True


def test_execution_context_reflects_real_out_of_scope_target(monkeypatch):
    """The core of SEC-005: a target NOT covered by the real scope contract
    must not be reported to the LLM as authorized just because the field
    used to be hardcoded True."""
    from app.graph.nodes.skill_pipeline import skill_planner_node

    monkeypatch.setattr("app.core.config.settings.llm_reasoning_enabled", True)
    captured = {}

    def _fake_decide(*, playbook, execution_context, tool_catalog, skill_memory, timeout):
        captured["execution_context"] = execution_context
        return {"selected_technique": {}, "signals_to_validate": [], "constraints": []}

    with patch("app.agents.supervisor_runtime.decide_next_technique", _fake_decide):
        skill_planner_node(_base_state("https://evil-out-of-scope.com/", ["example.com"]))

    assert captured["execution_context"]["authorized_scope"] is False


def test_execution_context_false_when_no_scope_authorized_at_all(monkeypatch):
    from app.graph.nodes.skill_pipeline import skill_planner_node

    monkeypatch.setattr("app.core.config.settings.llm_reasoning_enabled", True)
    captured = {}

    def _fake_decide(*, playbook, execution_context, tool_catalog, skill_memory, timeout):
        captured["execution_context"] = execution_context
        return {"selected_technique": {}, "signals_to_validate": [], "constraints": []}

    with patch("app.agents.supervisor_runtime.decide_next_technique", _fake_decide):
        skill_planner_node(_base_state("https://example.com/", []))

    assert captured["execution_context"]["authorized_scope"] is False
