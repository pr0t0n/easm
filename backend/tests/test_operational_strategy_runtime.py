from __future__ import annotations

from types import SimpleNamespace

from app.agents.orchestrator import AgentOrchestrator
from app.services.operational_strategy import build_mcp_adapter_contract, build_operational_strategy, scan_strategy_snapshot


def test_agent_orchestrator_builds_phase_contract() -> None:
    contract = AgentOrchestrator("P12").build_execution_contract()

    assert contract["enabled"] is True
    assert contract["phase_id"] == "P12"
    assert contract["mandatory_agents"]
    assert "sqlmap" in contract["all_tools"] or "dalfox" in contract["all_tools"]


def test_operational_strategy_builds_mcp_contract() -> None:
    strategy = build_operational_strategy(
        target="https://app.example.test",
        target_type="site",
        scan_mode="unit",
    )
    contract = build_mcp_adapter_contract(
        strategy=strategy,
        capability="risk_assessment",
        skill_id="vuln-injection",
        tools=["sqlmap", "dalfox"],
        evidence_required=["baseline_request", "response_diff"],
    )

    assert contract["required"] is True
    assert contract["guardrail_sanitization"] is True
    assert contract["agent"]["id"] == "exploit_validator"
    assert contract["tools"] == ["sqlmap", "dalfox"]


def test_scan_strategy_snapshot_exposes_runtime_state() -> None:
    strategy = build_operational_strategy(target="example.test", target_type="dominio", scan_mode="unit")
    scan = SimpleNamespace(
        id=123,
        target_query="example.test",
        status="running",
        state_data={
            "operational_strategy": strategy,
            "pending_capability_node": "risk_assessment",
            "selected_skill": {"skill_id": "api-security"},
            "skill_invocation": {"skill_id": "api-security", "called": True},
            "tool_selection_contract": {
                "capability": "risk_assessment",
                "mcp_adapter_contract": {"contract_id": "adapter:risk_assessment:api-security"},
            },
            "llm_reasoning": [{"phase": "P16", "skill_id": "api-security"}],
        },
    )

    snapshot = scan_strategy_snapshot(scan)

    assert snapshot["current"]["agent"]["id"] == "exploit_validator"
    assert snapshot["current"]["selected_skill"]["skill_id"] == "api-security"
    assert snapshot["current"]["mcp_adapter_contract"]["contract_id"] == "adapter:risk_assessment:api-security"
