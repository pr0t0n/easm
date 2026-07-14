from __future__ import annotations

from app.services.platform_capability_blueprint import capability_blueprint_summary, list_capability_blueprints


def test_capability_blueprint_keeps_best_of_positioning() -> None:
    summary = capability_blueprint_summary()

    assert "Pentest automatizado orientado por objetivos" in summary["north_star"]
    assert summary["non_goal"].startswith("Nao competir por volume")
    assert summary["implementation_order"][0] == "objective-driven-autonomy"


def test_capability_blueprint_covers_required_platform_families() -> None:
    capabilities = list_capability_blueprints()
    inspirations = {name for item in capabilities for name in item["inspired_by"]}

    assert "PentAGI" in inspirations
    assert "Pentest Swarm AI" in inspirations
    assert "HexStrike AI" in inspirations
    assert "promptfoo" in inspirations
    assert "vuln-bank" in inspirations


def test_capability_blueprint_defines_acceptance_gates_and_visibility() -> None:
    capabilities = list_capability_blueprints()

    assert all(item["acceptance_gates"] for item in capabilities)
    assert all(item["operator_visibility"] for item in capabilities)
    assert any("proof pack" in " ".join(item["acceptance_gates"]).lower() for item in capabilities)


def test_capability_blueprint_can_filter_by_category() -> None:
    capabilities = list_capability_blueprints(category="ai_security")

    assert [item["id"] for item in capabilities] == ["ai-rag-agent-security"]
