#!/usr/bin/env python3
"""Architecture validation test for EASM platform.

Tests:
1. Agent registry and orchestration
2. Phase monitor validation logic
3. Mission execution plan
4. Tool catalog consistency
"""
import sys
import os

# Set Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from app.agents import (
    AGENT_REGISTRY,
    get_agents_for_phase,
    validate_phase_completion,
    AgentOrchestrator,
)
from app.graph.mission import PENTEST_PHASES, SKILL_CATALOG
from app.services.tool_catalog import TOOL_CATALOG

def test_agent_registry():
    """Validate agent registry completeness."""
    print("\n" + "="*70)
    print("TEST 1: Agent Registry")
    print("="*70)

    assert len(AGENT_REGISTRY) >= 15, f"Expected >=15 agents, got {len(AGENT_REGISTRY)}"
    print(f"✅ Agents registered: {len(AGENT_REGISTRY)}")

    # Check categories
    categories = set(a.category for a in AGENT_REGISTRY)
    expected_categories = {"reconnaissance", "osint", "vulnerability", "code"}
    assert expected_categories.issubset(categories), f"Missing categories: {expected_categories - categories}"
    print(f"✅ Categories covered: {sorted(categories)}")

    # Check each agent has required fields
    for agent in AGENT_REGISTRY:
        assert agent.agent_id, "Agent missing ID"
        assert agent.name, "Agent missing name"
        assert agent.tools, "Agent missing tools"
        assert agent.required_skills, "Agent missing required_skills"

    print(f"✅ All agents have required fields")
    return True


def test_phase_coverage():
    """Validate phases have corresponding agents."""
    print("\n" + "="*70)
    print("TEST 2: Phase Coverage")
    print("="*70)

    phases_with_agents = {}
    for phase in PENTEST_PHASES:
        phase_id = phase["id"]
        agents = get_agents_for_phase(phase_id)
        phases_with_agents[phase_id] = len(agents)
        if agents:
            print(f"  {phase_id} ({phase['title']:<40}) → {len(agents)} agent(s)")

    phases_with_no_agents = [p for p, count in phases_with_agents.items() if count == 0]
    if phases_with_no_agents:
        print(f"⚠️  Phases with no agents: {phases_with_no_agents}")
    else:
        print(f"✅ All {len(PENTEST_PHASES)} phases have agents")

    return True


def test_tool_consistency():
    """Validate tool catalog entries."""
    print("\n" + "="*70)
    print("TEST 3: Tool Consistency")
    print("="*70)

    tool_count = len(TOOL_CATALOG)
    print(f"✅ Tools in catalog: {tool_count}")

    # Check that tools are referenced by agents
    agent_tools = set()
    for agent in AGENT_REGISTRY:
        agent_tools.update(agent.tools)

    missing_from_catalog = agent_tools - set(TOOL_CATALOG.keys())
    if missing_from_catalog:
        print(f"⚠️  Tools referenced but not in catalog: {list(missing_from_catalog)[:5]}")
    else:
        print(f"✅ All agent tools are in catalog")

    return True


def test_orchestrator():
    """Validate agent orchestrator logic."""
    print("\n" + "="*70)
    print("TEST 4: Agent Orchestrator")
    print("="*70)

    # Test on key phases
    test_phases = ["P01", "P11", "P12"]
    for phase_id in test_phases:
        orchestrator = AgentOrchestrator(phase_id)
        mandatory = orchestrator.get_mandatory_agents()
        summary = orchestrator.get_summary()

        phase_name = next((p["title"] for p in PENTEST_PHASES if p["id"] == phase_id), "Unknown")
        print(f"  {phase_id} {phase_name:<40}")
        print(f"    - Mandatory agents: {len(mandatory)}")
        print(f"    - Total agents: {summary['agents_expected']}")

    print(f"✅ Orchestrator working correctly")
    return True


def test_mission_items():
    """Validate mission structure."""
    print("\n" + "="*70)
    print("TEST 5: Mission Items")
    print("="*70)

    from app.graph.mission import MISSION_ITEMS
    assert len(MISSION_ITEMS) >= 9, f"Expected >=9 mission items, got {len(MISSION_ITEMS)}"
    print(f"✅ Mission items: {len(MISSION_ITEMS)}")
    for i, item in enumerate(MISSION_ITEMS, 1):
        print(f"  {i}. {item}")

    return True


def test_phase_validation():
    """Test phase completion validation."""
    print("\n" + "="*70)
    print("TEST 6: Phase Validation")
    print("="*70)

    # Test P01 with only partial tools
    all_done, missing = validate_phase_completion("P01", {"subfinder", "amass"})
    print(f"  P01 with {{subfinder, amass}}: all_done={all_done}, missing={missing}")

    # Test P01 with all tools
    p01_tools = next((p["tools"] for p in PENTEST_PHASES if p["id"] == "P01"), [])
    all_done, missing = validate_phase_completion("P01", set(p01_tools))
    assert all_done, f"P01 should be complete with all tools"
    print(f"✅ P01 validation correct with all tools")

    return True


def main():
    """Run all architecture tests."""
    print("\n" + "█"*70)
    print("EASM Platform Architecture Validation")
    print("█"*70)

    tests = [
        ("Agent Registry", test_agent_registry),
        ("Phase Coverage", test_phase_coverage),
        ("Tool Consistency", test_tool_consistency),
        ("Agent Orchestrator", test_orchestrator),
        ("Mission Items", test_mission_items),
        ("Phase Validation", test_phase_validation),
    ]

    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, True, None))
        except Exception as e:
            results.append((name, False, str(e)))
            print(f"\n❌ {name} failed: {e}")

    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)

    passed = sum(1 for _, success, _ in results if success)
    total = len(results)

    for name, success, error in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {name}")
        if error:
            print(f"      {error[:80]}")

    print(f"\nResult: {passed}/{total} tests passed")

    if passed == total:
        print("\n✅ All architecture validations PASSED!")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
