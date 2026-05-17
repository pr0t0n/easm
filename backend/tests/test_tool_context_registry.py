from app.services.tool_context_registry import (
    build_tool_context_registry,
    dashboard_bas_variables,
    rank_tools_for_context,
)


def test_tool_context_registry_ranks_by_context_and_mcp_metadata() -> None:
    mcp_tools = [
        {
            "name": "nuclei_cves",
            "description": "CVE and misconfiguration template scan",
            "metadata": {
                "tool": "nuclei",
                "category": "vuln",
                "phase": "WEAPONIZATION_SIMULATION",
                "timeout": 900,
            },
        },
        {
            "name": "katana_crawl",
            "description": "Web crawler and endpoint discovery",
            "metadata": {
                "tool": "katana",
                "category": "recon",
                "phase": "RECONNAISSANCE",
                "timeout": 180,
            },
        },
    ]

    ordered, registry = rank_tools_for_context(
        ["katana", "nuclei"],
        context={
            "target": "https://example.test",
            "capability": "risk_assessment",
            "skill_id": "vuln-nuclei-cve",
            "hypothesis": "validate CVE and misconfiguration exposure",
            "preferred_tools": ["nuclei"],
            "dashboard_tool_metrics": {
                "nuclei": {"attempts": 4, "successes": 4, "failures": 0},
                "katana": {"attempts": 2, "successes": 1, "failures": 1},
            },
        },
        mcp_tools=mcp_tools,
        include_mcp=False,
    )

    assert ordered[0] == "nuclei"
    assert registry["by_tool"]["nuclei"]["profile"] == "nuclei_cves"
    assert "preferred_by_skill_or_learning" in registry["by_tool"]["nuclei"]["context_reasons"]
    assert registry["variables"]["TOOL_CONTEXT_MCP_PROFILES"]["nuclei"] == "nuclei_cves"
    assert registry["variables"]["TOOL_CONTEXT_DASHBOARD_METRICS"]["nuclei"]["success_rate"] == 100.0


def test_dashboard_bas_variables_are_flat_and_prompt_ready() -> None:
    variables = dashboard_bas_variables(
        {
            "summary": {
                "bas_resilience_index": 65.4,
                "attack_success_index": 56.3,
                "control_efficacy_index": 75.2,
                "tool_efficiency_index": 57.9,
            },
            "tools": [{"tool": "nuclei", "attempts": 3, "success_rate": 66.7, "findings": 2, "failures": 1}],
            "detection": {"telemetry_sources": [{"source": "asset_discovery"}]},
            "learning": {"accepted": 7, "pending": 2, "rag_trace_hits": 11},
            "workers": {"total": 5, "active": 2, "stale": 1},
        }
    )

    assert variables["BAS_RESILIENCE_INDEX"] == 65.4
    assert variables["BAS_TOP_TOOLS"] == ["nuclei"]
    assert variables["BAS_TOOL_METRICS"]["nuclei"]["success_rate"] == 66.7
    assert variables["BAS_TOP_TELEMETRY_SOURCES"] == ["asset_discovery"]
