from __future__ import annotations

from app.services.benchmark_registry import benchmark_readiness_summary, list_benchmark_targets


def test_benchmark_registry_prioritizes_safe_local_labs() -> None:
    targets = list_benchmark_targets(include_ai_suites=False)

    assert [item["id"] for item in targets[:4]] == ["vuln-bank", "aigoat", "dvaia", "dvmcp"]
    assert all(item["safe_execution"] in {"local_container_only", "simulated_network_only"} for item in targets)


def test_benchmark_registry_covers_ai_rag_and_mcp_security() -> None:
    targets = list_benchmark_targets()
    coverage = {label for item in targets for label in item["coverage"]}

    assert "rag_testing" in coverage
    assert "prompt_injection" in coverage
    assert "mcp_scan" in coverage
    assert "mcp_tool_abuse" in coverage


def test_benchmark_registry_summary_defines_acceptance_gates() -> None:
    summary = benchmark_readiness_summary()

    assert summary["first_milestone"].startswith("wire vuln-bank")
    assert summary["local_only_target_count"] >= 4
    assert "benchmark score must track false positives, evidence quality, and phase coverage" in summary["acceptance_gates"]


def test_benchmark_registry_can_filter_by_category() -> None:
    targets = list_benchmark_targets(category="llm_security_lab")

    assert [item["id"] for item in targets] == ["aigoat"]
