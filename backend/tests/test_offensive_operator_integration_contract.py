from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def test_scan_worker_uses_offensive_operator_before_langgraph_finding_flow():
    source = (ROOT / "backend/app/workers/tasks.py").read_text(encoding="utf-8")
    offensive_index = source.index("run_offensive_operator_scan")
    graph_index = source.index("app = build_graph")
    assert offensive_index < graph_index
    assert "settings.offensive_operator_enabled" in source


def test_legacy_tool_adapter_does_not_fallback_when_mcp_is_mandatory():
    source = (ROOT / "backend/app/services/tool_adapters.py").read_text(encoding="utf-8")
    mandatory_block = source[source.index("if settings.mcp_execute_tools_via_mcp:") : source.index("return execute_via_kali")]
    assert "mcp_unavailable" in mandatory_block
    assert "execute_via_kali" not in mandatory_block


def test_worker_dispatcher_does_not_fallback_when_mcp_is_mandatory():
    source = (ROOT / "backend/app/services/worker_dispatcher.py").read_text(encoding="utf-8")
    mandatory_block = source[source.index("if settings.mcp_execute_tools_via_mcp:") : source.index("else:", source.index("if settings.mcp_execute_tools_via_mcp:"))]
    assert "mcp_unavailable" in mandatory_block
    assert "execute_via_kali" not in mandatory_block


def test_phase_contracts_reference_real_skill_ids_and_tool_names():
    source = (ROOT / "backend/app/services/offensive_operator_core.py").read_text(encoding="utf-8")
    for phase_id in [f"P{i:02d}" for i in range(1, 23)]:
        assert f'"{phase_id}"' in source
    for skill_id in [
        "skill.recon.subdomain_enumeration",
        "skill.discovery.parameter_discovery",
        "skill.vuln.ssrf",
        "skill.chain.exposed_git_to_credential_leak",
        "skill.reporting.evidence_quality",
    ]:
        assert skill_id in source


def test_each_required_phase_has_approved_skill_for_controlled_pentest():
    from app.services.offensive_operator_core import PHASE_ORDER, SkillRegistry

    registry = SkillRegistry(ROOT / "skills")
    missing = [
        phase_id
        for phase_id in PHASE_ORDER
        if not registry.approved_for_phase(phase_id, execution_mode="controlled_pentest")
    ]
    assert missing == []


def test_campaign_report_is_built_from_phase_ledger_not_only_findings():
    source = (ROOT / "backend/app/services/offensive_operator_core.py").read_text(encoding="utf-8")
    report_builder = source[source.index("class ReportBuilder") : source.index("class OffensiveSkillRuntime")]
    assert "phase_ledger" in report_builder
    assert "offensive_campaign_timeline" in report_builder
    assert "findings_validated" in report_builder
