#!/usr/bin/env python3
"""
Validar contrato de agentes operacionais e fluxo supervisor-centric.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent.parent / "backend"
sys.path.insert(0, str(backend_path))

from app.workers.worker_groups import (
    get_worker_agent_profiles,
    get_canonical_group_tools,
    find_agent_by_tool,
)


def validate_agent_profiles() -> dict:
    """Validar perfis de agentes e metadados."""
    checks = {}
    
    # Check unit mode
    unit_agents = get_worker_agent_profiles("unit")
    checks["unit_agents_count"] = len(unit_agents) == 3
    checks["unit_agents_ids"] = {
        "recon": unit_agents.get("reconhecimento", {}).get("agent_id") == "agent.recon",
        "vuln": unit_agents.get("analise_vulnerabilidade", {}).get("agent_id") == "agent.vuln",
        "osint": unit_agents.get("osint", {}).get("agent_id") == "agent.osint",
    }
    
    # Check scheduled mode
    scheduled_agents = get_worker_agent_profiles("scheduled")
    checks["scheduled_agents_count"] = len(scheduled_agents) == 3
    checks["scheduled_agents_same_as_unit"] = (
        unit_agents["reconhecimento"]["tools"] == scheduled_agents["reconhecimento"]["tools"]
        and unit_agents["analise_vulnerabilidade"]["tools"] == scheduled_agents["analise_vulnerabilidade"]["tools"]
        and unit_agents["osint"]["tools"] == scheduled_agents["osint"]["tools"]
    )
    
    # Check contract presence
    checks["recon_has_contract"] = "contract" in unit_agents.get("reconhecimento", {})
    checks["vuln_has_contract"] = "contract" in unit_agents.get("analise_vulnerabilidade", {})
    checks["osint_has_contract"] = "contract" in unit_agents.get("osint", {})
    
    # Check confidence thresholds
    recon_contract = unit_agents.get("reconhecimento", {}).get("contract", {})
    checks["recon_thresholds"] = (
        recon_contract.get("confidence_thresholds", {}).get("high") == 80
        and recon_contract.get("confidence_thresholds", {}).get("medium") == 50
    )
    
    return checks


def validate_tool_agent_mapping() -> dict:
    """Validar que cada ferramenta mapeia para o agente correto."""
    checks = {}
    canonical = get_canonical_group_tools()
    
    for group, tools in canonical.items():
        if group == "core_orchestration":
            continue
        if group == "native_execution":
            continue
        if group == "memory_and_reflection":
            continue
        if group == "meta_tooling":
            continue
        if group == "supported_scan_tools":
            continue
        
        for tool in tools:
            agent = find_agent_by_tool(tool, mode="unit")
            agent_id = agent.get("agent_id", "")
            
            if group in ["recon", "reconhecimento"]:
                checks[f"tool_{tool}_maps_to_recon"] = agent_id == "agent.recon"
            elif group in ["vuln", "analise_vulnerabilidade"]:
                checks[f"tool_{tool}_maps_to_vuln"] = agent_id == "agent.vuln"
            elif group in ["osint"]:
                checks[f"tool_{tool}_maps_to_osint"] = agent_id == "agent.osint"
    
    return checks


def validate_mission_items() -> dict:
    """Validar que mission.py contém as ferramentas dos agentes."""
    mission_path = Path(__file__).parent.parent / "backend" / "app" / "graph" / "mission.py"
    mission_text = mission_path.read_text()
    
    checks = {}
    
    # Check that mission lists tools by agent
    checks["mission_has_recon_tools"] = "amass" in mission_text and "nmap" in mission_text
    checks["mission_has_vuln_tools"] = "burp-cli" in mission_text or "burp_cli" in mission_text
    checks["mission_has_osint_tools"] = "shodan-cli" in mission_text or "shodan_cli" in mission_text
    checks["mission_mentions_agents"] = (
        "Recon Agent" in mission_text
        and "OSINT Agent" in mission_text
        and "Vuln Agent" in mission_text
    )
    
    return checks


def validate_dispatcher_integration() -> dict:
    """Validar que dispatcher propaga metadados de agente."""
    dispatcher_path = Path(__file__).parent.parent / "backend" / "app" / "services" / "worker_dispatcher.py"
    dispatcher_text = dispatcher_path.read_text()
    
    checks = {}
    checks["dispatcher_imports_agent_finder"] = "find_agent_by_tool" in dispatcher_text
    checks["dispatcher_sets_source_agent_id"] = "source_agent_id" in dispatcher_text
    checks["dispatcher_sets_source_agent_name"] = "source_agent_name" in dispatcher_text
    checks["dispatcher_sets_dispatch_agent"] = "dispatch_agent" in dispatcher_text
    
    return checks


def validate_tasks_integration() -> dict:
    """Validar que tasks.py inclui _worker_result com metadados."""
    tasks_path = Path(__file__).parent.parent / "backend" / "app" / "workers" / "tasks.py"
    tasks_text = tasks_path.read_text()
    
    checks = {}
    checks["tasks_has_worker_result"] = "def _worker_result(" in tasks_text
    checks["tasks_worker_result_imports_agent_profile"] = "get_worker_agent_profile" in tasks_text
    checks["tasks_worker_result_sets_agent_profile"] = "agent_profile" in tasks_text and '"agent_id"' in tasks_text
    checks["tasks_has_source_agent_logging"] = "source_agent" in tasks_text
    
    return checks


def main() -> int:
    all_results = {
        "agent_profiles": validate_agent_profiles(),
        "tool_agent_mapping": validate_tool_agent_mapping(),
        "mission_items": validate_mission_items(),
        "dispatcher_integration": validate_dispatcher_integration(),
        "tasks_integration": validate_tasks_integration(),
    }
    
    all_passed = sum(
        sum(1 for v in checks.values() if v is True)
        for checks in all_results.values()
    )
    all_total = sum(
        len(checks)
        for checks in all_results.values()
    )
    all_failed = all_total - all_passed
    
    output = {
        "total": all_total,
        "passed": all_passed,
        "failed": all_failed,
        "sections": {
            section: {
                "passed": sum(1 for v in checks.values() if v is True),
                "failed": sum(1 for v in checks.values() if v is False),
                "checks": {k: v for k, v in checks.items()},
            }
            for section, checks in all_results.items()
        },
    }
    
    print(json.dumps(output, ensure_ascii=True, indent=2))
    return 0 if all_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
