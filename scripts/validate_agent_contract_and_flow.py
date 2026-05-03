#!/usr/bin/env python3
"""Validate worker/agent routing after the Kali runner refactor."""
from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.kali_executor import TOOL_TO_PROFILE  # noqa: E402
from app.workers.worker_groups import (  # noqa: E402
    all_queues,
    find_agent_by_tool,
    find_group_by_tool,
    get_canonical_group_tools,
    get_worker_agent_profiles,
    get_worker_groups,
)


def normalize(value: str | None) -> str:
    return str(value or "").strip().lower()


def main() -> int:
    groups = get_worker_groups("unit")
    profiles = get_worker_agent_profiles("unit")
    canonical_tools = {
        normalize(tool)
        for tools in get_canonical_group_tools().values()
        for tool in tools
    }
    mapped_tools = set(TOOL_TO_PROFILE)

    checks: dict[str, bool] = {
        "has_kill_chain_workers": all(
            name in groups
            for name in [
                "scope_validation",
                "reconnaissance",
                "weaponization",
                "delivery",
                "exploitation",
                "installation",
                "command_control",
                "actions_on_objectives",
                "reporting",
            ]
        ),
        "queues_cover_unit_workers": len(all_queues("unit")) >= 9,
        "agent_profiles_exist": all(
            name in profiles
            for name in ["reconhecimento", "analise_vulnerabilidade", "osint", "exploit", "api", "code"]
        ),
        "every_worker_tool_has_kali_profile": canonical_tools == mapped_tools,
        "theharvester_routes_to_weaponization": find_group_by_tool("theHarvester") == "weaponization",
        "nuclei_routes_to_weaponization_or_exploitation": find_group_by_tool("nuclei") in {"weaponization", "exploitation"},
        "nikto_routes_to_exploitation": find_group_by_tool("nikto") == "exploitation",
        "agents_return_profiles": bool(find_agent_by_tool("nikto").get("agent_id")),
    }

    failures = [name for name, ok in checks.items() if not ok]
    payload = {
        "ok": not failures,
        "total": len(checks),
        "passed": len(checks) - len(failures),
        "failed": len(failures),
        "failures": failures,
        "worker_tool_count": len(canonical_tools),
        "kali_profile_mapping_count": len(mapped_tools),
        "groups": sorted(groups),
        "queues": all_queues("unit"),
    }
    print(json.dumps(payload, ensure_ascii=True, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
