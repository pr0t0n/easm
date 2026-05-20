"""Tool dispatcher — MCP is the mandatory offensive execution path.

After the architecture refactor, every offensive tool must pass through MCP,
which then proxies the request to the Kali runner. Workers no longer carry
tools themselves. This module exists only to shape legacy worker requests into
the execution contract the current workflow expects.

If MCP cannot proxy to Kali, the call returns a structured `mcp_unavailable`
result so the phase validator can block or mark partial instead of creating a
false success trail.
"""
from __future__ import annotations

import logging
from typing import Any

from app.core.config import settings
from app.services.mcp_client import mcp_client
from app.services.kali_executor import execute_via_kali, TOOL_TO_PROFILE
from app.workers.worker_groups import find_agent_by_tool


logger = logging.getLogger(__name__)


def execute_tool_with_workers(
    tool_name: str,
    target: str,
    scan_mode: str = "unit",
    scan_id: int | None = None,
    skill_id: str | None = None,
    skill_contract: dict[str, Any] | None = None,
    technique: dict[str, Any] | None = None,
    evidence_required: list[str] | None = None,
    constraints: list[str] | None = None,
    worker_rules: dict[str, Any] | None = None,
    sub_agent_plan: list[dict[str, Any]] | None = None,
    playbook: str | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Single-path tool execution.

    When MCP execution is enabled, every offensive tool must go through MCP.
    If MCP cannot proxy to Kali, return a structured failure instead of
    falling back to direct Kali execution and creating a false success trail.

    The `code-analyzer` tool remains intentionally backend-local because it
    does not execute external offensive tooling.
    """
    norm_tool = str(tool_name or "").strip().lower()
    if norm_tool == "code-analyzer":
        from app.services.code_analyzer import run_as_tool

        result = run_as_tool(target)
        if skill_id:
            result.setdefault("skill_id", skill_id)
            result.setdefault("skill_contract", skill_contract or {})
            result.setdefault("technique", (technique or {}).get("name") or technique or {})
            result.setdefault("evidence_required", evidence_required or [])
            result.setdefault("constraints", constraints or [])
            result.setdefault("worker_rules", worker_rules or {})
            result.setdefault("sub_agent_plan", sub_agent_plan or [])
            result.setdefault("playbook", playbook or "")
        result.setdefault("source_agent_id", "backend")
        result.setdefault("source_agent_name", "Backend Code Analyzer")
        result.setdefault("worker_group", "asset_discovery")
        return result

    if norm_tool not in TOOL_TO_PROFILE:
        return {
            "tool": tool_name,
            "target": target,
            "scan_mode": scan_mode,
            "status": "error",
            "command": "",
            "stdout": "",
            "stderr": "",
            "dispatch_error": f"no_profile_mapping for tool '{tool_name}'",
            "source_agent_id": "kali_runner",
            "source_agent_name": "Kali Runner",
            "open_ports": [],
        }

    # Try to surface the current scan_id so evidence is filed under
    # /workspace/{scan_id}/{tool}/{job_id}/ on the runner.
    if scan_id is None:
        try:
            from celery import current_task as _ct  # type: ignore
            if _ct is not None and getattr(_ct, "request", None):
                scan_id = (_ct.request.kwargs or {}).get("scan_id")
                if not scan_id and _ct.request.args:
                    scan_id = _ct.request.args[0]
        except Exception:
            scan_id = None

    if settings.mcp_execute_tools_via_mcp:
        if not mcp_client.kali_tools_available_sync():
            result = {
                "tool": tool_name,
                "target": target,
                "scan_mode": scan_mode,
                "status": "error",
                "error": "mcp_unavailable",
                "dispatch_error": "mcp_unavailable",
                "execution_path": "mcp_required",
                "mcp_used": False,
                "stdout": "",
                "stderr": "",
                "command": "",
                "open_ports": [],
            }
        else:
            result = mcp_client.execute_kali_tool_sync(
                tool_name=tool_name,
                target=target,
                scan_id=scan_id,
                skill_context={
                    "skill_id": skill_id,
                    "skill_contract": skill_contract or {},
                    "technique": technique or {},
                    "evidence_required": evidence_required or [],
                    "constraints": constraints or [],
                    "playbook": playbook or "",
                },
            )
    else:
        result = execute_via_kali(
            tool_name=tool_name,
            target=target,
            scan_id=scan_id,
            scan_mode=scan_mode,
            skill_context={
                "skill_id": skill_id,
                "skill_contract": skill_contract or {},
                "technique": technique or {},
                "evidence_required": evidence_required or [],
                "constraints": constraints or [],
                "playbook": playbook or "",
            },
        )
    if skill_id:
        result.setdefault("skill_id", skill_id)
        result.setdefault("skill_contract", skill_contract or {})
        result.setdefault("technique", (technique or {}).get("name") or technique or {})
        result.setdefault("evidence_required", evidence_required or [])
        result.setdefault("constraints", constraints or [])
        result.setdefault("worker_rules", worker_rules or {})
        result.setdefault("sub_agent_plan", sub_agent_plan or [])
        result.setdefault("playbook", playbook or "")
    try:
        agent = find_agent_by_tool(tool_name, mode="scheduled" if str(scan_mode).lower() == "scheduled" else "unit")
        result.setdefault("source_agent_id", agent.get("agent_id"))
        result.setdefault("source_agent_name", agent.get("agent_name"))
        result.setdefault("worker_group", agent.get("worker_group"))
        result.setdefault("worker_mission", agent.get("mission"))
        result.setdefault("worker_techniques", list(agent.get("techniques") or []))
        result.setdefault(
            "agent_profile",
            {
                "agent_id": agent.get("agent_id"),
                "agent_name": agent.get("agent_name"),
                "worker_group": agent.get("worker_group"),
                "mission": agent.get("mission"),
                "techniques": list(agent.get("techniques") or []),
                "phases": list(agent.get("phases") or []),
                "tools": list(agent.get("tools") or []),
                "evidence_focus": list(agent.get("evidence_focus") or []),
                "decision_rules": list(agent.get("decision_rules") or []),
                "worker_rules": dict(agent.get("worker_rules") or {}),
                "sub_agent_rules": list(agent.get("sub_agent_rules") or []),
            },
        )
    except Exception:
        logger.exception("Falha ao anexar perfil do agente para tool=%s", tool_name)
    return result
