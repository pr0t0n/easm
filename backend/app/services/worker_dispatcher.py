"""Tool dispatcher — Kali runner is the ONLY execution path.

After the architecture refactor, every offensive tool runs inside the
Kali container. Workers no longer carry tools themselves. This module
exists only to (a) translate `tool_name → profile`, (b) post the job
to `kali_runner`, (c) poll for the result, (d) shape it back into the
dict structure the existing workflow code expects.

If the runner is unreachable, the call returns a structured `error`
result so the workflow can flag it as `attempted_failed` instead of
hanging. There is NO local fallback — that codepath has been removed.
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
    playbook: str | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Single-path tool execution: via the Kali runner OR backend-local
    services. The `code-analyzer` tool is intentionally backend-local so it
    can fetch HTML/JS and produce structured findings without paying the
    Kali round-trip cost. It carries `findings_extracted` so the workflow's
    parser merges them directly.
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

    if settings.mcp_execute_tools_via_mcp and mcp_client.health_check_sync():
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
                "extra_args": list(extra_args or []),
            },
            extra_args=list(extra_args or []),
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
            extra_args=list(extra_args or []),
        )
    if skill_id:
        result.setdefault("skill_id", skill_id)
        result.setdefault("skill_contract", skill_contract or {})
        result.setdefault("technique", (technique or {}).get("name") or technique or {})
        result.setdefault("evidence_required", evidence_required or [])
        result.setdefault("constraints", constraints or [])
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
            },
        )
    except Exception:
        logger.exception("Falha ao anexar perfil do agente para tool=%s", tool_name)
    return result
