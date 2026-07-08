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
    targets: list[str] | None = None,
) -> dict[str, Any]:
    """Single-path tool execution.

    When MCP execution is enabled, every offensive tool must go through MCP.
    If MCP cannot proxy to Kali, return a structured failure instead of
    falling back to direct Kali execution and creating a false success trail.

    `code-analyzer` and SAST tools with local source requirements remain
    backend-local because they do not execute external offensive tooling.
    """
    norm_tool = str(tool_name or "").strip().lower()
    # Try to surface the current scan_id so evidence and auth context are filed
    # under the same scan, including backend-local tools.
    if scan_id is None:
        try:
            from celery import current_task as _ct  # type: ignore
            if _ct is not None and getattr(_ct, "request", None):
                scan_id = (_ct.request.kwargs or {}).get("scan_id")
                if not scan_id and _ct.request.args:
                    scan_id = _ct.request.args[0]
        except Exception:
            scan_id = None
    auth_context = _resolve_auth_context(scan_id, skill_contract)
    if norm_tool in {"code-analyzer", "semgrep"}:
        if norm_tool == "code-analyzer":
            from app.services.code_analyzer import run_as_tool
            source_agent_name = "Backend Code Analyzer"
            worker_group = "asset_discovery"
        else:
            from app.services.semgrep_local import run_as_tool
            source_agent_name = "Backend Semgrep SAST"
            worker_group = "actions_on_objectives"

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
        if auth_context:
            result.setdefault("auth_context", auth_context)
        result.setdefault("source_agent_id", "backend")
        result.setdefault("source_agent_name", source_agent_name)
        result.setdefault("worker_group", worker_group)
        _persist_result_artifact(scan_id, result, skill_contract, auth_context)
        return result

    if norm_tool == "bl-test":
        # Teste ATIVO de business logic — backend-local (descoberta+auth, sem kali).
        from app.services.business_logic_test import run_as_tool as _bl_run
        result = _bl_run(target)
        if skill_id:
            result.setdefault("skill_id", skill_id)
            result.setdefault("skill_contract", skill_contract or {})
            result.setdefault("evidence_required", evidence_required or [])
        if auth_context:
            result.setdefault("auth_context", auth_context)
        result.setdefault("source_agent_id", "backend")
        result.setdefault("source_agent_name", "Backend Business Logic Tester")
        result.setdefault("worker_group", "risk_assessment")
        _persist_result_artifact(scan_id, result, skill_contract, auth_context)
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
                targets=targets or None,
                scan_id=scan_id,
                skill_context={
                    "skill_id": skill_id,
                    "skill_contract": skill_contract or {},
                    "technique": technique or {},
                    "evidence_required": evidence_required or [],
                    "constraints": constraints or [],
                    "playbook": playbook or "",
                    "auth_context": auth_context,
                },
            )
    else:
        result = execute_via_kali(
            tool_name=tool_name,
            target=target,
            targets=targets or None,
            scan_id=scan_id,
            scan_mode=scan_mode,
            skill_context={
                "skill_id": skill_id,
                "skill_contract": skill_contract or {},
                "technique": technique or {},
                "evidence_required": evidence_required or [],
                "constraints": constraints or [],
                "playbook": playbook or "",
                "auth_context": auth_context,
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
    _persist_result_artifact(scan_id, result, skill_contract, auth_context)
    return result


def _resolve_auth_context(scan_id: int | None, skill_contract: dict[str, Any] | None) -> dict[str, Any]:
    if not scan_id:
        return {}
    identity_key = ""
    if isinstance(skill_contract, dict):
        identity_key = str(skill_contract.get("identity_key") or "")
    try:
        from app.db.session import SessionLocal
        from app.models.models import ScanJob
        from app.services.auth_session_manager import AuthSessionManager

        db = SessionLocal()
        try:
            scan = db.query(ScanJob).filter(ScanJob.id == int(scan_id)).first()
            if not scan:
                return {}
            material = AuthSessionManager(db, scan).get_material(identity_key or None)
            return material.to_dict() if material else {}
        finally:
            db.close()
    except Exception:
        return {}


def _persist_result_artifact(
    scan_id: int | None,
    result: dict[str, Any],
    skill_contract: dict[str, Any] | None,
    auth_context: dict[str, Any] | None,
) -> None:
    if not scan_id:
        return
    try:
        from app.db.session import SessionLocal
        from app.services.evidence_contract_service import create_artifact_from_tool_result

        db = SessionLocal()
        try:
            create_artifact_from_tool_result(
                db,
                scan_job_id=int(scan_id),
                result=result,
                phase_id=str((skill_contract or {}).get("phase_id") or result.get("phase_id") or ""),
                skill_id=str((skill_contract or {}).get("skill_id") or result.get("skill_id") or ""),
                identity_key=str((auth_context or {}).get("identity_key") or ""),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
    except Exception:
        logger.debug("evidence artifact persistence skipped", exc_info=True)
