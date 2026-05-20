"""Persistent P01-P22 offensive operator execution.

This is the integration layer that binds the dependency-light contracts in
`offensive_operator_core` to ScanJob.state_data. It is intentionally explicit:
phase progress is only persisted from Skill -> Tool Plan -> MCP -> Evidence ->
Validator output.
"""
from __future__ import annotations

from typing import Any

import requests

from app.core.config import settings
from app.models.models import ScanJob, ScanLog
from app.services.offensive_operator_core import (
    MCPToolExecutor,
    PHASE_CONTRACTS,
    PHASE_ORDER,
    ReportBuilder,
    Scope,
    OffensiveSkillRuntime,
    create_operation_event,
    create_offensive_state,
)


def _scope_from_job(job: ScanJob, target: str) -> Scope:
    state = dict(job.state_data or {})
    raw_scope = state.get("scope") if isinstance(state.get("scope"), dict) else {}
    allowed_domains = list(raw_scope.get("allowed_domains") or [])
    allowed_subdomains = list(raw_scope.get("allowed_subdomains") or [])
    allowed_ips = list(raw_scope.get("allowed_ips") or [])
    if not (allowed_domains or allowed_subdomains or allowed_ips):
        from urllib.parse import urlparse

        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        allowed_domains = [host]
    return Scope(
        scope_id=str(raw_scope.get("scope_id") or f"scan-{job.id}"),
        allowed_domains=allowed_domains,
        allowed_subdomains=allowed_subdomains,
        allowed_ips=allowed_ips,
        allowed_ports=list(raw_scope.get("allowed_ports") or []),
        allowed_protocols=list(raw_scope.get("allowed_protocols") or ["http", "https"]),
        disallowed_targets=list(raw_scope.get("disallowed_targets") or []),
        allowed_techniques=list(raw_scope.get("allowed_techniques") or []),
        disallowed_techniques=list(raw_scope.get("disallowed_techniques") or []),
        max_noise_level=str(raw_scope.get("max_noise_level") or "medium"),
        allow_authenticated_testing=bool(raw_scope.get("allow_authenticated_testing", True)),
        allow_post_exploitation=bool(raw_scope.get("allow_post_exploitation", False)),
        allow_credential_testing=bool(raw_scope.get("allow_credential_testing", False)),
        allow_data_access_validation=bool(raw_scope.get("allow_data_access_validation", False)),
        execution_windows=list(raw_scope.get("execution_windows") or []),
    )


def _mcp_available() -> bool:
    try:
        response = requests.get(f"{settings.mcp_server_url.rstrip('/')}/health", timeout=3)
        payload = response.json() if response.ok else {}
        return response.ok and bool(payload.get("kali_connected", True))
    except Exception:
        return False


def _call_mcp_execution(execution: dict[str, Any]) -> dict[str, Any]:
    request = {
        "mcp_request_id": execution.get("mcp_request_id"),
        "phase_id": execution["phase_id"],
        "skill_id": execution["skill_id"],
        "tool_name": execution["tool_name"],
        "profile": execution["profile"],
        "target": execution["target"],
        "arguments": {"target": execution["target"], "timeout": 120},
        "expected_evidence": ["stdout", "raw_tool_output", "parsed_result"],
    }
    response = requests.post(
        f"{settings.mcp_server_url.rstrip('/')}/mcp/execute",
        json=request,
        timeout=max(5, int(settings.mcp_request_timeout_seconds)),
    )
    response.raise_for_status()
    return response.json()


def run_offensive_operator_scan(db, job: ScanJob, scan_mode: str = "unit") -> dict[str, Any]:
    """Run deterministic Skill-based P01-P22 campaign and persist every phase."""
    target = str(job.target_query or "").replace(",", ";").split(";")[0].strip()
    execution_mode = str((job.state_data or {}).get("execution_mode") or "controlled_pentest")
    scope = _scope_from_job(job, target)
    offensive_state = dict((job.state_data or {}).get("offensive_state") or create_offensive_state(target, campaign_id=f"scan-{job.id}"))
    phase_ledgers: list[dict[str, Any]] = list((job.state_data or {}).get("phase_ledger_v2") or [])
    completed = {ledger.get("phase_id") for ledger in phase_ledgers if ledger.get("status") in {"completed", "partial", "skipped_with_justification"}}
    events: list[dict[str, Any]] = list((job.state_data or {}).get("operation_events") or [])
    mcp_available = _mcp_available() if settings.mcp_execute_tools_via_mcp else False
    runtime = OffensiveSkillRuntime(executor=MCPToolExecutor(call_tool=_call_mcp_execution, available=mcp_available))

    for phase_id in PHASE_ORDER:
        if phase_id in completed:
            continue
        job.current_step = f"{phase_id} {PHASE_CONTRACTS[phase_id]['name']}"
        state = dict(job.state_data or {})
        state.update(
            {
                "execution_mode": execution_mode,
                "current_pentest_phase_id": phase_id,
                "offensive_state": offensive_state,
                "phase_ledger_v2": phase_ledgers,
                "operation_events": events,
            }
        )
        job.state_data = state
        db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO", message=f"phase_started {phase_id}"))
        db.commit()

        events.append(create_operation_event("phase_started", offensive_state["campaign_id"], str(job.id), phase_id, status="running"))
        result = runtime.run_phase(phase_id, target, scope, execution_mode, offensive_state)
        offensive_state = result["offensive_state"]
        phase_ledgers.append(result["phase_ledger"])
        events.append(
            create_operation_event(
                "phase_completed" if result["validator_decision"].get("can_advance") else "phase_blocked",
                offensive_state["campaign_id"],
                str(job.id),
                phase_id,
                skill_id=(result.get("skill_plan") or {}).get("selected_skills", [""])[0] if result.get("skill_plan") else "",
                status=result["phase_ledger"].get("status", ""),
                details={"reason": result["validator_decision"].get("reason")},
            )
        )
        state = dict(job.state_data or {})
        state.update(
            {
                "offensive_operator_enabled": True,
                "execution_mode": execution_mode,
                "current_pentest_phase_id": phase_id,
                "offensive_state": offensive_state,
                "phase_ledger_v2": phase_ledgers,
                "operation_events": events,
                "last_skill_plan": result.get("skill_plan"),
                "last_tool_plan": result.get("tool_plan"),
                "last_mcp_results": result.get("mcp_results"),
                "last_evidence": result.get("evidence"),
            }
        )
        job.state_data = state
        db.commit()
        if result["phase_ledger"].get("status") == "blocked":
            break

    campaign = {
        "target": target,
        "execution_mode": execution_mode,
        "phase_ledger": phase_ledgers,
        "offensive_state": offensive_state,
        "operation_events": events,
    }
    report = ReportBuilder().build(campaign)
    state = dict(job.state_data or {})
    state["campaign_report"] = report
    state["report_v2"] = {**dict(state.get("report_v2") or {}), "campaign_report": report}
    job.state_data = state
    job.mission_progress = int(round((len(phase_ledgers) / max(1, len(PHASE_ORDER))) * 100))
    job.status = "completed" if len(phase_ledgers) == len(PHASE_ORDER) and all(l.get("status") != "blocked" for l in phase_ledgers) else "failed"
    job.current_step = "P22 Campaign Report" if job.status == "completed" else "Blocked by phase validator"
    db.commit()
    return campaign
