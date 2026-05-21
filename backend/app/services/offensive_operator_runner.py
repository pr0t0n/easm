"""Persistent P01-P22 offensive operator execution.

This is the integration layer that binds the dependency-light contracts in
`offensive_operator_core` to ScanJob.state_data. It is intentionally explicit:
phase progress is only persisted from Skill -> Tool Plan -> MCP -> Evidence ->
Validator output.
"""
from __future__ import annotations

import re
from typing import Any

import requests

from app.core.config import settings
from app.models.models import Finding, ScanJob, ScanLog
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


def _parse_targets_from_query(target_query: str) -> list[str]:
    raw = str(target_query or "")
    tokens = [token.strip() for token in re.split(r"[;,\n]", raw) if str(token or "").strip()]
    return tokens


def _scope_from_job(job: ScanJob, target: str, execution_mode: str = "controlled_pentest") -> Scope:
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
        max_noise_level=str(
            raw_scope.get("max_noise_level")
            or ("high" if execution_mode in {"controlled_pentest", "full_authorized_pentest"} else "medium")
        ),
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
    tool_timeout = max(900, int(execution.get("timeout") or 0))
    request = {
        "mcp_request_id": execution.get("mcp_request_id"),
        "phase_id": execution["phase_id"],
        "skill_id": execution["skill_id"],
        "tool_name": execution["tool_name"],
        "profile": execution["profile"],
        "target": execution["target"],
        "arguments": {"target": execution["target"]},
        "expected_evidence": ["stdout", "raw_tool_output", "parsed_result"],
    }
    response = requests.post(
        f"{settings.mcp_server_url.rstrip('/')}/mcp/execute",
        json=request,
        timeout=max(30, int(settings.mcp_request_timeout_seconds), tool_timeout + 30),
    )
    response.raise_for_status()
    return response.json()


def run_offensive_operator_scan(db, job: ScanJob, scan_mode: str = "unit") -> dict[str, Any]:
    """Run deterministic Skill-based P01-P22 campaign and persist every phase."""
    targets = _parse_targets_from_query(str(job.target_query or ""))
    if not targets:
        targets = [""]
    execution_mode = str((job.state_data or {}).get("execution_mode") or "controlled_pentest")
    offensive_state = dict((job.state_data or {}).get("offensive_state") or create_offensive_state(targets[0], campaign_id=f"scan-{job.id}"))
    phase_ledgers: list[dict[str, Any]] = list((job.state_data or {}).get("phase_ledger_v2") or [])
    events: list[dict[str, Any]] = list((job.state_data or {}).get("operation_events") or [])
    mcp_available = _mcp_available() if settings.mcp_execute_tools_via_mcp else False
    if not mcp_available:
        db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                       message="mcp_server unreachable — tools will be skipped; phases will be marked partial"))
        db.commit()
    runtime = OffensiveSkillRuntime(executor=MCPToolExecutor(call_tool=_call_mcp_execution, available=mcp_available))

    for target in targets:
        if not target:
            continue
        scope = _scope_from_job(job, target, execution_mode)
        offensive_state["target"] = target
        offensive_state["campaign_id"] = offensive_state.get("campaign_id") or f"scan-{job.id}"

        for phase_id in PHASE_ORDER:
            job.current_step = f"{phase_id} {PHASE_CONTRACTS[phase_id]['name']} ({target})"
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
            db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO", message=f"dispatch phase_id={phase_id} tool=kali target={target}"))
            db.commit()

            events.append(create_operation_event("phase_started", offensive_state["campaign_id"], str(job.id), phase_id, status="running"))
            result = runtime.run_phase(phase_id, target, scope, execution_mode, offensive_state)
            offensive_state = result["offensive_state"]
            phase_ledger = result["phase_ledger"]
            phase_ledger["target"] = target
            phase_ledgers.append(phase_ledger)

            # Emit per-tool command log lines so WorkerLogsPage CommandFeed picks them up
            mcp_results = result.get("mcp_results") or []
            for mcp_res in mcp_results:
                tool_name = mcp_res.get("tool_name", "unknown")
                status_v = mcp_res.get("status", "unknown")
                stdout_v = str(mcp_res.get("stdout_path") or mcp_res.get("stdout") or "")[:500]
                stderr_v = str(mcp_res.get("stderr_path") or mcp_res.get("stderr") or "")[:200]
                rc = mcp_res.get("exit_code") if mcp_res.get("exit_code") is not None else mcp_res.get("return_code")
                log_msg = (
                    f"kali runner tool={tool_name} phase={phase_id} status={status_v}"
                    f" return_code={rc}"
                    f" stdout={stdout_v!r}"
                    + (f" stderr={stderr_v!r}" if stderr_v else "")
                )
                db.add(ScanLog(scan_job_id=job.id, source="kali-runner", level="INFO", message=log_msg))

            phase_status = phase_ledger.get("status", "")
            validator_reason = result["validator_decision"].get("reason", "")
            db.add(ScanLog(
                scan_job_id=job.id,
                source="offensive-operator",
                level="INFO" if phase_status in {"completed", "partial"} else "WARNING",
                message=(
                    f"phase_result phase_id={phase_id} status={phase_status}"
                    f" tools_attempted={phase_ledger.get('tools_attempted', [])} tools_success={phase_ledger.get('tools_success', [])}"
                    f" reason={validator_reason}"
                ),
            ))

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
            # Only abort on blocked if no skill was resolved at all (hard blocker).
            # Tool-level blocks (e.g. missing optional OOB tool) are logged and skipped.
            if result["phase_ledger"].get("status") == "blocked":
                blocking_reason = result["phase_ledger"].get("blocking_reason", "")
                if blocking_reason in {"no_approved_skill_resolved"}:
                    break
                # Otherwise continue to the next phase — record as covered/partial.

    campaign = {
        "target": targets[0] if targets else "",
        "targets": targets,
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
    completed_count = len([l for l in phase_ledgers if l.get("status") == "completed"])
    partial_count = len([l for l in phase_ledgers if l.get("status") == "partial"])
    blocked_count = len([l for l in phase_ledgers if l.get("status") == "blocked"])
    job.mission_progress = int(round((len(phase_ledgers) / max(1, len(PHASE_ORDER))) * 100))
    # A scan is "completed" if at least one phase ran (completed or partial).
    # It is "failed" only when zero phases produced any result at all.
    job.status = "completed" if (completed_count + partial_count) > 0 else "failed"
    job.current_step = "P22 Campaign Report"
    db.commit()

    # ── Persist findings from phase evidence into the Finding table ────────
    _persist_offensive_findings(db, job, phase_ledgers, targets)

    db.commit()
    return campaign


def _persist_offensive_findings(db, job: ScanJob, phase_ledgers: list[dict[str, Any]], targets: list[str]) -> None:
    """Convert phase ledger evidence + hypotheses into Finding rows."""
    from app.models.models import Asset, Vulnerability

    seen: set[tuple[str, str]] = set()
    primary_target = targets[0] if targets else str(job.target_query or "")

    # Map severity from phase type
    PHASE_SEVERITY: dict[str, str] = {
        "P10": "high",   # injection
        "P11": "high",   # ssrf
        "P12": "medium", # xss
        "P13": "high",   # idor
        "P14": "high",   # auth bypass
        "P15": "medium", # file handling
        "P17": "critical",  # exploit validation
        "P18": "critical",  # credential exposure
    }

    for ledger in phase_ledgers:
        phase_id = ledger.get("phase_id", "")
        phase_name = ledger.get("phase_name", phase_id)
        status = ledger.get("status", "")
        target = ledger.get("target") or primary_target

        # Only persist findings from phases with successful tool runs
        tools_success = ledger.get("tools_success", [])
        tools_attempted = ledger.get("tools_attempted", [])
        if not tools_attempted:
            continue

        severity = PHASE_SEVERITY.get(phase_id, "info")
        confidence = 75 if status == "completed" else (50 if status == "partial" else 30)
        title = f"{phase_name} — {'Finding' if status == 'completed' else 'Partial Evidence'} [{phase_id}]"

        key = (phase_id, str(target))
        if key in seen:
            continue
        seen.add(key)

        details: dict[str, Any] = {
            "phase_id": phase_id,
            "phase_name": phase_name,
            "phase_status": status,
            "tools_attempted": tools_attempted,
            "tools_success": tools_success,
            "tools_failed": ledger.get("tools_failed", []),
            "evidence_ids": ledger.get("evidence_ids", []),
            "hypotheses_created": ledger.get("hypotheses_created", []),
            "attack_paths_updated": ledger.get("attack_paths_updated", []),
            "blocking_reason": ledger.get("blocking_reason"),
            "target": target,
            "scan_mode": "offensive_operator",
            "source_worker": "offensive_operator",
        }

        finding = Finding(
            scan_job_id=job.id,
            title=title,
            severity=severity,
            cve=None,
            cvss=None,
            domain=str(target)[:255],
            tool=", ".join(tools_success or tools_attempted)[:100] or None,
            recommendation=None,
            confidence_score=confidence,
            risk_score=max(1, confidence // 10),
            details=details,
        )
        db.add(finding)

        # Also persist asset + vulnerability for completed/partial phases
        if status in {"completed", "partial"} and target:
            try:
                asset = db.query(Asset).filter(
                    Asset.owner_id == job.owner_id,
                    Asset.domain_or_ip == str(target)[:255],
                ).first()
                if not asset:
                    from datetime import datetime as _dt
                    _now = _dt.utcnow()
                    asset = Asset(
                        owner_id=job.owner_id,
                        domain_or_ip=str(target)[:255],
                        asset_type="domain",
                        first_seen=_now,
                        last_seen=_now,
                        last_scan_id=job.id,
                    )
                    db.add(asset)
                    db.flush()
                existing_vuln = db.query(Vulnerability).filter(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.title == title,
                ).first()
                if not existing_vuln:
                    from datetime import datetime as _dt
                    _now = _dt.utcnow()
                    vuln = Vulnerability(
                        asset_id=asset.id,
                        title=title,
                        severity=severity,
                        tool_source=", ".join(tools_success or tools_attempted)[:100] or "offensive_operator",
                        first_detected=_now,
                        last_detected=_now,
                    )
                    db.add(vuln)
            except Exception:
                pass
