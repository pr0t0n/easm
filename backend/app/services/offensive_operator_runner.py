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
from app.services.capability_runtime import mark_capability
from app.services.scan_intelligence import (
    expand_targets_after_p01,
    detect_tech_stack,
    tools_to_inject_for_tech,
    wordlist_for_tech,
    validate_critical_findings,
    evasion_profile_for,
    enrich_finding_with_mappings,
    auth_headers_from_state,
    has_auth,
    phases_for_scan_level,
    extract_learning_signals,
)


# Phase → capability mapping: which capabilities each phase contributes evidence for
PHASE_TO_CAPABILITIES: dict[str, list[str]] = {
    "P01": ["strategic_planning", "asset_discovery"],
    "P02": ["asset_discovery", "threat_intel"],
    "P03": ["asset_discovery", "adversarial_hypothesis"],
    "P04": ["adversarial_hypothesis"],
    "P05": ["asset_discovery"],
    "P06": ["asset_discovery", "threat_intel"],
    "P07": ["threat_intel"],
    "P08": ["adversarial_hypothesis"],
    "P09": ["risk_assessment", "threat_intel"],
    "P10": ["risk_assessment"],
    "P11": ["risk_assessment"],
    "P12": ["risk_assessment"],
    "P13": ["risk_assessment"],
    "P14": ["risk_assessment"],
    "P15": ["risk_assessment", "evidence_adjudication"],
    "P16": ["adversarial_hypothesis"],
    "P17": ["risk_assessment", "evidence_adjudication"],
    "P18": ["threat_intel", "evidence_adjudication"],
    "P19": ["risk_assessment"],
    "P20": ["evidence_adjudication"],
    "P21": ["evidence_adjudication", "governance"],
    "P22": ["governance", "executive_analyst"],
}


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


# Module-level holder for current scan's auth headers (set per scan by runner).
# Single Celery worker process executes one scan task at a time per fork, so this
# is safe. Reset to {} at the start of each run_offensive_operator_scan().
_CURRENT_AUTH_HEADERS: dict[str, str] = {}


def _call_mcp_execution(execution: dict[str, Any]) -> dict[str, Any]:
    tool_timeout = max(900, int(execution.get("timeout") or 0))
    arguments: dict[str, Any] = {"target": execution["target"]}
    if _CURRENT_AUTH_HEADERS:
        # Pass auth headers to kali runner so it can inject -H flags into the tool command
        arguments["auth_headers"] = dict(_CURRENT_AUTH_HEADERS)
    request = {
        "mcp_request_id": execution.get("mcp_request_id"),
        "phase_id": execution["phase_id"],
        "skill_id": execution["skill_id"],
        "tool_name": execution["tool_name"],
        "profile": execution["profile"],
        "target": execution["target"],
        "arguments": arguments,
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

    # Read EASM scan-level (asm/full) from state_data; default = full.
    initial_state = dict(job.state_data or {})
    scan_level = str(initial_state.get("scan_level") or "full").lower()
    allowed_phases = phases_for_scan_level(scan_level)
    if allowed_phases is not None:
        db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                       message=f"scan_level={scan_level} — limiting to phases: {sorted(allowed_phases)}"))
        db.commit()

    # Set auth headers for this scan so _call_mcp_execution propagates them to kali.
    global _CURRENT_AUTH_HEADERS
    _CURRENT_AUTH_HEADERS = auth_headers_from_state(initial_state)
    if _CURRENT_AUTH_HEADERS:
        masked = {k: (v[:10] + "***" if v else "") for k, v in _CURRENT_AUTH_HEADERS.items()}
        db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                       message=f"auth_engaged headers={masked} — tools will inject these into requests"))
        db.commit()

    for target in targets:
        if not target:
            continue
        scope = _scope_from_job(job, target, execution_mode)
        offensive_state["target"] = target
        offensive_state["campaign_id"] = offensive_state.get("campaign_id") or f"scan-{job.id}"

        for phase_id in PHASE_ORDER:
            # Skip phases outside the configured scan_level (asm = recon only).
            if allowed_phases is not None and phase_id not in allowed_phases:
                continue
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
            # Embed mcp_results in the ledger so _persist_offensive_findings can extract evidence
            phase_ledger["mcp_results"] = result.get("mcp_results") or []
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

            # ─ Populate runtime evidence so capability ledger inference works ─
            # strategic_planning needs: supervisor_route, selected_skill, operation_plan, pentest_strategy
            selected_skill_ids = (result.get("skill_plan") or {}).get("selected_skills") or []
            if selected_skill_ids:
                state["selected_skill"] = selected_skill_ids[0]
            state["supervisor_route"] = state.get("supervisor_route") or list(state.get("phase_ledger_v2") and [phase_id] or [phase_id])
            state["operation_plan"] = state.get("operation_plan") or {
                "campaign_id": offensive_state.get("campaign_id"),
                "target": target,
                "phases": PHASE_ORDER,
                "execution_mode": execution_mode,
            }
            state["pentest_strategy"] = state.get("pentest_strategy") or {
                "campaign_id": offensive_state.get("campaign_id"),
                "phases_planned": PHASE_ORDER,
                "current_phase": phase_id,
            }
            # asset_discovery needs: recon_graph, executed_tool_runs, discovered_ports, lista_ativos
            mcp_list = result.get("mcp_results") or []
            existing_runs = list(state.get("executed_tool_runs") or [])
            existing_runs.extend([{
                "tool": m.get("tool_name"),
                "phase": phase_id,
                "status": m.get("status"),
                "started_at": m.get("started_at"),
                "finished_at": m.get("finished_at"),
                "exit_code": m.get("exit_code"),
            } for m in mcp_list if isinstance(m, dict)])
            state["executed_tool_runs"] = existing_runs[-500:]
            if phase_id == "P01":
                lista = list(state.get("lista_ativos") or [])
                for m in mcp_list:
                    stdout = str((m or {}).get("stdout") or "")
                    for line in stdout.splitlines():
                        host = line.strip().split()[0] if line.strip() else ""
                        if host and "." in host and host not in lista:
                            lista.append(host)
                state["lista_ativos"] = lista[:1000]
                state["recon_graph"] = {"root": target, "assets": lista[:200]}
            if phase_id == "P02":
                ports: list[int] = list(state.get("discovered_ports") or [])
                for m in mcp_list:
                    stdout = str((m or {}).get("stdout") or "")
                    for line in stdout.splitlines():
                        if ":" in line:
                            part = line.split(":")[-1].strip()
                            if part.isdigit():
                                p = int(part)
                                if p not in ports and 1 <= p <= 65535:
                                    ports.append(p)
                state["discovered_ports"] = ports[:500]

            # ─── Scan Intelligence hooks ───────────────────────────────────
            # 1. Multi-target propagation: after P01, expand to discovered subdomains
            if phase_id == "P01":
                expanded = expand_targets_after_p01(state, target, mcp_list)
                if len(expanded) > 1:
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                   message=f"target_expansion phase=P01 root={target} expanded_to={len(expanded)} hosts (first 5: {expanded[1:6]})"))
            # 2. Tech-stack detection: every phase contributes signals
            tech_stack = detect_tech_stack(state, mcp_list)
            if tech_stack.get("detected") and phase_id in {"P06", "P07"}:
                db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                               message=f"tech_detected phase={phase_id} stack={tech_stack['detected']} cms={tech_stack.get('cms')} waf={tech_stack.get('waf')}"))
            # 3. Evasion profile: adapt rate-limits when WAF detected
            evasion = evasion_profile_for(tech_stack)
            state["evasion_profile"] = evasion
            if tech_stack.get("waf") and not state.get("_evasion_logged"):
                db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                               message=f"evasion_engaged {evasion['rationale']} rate={evasion['rate_limit']}/s threads={evasion['threads']}"))
                state["_evasion_logged"] = True
            # 4. Evidence validation: re-probe critical findings via MCP curl
            try:
                def _call_curl(url: str) -> dict:
                    import requests as _r
                    headers = {"User-Agent": evasion.get("user_agents", ["Mozilla/5.0"])[0], **auth_headers_from_state(state)}
                    r = _r.get(url, headers=headers, timeout=15, allow_redirects=True, verify=False)
                    return {"status_code": r.status_code, "body": r.text[:500]}
                validations = validate_critical_findings(state, mcp_list, call_curl=_call_curl)
                if validations:
                    confirmed = sum(1 for v in validations if v.get("validation_status") == "confirmed")
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                   message=f"finding_validation phase={phase_id} validated={len(validations)} confirmed={confirmed}"))
            except Exception as exc:  # noqa: BLE001
                pass
            # adversarial_hypothesis needs: pentest_hypotheses, skill_invocation, tool_selection_contract
            hypotheses = list(state.get("pentest_hypotheses") or [])
            for h in offensive_state.get("open_hypotheses", [])[-5:]:
                if h not in hypotheses:
                    hypotheses.append(h)
            state["pentest_hypotheses"] = hypotheses[-200:]
            invocations = list(state.get("skill_invocation") or [])
            if selected_skill_ids:
                invocations.append({"phase_id": phase_id, "skill_id": selected_skill_ids[0]})
            state["skill_invocation"] = invocations[-200:]
            state["tool_selection_contract"] = {
                "phase_id": phase_id,
                "tools": [t.get("tool_name") for t in (result.get("tool_plan") or {}).get("tools", [])],
            }
            # risk_assessment needs: tool_execution_results, vulnerabilidades_encontradas
            state["tool_execution_results"] = mcp_list
            vulns = list(state.get("vulnerabilidades_encontradas") or [])
            for ev in (result.get("evidence") or []):
                if isinstance(ev, dict) and ev.get("evidence_strength") in {"medium", "strong", "conclusive"}:
                    vulns.append({"phase_id": phase_id, "evidence_id": ev.get("evidence_id"), "type": ev.get("vulnerability_class")})
            state["vulnerabilidades_encontradas"] = vulns[-500:]
            # evidence_adjudication needs: validation_backlog
            state["validation_backlog"] = state.get("validation_backlog") or []
            # node_history: append capability nodes touched
            node_history = list(state.get("node_history") or [])
            for cap in PHASE_TO_CAPABILITIES.get(phase_id, []):
                if cap not in node_history:
                    node_history.append(cap)
            state["node_history"] = node_history
            # completed_capabilities for fully-completed phase
            if result["phase_ledger"].get("status") == "completed":
                completed_caps = list(state.get("completed_capabilities") or [])
                for cap in PHASE_TO_CAPABILITIES.get(phase_id, []):
                    if cap not in completed_caps:
                        completed_caps.append(cap)
                        # Also mark in capability_ledger directly
                        mark_capability(
                            state,
                            cap,
                            source=f"phase_{phase_id}",
                            status="completed",
                            evidence={"phase_id": phase_id, "skill_id": selected_skill_ids[0] if selected_skill_ids else ""},
                        )
                state["completed_capabilities"] = completed_caps

            job.state_data = state
            # REAL-TIME PERSISTENCE: update progress + persist findings after each phase
            # so partial results survive worker crashes / scan interruption.
            completed_so_far = len([l for l in phase_ledgers if l.get("status") == "completed"])
            partial_so_far = len([l for l in phase_ledgers if l.get("status") == "partial"])
            job.mission_progress = int(round((len(phase_ledgers) / max(1, len(PHASE_ORDER))) * 100))
            db.commit()
            try:
                _persist_offensive_findings(db, job, phase_ledgers, targets)
                db.commit()
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                               message=f"finding_persist_partial_failure phase={phase_id} error={exc!s}"))
                db.commit()
            # Only abort on blocked if no skill was resolved at all (hard blocker).
            # Tool-level blocks (e.g. missing optional OOB tool) are logged and skipped.
            if result["phase_ledger"].get("status") == "blocked":
                blocking_reason = result["phase_ledger"].get("blocking_reason", "")
                if blocking_reason in {"no_approved_skill_resolved"}:
                    break
                # Otherwise continue to the next phase — record as covered/partial.

    # ─── Multi-target propagation: MANDATORY for domain scans ────────────────
    # When a scan is requested by domain, discovered subdomains MUST be tested —
    # a domain scan that only tests the apex is incomplete. Each discovered
    # subdomain gets the recon + vulnerability phase set re-run against it.
    state = dict(job.state_data or {})
    expanded = list(state.get("expanded_targets") or [])
    # exclude root (already scanned); cap at 12 subdomains to bound runtime
    propagation_cap = int(state.get("subdomain_propagation_cap") or 12)
    secondary_targets = [t for t in expanded[1:propagation_cap + 1] if t and t != targets[0]]
    # Recon + nuclei-driven vuln phases — fast, high-signal coverage per subdomain.
    # ASM mode keeps recon-only; full mode adds vuln template scanning.
    if scan_level == "asm":
        recon_propagation_phases = ["P02", "P03", "P05", "P06", "P07"]
    else:
        recon_propagation_phases = ["P02", "P03", "P05", "P06", "P07", "P09", "P11", "P15", "P18"]
    if secondary_targets:
        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                       message=f"multi_target_propagation starting for {len(secondary_targets)} subdomains: {secondary_targets}"))
        db.commit()
        for sub_target in secondary_targets:
            sub_scope = _scope_from_job(job, sub_target, execution_mode)
            for phase_id in recon_propagation_phases:
                if allowed_phases is not None and phase_id not in allowed_phases:
                    continue
                job.current_step = f"{phase_id} {PHASE_CONTRACTS[phase_id]['name']} (sub:{sub_target})"
                db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                               message=f"dispatch phase_id={phase_id} tool=kali target={sub_target} (multi-target)"))
                db.commit()
                try:
                    result = runtime.run_phase(phase_id, sub_target, sub_scope, execution_mode, offensive_state)
                    sub_ledger = result["phase_ledger"]
                    sub_ledger["target"] = sub_target
                    sub_ledger["mcp_results"] = result.get("mcp_results") or []
                    sub_ledger["multi_target_propagation"] = True
                    phase_ledgers.append(sub_ledger)
                    offensive_state = result["offensive_state"]
                    db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                                   message=f"phase_result phase_id={phase_id} status={sub_ledger.get('status')} target={sub_target} tools_attempted={sub_ledger.get('tools_attempted', [])}"))
                    state = dict(job.state_data or {})
                    state["phase_ledger_v2"] = phase_ledgers
                    job.state_data = state
                    db.commit()
                    try:
                        _persist_offensive_findings(db, job, phase_ledgers, [sub_target])
                        db.commit()
                    except Exception as exc:  # noqa: BLE001
                        db.rollback()
                except Exception as exc:  # noqa: BLE001
                    db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                                   message=f"multi_target_propagation_failed phase={phase_id} target={sub_target} error={exc!s}"))
                    db.commit()

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

    completed_count = len([l for l in phase_ledgers if l.get("status") == "completed"])
    partial_count = len([l for l in phase_ledgers if l.get("status") == "partial"])
    blocked_count = len([l for l in phase_ledgers if l.get("status") == "blocked"])

    # ─ Finalize capability ledger: governance + executive_analyst from campaign report ─
    completed_phases = [l.get("phase_id") for l in phase_ledgers if l.get("status") == "completed"]
    state["easm_rating"] = {
        "campaign_id": offensive_state.get("campaign_id"),
        "phases_completed": completed_phases,
        "phase_count": len(completed_phases),
        "total_phases": len(PHASE_ORDER),
        "coverage_percent": round((len(completed_phases) / max(1, len(PHASE_ORDER))) * 100),
    }
    state["fair_decomposition"] = state.get("fair_decomposition") or {
        "loss_event_frequency": "low",
        "loss_magnitude": "medium",
        "evidence_phases": completed_phases,
    }
    state["executive_summary"] = state.get("executive_summary") or {
        "target": targets[0] if targets else "",
        "phases_executed": len(phase_ledgers),
        "phases_completed": len(completed_phases),
        "campaign_status": "completed" if (completed_count + partial_count) > 0 else "failed",
    }
    mark_capability(state, "governance", source="report_builder", status="completed",
                    evidence={"easm_rating": state["easm_rating"]})
    mark_capability(state, "executive_analyst", source="report_builder", status="completed",
                    evidence={"summary": state["executive_summary"]})

    # ─── Learning loop: extract VulnerabilityLearning seeds from scan results ───
    try:
        learning_signals = extract_learning_signals(state, phase_ledgers)
        if learning_signals:
            from app.models.models import VulnerabilityLearning
            from datetime import datetime as _dt
            persisted = 0
            for sig in learning_signals[:30]:  # cap to 30 per scan
                exists = db.query(VulnerabilityLearning).filter(
                    VulnerabilityLearning.title == (sig.get("title") or "")[:255],
                    VulnerabilityLearning.vulnerability_type == (sig.get("template") or "nuclei")[:120],
                ).first()
                if exists:
                    continue
                row = VulnerabilityLearning(
                    title=(sig.get("title") or sig.get("template") or "scan-derived")[:255],
                    vulnerability_type=(sig.get("template") or "nuclei")[:120],
                    url=(sig.get("evidence_url") or "")[:500],
                    final_url=(sig.get("evidence_url") or "")[:500],
                    summary=sig.get("description") or "",
                    impact=f"Tech stack: {', '.join(sig.get('tech_stack', [])) or 'unknown'}. Severity: {sig.get('severity')}",
                    remediation="Review nuclei template guidance and apply patch/configuration changes.",
                    evidence_signals=[sig.get("template"), sig.get("cve")],
                    safe_validation_steps=[f"curl {sig.get('evidence_url')}", "Verify with nuclei -id " + str(sig.get("template"))],
                    affected_phases=[sig.get("phase_id")],
                    affected_skills=[],
                    recommended_tools=["nuclei", "curl"],
                    technique_count=1,
                    status="pending_review",
                    source="scan_extraction",
                    source_kind="scan_finding",
                    model="scan_intelligence_extractor",
                    owner_id=job.owner_id,
                    created_at=_dt.utcnow(),
                    updated_at=_dt.utcnow(),
                )
                db.add(row)
                persisted += 1
            if persisted:
                db.commit()
                db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                               message=f"learning_loop persisted={persisted} new_signals_from_scan"))
                db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                       message=f"learning_loop_failed error={exc!s}"))
        db.commit()

    job.state_data = state
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


def _extract_evidence(phase_id: str, tool_name: str, mcp_res: dict[str, Any]) -> dict[str, Any]:
    """Parse tool stdout/parsed_result into structured evidence for RedTeam reporting."""
    import json as _json
    stdout = str(mcp_res.get("stdout") or "")
    parsed = mcp_res.get("parsed_result")
    command = str(mcp_res.get("command") or "")
    duration = mcp_res.get("duration_seconds")
    workdir = str(mcp_res.get("stdout_path") or "")

    evidence: dict[str, Any] = {
        "tool": tool_name,
        "command": command,
        "duration_seconds": duration,
        "workdir": workdir,
        "raw_output_preview": stdout[:3000] if stdout else None,
    }

    tool_lower = tool_name.lower()

    # --- subfinder / amass: subdomains list ---
    if tool_lower in {"subfinder", "amass", "assetfinder", "dnsx"}:
        lines = [l.strip() for l in stdout.splitlines() if l.strip() and not l.startswith("[")]
        domains = [l for l in lines if "." in l and not l.startswith("http")]
        evidence["discovered_subdomains"] = domains[:200]
        evidence["subdomain_count"] = len(domains)
        evidence["finding_summary"] = (
            f"{len(domains)} subdomains discovered via {tool_name}: "
            + (", ".join(domains[:5]) + ("…" if len(domains) > 5 else ""))
            if domains else f"No subdomains found via {tool_name}"
        )

    # --- theHarvester: emails, hosts, IPs from OSINT ---
    elif tool_lower in {"theharvester"}:
        emails = [l.strip() for l in stdout.splitlines() if "@" in l and "." in l]
        hosts = [l.strip() for l in stdout.splitlines() if l.strip().startswith("-") or ("." in l and "@" not in l and not l.startswith("["))]
        evidence["emails_found"] = emails[:50]
        evidence["hosts_found"] = hosts[:50]
        evidence["finding_summary"] = (
            f"OSINT harvest: {len(emails)} email(s), {len(hosts)} host(s). "
            + ("Emails: " + ", ".join(emails[:3]) if emails else "")
        )

    # --- naabu / nmap: open ports ---
    elif tool_lower in {"naabu", "nmap", "masscan"}:
        port_lines = [l.strip() for l in stdout.splitlines() if l.strip() and ":" in l]
        parsed_ports = []
        if isinstance(parsed, list):
            parsed_ports = parsed
        elif port_lines:
            parsed_ports = port_lines[:50]
        evidence["open_ports"] = parsed_ports[:50]
        evidence["port_count"] = len(parsed_ports)
        evidence["finding_summary"] = (
            f"{len(parsed_ports)} open port(s) found: "
            + ", ".join(str(p) for p in parsed_ports[:10])
            if parsed_ports else "No open ports found"
        )

    # --- shodan: service banners and exposed services (JSON output from Python API) ---
    elif tool_lower in {"shodan-cli", "shodan"}:
        evidence["shodan_raw"] = stdout[:2000]
        shodan_data: dict[str, Any] = {}
        try:
            shodan_data = _json.loads(stdout) if stdout.strip().startswith("{") else {}
        except Exception:
            shodan_data = {}
        if shodan_data:
            ports = shodan_data.get("ports") or []
            org = shodan_data.get("org") or ""
            hostnames = shodan_data.get("hostnames") or []
            vulns = shodan_data.get("vulns") or []
            banners = shodan_data.get("banners") or []
            evidence["open_ports"] = ports
            evidence["organization"] = org
            evidence["hostnames"] = hostnames
            evidence["cve_ids"] = vulns
            evidence["service_banners"] = banners[:10]
            vuln_str = f", CVEs: {', '.join(vulns[:3])}" if vulns else ""
            evidence["finding_summary"] = (
                f"Shodan [{org}]: {len(ports)} port(s) open — {', '.join(str(p) for p in ports[:8])}"
                + (f", hostnames: {', '.join(hostnames[:3])}" if hostnames else "")
                + vuln_str
            )
        else:
            interesting = [l.strip() for l in stdout.splitlines()
                           if any(k in l.lower() for k in ["ip:", "port:", "os:", "org:", "cpe:", "vuln", "banner"])]
            evidence["service_intel"] = interesting[:30]
            evidence["finding_summary"] = (
                f"Shodan OSINT: " + "; ".join(interesting[:5])
                if interesting else "Shodan: no enrichment data"
            )

    # --- ffuf / gobuster: discovered paths ---
    elif tool_lower in {"ffuf", "gobuster", "feroxbuster"}:
        if isinstance(parsed, list) and parsed:
            paths = [str(p.get("url") or p.get("path") or p) for p in parsed[:100]]
        else:
            paths = [l.strip() for l in stdout.splitlines() if l.strip() and "/" in l][:100]
        evidence["discovered_paths"] = paths[:100]
        evidence["path_count"] = len(paths)
        evidence["finding_summary"] = (
            f"{len(paths)} path(s) discovered: "
            + ", ".join(paths[:5]) + ("…" if len(paths) > 5 else "")
            if paths else "No paths discovered"
        )

    # --- nuclei: CVEs, vulnerabilities, misconfigurations ---
    elif tool_lower in {"nuclei"}:
        findings = []
        if isinstance(parsed, list):
            for item in parsed[:50]:
                if isinstance(item, dict):
                    findings.append({
                        "template": item.get("template-id") or item.get("template"),
                        "name": item.get("info", {}).get("name") or item.get("name"),
                        "severity": item.get("info", {}).get("severity") or item.get("severity"),
                        "url": item.get("matched-at") or item.get("url"),
                        "description": item.get("info", {}).get("description") or "",
                        "cve": item.get("info", {}).get("classification", {}).get("cve-id") if isinstance(item.get("info"), dict) else None,
                    })
        else:
            # Try parsing JSONL from stdout
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = _json.loads(line)
                    findings.append({
                        "template": item.get("template-id"),
                        "name": (item.get("info") or {}).get("name"),
                        "severity": (item.get("info") or {}).get("severity"),
                        "url": item.get("matched-at"),
                        "description": (item.get("info") or {}).get("description", ""),
                        "cve": ((item.get("info") or {}).get("classification") or {}).get("cve-id"),
                    })
                except Exception:
                    pass
        evidence["nuclei_findings"] = findings
        evidence["vulnerability_count"] = len(findings)
        crits = [f for f in findings if str(f.get("severity") or "").lower() in {"critical", "high"}]
        evidence["finding_summary"] = (
            f"Nuclei: {len(findings)} finding(s) — "
            + (f"{len(crits)} critical/high: " + ", ".join(f.get("name","?") for f in crits[:3]) if crits
               else "no critical/high findings" if findings else "no vulnerabilities detected")
        )

    # --- gitleaks / trufflehog: secrets and credentials ---
    elif tool_lower in {"gitleaks", "trufflehog", "trufflehog-filesystem"}:
        secrets = []
        if isinstance(parsed, list):
            for item in parsed[:20]:
                if isinstance(item, dict):
                    secrets.append({
                        "type": item.get("RuleID") or item.get("rule_id") or item.get("DetectorName") or "secret",
                        "file": item.get("File") or item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file") or "unknown",
                        "line": item.get("StartLine") or item.get("line"),
                        "secret_preview": str(item.get("Secret") or item.get("Raw") or "")[:20] + "***",
                        "description": item.get("Description") or item.get("RuleDescription") or "",
                    })
        else:
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = _json.loads(line)
                    secrets.append({
                        "type": item.get("RuleID") or item.get("DetectorName") or "secret",
                        "file": item.get("File") or "unknown",
                        "line": item.get("StartLine"),
                        "secret_preview": str(item.get("Secret") or item.get("Raw") or "")[:20] + "***",
                    })
                except Exception:
                    pass
        evidence["secrets_found"] = secrets
        evidence["secret_count"] = len(secrets)
        evidence["finding_summary"] = (
            f"Credential scan: {len(secrets)} secret(s) found — "
            + "; ".join(f"{s['type']} in {s['file']}:{s.get('line','?')}" for s in secrets[:3])
            if secrets else "No credentials or secrets found"
        )

    # --- curl / curl-headers: HTTP response evidence ---
    elif tool_lower in {"curl", "curl-headers"}:
        headers = {}
        status_line = ""
        for line in stdout.splitlines():
            if line.startswith("HTTP/"):
                status_line = line.strip()
            elif ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        security_headers = {
            k: v for k, v in headers.items()
            if k in {"server", "x-powered-by", "x-frame-options", "content-security-policy",
                     "strict-transport-security", "x-content-type-options", "set-cookie",
                     "www-authenticate", "cf-ray", "x-amz-request-id", "x-aspnet-version"}
        }
        missing_security = [
            h for h in ["x-frame-options", "content-security-policy", "strict-transport-security",
                        "x-content-type-options"]
            if h not in headers
        ]
        tech_hints = []
        if "server" in headers:
            tech_hints.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            tech_hints.append(f"X-Powered-By: {headers['x-powered-by']}")
        if "x-aspnet-version" in headers:
            tech_hints.append(f"ASP.NET: {headers['x-aspnet-version']}")
        evidence["http_status"] = status_line
        evidence["security_headers"] = security_headers
        evidence["missing_security_headers"] = missing_security
        evidence["technology_hints"] = tech_hints
        evidence["finding_summary"] = (
            f"HTTP {status_line}. "
            + (f"Tech: {'; '.join(tech_hints)}. " if tech_hints else "")
            + (f"Missing headers: {', '.join(missing_security)}" if missing_security else "All security headers present")
        )

    # --- arjun: discovered parameters ---
    elif tool_lower in {"arjun", "paramspider"}:
        params = []
        if isinstance(parsed, list):
            params = [str(p) for p in parsed[:100]]
        else:
            params = [l.strip() for l in stdout.splitlines() if l.strip() and "?" not in l and len(l.strip()) < 50][:50]
        evidence["discovered_parameters"] = params
        evidence["parameter_count"] = len(params)
        evidence["finding_summary"] = (
            f"{len(params)} parameter(s) discovered: " + ", ".join(params[:10])
            if params else "No parameters discovered"
        )

    # --- sqlmap: injection points ---
    elif tool_lower in {"sqlmap"}:
        injections = [l.strip() for l in stdout.splitlines()
                      if any(k in l.lower() for k in ["parameter", "injectable", "payload", "technique", "dbms"])]
        evidence["injection_evidence"] = injections[:20]
        evidence["finding_summary"] = (
            "SQLMap injection evidence: " + "; ".join(injections[:3])
            if injections else "No SQL injection found"
        )

    else:
        # Generic: return first meaningful output lines
        lines = [l.strip() for l in stdout.splitlines() if l.strip()][:20]
        evidence["output_lines"] = lines
        evidence["finding_summary"] = lines[0] if lines else f"{tool_name} ran (no parseable output)"

    return evidence


def _generate_recommendation(phase_id: str, tool_evidences: list[dict[str, Any]]) -> str:
    """Generate specific, actionable recommendation from phase evidence."""
    recs: list[str] = []

    for ev in tool_evidences:
        tool = str(ev.get("tool") or "").lower()

        if tool in {"subfinder", "amass", "amass-brute", "assetfinder"}:
            count = ev.get("subdomain_count", 0)
            subs = ev.get("discovered_subdomains") or []
            if count:
                recs.append(
                    f"Foram encontrados {count} subdomínio(s) ({', '.join(subs[:3])}{'…' if count > 3 else ''}). "
                    "Revise cada subdomínio para verificar se está ativo, se contém serviços expostos indevidamente "
                    "e aplique política de subdomain takeover monitoring."
                )

        elif tool == "theharvester":
            emails = ev.get("emails_found") or []
            if emails:
                recs.append(
                    f"OSINT revelou {len(emails)} e-mail(s) corporativo(s) ({', '.join(emails[:3])}). "
                    "Implemente monitoramento de data leaks (HaveIBeenPwned, DarkWeb), "
                    "habilite MFA em todas as contas e remova endereços expostos de páginas públicas."
                )

        elif tool in {"naabu", "nmap", "masscan"}:
            ports = ev.get("open_ports") or []
            if ports:
                recs.append(
                    f"Portas abertas identificadas: {', '.join(str(p) for p in ports[:10])}. "
                    "Feche portas desnecessárias via firewall, aplique segmentação de rede e "
                    "garanta que serviços expostos estão na versão mais recente com patches de segurança."
                )

        elif tool in {"shodan-cli", "shodan"}:
            cves = ev.get("cve_ids") or []
            banners = ev.get("service_banners") or []
            if cves:
                recs.append(
                    f"Shodan identificou {len(cves)} CVE(s) associado(s) ao alvo: {', '.join(cves[:5])}. "
                    "Aplique os patches correspondentes imediatamente e revise banners de serviços que expõem versões."
                )
            elif banners:
                recs.append(
                    "Shodan indexou banners de serviços deste alvo. "
                    "Remova headers/banners que expõem versão de servidor e habilite regras de firewall para bloquear crawlers."
                )

        elif tool in {"ffuf", "gobuster", "feroxbuster"}:
            paths = ev.get("discovered_paths") or []
            if paths:
                sensitive = [p for p in paths if any(k in p.lower() for k in
                    ["admin", "backup", ".git", "config", "env", "secret", "api", "swagger", "debug", "test"])]
                recs.append(
                    f"Content discovery encontrou {len(paths)} caminho(s)"
                    + (f", incluindo caminhos sensíveis: {', '.join(sensitive[:5])}" if sensitive else "")
                    + ". Restrinja acesso a endpoints administrativos via autenticação, "
                    "remova arquivos de backup/config expostos e configure WAF para bloquear path traversal."
                )

        elif tool == "nuclei":
            findings = ev.get("nuclei_findings") or []
            crits = [f for f in findings if str(f.get("severity") or "").lower() in {"critical", "high"}]
            if crits:
                crit_names = ", ".join(f.get("name", f.get("template", "?")) for f in crits[:3])
                recs.append(
                    f"Nuclei detectou {len(crits)} vulnerabilidade(s) crítica(s)/alta(s): {crit_names}. "
                    "Aplique patches imediatamente, revise configurações de servidor e implemente "
                    "controles de segurança conforme as recomendações de cada template Nuclei."
                )
            elif findings:
                recs.append(
                    f"Nuclei identificou {len(findings)} finding(s) de média/baixa severidade. "
                    "Revise e corrija configurações de segurança, headers HTTP e versões de componentes."
                )

        elif tool in {"gitleaks", "trufflehog", "trufflehog-filesystem"}:
            secrets = ev.get("secrets_found") or []
            if secrets:
                types = list({s.get("type", "secret") for s in secrets[:5]})
                recs.append(
                    f"CRITICAL: {len(secrets)} credencial(is) exposta(s) via {tool}: {', '.join(types)}. "
                    "Revogue e rotacione IMEDIATAMENTE todas as credenciais expostas, "
                    "remova do repositório usando git-filter-branch/BFG, "
                    "implemente pre-commit hooks (git-secrets, detect-secrets) e "
                    "use gerenciador de segredos (HashiCorp Vault, AWS Secrets Manager)."
                )

        elif tool in {"curl", "curl-headers"}:
            missing = ev.get("missing_security_headers") or []
            tech = ev.get("technology_hints") or []
            if missing:
                recs.append(
                    f"Headers de segurança ausentes: {', '.join(missing)}. "
                    "Configure Content-Security-Policy, X-Frame-Options (SAMEORIGIN), "
                    "Strict-Transport-Security (HSTS) e X-Content-Type-Options (nosniff) no servidor web."
                )
            if tech:
                recs.append(
                    f"Stack tecnológica identificada via headers: {'; '.join(tech)}. "
                    "Remova ou ofusque headers que expõem versões de servidor (Server, X-Powered-By) "
                    "para dificultar fingerprinting."
                )

        elif tool in {"arjun", "paramspider"}:
            params = ev.get("discovered_parameters") or []
            if params:
                recs.append(
                    f"{len(params)} parâmetro(s) descoberto(s): {', '.join(params[:8])}. "
                    "Valide e sanitize todos os parâmetros de entrada, implemente rate limiting, "
                    "e revise se parâmetros expostos podem ser vetores de injection ou IDOR."
                )

    if not recs:
        # Phase-level fallback
        phase_fallbacks = {
            "P01": "Implemente monitoramento contínuo de surface de ataque e política de DNS naming convention.",
            "P02": "Minimize a superfície de ataque fechando portas não essenciais e aplicando firewall.",
            "P09": "Execute scans regulares de vulnerabilidade com Nuclei e mantenha templates atualizados.",
            "P17": "Aplique patches de segurança imediatamente para CVEs identificados.",
            "P18": "Implemente DLP (Data Loss Prevention) e monitore vazamentos de credenciais em Dark Web.",
            "P22": "Implemente ciclo de revisão de segurança contínuo baseado nos findings deste relatório.",
        }
        return phase_fallbacks.get(phase_id, "Revise os resultados deste fase e aplique controles de segurança adequados.")

    return " | ".join(recs)


def _has_real_evidence(tool_evidences: list[dict[str, Any]]) -> tuple[bool, str]:
    """Inspect tool evidence and decide whether an actual security-relevant
    finding exists. Returns (has_evidence, strongest_signal).

    A finding is only "real" when a tool produced concrete output:
    discovered ports/paths/subdomains/params, nuclei findings, secrets,
    missing security headers, etc. Phases that ran but found nothing must
    NOT be reported as high/critical vulnerabilities.
    """
    strongest = ""
    for ev in tool_evidences:
        if ev.get("nuclei_findings"):
            crits = [f for f in ev["nuclei_findings"] if str(f.get("severity") or "").lower() in {"critical", "high"}]
            if crits:
                return True, "nuclei_critical"
            strongest = "nuclei_finding"
        if ev.get("secrets_found"):
            return True, "secret_exposed"
        if ev.get("cve_ids"):
            return True, "cve_identified"
        if ev.get("vulnerability_count", 0) > 0:
            strongest = strongest or "vulnerability"
        if ev.get("discovered_paths"):
            sensitive = [p for p in ev["discovered_paths"] if any(
                k in str(p).lower() for k in ["admin", "backup", ".git", "config", ".env", "secret", "debug", "swagger"])]
            if sensitive:
                strongest = "sensitive_path"
            else:
                strongest = strongest or "path_discovered"
        if ev.get("open_ports"):
            strongest = strongest or "ports_open"
        if ev.get("discovered_subdomains"):
            strongest = strongest or "subdomains_found"
        if ev.get("discovered_parameters"):
            strongest = strongest or "params_found"
        if ev.get("missing_security_headers"):
            strongest = strongest or "missing_headers"
        if ev.get("injection_evidence"):
            return True, "injection_confirmed"
    return (bool(strongest), strongest)


def _assess_evidence_severity(phase_id: str, status: str, tool_evidences: list[dict[str, Any]],
                              phase_severity_map: dict[str, str]) -> tuple[str, int]:
    """Derive severity + confidence from ACTUAL evidence — not just the phase.

    Previously every P11 (SSRF) finding was 'high' even with zero evidence,
    producing false positives. Now:
      - no evidence at all   → 'info', low confidence
      - weak recon evidence  → 'info'/'low'
      - confirmed vuln/secret/CVE → phase severity
    """
    has_evidence, signal = _has_real_evidence(tool_evidences)
    phase_sev = phase_severity_map.get(phase_id, "info")

    if not has_evidence:
        # Phase ran but produced nothing actionable — informational only.
        return "info", (25 if status == "completed" else 15)

    # Strong, confirmed signals → escalate to the phase's intended severity.
    if signal in {"nuclei_critical", "secret_exposed", "cve_identified", "injection_confirmed"}:
        return phase_sev if phase_sev != "info" else "high", 90

    # Sensitive path / nuclei medium finding → at least medium.
    if signal in {"sensitive_path", "nuclei_finding", "vulnerability"}:
        escalated = phase_sev if phase_sev in {"high", "critical", "medium"} else "medium"
        return escalated, 70

    # Recon-level evidence (ports, subdomains, params) → low/info, never high.
    if signal in {"ports_open", "subdomains_found", "path_discovered", "params_found"}:
        return "low", 55
    if signal in {"missing_headers"}:
        return "medium", 60

    return "info", 40


def _build_redteam_title(phase_id: str, phase_name: str, status: str, evidence_list: list[dict[str, Any]]) -> str:
    """Build a descriptive finding title that reflects what was actually found.

    Titles must not imply a vulnerability when no evidence exists. A phase that
    ran but found nothing is labelled 'Sem achados' (coverage only).
    """
    has_evidence, signal = _has_real_evidence(evidence_list)
    # Pick the most informative non-empty summary that isn't a "nothing found" line
    meaningful = [
        e.get("finding_summary", "") for e in evidence_list
        if e.get("finding_summary") and not str(e.get("finding_summary")).lower().startswith(("no ", "nenhum", "sem "))
    ]
    if has_evidence and meaningful:
        return f"[{phase_id}] {phase_name}: {meaningful[0][:120]}"
    if has_evidence:
        return f"[{phase_id}] {phase_name}: evidência de superfície coletada"
    # No real evidence — coverage record only, not a vulnerability.
    return f"[{phase_id}] {phase_name} — Sem achados (cobertura executada)"


def _persist_offensive_findings(db, job: ScanJob, phase_ledgers: list[dict[str, Any]], targets: list[str]) -> None:
    """Convert phase ledger + MCP tool output into rich Finding rows with real evidence.

    Idempotent: pre-loads existing (phase_id, target) pairs from DB so re-running
    after each phase only adds new findings, never duplicates.
    """
    from app.models.models import Asset, Vulnerability

    # Pre-seed `seen` with (phase_id, target) keys already persisted for this scan
    # so this function is safe to call multiple times during a single scan execution.
    existing_findings = (
        db.query(Finding)
        .filter(Finding.scan_job_id == job.id)
        .all()
    )
    seen: set[tuple[str, str]] = set()
    for f in existing_findings:
        d = f.details or {}
        pid = str(d.get("phase_id") or "")
        tgt = str(d.get("target") or f.domain or "")
        if pid:
            seen.add((pid, tgt))
    primary_target = targets[0] if targets else str(job.target_query or "")

    PHASE_SEVERITY: dict[str, str] = {
        "P09": "medium",    # nuclei vuln templates
        "P10": "high",      # injection
        "P11": "high",      # ssrf
        "P12": "medium",    # xss
        "P13": "high",      # idor
        "P14": "high",      # auth bypass
        "P15": "medium",    # file handling
        "P17": "critical",  # exploit validation
        "P18": "critical",  # credential exposure
    }

    # Build index of mcp_results per phase from state_data
    state = dict(job.state_data or {})
    # phase_ledger_v2 and last_mcp_results are the sources; build a map phase→mcp_results
    phase_mcp_map: dict[str, list[dict[str, Any]]] = {}
    for ledger in phase_ledgers:
        pid = ledger.get("phase_id", "")
        if pid and ledger.get("mcp_results"):
            phase_mcp_map[pid] = list(ledger["mcp_results"])

    for ledger in phase_ledgers:
        phase_id = ledger.get("phase_id", "")
        phase_name = ledger.get("phase_name", phase_id)
        status = ledger.get("status", "")
        target = ledger.get("target") or primary_target

        tools_success = ledger.get("tools_success", [])
        tools_attempted = ledger.get("tools_attempted", [])
        if not tools_attempted:
            continue

        key = (phase_id, str(target))
        if key in seen:
            continue
        seen.add(key)

        # Extract per-tool evidence from MCP results stored in the ledger
        mcp_results = phase_mcp_map.get(phase_id) or ledger.get("mcp_results") or []
        tool_evidences: list[dict[str, Any]] = []
        for mcp_res in mcp_results:
            tool_name = str(mcp_res.get("tool_name") or "")
            if mcp_res.get("status") in {"success", "done"} and tool_name:
                ev = _extract_evidence(phase_id, tool_name, mcp_res)
                tool_evidences.append(ev)

        # Severity + confidence are derived from ACTUAL evidence, not the phase.
        # A phase that ran with no findings → 'info', never 'high'.
        severity, confidence = _assess_evidence_severity(phase_id, status, tool_evidences, PHASE_SEVERITY)

        title = _build_redteam_title(phase_id, phase_name, status, tool_evidences)
        recommendation = _generate_recommendation(phase_id, tool_evidences)

        # State-derived context for MITRE/OWASP enrichment + tech_stack snapshot
        state_snap = dict(job.state_data or {})
        tech_snap = state_snap.get("tech_stack") or {}

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
            # RedTeam evidence — one entry per tool that ran
            "tool_evidence": tool_evidences,
            # Tech stack snapshot at time of finding
            "tech_stack": tech_snap.get("detected") or [],
            "cms_detected": tech_snap.get("cms") or [],
            "waf_detected": tech_snap.get("waf") or [],
        }
        details = enrich_finding_with_mappings(phase_id, details)

        finding = Finding(
            scan_job_id=job.id,
            title=title[:255],
            severity=severity,
            cve=None,
            cvss=None,
            domain=str(target)[:255],
            tool=", ".join(tools_success or tools_attempted)[:100] or None,
            recommendation=recommendation or None,
            confidence_score=confidence,
            risk_score=max(1, confidence // 10),
            details=details,
        )
        db.add(finding)

        # Persist asset + vulnerability for completed/partial phases
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
                    Vulnerability.title == title[:255],
                ).first()
                if not existing_vuln:
                    from datetime import datetime as _dt
                    _now = _dt.utcnow()
                    vuln = Vulnerability(
                        asset_id=asset.id,
                        title=title[:255],
                        severity=severity,
                        tool_source=", ".join(tools_success or tools_attempted)[:100] or "offensive_operator",
                        first_detected=_now,
                        last_detected=_now,
                    )
                    db.add(vuln)
            except Exception:
                pass
