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
    analyze_waf_behavior,
    apply_waf_confidence_adjustment,
    refine_target_set,
    NETWORK_PHASES,
    detect_rate_limit_signals,
    dedup_findings_by_signature,
    derive_cvss,
    build_executive_narrative,
    diff_against_previous,
    chain_findings,
    load_fp_blocklist,
    apply_fp_blocklist,
    llm_phase_reasoning,
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

    # ─── Checkpoint Engine: resumable work queue across root + subdomains ────
    import time as _time
    _checkpoint_start = _time.monotonic()
    _CHECKPOINT_SECONDS = int(initial_state.get("checkpoint_seconds") or 3000)
    completed_work: set[str] = set(initial_state.get("completed_work") or [])
    # all_targets starts as the input targets; after P01 it grows with every
    # discovered subdomain so each phase P02-P22 runs against the full set.
    all_targets: list[str] = list(initial_state.get("target_set") or targets)
    _input_target_count = len(targets)
    _phases_for_level = [p for p in PHASE_ORDER if allowed_phases is None or p in allowed_phases]
    # host → resolved IP, for IP-grouped network phases (populated after P01)
    host_ip_map: dict[str, str] = dict(initial_state.get("host_ip_map") or {})
    _target_idx = 0
    while _target_idx < len(all_targets):
        target = all_targets[_target_idx]
        if not target:
            _target_idx += 1
            continue
        # RACE-FIX: refresh completed_work + target_set from DB at every target
        # iteration so updates from parallel subtasks are visible to the main
        # task (and vice-versa). Without this, parallel subtasks' progress is
        # invisible and the main task re-executes phases they already finished.
        try:
            db.refresh(job)
            _live_state = job.state_data or {}
            for _k in (_live_state.get("completed_work") or []):
                completed_work.add(_k)
            for _t in (_live_state.get("target_set") or []):
                if _t and _t not in all_targets:
                    all_targets.append(_t)
            for _h, _ip in (_live_state.get("host_ip_map") or {}).items():
                host_ip_map.setdefault(_h, _ip)
        except Exception:  # noqa: BLE001
            pass
        scope = _scope_from_job(job, target, execution_mode)
        offensive_state["target"] = target
        offensive_state["campaign_id"] = offensive_state.get("campaign_id") or f"scan-{job.id}"

        for phase_id in PHASE_ORDER:
            # Skip phases outside the configured scan_level (asm = recon only).
            if allowed_phases is not None and phase_id not in allowed_phases:
                continue
            # P01 (subdomain enumeration) only runs on root/input targets — a
            # discovered subdomain does not get re-enumerated for subdomains.
            if phase_id == "P01" and _target_idx >= _input_target_count:
                continue
            # RESUME: skip work already completed in a prior checkpoint segment.
            _work_key = f"{phase_id}:{target}"
            if _work_key in completed_work:
                continue
            # IP-GROUPING: a network phase (port scan) is bound to the host's
            # IP. If a sibling hostname on the same IP already ran it, reuse —
            # don't re-scan the same WAF/CDN edge (and trigger 429s).
            if phase_id in NETWORK_PHASES:
                _host_ip = host_ip_map.get(target)
                if _host_ip and f"{phase_id}:ip:{_host_ip}" in completed_work:
                    completed_work.add(_work_key)
                    db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                                   message=f"ip_dedup phase={phase_id} target={target} — IP {_host_ip} already scanned, reused"))
                    db.commit()
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
            # 3b. WAF deception analysis — learn the environment, flag fake ports/429
            env_profile = analyze_waf_behavior(state, mcp_list)
            if env_profile.get("waf_present") and not state.get("_waf_analysis_logged"):
                behaviors = env_profile.get("observed_behaviors") or []
                db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                               message=(f"waf_environment_learned vendors={env_profile.get('waf_vendors')} "
                                        f"behaviors={behaviors} confidence_penalty={env_profile.get('finding_confidence_penalty')}%")))
                state["_waf_analysis_logged"] = True
            # 4. Evidence validation: re-probe critical findings via MCP curl
            try:
                def _call_curl(url: str) -> dict:
                    import requests as _r
                    headers = {"User-Agent": evasion.get("user_agents", ["Mozilla/5.0"])[0], **auth_headers_from_state(state)}
                    r = _r.get(url, headers=headers, timeout=15, allow_redirects=True, verify=False)
                    return {"status_code": r.status_code, "body": r.text[:500]}
                # 429 detection + ADAPTIVE RETRY. If the WAF throttled tools,
                # wait the back-off window and re-run the phase with the
                # reduced-rate evasion profile already engaged. Cap at 1 retry
                # per (phase,target) so we never loop indefinitely.
                _rl = detect_rate_limit_signals(mcp_list)
                _retry_key = f"_rl_retried_{_work_key}"
                if _rl.get("hit") and not state.get(_retry_key):
                    state[_retry_key] = True
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                                   message=(f"rate_limit_detected phase={phase_id} target={target} "
                                            f"tools_throttled={_rl['tools_throttled']} — backing off 30s "
                                            f"and re-running with reduced-rate evasion profile")))
                    state["rate_limited_phases"] = list(set((state.get("rate_limited_phases") or []) + [phase_id]))
                    job.state_data = state
                    db.commit()
                    _time.sleep(30)
                    # Re-run the phase with the slow profile already in state
                    try:
                        _retry_result = runtime.run_phase(phase_id, target, scope, execution_mode, offensive_state)
                        _retry_ledger = _retry_result["phase_ledger"]
                        _retry_ledger["target"] = target
                        _retry_ledger["mcp_results"] = _retry_result.get("mcp_results") or []
                        _retry_ledger["rate_limit_retry"] = True
                        phase_ledgers.append(_retry_ledger)
                        offensive_state = _retry_result["offensive_state"]
                        # Replace mcp_list with retry data for downstream hooks
                        mcp_list = _retry_result.get("mcp_results") or []
                        result = _retry_result
                        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                       message=f"rate_limit_retry_completed phase={phase_id} target={target} status={_retry_ledger.get('status')}"))
                    except Exception as _re_exc:  # noqa: BLE001
                        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                                       message=f"rate_limit_retry_failed phase={phase_id} error={_re_exc!s}"))
                validations = validate_critical_findings(state, mcp_list, call_curl=_call_curl)
                # LLM reasoning between phases — only after high-signal phases
                try:
                    _tool_evs_for_llm = []
                    for m in mcp_list:
                        if isinstance(m, dict) and m.get("status") in ("success", "done"):
                            _tool_evs_for_llm.append(_extract_evidence(phase_id, m.get("tool_name", ""), m))
                    _reasoning = llm_phase_reasoning(state, phase_id, target, _tool_evs_for_llm, tech_stack, env_profile)
                    if _reasoning:
                        state["llm_reasoning"] = (state.get("llm_reasoning") or []) + [_reasoning]
                        # Merge injected_tools into per-phase plans
                        merged = state.get("llm_injected_tools") or {}
                        for ph, tools in (_reasoning.get("injected_tools") or {}).items():
                            merged.setdefault(ph, [])
                            for t in tools:
                                if t not in merged[ph]:
                                    merged[ph].append(t)
                        state["llm_injected_tools"] = merged
                        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                       message=(f"llm_reasoning after={phase_id} "
                                                f"suggested_phases={list((_reasoning.get('injected_tools') or {}).keys())} "
                                                f"reason=\"{_reasoning.get('reasoning','')[:120]}\"")))
                except Exception:  # noqa: BLE001
                    pass
                if validations:
                    _vc = {}
                    for _v in validations:
                        _s = _v.get("validation_status", "?")
                        _vc[_s] = _vc.get(_s, 0) + 1
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                   message=(f"finding_validation phase={phase_id} validated={len(validations)} "
                                            f"confirmed={_vc.get('confirmed', 0)} false_positive={_vc.get('false_positive', 0)} "
                                            f"waf_blocked={_vc.get('waf_blocked', 0)} unconfirmed={_vc.get('unconfirmed', 0)}")))
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
            _hard_blocked = False
            if result["phase_ledger"].get("status") == "blocked":
                blocking_reason = result["phase_ledger"].get("blocking_reason", "")
                if blocking_reason in {"no_approved_skill_resolved"}:
                    _hard_blocked = True
                # Otherwise continue to the next phase — record as covered/partial.

            # ─── Checkpoint Engine: mark work done, expand targets, re-dispatch ──
            completed_work.add(_work_key)
            # Record the IP-level key for network phases so sibling hostnames
            # on the same IP skip the redundant re-scan.
            if phase_id in NETWORK_PHASES:
                _done_ip = host_ip_map.get(target)
                if _done_ip:
                    completed_work.add(f"{phase_id}:ip:{_done_ip}")
            _cp_state = dict(job.state_data or {})
            _cp_state["completed_work"] = sorted(completed_work)
            # After P01 on a root target, expand the work set with every
            # discovered subdomain. Liveness-filter (drop hosts that don't
            # resolve) and IP-group (so network phases run once per IP).
            # NO CAP by default — every alive subdomain enters the queue.
            # Set subdomain_propagation_cap explicitly to limit if needed.
            if phase_id == "P01":
                _cap_raw = _cp_state.get("subdomain_propagation_cap")
                _cap = int(_cap_raw) if _cap_raw not in (None, 0) else 10000
                _subs = [s for s in (_cp_state.get("expanded_targets") or []) if s and s != target]
                _refined = refine_target_set(target, _subs, cap=_cap)
                for _live in _refined["live_targets"]:
                    if _live and _live not in all_targets:
                        all_targets.append(_live)
                _cp_state["target_set"] = list(all_targets)
                _cp_state["host_ip_map"] = _refined["host_ip"]
                _cp_state["dead_targets"] = _refined["dead_targets"]
                _cp_state["ip_groups"] = _refined["ip_groups"]
                host_ip_map = _refined["host_ip"]
                db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                               message=(f"target_set refined — {len(_refined['live_targets'])} live, "
                                        f"{len(_refined['dead_targets'])} dead, "
                                        f"{len(_refined['ip_groups'])} unique IP(s); full P02-P22 per live target")))
                # ─ Parallel fan-out: dispatch a subtask per non-root target ─
                if _cp_state.get("parallelize"):
                    try:
                        from app.workers.tasks import run_scan_target_subset as _rsts
                        _dispatched = 0
                        for _t in _refined["live_targets"]:
                            if _t and _t != target:
                                _rsts.delay(job.id, _t)
                                _dispatched += 1
                        if _dispatched:
                            db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                                           message=f"parallel_fanout dispatched {_dispatched} subtasks (one per non-root target)"))
                    except Exception as _pfe:  # noqa: BLE001
                        db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                                       message=f"parallel_fanout_failed error={_pfe!s}"))
                # ─ WAF Origin Discovery — hunt the real server behind the WAF ─
                try:
                    from app.services.waf_origin import discover_origin_candidates as _disc_origin
                    _origin = _disc_origin(target, _refined["host_ip"], result.get("mcp_results") or [])
                    _cp_state["origin_discovery"] = _origin
                    _cands = _origin.get("candidate_origins") or []
                    if _cands:
                        _top = _cands[0]
                        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                                       message=(f"waf_origin_discovery {_origin['summary']} — "
                                                f"top candidate {_top['ip']} (confidence={_top['confidence']}, "
                                                f"hosts={_top['hosts'][:3]})")))
                        _persist_origin_finding(db, job, target, _origin)
                    else:
                        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                       message=f"waf_origin_discovery {_origin['summary']}"))
                except Exception as _oexc:  # noqa: BLE001
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                                   message=f"waf_origin_discovery_failed error={_oexc!s}"))
            # Progress across the whole job (every target × every phase).
            _total_units = max(1, len(all_targets) * max(1, len(_phases_for_level)))
            job.mission_progress = min(100, int(round(len(completed_work) / _total_units * 100)))
            job.state_data = _cp_state
            db.commit()
            # Re-dispatch before the Celery time limit so deep multi-target
            # scans run effectively unbounded — each (phase,target) is a
            # durable checkpoint, so a continuation resumes exactly here.
            if _time.monotonic() - _checkpoint_start > _CHECKPOINT_SECONDS:
                db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                               message=(f"checkpoint — {len(completed_work)} phase-targets done; "
                                        f"re-dispatching scan to continue")))
                job.current_step = f"checkpoint: {len(completed_work)} concluídos — continuando"
                db.commit()
                from app.workers.tasks import run_scan_job_unit as _continue_scan
                _continue_scan.delay(job.id)
                return {"checkpointed": True, "completed_phase_targets": len(completed_work)}
            if _hard_blocked:
                break
        _target_idx += 1

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

    # ─── Tier 3/4 post-processing: dedup, CVSS, narrative, diff vs previous ───
    try:
        all_findings = db.query(Finding).filter(Finding.scan_job_id == job.id).all()
        finding_dicts = [{
            "id": f.id, "title": f.title, "severity": f.severity,
            "domain": f.domain, "details": f.details or {},
            "recommendation": f.recommendation,
        } for f in all_findings]
        env_snap = state.get("environment_profile") or {}
        for f, fd in zip(all_findings, finding_dicts):
            _signal = ""
            te = (fd["details"] or {}).get("tool_evidence") or []
            for e in te:
                if e.get("nuclei_findings"): _signal = "nuclei_finding"; break
                if e.get("secrets_found"): _signal = "secret_exposed"; break
                if e.get("open_ports"): _signal = "ports_open"
                elif e.get("discovered_paths"): _signal = "sensitive_path"
            cvss = derive_cvss(f.severity, _signal, bool(env_snap.get("waf_present")))
            f.cvss = cvss
            (f.details or {})["cvss_calculated"] = cvss
        db.commit()
        # FP blocklist — downgrade findings matching past analyst FP markings
        try:
            blocklist = load_fp_blocklist(db, owner_id=job.owner_id)
            if blocklist:
                downgraded = 0
                for f, fd in zip(all_findings, finding_dicts):
                    if apply_fp_blocklist(fd, blocklist):
                        f.severity = "info"
                        d = f.details or {}
                        d["fp_downgraded"] = True
                        f.details = d
                        downgraded += 1
                if downgraded:
                    db.commit()
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                   message=f"fp_blocklist_applied downgraded={downgraded} finding(s) matching known FP signatures"))
                    db.commit()
        except Exception as _fpe:  # noqa: BLE001
            db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                           message=f"fp_blocklist_failed error={_fpe!s}"))
        deduped = dedup_findings_by_signature(finding_dicts)
        state["unique_findings"] = [{
            "title": d["title"], "severity": d["severity"],
            "instance_count": d.get("instance_count", 1),
            "instances": d.get("instances", []),
        } for d in deduped]
        # Attack-path chaining — correlate findings into kill chains
        chains = chain_findings(finding_dicts)
        state["attack_chains"] = chains
        if chains:
            db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                           message=(f"attack_chains_identified count={len(chains)} "
                                    f"top=\"{chains[0]['name']}\" severity={chains[0]['severity']}")))
        primary = targets[0] if targets else ""
        narrative = build_executive_narrative(
            job.id, primary, finding_dicts,
            env_profile=env_snap,
            origin=state.get("origin_discovery"),
        )
        state["executive_summary"] = narrative
        from app.models.models import ScanJob as _SJ
        prev_scan = (
            db.query(_SJ)
            .filter(_SJ.target_query == job.target_query, _SJ.id != job.id, _SJ.status == "completed")
            .order_by(_SJ.created_at.desc())
            .first()
        )
        if prev_scan:
            prev_findings = db.query(Finding).filter(Finding.scan_job_id == prev_scan.id).all()
            prev_dicts = [{"id": pf.id, "title": pf.title, "severity": pf.severity,
                           "domain": pf.domain, "details": pf.details or {}} for pf in prev_findings]
            diff = diff_against_previous(finding_dicts, prev_dicts)
            state["regression_diff"] = {
                "previous_scan_id": prev_scan.id,
                "previous_scan_date": prev_scan.created_at.isoformat() if prev_scan.created_at else None,
                "new_count": diff["new_count"],
                "fixed_count": diff["fixed_count"],
                "persistent_count": diff["persistent_count"],
                "new_titles": [f.get("title") for f in diff["new_findings"]][:10],
                "fixed_titles": [f.get("title") for f in diff["fixed_findings"]][:10],
            }
            db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                           message=(f"regression_diff vs scan #{prev_scan.id}: "
                                    f"new={diff['new_count']} fixed={diff['fixed_count']} "
                                    f"persistent={diff['persistent_count']}")))
        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                       message=(f"post_processing dedup_unique={len(deduped)} from {len(finding_dicts)} raw, "
                                f"headline=\"{narrative['headline']}\"")))
    except Exception as _ppe:  # noqa: BLE001
        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                       message=f"post_processing_failed error={_ppe!s}"))
    db.commit()

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
            paths = [str(p.get("url") or p.get("path") or p) if isinstance(p, dict) else str(p) for p in parsed[:100]]
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


def _build_reproduction(phase_id: str, target: str, tool_evidences: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a complete reproduction package for a finding.

    Every finding must be independently verifiable. This returns:
      - discovery_method: how the issue was found (tool + technique)
      - commands: exact CLI commands that produced the evidence (copy-paste ready)
      - payloads: any attack payloads used (SQLi/XSS/SSRF strings, fuzz inputs)
      - proof: raw tool output snippets that constitute the evidence
      - steps: numbered reproduction steps an analyst can follow
    """
    commands: list[dict[str, str]] = []
    payloads: list[str] = []
    proof: list[dict[str, str]] = []

    for ev in tool_evidences:
        tool = str(ev.get("tool") or "")
        cmd = str(ev.get("command") or "")
        if cmd and not any(c["command"] == cmd for c in commands):
            commands.append({"tool": tool, "command": cmd})
        # Raw output proof — first meaningful slice of stdout
        raw = ev.get("raw_output_preview") or ""
        summary = ev.get("finding_summary") or ""
        if raw and summary and not summary.lower().startswith(("no ", "nenhum", "sem ")):
            proof.append({"tool": tool, "output": str(raw)[:1200], "summary": summary})
        # Tool-specific payloads
        if tool == "nuclei":
            for nf in (ev.get("nuclei_findings") or [])[:5]:
                tid = nf.get("template") or ""
                url = nf.get("url") or ""
                if tid:
                    payloads.append(f"nuclei -id {tid} -u {url or target} -v")
        if tool in {"sqlmap"}:
            for inj in (ev.get("injection_evidence") or [])[:3]:
                payloads.append(str(inj))
        if tool in {"ffuf", "gobuster", "feroxbuster", "dirsearch"}:
            for p in (ev.get("discovered_paths") or [])[:8]:
                payloads.append(f"curl -sk -i {p}")
        if tool in {"dalfox"}:
            for x in (ev.get("xss_payloads") or [])[:3]:
                payloads.append(str(x))
        if tool in {"arjun", "paramspider"}:
            for prm in (ev.get("discovered_parameters") or [])[:8]:
                payloads.append(f"# parameter to fuzz: {prm}")

    # Discovery method narrative
    tools_used = sorted({str(ev.get("tool") or "") for ev in tool_evidences if ev.get("tool")})
    discovery_method = (
        f"Fase {phase_id}: descoberto via {', '.join(tools_used)}"
        if tools_used else f"Fase {phase_id}: nenhuma ferramenta produziu evidência"
    )

    # Numbered reproduction steps
    steps: list[str] = []
    if commands:
        steps.append(f"1. Garanta que as ferramentas estejam instaladas: {', '.join(tools_used)}")
        for idx, c in enumerate(commands[:6], start=2):
            steps.append(f"{idx}. Execute: {c['command']}")
        if payloads:
            steps.append(f"{len(steps) + 1}. Valide manualmente com os payloads listados em 'payloads'")
        steps.append(f"{len(steps) + 1}. Compare a saída obtida com a evidência em 'proof'")

    return {
        "discovery_method": discovery_method,
        "commands": commands,
        "payloads": payloads[:20],
        "proof": proof[:8],
        "steps": steps,
        "target": target,
        "verifiable": bool(commands and proof),
    }


def _run_target_phases_subset(db, job: ScanJob, target: str) -> dict[str, Any]:
    """Run P02-P22 for a single target. Used by the parallel fan-out task.

    Each phase result is persisted via the same idempotent _persist_offensive_findings
    flow used by the main scan, so concurrent subtasks writing different (phase,
    target) pairs do not collide.
    """
    state = dict(job.state_data or {})
    execution_mode = str(state.get("execution_mode") or "controlled_pentest")
    allowed_phases = phases_for_scan_level(state.get("scan_level"))
    scope = _scope_from_job(job, target, execution_mode)
    offensive_state = dict(state.get("offensive_state") or create_offensive_state(target, campaign_id=f"scan-{job.id}"))
    offensive_state["target"] = target

    # Auth for downstream tools — shared across all subtasks
    global _CURRENT_AUTH_HEADERS
    _CURRENT_AUTH_HEADERS = auth_headers_from_state(state)

    mcp_available = _mcp_available() if settings.mcp_execute_tools_via_mcp else False
    runtime = OffensiveSkillRuntime(executor=MCPToolExecutor(call_tool=_call_mcp_execution, available=mcp_available))

    completed_work: set[str] = set(state.get("completed_work") or [])
    host_ip_map: dict[str, str] = dict(state.get("host_ip_map") or {})
    phase_ledgers: list[dict[str, Any]] = list(state.get("phase_ledger_v2") or [])
    processed = 0
    skipped = 0
    for phase_id in PHASE_ORDER:
        if phase_id == "P01":
            continue
        if allowed_phases is not None and phase_id not in allowed_phases:
            continue
        wk = f"{phase_id}:{target}"
        if wk in completed_work:
            skipped += 1
            continue
        # IP dedup
        if phase_id in NETWORK_PHASES:
            _ip = host_ip_map.get(target)
            if _ip and f"{phase_id}:ip:{_ip}" in completed_work:
                completed_work.add(wk)
                skipped += 1
                continue
        try:
            result = runtime.run_phase(phase_id, target, scope, execution_mode, offensive_state)
            offensive_state = result["offensive_state"]
            ledger = result["phase_ledger"]
            ledger["target"] = target
            ledger["mcp_results"] = result.get("mcp_results") or []
            ledger["parallel_subtask"] = True
            phase_ledgers.append(ledger)
            completed_work.add(wk)
            if phase_id in NETWORK_PHASES:
                ip = host_ip_map.get(target)
                if ip:
                    completed_work.add(f"{phase_id}:ip:{ip}")
            # Persist incremental state
            cur = dict(job.state_data or {})
            cur["completed_work"] = sorted(set((cur.get("completed_work") or [])) | completed_work)
            cur["phase_ledger_v2"] = (cur.get("phase_ledger_v2") or []) + [ledger]
            job.state_data = cur
            db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                           message=f"phase_result phase_id={phase_id} status={ledger.get('status')} target={target} (parallel)"))
            db.commit()
            try:
                _persist_offensive_findings(db, job, phase_ledgers, [target])
                db.commit()
            except Exception:  # noqa: BLE001
                db.rollback()
            processed += 1
        except Exception as exc:  # noqa: BLE001
            db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                           message=f"parallel_phase_failed phase={phase_id} target={target} error={exc!s}"))
            db.commit()
    return {"target": target, "processed": processed, "skipped": skipped}


def _persist_origin_finding(db, job: ScanJob, target: str, origin: dict[str, Any]) -> None:
    """Persist a Finding for WAF origin discovery — the real server behind the edge.

    This is one of the highest-value RedTeam findings: if the origin is
    reachable directly, every WAF protection is bypassable.
    """
    candidates = origin.get("candidate_origins") or []
    if not candidates:
        return
    # Idempotent — one origin-discovery finding per (scan, target)
    existing = (
        db.query(Finding)
        .filter(Finding.scan_job_id == job.id, Finding.domain == str(target)[:255])
        .all()
    )
    for f in existing:
        if (f.details or {}).get("finding_kind") == "waf_origin_discovery":
            return

    top = candidates[0]
    high_conf = [c for c in candidates if c.get("confidence") == "high"]
    severity = "high" if high_conf else "medium"
    confidence = 80 if high_conf else 55

    title = (f"[WAF-BYPASS] Origem potencial exposta atrás do WAF — "
             f"{len(candidates)} IP(s) candidato(s), top {top['ip']}")
    recommendation = (
        "Confirme o IP de origem com requisição Host-header direta; se a origem "
        "responder a aplicação real, TODA proteção do WAF é contornável. "
        "Mitigação: bloqueie no firewall da origem todo tráfego que não venha "
        "dos ranges do WAF, e rotacione o IP de origem após exposição."
    )
    repro_commands = [{"tool": "curl", "command": c["verify"]} for c in candidates[:6]]
    steps = [
        "1. Para cada IP candidato, envie uma requisição com o Host header do alvo",
        "2. Compare o corpo da resposta com a resposta servida pelo WAF",
        "3. Resposta idêntica à aplicação real = origem confirmada (WAF bypassável)",
        "4. Documente o IP de origem e o vetor de acesso direto",
    ]
    details: dict[str, Any] = {
        "finding_kind": "waf_origin_discovery",
        "phase_id": "P01",
        "phase_name": "WAF Origin Discovery",
        "target": target,
        "apex_behind_waf": origin.get("apex_behind_waf"),
        "waf_edge_ips": origin.get("waf_edge_ips") or [],
        "candidate_origins": candidates,
        "summary": origin.get("summary"),
        "reproduction": {
            "discovery_method": "Análise de divergência de IP entre subdomínios + mineração de registros DNS (SPF/MX)",
            "commands": repro_commands,
            "payloads": [c["verify"] for c in candidates[:10]],
            "proof": [{"tool": "dns", "summary": f"{c['ip']} via {c['source']} (hosts: {', '.join(c['hosts'][:3]) or 'DNS record'})", "output": c["verify"]} for c in candidates[:6]],
            "steps": steps,
            "verifiable": True,
        },
        "mitre_attack": [{"id": "T1590.005", "name": "Gather Victim Network Info: IP Addresses"},
                         {"id": "T1133", "name": "External Remote Services"}],
        "owasp_top10": ["A05:2021 Security Misconfiguration"],
        "kill_chain_stage": "Reconnaissance",
    }
    finding = Finding(
        scan_job_id=job.id,
        title=title[:255],
        severity=severity,
        domain=str(target)[:255],
        tool="waf_origin_discovery",
        recommendation=recommendation,
        confidence_score=confidence,
        risk_score=max(1, confidence // 10),
        details=details,
    )
    db.add(finding)
    db.commit()


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

        # Extract per-tool evidence from MCP results stored in the ledger.
        # Prefer the ledger's own mcp_results (correct for multi-target
        # propagation where many ledgers share the same phase_id).
        mcp_results = ledger.get("mcp_results") or phase_mcp_map.get(phase_id) or []
        tool_evidences: list[dict[str, Any]] = []
        for mcp_res in mcp_results:
            if not isinstance(mcp_res, dict):
                continue
            tool_name = str(mcp_res.get("tool_name") or "")
            if mcp_res.get("status") in {"success", "done"} and tool_name:
                ev = _extract_evidence(phase_id, tool_name, mcp_res)
                tool_evidences.append(ev)

        # Severity + confidence are derived from ACTUAL evidence, not the phase.
        # A phase that ran with no findings → 'info', never 'high'.
        severity, confidence = _assess_evidence_severity(phase_id, status, tool_evidences, PHASE_SEVERITY)

        # State-derived context for MITRE/OWASP enrichment + tech_stack snapshot
        state_snap = dict(job.state_data or {})
        tech_snap = state_snap.get("tech_stack") or {}
        env_snap = state_snap.get("environment_profile") or {}

        # WAF deception adjustment — discount findings the WAF likely faked.
        waf_caveat = None
        if env_snap.get("waf_present"):
            _, signal = _has_real_evidence(tool_evidences)
            severity, confidence, waf_caveat = apply_waf_confidence_adjustment(
                env_snap, severity, confidence, phase_id, signal)

        title = _build_redteam_title(phase_id, phase_name, status, tool_evidences)
        recommendation = _generate_recommendation(phase_id, tool_evidences)
        if waf_caveat:
            recommendation = f"[WAF] {waf_caveat} | {recommendation}"

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
            # Complete reproduction package: discovery method, commands,
            # payloads, raw proof and numbered steps so the finding is
            # independently verifiable by an analyst.
            "reproduction": _build_reproduction(phase_id, str(target), tool_evidences),
            # Tech stack snapshot at time of finding
            "tech_stack": tech_snap.get("detected") or [],
            "cms_detected": tech_snap.get("cms") or [],
            "waf_detected": tech_snap.get("waf") or [],
            # Learned environment profile — WAF behaviour, deception flags,
            # and how to interpret results for this target.
            "environment_profile": {
                "waf_present": env_snap.get("waf_present", False),
                "waf_vendors": env_snap.get("waf_vendors") or [],
                "observed_behaviors": env_snap.get("observed_behaviors") or [],
                "interpretation_notes": env_snap.get("interpretation_notes") or [],
                "finding_confidence_penalty": env_snap.get("finding_confidence_penalty", 0),
            },
            "waf_caveat": waf_caveat,
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
