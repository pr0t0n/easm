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

    # --- shodan: service banners and exposed services ---
    elif tool_lower in {"shodan-cli", "shodan"}:
        evidence["shodan_raw"] = stdout[:2000]
        # Extract interesting lines: IP, ports, OS, org, vulns
        interesting = [l.strip() for l in stdout.splitlines()
                       if any(k in l.lower() for k in ["ip:", "port:", "os:", "org:", "cpe:", "vuln", "banner"])]
        evidence["service_intel"] = interesting[:30]
        evidence["finding_summary"] = (
            f"Shodan OSINT: " + "; ".join(interesting[:5])
            if interesting else "Shodan: no enrichment data (API key not configured)"
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


def _build_redteam_title(phase_id: str, phase_name: str, status: str, evidence_list: list[dict[str, Any]]) -> str:
    """Build a descriptive finding title that reflects what was actually found."""
    summaries = [e.get("finding_summary", "") for e in evidence_list if e.get("finding_summary")]
    if not summaries:
        return f"{phase_name} — {'Finding' if status == 'completed' else 'Partial Evidence'} [{phase_id}]"
    # Use the first non-empty summary as the title suffix
    primary = summaries[0][:120]
    return f"[{phase_id}] {phase_name}: {primary}"


def _persist_offensive_findings(db, job: ScanJob, phase_ledgers: list[dict[str, Any]], targets: list[str]) -> None:
    """Convert phase ledger + MCP tool output into rich Finding rows with real evidence."""
    from app.models.models import Asset, Vulnerability

    seen: set[tuple[str, str]] = set()
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

        severity = PHASE_SEVERITY.get(phase_id, "info")
        confidence = 75 if status == "completed" else (50 if status == "partial" else 30)

        # Extract per-tool evidence from MCP results stored in the ledger
        mcp_results = phase_mcp_map.get(phase_id) or ledger.get("mcp_results") or []
        tool_evidences: list[dict[str, Any]] = []
        for mcp_res in mcp_results:
            tool_name = str(mcp_res.get("tool_name") or "")
            if mcp_res.get("status") in {"success", "done"} and tool_name:
                ev = _extract_evidence(phase_id, tool_name, mcp_res)
                tool_evidences.append(ev)

        title = _build_redteam_title(phase_id, phase_name, status, tool_evidences)

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
        }

        finding = Finding(
            scan_job_id=job.id,
            title=title[:255],
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
