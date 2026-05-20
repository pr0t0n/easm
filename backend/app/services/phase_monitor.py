from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import re
from typing import Any

from sqlalchemy.orm import Session

from app.graph.mission import PENTEST_PHASES, MISSION_ITEMS, PHASE_CONTRACTS
from app.models.models import ScanJob, ExecutedToolRun, Finding
from app.services.capability_runtime import CAPABILITY_CONTRACT, infer_capability_ledger


CAPABILITY_NODES = [
    "strategic_planning",
    "asset_discovery",
    "threat_intel",
    "adversarial_hypothesis",
    "risk_assessment",
    "evidence_adjudication",
    "governance",
    "executive_analyst",
]

CAPABILITY_ALIASES: dict[str, set[str]] = {
    "strategic_planning": {"strategic_planning", "supervisor", "skill_planner"},
    "asset_discovery": {"asset_discovery"},
    "threat_intel": {"threat_intel"},
    "adversarial_hypothesis": {"adversarial_hypothesis", "skill_selector", "skill_planner", "tool_selector"},
    "risk_assessment": {"risk_assessment"},
    "evidence_adjudication": {"evidence_adjudication", "evidence_gate"},
    "governance": {"governance"},
    "executive_analyst": {"executive_analyst"},
}


def _node_for_phase(phase_id: str) -> str:
    for p in PENTEST_PHASES:
        if p.get("id") == phase_id:
            return str(p.get("node") or "")
    return ""


def _expected_tools_by_phase() -> dict[str, list[str]]:
    return {p["id"]: list(p.get("tools") or []) for p in PENTEST_PHASES}


def _expected_tools_by_node() -> dict[str, set[str]]:
    by_node: dict[str, set[str]] = defaultdict(set)
    for p in PENTEST_PHASES:
        for t in (p.get("tools") or []):
            by_node[str(p.get("node") or "")].add(t)
    return by_node


def _normalize_tool(name: str | None) -> str:
    return str(name or "").strip().lower()


def _extract_command_from_error(error: str | None) -> str | None:
    text = str(error or "")
    match = re.search(r"(?:^|\n)command=([^\n]+)", text)
    if match:
        return match.group(1).strip()
    return None


def _phase_ledger_map(raw: Any) -> dict[str, dict[str, Any]]:
    if isinstance(raw, dict):
        return {str(k): dict(v or {}) for k, v in raw.items()}
    if isinstance(raw, list):
        result: dict[str, dict[str, Any]] = {}
        for item in raw:
            entry = dict(item or {})
            phase_id = str(entry.get("phase_id") or entry.get("id") or "")
            if phase_id:
                result[phase_id] = entry
        return result
    return {}


def build_phase_monitor(db: Session, scan: ScanJob) -> dict[str, Any]:
    """Cross-references phase_ledger, state_data, executed_tool_runs, findings, scan_logs.

    Produces the full pentest journey report:
    - phases_executed / completed / partial / skipped / pending
    - tools_attempted / succeeded / failed per phase
    - evidence collected per phase
    - gaps (required tools not attempted)
    - hypotheses validated vs not tested
    - MCP architectural failures
    - legacy capability/node coverage (backward compat)
    """
    state = dict(scan.state_data or {})
    completed_caps: list[str] = list(state.get("completed_capabilities") or [])
    node_history: list[str] = list(state.get("node_history") or [])
    autonomy_obs: list[dict] = list(state.get("autonomy_observations") or [])
    metrics = dict(state.get("mission_metrics") or {})
    objective_met = bool(state.get("objective_met"))
    termination_reason = str(state.get("termination_reason") or "")
    pentest_phase_index = int(state.get("pentest_phase_index") or 0)
    current_pentest_phase_id = str(state.get("current_pentest_phase_id") or "")
    capability_ledger = infer_capability_ledger(state)
    phase_ledger = _phase_ledger_map(state.get("phase_ledger") or state.get("phase_ledger_v2"))

    obs_by_node: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for obs in autonomy_obs:
        node = str(dict(obs or {}).get("node") or dict(obs or {}).get("capability") or "")
        if node:
            obs_by_node[node].append(dict(obs or {}))

    runs = (
        db.query(ExecutedToolRun)
        .filter(ExecutedToolRun.scan_job_id == scan.id)
        .order_by(ExecutedToolRun.created_at.asc())
        .all()
    )
    findings = (
        db.query(Finding)
        .filter(Finding.scan_job_id == scan.id)
        .all()
    )

    # ── Tool stats from ExecutedToolRun (ground truth) ────────────────────────
    tool_stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "tool": "",
            "attempts": 0,
            "success": 0,
            "failed": 0,
            "skipped": 0,
            "targets": set(),
            "last_status": None,
            "last_error": None,
            "last_command": None,
            "total_seconds": 0.0,
        }
    )
    run_status_by_tool_target: dict[tuple[str, str], str] = {}
    for r in runs:
        key = _normalize_tool(r.tool_name)
        target_key = str(r.target or "").strip().lower()
        stats = tool_stats[key]
        stats["tool"] = key
        stats["attempts"] += 1
        stats["targets"].add(str(r.target or ""))
        if r.status == "success":
            stats["success"] += 1
        elif r.status == "skipped":
            stats["skipped"] += 1
        else:
            stats["failed"] += 1
        stats["last_status"] = r.status
        run_status_by_tool_target[(key, target_key)] = str(r.status or "unknown")
        if r.error_message:
            stats["last_error"] = (r.error_message or "")[:300]
            command = _extract_command_from_error(r.error_message)
            if command:
                stats["last_command"] = command
        if r.execution_time_seconds:
            stats["total_seconds"] += float(r.execution_time_seconds or 0.0)

    # ── Findings by tool ──────────────────────────────────────────────────────
    findings_by_tool: dict[str, int] = defaultdict(int)
    severity_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        t = _normalize_tool(f.tool)
        if t:
            findings_by_tool[t] += 1
        severity_counts[(f.severity or "info").lower()] += 1

    # ── Kali tool availability ────────────────────────────────────────────────
    try:
        from app.services.tool_catalog import is_tool_installed
    except Exception:
        def is_tool_installed(_t: str) -> bool:  # type: ignore
            return True

    # Phases (22) — status derived from node completion + tools attempted
    expected_tools = _expected_tools_by_phase()
    phases: list[dict[str, Any]] = []
    phase_contract_reports: list[dict[str, Any]] = []
    phase_used_tools_set: set[str] = set()
    for phase in PENTEST_PHASES:
        pid = phase["id"]
        node = phase["node"]
        phase_idx = int(str(pid).replace("P", "") or 0)
        ledger_entry = dict(phase_ledger.get(pid) or {})
        ledger_tools_attempted = [_normalize_tool(t) for t in ledger_entry.get("tools_attempted") or []]
        ledger_tools_succeeded = [_normalize_tool(t) for t in ledger_entry.get("tools_succeeded") or []]
        phase_used_tools_set.update(t for t in ledger_tools_attempted if t)
        node_done = node in completed_caps
        node_visited = node in node_history
        effective_node_visited = node_visited or bool(ledger_entry) or bool(capability_ledger.get(node, {}).get("visited"))
        phase_started = bool(ledger_entry) or phase_idx <= pentest_phase_index or pid == current_pentest_phase_id
        tools_expected = [_normalize_tool(t) for t in phase.get("tools", [])]
        tools_installed = [t for t in tools_expected if is_tool_installed(t)]
        tools_uninstalled = [t for t in tools_expected if not is_tool_installed(t)]
        tools_used = sorted({
            t for t in tools_expected
            if tool_stats.get(t, {}).get("attempts", 0) > 0 or t in ledger_tools_attempted
        })
        tools_success = sorted({
            t for t in tools_used
            if tool_stats.get(t, {}).get("success", 0) > 0 or t in ledger_tools_succeeded
        })
        tools_failed = [
            t for t in tools_used
            if tool_stats.get(t, {}).get("failed", 0) > 0
            and tool_stats.get(t, {}).get("success", 0) == 0
            and tool_stats.get(t, {}).get("skipped", 0) == 0
        ]
        tools_skipped = [
            t for t in tools_used
            if tool_stats.get(t, {}).get("skipped", 0) > 0
            and tool_stats.get(t, {}).get("success", 0) == 0
            and tool_stats.get(t, {}).get("failed", 0) == 0
        ]
        # Distinguish "missing because unavailable in Kali" vs "ready but skipped".
        tools_missing_uninstalled = [t for t in tools_uninstalled if tool_stats.get(t, {}).get("attempts", 0) == 0]
        tools_missing_unused = [t for t in tools_installed if tool_stats.get(t, {}).get("attempts", 0) == 0]
        tools_missing = tools_missing_uninstalled + tools_missing_unused
        tools_failed_list = sorted(set(tools_failed))
        ledger_status = str(ledger_entry.get("status") or "")

        if ledger_status:
            status_label = ledger_status
        elif not effective_node_visited:
            status_label = "skipped"
        elif tools_missing_unused and tools_success:
            status_label = "partial_coverage"
        elif tools_success and not tools_missing_unused:
            status_label = "executed"
        elif tools_skipped and not tools_failed:
            status_label = "node_visited_no_tools"
        elif tools_used:
            status_label = "attempted_failed"
        else:
            status_label = "node_visited_no_tools"

        phase_row = {
            "id": pid,
            "title": phase["title"],
            "node": node,
            "status": status_label,
            "node_visited": effective_node_visited,
            "node_completed": node_done,
            "phase_started": phase_started,
            "phase_index": phase_idx,
            "tools_expected": tools_expected,
            "tools_installed": tools_installed,
            "tools_uninstalled": tools_uninstalled,
            "tools_available": tools_installed,
            "tools_unavailable": tools_uninstalled,
            "tools_used": tools_used,
            "tools_success": tools_success,
            "tools_failed": tools_failed_list,
            "tools_skipped": tools_skipped,
            "tools_missing": tools_missing,
            "tools_missing_uninstalled": tools_missing_uninstalled,
            "tools_missing_unused": tools_missing_unused,
            # Ledger enrichment
            "ledger_status": ledger_status,
            "ledger_exit_criteria_met": bool(ledger_entry.get("exit_criteria_met")),
            "ledger_can_advance": bool(ledger_entry.get("can_advance")),
            "ledger_mcp_status": str(ledger_entry.get("mcp_status") or "not_attempted"),
            "ledger_skip_reason": ledger_entry.get("skip_reason"),
            "ledger_validation_result": dict(ledger_entry.get("validation_result") or {}),
        }
        phases.append(phase_row)

        contract = dict(PHASE_CONTRACTS.get(pid) or {})
        required_tools = [_normalize_tool(t) for t in contract.get("required_tools") or []]
        required_tools_missing = [t for t in required_tools if t and t not in tools_used]
        phase_contract_reports.append({
            **phase_row,
            "phase_id": pid,
            "name": contract.get("name") or phase["title"],
            "can_advance": bool(ledger_entry.get("can_advance")) or status_label in {"completed", "executed", "skipped"},
            "required_tools": required_tools,
            "required_tools_missing": required_tools_missing,
            "validation_result": dict(ledger_entry.get("validation_result") or {}),
        })

    hypothesis_report = list(state.get("pentest_hypotheses") or state.get("hypotheses") or [])
    journey_summary = {
        "total_phases": len(PENTEST_PHASES),
        "executed": sum(1 for p in phase_contract_reports if p["status"] in {"completed", "executed"}),
        "partial": sum(1 for p in phase_contract_reports if "partial" in str(p["status"])),
        "skipped": sum(1 for p in phase_contract_reports if str(p["status"]).startswith("skipped")),
        "pending": sum(1 for p in phase_contract_reports if p["status"] in {"pending", "node_visited_no_tools"}),
        "blocked": sum(1 for p in phase_contract_reports if p["status"] == "blocked"),
        "mcp_failures_total": sum(
            1 for p in phase_contract_reports
            if str(p.get("ledger_mcp_status") or "").lower() in {"failed", "timeout", "unreachable"}
        ),
    }

    # ── Capability summary ────────────────────────────────────────────────────
    capabilities: list[dict[str, Any]] = []
    expected_node_tools = _expected_tools_by_node()
    for cap in CAPABILITY_NODES:
        cap_done = cap in completed_caps
        cap_visited = cap in node_history
        # Tools that ran during this node based on phases of node
        node_expected = list(expected_node_tools.get(cap, []))
        node_attempted = [t for t in node_expected if tool_stats.get(t, {}).get("attempts", 0) > 0]
        node_success = [t for t in node_expected if tool_stats.get(t, {}).get("success", 0) > 0]
        capabilities.append({
            "id": cap,
            "label": CAPABILITY_CONTRACT.get(cap, {}).get("label") or cap.replace("_", " ").title(),
            "definition": CAPABILITY_CONTRACT.get(cap, {}).get("definition") or "",
            "completed": cap_done,
            "visited": cap_visited,
            "runtime_evidence": dict(capability_ledger.get(cap) or {}),
            "required_evidence": list(CAPABILITY_CONTRACT.get(cap, {}).get("required_evidence") or []),
            "tools_expected": node_expected,
            "tools_attempted": node_attempted,
            "tools_success": node_success,
            "observations_count": len(obs_by_node.get(cap, [])),
        })

    # ── Tool inventory ────────────────────────────────────────────────────────
    tool_inventory = []
    for k, v in sorted(tool_stats.items()):
        tool_inventory.append({
            "tool": v["tool"] or k,
            "attempts": v["attempts"],
            "success": v["success"],
            "failed": v["failed"],
            "skipped": v["skipped"],
            "targets_count": len(v["targets"]),
            "total_seconds": round(v["total_seconds"], 2),
            "last_status": v["last_status"],
            "last_error": v["last_error"],
            "last_command": v["last_command"],
            "findings_generated": findings_by_tool.get(k, 0),
        })

    # ── Critical validation (issues list) ────────────────────────────────────
    issues: list[str] = []
    validation_summary: dict[str, Any] = {"critical": [], "warning": [], "info": []}

    # 1. Phase blocking: any phase that failed exit criteria
    blocked_phases = [
        r for r in phase_contract_reports
        if r["status"] not in ("completed", "skipped", "pending")
        and not r["can_advance"]
    ]
    for r in blocked_phases:
        reason = str((r.get("validation_result") or {}).get("reason") or "unknown")
        issue = f"PHASE BLOCKED [{r['phase_id']} {r['name']}]: {reason}"
        issues.append(issue)
        validation_summary["critical"].append(issue)

    # 2. MCP architectural failures
    if journey_summary.get("mcp_failures_total", 0) > 0:
        issue = (
            f"MCP ARCHITECTURAL FAILURES: {journey_summary['mcp_failures_total']} total. "
            "MCP was configured but unreachable for some tool executions. "
            "Affected phases may be partial. Fix MCP connectivity."
        )
        issues.append(issue)
        validation_summary["critical"].append(issue)

    # 3. Required tools missing (attempted zero times)
    for r in phase_contract_reports:
        if r.get("required_tools_missing") and r["status"] not in ("skipped", "pending"):
            issue = (
                f"REQUIRED TOOLS NOT ATTEMPTED [{r['phase_id']}]: "
                f"{', '.join(r['required_tools_missing'])}. "
                "These tools must be executed before phase can complete."
            )
            issues.append(issue)
            validation_summary["critical"].append(issue)

    # 4. Installed Kali tools not executed (coverage gap)
    expected_all_tools = sorted({t for tools in expected_tools.values() for t in tools})
    installed_expected = sorted({t for t in expected_all_tools if is_tool_installed(t)})
    uninstalled_expected = sorted({t for t in expected_all_tools if not is_tool_installed(t)})
    used_tools_set = {k for k, v in tool_stats.items() if v["attempts"] > 0} | phase_used_tools_set
    installed_unused = [t for t in installed_expected if t not in used_tools_set]
    has_tool_execution_evidence = bool(used_tools_set or tool_stats or phase_used_tools_set)
    scan_status = str(scan.status or "").strip().lower()
    scan_is_terminal = scan_status in {"completed", "failed", "error", "cancelled", "canceled"}
    validation_is_active = has_tool_execution_evidence
    if scan_is_terminal and not has_tool_execution_evidence:
        issue = (
            "NO KALI TOOL EXECUTION RECORDED: scan reached a terminal state without tool attempts. "
            "This indicates orchestration/worker dispatch did not start; tool coverage lists are suppressed until execution evidence exists."
        )
        issues.append(issue)
        validation_summary["critical"].append(issue)

    if installed_unused and validation_is_active:
        issue = (
            f"KALI TOOLS NOT EXECUTED ({len(installed_unused)}): "
            f"{', '.join(installed_unused[:8])}{'…' if len(installed_unused) > 8 else ''}. "
            "These tools are available in Kali runner but were not attempted."
        )
        issues.append(issue)
        validation_summary["critical"].append(issue)
    elif installed_unused:
        issue = (
            f"KALI TOOL EXECUTION PENDING: {len(installed_unused)} Kali-ready tool(s) aguardam execução. "
            "Coverage will be evaluated after the agent records the first tool attempt."
        )
        validation_summary["info"].append(issue)

    if uninstalled_expected and validation_is_active:
        issue = (
            f"KALI TOOLS NOT AVAILABLE ({len(uninstalled_expected)}): "
            f"{', '.join(uninstalled_expected[:8])}{'…' if len(uninstalled_expected) > 8 else ''}. "
            "Add to Kali runner profiles or remove from expected catalog."
        )
        issues.append(issue)
        validation_summary["warning"].append(issue)
    elif uninstalled_expected:
        issue = (
            f"KALI TOOL AVAILABILITY PENDING: {len(uninstalled_expected)} expected tool(s) have no ready Kali profile yet. "
            "This is informational until the scan starts executing tools."
        )
        validation_summary["info"].append(issue)

    coverage_ratio_installed = (
        len(used_tools_set & set(installed_expected)) / max(1, len(installed_expected))
    )
    coverage_ratio = coverage_ratio_installed
    if not validation_is_active:
        validation_summary["info"].append(
            f"Coverage pending: 0/{len(installed_expected)} Kali-ready tool(s) attempted so far."
        )
    elif coverage_ratio_installed < 0.7:
        issue = (
            f"Coverage of Kali-ready tools low: {coverage_ratio_installed:.0%} "
            f"({len(used_tools_set & set(installed_expected))}/{len(installed_expected)}). "
            "Target ≥70% of Kali-ready tools per scan."
        )
        issues.append(issue)
        validation_summary["critical"].append(issue)

    # 2. Capability completion: all 8 nodes should execute
    capability_gaps: list[dict[str, Any]] = []
    if validation_is_active:
        for cap in CAPABILITY_NODES:
            ledger = dict(capability_ledger.get(cap) or {})
            if cap in completed_caps or bool(ledger.get("completed")):
                continue
            gap = {
                "id": cap,
                "label": CAPABILITY_CONTRACT.get(cap, {}).get("label") or cap,
                "required_evidence": list(CAPABILITY_CONTRACT.get(cap, {}).get("required_evidence") or []),
            }
            capability_gaps.append(gap)
        if capability_gaps:
            issue = (
                "INCOMPLETE CAPABILITIES: "
                f"{', '.join(g['id'] for g in capability_gaps)}. "
                "Graph traversal did not produce the required capability evidence: "
                f"{capability_gaps[0]['id']} requires {', '.join(capability_gaps[0]['required_evidence'])}."
            )
            issues.append(issue)
            validation_summary["critical"].append(issue)

    # 3. Tool failures: tools that failed all attempts must retry
    failed_only = [k for k, v in tool_stats.items() if v["attempts"] > 0 and v["success"] == 0 and v["skipped"] == 0]
    command_fix_required = [
        {
            "tool": k,
            "attempts": tool_stats[k]["attempts"],
            "last_status": tool_stats[k]["last_status"],
            "last_command": tool_stats[k]["last_command"],
            "last_error": tool_stats[k]["last_error"],
        }
        for k in sorted(failed_only)
        if is_tool_installed(k) and tool_stats[k].get("last_command")
    ]
    for item in command_fix_required:
        issue = (
            f"COMMAND FIX REQUIRED: {item['tool']} command=`{item['last_command']}`. "
            "A ferramenta existe no Kali; ajuste argumentos/sintaxe antes de marcar como falha de ferramenta."
        )
        issues.append(issue)
        validation_summary["critical"].append(issue)

    failed_without_command_fix = [k for k in failed_only if k not in {item["tool"] for item in command_fix_required}]
    if failed_without_command_fix:
        issue = f"TOOL FAILURES (all attempts): {', '.join(sorted(failed_without_command_fix)[:5])}. "
        issue += "These must be retried or skipped with explanation."
        issues.append(issue)
        validation_summary["critical"].append(issue)

    # 4. Node history validation: should visit asset_discovery, risk_assessment, evidence_adjudication
    critical_nodes = ["asset_discovery", "risk_assessment", "evidence_adjudication"]
    missing_critical = [n for n in critical_nodes if n not in node_history and not capability_ledger.get(n, {}).get("visited")]
    if missing_critical and validation_is_active:
        issue = f"CRITICAL NODES NOT VISITED: {', '.join(missing_critical)}. "
        issue += "Graph did not traverse essential analysis nodes."
        issues.append(issue)
        validation_summary["critical"].append(issue)

    # 5. Findings validation: high-severity findings should have strong evidence
    high_severity = [f for f in findings if (f.severity or "").lower() in {"critical", "high"}]
    weak_evidence = [
        f for f in high_severity
        if not str(dict(f.details or {}).get("validation_status", "")).lower().startswith("verified")
    ]
    if weak_evidence and len(high_severity) > 0:
        ratio = len(weak_evidence) / len(high_severity)
        if ratio > 0.5:
            issue = (
                f"WEAK EVIDENCE for {len(weak_evidence)}/{len(high_severity)} high-severity findings. "
                "Evidence adjudication may be incomplete."
            )
            validation_summary["warning"].append(issue)
            issues.append(issue)

    try:
        from app.services.tool_catalog import installation_report as _install_report
        installation = _install_report()
    except Exception:
        installation = {"total": 0, "installed": [], "missing": [], "coverage_ratio": 0}

    try:
        from app.graph.kill_chain import render_kill_chain_summary
        kill_chain = render_kill_chain_summary(state)
    except Exception:
        kill_chain = {"phases": [], "total": 0}

    return {
        # ── Scan metadata ──────────────────────────────────────────────────
        "scan_id": scan.id,
        "status": scan.status,
        "current_step": scan.current_step,
        "mission_progress": scan.mission_progress,
        "objective_met": objective_met,
        "termination_reason": termination_reason,
        # ── Pentest phase execution state ──────────────────────────────────
        "pentest_phase_index": pentest_phase_index,
        "current_pentest_phase_id": current_pentest_phase_id,
        # ── PRIMARY REPORT: phased pentest journey ─────────────────────────
        "pentest_journey": {
            "summary": journey_summary,
            "phases": phase_contract_reports,
            "hypotheses": hypothesis_report,
        },
        # ── Metrics ───────────────────────────────────────────────────────
        "metrics": {
            "tools_attempted": int(metrics.get("tools_attempted", 0) or 0),
            "tools_success": int(metrics.get("tools_success", 0) or 0),
            "steps_done": int(metrics.get("steps_done", 0) or 0),
            "steps_success": int(metrics.get("steps_success", 0) or 0),
            "loop_iteration": int(state.get("loop_iteration", 0) or 0),
            "max_iterations": int(state.get("max_iterations", 0) or 0),
            "findings_total": len(findings),
            "tool_runs_total": len(runs),
            "tools_installed_used_ratio": round(coverage_ratio_installed, 3),
            "tools_installed_total": len(installed_expected),
            "tools_uninstalled_total": len(uninstalled_expected),
        },
        "severity_counts": dict(severity_counts),
        # ── Capability/node coverage (legacy backward compat) ──────────────
        "completed_capabilities": completed_caps,
        "capability_ledger": capability_ledger,
        "node_history": node_history,
        "missions": MISSION_ITEMS,
        "capabilities": capabilities,
        "phases": phases,
        "tool_inventory": tool_inventory,
        "command_fix_required": command_fix_required,
        "capability_gaps": capability_gaps,
        "issues": issues,
        "validation_summary": validation_summary,
        "installation_report": installation,
        "kill_chain": kill_chain,
        "recon_graph": dict(state.get("recon_graph") or {}),
        "recon_skill_recommendations": list(state.get("recon_skill_recommendations") or (state.get("recon_graph") or {}).get("skill_recommendations") or []),
        "recon_reanalyze_queue": list(state.get("recon_reanalyze_queue") or (state.get("recon_graph") or {}).get("reanalyze_queue") or []),
        "recon_coverage": dict(state.get("recon_coverage") or (state.get("recon_graph") or {}).get("coverage") or {}),
        "recon_coverage_gaps": list(state.get("recon_coverage_gaps") or (state.get("recon_graph") or {}).get("coverage_gaps") or []),
    }
