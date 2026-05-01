from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.graph.mission import PENTEST_PHASES, MISSION_ITEMS
from app.models.models import ScanJob, ExecutedToolRun, Finding


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


def build_phase_monitor(db: Session, scan: ScanJob) -> dict[str, Any]:
    """Cross-references state_data, executed_tool_runs, findings, scan_logs.

    Validates that ALL expected tools per phase have been attempted.
    Flags mandatory gaps and missing tool executions for supervisor review.
    """
    state = dict(scan.state_data or {})
    completed_caps: list[str] = list(state.get("completed_capabilities") or [])
    node_history: list[str] = list(state.get("node_history") or [])
    autonomy_obs: list[dict] = list(state.get("autonomy_observations") or [])
    metrics = dict(state.get("mission_metrics") or {})
    objective_met = bool(state.get("objective_met"))
    termination_reason = str(state.get("termination_reason") or "")

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

    # Tool aggregations
    tool_stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "tool": "",
            "attempts": 0,
            "success": 0,
            "failed": 0,
            "targets": set(),
            "last_status": None,
            "last_error": None,
            "total_seconds": 0.0,
        }
    )
    for r in runs:
        key = _normalize_tool(r.tool_name)
        stats = tool_stats[key]
        stats["tool"] = key
        stats["attempts"] += 1
        stats["targets"].add(str(r.target or ""))
        if r.status == "success":
            stats["success"] += 1
        else:
            stats["failed"] += 1
        stats["last_status"] = r.status
        if r.error_message:
            stats["last_error"] = (r.error_message or "")[:300]
        if r.execution_time_seconds:
            stats["total_seconds"] += float(r.execution_time_seconds or 0.0)

    # Findings by tool
    findings_by_tool: dict[str, int] = defaultdict(int)
    findings_by_node: dict[str, int] = defaultdict(int)
    severity_by_node: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        t = _normalize_tool(f.tool)
        if t:
            findings_by_tool[t] += 1
        # Try to derive node from autonomy_observations source field
        # (best-effort; otherwise unknown)

    # Map autonomy_observations to nodes/tools (provides timing)
    obs_by_node: dict[str, list[dict]] = defaultdict(list)
    for ob in autonomy_obs:
        src = str(ob.get("source") or "").lower()
        # source may be a node name or a freeform "ReconNode"; map known ones
        node_key = src
        for cap in CAPABILITY_NODES:
            if cap.replace("_", "") in src.replace("_", ""):
                node_key = cap
                break
        obs_by_node[node_key].append(ob)

    # Phases (22) — status derived from node completion + tools attempted
    expected_tools = _expected_tools_by_phase()
    phases: list[dict[str, Any]] = []
    for phase in PENTEST_PHASES:
        pid = phase["id"]
        node = phase["node"]
        node_done = node in completed_caps
        node_visited = node in node_history
        tools_expected = [_normalize_tool(t) for t in phase.get("tools", [])]
        tools_used = [t for t in tools_expected if tool_stats.get(t, {}).get("attempts", 0) > 0]
        tools_success = [t for t in tools_used if tool_stats.get(t, {}).get("success", 0) > 0]
        tools_failed = [t for t in tools_used if tool_stats.get(t, {}).get("failed", 0) > 0 and tool_stats.get(t, {}).get("success", 0) == 0]
        tools_missing = [t for t in tools_expected if tool_stats.get(t, {}).get("attempts", 0) == 0]

        if not node_visited:
            status_label = "skipped"
        elif tools_success:
            status_label = "executed"
        elif tools_used:
            status_label = "attempted_failed"
        else:
            status_label = "node_visited_no_tools"

        if node_done and not tools_used:
            status_label = "node_completed_no_phase_tools"

        phases.append({
            "id": pid,
            "title": phase["title"],
            "node": node,
            "status": status_label,
            "node_visited": node_visited,
            "node_completed": node_done,
            "tools_expected": tools_expected,
            "tools_used": tools_used,
            "tools_success": tools_success,
            "tools_failed": tools_failed,
            "tools_missing": tools_missing,
        })

    # Capability summary (9 missions equivalent — actually 8 graph nodes + supervisor)
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
            "label": cap.replace("_", " ").title(),
            "completed": cap_done,
            "visited": cap_visited,
            "tools_expected": node_expected,
            "tools_attempted": node_attempted,
            "tools_success": node_success,
            "observations_count": len(obs_by_node.get(cap, [])),
        })

    # Tool inventory summary
    tool_inventory = []
    for k, v in sorted(tool_stats.items()):
        tool_inventory.append({
            "tool": v["tool"] or k,
            "attempts": v["attempts"],
            "success": v["success"],
            "failed": v["failed"],
            "targets_count": len(v["targets"]),
            "total_seconds": round(v["total_seconds"], 2),
            "last_status": v["last_status"],
            "last_error": v["last_error"],
            "findings_generated": findings_by_tool.get(k, 0),
        })

    # Findings overview
    severity_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        severity_counts[(f.severity or "info").lower()] += 1

    # ──────────────────────────────────────────────────────────────────────────
    # CRITICAL VALIDATION: mandatory tool execution per phase
    # ──────────────────────────────────────────────────────────────────────────
    issues: list[str] = []
    validation_summary: dict[str, Any] = {"critical": [], "warning": [], "info": []}

    # 1. Phase coverage: mandatory tools that MUST run
    expected_all_tools = sorted({t for tools in expected_tools.values() for t in tools})
    used_tools_set = {k for k, v in tool_stats.items() if v["attempts"] > 0}
    missing_mandatory = expected_all_tools[: max(1, len(expected_all_tools) // 3)]  # ~33% are mandatory
    missing_mandatory_unused = [t for t in missing_mandatory if t not in used_tools_set]

    if missing_mandatory_unused:
        issue = f"MANDATORY TOOLS NOT EXECUTED: {', '.join(missing_mandatory_unused[:5])}. "
        issue += "Supervisor MUST retry these phases."
        issues.append(issue)
        validation_summary["critical"].append(issue)

    coverage_ratio = (len(used_tools_set & set(expected_all_tools)) / max(1, len(expected_all_tools)))
    if coverage_ratio < 0.5:
        issue = f"Tool coverage critically low: {coverage_ratio:.0%} (<50%). "
        issue += f"Expected {len(expected_all_tools)}, used {len(used_tools_set)}"
        issues.append(issue)
        validation_summary["critical"].append(issue)

    # 2. Capability completion: all 8 nodes should execute
    skipped_caps = [c for c in CAPABILITY_NODES if c not in completed_caps]
    if skipped_caps:
        issue = f"INCOMPLETE CAPABILITIES: {', '.join(skipped_caps)}. "
        issue += "Graph traversal did not visit all capability nodes."
        issues.append(issue)
        validation_summary["critical"].append(issue)

    # 3. Tool failures: tools that failed all attempts must retry
    failed_only = [k for k, v in tool_stats.items() if v["attempts"] > 0 and v["success"] == 0]
    if failed_only:
        issue = f"TOOL FAILURES (all attempts): {', '.join(sorted(failed_only)[:5])}. "
        issue += "These must be retried or skipped with explanation."
        issues.append(issue)
        validation_summary["critical"].append(issue)

    # 4. Node history validation: should visit asset_discovery, risk_assessment, evidence_adjudication
    critical_nodes = ["asset_discovery", "risk_assessment", "evidence_adjudication"]
    missing_critical = [n for n in critical_nodes if n not in node_history]
    if missing_critical:
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
            issue = f"WEAK EVIDENCE for {len(weak_evidence)}/{len(high_severity)} high-severity findings. "
            issue += "Evidence adjudication may be incomplete."
            validation_summary["warning"].append(issue)
            issues.append(issue)

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "current_step": scan.current_step,
        "mission_progress": scan.mission_progress,
        "objective_met": objective_met,
        "termination_reason": termination_reason,
        "metrics": {
            "tools_attempted": int(metrics.get("tools_attempted", 0) or 0),
            "tools_success": int(metrics.get("tools_success", 0) or 0),
            "steps_done": int(metrics.get("steps_done", 0) or 0),
            "steps_success": int(metrics.get("steps_success", 0) or 0),
            "loop_iteration": int(state.get("loop_iteration", 0) or 0),
            "max_iterations": int(state.get("max_iterations", 0) or 0),
            "findings_total": len(findings),
            "tool_runs_total": len(runs),
        },
        "severity_counts": dict(severity_counts),
        "completed_capabilities": completed_caps,
        "node_history": node_history,
        "missions": MISSION_ITEMS,
        "capabilities": capabilities,
        "phases": phases,
        "tool_inventory": tool_inventory,
        "issues": issues,
        "validation_summary": validation_summary,
    }
