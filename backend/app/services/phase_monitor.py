from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import re
from typing import Any

from sqlalchemy.orm import Session

from app.graph.mission import PENTEST_PHASES, MISSION_ITEMS, PHASE_CONTRACTS
from app.models.models import AgentTraceEvent, ScanJob, ExecutedToolRun, Finding, ScanWorkItem
from app.services.capability_runtime import CAPABILITY_CONTRACT, infer_capability_ledger

try:
    from app.services.offensive_operator_core import (
        PHASE_CONTRACTS as OPERATOR_PHASE_CONTRACTS,
        PHASE_TOOL_BINDINGS as OPERATOR_PHASE_TOOL_BINDINGS,
    )
except Exception:  # pragma: no cover - legacy/minimal env fallback
    OPERATOR_PHASE_CONTRACTS = {}
    OPERATOR_PHASE_TOOL_BINDINGS = {}


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


def _operator_skill_tools_by_phase() -> dict[str, dict[str, set[str]]]:
    """Map phase -> skill -> tools from the real offensive-operator contracts."""
    result: dict[str, dict[str, set[str]]] = {}
    for phase_id, contract in (OPERATOR_PHASE_CONTRACTS or PHASE_CONTRACTS).items():
        phase_tools = {
            _normalize_tool(t)
            for t in list(contract.get("required_tools") or []) + list(contract.get("optional_tools") or [])
            if _normalize_tool(t)
        }
        bindings = OPERATOR_PHASE_TOOL_BINDINGS.get(str(phase_id), {}) if isinstance(OPERATOR_PHASE_TOOL_BINDINGS, dict) else {}
        skills = [str(s) for s in contract.get("required_skills") or [] if str(s)]
        phase_map: dict[str, set[str]] = {skill: set(phase_tools) for skill in skills}
        for tool_name, bound_skills in bindings.items():
            tool = _normalize_tool(tool_name)
            if not tool:
                continue
            bound_set = {str(s) for s in (bound_skills or [])}
            for skill in skills:
                if skill in bound_set:
                    phase_map.setdefault(skill, set()).add(tool)
                else:
                    phase_map.setdefault(skill, set()).discard(tool)
        result[str(phase_id)] = phase_map
    return result


def _tool_backend(tool_name: str, profile: str = "") -> str:
    tool = _normalize_tool(tool_name)
    prof = _normalize_tool(profile)
    if tool in {"bl-test", "code-analyzer", "semgrep"} or prof in {"business_logic_backend", "code_analyzer_backend", "semgrep_backend"}:
        return "backend_local"
    if tool in {"manual_review", "manual_scope_review", "manual_correlation"} or tool.startswith("manual_"):
        return "manual"
    if tool in {"report-builder"} or prof in {"report_builder"}:
        return "reporting"
    return "kali"


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


def _parse_dt(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _normalized_ledger_status(status: str) -> str:
    raw = str(status or "").strip().lower()
    if raw == "completed":
        return "executed"
    if raw == "partial":
        return "partial_coverage"
    if raw in {"failed", "error"}:
        return "attempted_failed"
    if raw == "blocked":
        return "blocked"
    if raw:
        return raw
    return ""


def _normalized_phase_status(wq: dict[str, int], fallback: str = "") -> str:
    total = int(wq.get("total", 0) or 0)
    done = int(wq.get("done", 0) or 0)
    running = int(wq.get("running", 0) or 0)
    queued = int(wq.get("queued", 0) or 0)
    blocked = int(wq.get("blocked", 0) or 0)
    skipped = int(wq.get("skipped", 0) or 0)
    failed = int(wq.get("failed", 0) or 0)
    timeout = int(wq.get("timeout", 0) or 0)
    terminal = done + skipped + failed
    if total > 0:
        if terminal >= total:
            return "failed" if (failed + timeout) and done == 0 else "completed"
        if running > 0:
            return "executing"
        if queued > 0:
            return "queued"
        if blocked > 0:
            return "gate_blocked"
        if done > 0 or skipped > 0:
            return "completed"
        return "failed" if failed or timeout else "queued"
    raw = str(fallback or "").strip().lower()
    if raw in {"completed", "executed", "partial", "partial_coverage"}:
        return "completed"
    if raw in {"failed", "attempted_failed", "error"}:
        return "failed"
    if raw == "blocked":
        return "gate_blocked"
    if raw in {"executing", "in_progress", "running"}:
        return "executing"
    return "queued"


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

    # ── Work-queue truth per phase ────────────────────────────────────────────
    # The ledger marks a phase "executed" after a SINGLE target completes — it
    # over-reports progress. The work_queue holds the real per-phase counts
    # (done/total across ALL targets). Query it once and use it as the
    # authoritative progress source so the UI reflects reality, not the ledger.
    wq_by_phase: dict[str, dict[str, int]] = {}
    wq_tools_by_phase: dict[str, dict[str, dict[str, int]]] = {}
    wq_skills_by_phase: dict[str, dict[str, dict[str, Any]]] = {}
    try:
        import sqlalchemy as _sa_pm
        _wq_rows = (
            db.query(ScanWorkItem.phase_id, ScanWorkItem.status, _sa_pm.func.count(ScanWorkItem.id))
            .filter(ScanWorkItem.scan_job_id == scan.id)
            .group_by(ScanWorkItem.phase_id, ScanWorkItem.status)
            .all()
        )
        for _pid, _st, _cnt in _wq_rows:
            slot = wq_by_phase.setdefault(_pid, {
                "total": 0, "done": 0, "running": 0, "queued": 0, "blocked": 0,
                "failed": 0, "skipped": 0, "timeout": 0,
            })
            slot["total"] += _cnt
            if _st in ("completed", "done"):
                slot["done"] += _cnt
            elif _st in ("dispatched", "running", "submitted"):
                slot["running"] += _cnt
            elif _st == "queued":
                slot["queued"] += _cnt
            elif _st == "blocked":
                slot["blocked"] += _cnt
            elif _st == "skipped":
                slot["skipped"] += _cnt
            elif _st == "timeout":
                slot["timeout"] += _cnt
                slot["failed"] += _cnt
            elif _st == "failed":
                slot["failed"] += _cnt
        _wq_tool_rows = (
            db.query(ScanWorkItem.phase_id, ScanWorkItem.tool_name, ScanWorkItem.status, _sa_pm.func.count(ScanWorkItem.id))
            .filter(ScanWorkItem.scan_job_id == scan.id)
            .group_by(ScanWorkItem.phase_id, ScanWorkItem.tool_name, ScanWorkItem.status)
            .all()
        )
        for _pid, _tool, _st, _cnt in _wq_tool_rows:
            phase_tools = wq_tools_by_phase.setdefault(str(_pid or ""), {})
            tool_slot = phase_tools.setdefault(_normalize_tool(_tool), {"attempts": 0, "success": 0, "failed": 0, "skipped": 0, "running": 0, "queued": 0, "blocked": 0})
            status_text = str(_st or "").lower()
            count_int = int(_cnt or 0)
            if status_text in {"completed", "done", "failed", "timeout", "skipped", "submitted", "dispatched", "running", "retry"}:
                tool_slot["attempts"] += count_int
            if status_text in {"completed", "done"}:
                tool_slot["success"] += count_int
            elif status_text in {"failed", "timeout"}:
                tool_slot["failed"] += count_int
            elif status_text == "skipped":
                tool_slot["skipped"] += count_int
            elif status_text in {"submitted", "dispatched", "running", "retry"}:
                tool_slot["running"] += count_int
            elif status_text == "queued":
                tool_slot["queued"] += count_int
            elif status_text == "blocked":
                tool_slot["blocked"] += count_int
        _wq_skill_rows = (
            db.query(ScanWorkItem.phase_id, ScanWorkItem.tool_name, ScanWorkItem.status, ScanWorkItem.item_metadata)
            .filter(ScanWorkItem.scan_job_id == scan.id)
            .all()
        )
        for _pid, _tool, _st, _meta in _wq_skill_rows:
            meta = dict(_meta or {})
            skill_ids = [str(s) for s in meta.get("skill_ids") or [] if str(s)]
            if not skill_ids and meta.get("skill_id"):
                skill_ids = [str(meta.get("skill_id"))]
            if not skill_ids:
                continue
            phase_skills = wq_skills_by_phase.setdefault(str(_pid or ""), {})
            tool = _normalize_tool(_tool)
            status_text = str(_st or "").lower()
            for skill_id in skill_ids:
                slot = phase_skills.setdefault(
                    skill_id,
                    {"items": 0, "tools_attempted": set(), "tools_success": set(), "tools_failed": set(), "tools_queued": set()},
                )
                slot["items"] += 1
                if status_text in {"completed", "done", "failed", "timeout", "skipped", "submitted", "dispatched", "running", "retry"}:
                    slot["tools_attempted"].add(tool)
                elif status_text == "queued":
                    slot["tools_queued"].add(tool)
                if status_text in {"completed", "done"}:
                    slot["tools_success"].add(tool)
                elif status_text in {"failed", "timeout"}:
                    slot["tools_failed"].add(tool)
    except Exception:
        wq_by_phase = {}
        wq_tools_by_phase = {}
        wq_skills_by_phase = {}

    wq_current_phase_id = ""
    if wq_by_phase:
        active_phases = sorted(
            pid for pid, counts in wq_by_phase.items()
            if int(counts.get("running", 0) or 0) > 0
            or int(counts.get("queued", 0) or 0) > 0
        )
        blocked_phases = sorted(
            pid for pid, counts in wq_by_phase.items()
            if int(counts.get("blocked", 0) or 0) > 0
        )
        wq_current_phase_id = active_phases[0] if active_phases else (blocked_phases[0] if blocked_phases else "")
    effective_current_pentest_phase_id = wq_current_phase_id or current_pentest_phase_id

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
    skill_consult_events = (
        db.query(AgentTraceEvent)
        .filter(
            AgentTraceEvent.scan_id == scan.id,
            AgentTraceEvent.event_type == "skill_consulted",
        )
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

    # New offensive-operator scans persist tool execution inside phase_ledger_v2,
    # not ExecutedToolRun. Fold that ledger into the same inventory so every UI
    # sees the real MCP/Kali activity.
    for ledger_entry in phase_ledger.values():
        target = str(ledger_entry.get("target") or scan.target_query or "")
        target_key = target.strip().lower()
        attempted = [_normalize_tool(t) for t in ledger_entry.get("tools_attempted") or [] if _normalize_tool(t)]
        succeeded = {_normalize_tool(t) for t in (ledger_entry.get("tools_success") or ledger_entry.get("tools_succeeded") or [])}
        failed = {_normalize_tool(t) for t in ledger_entry.get("tools_failed") or []}
        skipped = {_normalize_tool(t) for t in ledger_entry.get("tools_skipped") or []}
        started = _parse_dt(ledger_entry.get("started_at"))
        finished = _parse_dt(ledger_entry.get("finished_at"))
        elapsed = 0.0
        if started and finished:
            elapsed = max((finished - started).total_seconds(), 0.0)

        for tool in attempted:
            if (tool, target_key) in run_status_by_tool_target:
                continue
            stats = tool_stats[tool]
            stats["tool"] = tool
            stats["attempts"] += 1
            stats["targets"].add(target)
            if tool in succeeded:
                stats["success"] += 1
                status_value = "success"
            elif tool in skipped:
                stats["skipped"] += 1
                status_value = "skipped"
            elif tool in failed or str(ledger_entry.get("status") or "").lower() in {"failed", "blocked"}:
                stats["failed"] += 1
                status_value = "failed"
            else:
                status_value = str(ledger_entry.get("status") or "unknown")
                if status_value == "completed":
                    stats["success"] += 1
                    status_value = "success"
                else:
                    stats["failed"] += 1
            stats["last_status"] = status_value
            stats["total_seconds"] += elapsed
            if ledger_entry.get("blocking_reason"):
                stats["last_error"] = str(ledger_entry.get("blocking_reason"))[:300]
            run_status_by_tool_target[(tool, target_key)] = status_value

    # Work-queue scans can execute thousands of tool/target units without each
    # unit being mirrored into ExecutedToolRun or phase_ledger_v2. Fold the queue
    # into the same inventory so validation and dashboard counts reflect the
    # active orchestration path.
    for phase_tools in wq_tools_by_phase.values():
        for tool, counts in phase_tools.items():
            if not tool:
                continue
            stats = tool_stats[tool]
            stats["tool"] = tool
            stats["attempts"] = max(int(stats.get("attempts", 0) or 0), int(counts.get("attempts", 0) or 0))
            stats["success"] = max(int(stats.get("success", 0) or 0), int(counts.get("success", 0) or 0))
            stats["failed"] = max(int(stats.get("failed", 0) or 0), int(counts.get("failed", 0) or 0))
            stats["skipped"] = max(int(stats.get("skipped", 0) or 0), int(counts.get("skipped", 0) or 0))
            if counts.get("running"):
                stats["last_status"] = "running"
            elif counts.get("queued"):
                stats["last_status"] = stats.get("last_status") or "queued"
            elif counts.get("blocked"):
                stats["last_status"] = stats.get("last_status") or "blocked"

    # ── Findings by tool ──────────────────────────────────────────────────────
    findings_by_tool: dict[str, int] = defaultdict(int)
    positive_findings_by_tool: dict[str, int] = defaultdict(int)
    confirmed_findings_by_tool: dict[str, int] = defaultdict(int)
    severity_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        t = _normalize_tool(f.tool)
        if t:
            findings_by_tool[t] += 1
            details = dict(f.details or {})
            supervisor_status = str((details.get("supervisor_validation") or {}).get("status") or "")
            is_fp = bool(getattr(f, "is_false_positive", False)) or supervisor_status.startswith("refuted")
            if not is_fp:
                positive_findings_by_tool[t] += 1
                if str(f.verification_status or "").lower() == "confirmed":
                    confirmed_findings_by_tool[t] += 1
        severity_counts[(f.severity or "info").lower()] += 1

    # ── Supervisor validation of skill consultation/utilization/effectiveness ──
    raw_ledgers = state.get("phase_ledger_v2") or state.get("phase_ledger") or []
    raw_ledgers = raw_ledgers if isinstance(raw_ledgers, list) else []
    ledgers_by_phase: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ledger in raw_ledgers:
        if isinstance(ledger, dict):
            ledgers_by_phase[str(ledger.get("phase_id") or "")].append(ledger)
    consulted_events_by_phase: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in skill_consult_events:
        payload = dict(event.payload or {})
        phase_id = str(payload.get("phase_id") or event.capability or "")
        if not phase_id:
            continue
        consulted_events_by_phase[phase_id].append({
            "skill_id": str(event.skill_id or payload.get("skill_id") or ""),
            "status": str(event.status or ""),
            "payload": payload,
        })

    skill_tools_by_phase = _operator_skill_tools_by_phase()
    skill_rows: list[dict[str, Any]] = []
    totals = {
        "expected": 0,
        "consulted_observed": 0,
        "used_observed_or_inferred": 0,
        "positive_result": 0,
        "confirmed_result": 0,
        "missing_consultation": 0,
        "attributed_in_work_queue": 0,
    }
    for phase_id, skills_tools in skill_tools_by_phase.items():
        ledgers_for_phase = ledgers_by_phase.get(phase_id) or []
        wq_phase_tools = wq_tools_by_phase.get(phase_id) or {}
        wq_phase_skills = wq_skills_by_phase.get(phase_id) or {}
        attempted_tools = {
            tool for tool, counts in wq_phase_tools.items()
            if int(counts.get("attempts", 0) or 0) > 0
        }
        successful_tools = {
            tool for tool, counts in wq_phase_tools.items()
            if int(counts.get("success", 0) or 0) > 0
        }
        for ledger in ledgers_for_phase:
            attempted_tools.update(_normalize_tool(t) for t in ledger.get("tools_attempted") or [] if _normalize_tool(t))
            successful_tools.update(_normalize_tool(t) for t in (ledger.get("tools_success") or ledger.get("tools_succeeded") or []) if _normalize_tool(t))

        consulted: set[str] = set()
        selected: set[str] = set()
        coverage_by_skill: dict[str, dict[str, Any]] = {}
        for ledger in ledgers_for_phase:
            selected.update(str(s) for s in ledger.get("selected_skills") or [] if str(s))
            consulted.update(str(s) for s in ledger.get("selected_skills") or [] if str(s))
            consulted.update(str(s) for s in ledger.get("skills_planned") or [] if str(s))
            for item in ledger.get("retrieved_rag_context") or []:
                if isinstance(item, dict) and item.get("skill_id"):
                    consulted.add(str(item.get("skill_id")))
            for skill_id, coverage in (ledger.get("skill_coverage") or {}).items():
                if skill_id:
                    consulted.add(str(skill_id))
                    if isinstance(coverage, dict):
                        coverage_by_skill[str(skill_id)] = coverage
        for event in consulted_events_by_phase.get(phase_id) or []:
            event_skill = str(event.get("skill_id") or "")
            if not event_skill:
                continue
            consulted.add(event_skill)
            if str(event.get("status") or "") in {"selected", "used", "positive"}:
                selected.add(event_skill)

        for skill_id, skill_tools in skills_tools.items():
            totals["expected"] += 1
            wq_skill = dict(wq_phase_skills.get(skill_id) or {})
            wq_skill_attempted = {_normalize_tool(t) for t in (wq_skill.get("tools_attempted") or set()) if _normalize_tool(t)}
            wq_skill_success = {_normalize_tool(t) for t in (wq_skill.get("tools_success") or set()) if _normalize_tool(t)}
            tool_overlap = sorted(attempted_tools & skill_tools)
            successful_overlap = sorted(successful_tools & skill_tools)
            coverage = dict(coverage_by_skill.get(skill_id) or {})
            coverage_attempted = [_normalize_tool(t) for t in coverage.get("tools_attempted") or []]
            coverage_success = [_normalize_tool(t) for t in coverage.get("tools_success") or []]
            attributed_in_work_queue = bool(wq_skill)
            used_observed = bool(coverage_attempted or coverage_success or wq_skill_attempted or wq_skill_success)
            used_inferred = bool(tool_overlap) and not used_observed
            used = used_observed or used_inferred
            credited_tools = set(tool_overlap) | set(coverage_success) | wq_skill_success | wq_skill_attempted
            positive_tools = sorted(t for t in credited_tools if positive_findings_by_tool.get(t, 0) > 0)
            confirmed_tools = sorted(t for t in credited_tools if confirmed_findings_by_tool.get(t, 0) > 0)
            positive = bool(positive_tools)
            confirmed = bool(confirmed_tools)
            consulted_observed = skill_id in consulted
            if consulted_observed:
                totals["consulted_observed"] += 1
            else:
                totals["missing_consultation"] += 1
            if attributed_in_work_queue:
                totals["attributed_in_work_queue"] += 1
            if used:
                totals["used_observed_or_inferred"] += 1
            if positive:
                totals["positive_result"] += 1
            if confirmed:
                totals["confirmed_result"] += 1
            if positive:
                outcome = "positive"
            elif used:
                outcome = "used_no_positive_result"
            elif consulted_observed:
                outcome = "consulted_not_used"
            else:
                outcome = "not_observed"
            skill_rows.append({
                "phase_id": phase_id,
                "skill_id": skill_id,
                "consulted_observed": consulted_observed,
                "selected_observed": skill_id in selected,
                "attributed_in_work_queue": attributed_in_work_queue,
                "used": used,
                "used_observed": used_observed,
                "used_inferred_from_phase_tools": used_inferred,
                "expected_tools": sorted(skill_tools),
                "tools_attempted": sorted(set(tool_overlap) | set(coverage_attempted) | wq_skill_attempted),
                "tools_success": sorted(set(successful_overlap) | set(coverage_success) | wq_skill_success),
                "positive_result": positive,
                "confirmed_result": confirmed,
                "positive_tools": positive_tools,
                "confirmed_tools": confirmed_tools,
                "positive_findings_count": sum(int(positive_findings_by_tool.get(t, 0) or 0) for t in positive_tools),
                "confirmed_findings_count": sum(int(confirmed_findings_by_tool.get(t, 0) or 0) for t in confirmed_tools),
                "coverage_status": str(coverage.get("status") or ""),
                "outcome": outcome,
                "supervisor_note": (
                    "Consulta de skill observada no ledger/RAG."
                    if consulted_observed
                    else "Consulta de skill NAO observada; uso/resultado foi inferido por fase/ferramenta."
                ),
            })

    def _ratio(num: int, den: int) -> float:
        return round(float(num) / max(1, float(den)), 3)

    skill_supervision = {
        "summary": {
            **totals,
            "consultation_rate": _ratio(totals["consulted_observed"], totals["expected"]),
            "utilization_rate": _ratio(totals["used_observed_or_inferred"], totals["expected"]),
            "positive_result_rate": _ratio(totals["positive_result"], totals["used_observed_or_inferred"]),
            "confirmed_result_rate": _ratio(totals["confirmed_result"], totals["used_observed_or_inferred"]),
            "modeling_warning": (
                "consulta dinamica RAG/supervisor nao foi observada para todas as skills; "
                "quando existe item_metadata.skill_ids, uso e resultado sao creditados por atribuicao contratual."
                if totals["missing_consultation"] else ""
            ),
        },
        "skills": skill_rows,
    }

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
        ledger_tools_succeeded = [_normalize_tool(t) for t in (ledger_entry.get("tools_success") or ledger_entry.get("tools_succeeded") or [])]
        ledger_tools_failed = [_normalize_tool(t) for t in ledger_entry.get("tools_failed") or []]
        ledger_tools_skipped = [_normalize_tool(t) for t in ledger_entry.get("tools_skipped") or []]
        phase_used_tools_set.update(t for t in ledger_tools_attempted if t)
        wq_phase_tools = wq_tools_by_phase.get(pid) or {}
        wq_phase_attempted = {
            tool for tool, counts in wq_phase_tools.items()
            if int(counts.get("attempts", 0) or 0) > 0
        }
        phase_used_tools_set.update(wq_phase_attempted)
        node_done = node in completed_caps
        node_visited = node in node_history
        phase_started = bool(ledger_entry) or phase_idx <= pentest_phase_index or pid == current_pentest_phase_id
        tools_expected = [_normalize_tool(t) for t in phase.get("tools", [])]
        tools_installed = [t for t in tools_expected if is_tool_installed(t)]
        tools_uninstalled = [t for t in tools_expected if not is_tool_installed(t)]
        tools_used = sorted({
            t for t in tools_expected
            if tool_stats.get(t, {}).get("attempts", 0) > 0 or t in ledger_tools_attempted or t in wq_phase_attempted
        })
        # Work-queue tools (in ExecutedToolRun but not in tools_expected) also count
        # as evidence that the phase was visited — check tool_stats directly for the
        # phase's tool names even when not in PENTEST_PHASES tools list.
        work_queue_ran = bool(tools_used)
        effective_node_visited = (
            node_visited
            or bool(ledger_entry)
            or bool(capability_ledger.get(node, {}).get("visited"))
            or work_queue_ran  # ← work queue ran tools → phase was visited
        )
        tools_success = sorted({
            t for t in tools_used
            if tool_stats.get(t, {}).get("success", 0) > 0 or t in ledger_tools_succeeded or int((wq_phase_tools.get(t) or {}).get("success", 0) or 0) > 0
        })
        tools_failed = [
            t for t in tools_used
            if (tool_stats.get(t, {}).get("failed", 0) > 0 or t in ledger_tools_failed or int((wq_phase_tools.get(t) or {}).get("failed", 0) or 0) > 0)
            and tool_stats.get(t, {}).get("success", 0) == 0
            and int((wq_phase_tools.get(t) or {}).get("success", 0) or 0) == 0
            and tool_stats.get(t, {}).get("skipped", 0) == 0
        ]
        tools_skipped = [
            t for t in tools_used
            if (tool_stats.get(t, {}).get("skipped", 0) > 0 or t in ledger_tools_skipped or int((wq_phase_tools.get(t) or {}).get("skipped", 0) or 0) > 0)
            and tool_stats.get(t, {}).get("success", 0) == 0
            and int((wq_phase_tools.get(t) or {}).get("success", 0) or 0) == 0
            and tool_stats.get(t, {}).get("failed", 0) == 0
        ]
        # Distinguish "missing because unavailable in Kali" vs "ready but skipped".
        tools_missing_uninstalled = [t for t in tools_uninstalled if t not in tools_used]
        tools_missing_unused = [t for t in tools_installed if t not in tools_used]
        tools_missing = tools_missing_uninstalled + tools_missing_unused
        tools_failed_list = sorted(set(tools_failed))
        ledger_status = str(ledger_entry.get("status") or "")
        normalized_ledger_status = _normalized_ledger_status(ledger_status)

        # ── Work-queue per-phase progress (authoritative) ─────────────────────
        _wq = wq_by_phase.get(pid) or {}
        _wq_total = _wq.get("total", 0)
        _wq_done = _wq.get("done", 0)
        _wq_running = _wq.get("running", 0)
        _wq_queued = _wq.get("queued", 0)
        _wq_blocked = _wq.get("blocked", 0)
        _wq_skipped = _wq.get("skipped", 0)
        _wq_timeout = _wq.get("timeout", 0)
        _wq_failed = _wq.get("failed", 0)
        # Phase completion % = terminal/total. A phase is 100% when every item
        # reached a terminal state (done/skipped/failed/timeout). A skipped tool
        # (not applicable to this target — no .git, no API key, etc.) is a
        # LEGITIMATE completion, not a gap, so it counts toward 100%. The
        # success quality (how many actually succeeded) is exposed separately
        # via the done/skipped/failed counts so the UI can show green vs gray.
        _wq_terminal = _wq_done + _wq_skipped + _wq_failed
        _wq_pct = int(_wq_terminal / _wq_total * 100) if _wq_total > 0 else None

        if not effective_node_visited and _wq_total == 0:
            status_label = "queued"
        else:
            status_label = _normalized_phase_status(_wq, normalized_ledger_status)

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
            "tool_backends": {tool: _tool_backend(tool) for tool in tools_expected},
            # Work-queue truth (authoritative per-phase progress across ALL targets)
            # pct = terminal/total (phase finished). success_pct = done/total (quality).
            "work_queue": {
                "total": _wq_total,
                "done": _wq_done,
                "running": _wq_running,
                "queued": _wq_queued,
                "blocked": _wq_blocked,
                "skipped": _wq_skipped,
                "timeout": _wq_timeout,
                "failed": _wq_failed,
                "pct": _wq_pct,
                "success_pct": int(_wq_done / _wq_total * 100) if _wq_total > 0 else None,
            },
            # Ledger enrichment
            "ledger_status": ledger_status,
            "ledger_exit_criteria_met": bool(ledger_entry.get("exit_criteria_met")),
            "ledger_can_advance": bool(ledger_entry.get("can_advance")),
            "ledger_mcp_status": str(ledger_entry.get("mcp_status") or "not_attempted"),
            "ledger_skip_reason": ledger_entry.get("skip_reason"),
            "ledger_validation_result": dict(ledger_entry.get("validation_result") or {}),
        }
        if pid == "P13":
            bl_tools = {"bl-test", "chromium-capture"}
            bl_attempted = any(tool in wq_phase_attempted or tool in ledger_tools_attempted for tool in bl_tools)
            bl_blocked = any(int((wq_phase_tools.get(tool) or {}).get("blocked", 0) or 0) > 0 for tool in bl_tools)
            bl_success = any(int((wq_phase_tools.get(tool) or {}).get("success", 0) or 0) > 0 for tool in bl_tools) or any(tool in ledger_tools_succeeded for tool in bl_tools)
            bl_findings = [
                f for f in findings
                if _normalize_tool(getattr(f, "tool", "")) in bl_tools
                or "business" in str(getattr(f, "title", "") or "").lower()
                or "business" in str(getattr(f, "vulnerability_type", "") or "").lower()
            ]
            if bl_findings:
                bl_state = "finding"
            elif bl_success or bl_attempted:
                bl_state = "executed_no_finding"
            elif bl_blocked or status_label == "gate_blocked":
                bl_state = "gate_blocked"
            else:
                bl_state = "planned"
            phase_row["business_logic"] = {
                "state": bl_state,
                "label": {
                    "planned": "planejado",
                    "gate_blocked": "bloqueado/aguardando gate",
                    "executed_no_finding": "executado sem achado",
                    "finding": "achado real",
                }[bl_state],
                "tools": sorted(bl_tools),
                "findings_count": len(bl_findings),
            }
        phases.append(phase_row)

        contract = dict(PHASE_CONTRACTS.get(pid) or {})
        required_tools = [_normalize_tool(t) for t in contract.get("required_tools") or []]
        required_tools_missing = [t for t in required_tools if t and t not in tools_used]
        phase_contract_reports.append({
            **phase_row,
            "phase_id": pid,
            "name": contract.get("name") or phase["title"],
            "can_advance": bool(ledger_entry.get("can_advance")) or status_label in {"completed"},
            "required_tools": required_tools,
            "required_tools_missing": required_tools_missing,
            "validation_result": dict(ledger_entry.get("validation_result") or {}),
        })

    hypothesis_report = list(state.get("pentest_hypotheses") or state.get("hypotheses") or [])
    journey_summary = {
        "total_phases": len(PENTEST_PHASES),
        "executed": sum(1 for p in phase_contract_reports if p["status"] == "completed"),
        "partial": 0,
        "skipped": 0,
        "pending": sum(1 for p in phase_contract_reports if p["status"] == "queued"),
        "blocked": sum(1 for p in phase_contract_reports if p["status"] == "gate_blocked"),
        "executing": sum(1 for p in phase_contract_reports if p["status"] == "executing"),
        "failed": sum(1 for p in phase_contract_reports if p["status"] == "failed"),
        "mcp_failures_total": sum(
            1 for p in phase_contract_reports
            if str(p.get("ledger_mcp_status") or "").lower() in {"failed", "timeout", "unreachable"}
        ),
    }
    # "blocked" = phase aguardando gate — NÃO conta como concluída para o progresso.
    # Só "completed" e "partial" indicam trabalho real realizado.
    ledger_completed_count = sum(
        1 for entry in phase_ledger.values()
        if str(entry.get("status") or "").lower() in {"completed", "partial"}
    )
    _scan_running = str(scan.status or "").lower() in ("running", "queued", "retrying")

    # ── Progress from work-queue (authoritative) with ledger fallback ─────────
    # Work-queue engine: real progress = terminal / (total - blocked), since
    # blocked items are pending (awaiting gate), not done. The ledger fallback
    # is only for legacy scans without work items.
    _wq_total_all = sum(s.get("total", 0) for s in wq_by_phase.values())
    if _wq_total_all > 0:
        _wq_blocked_all = sum(s.get("blocked", 0) for s in wq_by_phase.values())
        _wq_done_all = sum(s.get("done", 0) for s in wq_by_phase.values())
        _wq_failed_all = sum(s.get("failed", 0) for s in wq_by_phase.values())
        _wq_skipped_all = sum(s.get("skipped", 0) for s in wq_by_phase.values())
        _effective = max(1, _wq_total_all - _wq_blocked_all)
        # terminal = done + failed(inc. timeout) + skipped — all "phase finished" states
        _terminal = _wq_done_all + _wq_failed_all + _wq_skipped_all
        computed_progress = int(_terminal / _effective * 100)
        if _scan_running:
            computed_progress = min(99, computed_progress)
    else:
        # Legacy: ledger-based per-phase progress.
        computed_progress = round((ledger_completed_count / max(1, len(PENTEST_PHASES))) * 100)
        if _scan_running:
            computed_progress = min(99, computed_progress)

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
            "backend": _tool_backend(v["tool"] or k),
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

    scan_status = str(scan.status or "").strip().lower()
    scan_is_terminal = scan_status in {"completed", "failed", "error", "cancelled", "canceled"}
    scan_is_active = scan_status in {"queued", "running", "retrying", "paused"}

    # 1. Phase blocking: only critical when the phase truly failed/blocked.
    # During active work-queue scans, queued/running/gate-blocked phases are
    # expected orchestration states and should not flood "Pontos de atenção".
    blocked_phases = []
    for r in phase_contract_reports:
        status_text = str(r.get("status") or "")
        wq = dict(r.get("work_queue") or {})
        has_pending_work = any(int(wq.get(key, 0) or 0) > 0 for key in ("running", "queued"))
        gate_blocked = int(wq.get("total", 0) or 0) > 0 and int(wq.get("blocked", 0) or 0) == int(wq.get("total", 0) or 0)
        if scan_is_active and (has_pending_work or gate_blocked or status_text in {"executing", "queued", "gate_blocked"}):
            continue
        if status_text not in ("completed", "queued") and not r["can_advance"]:
            blocked_phases.append(r)
    for r in blocked_phases:
        reason = str((r.get("validation_result") or {}).get("reason") or "unknown")
        if scan_is_active and reason == "unknown":
            continue
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
        wq = dict(r.get("work_queue") or {})
        phase_still_active = scan_is_active and any(int(wq.get(key, 0) or 0) > 0 for key in ("running", "queued", "blocked"))
        if r.get("required_tools_missing") and r["status"] not in ("queued", "gate_blocked") and not phase_still_active:
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
    validation_is_active = has_tool_execution_evidence
    if scan_is_terminal and not has_tool_execution_evidence:
        issue = (
            "NO KALI TOOL EXECUTION RECORDED: scan reached a terminal state without tool attempts. "
            "This indicates orchestration/worker dispatch did not start; tool coverage lists are suppressed until execution evidence exists."
        )
        issues.append(issue)
        validation_summary["critical"].append(issue)

    if installed_unused and validation_is_active and scan_is_terminal:
        issue = (
            f"KALI TOOLS NOT EXECUTED ({len(installed_unused)}): "
            f"{', '.join(installed_unused[:8])}{'…' if len(installed_unused) > 8 else ''}. "
            "These tools are available in Kali runner but were not attempted."
        )
        issues.append(issue)
        validation_summary["critical"].append(issue)
    elif installed_unused and validation_is_active:
        issue = (
            f"KALI TOOLS STILL PENDING ({len(installed_unused)}): "
            f"{', '.join(installed_unused[:8])}{'…' if len(installed_unused) > 8 else ''}. "
            "Scan still running; final coverage will be evaluated at completion."
        )
        validation_summary["info"].append(issue)
    elif installed_unused:
        issue = (
            f"KALI TOOL EXECUTION PENDING: {len(installed_unused)} Kali-ready tool(s) aguardam execução. "
            "Coverage will be evaluated after the agent records the first tool attempt."
        )
        validation_summary["info"].append(issue)

    if uninstalled_expected and validation_is_active and scan_is_terminal:
        issue = (
            f"KALI TOOLS NOT AVAILABLE ({len(uninstalled_expected)}): "
            f"{', '.join(uninstalled_expected[:8])}{'…' if len(uninstalled_expected) > 8 else ''}. "
            "Add to Kali runner profiles or remove from expected catalog."
        )
        issues.append(issue)
        validation_summary["warning"].append(issue)
    elif uninstalled_expected and validation_is_active:
        issue = (
            f"KALI TOOL AVAILABILITY REVIEW PENDING ({len(uninstalled_expected)}): "
            "Scan still running; availability gaps will be classified after completion."
        )
        validation_summary["info"].append(issue)
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
    elif coverage_ratio_installed < 0.7 and scan_is_terminal:
        issue = (
            f"Coverage of Kali-ready tools low: {coverage_ratio_installed:.0%} "
            f"({len(used_tools_set & set(installed_expected))}/{len(installed_expected)}). "
            "Target ≥70% of Kali-ready tools per scan."
        )
        issues.append(issue)
        validation_summary["critical"].append(issue)
    elif coverage_ratio_installed < 0.7:
        validation_summary["info"].append(
            f"Coverage in progress: {coverage_ratio_installed:.0%} "
            f"({len(used_tools_set & set(installed_expected))}/{len(installed_expected)}) Kali-ready tools attempted so far."
        )

    # 2. Capability completion: all 8 nodes should execute
    capability_gaps: list[dict[str, Any]] = []
    if validation_is_active and scan_is_terminal:
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
    if scan_is_terminal:
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
    elif failed_only:
        validation_summary["info"].append(
            f"Tool failures observed so far: {', '.join(sorted(failed_only)[:5])}. "
            "Scan still running; retry/skip classification will be evaluated at completion."
        )

    # 4. Node history validation: should visit asset_discovery, risk_assessment, evidence_adjudication
    critical_nodes = ["asset_discovery", "risk_assessment", "evidence_adjudication"]
    missing_critical = [n for n in critical_nodes if n not in node_history and not capability_ledger.get(n, {}).get("visited")]
    if missing_critical and validation_is_active and scan_is_terminal:
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
    if weak_evidence and len(high_severity) > 0 and scan_is_terminal:
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

    if skill_supervision["summary"].get("missing_consultation"):
        validation_summary["warning"].append(
            "SKILL MODELING GAP: nem todas as skills esperadas tiveram consulta/seleção dinâmica observável. "
            "Uso e resultado podem ser creditados por item_metadata.skill_ids, mas o supervisor ainda deve registrar a consulta RAG/decisão."
        )

    return {
        # ── Scan metadata ──────────────────────────────────────────────────
        "scan_id": scan.id,
        "status": scan.status,
        # current_step: em scans work_queue, scan.current_step fica obsoleto
        # ("Iniciando grafo"). Usa a fase pentest ativa real quando disponível.
        "current_step": (
            effective_current_pentest_phase_id
            if (_wq_total_all > 0 and effective_current_pentest_phase_id
                and str(scan.status or "").lower() not in ("completed", "done", "finished"))
            else scan.current_step
        ),
        # mission_progress source of truth:
        #  - work_queue scans: computed_progress (terminal/effective from the queue,
        #    computed above) — NOT scan.mission_progress which can stall stale.
        #  - completed scans: 100%.
        #  - legacy scans: computed_progress from ledger.
        "mission_progress": (
            100 if str(scan.status or "").lower() == "completed"
            else int(computed_progress or 0) if _wq_total_all > 0
            else max(int(scan.mission_progress or 0), int(computed_progress or 0))
        ),
        "objective_met": objective_met,
        "termination_reason": termination_reason,
        # ── Pentest phase execution state ──────────────────────────────────
        "pentest_phase_index": pentest_phase_index,
        "current_pentest_phase_id": effective_current_pentest_phase_id,
        # ── PRIMARY REPORT: phased pentest journey ─────────────────────────
        "pentest_journey": {
            "summary": journey_summary,
            "phases": phase_contract_reports,
            "hypotheses": hypothesis_report,
        },
        # ── Metrics ───────────────────────────────────────────────────────
        "metrics": {
            "tools_attempted": max(int(metrics.get("tools_attempted", 0) or 0), sum(int(v.get("attempts", 0) or 0) for v in tool_stats.values())),
            "tools_success": max(int(metrics.get("tools_success", 0) or 0), sum(int(v.get("success", 0) or 0) for v in tool_stats.values())),
            "steps_done": max(int(metrics.get("steps_done", 0) or 0), ledger_completed_count),
            "steps_success": max(int(metrics.get("steps_success", 0) or 0), sum(1 for entry in phase_ledger.values() if str(entry.get("status") or "").lower() == "completed")),
            "loop_iteration": int(state.get("loop_iteration", 0) or 0),
            "max_iterations": int(state.get("max_iterations", 0) or 0),
            "findings_total": len(findings),
            "tool_runs_total": max(len(runs), sum(int(v.get("attempts", 0) or 0) for v in tool_stats.values())),
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
        "skill_supervision": skill_supervision,
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
