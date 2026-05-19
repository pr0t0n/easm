from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import uuid4

from langgraph.graph import END

from app.graph.state import AgentState, TOOL_CAPABILITY_NODES, CAPABILITY_SKILL_CATEGORIES

logger = logging.getLogger(__name__)

# These constants are used by supervisor_node and must be accessible here
ANALYST_CONFIDENCE_THRESHOLDS: dict[str, int] = {
    "high": 80,
    "medium": 50,
    "low": 0,
}


def _count_high_signal_findings(state: AgentState) -> int:
    findings = state.get("vulnerabilidades_encontradas") or []
    return sum(
        1
        for finding in findings
        if str(finding.get("severity", "")).lower() in {"critical", "high"}
    )


def _has_verified_or_strong_evidence(state: AgentState) -> bool:
    findings = state.get("vulnerabilidades_encontradas") or []
    for finding in findings:
        details = dict(finding.get("details") or {})
        status = str(details.get("validation_status") or "").lower()
        risk_score = float(finding.get("risk_score") or 0)
        if status == "verified":
            return True
        if str(finding.get("severity", "")).lower() in {"critical", "high"} and risk_score >= 7:
            return True
    return False


def _route_from_supervisor(state: AgentState):
    next_node = state.get("routing_next_node")
    if next_node in (END, "END"):
        return END
    # If the supervisor already committed to a skill, head straight to the pipeline.
    # pending_capability_node carries the capability label for context.
    if state.get("selected_skill"):
        if next_node in TOOL_CAPABILITY_NODES:
            state["pending_capability_node"] = str(next_node)
        return "skill_selector"
    # Backward-compat: capability label alone still routes to skill_selector.
    if next_node in TOOL_CAPABILITY_NODES:
        state["pending_capability_node"] = str(next_node)
        return "skill_selector"
    return next_node


def _append_autonomy_entry(state: AgentState, key: str, payload: dict[str, Any]) -> None:
    bucket = list(state.get(key) or [])
    bucket.append(
        {
            **payload,
            "ts": datetime.utcnow().isoformat(),
            "iteration": int(state.get("loop_iteration", 0)),
        }
    )
    state[key] = bucket


def _append_note(state: AgentState, text: str, phase: str) -> None:
    _append_autonomy_entry(state, "autonomy_notes", {"phase": phase, "text": str(text)})


def _append_todo(state: AgentState, title: str, priority: str = "medium") -> None:
    _append_autonomy_entry(
        state,
        "autonomy_todos",
        {"title": str(title), "priority": str(priority), "status": "open"},
    )


def _append_action(state: AgentState, action: str, data: dict[str, Any] | None = None) -> None:
    _append_autonomy_entry(state, "autonomy_actions", {"action": str(action), "data": dict(data or {})})


def _append_observation(state: AgentState, text: str, source: str) -> None:
    _append_autonomy_entry(state, "autonomy_observations", {"source": source, "text": str(text)})


def _append_error(state: AgentState, text: str, source: str) -> None:
    _append_autonomy_entry(state, "autonomy_errors", {"source": source, "text": str(text)})


def _refresh_active_skills(state: AgentState) -> None:
    from app.graph.mission import select_mission_skills
    selected = select_mission_skills(
        target=str(state.get("target") or ""),
        findings=list(state.get("vulnerabilidades_encontradas") or []),
        target_type=str(state.get("target_type") or "dominio"),
        discovered_ports=list(state.get("discovered_ports") or []),
        max_skills=5,
    )
    prev_ids = {str(item.get("id") or "") for item in list(state.get("active_skills") or [])}
    state["active_skills"] = selected
    selected_ids = [str(item.get("id") or "") for item in selected]
    if set(selected_ids) != prev_ids:
        _append_note(state, f"Skills ativas atualizadas: {', '.join(selected_ids)}", phase="skill-selection")


def _register_delegation_task(state: AgentState, node: str, reason: str, priority: int) -> None:
    tasks = list(state.get("delegated_tasks") or [])
    duplicate = any(
        str(item.get("node") or "") == node and str(item.get("status") or "") == "pending"
        for item in tasks
    )
    if duplicate:
        return
    task = {
        "id": f"deleg-{uuid4().hex[:10]}",
        "node": node,
        "reason": reason,
        "priority": int(priority),
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
    }
    tasks.append(task)
    tasks.sort(key=lambda item: int(item.get("priority", 999)))
    state["delegated_tasks"] = tasks
    _append_action(state, "delegate_task_created", task)


def _complete_delegation_task(state: AgentState, node: str, summary: str) -> None:
    tasks = list(state.get("delegated_tasks") or [])
    changed = False
    for item in tasks:
        if str(item.get("node") or "") == node and str(item.get("status") or "") == "pending":
            item["status"] = "done"
            item["completed_at"] = datetime.utcnow().isoformat()
            item["summary"] = summary
            changed = True
            break
    state["delegated_tasks"] = tasks
    if changed:
        delegation_log = list(state.get("delegation_log") or [])
        delegation_log.append({"node": node, "summary": summary, "ts": datetime.utcnow().isoformat()})
        state["delegation_log"] = delegation_log


def _update_execution_guardrails(state: AgentState) -> None:
    ctrl = dict(state.get("execution_control") or {})
    max_iterations = int(state.get("max_iterations", 12))
    iteration = int(state.get("loop_iteration", 0))
    findings_total = len(state.get("vulnerabilidades_encontradas") or [])
    last_total = int(ctrl.get("last_findings_total", 0))
    no_progress = int(ctrl.get("no_progress_iterations", 0))

    if findings_total <= last_total:
        no_progress += 1
    else:
        no_progress = 0

    ctrl["last_findings_total"] = findings_total
    ctrl["no_progress_iterations"] = no_progress
    ctrl["approaching_limit"] = iteration >= max(1, int(max_iterations * 0.85))
    ctrl["remaining_iterations"] = max(0, max_iterations - iteration)
    ctrl["paused"] = bool(ctrl.get("paused", False))

    if ctrl["approaching_limit"]:
        _append_note(
            state,
            f"Orçamento de iterações próximo do limite ({iteration}/{max_iterations}).",
            phase="execution-control",
        )
    if no_progress >= 3:
        _append_todo(state, "Pivotar estratégia por estagnação de evidências", priority="high")
        ctrl["paused"] = True
    else:
        ctrl["paused"] = False

    state["execution_control"] = ctrl


def _rank_tools_for_iteration(state: AgentState, tools: list[str]) -> list[str]:
    runtime = dict(state.get("tool_runtime") or {})
    ranked: list[tuple[tuple[int, int, int], str]] = []
    for tool in tools:
        stats = dict(runtime.get(str(tool), {}))
        failures = int(stats.get("failures", 0))
        attempts = int(stats.get("attempts", 0))
        success = int(stats.get("success", 0))
        ranked.append(((failures, attempts, -success), tool))
    ranked.sort(key=lambda item: item[0])
    return [item[1] for item in ranked]


def _default_skill_playbook(group: str, candidate_tools: list[str], primary_skill: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": f"{group} skill-first playbook",
        "vulnerability_type": str(primary_skill.get("category") or group),
        "techniques": [
            {"name": t, "objective": f"execute {t} for {group}", "risk": "low"}
            for t in candidate_tools
        ],
        "evidence_signals": list(primary_skill.get("triggers") or [])[:8],
    }


def _build_skill_playbook_for_context(
    state: AgentState,
    group: str,
    candidate_tools: list[str],
    phase_label: str,
    primary_skill: dict[str, Any],
) -> dict[str, Any]:
    playbook = _default_skill_playbook(group, candidate_tools, primary_skill)
    try:
        from app.services.vulnerability_learning_service import build_runtime_learning_playbook

        learned_playbook = build_runtime_learning_playbook(
            candidate_tools=candidate_tools,
            phase=phase_label,
            limit=12,
        )
        if learned_playbook:
            state["logs_terminais"].append(
                f"[{group}] supervisor usando playbook de aprendizado aceito: "
                f"techniques={len(learned_playbook.get('techniques') or [])}"
            )
            return learned_playbook

        learned_playbook = build_runtime_learning_playbook(
            candidate_tools=candidate_tools,
            phase=None,
            limit=12,
        )
        if learned_playbook:
            state["logs_terminais"].append(
                f"[{group}] supervisor usando playbook de aprendizado aceito (sem filtro de fase): "
                f"techniques={len(learned_playbook.get('techniques') or [])}"
            )
            return learned_playbook
    except Exception as exc:
        state["logs_terminais"].append(f"[{group}] erro ao carregar aprendizado: {exc}")
    return playbook


def _invoke_skill_for_context(
    state: AgentState,
    group: str,
    candidate_tools: list[str],
    playbook: dict[str, Any],
    phase_label: str | None = None,
    purpose: str = "pre_dispatch",
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    target = str(state.get("target") or "").strip()
    resolved_phase = str(phase_label or state.get("current_phase") or group)
    skills = list(state.get("active_skills") or [])
    primary_skill = skills[0] if skills else {"id": group, "phases": [resolved_phase]}
    skill_invocation: dict[str, Any] = {}

    try:
        from app.services.skill_runtime import resolve_skill_invocation

        skill_invocation = resolve_skill_invocation(
            worker_group=group,
            phase=resolved_phase,
            target=target,
            candidate_tools=candidate_tools,
            active_skills=skills,
            playbook=playbook,
        )
        if not skill_invocation.get("called"):
            state["logs_terminais"].append(
                f"[{group}] skill_call skipped: {skill_invocation.get('reason', 'no skill')}"
            )
            return skill_invocation, primary_skill, candidate_tools

        primary_skill = dict(skill_invocation.get("skill") or primary_skill)
        selected_skill_id = str(skill_invocation.get("skill_id") or primary_skill.get("id") or group)
        preferred = [
            str(tool).strip()
            for tool in (skill_invocation.get("recommended_tools") or [])
            if str(tool).strip() in candidate_tools
        ]
        if preferred:
            candidate_tools = preferred + [tool for tool in candidate_tools if tool not in preferred]

        invocation_record = {
            "invocation_id": skill_invocation.get("invocation_id"),
            "skill_id": selected_skill_id,
            "worker_group": group,
            "phase": resolved_phase,
            "purpose": purpose,
            "source": skill_invocation.get("source"),
            "matched_by": list(skill_invocation.get("matched_by") or []),
            "candidate_tools": list(skill_invocation.get("candidate_tools") or []),
            "recommended_tools": list(skill_invocation.get("recommended_tools") or []),
            "confidence": skill_invocation.get("confidence"),
            "playbook_title": skill_invocation.get("playbook_title"),
            "created_at": skill_invocation.get("created_at"),
        }
        invocations = list(state.get("skill_invocations") or [])
        invocations.append(invocation_record)
        state["skill_invocations"] = invocations[-80:]
        state["current_skill"] = selected_skill_id
        state["active_skill"] = selected_skill_id
        state["skill_contract"] = invocation_record
        state["skill_invocation"] = dict(skill_invocation)
        _append_action(state, "skill_invoked", invocation_record)
        state["logs_terminais"].append(
            f"[{group}] skill_call skill={selected_skill_id} "
            f"purpose={purpose} source={skill_invocation.get('source')} "
            f"tools={','.join(invocation_record['recommended_tools'][:6]) or '-'}"
        )
    except Exception as exc:
        state["logs_terminais"].append(f"[{group}] erro ao invocar skill service: {exc}")

    return skill_invocation, primary_skill, candidate_tools


def _select_tool_batch_for_iteration(state: AgentState, group: str, tools: list[str]) -> list[str]:
    """Returns every Kali-mapped tool applicable to the group, minus those
    that already ran successfully in this scan.

    The Kali runner ships every supported tool, so "is_tool_installed" reduces
    to "does this tool have a profile mapping in TOOL_TO_PROFILE". Tools that
    failed twice are also skipped to keep transient failures from looping.
    """
    if not tools:
        return []
    from app.services.tool_catalog import is_tool_installed

    ranked = _rank_tools_for_iteration(state, tools)
    runtime = dict(state.get("tool_runtime") or {})

    selected: list[str] = []
    no_profile: list[str] = []
    skipped_already_done: list[str] = []
    for t in ranked:
        if not is_tool_installed(t):
            no_profile.append(t)
            continue
        meta = runtime.get(t, {})
        if int(meta.get("success", 0) or 0) >= 1:
            skipped_already_done.append(t)
            continue
        if int(meta.get("attempts", 0) or 0) >= 1 and int(meta.get("success", 0) or 0) == 0:
            skipped_already_done.append(t)
            continue
        selected.append(t)

    if no_profile:
        state["logs_terminais"].append(
            f"[{group}] tools sem profile no Kali runner: {', '.join(sorted(no_profile))}"
        )
    if skipped_already_done:
        state["logs_terminais"].append(
            f"[{group}] tools já executadas no scan: {', '.join(sorted(skipped_already_done))}"
        )
    return selected


def _update_tool_runtime_metrics(state: AgentState, tool: str, status: str) -> None:
    runtime = dict(state.get("tool_runtime") or {})
    current = dict(runtime.get(tool, {}))
    current["attempts"] = int(current.get("attempts", 0)) + 1
    if status == "executed":
        current["success"] = int(current.get("success", 0)) + 1
    else:
        current["failures"] = int(current.get("failures", 0)) + 1
    runtime[tool] = current
    state["tool_runtime"] = runtime


def _find_node_with_uncovered_tools(state: AgentState) -> str | None:
    """Returns the first capability node that still has installed tools that
    haven't been executed in this scan. Drives the second-pass sweep.

    Order is intentional: asset_discovery feeds threat_intel feeds
    risk_assessment, so we re-enter from upstream -> downstream.
    """
    try:
        from app.services.tool_catalog import is_tool_installed
    except Exception:
        return None

    # Import here to avoid circular dependency
    from app.graph.workflow import _tools_for_group

    runtime = dict(state.get("tool_runtime") or {})

    def _has_uncovered(group_alias: str) -> bool:
        try:
            tools = _tools_for_group(state.get("scan_mode", "unit"), group_alias)
        except Exception:
            tools = []
        for t in tools:
            if not is_tool_installed(t):
                continue
            meta = runtime.get(t, {})
            if int(meta.get("success", 0) or 0) == 0 and int(meta.get("attempts", 0) or 0) < 2:
                return True
        return False

    if _has_uncovered("asset_discovery"):
        return "asset_discovery"
    if _has_uncovered("threat_intel"):
        return "threat_intel"
    if _has_uncovered("risk_assessment"):
        return "risk_assessment"
    return None


def _select_skill_for_capability(
    capability: str,
    active_skills: list[dict[str, Any]],
    scan_mode: str,
) -> dict[str, Any] | None:
    """Pick the best skill from active_skills for the given capability node.

    Returns a selected_skill dict with skill_id, allowed_tools, preferred_tool,
    objective, and reason — the supervisor's executable decision.
    Returns None only when active_skills is completely empty.
    """
    # Import here to avoid circular dependency
    from app.graph.workflow import _tools_for_group

    preferred_cats = set(CAPABILITY_SKILL_CATEGORIES.get(capability, ()))
    candidate_tools = _tools_for_group(scan_mode, capability)
    candidate_lower = {t.lower() for t in candidate_tools}

    best_skill: dict[str, Any] | None = None
    best_score = -1

    for skill in active_skills:
        cat = str(skill.get("category") or "").lower()
        skill_tool_lower = {str(t).lower() for t in (skill.get("playbook") or [])}
        score = 0
        if cat in preferred_cats:
            score += 10
        score += len(skill_tool_lower & candidate_lower) * 3
        if score > best_score:
            best_score = score
            best_skill = skill

    if not best_skill:
        if not active_skills:
            return None
        best_skill = dict(active_skills[0])

    skill_tools = [str(t) for t in (best_skill.get("playbook") or [])]
    # allowed_tools = skill playbook intersected with capability's candidate pool
    allowed_tools = [t for t in skill_tools if t.lower() in candidate_lower]
    if not allowed_tools:
        allowed_tools = [t for t in candidate_tools if t.lower() in {s.lower() for s in skill_tools}]
    if not allowed_tools:
        # Last resort: use the full capability catalog (capped)
        allowed_tools = candidate_tools[:8]

    preferred_tool = allowed_tools[0] if allowed_tools else ""

    return {
        "skill_id": str(best_skill.get("id") or capability),
        "capability": capability,
        "objective": str(best_skill.get("description") or f"Execute {capability} using {best_skill.get('id')}"),
        "allowed_tools": allowed_tools,
        "preferred_tool": preferred_tool,
        "reason": (
            f"Skill '{best_skill.get('id')}' selecionada para capability '{capability}' "
            f"(score={best_score}, categoria={best_skill.get('category')})"
        ),
    }


def _log_offensive_context(state: AgentState, next_node: str) -> None:
    """Logs the current offensive campaign state alongside the routing decision."""
    campaign = dict(state.get("campaign") or {})
    current_stage = str(campaign.get("current_stage") or "initial_access")
    active_hypotheses = list(state.get("active_hypotheses") or [])
    validated_chains = list(state.get("validated_chains") or [])
    noise_profile = str(state.get("noise_profile") or "balanced")
    phase_promotions = list(campaign.get("phase_promotions") or [])
    offensive_pq = list(state.get("offensive_priority_queue") or [])
    pentest_phase_id = str(state.get("current_pentest_phase_id") or "")

    state["logs_terminais"].append(
        "Supervisor[offensive]: "
        f"stage={current_stage} "
        f"noise={noise_profile} "
        f"hypotheses={len(active_hypotheses)} "
        f"chains={len(validated_chains)} "
        f"promotions={len(phase_promotions)} "
        f"priority_queue={len(offensive_pq)} "
        f"pentest_phase={pentest_phase_id} "
        f"routing_to={next_node}"
    )

    # Surface confirmed exploit chains as critical observations
    confirmed_chains = [c for c in validated_chains if c.get("is_fully_validated")]
    for chain in confirmed_chains[:3]:
        state["logs_terminais"].append(
            f"Supervisor[EXPLOIT_CHAIN_CONFIRMED]: {chain.get('name')} "
            f"cvss={chain.get('cvss_estimate')} "
            f"tags={chain.get('matched_tags')}"
        )
        _append_observation(
            state,
            f"CONFIRMED exploit chain: {chain.get('name')} — CVSS {chain.get('cvss_estimate')}. "
            f"{chain.get('recommendation', '')}",
            source="offensive_reasoning",
        )

    # Log promoted phases if they affected routing
    if offensive_pq:
        promoted_ids = [str(p.get("phase_id") or p.get("phase") or "") for p in offensive_pq[:3]]
        state["logs_terminais"].append(
            f"Supervisor[offensive]: priority_phases={promoted_ids} (offensive signal promotion)"
        )


def _validate_and_advance_phase(state: AgentState) -> None:
    """Validate the current pentest phase exit criteria and advance phase index if met.

    Called after each capability node completes. Never raises — logs silently on error.
    """
    try:
        from app.graph.workflow import validate_phase_exit_criteria, finalize_phase_in_ledger
        from app.services.skill_runtime import get_skill_by_id
    except ImportError:
        return

    phase_id = str(state.get("current_pentest_phase_id") or "").strip()
    if not phase_id:
        return

    phase_ledger = dict(state.get("phase_ledger") or {})
    entry = dict(phase_ledger.get(phase_id) or {})
    entry_status = str(entry.get("status") or "pending")
    if entry_status in ("completed", "skipped"):
        return

    # Retrieve skill contract for this phase if available
    skill_id = str((entry.get("skill_context") or {}).get("skill_id") or "")
    skill_contract: dict[str, Any] | None = None
    if skill_id:
        skill_contract = get_skill_by_id(skill_id)

    can_advance, status, reason = validate_phase_exit_criteria(state, phase_id)
    finalize_phase_in_ledger(state, phase_id, can_advance=can_advance, status=status, reason=reason)

    state["logs_terminais"].append(
        f"PhaseValidator[{phase_id}]: status={status} can_advance={can_advance} reason={reason[:120]}"
    )

    if can_advance and status in ("completed", "skipped", "partial"):
        from app.graph.workflow import route_next_required_phase
        next_phase = route_next_required_phase(state)
        if next_phase:
            state["current_pentest_phase_id"] = next_phase
            state["logs_terminais"].append(
                f"PhaseAdvance: {phase_id} → {next_phase} (can_advance={can_advance})"
            )
        else:
            state["logs_terminais"].append(
                f"PhaseAdvance: {phase_id} → all phases exhausted, setting objective_met"
            )
            state["objective_met"] = True


def supervisor_node(state: AgentState) -> AgentState:
    """Single decision-maker: roteia capacidades dinamicamente por confiança e evidência."""
    from time import perf_counter
    from app.graph.workflow import _metric_start, _metric_end, _sync_step_to_db

    started_at = _metric_start()
    _sync_step_to_db(state, "0. Supervisor")

    # Kill switch: proteção contra loops infinitos
    state["loop_iteration"] = int(state.get("loop_iteration", 0)) + 1
    max_iterations = int(state.get("max_iterations", 12))
    if state["loop_iteration"] > max_iterations:
        state["routing_next_node"] = END
        state["termination_reason"] = "max_iterations_reached"
        state["objective_met"] = True
        return state

    _update_execution_guardrails(state)
    _refresh_active_skills(state)
    # completed_capabilities deve ser sempre list
    if "completed_capabilities" not in state or not isinstance(state["completed_capabilities"], list):
        state["completed_capabilities"] = []
    completed = list(state.get("completed_capabilities") or [])
    last_node = str(state.get("last_completed_node") or "").strip()
    pending_validation = list(state.get("validation_backlog") or [])

    capability_nodes = {"governance", "executive_analyst"}
    if last_node in capability_nodes:
        if last_node not in completed:
            completed.append(last_node)
            state["completed_capabilities"] = completed
        # always close any pending delegation task for the node we just left
        _complete_delegation_task(state, last_node, f"capability_executed:{last_node}")

    # ── Phase ledger validation after each capability node ───────────────────
    # When a capability node just ran, validate the current pentest phase and
    # advance pentest_phase_index when exit criteria are met.
    if last_node in TOOL_CAPABILITY_NODES | capability_nodes:
        _validate_and_advance_phase(state)

    confidence = int((state.get("confidence_state") or {}).get("global_confidence", 60))
    high_signals = _count_high_signal_findings(state)
    has_strong_evidence = _has_verified_or_strong_evidence(state)

    if confidence < ANALYST_CONFIDENCE_THRESHOLDS["medium"]:
        _register_delegation_task(state, node="asset_discovery", reason="low_confidence_expand_surface", priority=1)
        _register_delegation_task(state, node="threat_intel", reason="low_confidence_collect_intel", priority=2)
    elif confidence < ANALYST_CONFIDENCE_THRESHOLDS["high"]:
        _register_delegation_task(state, node="threat_intel", reason="medium_confidence_collect_more_context", priority=2)
    else:
        _register_delegation_task(state, node="risk_assessment", reason="high_confidence_validate_exploitability", priority=1)

    next_node = "END"
    termination_reason = str(state.get("termination_reason") or "")

    if pending_validation:
        _register_delegation_task(
            state,
            node="risk_assessment",
            reason=f"validation_backlog={len(pending_validation)}",
            priority=0,
        )

    if state.get("objective_met"):
        if "executive_analyst" not in completed:
            next_node = "executive_analyst"
        else:
            next_node = "END"
            termination_reason = termination_reason or "objective_already_met"
    elif "asset_discovery" not in completed:
        next_node = "asset_discovery"
    elif "threat_intel" not in completed:
        next_node = "threat_intel"
    elif "risk_assessment" not in completed:
        next_node = "risk_assessment"
    elif "governance" not in completed:
        next_node = "governance"
    elif "executive_analyst" not in completed:
        # Segunda passada de cobertura SOMENTE quando coverage_mode está explicitamente
        # habilitado. Por padrão o fluxo segue direto para o analista executivo.
        ctrl_now = dict(state.get("execution_control") or {})
        coverage_mode_active = bool(ctrl_now.get("coverage_mode", False))
        coverage_gap_node = (
            _find_node_with_uncovered_tools(state)
            if coverage_mode_active
            else None
        )
        if coverage_gap_node and int(state.get("loop_iteration", 0)) < max_iterations - 2:
            _append_note(
                state,
                f"Segunda passada (coverage_mode=true): {coverage_gap_node} ainda tem profiles sem rodar.",
                phase="coverage-sweep",
            )
            next_node = coverage_gap_node
        else:
            state["objective_met"] = state.get("objective_met") or has_strong_evidence
            termination_reason = termination_reason or "post_governance_executive_close"
            next_node = "executive_analyst"
    else:
        # Loop adaptativo após primeiro ciclo completo (incluindo executive_analyst)
        if pending_validation:
            next_node = "risk_assessment"
        else:
            next_node = "END"
            termination_reason = termination_reason or "full_cycle_completed"

    ctrl = dict(state.get("execution_control") or {})
    remaining = int(ctrl.get("remaining_iterations", max_iterations))
    if bool(ctrl.get("paused", False)) and next_node == "risk_assessment":
        _append_note(state, "Execução pausada por estagnação; aplicando pivô para coleta de novo contexto.", phase="execution-control")
        next_node = "threat_intel"
    if remaining <= 2 and next_node not in {"governance", "executive_analyst", "END"}:
        _append_note(state, "Forçando finalização contextual por orçamento baixo.", phase="execution-control")
        next_node = "governance" if "governance" not in completed else "executive_analyst"
        termination_reason = termination_reason or "forced_finalize_guardrail"

    # Delegation override only after FULL cycle (essential + executive_analyst).
    # Sem isso, delegação atropelava o caminho sequencial e voltava para fases já feitas.
    essential_phases = {"asset_discovery", "threat_intel", "risk_assessment", "governance"}
    full_cycle_done = essential_phases.issubset(set(completed)) and "executive_analyst" in completed
    if full_cycle_done:
        for delegated in list(state.get("delegated_tasks") or []):
            if str(delegated.get("status") or "") != "pending":
                continue
            delegated_node = str(delegated.get("node") or "")
            if delegated_node in essential_phases:
                next_node = delegated_node
                break

    # Proteção contra loop do mesmo node
    current_phase = str(state.get("current_phase") or "").strip()
    if next_node == current_phase and next_node not in {"END", ""}:
        state["routing_next_node"] = END
        state["termination_reason"] = "loop_on_same_phase"
        state["completed_capabilities"] = completed
        state["current_phase"] = next_node
        return state

    route_node = "skill_selector" if next_node in TOOL_CAPABILITY_NODES else next_node

    # ── Avaliação do relatório do agente (ciclo anterior) ────────────────────
    _evaluate_agent_report(state, next_node)

    # ── Skill selection: supervisor commits to a skill before the pipeline ─────
    # Always clear the previous iteration's selected_skill to avoid stale state.
    state["selected_skill"] = {}
    if next_node in TOOL_CAPABILITY_NODES:
        state["pending_capability_node"] = next_node
        chosen_skill = _select_skill_for_capability(
            capability=next_node,
            active_skills=list(state.get("active_skills") or []),
            scan_mode=str(state.get("scan_mode") or "unit"),
        )
        if chosen_skill:
            state["selected_skill"] = chosen_skill
            state["logs_terminais"].append(
                f"Supervisor: skill={chosen_skill['skill_id']} "
                f"capability={next_node} "
                f"allowed_tools={chosen_skill['allowed_tools'][:4]} "
                f"preferred={chosen_skill['preferred_tool']}"
            )
        else:
            state["logs_terminais"].append(
                f"Supervisor: capability={next_node} sem skills ativas; pipeline seguirá sem selected_skill"
            )

        # ── Emite ActivityDemand explícita para o agente ──────────────────────
        _emit_activity_demand(state, next_node)

    elif next_node != "END":
        state["pending_capability_node"] = ""

    state["completed_capabilities"] = completed
    state["current_phase"] = next_node
    state["routing_next_node"] = END if route_node == "END" else route_node
    state["termination_reason"] = termination_reason
    state["proxima_ferramenta"] = route_node

    # Offensive context — read after all routing decisions are made
    _campaign = dict(state.get("campaign") or {})
    _current_stage = str(_campaign.get("current_stage") or "initial_access")
    _noise_profile = str(state.get("noise_profile") or "balanced")
    _n_hypotheses = len(list(state.get("active_hypotheses") or []))
    _n_chains = len(list(state.get("validated_chains") or []))
    _pentest_phase_id = str(state.get("current_pentest_phase_id") or "")

    state["logs_terminais"].append(
        "Supervisor: "
        f"iter={state['loop_iteration']}/{max_iterations} "
        f"confidence={confidence} "
        f"high_signals={high_signals} "
        f"skills={len(state.get('active_skills') or [])} "
        f"pending_validation={len(pending_validation)} "
        f"stage={_current_stage} "
        f"noise={_noise_profile} "
        f"hypotheses={_n_hypotheses} "
        f"chains={_n_chains} "
        f"pentest_phase={_pentest_phase_id} "
        f"next={next_node}"
    )
    _log_offensive_context(state, next_node)
    _append_action(
        state,
        "supervisor_route",
        {
            "next_node": next_node,
            "confidence": confidence,
            "high_signals": high_signals,
            "pending_validation": len(pending_validation),
            "activity_demand": dict(state.get("current_activity_demand") or {}),
            "offensive_stage": _current_stage,
            "noise_profile": _noise_profile,
            "active_hypotheses": _n_hypotheses,
            "validated_chains": _n_chains,
            "pentest_phase_id": _pentest_phase_id,
        },
    )

    _metric_end(state, "supervisor", started_at)
    _sync_step_to_db(state, "0. Supervisor")
    return state


# ── Helpers do ciclo supervisor ↔ agente ──────────────────────────────────────


def _emit_activity_demand(state: AgentState, capability: str) -> None:
    """Cria e persiste a demanda de atividade que o supervisor envia ao agente."""
    from app.services.skill_library_service import get_activity_demand_for_capability, create_agent_activity_log
    from app.db.session import SessionLocal

    iteration = int(state.get("loop_iteration", 0))
    target = str(state.get("target") or "")
    done_types = list(state.get("completed_activity_types") or [])

    demand = get_activity_demand_for_capability(
        capability=capability,
        iteration=iteration,
        target=target,
        already_done=done_types,
    )
    state["current_activity_demand"] = demand

    # Persiste no banco para visibilidade na UI
    scan_id = state.get("scan_id")
    if scan_id:
        try:
            db = SessionLocal()
            log_id = create_agent_activity_log(db, scan_id, iteration, demand)
            state["current_activity_log_id"] = log_id
            db.close()
        except Exception as exc:
            state["logs_terminais"].append(f"[Supervisor] falha ao criar activity_log: {exc}")

    state["logs_terminais"].append(
        f"[Supervisor→Agente] Demanda emitida: activity_type={demand['activity_type']} "
        f"capability={capability} phases={demand.get('kill_chain_phases')} "
        f"objetivo='{demand['objective'][:80]}'"
    )


def _evaluate_agent_report(state: AgentState, next_node: str) -> None:
    """Avalia o relatório do agente recebido após execução e persiste a avaliação."""
    from datetime import datetime as _dt
    from app.services.skill_library_service import update_agent_activity_log
    from app.db.session import SessionLocal

    report = dict(state.get("agent_report") or {})
    if not report or not report.get("activity_id"):
        return

    # Já avaliado nesta iteração?
    evaluations = list(state.get("supervisor_evaluations") or [])
    if any(e.get("activity_id") == report.get("activity_id") for e in evaluations):
        return

    quality_score = float(report.get("quality_score", 0.0))
    findings_count = int(report.get("findings_count", 0))
    tool_used = str(report.get("tool_used") or "")
    operation_performed = str(report.get("operation_performed") or "")

    # Critério de aprovação: qualidade ≥ 0.5 ou pelo menos 1 finding, e operação realizada
    approved = (quality_score >= 0.5 or findings_count >= 1) and bool(operation_performed)

    reason = (
        f"quality_score={quality_score:.2f} findings={findings_count} tool={tool_used}"
    )
    if approved:
        next_phase = _determine_next_kill_chain_phase(state, report)
        quality_assessment = "Atividade satisfatória — dados coletados e operação realizada."
    else:
        next_phase = str(state.get("current_phase") or "")
        quality_assessment = (
            "Atividade insatisfatória — sem dados coletados ou operação não realizada."
        )

    evaluation = {
        "activity_id": report.get("activity_id"),
        "activity_type": report.get("activity_type", ""),
        "capability": report.get("capability", ""),
        "tool_used": tool_used,
        "approved": approved,
        "reason": reason,
        "quality_assessment": quality_assessment,
        "next_phase": next_phase,
        "evaluated_at": _dt.utcnow().isoformat(),
        "iteration": int(state.get("loop_iteration", 0)),
    }
    evaluations.append(evaluation)
    state["supervisor_evaluations"] = evaluations

    # Registra activity_type como concluído
    if approved:
        done = list(state.get("completed_activity_types") or [])
        atype = str(report.get("activity_type") or "")
        if atype and atype not in done:
            done.append(atype)
            state["completed_activity_types"] = done
        _update_kill_chain_progress(state, report, approved=True)

    # Persiste avaliação no banco
    log_id = state.get("current_activity_log_id")
    scan_id = state.get("scan_id")
    if log_id and scan_id:
        try:
            db = SessionLocal()
            update_agent_activity_log(
                db,
                log_id,
                supervisor_evaluation=evaluation,
                approved=approved,
                status="approved" if approved else "rejected",
            )
            db.close()
        except Exception as exc:
            state["logs_terminais"].append(f"[Supervisor] falha ao atualizar activity_log: {exc}")

    _append_action(state, "supervisor_evaluated_report", evaluation)
    state["logs_terminais"].append(
        f"[Supervisor←Agente] Avaliação: activity={report.get('activity_type')} "
        f"approved={approved} {quality_assessment}"
    )


def _determine_next_kill_chain_phase(state: AgentState, report: dict) -> str:
    phases = list(report.get("kill_chain_phases") or [])
    return phases[0] if phases else str(state.get("current_phase") or "")


def _update_kill_chain_progress(state: AgentState, report: dict, approved: bool) -> None:
    progress = dict(state.get("kill_chain_progress") or {})
    phases = list(report.get("kill_chain_phases") or [])
    atype = str(report.get("activity_type") or "")

    for phase in phases:
        entry = dict(progress.get(phase) or {})
        acts = list(entry.get("approved_activities") or [])
        if atype and atype not in acts:
            acts.append(atype)
        entry["approved_activities"] = acts
        entry["status"] = "approved" if approved else "pending"
        progress[phase] = entry

    state["kill_chain_progress"] = progress
