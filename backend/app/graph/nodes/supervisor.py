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
        max_skills=8,
        detected_tech_stack=list(state.get("detected_tech_stack") or []),
    )
    prev_ids = {str(item.get("id") or "") for item in list(state.get("active_skills") or [])}
    state["active_skills"] = selected
    selected_ids = [str(item.get("id") or "") for item in selected]
    if set(selected_ids) != prev_ids:
        _append_note(state, f"Skills ativas atualizadas: {', '.join(selected_ids)}", phase="skill-selection")
    # Consumed: clear pending_skill_refresh hint set by skill_pipeline when
    # the tech-stack signature changed last iteration.
    if state.get("pending_skill_refresh"):
        state["pending_skill_refresh"] = False


def _auto_lock_tactic_from_tech_stack(state: AgentState) -> dict[str, Any] | None:
    """Builds a high-priority pentest tactic from detected_tech_stack.

    Returns the tactic dict (also stored in state["pending_pentest_tactic"])
    when a matching tag is present and the tactic was not already completed.
    Returns None when no auto-lock applies — the regular strategy queue path
    handles fallback in that case.
    """
    try:
        from app.services.tech_stack_detector import TECH_STACK_TACTIC_LOCKS
    except Exception:
        return None

    stack = [str(item).strip().lower() for item in (state.get("detected_tech_stack") or [])]
    if not stack:
        return None

    completed_ids = _completed_pentest_tactic_ids(state)
    pending_existing = dict(state.get("pending_pentest_tactic") or {})
    if pending_existing.get("tactic_id", "").startswith("tech-stack:"):
        # Already locked from a previous iteration; honour it instead of
        # rebuilding on every supervisor pass.
        if str(pending_existing.get("tactic_id") or "") not in completed_ids:
            return pending_existing

    for tag in stack:
        spec = TECH_STACK_TACTIC_LOCKS.get(tag)
        if not spec:
            continue
        tactic_id = f"tech-stack:{tag}:{spec['skill_id']}"
        if tactic_id in completed_ids:
            continue
        tactic = {
            "tactic_id": tactic_id,
            "skill_id": spec["skill_id"],
            "capability": spec["capability"],
            "objective": f"Auto-lock por fingerprint do ambiente: {tag}.",
            "hypothesis": spec.get("hypothesis", ""),
            "allowed_tools": list(spec.get("allowed_tools") or []),
            "preferred_tool": spec.get("preferred_tool", ""),
            "extra_args": dict(spec.get("extra_args") or {}),
            "strategy_source": "tech_stack_auto_lock",
            "strategy_score": 95,
            "learning_techniques": [],
            "evidence_required": [],
            "constraints": [],
            "phase_refs": [],
            "targets": [],
            "reason": f"detected_tech_stack contains '{tag}' → lock skill '{spec['skill_id']}' on capability '{spec['capability']}'",
        }
        state["pending_pentest_tactic"] = tactic
        _append_action(state, "tech_stack_auto_lock", {
            "tag": tag,
            "tactic_id": tactic_id,
            "skill_id": spec["skill_id"],
            "preferred_tool": spec.get("preferred_tool"),
            "extra_args_keys": list((spec.get("extra_args") or {}).keys()),
        })
        state.setdefault("logs_terminais", []).append(
            f"[supervisor] tech_stack auto-lock tag={tag} → skill={spec['skill_id']} "
            f"tool={spec.get('preferred_tool')} extra_args={list((spec.get('extra_args') or {}).keys())}"
        )
        return tactic
    return None


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


def _completed_pentest_tactic_ids(state: AgentState) -> set[str]:
    return {
        str(item.get("tactic_id") or "")
        for item in list(state.get("pentest_tactics_completed") or [])
        if isinstance(item, dict) and str(item.get("tactic_id") or "").strip()
    }


def _ensure_pentest_strategy(state: AgentState) -> dict[str, Any]:
    strategy = dict(state.get("pentest_strategy") or {})
    queue = list(strategy.get("queue") or [])
    completed_ids = _completed_pentest_tactic_ids(state)
    has_pending = any(
        str(item.get("tactic_id") or "") not in completed_ids
        for item in queue
        if isinstance(item, dict)
    )
    if has_pending:
        return strategy

    try:
        from app.services.pentest_strategy_service import build_pentest_strategy

        strategy = build_pentest_strategy(dict(state), max_items=8)
    except Exception as exc:
        logger.warning("pentest strategy build failed: %s", exc)
        strategy = {
            "mode": "pentest_strategy",
            "queue": [],
            "error": f"{type(exc).__name__}: {exc}",
        }

    state["pentest_strategy"] = strategy
    _append_action(
        state,
        "pentest_strategy_built",
        {
            "items": len(strategy.get("queue") or []),
            "candidate_count": strategy.get("candidate_count"),
            "mcp_rag_hits": strategy.get("mcp_rag_hits"),
            "llm": strategy.get("llm"),
        },
    )
    state["logs_terminais"].append(
        "SupervisorStrategy: "
        f"items={len(strategy.get('queue') or [])} "
        f"candidates={strategy.get('candidate_count', 0)} "
        f"rag_hits={strategy.get('mcp_rag_hits', 0)} "
        f"llm_used={bool((strategy.get('llm') or {}).get('used'))}"
    )
    return strategy


def _next_pentest_tactic(state: AgentState) -> dict[str, Any] | None:
    strategy = _ensure_pentest_strategy(state)
    completed_ids = _completed_pentest_tactic_ids(state)
    for item in list(strategy.get("queue") or []):
        if not isinstance(item, dict):
            continue
        tactic_id = str(item.get("tactic_id") or "")
        if tactic_id and tactic_id not in completed_ids:
            state["pending_pentest_tactic"] = dict(item)
            return dict(item)
    state["pending_pentest_tactic"] = {}
    return None


def _selected_skill_from_tactic(tactic: dict[str, Any]) -> dict[str, Any]:
    return {
        "skill_id": str(tactic.get("skill_id") or ""),
        "capability": str(tactic.get("capability") or ""),
        "objective": str(tactic.get("objective") or ""),
        "allowed_tools": list(tactic.get("allowed_tools") or []),
        "preferred_tool": str(tactic.get("preferred_tool") or ""),
        "reason": str(tactic.get("reason") or ""),
        "tactic_id": str(tactic.get("tactic_id") or ""),
        "hypothesis": str(tactic.get("hypothesis") or ""),
        "strategy_source": str(tactic.get("strategy_source") or ""),
        "strategy_score": tactic.get("strategy_score"),
        "learning_guided": bool(tactic.get("learning_techniques")),
        "learning_techniques": list(tactic.get("learning_techniques") or []),
        "evidence_required": list(tactic.get("evidence_required") or []),
        "constraints": list(tactic.get("constraints") or []),
        "phase_refs": list(tactic.get("phase_refs") or []),
        "targets": list(tactic.get("targets") or []),
        # Per-tool extra_args propagated to the Kali runner via the workflow's
        # `technique_extra_args_by_tool` extractor (see _run_tools_and_collect).
        "extra_args": dict(tactic.get("extra_args") or {}),
        "lock_skill": True,
    }


def _select_skill_for_capability(
    capability: str,
    active_skills: list[dict[str, Any]],
    scan_mode: str,
    tech_stack: list[str] | None = None,
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

    learning_playbook: dict[str, Any] | None = None
    learning_invocation: dict[str, Any] = {}
    try:
        from app.services.vulnerability_learning_service import build_runtime_learning_playbook
        from app.services.skill_runtime import resolve_skill_invocation

        learning_playbook = build_runtime_learning_playbook(
            candidate_tools=candidate_tools,
            phase=capability,
            limit=16,
            tech_stack=tech_stack,
        )
        if learning_playbook:
            learning_invocation = resolve_skill_invocation(
                worker_group=capability,
                phase=capability,
                target="",
                candidate_tools=candidate_tools,
                active_skills=active_skills,
                playbook=learning_playbook,
                tech_stack=tech_stack,
            )
    except Exception as exc:
        logger.debug("learning-guided skill selection unavailable: %s", exc)

    if learning_invocation.get("called"):
        skill = dict(learning_invocation.get("skill") or {})
        recommended = [
            str(tool)
            for tool in list(learning_invocation.get("recommended_tools") or [])
            if str(tool).strip()
        ]
        if not recommended:
            recommended = [
                str(tool)
                for tool in list(learning_invocation.get("learned_recommended_tools") or [])
                if str(tool).strip().lower() in candidate_lower
            ]
        allowed_tools = recommended or [
            str(tool)
            for tool in list(skill.get("playbook") or [])
            if str(tool).strip().lower() in candidate_lower
        ]
        if allowed_tools:
            source_ids = [
                str(item.get("source_learning_id"))
                for item in list(learning_invocation.get("techniques") or [])
                if isinstance(item, dict) and item.get("source_learning_id")
            ]
            technique = next(
                (
                    str(item.get("name") or "")
                    for item in list(learning_invocation.get("techniques") or [])
                    if isinstance(item, dict) and str(item.get("name") or "").strip()
                ),
                "",
            )
            return {
                "skill_id": str(learning_invocation.get("skill_id") or skill.get("id") or capability),
                "capability": capability,
                "objective": str(skill.get("description") or (learning_playbook or {}).get("learned_mission") or f"Execute {capability} com aprendizado aceito"),
                "allowed_tools": list(dict.fromkeys(allowed_tools))[:8],
                "preferred_tool": allowed_tools[0],
                "reason": (
                    "Skill selecionada por aprendizado aceito "
                    f"(source={learning_invocation.get('source')}, "
                    f"technique={technique or '-'}, "
                    f"learning_ids={','.join(list(dict.fromkeys(source_ids))[:5]) or '-'})"
                ),
                "learning_guided": True,
                "learning_playbook_title": (learning_playbook or {}).get("title"),
                "learning_techniques": list(learning_invocation.get("techniques") or [])[:8],
                "learning_sources": list((learning_playbook or {}).get("sources") or [])[:8],
                "matched_by": list(learning_invocation.get("matched_by") or []),
            }

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
    ctrl = dict(state.get("execution_control") or {})
    remaining = int(ctrl.get("remaining_iterations", max_iterations))

    if pending_validation:
        _register_delegation_task(
            state,
            node="risk_assessment",
            reason=f"validation_backlog={len(pending_validation)}",
            priority=0,
        )

    next_tactic: dict[str, Any] | None = None
    if not state.get("objective_met") and remaining > 2:
        next_tactic = _next_pentest_tactic(state)

    if next_tactic:
        next_node = str(next_tactic.get("capability") or "risk_assessment")
        termination_reason = ""
    elif state.get("objective_met"):
        if "executive_analyst" not in completed:
            next_node = "executive_analyst"
        else:
            next_node = "END"
            termination_reason = termination_reason or "objective_already_met"
    elif state.get("pentest_strategy") and list((state.get("pentest_strategy") or {}).get("queue") or []):
        # The tactical pentest queue is the source of truth. Once exhausted, close
        # with governance/executive analysis instead of falling back to a generic
        # vulnerability-assessment pass.
        if "governance" not in completed:
            next_node = "governance"
        elif "executive_analyst" not in completed:
            next_node = "executive_analyst"
        else:
            next_node = "END"
            termination_reason = termination_reason or "pentest_tactic_queue_completed"
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
        pending_tactic = dict(state.get("pending_pentest_tactic") or {})
        pending_id = str(pending_tactic.get("tactic_id") or "")
        if not pending_id or pending_id in _completed_pentest_tactic_ids(state):
            state["routing_next_node"] = END
            state["termination_reason"] = "loop_on_same_phase"
            state["completed_capabilities"] = completed
            state["current_phase"] = next_node
            return state

    route_node = "skill_selector" if next_node in TOOL_CAPABILITY_NODES else next_node

    # ── Skill selection: supervisor commits to a skill before the pipeline ─────
    # Always clear the previous iteration's selected_skill to avoid stale state.
    state["selected_skill"] = {}
    state["capability_context"] = {}
    if next_node in TOOL_CAPABILITY_NODES:
        state["pending_capability_node"] = next_node
        # Tech-stack auto-lock takes precedence over both the strategy queue
        # and the heuristic selector: when fingerprint matches a locked tactic
        # we force that path so the supervisor cannot drift away from the
        # environment-specific skill (e.g. ASP/MSSQL → vuln-injection sqlmap).
        auto_locked_tactic = _auto_lock_tactic_from_tech_stack(state)
        if auto_locked_tactic and str(auto_locked_tactic.get("capability") or "") == next_node:
            chosen_skill = _selected_skill_from_tactic(auto_locked_tactic)
        elif next_tactic:
            chosen_skill = _selected_skill_from_tactic(next_tactic)
        else:
            chosen_skill = _select_skill_for_capability(
                capability=next_node,
                active_skills=list(state.get("active_skills") or []),
                scan_mode=str(state.get("scan_mode") or "unit"),
                tech_stack=list(state.get("detected_tech_stack") or []),
            )
        if chosen_skill:
            state["selected_skill"] = chosen_skill
            if chosen_skill.get("tactic_id"):
                state["capability_context"] = {
                    "node": next_node,
                    "candidate_tools": list(chosen_skill.get("allowed_tools") or []),
                    "targets": list(chosen_skill.get("targets") or []),
                    "tactic_id": chosen_skill.get("tactic_id"),
                    "hypothesis": chosen_skill.get("hypothesis"),
                    "strategy_source": chosen_skill.get("strategy_source"),
                }
            state["logs_terminais"].append(
                f"Supervisor: skill={chosen_skill['skill_id']} "
                f"capability={next_node} "
                f"allowed_tools={chosen_skill['allowed_tools'][:4]} "
                f"preferred={chosen_skill['preferred_tool']} "
                f"tactic={chosen_skill.get('tactic_id') or '-'}"
            )
            try:
                from app.graph.tracer import emit_trace as _emit_trace
                _scan_id = state.get("scan_id")
                if _scan_id:
                    _emit_trace(
                        scan_id=int(_scan_id),
                        iteration=int(state.get("loop_iteration", 0)),
                        event_type="supervisor_dispatch",
                        from_node="supervisor",
                        to_node="agent",
                        skill_id=chosen_skill.get("skill_id"),
                        tool_name=chosen_skill.get("preferred_tool") or None,
                        capability=next_node,
                        status="pending",
                        payload={
                            "capability": next_node,
                            "objective": chosen_skill.get("objective", ""),
                            "hypothesis": chosen_skill.get("hypothesis", ""),
                            "tactic_id": chosen_skill.get("tactic_id", ""),
                            "strategy_source": chosen_skill.get("strategy_source", ""),
                            "technique": (
                                list(chosen_skill.get("learning_techniques") or [{}])[0]
                                if chosen_skill.get("learning_techniques")
                                else {}
                            ).get("name", ""),
                            "evidence_required": list(chosen_skill.get("evidence_required") or [])[:6],
                            "targets": list(chosen_skill.get("targets") or [])[:3],
                            "allowed_tools": chosen_skill.get("allowed_tools", [])[:4],
                        },
                    )
            except Exception:
                pass
        else:
            state["logs_terminais"].append(
                f"Supervisor: capability={next_node} sem skills ativas; pipeline seguirá sem selected_skill"
            )
    elif next_node != "END":
        state["pending_capability_node"] = ""

    state["completed_capabilities"] = completed
    state["current_phase"] = next_node
    state["routing_next_node"] = END if route_node == "END" else route_node
    state["termination_reason"] = termination_reason
    state["proxima_ferramenta"] = route_node
    state["logs_terminais"].append(
        "Supervisor: "
        f"iter={state['loop_iteration']}/{max_iterations} "
        f"confidence={confidence} "
        f"high_signals={high_signals} "
        f"skills={len(state.get('active_skills') or [])} "
        f"pending_validation={len(pending_validation)} "
        f"next={next_node}"
    )
    _append_action(
        state,
        "supervisor_route",
        {
            "next_node": next_node,
            "confidence": confidence,
            "high_signals": high_signals,
            "pending_validation": len(pending_validation),
        },
    )

    _metric_end(state, "supervisor", started_at)
    _sync_step_to_db(state, "0. Supervisor")
    return state
