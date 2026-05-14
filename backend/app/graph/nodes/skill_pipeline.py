from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import uuid4

from app.graph.state import AgentState, TOOL_CAPABILITY_NODES

logger = logging.getLogger(__name__)


def rag_enrichment_node(state: AgentState) -> AgentState:
    """RAG enrichment node: enriches prompts and context with knowledge base."""
    from app.graph.workflow import _metric_start, _metric_end, _sync_step_to_db

    started_at = _metric_start()
    _sync_step_to_db(state, "RAG Enrichment")

    try:
        from app.core.config import settings
        from app.services.mcp_client import mcp_client

        if not settings.mcp_rag_enabled or not mcp_client.health_check_sync():
            state["logs_terminais"].append("[RAG] MCP server not available, skipping enrichment")
            _metric_end(state, "rag_enrichment", started_at)
            return state

        # Enrich current context with RAG knowledge
        target_info = {
            "target": state.get("target", ""),
            "phase": state.get("current_phase", ""),
            "tools": list(state.get("executed_tool_runs", []))[:5],  # Recent tools
        }

        # Determine context type based on current phase
        phase = str(state.get("current_phase", "")).lower()
        if "recon" in phase or "discovery" in phase:
            context_type = "reconnaissance"
        elif "vuln" in phase or "assessment" in phase:
            context_type = "vulnerability_analysis"
        elif "exploit" in phase or "weaponization" in phase:
            context_type = "tool_usage"
        else:
            context_type = "vulnerability_analysis"

        patterns = mcp_client.query_knowledge_sync(
            query=f"{context_type} target {target_info['target']} phase {phase}",
            top_k=5,
            skill=str(state.get("current_phase") or "") or None,
        )

        if patterns:
            state["logs_terminais"].append(
                f"[RAG] Found {len(patterns)} relevant patterns for {context_type}"
            )

            # Store patterns in state for use by other nodes
            state.setdefault("rag_patterns", []).extend(patterns[:5])

            # Store learning insights for future use
            for pattern in patterns[:3]:
                insight = f"Pattern identified: {pattern.get('content', '')[:200]}..."
                metadata = {
                    "source": "rag_enrichment",
                    "phase": phase,
                    "target": target_info["target"],
                    "pattern_type": pattern.get("metadata", {}).get("type", "unknown")
                }
                mcp_client.ingest_document_sync(
                    content=insight,
                    metadata=metadata,
                    source="rag_enrichment",
                )

        # Enrich prompts for upcoming LLM calls
        state["rag_enriched"] = True
        state["logs_terminais"].append("[RAG] Context enrichment completed")

    except Exception as exc:
        state["logs_terminais"].append(f"[RAG] Enrichment failed: {exc}")
        logger.warning(f"RAG enrichment failed: {exc}")

    _metric_end(state, "rag_enrichment", started_at)
    return state


def _bootstrap_skill_group(state: AgentState) -> str:
    pending = str(state.get("pending_capability_node") or "").strip()
    if pending in TOOL_CAPABILITY_NODES:
        return pending
    next_node = str(state.get("routing_next_node") or "").strip()
    if next_node in TOOL_CAPABILITY_NODES:
        return next_node
    current = str(state.get("current_phase") or "").strip()
    if current in TOOL_CAPABILITY_NODES:
        return current
    return "asset_discovery"


def _candidate_tools_for_skill_bootstrap(state: AgentState, group: str) -> list[str]:
    from app.graph.workflow import _tools_for_group, _adapt_recon_tools_for_target, _adapt_vuln_tools_for_target
    from app.graph.nodes.supervisor import _select_tool_batch_for_iteration

    context = dict(state.get("capability_context") or {})
    if str(context.get("node") or "") == group and context.get("candidate_tools"):
        return _select_tool_batch_for_iteration(
            state,
            group=group,
            tools=[str(tool) for tool in list(context.get("candidate_tools") or [])],
        )
    scan_mode = str(state.get("scan_mode") or "unit")
    tools = _tools_for_group(scan_mode, group)
    target = str(state.get("target") or "")
    if group == "asset_discovery":
        tools = _adapt_recon_tools_for_target(target, tools)
        if str(state.get("target_type") or "") == "site":
            subdomain_expansion_tools = {"amass", "sublist3r", "massdns"}
            tools = [t for t in tools if t not in subdomain_expansion_tools]
    elif group == "risk_assessment":
        tools = _adapt_vuln_tools_for_target(target, tools)
    return _select_tool_batch_for_iteration(state, group=group, tools=tools)


def skill_selector_node(state: AgentState) -> AgentState:
    """Validate/enrich the supervisor's selected_skill and materialise the skill contract.

    When the supervisor has already committed to a skill (state["selected_skill"] is
    populated), this node uses that as the authoritative source — it never overrides
    the supervisor's choice with active_skills[0] or an inferred skill.

    When selected_skill is absent (e.g., unit tests calling this node directly), the
    node falls back to the original scored-inference logic for backward compatibility.
    """
    from app.graph.workflow import _metric_start, _metric_end, _sync_step_to_db
    from app.graph.nodes.supervisor import (
        _refresh_active_skills,
        _append_action,
        _build_skill_playbook_for_context,
        _invoke_skill_for_context,
    )

    started_at = _metric_start()
    _sync_step_to_db(state, "Skill Selector")

    try:
        from app.graph.tracer import emit_trace as _emit_trace
        _trace_scan_id = state.get("scan_id")
        _trace_iter = int(state.get("loop_iteration", 0))
        _trace_cap = str(state.get("pending_capability_node") or state.get("current_phase") or "")
        if _trace_scan_id:
            _emit_trace(
                scan_id=int(_trace_scan_id), iteration=_trace_iter,
                event_type="skill_lookup", from_node="agent", to_node="library",
                capability=_trace_cap, status="pending",
                payload={"phase": _trace_cap},
            )
    except Exception:
        pass

    try:
        _refresh_active_skills(state)
        group = _bootstrap_skill_group(state)
        phase_label = str(state.get("current_phase") or group)
        candidate_tools = _candidate_tools_for_skill_bootstrap(state, group)
        skills = list(state.get("active_skills") or [])

        supervisor_selected = dict(state.get("selected_skill") or {})
        supervisor_skill_id = str(supervisor_selected.get("skill_id") or "").strip()

        if supervisor_skill_id:
            # ── Supervisor-driven path: use selected_skill as source of truth ──
            allowed_tools = list(supervisor_selected.get("allowed_tools") or [])
            preferred_tool = str(supervisor_selected.get("preferred_tool") or "").strip().lower()
            lock_skill = bool(supervisor_selected.get("lock_skill"))
            allowed_lower = {t.lower() for t in allowed_tools}

            # candidate_tools filtered to what the skill permits
            guided_tools = [t for t in candidate_tools if t.lower() in allowed_lower]
            if not guided_tools and allowed_tools:
                # allowed_tools may name tools not in the current candidate pool; keep them
                guided_tools = allowed_tools

            # Locate the full skill object (for techniques, triggers, etc.)
            from app.graph.mission import SKILL_CATALOG as _SC
            skill_obj = next(
                (dict(s) for s in _SC if str(s.get("id") or "") == supervisor_skill_id),
                None,
            )
            if skill_obj is None:
                skill_obj = next(
                    (dict(s) for s in skills if str(s.get("id") or "") == supervisor_skill_id),
                    None,
                )
            if skill_obj is None:
                skill_obj = {
                    "id": supervisor_skill_id,
                    "category": supervisor_selected.get("capability", group),
                    "description": supervisor_selected.get("objective", ""),
                    "playbook": allowed_tools,
                    "phases": [],
                    "triggers": [],
                }

            selected_techniques = [
                dict(item)
                for item in list(supervisor_selected.get("learning_techniques") or [])
                if isinstance(item, dict)
            ]
            if selected_techniques:
                playbook = {
                    "title": "Supervisor pentest tactic playbook",
                    "vulnerability_type": str(supervisor_selected.get("skill_id") or group),
                    "summary": str(supervisor_selected.get("hypothesis") or ""),
                    "learned_mission": str(supervisor_selected.get("objective") or ""),
                    "techniques": selected_techniques,
                    "evidence_signals": list(supervisor_selected.get("evidence_required") or []),
                    "recommended_tools": allowed_tools,
                    "sources": [],
                }
            else:
                playbook = _build_skill_playbook_for_context(state, group, candidate_tools, phase_label, skill_obj)
            runtime_invocation: dict[str, Any] = {}
            try:
                from app.services.skill_runtime import resolve_skill_invocation

                runtime_invocation = resolve_skill_invocation(
                    worker_group=group,
                    phase=phase_label,
                    target=str(state.get("target") or ""),
                    candidate_tools=candidate_tools,
                    active_skills=[skill_obj, *skills],
                    playbook=playbook,
                )
            except Exception as exc:
                state["logs_terminais"].append(f"[SKILL] learning runtime unavailable: {exc}")

            runtime_tools = [
                str(tool).strip()
                for tool in list(runtime_invocation.get("recommended_tools") or [])
                if str(tool).strip()
            ]
            if runtime_tools and not lock_skill:
                guided_tools = list(dict.fromkeys([*runtime_tools, *guided_tools]))
            if runtime_invocation.get("called") and not lock_skill:
                runtime_skill = dict(runtime_invocation.get("skill") or {})
                supervisor_selected["skill_id"] = str(runtime_invocation.get("skill_id") or runtime_skill.get("id") or supervisor_skill_id)
                supervisor_selected["objective"] = str(runtime_skill.get("description") or supervisor_selected.get("objective") or "")
                supervisor_selected["reason"] = (
                    "Supervisor intent refined by accepted learning: "
                    f"source={runtime_invocation.get('source')}; "
                    f"matched_by={','.join(list(runtime_invocation.get('matched_by') or [])[:5])}"
                )
                supervisor_skill_id = supervisor_selected["skill_id"]
                skill_obj = runtime_skill or skill_obj
            elif runtime_invocation.get("called"):
                supervisor_selected["reason"] = (
                    f"{supervisor_selected.get('reason') or ''} | "
                    f"locked_pentest_tactic; learning_source={runtime_invocation.get('source')}; "
                    f"matched_by={','.join(list(runtime_invocation.get('matched_by') or [])[:5])}"
                ).strip(" |")
                skill_obj = skill_obj or dict(runtime_invocation.get("skill") or {})
            if lock_skill and allowed_tools:
                guided_tools = allowed_tools
            if runtime_tools:
                supervisor_selected["allowed_tools"] = guided_tools
                supervisor_selected["preferred_tool"] = guided_tools[0]
            state["selected_skill"] = supervisor_selected

            invocation_id = f"skill-{uuid4().hex[:12]}"
            resolved_skill_id = str(supervisor_skill_id if lock_skill else (runtime_invocation.get("skill_id") or supervisor_skill_id))
            resolved_techniques = (
                selected_techniques
                if selected_techniques
                else list(runtime_invocation.get("techniques") or [])
            )
            invocation_record = {
                "invocation_id": invocation_id,
                "skill_id": resolved_skill_id,
                "worker_group": group,
                "phase": phase_label,
                "purpose": "skill_selector",
                "tactic_id": supervisor_selected.get("tactic_id"),
                "hypothesis": supervisor_selected.get("hypothesis"),
                "strategy_source": supervisor_selected.get("strategy_source"),
                "source": runtime_invocation.get("source") or "supervisor_selected",
                "matched_by": list(dict.fromkeys(["supervisor_selected_skill", *list(runtime_invocation.get("matched_by") or [])])),
                "candidate_tools": candidate_tools,
                "recommended_tools": guided_tools,
                "confidence": runtime_invocation.get("confidence", 0.9),
                "playbook_title": playbook.get("title"),
                "created_at": datetime.utcnow().isoformat(),
            }
            invocations = list(state.get("skill_invocations") or [])
            invocations.append(invocation_record)
            state["skill_invocations"] = invocations[-80:]
            state["current_skill"] = invocation_record["skill_id"]
            state["active_skill"] = invocation_record["skill_id"]
            state["skill_contract"] = invocation_record
            state["skill_invocation"] = {
                "called": True,
                "invocation_id": invocation_id,
                "skill_id": invocation_record["skill_id"],
                "skill": skill_obj if lock_skill else (runtime_invocation.get("skill") or skill_obj),
                "worker_group": group,
                "phase": phase_label,
                "target": str(state.get("target") or ""),
                "candidate_tools": candidate_tools,
                "recommended_tools": guided_tools,
                "learned_recommended_tools": list(runtime_invocation.get("learned_recommended_tools") or []),
                "matched_by": invocation_record["matched_by"],
                "score": runtime_invocation.get("score", 90),
                "confidence": invocation_record["confidence"],
                "techniques": resolved_techniques,
                "source": invocation_record["source"],
                "playbook_title": playbook.get("title"),
                "tactic_id": supervisor_selected.get("tactic_id"),
                "hypothesis": supervisor_selected.get("hypothesis"),
                "strategy_source": supervisor_selected.get("strategy_source"),
            }
            _append_action(state, "skill_invoked", invocation_record)
            state["skill_selector_ready"] = True
            state["skill_selector_gate"] = {
                "group": group,
                "phase": phase_label,
                "called": True,
                "skill_id": invocation_record["skill_id"],
                "recommended_tools": guided_tools,
                "candidate_tools": guided_tools,
                "allowed_tools": allowed_tools,
                "preferred_tool": preferred_tool,
                "playbook_title": playbook.get("title"),
                "tactic_id": supervisor_selected.get("tactic_id"),
                "hypothesis": supervisor_selected.get("hypothesis"),
            }
            state["logs_terminais"].append(
                f"[SKILL] selector supervisor-driven skill={invocation_record['skill_id']} "
                f"group={group} source={invocation_record['source']} "
                f"techniques={len(resolved_techniques or [])} "
                f"allowed={allowed_tools[:4]} guided={guided_tools[:4]}"
            )
        else:
            # ── Inference path (no supervisor-selected skill) ─────────────────
            primary_skill = skills[0] if skills else {"id": group, "phases": [phase_label]}
            playbook = _build_skill_playbook_for_context(state, group, candidate_tools, phase_label, primary_skill)
            invocation, _, guided_tools = _invoke_skill_for_context(
                state,
                group,
                candidate_tools,
                playbook,
                phase_label,
                purpose="skill_selector",
            )
            ready = bool(invocation.get("called"))
            inferred_skill_id = str(invocation.get("skill_id") or group)
            invocation_id = f"inferred-{uuid4().hex[:12]}"
            invocation_record = {
                "invocation_id": invocation_id,
                "skill_id": inferred_skill_id,
                "worker_group": group,
                "phase": phase_label,
                "purpose": "skill_selector",
                "source": "accepted_learning+skill_catalog",
                "matched_by": list(invocation.get("matched_by") or []),
                "candidate_tools": candidate_tools,
                "recommended_tools": guided_tools,
                "confidence": invocation.get("confidence", 0.7),
                "playbook_title": playbook.get("title"),
                "created_at": datetime.utcnow().isoformat(),
            }
            invocations = list(state.get("skill_invocations") or [])
            invocations.append(invocation_record)
            state["skill_invocations"] = invocations[-80:]
            state["current_skill"] = inferred_skill_id
            state["active_skill"] = inferred_skill_id
            state["skill_contract"] = invocation_record
            state["skill_invocation"] = dict(invocation) | {
                "invocation_id": invocation_id,
                "source": "accepted_learning+skill_catalog",
            }
            # Populate selected_skill so tool_executor_node can proceed.
            state["selected_skill"] = {
                "skill_id": inferred_skill_id,
                "capability": group,
                "objective": str(invocation.get("objective") or ""),
                "allowed_tools": guided_tools,
                "preferred_tool": guided_tools[0] if guided_tools else "",
                "reason": "inferred from accepted learning + skill catalog",
            }
            _append_action(state, "skill_invoked", invocation_record)
            state["skill_selector_ready"] = ready
            state["skill_selector_gate"] = {
                "group": group,
                "phase": phase_label,
                "called": bool(invocation.get("called")),
                "skill_id": inferred_skill_id,
                "recommended_tools": guided_tools,
                "candidate_tools": guided_tools,
                "allowed_tools": guided_tools,
                "playbook_title": playbook.get("title"),
            }
            state["logs_terminais"].append(
                f"[SKILL] runtime gate ready={state['skill_selector_ready']} "
                f"group={group} skill={inferred_skill_id}"
            )

    except Exception as exc:
        state["skill_selector_ready"] = False
        state["logs_terminais"].append(f"[SKILL] selector failed: {exc}")
        logger.warning("Skill selector failed: %s", exc)

    try:
        from app.graph.tracer import emit_trace as _emit_trace
        _trace_scan_id = state.get("scan_id")
        if _trace_scan_id:
            _skill_found_id = str(state.get("current_skill") or state.get("active_skill") or "")
            _emit_trace(
                scan_id=int(_trace_scan_id), iteration=int(state.get("loop_iteration", 0)),
                event_type="skill_found", from_node="library", to_node="agent",
                skill_id=_skill_found_id or None,
                capability=str(state.get("pending_capability_node") or state.get("current_phase") or ""),
                status="success" if state.get("skill_selector_ready") else "failure",
                payload={"skill_id": _skill_found_id},
            )
    except Exception:
        pass

    _metric_end(state, "skill_selector", started_at)
    return state


def skill_planner_node(state: AgentState) -> AgentState:
    """Turn the selected skill into an executable plan contract."""
    from app.graph.workflow import _metric_start, _metric_end, _sync_step_to_db
    from app.graph.nodes.supervisor import _append_action

    started_at = _metric_start()
    _sync_step_to_db(state, "Skill Planner")

    gate = dict(state.get("skill_selector_gate") or {})
    contract = dict(state.get("skill_contract") or {})
    invocation = dict(state.get("skill_invocation") or {})
    capability = str(gate.get("group") or state.get("pending_capability_node") or _bootstrap_skill_group(state))
    techniques = [dict(item) for item in list(invocation.get("techniques") or []) if isinstance(item, dict)]
    selected_technique = techniques[0] if techniques else {
        "name": f"{contract.get('skill_id') or capability} plan",
        "objective": "Execute the selected skill with one authorized tool and reproducible evidence.",
        "recommended_kali_tools": list(gate.get("recommended_tools") or []),
        "evidence_signals": [],
        "safe_validation_steps": [],
    }
    plan = {
        "capability": capability,
        "phase": gate.get("phase") or state.get("current_phase") or capability,
        "skill_id": contract.get("skill_id") or invocation.get("skill_id"),
        "skill_invocation_id": contract.get("invocation_id") or invocation.get("invocation_id"),
        "skill_contract": contract,
        "technique": selected_technique,
        "candidate_tools": list(gate.get("candidate_tools") or invocation.get("candidate_tools") or []),
        "recommended_tools": list(gate.get("recommended_tools") or invocation.get("recommended_tools") or []),
        "evidence_required": list(selected_technique.get("evidence_signals") or []),
        "constraints": list(selected_technique.get("safe_validation_steps") or []),
        "playbook_title": contract.get("playbook_title") or gate.get("playbook_title"),
        "decision_source": "skill_planner",
    }
    state["skill_plan_contract"] = plan
    _append_action(state, "skill_planned", plan)
    state["logs_terminais"].append(
        f"[SKILL] planned capability={capability} skill={plan.get('skill_id')} "
        f"technique={selected_technique.get('name') or '-'}"
    )

    _metric_end(state, "skill_planner", started_at)
    return state


def _technique_for_selected_tool(invocation: dict[str, Any], selected_tool: str) -> dict[str, Any]:
    selected = str(selected_tool or "").strip().lower()
    techniques = [dict(item) for item in list(invocation.get("techniques") or []) if isinstance(item, dict)]
    for technique in techniques:
        tools = {str(tool).strip().lower() for tool in list(technique.get("recommended_kali_tools") or [])}
        if selected and selected in tools:
            return technique
    return techniques[0] if techniques else {}


def tool_selector_node(state: AgentState) -> AgentState:
    """Select exactly the tool(s) authorized by the current skill contract."""
    from app.graph.workflow import _metric_start, _metric_end, _sync_step_to_db
    from app.graph.nodes.supervisor import _append_action

    started_at = _metric_start()
    _sync_step_to_db(state, "Tool Selector")

    plan = dict(state.get("skill_plan_contract") or {})
    capability = str(plan.get("capability") or state.get("pending_capability_node") or _bootstrap_skill_group(state))
    gate = dict(state.get("skill_selector_gate") or {})
    contract = dict(plan.get("skill_contract") or state.get("skill_contract") or {})
    invocation = dict(state.get("skill_invocation") or {})
    candidate_tools = [str(tool) for tool in list(plan.get("candidate_tools") or gate.get("candidate_tools") or []) if str(tool or "").strip()]
    recommended_tools = [
        str(tool)
        for tool in list(plan.get("recommended_tools") or contract.get("recommended_tools") or invocation.get("recommended_tools") or [])
        if str(tool or "").strip()
    ]

    try:
        from app.graph.tracer import emit_trace as _emit_trace
        _trace_scan_id = state.get("scan_id")
        if _trace_scan_id:
            _emit_trace(
                scan_id=int(_trace_scan_id), iteration=int(state.get("loop_iteration", 0)),
                event_type="tool_usage_lookup", from_node="agent", to_node="library",
                skill_id=str(plan.get("skill_id") or "") or None,
                capability=capability, status="pending",
                payload={"capability": capability, "candidate_tools": candidate_tools[:4]},
            )
    except Exception:
        pass

    try:
        from app.services.agent_context_service import build_worker_knowledge_context

        bundle = build_worker_knowledge_context(
            worker_group=capability,
            skill=str(plan.get("skill_id") or contract.get("skill_id") or invocation.get("skill_id") or capability),
            phase=str(plan.get("phase") or gate.get("phase") or state.get("current_phase") or capability),
            target=str(state.get("target") or ""),
            candidate_tools=candidate_tools,
            mode=str(state.get("scan_mode") or "unit"),
        )
        for tool in list(bundle.get("recommended_tools") or []):
            if str(tool).strip():
                recommended_tools.append(str(tool).strip())
        state["logs_terminais"].append(
            f"[selector] skill-memory retrieved={len(bundle.get('knowledge_items') or [])}"
        )
    except Exception as exc:
        state["logs_terminais"].append(f"[selector] skill-memory unavailable: {exc}")

    supervisor_selected = dict(state.get("selected_skill") or {})
    allowed_tools = list(supervisor_selected.get("allowed_tools") or [])
    preferred_tool = str(supervisor_selected.get("preferred_tool") or "").strip().lower()

    if allowed_tools:
        # ── Skill-constrained selection ───────────────────────────────────────
        # Only tools that the supervisor's selected_skill explicitly permits.
        allowed_lower = {t.lower() for t in allowed_tools}
        from_allowed = [t for t in candidate_tools if t.lower() in allowed_lower]
        if preferred_tool:
            pref_first = [t for t in from_allowed if t.lower() == preferred_tool]
            rest = [t for t in from_allowed if t.lower() != preferred_tool]
            selected_tools = pref_first + rest
        else:
            selected_tools = from_allowed

        if not selected_tools:
            state["logs_terminais"].append(
                f"[selector] BLOCKED: nenhum candidate_tool corresponde a "
                f"allowed_tools={allowed_tools} para skill={supervisor_selected.get('skill_id')}; "
                "execução bloqueada"
            )
            # selected_tools stays empty — executor will catch and abort cleanly
    else:
        # ── No allowed_tools constraint (no supervisor skill / inference path) ─
        candidate_set = set(candidate_tools)
        selected_tools = [tool for tool in dict.fromkeys(recommended_tools) if tool in candidate_set]
        # NOTE: the old candidate_tools[0] fallback has been intentionally removed.
        # Without a skill contract there is no safe basis for choosing an arbitrary tool.

    # Skill-first: execute pelo menos 2 ferramentas distintas quando disponíveis
    # para validar a hipótese da skill com triangulação de evidência.
    # Motivo: rodar uma única ferramenta e parar deixa SQLi/XSS/LFI passando em
    # ambientes ASP/PHP onde a primeira ferramenta retorna pouco mas a segunda
    # confirma. Mantemos o limite em 2 para evitar explosão de runtime.
    selected_tools = selected_tools[:2]
    selected_tool = selected_tools[0] if selected_tools else ""
    technique = dict(plan.get("technique") or {}) or _technique_for_selected_tool(invocation, selected_tool)
    evidence_required = list(plan.get("evidence_required") or technique.get("evidence_signals") or [])
    constraints = list(plan.get("constraints") or technique.get("safe_validation_steps") or [])

    selection = {
        "capability": capability,
        "selected_tools": selected_tools,
        "candidate_tools": candidate_tools,
        "skill_id": plan.get("skill_id") or contract.get("skill_id") or invocation.get("skill_id"),
        "skill_invocation_id": plan.get("skill_invocation_id") or contract.get("invocation_id") or invocation.get("invocation_id"),
        "skill_contract": contract,
        "technique": technique,
        "evidence_required": evidence_required,
        "constraints": constraints,
        "playbook_title": plan.get("playbook_title") or contract.get("playbook_title") or gate.get("playbook_title"),
        "decision_source": "skill_selector",
    }
    state["tool_selection_contract"] = selection
    _append_action(state, "tool_selected", selection)

    try:
        from app.graph.tracer import emit_trace as _emit_trace
        _trace_scan_id = state.get("scan_id")
        if _trace_scan_id:
            _emit_trace(
                scan_id=int(_trace_scan_id), iteration=int(state.get("loop_iteration", 0)),
                event_type="tool_select", from_node="agent", to_node="kali",
                skill_id=str(selection.get("skill_id") or "") or None,
                tool_name=selected_tool or None,
                capability=capability,
                status="success" if selected_tool else "skipped",
                payload={
                    "selected_tool": selected_tool,
                    "capability": capability,
                    "technique": (selection.get("technique") or {}).get("name", ""),
                },
            )
            if selected_tool:
                _emit_trace(
                    scan_id=int(_trace_scan_id), iteration=int(state.get("loop_iteration", 0)),
                    event_type="tool_usage_found", from_node="library", to_node="agent",
                    skill_id=str(selection.get("skill_id") or "") or None,
                    tool_name=selected_tool,
                    capability=capability,
                    status="success",
                    payload={"tool": selected_tool, "technique": (selection.get("technique") or {}).get("name", "")},
                )
    except Exception:
        pass

    if selected_tools:
        state["logs_terminais"].append(
            f"[selector] capability={capability} skill={selection.get('skill_id')} selected={','.join(selected_tools)}"
        )
    else:
        state["logs_terminais"].append(
            f"[selector] capability={capability} sem ferramenta selecionada pela skill"
        )

    _metric_end(state, "tool_selector", started_at)
    return state


def _targets_for_tool_pipeline(state: AgentState, capability: str) -> list[str]:
    from app.graph.workflow import (
        _validate_osint_targets,
        _targets_for_deep_scan,
        _is_local_target,
        _filter_resolvable_targets,
        _target_host,
    )

    context = dict(state.get("capability_context") or {})
    if str(context.get("node") or "") == capability and context.get("targets"):
        return [str(target) for target in list(context.get("targets") or []) if str(target or "").strip()]

    if capability == "threat_intel":
        osint_targets = _validate_osint_targets(_targets_for_deep_scan(state, limit=6))
        if osint_targets:
            return osint_targets
        host = _target_host(str(state.get("target") or ""))
        return [host or str(state.get("target") or "").strip()]

    if capability == "risk_assessment":
        limit = 10 if _is_local_target(state.get("target", "")) else 6
        primary_targets = _targets_for_deep_scan(state, limit=limit)
        resolvable_targets, unresolved_targets = _filter_resolvable_targets(primary_targets)
        explicit_target = str(state.get("target") or "").strip()
        if explicit_target and _is_local_target(explicit_target):
            local_targets = [t for t in primary_targets if _is_local_target(t)]
            if explicit_target not in local_targets:
                local_targets.insert(0, explicit_target)
            resolvable_targets = list(dict.fromkeys(local_targets + resolvable_targets))
            unresolved_targets = [t for t in unresolved_targets if not _is_local_target(t)]
        if not resolvable_targets:
            resolvable_targets = [state.get("target", "")]
        state["risk_targets_resolvable"] = list(resolvable_targets)
        state["risk_targets_unresolved"] = list(unresolved_targets)
        if unresolved_targets:
            state["logs_terminais"].append(
                f"RiskAssessment: unresolved_targets_skipped={len(unresolved_targets)} sample={unresolved_targets[:5]}"
            )
        return list(resolvable_targets)

    return [str(state.get("target") or "").strip()]


def _apply_tool_execution_findings(
    state: AgentState,
    capability: str,
    target: str,
    tools: list[str],
    findings: list[dict[str, Any]],
    ports: list[int],
    assets: list[str],
    port_evidence: dict[int, dict[str, str]],
) -> None:
    from app.graph.workflow import (
        _step_name,
        _target_host,
        _register_discovered_assets,
        _persist_discovered_assets_to_db,
        MAX_DISCOVERED_ASSETS,
    )

    current = _step_name(state)
    if findings:
        state["vulnerabilidades_encontradas"].extend(findings)

    if capability == "asset_discovery":
        if ports:
            state["discovered_ports"] = sorted(set((state.get("discovered_ports") or []) + ports))
            state["pending_port_tests"] = state["discovered_ports"].copy()
        if assets:
            root_domain = _target_host(state.get("target") or target)
            _register_discovered_assets(state, root_domain=root_domain, assets=assets)
            owner_id = state.get("owner_id")
            scan_id = state.get("scan_id")
            if owner_id and scan_id:
                inserted = _persist_discovered_assets_to_db(
                    scan_job_id=scan_id,
                    owner_id=owner_id,
                    assets=assets,
                    source_tool="recon",
                )
                state["discovered_subdomains_persisted"].extend(
                    [a.lower() for a in assets[:MAX_DISCOVERED_ASSETS]]
                )
                state["logs_terminais"].append(
                    f"ReconNode: {len(assets)} subdomínios persistidos no banco (novos: {inserted})"
                )
            for asset in assets[:MAX_DISCOVERED_ASSETS]:
                state["vulnerabilidades_encontradas"].append(
                    {
                        "title": f"Ativo descoberto no reconhecimento: {asset}",
                        "severity": "info",
                        "risk_score": 1,
                        "source_worker": "reconhecimento",
                        "details": {
                            "node": "recon",
                            "step": current,
                            "asset": asset,
                            "tool": "reconhecimento",
                        },
                    }
                )
        state["vulnerabilidades_encontradas"].append(
            {
                "title": f"Ativo externo mapeado: {state['target']}",
                "severity": "low",
                "risk_score": 2,
                "source_worker": "asset_discovery",
                "details": {"node": "asset_discovery", "step": current, "tools": tools},
            }
        )
        return

    if capability == "threat_intel":
        state["vulnerabilidades_encontradas"].append(
            {
                "title": f"Threat Intel executado em {target}",
                "severity": "info",
                "risk_score": 1,
                "source_worker": "threat_intel",
                "details": {
                    "node": "threat_intel",
                    "step": current,
                    "asset": target,
                    "tool": "threat_intel",
                    "tools": tools,
                },
            }
        )
        return

    if capability == "risk_assessment":
        state["vulnerabilidades_encontradas"].append(
            {
                "title": f"Avaliação de risco executada em {target}",
                "severity": "info",
                "risk_score": 1,
                "source_worker": "risk_assessment",
                "details": {
                    "node": "risk_assessment",
                    "step": current,
                    "asset": target,
                    "tool": "risk_assessment",
                    "tools": tools,
                },
            }
        )


def tool_executor_node(state: AgentState) -> AgentState:
    """Execute the selected skill-bound tool through MCP/Kali."""
    from app.graph.workflow import (
        _metric_start,
        _metric_end,
        _sync_step_to_db,
        _run_tools_and_collect,
        _tools_for_validation_target,
        _target_host,
        _step_name,
    )
    from app.graph.nodes.supervisor import (
        _append_error,
        _append_observation,
        _complete_delegation_task,
    )

    started_at = _metric_start()
    _sync_step_to_db(state, "Tool Executor")

    selection = dict(state.get("tool_selection_contract") or {})
    supervisor_selected = dict(state.get("selected_skill") or {})
    capability = str(selection.get("capability") or state.get("pending_capability_node") or _bootstrap_skill_group(state))
    selected_tools = [str(tool) for tool in list(selection.get("selected_tools") or []) if str(tool or "").strip()]

    skill_id = str(
        supervisor_selected.get("skill_id")
        or selection.get("skill_id")
        or ""
    ).strip()
    allowed_tools = list(supervisor_selected.get("allowed_tools") or [])

    # ── Pre-execution contract validation ────────────────────────────────────
    def _mark_pentest_tactic(status: str, findings_added: int = 0, targets_executed: int = 0, reason: str = "") -> None:
        tactic_id = str(
            supervisor_selected.get("tactic_id")
            or (state.get("capability_context") or {}).get("tactic_id")
            or (state.get("skill_invocation") or {}).get("tactic_id")
            or ""
        ).strip()
        if not tactic_id:
            return
        completed_tactics = [
            dict(item)
            for item in list(state.get("pentest_tactics_completed") or [])
            if isinstance(item, dict)
        ]
        if any(str(item.get("tactic_id") or "") == tactic_id for item in completed_tactics):
            state["pending_pentest_tactic"] = {}
            return
        completed_tactics.append(
            {
                "tactic_id": tactic_id,
                "skill_id": skill_id,
                "capability": capability,
                "status": status,
                "tools": selected_tools,
                "findings_added": int(findings_added),
                "targets_executed": int(targets_executed),
                "reason": reason,
                "completed_at": datetime.utcnow().isoformat(),
            }
        )
        state["pentest_tactics_completed"] = completed_tactics[-40:]
        state["pending_pentest_tactic"] = {}

    def _abort(reason: str) -> AgentState:
        state["logs_terminais"].append(f"[executor] BLOCKED: {reason}")
        _append_error(state, reason, source="tool_executor")
        _mark_pentest_tactic("blocked", reason=reason)
        # Mark capability complete to prevent the supervisor from looping on it.
        completed = list(state.get("completed_capabilities") or [])
        if capability in TOOL_CAPABILITY_NODES and capability not in completed:
            completed.append(capability)
        state["completed_capabilities"] = completed
        state["pending_capability_node"] = ""
        state["proxima_ferramenta"] = "evidence_gate"
        state["routing_next_node"] = "evidence_gate"
        state["mission_index"] = int(state.get("mission_index", 0)) + 1
        _metric_end(state, "tool_executor", started_at)
        return state

    if not supervisor_selected:
        return _abort("selected_skill ausente; nenhuma execução sem contrato de skill")

    if not skill_id:
        return _abort("skill_id ausente; nenhuma execução sem skill_id")

    if not selected_tools:
        return _abort(f"selected_tools vazio para skill={skill_id}; nada a executar")

    if allowed_tools:
        allowed_lower = {t.lower() for t in allowed_tools}
        invalid = [t for t in selected_tools if t.lower() not in allowed_lower]
        if invalid:
            return _abort(
                f"ferramentas {invalid} não pertencem a allowed_tools={allowed_tools} "
                f"da skill={skill_id}; execução bloqueada"
            )

    # ── Safe to execute ───────────────────────────────────────────────────────
    targets = _targets_for_tool_pipeline(state, capability)
    all_results: list[dict[str, Any]] = []

    try:
        from app.graph.tracer import emit_trace as _emit_trace
        _trace_scan_id_ex = state.get("scan_id")
        if _trace_scan_id_ex and selected_tools:
            _emit_trace(
                scan_id=int(_trace_scan_id_ex), iteration=int(state.get("loop_iteration", 0)),
                event_type="tool_execute", from_node="agent", to_node="kali",
                skill_id=skill_id or None,
                tool_name=selected_tools[0] if selected_tools else None,
                capability=capability, status="pending",
                payload={"tools": selected_tools, "targets": [str(t) for t in targets[:3]]},
            )
    except Exception:
        pass

    _executor_findings_before = len(state.get("vulnerabilidades_encontradas") or [])

    if not selected_tools:
        state["logs_terminais"].append(f"[executor] capability={capability} sem tool selecionada; nada executado")
    for scan_target in targets:
        target_tools = selected_tools
        if capability == "risk_assessment":
            target_tools = _tools_for_validation_target(scan_target, selected_tools)
        if not target_tools:
            continue
        findings, ports, assets, port_evidence = _run_tools_and_collect(
            state,
            target_tools,
            scan_target,
            _step_name(state),
            f"ToolExecutor:{capability}",
            root_domain=_target_host(state.get("target") or scan_target),
            skill_context=selection,
        )
        _apply_tool_execution_findings(
            state,
            capability,
            scan_target,
            target_tools,
            findings,
            ports,
            assets,
            port_evidence,
        )
        all_results.append(
            {
                "target": scan_target,
                "tools": target_tools,
                "findings": len(findings),
                "ports": ports,
                "assets": assets,
                "skill_id": selection.get("skill_id"),
                "technique": (selection.get("technique") or {}).get("name"),
            }
        )

    state["tool_execution_results"] = list(state.get("tool_execution_results") or []) + all_results
    completed = list(state.get("completed_capabilities") or [])
    if capability in TOOL_CAPABILITY_NODES and capability not in completed:
        completed.append(capability)
    state["completed_capabilities"] = completed
    if capability == "risk_assessment" and state.get("validation_backlog"):
        state["validation_backlog"] = []
    _complete_delegation_task(state, capability, f"skill_tool_executed:{','.join(selected_tools) or 'none'}")
    _findings_now_post = len(state.get("vulnerabilidades_encontradas") or [])
    _findings_delta_post = max(0, _findings_now_post - _executor_findings_before)
    _mark_pentest_tactic(
        "success" if all_results else "skipped",
        findings_added=_findings_delta_post,
        targets_executed=len(all_results),
        reason="executed" if all_results else "no_target_or_tool_execution",
    )

    try:
        from app.graph.tracer import emit_trace as _emit_trace, save_skill_score as _save_score
        _trace_scan_id_ex = state.get("scan_id")
        if _trace_scan_id_ex:
            _findings_delta = _findings_delta_post
            _tool_runs = list(state.get("executed_tool_runs") or [])
            _tool_ok = sum(1 for r in all_results if r.get("findings", 0) >= 0)
            _elapsed = _findings_delta  # proxy
            _emit_trace(
                scan_id=int(_trace_scan_id_ex), iteration=int(state.get("loop_iteration", 0)),
                event_type="result_return", from_node="agent", to_node="supervisor",
                skill_id=skill_id or None,
                tool_name=selected_tools[0] if selected_tools else None,
                capability=capability,
                status="success" if all_results else "skipped",
                payload={
                    "findings_added": _findings_delta,
                    "targets_executed": len(all_results),
                    "tools": selected_tools,
                },
            )
            _save_score(
                scan_id=int(_trace_scan_id_ex),
                iteration=int(state.get("loop_iteration", 0)),
                skill_id=skill_id or capability,
                capability=capability,
                library_hits=2,  # skill_lookup + tool_usage_lookup
                tool_attempts=len(all_results),
                tool_successes=_tool_ok,
                tool_failures=max(0, len(all_results) - _tool_ok),
                findings_raw=_findings_delta,
                findings_promoted=sum(
                    1 for f in (state.get("vulnerabilidades_encontradas") or [])[-_findings_delta:]
                    if str(f.get("severity", "")).lower() in {"critical", "high"}
                ),
                duration_ms=float(state.get("tool_runtime", {}).get(selected_tools[0], {}).get("attempts", 0)) * 1000,
            )
    except Exception:
        pass
    state["pending_capability_node"] = ""
    state["proxima_ferramenta"] = "evidence_gate"
    state["routing_next_node"] = "evidence_gate"
    state["mission_index"] += 1
    _append_observation(
        state,
        f"Skill-bound execution completed: capability={capability} tools={','.join(selected_tools) or '-'}",
        source="tool_executor",
    )

    _metric_end(state, "tool_executor", started_at)
    return state


def evidence_gate_node(state: AgentState) -> AgentState:
    """Evidence gate after every skill-bound execution."""
    state["logs_terminais"].append("[EVIDENCE] gate evaluating skill-bound execution")
    return _evaluate_evidence_gate(state)


def _evaluate_evidence_gate(state: AgentState) -> AgentState:
    """Aplica contrato de evidência para separar hipótese de finding verificável."""
    from app.graph.workflow import (
        _metric_start,
        _metric_end,
        _sync_step_to_db,
        EVIDENCE_RULES,
    )
    from app.graph.nodes.supervisor import (
        _register_delegation_task,
        _append_todo,
        _append_note,
        _complete_delegation_task,
    )

    state["routing_next_node"] = "governance"
    started_at = _metric_start()
    _sync_step_to_db(state, "Evidence Gate")

    rules = (state.get("evidence_contract") or {}).get("rules") or EVIDENCE_RULES
    min_conf = int(rules.get("minimum_confidence_for_promote", 70))

    adjudicated: list[dict[str, Any]] = []
    promoted = 0
    backlog: list[dict[str, Any]] = []
    findings_for_adjudication = list(state.get("vulnerabilidades_encontradas") or [])
    try:
        from app.services.vulnerability_learning_service import enrich_findings_with_accepted_learning

        findings_for_adjudication = enrich_findings_with_accepted_learning(findings_for_adjudication)
    except Exception:
        pass

    for finding in findings_for_adjudication:
        item = dict(finding)
        details = dict(item.get("details") or {})
        sev = str(item.get("severity", "low")).lower()
        confidence = float(details.get("confidence") or item.get("risk_score") or 0)
        evidence = str(details.get("evidence") or "").strip()
        repro_steps = str(details.get("repro_steps") or "").strip()
        has_minimum_proof = bool(evidence) and (
            bool(repro_steps)
            or bool(details.get("url"))
            or bool(details.get("port"))
        )

        if sev in {"critical", "high"} and (confidence < min_conf or not has_minimum_proof):
            details["validation_status"] = "hypothesis"
            details["adjudication_reason"] = "insufficient_confidence_or_missing_reproducible_proof"
            backlog.append({
                "title": str(item.get("title") or ""),
                "severity": sev,
                "asset": str(details.get("asset") or state.get("target") or ""),
                "reason": details["adjudication_reason"],
                "required_action": "rerun_learning_guided_validation_with_repro_steps",
                "details": {
                    "tool": details.get("tool"),
                    "evidence": evidence[:1200],
                    "learning_match": details.get("learning_match"),
                    "reproduction_playbook": details.get("reproduction_playbook"),
                    "repro_steps": details.get("repro_steps"),
                    "technical_evidence_expected": details.get("technical_evidence_expected"),
                },
            })
        else:
            if sev in {"critical", "high"}:
                details["validation_status"] = "verified"
            else:
                details.setdefault("validation_status", "unverified")
            if confidence >= min_conf:
                promoted += 1
        item["details"] = details
        adjudicated.append(item)

    state["vulnerabilidades_encontradas"] = adjudicated
    state["validation_backlog"] = backlog
    if backlog:
        _register_delegation_task(
            state,
            node="risk_assessment",
            reason=f"evidence_backlog={len(backlog)}",
            priority=0,
        )
        _append_todo(state, f"Revalidar {len(backlog)} findings high/critical sem proof-pack", priority="high")
        _append_note(
            state,
            f"Evidence gate bloqueou promoção de {len(backlog)} finding(s) por falta de reprodução.",
            phase="evidence-gate",
        )
    _complete_delegation_task(state, "evidence_gate", f"promoted={promoted}; backlog={len(backlog)}")
    state["logs_terminais"].append(
        f"EvidenceGate: total={len(adjudicated)} promoted_confident={promoted} backlog={len(backlog)}"
    )
    state["proxima_ferramenta"] = "governance"
    state["mission_index"] += 1
    _metric_end(state, "evidence_gate", started_at)
    _sync_step_to_db(state, "Evidence Gate")
    return state
