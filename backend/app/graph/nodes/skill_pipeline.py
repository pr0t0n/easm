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
        # When target_type=="site" we DO NOT prune passive subdomain enum.
        # Even single-URL targets can have sibling subdomains discoverable
        # via cert transparency / passive sources, and the user requested
        # ALL recon tools per the article. Only skip heavy active brute
        # (amass-brute, shuffledns) and tools that have no profile.
        if str(state.get("target_type") or "") == "site":
            heavy_active_brute = {"amass-brute", "shuffledns"}
            tools = [t for t in tools if t not in heavy_active_brute]
    elif group == "risk_assessment":
        tools = _adapt_vuln_tools_for_target(target, tools)
    return _select_tool_batch_for_iteration(state, group=group, tools=tools)


def _lookup_skill_from_library(state: AgentState, group: str) -> dict | None:
    """Consulta a SkillLibrary no banco para a activity_demand atual.

    Retorna um dict com skill info (nome, ferramentas ranqueadas, guia) ou None.
    """
    from app.services.skill_library_service import get_skill_for_activity
    from app.db.session import SessionLocal

    demand = dict(state.get("current_activity_demand") or {})
    activity_type = str(demand.get("activity_type") or "").strip()
    if not activity_type:
        return None
    try:
        db = SessionLocal()
        skill = get_skill_for_activity(db, activity_type, capability=group)
        db.close()
        return skill
    except Exception as exc:
        state["logs_terminais"].append(f"[SkillLibrary] lookup falhou: {exc}")
    return None


def _update_log_skill_found(state: AgentState, skill: dict, source: str) -> None:
    """Persiste o resultado do lookup de skill no AgentActivityLog."""
    from app.services.skill_library_service import update_agent_activity_log
    from app.db.session import SessionLocal

    log_id = state.get("current_activity_log_id")
    if not log_id:
        return
    try:
        db = SessionLocal()
        update_agent_activity_log(
            db,
            log_id,
            skill_found=skill,
            skill_lookup_source=source,
            status="skill_selected",
        )
        db.close()
    except Exception as exc:
        state["logs_terminais"].append(f"[SkillLibrary] log update falhou: {exc}")


def skill_selector_node(state: AgentState) -> AgentState:
    """Seleciona a skill para a atividade demandada pelo supervisor.

    Fluxo:
    1. Consulta SkillLibrary DB pela activity_type da demanda atual.
    2. Se encontrar, usa a skill da biblioteca como fonte de verdade.
    3. Fallback: usa selected_skill do supervisor ou inferência por active_skills.
    """
    from app.graph.workflow import _metric_start, _metric_end, _sync_step_to_db
    from app.graph.nodes.supervisor import (
        _refresh_active_skills,
        _append_action,
        _mark_capability_runtime,
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
            _supervisor_intent = dict(state.get("selected_skill") or {})
            _emit_trace(
                scan_id=int(_trace_scan_id), iteration=_trace_iter,
                event_type="skill_lookup", from_node="agent", to_node="library",
                skill_id=_supervisor_intent.get("skill_id") or None,
                capability=_trace_cap, status="pending",
                payload={
                    "phase": _trace_cap,
                    "supervisor_intent_skill": _supervisor_intent.get("skill_id"),
                    "tech_stack": list(state.get("detected_tech_stack") or [])[:8],
                    "lock_skill": bool(_supervisor_intent.get("lock_skill")),
                    "reason": _supervisor_intent.get("reason", ""),
                    "tactic_id": _supervisor_intent.get("tactic_id", ""),
                    "query": "Buscando skill compatível com tech_stack + capability + learning aceito",
                },
            )
    except Exception:
        pass

    try:
        _refresh_active_skills(state)
        group = _bootstrap_skill_group(state)
        phase_label = str(state.get("current_phase") or group)
        candidate_tools = _candidate_tools_for_skill_bootstrap(state, group)
        skills = list(state.get("active_skills") or [])

        # ── Lookup da Skill Library (fonte primária) ──────────────────────────
        # O agente consulta o banco para encontrar a skill certa para a atividade
        # demandada pelo supervisor, e obtém as ferramentas ranqueadas por score.
        library_skill = _lookup_skill_from_library(state, group)
        if library_skill:
            lib_tools = [t["tool_name"] for t in (library_skill.get("tools") or []) if t.get("tool_name")]
            lib_skill_name = str(library_skill.get("skill_name") or group)
            # Ferramentas da biblioteca têm prioridade; as demais ficam como fallback
            merged_tools = lib_tools + [t for t in candidate_tools if t not in lib_tools]
            candidate_tools = merged_tools
            _update_log_skill_found(state, library_skill, source="library_db")
            state["logs_terminais"].append(
                f"[SkillLibrary] skill encontrada: {lib_skill_name} "
                f"tools_ranqueadas={lib_tools[:5]} "
                f"source=library_db"
            )
            # Guarda guia da melhor ferramenta no estado para uso pelo tool_executor
            best_tool_entry = library_skill.get("tools", [{}])[0] if library_skill.get("tools") else {}
            state["skill_library_context"] = {
                "skill_name": lib_skill_name,
                "skill_id": lib_skill_name,
                "ranked_tools": lib_tools,
                "best_tool": best_tool_entry.get("tool_name", ""),
                "best_tool_score": best_tool_entry.get("score", 0),
                "best_tool_guide": best_tool_entry.get("usage_guide", ""),
                "evidence_type": best_tool_entry.get("evidence_type", ""),
                "objective": library_skill.get("objective", ""),
                "quality_criteria": library_skill.get("quality_criteria", ""),
            }
        else:
            state["logs_terminais"].append(
                f"[SkillLibrary] skill não encontrada para activity_type="
                f"{(state.get('current_activity_demand') or {}).get('activity_type', '')}; "
                "usando inferência"
            )

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
            tactic_extra_args = dict(supervisor_selected.get("extra_args") or {})
            adversary_technique = dict(supervisor_selected.get("adversary_technique") or {})
            control_objectives = list(supervisor_selected.get("control_objectives") or [])
            expected_telemetry = list(supervisor_selected.get("expected_telemetry") or [])
            detection_proof_pack = dict(supervisor_selected.get("detection_proof_pack") or {})
            if selected_techniques:
                # If techniques came from accepted learning we still want the
                # tactic-level extra_args to ride along when the technique
                # itself didn't carry any.
                if tactic_extra_args:
                    for tech in selected_techniques:
                        tech.setdefault("extra_args", dict(tactic_extra_args))
                if adversary_technique:
                    for tech in selected_techniques:
                        tech.setdefault("adversary_technique", dict(adversary_technique))
                        tech.setdefault("control_objectives", list(control_objectives))
                        tech.setdefault("expected_telemetry", list(expected_telemetry))
                        tech.setdefault("detection_proof_pack", dict(detection_proof_pack))
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
                if tactic_extra_args and isinstance(playbook, dict):
                    techniques = list(playbook.get("techniques") or [])
                    for tech in techniques:
                        if isinstance(tech, dict):
                            tech.setdefault("extra_args", dict(tactic_extra_args))
                    playbook["techniques"] = techniques
                if adversary_technique and isinstance(playbook, dict):
                    techniques = list(playbook.get("techniques") or [])
                    for tech in techniques:
                        if isinstance(tech, dict):
                            tech.setdefault("adversary_technique", dict(adversary_technique))
                            tech.setdefault("control_objectives", list(control_objectives))
                            tech.setdefault("expected_telemetry", list(expected_telemetry))
                            tech.setdefault("detection_proof_pack", dict(detection_proof_pack))
                    playbook["techniques"] = techniques
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
                    tech_stack=list(state.get("detected_tech_stack") or []),
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
                "adversary_technique": adversary_technique,
                "control_objectives": control_objectives,
                "expected_telemetry": expected_telemetry,
                "detection_proof_pack": detection_proof_pack,
                "source": runtime_invocation.get("source") or "supervisor_selected",
                "matched_by": list(dict.fromkeys(["supervisor_selected_skill", *list(runtime_invocation.get("matched_by") or [])])),
                "candidate_tools": candidate_tools,
                "recommended_tools": guided_tools,
                "worker_rules": dict(runtime_invocation.get("worker_rules") or {}),
                "sub_agent_plan": list(runtime_invocation.get("sub_agent_plan") or []),
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
                "worker_rules": dict(runtime_invocation.get("worker_rules") or {}),
                "sub_agent_plan": list(runtime_invocation.get("sub_agent_plan") or []),
                "matched_by": invocation_record["matched_by"],
                "score": runtime_invocation.get("score", 90),
                "confidence": invocation_record["confidence"],
                "techniques": resolved_techniques,
                "source": invocation_record["source"],
                "playbook_title": playbook.get("title"),
                "tactic_id": supervisor_selected.get("tactic_id"),
                "hypothesis": supervisor_selected.get("hypothesis"),
                "strategy_source": supervisor_selected.get("strategy_source"),
                "adversary_technique": adversary_technique,
                "control_objectives": control_objectives,
                "expected_telemetry": expected_telemetry,
                "detection_proof_pack": detection_proof_pack,
            }
            _append_action(state, "skill_invoked", invocation_record)
            _mark_capability_runtime(
                state,
                "adversarial_hypothesis",
                "skill_selector",
                {
                    "skill_id": invocation_record["skill_id"],
                    "recommended_tools": guided_tools[:8],
                    "source": invocation_record["source"],
                },
            )
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
                "worker_rules": dict(invocation.get("worker_rules") or {}),
                "sub_agent_plan": list(invocation.get("sub_agent_plan") or []),
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
            _mark_capability_runtime(
                state,
                "adversarial_hypothesis",
                "skill_selector",
                {
                    "skill_id": inferred_skill_id,
                    "recommended_tools": guided_tools[:8],
                    "source": invocation_record["source"],
                },
            )
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
            _inv = dict(state.get("skill_invocation") or {})
            _gate = dict(state.get("skill_selector_gate") or {})
            _contract = dict(state.get("skill_contract") or {})
            _emit_trace(
                scan_id=int(_trace_scan_id), iteration=int(state.get("loop_iteration", 0)),
                event_type="skill_found", from_node="library", to_node="agent",
                skill_id=_skill_found_id or None,
                capability=str(state.get("pending_capability_node") or state.get("current_phase") or ""),
                status="success" if state.get("skill_selector_ready") else "failure",
                payload={
                    "skill_id": _skill_found_id,
                    # ── PORQUE essa skill saiu como vencedora ──
                    "score": _inv.get("score"),
                    "matched_by": list(_inv.get("matched_by") or _contract.get("matched_by") or [])[:8],
                    "source": _inv.get("source") or _contract.get("source"),
                    "confidence": _inv.get("confidence") or _contract.get("confidence"),
                    "recommended_tools": list(_gate.get("recommended_tools") or [])[:6],
                    "allowed_tools": list(_gate.get("allowed_tools") or [])[:6],
                    "tech_stack": list(state.get("detected_tech_stack") or [])[:8],
                    "techniques_count": len(_inv.get("techniques") or []),
                    "first_technique": (list(_inv.get("techniques") or [{}])[0] if _inv.get("techniques") else {}).get("name", ""),
                    "playbook_title": _gate.get("playbook_title") or _contract.get("playbook_title"),
                },
            )
    except Exception:
        pass

    _metric_end(state, "skill_selector", started_at)
    return state


def skill_planner_node(state: AgentState) -> AgentState:
    """Turn the selected skill into an executable plan contract."""
    from app.graph.workflow import _metric_start, _metric_end, _sync_step_to_db
    from app.graph.nodes.supervisor import _append_action, _mark_capability_runtime

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
        "adversary_technique": dict(invocation.get("adversary_technique") or selected_technique.get("adversary_technique") or {}),
        "control_objectives": list(invocation.get("control_objectives") or selected_technique.get("control_objectives") or []),
        "expected_telemetry": list(invocation.get("expected_telemetry") or selected_technique.get("expected_telemetry") or []),
        "detection_proof_pack": dict(invocation.get("detection_proof_pack") or selected_technique.get("detection_proof_pack") or {}),
        "candidate_tools": list(gate.get("candidate_tools") or invocation.get("candidate_tools") or []),
        "recommended_tools": list(gate.get("recommended_tools") or invocation.get("recommended_tools") or []),
        "worker_rules": dict(contract.get("worker_rules") or invocation.get("worker_rules") or {}),
        "sub_agent_plan": list(contract.get("sub_agent_plan") or invocation.get("sub_agent_plan") or []),
        "evidence_required": list(selected_technique.get("evidence_signals") or []),
        "constraints": list(selected_technique.get("safe_validation_steps") or []),
        "playbook_title": contract.get("playbook_title") or gate.get("playbook_title"),
        "decision_source": "skill_planner",
    }
    state["skill_plan_contract"] = plan
    _append_action(state, "skill_planned", plan)
    _mark_capability_runtime(
        state,
        "strategic_planning",
        "skill_planner",
        {
            "capability": capability,
            "skill_id": plan.get("skill_id"),
            "candidate_tools": list(plan.get("candidate_tools") or [])[:8],
        },
    )
    _mark_capability_runtime(
        state,
        "adversarial_hypothesis",
        "skill_planner",
        {
            "technique": selected_technique.get("name"),
            "evidence_required": list(plan.get("evidence_required") or [])[:8],
        },
    )
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
    from app.graph.nodes.supervisor import _append_action, _mark_capability_runtime

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

    # ── Lookup de ferramentas ranqueadas pela SkillToolMapping (fonte primária) ─
    # O agente vai ao banco para saber qual ferramenta usar para a skill escolhida
    # e como usá-la corretamente (usage_guide).
    lib_ctx = dict(state.get("skill_library_context") or {})
    lib_ranked_tools = [str(t) for t in list(lib_ctx.get("ranked_tools") or []) if str(t or "").strip()]
    lib_best_tool = str(lib_ctx.get("best_tool") or "").strip()
    lib_best_guide = str(lib_ctx.get("best_tool_guide") or "").strip()
    lib_best_score = float(lib_ctx.get("best_tool_score") or 0.0)

    if lib_ranked_tools:
        # Ferramentas do banco (ranqueadas por score) têm precedência
        candidate_set = set(candidate_tools)
        library_valid = [t for t in lib_ranked_tools if t in candidate_set] or lib_ranked_tools
        recommended_tools = library_valid + [t for t in recommended_tools if t not in library_valid]
        state["logs_terminais"].append(
            f"[SkillToolMapping] ferramentas ranqueadas pelo banco: "
            f"{lib_ranked_tools[:5]} best={lib_best_tool}(score={lib_best_score:.1f})"
        )
        if lib_best_guide:
            state["logs_terminais"].append(
                f"[SkillToolMapping] guia de uso de '{lib_best_tool}': {lib_best_guide[:120]}"
            )

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

    # Skill-first: regra do usuario = "no MINIMO 2" (sem cap maximo).
    # Rodamos TODAS as ferramentas elegiveis ainda nao executadas no scan.
    # O ThreadPoolExecutor em _run_tools_and_collect ja limita paralelismo
    # a max_workers=6 e o dedup global em workflow.py protege contra
    # repeticao. Sem cap = cobertura maxima por iteracao.
    #
    # Filtro: preferir tools que AINDA NAO RODARAM neste scan, ordenadas
    # pela skill_runtime (heuristica que ja prioriza por sucesso/falha).
    runtime = dict(state.get("tool_runtime") or {})
    executed_runs = set(state.get("executed_tool_runs") or [])
    def _already_done(t: str) -> bool:
        if any(r.lower().endswith(f"|{str(t).lower()}") for r in executed_runs):
            return True
        meta = runtime.get(t, {})
        return int(meta.get("attempts", 0) or 0) >= 1
    not_yet_run = [t for t in selected_tools if not _already_done(t)]
    if not_yet_run:
        # Garantir minimo 2 quando o pool permite, sem cap maximo.
        selected_tools = not_yet_run
        if len(selected_tools) == 1 and len(candidate_tools) > 1:
            # Apenas 1 sobrou no pool da skill — busca extras no candidate_tools
            # para garantir o minimo de 2 (regra do usuario).
            for extra in candidate_tools:
                if extra not in selected_tools and not _already_done(extra):
                    selected_tools.append(extra)
                    if len(selected_tools) >= 2:
                        break
    else:
        # Todas ja rodaram — manter 1 para o supervisor seguir; o dedup
        # interno vai pular a execucao mas a iteracao avanca.
        selected_tools = selected_tools[:1]
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
        "adversary_technique": dict(plan.get("adversary_technique") or technique.get("adversary_technique") or {}),
        "control_objectives": list(plan.get("control_objectives") or technique.get("control_objectives") or []),
        "expected_telemetry": list(plan.get("expected_telemetry") or technique.get("expected_telemetry") or []),
        "detection_proof_pack": dict(plan.get("detection_proof_pack") or technique.get("detection_proof_pack") or {}),
        "evidence_required": evidence_required,
        "constraints": constraints,
        "worker_rules": dict(plan.get("worker_rules") or contract.get("worker_rules") or invocation.get("worker_rules") or {}),
        "sub_agent_plan": list(plan.get("sub_agent_plan") or contract.get("sub_agent_plan") or invocation.get("sub_agent_plan") or []),
        "playbook_title": plan.get("playbook_title") or contract.get("playbook_title") or gate.get("playbook_title"),
        "decision_source": "skill_selector",
    }
    state["tool_selection_contract"] = selection
    _append_action(state, "tool_selected", selection)
    _mark_capability_runtime(
        state,
        "adversarial_hypothesis",
        "tool_selector",
        {
            "skill_id": selection.get("skill_id"),
            "selected_tools": selected_tools[:8],
            "candidate_tools": candidate_tools[:8],
        },
    )

    try:
        from app.graph.tracer import emit_trace as _emit_trace
        _trace_scan_id = state.get("scan_id")
        if _trace_scan_id:
            _technique_full = dict(selection.get("technique") or {})
            _extra_args_by_tool = _technique_full.get("extra_args") or {}
            _emit_trace(
                scan_id=int(_trace_scan_id), iteration=int(state.get("loop_iteration", 0)),
                event_type="tool_select", from_node="agent", to_node="kali",
                skill_id=str(selection.get("skill_id") or "") or None,
                tool_name=selected_tool or None,
                capability=capability,
                status="success" if selected_tool else "skipped",
                payload={
                    "selected_tool": selected_tool,
                    "selected_tools_all": selected_tools,
                    "candidate_tools": candidate_tools[:8],
                    "allowed_tools_from_skill": list(supervisor_selected.get("allowed_tools") or [])[:8],
                    "preferred_tool": preferred_tool,
                    "capability": capability,
                    "technique": _technique_full.get("name", ""),
                    "technique_objective": _technique_full.get("objective", ""),
                    "adversary_technique": dict(selection.get("adversary_technique") or {}),
                    "control_objectives": list(selection.get("control_objectives") or [])[:5],
                    "expected_telemetry": list(selection.get("expected_telemetry") or [])[:5],
                    "detection_proof_pack": dict(selection.get("detection_proof_pack") or {}),
                    "extra_args": dict(_extra_args_by_tool) if isinstance(_extra_args_by_tool, dict) else {},
                    "evidence_required": evidence_required[:6],
                    "playbook_title": selection.get("playbook_title"),
                    "reason": (
                        f"ferramenta '{selected_tool}' selecionada por estar em allowed_tools={list(supervisor_selected.get('allowed_tools') or [])[:4]} "
                        f"da skill '{selection.get('skill_id')}'"
                        if selected_tool else
                        f"nenhuma ferramenta autorizada pela skill '{selection.get('skill_id')}'"
                    ),
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

    # Persiste ferramenta escolhida e score no AgentActivityLog
    _persist_tool_selection_to_log(state, selected_tool, lib_best_score if selected_tool == lib_best_tool else 0.0, lib_best_guide if selected_tool == lib_best_tool else "")

    _metric_end(state, "tool_selector", started_at)
    return state


def _persist_tool_selection_to_log(
    state: AgentState,
    tool_name: str,
    score: float,
    usage_guide: str,
) -> None:
    """Atualiza o AgentActivityLog com a ferramenta selecionada e seu score."""
    from app.services.skill_library_service import update_agent_activity_log
    from app.db.session import SessionLocal

    log_id = state.get("current_activity_log_id")
    if not log_id or not tool_name:
        return
    try:
        db = SessionLocal()
        update_agent_activity_log(
            db,
            log_id,
            tool_selected=tool_name,
            tool_score=score if score else None,
            tool_usage_guide=usage_guide,
            status="tool_selected",
        )
        db.close()
    except Exception as exc:
        state["logs_terminais"].append(f"[ToolSelector] log update falhou: {exc}")


def _all_pending_targets(state: AgentState) -> list[str]:
    """ALL operator-supplied root targets + every discovered subdomain.

    When the operator submitted "domain1.com; domain2.com", both are treated
    as roots so threat_intel / risk_assessment cover the full target set.
    No artificial cap — every subdomain discovered in P01 must be analyzed
    by subsequent phases.
    """
    from app.graph.workflow import _target_host

    root = str(state.get("target") or "").strip()
    scanned = set(state.get("scanned_assets") or [])
    candidates: list[str] = []

    # Prefer the full input_targets list so ALL operator-supplied roots are
    # included, not just the primary target stored in state['target'].
    input_targets = [
        str(t or "").strip()
        for t in list(state.get("input_targets") or [])
        if str(t or "").strip()
    ]
    if input_targets:
        for t in input_targets:
            if t and t not in candidates:
                candidates.append(t)
    else:
        # Fallback: split primary target string (handles legacy state without input_targets)
        import re as _re
        for token in _re.split(r"[;,]", root):
            t = str(token or "").strip()
            if t and t not in candidates:
                candidates.append(t)

    # All discovered subdomains not yet scanned
    for asset in list(state.get("pending_asset_scans") or []):
        host = str(asset or "").strip()
        if host and host not in scanned and host not in candidates:
            candidates.append(host)

    # Also include already-scanned assets so they aren't dropped from the list
    # (threat_intel may need to revisit them for correlation)
    for asset in list(state.get("scanned_assets") or []):
        host = str(asset or "").strip()
        if host and host not in candidates:
            candidates.append(host)

    return candidates


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
        # All pending subdomains + root — no artificial cap
        all_targets = _all_pending_targets(state)
        osint_targets = _validate_osint_targets(all_targets)
        if osint_targets:
            return osint_targets
        host = _target_host(str(state.get("target") or ""))
        return [host or str(state.get("target") or "").strip()]

    if capability == "risk_assessment":
        # All pending subdomains + root — no artificial cap
        all_targets = _all_pending_targets(state)
        explicit_target = str(state.get("target") or "").strip()
        is_local = _is_local_target(explicit_target)
        if is_local:
            # Local targets skip DNS resolution check
            resolvable_targets = list(dict.fromkeys(all_targets))
            unresolved_targets: list[str] = []
        else:
            resolvable_targets, unresolved_targets = _filter_resolvable_targets(all_targets)
            if explicit_target and _is_local_target(explicit_target):
                if explicit_target not in resolvable_targets:
                    resolvable_targets.insert(0, explicit_target)
        if not resolvable_targets:
            resolvable_targets = [explicit_target or state.get("target", "")]
        state["risk_targets_resolvable"] = list(resolvable_targets)
        state["risk_targets_unresolved"] = list(unresolved_targets)
        if unresolved_targets:
            state["logs_terminais"].append(
                f"RiskAssessment: unresolved_skipped={len(unresolved_targets)} sample={unresolved_targets[:5]}"
            )
        return list(resolvable_targets)

    # asset_discovery fallback:
    # P01 (subdomain enumeration) runs against EVERY root target the operator
    # supplied (input_targets). If they typed "domain1.com; domain2.com", both
    # domains are enumerated sequentially so their subdomains are combined into
    # the discovery pool before P02-P06 begins.
    # P02-P06 (port scan, WAF, TLS, headers, crawling) run against ALL root targets
    # PLUS every discovered subdomain — no artificial limit.
    phase_id = str(state.get("current_pentest_phase_id") or "")
    root = str(state.get("target") or "").strip()
    input_targets = [
        str(t or "").strip()
        for t in list(state.get("input_targets") or [])
        if str(t or "").strip()
    ] or ([root] if root else [])

    if phase_id == "P01" or not root:
        # P01: run discovery tools on each operator-supplied root domain
        # sequentially so all roots contribute subdomains to the scan pool.
        return input_targets if input_targets else ([root] if root else [])

    # P02-P06: expand from ALL root targets + all discovered subdomains
    pending = list(state.get("pending_asset_scans") or [])
    scanned = list(state.get("scanned_assets") or [])
    seen: set[str] = set()
    all_recon_targets: list[str] = []
    for host in input_targets + pending + scanned:
        h = str(host or "").strip()
        if h and h not in seen:
            seen.add(h)
            all_recon_targets.append(h)
    return all_recon_targets or input_targets or [root]


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
        _refresh_recon_graph,
        MAX_DISCOVERED_ASSETS,
    )

    current = _step_name(state)
    _refresh_recon_graph(
        state,
        capability=capability,
        target=target,
        tools=tools,
        findings=findings,
        ports=ports,
        assets=assets,
        port_evidence=port_evidence,
    )
    if findings:
        state["vulnerabilidades_encontradas"].extend(findings)

    if capability == "asset_discovery":
        if ports:
            state["discovered_ports"] = sorted(set((state.get("discovered_ports") or []) + ports))
            state["pending_port_tests"] = state["discovered_ports"].copy()
        if assets:
            # Use `target` (current scan target) as the scope root so that
            # assets discovered while running on domain2.com are scoped to
            # domain2.com, not filtered out by the primary state.target.
            root_domain = _target_host(target or state.get("target") or "")
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

    if capability in ("risk_assessment", "threat_intel"):
        # Mark this target as scanned and drain it from pending queue
        scanned = list(state.get("scanned_assets") or [])
        if target and target not in scanned:
            scanned.append(target)
            state["scanned_assets"] = scanned
        pending = list(state.get("pending_asset_scans") or [])
        if target in pending:
            pending.remove(target)
            state["pending_asset_scans"] = pending

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
        _mark_capability_runtime,
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
        if capability in TOOL_CAPABILITY_NODES:
            _mark_capability_runtime(
                state,
                capability,
                "tool_executor",
                {"blocked": True, "reason": reason},
            )
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
            _tech_for_emit = dict(selection.get("technique") or {})
            _exec_extra_args = _tech_for_emit.get("extra_args") or {}
            _emit_trace(
                scan_id=int(_trace_scan_id_ex), iteration=int(state.get("loop_iteration", 0)),
                event_type="tool_execute", from_node="agent", to_node="kali",
                skill_id=skill_id or None,
                tool_name=selected_tools[0] if selected_tools else None,
                capability=capability, status="pending",
                payload={
                    "tools": selected_tools,
                    "targets": [str(t) for t in targets[:3]],
                    "extra_args": dict(_exec_extra_args) if isinstance(_exec_extra_args, dict) else {},
                    "tech_stack": list(state.get("detected_tech_stack") or [])[:8],
                    "skill_id": skill_id,
                    "lock_skill": bool(supervisor_selected.get("lock_skill")),
                    "reason": (
                        f"executando {len(selected_tools)} ferramenta(s) da skill '{skill_id}' "
                        f"com argumentos calibrados pelo tech_stack: "
                        f"{','.join(state.get('detected_tech_stack') or []) or '-'}"
                    ),
                },
            )
    except Exception:
        pass

    _executor_findings_before = len(state.get("vulnerabilidades_encontradas") or [])

    if not selected_tools:
        state["logs_terminais"].append(f"[executor] capability={capability} sem tool selecionada; nada executado")
    else:
        # ── Batch-aware dispatch ─────────────────────────────────────────────────
        # Tools that natively support a targets-file (-iL / -list / -l) run ONCE
        # against ALL discovered subdomains.  Other tools still run per-target.
        from app.services.kali_executor import BATCH_TOOL_TO_PROFILE as _BATCH_PROFILES

        batch_tools = [t for t in selected_tools if t.lower() in _BATCH_PROFILES]
        serial_tools = [t for t in selected_tools if t.lower() not in _BATCH_PROFILES]
        use_batch = len(targets) > 1 and bool(batch_tools)

        if use_batch:
            state["logs_terminais"].append(
                f"[executor] BATCH dispatch: {len(batch_tools)} tools × {len(targets)} targets "
                f"→ 1 call each  batch={batch_tools[:4]}  serial_remaining={serial_tools[:4]}"
            )
            # Run batch-capable tools ONCE against the full target list.
            # targets[0] is the nominal "scan_target" for dedup/logging; the real
            # work happens against all hosts via the Kali runner's targets file.
            findings, ports, assets, port_evidence = _run_tools_and_collect(
                state,
                batch_tools,
                targets[0],
                _step_name(state),
                f"ToolExecutor:{capability}",
                root_domain=_target_host(targets[0]),
                skill_context=selection,
                all_targets=targets,
            )
            _apply_tool_execution_findings(
                state,
                capability,
                targets[0],
                batch_tools,
                findings,
                ports,
                assets,
                port_evidence,
            )
            # Mark ALL batch targets as scanned so pending queue drains correctly.
            if capability in ("risk_assessment", "threat_intel"):
                scanned = list(state.get("scanned_assets") or [])
                pending = list(state.get("pending_asset_scans") or [])
                for _bt in targets:
                    if _bt and _bt not in scanned:
                        scanned.append(_bt)
                    if _bt in pending:
                        pending.remove(_bt)
                state["scanned_assets"] = scanned
                state["pending_asset_scans"] = pending
            all_results.append(
                {
                    "target": f"[batch:{len(targets)}×{','.join(batch_tools[:3])}]",
                    "tools": batch_tools,
                    "findings": len(findings),
                    "ports": ports,
                    "assets": assets,
                    "skill_id": selection.get("skill_id"),
                    "technique": (selection.get("technique") or {}).get("name"),
                    "batch_target_count": len(targets),
                }
            )

        # Run non-batch tools per-target (unchanged legacy behaviour for tools
        # that do not support a targets file).
        tools_for_serial = serial_tools if use_batch else selected_tools
        for scan_target in targets:
            target_tools = tools_for_serial
            if capability == "risk_assessment":
                target_tools = _tools_for_validation_target(scan_target, tools_for_serial)
            if not target_tools:
                continue
            findings, ports, assets, port_evidence = _run_tools_and_collect(
                state,
                target_tools,
                scan_target,
                _step_name(state),
                f"ToolExecutor:{capability}",
                # Use scan_target as the scope root so that when running on
                # domain2.com the extracted assets (sub.domain2.com, etc.) are
                # scoped to domain2.com and not filtered out by domain1.com.
                root_domain=_target_host(scan_target),
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

    # ── Tech-stack refresh after every execution that touched recon/vuln. ─
    # The detector reads ALL findings, so even when this cycle ran a vuln
    # tool we update the fingerprint with anything new the workers produced.
    try:
        from app.graph.workflow import _refresh_recon_graph, _refresh_tech_stack
        stack_changed = _refresh_tech_stack(state)
        for executed in all_results:
            _refresh_recon_graph(
                state,
                capability=capability,
                target=str(executed.get("target") or state.get("target") or ""),
                tools=[str(tool) for tool in list(executed.get("tools") or [])],
                findings=[],
                ports=[],
                assets=[],
                port_evidence={},
            )
        if stack_changed:
            # Force supervisor to re-evaluate active_skills next iteration.
            state["pending_skill_refresh"] = True
    except Exception:
        pass

    completed = list(state.get("completed_capabilities") or [])
    if capability in TOOL_CAPABILITY_NODES and capability not in completed:
        completed.append(capability)
    state["completed_capabilities"] = completed
    if capability in TOOL_CAPABILITY_NODES:
        _mark_capability_runtime(
            state,
            capability,
            "tool_executor",
            {
                "tools": selected_tools[:12],
                "targets_executed": len(all_results),
                "findings_added": _findings_delta_post,
            },
        )
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
        _mark_capability_runtime,
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
    _mark_capability_runtime(
        state,
        "evidence_adjudication",
        "evidence_gate",
        {
            "findings_total": len(adjudicated),
            "promoted": promoted,
            "backlog": len(backlog),
        },
    )
    state["logs_terminais"].append(
        f"EvidenceGate: total={len(adjudicated)} promoted_confident={promoted} backlog={len(backlog)}"
    )
    state["proxima_ferramenta"] = "governance"
    state["mission_index"] += 1
    _metric_end(state, "evidence_gate", started_at)
    _sync_step_to_db(state, "Evidence Gate")
    return state


# ── Agent Reporter ─────────────────────────────────────────────────────────────


def agent_reporter_node(state: AgentState) -> AgentState:
    """Nó de relatório do agente.

    Após a execução da ferramenta, o agente compila um relatório estruturado
    com os dados coletados, operação realizada e score de qualidade,
    e o envia ao supervisor perguntando se a atividade foi satisfatória.
    O relatório é persistido no AgentActivityLog para visibilidade na UI.
    """
    from app.graph.workflow import _metric_start, _metric_end, _sync_step_to_db
    from app.graph.nodes.supervisor import _append_action

    started_at = _metric_start()
    _sync_step_to_db(state, "Agent Reporter")

    demand = dict(state.get("current_activity_demand") or {})
    selection = dict(state.get("tool_selection_contract") or {})
    lib_ctx = dict(state.get("skill_library_context") or {})
    results = list(state.get("tool_execution_results") or [])
    findings = list(state.get("vulnerabilidades_encontradas") or [])

    capability = str(selection.get("capability") or state.get("pending_capability_node") or "")
    tool_used = str(selection.get("selected_tools", [""])[0] if selection.get("selected_tools") else "")
    skill_used = str(selection.get("skill_id") or lib_ctx.get("skill_name") or "")

    # Conta achados gerados nesta iteração (últimos da lista)
    iteration_findings = [
        f for f in findings
        if str((f.get("details") or {}).get("node") or "") == capability
    ]
    findings_count = len(iteration_findings)

    # Score de qualidade: baseado em execução bem-sucedida + achados
    executed_ok = bool(results) and all(
        not r.get("error") for r in results
    )
    has_findings = findings_count > 0
    quality_score = 0.0
    if executed_ok:
        quality_score += 0.5
    if has_findings:
        quality_score += 0.3
    if findings_count >= 3:
        quality_score += 0.2

    operation_summary = (
        f"Executou '{tool_used}' para skill '{skill_used}' na fase '{capability}'. "
        f"Encontrou {findings_count} achados."
    )

    report = {
        "activity_id": demand.get("activity_id", ""),
        "activity_type": demand.get("activity_type", ""),
        "capability": capability,
        "kill_chain_phases": demand.get("kill_chain_phases", []),
        "skill_used": skill_used,
        "tool_used": tool_used,
        "tool_score": lib_ctx.get("best_tool_score", 0),
        "findings_count": findings_count,
        "quality_score": round(quality_score, 2),
        "operation_performed": operation_summary,
        "data_collected": [
            {
                "title": str(f.get("title", "")),
                "severity": str(f.get("severity", "")),
                "tool": str((f.get("details") or {}).get("tool", tool_used)),
            }
            for f in iteration_findings[:10]
        ],
        "question_to_supervisor": (
            f"Atividade '{demand.get('activity_type', '')}' concluída. "
            f"Qualidade: {quality_score:.0%}. "
            f"{findings_count} achados coletados com '{tool_used}'. "
            "Foi satisfatório para avançar na Kill Chain?"
        ),
        "reported_at": __import__("datetime").datetime.utcnow().isoformat(),
        "iteration": int(state.get("loop_iteration", 0)),
    }
    state["agent_report"] = report
    _append_action(state, "agent_reported", report)

    state["logs_terminais"].append(
        f"[Agente→Supervisor] Relatório: activity={report['activity_type']} "
        f"tool={tool_used} skill={skill_used} "
        f"findings={findings_count} quality={quality_score:.0%} "
        f"pergunta='{report['question_to_supervisor'][:80]}'"
    )

    # Persiste relatório no banco
    log_id = state.get("current_activity_log_id")
    if log_id:
        try:
            from app.services.skill_library_service import update_agent_activity_log
            from app.db.session import SessionLocal
            db = SessionLocal()
            update_agent_activity_log(
                db,
                log_id,
                agent_report=report,
                execution_result={
                    "results_count": len(results),
                    "executed_ok": executed_ok,
                    "tool": tool_used,
                },
                status="reported",
            )
            db.close()
        except Exception as exc:
            state["logs_terminais"].append(f"[AgentReporter] log update falhou: {exc}")

    _metric_end(state, "agent_reporter", started_at)
    return state
