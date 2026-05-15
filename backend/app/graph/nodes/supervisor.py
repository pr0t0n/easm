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
    from app.graph.kill_chain import STAGE_ALLOWED_SKILLS, KILL_CHAIN_STAGES

    selected = select_mission_skills(
        target=str(state.get("target") or ""),
        findings=list(state.get("vulnerabilidades_encontradas") or []),
        target_type=str(state.get("target_type") or "dominio"),
        discovered_ports=list(state.get("discovered_ports") or []),
        max_skills=8,
        detected_tech_stack=list(state.get("detected_tech_stack") or []),
    )
    # ── Kill-chain gating: drop skills that are not allowed in the current stage.
    # Without this, a recon iteration could pick vuln-injection (exploitation) just
    # because the trigger matched, jumping ahead of vuln-analysis.
    stage = str(state.get("kill_chain_stage") or "RECONNAISSANCE").upper()
    allowed = STAGE_ALLOWED_SKILLS.get(stage, set())
    if allowed:
        gated = [skill for skill in selected if str(skill.get("id") or "") in allowed]
        if gated:
            blocked = [str(s.get("id") or "") for s in selected if s not in gated]
            if blocked:
                _append_note(
                    state,
                    f"Kill-chain gate (stage={stage}) bloqueou skills fora da fase: {', '.join(blocked[:8])}",
                    phase="kill-chain-gate",
                )
            selected = gated
        else:
            # No allowed skill matched the heuristic — surface this so the
            # supervisor can pick from the stage's allowlist directly.
            from app.graph.mission import SKILL_CATALOG
            fallback = [dict(s) for s in SKILL_CATALOG if str(s.get("id") or "") in allowed][:6]
            if fallback:
                _append_note(
                    state,
                    f"Kill-chain gate (stage={stage}) usou catalogo direto (heuristica nao bateu): "
                    f"{', '.join(str(s.get('id') or '') for s in fallback)}",
                    phase="kill-chain-gate",
                )
                selected = fallback

    prev_ids = {str(item.get("id") or "") for item in list(state.get("active_skills") or [])}
    state["active_skills"] = selected
    selected_ids = [str(item.get("id") or "") for item in selected]
    if set(selected_ids) != prev_ids:
        _append_note(state, f"Skills ativas atualizadas: {', '.join(selected_ids)}", phase="skill-selection")
    # Consumed: clear pending_skill_refresh hint set by skill_pipeline when
    # the tech-stack signature changed last iteration.
    if state.get("pending_skill_refresh"):
        state["pending_skill_refresh"] = False


def _maybe_advance_kill_chain_stage(state: AgentState) -> None:
    """Called once per supervisor iteration; logs + persists transitions."""
    from app.graph.kill_chain import advance_kill_chain_stage

    new_stage, advanced, reason = advance_kill_chain_stage(dict(state))
    state["kill_chain_stage"] = new_stage
    if advanced:
        _append_note(
            state,
            f"Kill-chain stage advanced -> {new_stage} ({reason})",
            phase="kill-chain-gate",
        )
        try:
            from app.graph.tracer import emit_trace as _emit_trace
            _scan_id = state.get("scan_id")
            if _scan_id:
                _emit_trace(
                    scan_id=int(_scan_id),
                    iteration=int(state.get("loop_iteration", 0)),
                    event_type="stage_advanced",
                    from_node="supervisor",
                    to_node="supervisor",
                    capability=str(state.get("pending_capability_node") or ""),
                    status="success",
                    payload={
                        "new_stage": new_stage,
                        "reason": reason,
                        "tech_stack": list(state.get("detected_tech_stack") or [])[:8],
                        "discovered_ports": list(state.get("discovered_ports") or [])[:8],
                    },
                )
        except Exception:
            pass
    else:
        # Optional breadcrumb so the operator sees why the stage held.
        state.setdefault("logs_terminais", []).append(
            f"[kill-chain] stage={new_stage} held: {reason}"
        )


def _hypothesis_driven_tactic(state: AgentState, *, capability: str) -> dict[str, Any] | None:
    """Pick the highest-confidence pending hypothesis whose suggested_skill is
    allowed in the current kill-chain stage, and materialise it as a tactic.

    Hypotheses come from `app.services.hypothesis_engine` and are refreshed
    by the workflow after each tool execution. This is the PRIMARY source
    of tactic decisions — beats both tech-stack auto-lock and the strategy
    queue. If no hypothesis applies, the supervisor falls back to the
    other paths (auto-lock → queue → heuristic).

    The function NEVER returns hypotheses already executed (tracked via the
    `pentest_tactics_completed` list with tactic_id `hypothesis:family:hid`).
    """
    try:
        from app.graph.kill_chain import stage_allows_skill
        from app.services.hypothesis_engine import hypothesis_to_tactic
    except Exception:
        return None

    hypotheses = list(state.get("pentest_hypotheses") or [])
    if not hypotheses:
        return None

    stage = str(state.get("kill_chain_stage") or "RECONNAISSANCE").upper()
    completed_ids = _completed_pentest_tactic_ids(state)

    # Mapa skill_id → capability owner (skills só firam quando capability bate)
    # Sem isso, uma hipotese de vuln-injection (que pertence a risk_assessment)
    # era firada sob asset_discovery, criando um loop infinito na fase 1.
    from app.graph.mission import SKILL_CATALOG
    skill_to_capability = {}
    capability_categories = {
        "asset_discovery": {"reconnaissance", "technologies", "protocols"},
        "threat_intel": {"osint", "code"},
        "risk_assessment": {"vulnerabilities", "protocols", "tooling"},
    }
    for skill in SKILL_CATALOG:
        sid = str(skill.get("id") or "")
        cat = str(skill.get("category") or "").lower()
        for cap, cats in capability_categories.items():
            if cat in cats:
                skill_to_capability.setdefault(sid, cap)
                break

    # Sort by confidence descending; iterate until we find one whose
    # suggested_skill is permitted in current stage AND belongs to current
    # capability AND not already done.
    sorted_hs = sorted(
        hypotheses, key=lambda h: -float(h.get("confidence") or 0)
    )
    for h in sorted_hs:
        skill_id = str(h.get("suggested_skill") or "")
        if not stage_allows_skill(stage, skill_id):
            continue
        # Capability gate: only fire when the suggested skill actually
        # belongs to the current capability. Otherwise the supervisor would
        # be stuck on the first capability while injecting downstream skills.
        skill_owner_cap = skill_to_capability.get(skill_id)
        if skill_owner_cap and skill_owner_cap != capability:
            continue
        tactic = hypothesis_to_tactic(h, capability=capability)
        if str(tactic.get("capability") or "") != capability:
            continue
        if str(tactic.get("tactic_id") or "") in completed_ids:
            continue
        state["pending_pentest_tactic"] = dict(tactic)
        _append_action(state, "hypothesis_driven_tactic", {
            "hypothesis_id": h.get("id"),
            "family": h.get("family"),
            "confidence": h.get("confidence"),
            "skill_id": skill_id,
            "tool": h.get("suggested_tool"),
            "target": h.get("target"),
            "param": h.get("target_param"),
        })
        state.setdefault("logs_terminais", []).append(
            f"[hypothesis] driver={h.get('family')} skill={skill_id} "
            f"tool={h.get('suggested_tool')} conf={h.get('confidence')}"
        )
        return tactic
    return None


def _stack_evidence_strict(state: AgentState) -> dict[str, bool]:
    """Returns {tag: True/False} where True means the actual evidence
    blob from recon findings contains a high-confidence keyword for the
    tag — used to suppress tech-stack false positives that the permissive
    regex detector produces.

    Only tags listed here are strict-checked. Tags absent return True so
    the auto-lock keeps working for them.
    """
    findings = list(state.get("vulnerabilidades_encontradas") or [])
    blob = ""
    for f in findings:
        if not isinstance(f, dict):
            continue
        details = f.get("details") or {}
        if isinstance(details, dict):
            blob += " " + str(details.get("evidence") or "")
            blob += " " + str(details.get("stdout") or "")
            blob += " " + str(details.get("http_headers_raw") or "")
        blob += " " + str(f.get("title") or "")
    blob_l = blob.lower()
    return {
        "wordpress": (
            ("wp-content" in blob_l)
            or ("wp-admin" in blob_l)
            or ("wp-includes" in blob_l)
            or ("wp-json" in blob_l)
            or ("wp-login.php" in blob_l)
            or ("x-pingback" in blob_l)
        ),
        "php":       ("phpsessid" in blob_l) or ("x-powered-by: php" in blob_l) or (".php" in blob_l) or ("php/" in blob_l),
        "mysql":     ("you have an error in your sql syntax" in blob_l) or ("mariadb" in blob_l) or ("mysql" in blob_l) or ("phpmyadmin" in blob_l),
        "asp.net":   ("x-aspnet-version" in blob_l) or ("asp.net_sessionid" in blob_l) or ("aspsessionid" in blob_l) or (".aspx" in blob_l) or (".asp" in blob_l) or ("microsoft-iis" in blob_l),
        "iis":       ("microsoft-iis" in blob_l) or ("x-aspnet-version" in blob_l),
        "mssql":     ("microsoft sql server" in blob_l) or ("mssql" in blob_l) or ("sqlserver" in blob_l) or ("sqlexpress" in blob_l) or ("x-aspnet-version" in blob_l),
    }


def _auto_lock_tactic_from_tech_stack(state: AgentState) -> dict[str, Any] | None:
    """Builds a high-priority pentest tactic from detected_tech_stack.

    Returns the tactic dict (also stored in state["pending_pentest_tactic"])
    when a matching tag is present, the tactic was not already completed,
    AND the current kill-chain stage allows the locked skill.
    Returns None when no auto-lock applies — the regular strategy queue path
    handles fallback in that case.
    """
    try:
        from app.services.tech_stack_detector import TECH_STACK_TACTIC_LOCKS
        from app.graph.kill_chain import stage_allows_skill
    except Exception:
        return None

    stack = [str(item).strip().lower() for item in (state.get("detected_tech_stack") or [])]
    if not stack:
        return None

    current_stage = str(state.get("kill_chain_stage") or "RECONNAISSANCE").upper()

    completed_ids = _completed_pentest_tactic_ids(state)
    pending_existing = dict(state.get("pending_pentest_tactic") or {})
    if pending_existing.get("tactic_id", "").startswith("tech-stack:"):
        # Already locked from a previous iteration; honour it instead of
        # rebuilding on every supervisor pass.
        if str(pending_existing.get("tactic_id") or "") not in completed_ids:
            return pending_existing

    # Tools with attempts/success > 0 → no point in re-firing the same
    # tactic. The runtime metrics map tool → {attempts, success, failures}.
    runtime = dict(state.get("tool_runtime") or {})

    # Strict evidence gate per tag: only fire WordPress/CMS auto-lock when
    # the actual stdout from recon contained 'wp-content' or 'wp-admin'.
    # The tech-stack detector is permissive (matches the substring "wordpress"
    # anywhere) so it produced FPs on testaspnet. Strengthen by re-checking
    # the actual findings evidence.
    strong_evidence = _stack_evidence_strict(state)

    for tag in stack:
        spec = TECH_STACK_TACTIC_LOCKS.get(tag)
        if not spec:
            continue
        # Drop tags whose strict evidence isn't present in findings — this
        # prevents wpscan from firing against ASP.NET targets just because
        # the tech-stack detector matched a stray substring.
        if tag in strong_evidence and not strong_evidence.get(tag):
            state.setdefault("logs_terminais", []).append(
                f"[kill-chain] auto-lock '{tag}'→'{spec.get('skill_id')}' bloqueado "
                f"por falta de evidencia forte (sem keyword especifica nos findings)."
            )
            continue
        # ── Stage gate: do not lock an exploitation skill while we are still
        # in RECON or VULN_ANALYSIS. The lock takes effect when the stage
        # actually permits the skill.
        if not stage_allows_skill(current_stage, str(spec.get("skill_id") or "")):
            state.setdefault("logs_terminais", []).append(
                f"[kill-chain] auto-lock '{tag}'→'{spec.get('skill_id')}' bloqueado "
                f"pela stage atual ({current_stage})."
            )
            continue
        # Runtime gate: if the preferred tool already attempted, skip.
        preferred = str(spec.get("preferred_tool") or "").lower()
        if preferred:
            meta = runtime.get(preferred, {})
            if int(meta.get("attempts", 0) or 0) >= 1:
                state.setdefault("logs_terminais", []).append(
                    f"[kill-chain] auto-lock '{tag}'→'{preferred}' bloqueado "
                    f"porque tool ja tentou ({meta}) — aceitando proxima tactic."
                )
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


def _distinct_executed_tools(state: AgentState) -> set[str]:
    tools = {
        str(run).lower().split("|")[-1]
        for run in list(state.get("executed_tool_runs") or [])
        if "|" in str(run)
    }
    return {tool for tool in tools if tool}


def _coverage_gap_tactic_for_stage(state: AgentState) -> dict[str, Any] | None:
    """Exhaustive kill-chain coverage tactic.

    The user requirement: read the WHOLE skill library, see which tools
    apply to the current stage, and run ALL of them — not stop after one
    or two. This function therefore sweeps EVERY tool of EVERY skill the
    current kill-chain stage allows, and keeps emitting tactics until all
    of them have been attempted.

    Algorithm:
      1. Build the stage tool universe = union of playbooks of every
         skill in STAGE_ALLOWED_SKILLS[stage].
      2. Subtract tools already executed this scan -> pending tools.
      3. If nothing pending -> return None (stage fully swept; the
         supervisor may advance).
      4. Otherwise pick the stage-allowed skill that covers the MOST
         pending tools and emit a tactic locked to it with allowed_tools
         = every pending tool that skill can run.

    While this returns a tactic the supervisor stays on the stage — it
    cannot drift to governance/executive with the stage half-covered.
    """
    from app.graph.kill_chain import STAGE_ALLOWED_SKILLS, stage_allows_skill
    from app.graph.mission import SKILL_CATALOG
    from app.services.kali_executor import TOOL_TO_PROFILE

    stage = str(state.get("kill_chain_stage") or "RECONNAISSANCE").upper()
    completed_ids = _completed_pentest_tactic_ids(state)
    distinct_tools = _distinct_executed_tools(state)
    runtime = dict(state.get("tool_runtime") or {})

    allowed_skill_ids = STAGE_ALLOWED_SKILLS.get(stage, set())
    if not allowed_skill_ids:
        return None

    # skill_id -> playbook (only Kali-dispatchable tools), and skill -> capability
    _CAT_TO_CAP = {
        "reconnaissance": "asset_discovery", "technologies": "asset_discovery",
        "protocols": "risk_assessment", "osint": "threat_intel",
        "code": "threat_intel", "vulnerabilities": "risk_assessment",
        "tooling": "risk_assessment", "orchestration": "asset_discovery",
    }
    skill_tools: dict[str, list[str]] = {}
    skill_capability: dict[str, str] = {}
    skill_desc: dict[str, str] = {}
    for skill in SKILL_CATALOG:
        sid = str(skill.get("id") or "")
        if sid not in allowed_skill_ids:
            continue
        playbook = [
            str(t).strip().lower()
            for t in (skill.get("playbook") or [])
            if str(t).strip().lower() in TOOL_TO_PROFILE
        ]
        if not playbook:
            continue
        skill_tools[sid] = playbook
        skill_capability[sid] = _CAT_TO_CAP.get(str(skill.get("category") or "").lower(), "risk_assessment")
        skill_desc[sid] = str(skill.get("description") or "")

    # Stage tool universe minus already-attempted (executed OR runtime attempt).
    def _attempted(tool: str) -> bool:
        if tool in distinct_tools:
            return True
        meta = runtime.get(tool, {})
        return int(meta.get("attempts", 0) or 0) >= 1

    universe: set[str] = set()
    for tools in skill_tools.values():
        universe.update(tools)
    pending = sorted(t for t in universe if not _attempted(t))
    if not pending:
        return None  # stage fully swept

    # Pick the skill covering the MOST pending tools.
    best_skill = ""
    best_cover: list[str] = []
    for sid, tools in skill_tools.items():
        if not stage_allows_skill(stage, sid):
            continue
        cover = [t for t in tools if t in pending]
        if len(cover) > len(best_cover):
            best_cover = cover
            best_skill = sid
    if not best_skill or not best_cover:
        return None

    capability = skill_capability.get(best_skill, "asset_discovery")
    # tactic_id encodes how many pending tools remain so a fresh id fires
    # each iteration as the sweep progresses (never marked "completed" in a
    # way that would stop the sweep prematurely).
    tactic_id = f"coverage:{stage.lower()}:{best_skill}:remaining-{len(pending)}"
    if tactic_id in completed_ids:
        # Same remaining-count tactic already done — nudge the id so the
        # sweep continues on the next-best skill instead of stalling.
        alt = [sid for sid in skill_tools if sid != best_skill and any(t in pending for t in skill_tools[sid])]
        if not alt:
            return None
        best_skill = alt[0]
        best_cover = [t for t in skill_tools[best_skill] if t in pending]
        capability = skill_capability.get(best_skill, "asset_discovery")
        tactic_id = f"coverage:{stage.lower()}:{best_skill}:alt-{len(pending)}"

    tactic = {
        "tactic_id": tactic_id,
        "skill_id": best_skill,
        "capability": capability,
        "objective": (
            f"Cobertura exaustiva da stage {stage}: executar TODAS as ferramentas "
            f"pendentes da skill '{best_skill}'."
        ),
        "hypothesis": skill_desc.get(best_skill, "")[:300],
        "allowed_tools": list(dict.fromkeys(best_cover)),
        "preferred_tool": best_cover[0],
        "extra_args": {},
        "strategy_source": "kill_chain_coverage_gap",
        "strategy_score": 140,
        "learning_techniques": [],
        "evidence_required": [],
        "constraints": ["read-only probes"],
        "phase_refs": [],
        "targets": [str(state.get("target") or "").strip()],
        "reason": (
            f"Stage {stage} incompleta: {len(pending)} ferramentas pendentes no universo "
            f"da stage. Skill '{best_skill}' cobre {len(best_cover)}: {', '.join(best_cover[:8])}."
        ),
        "lock_skill": True,
    }
    state["pending_pentest_tactic"] = tactic
    _append_action(state, "coverage_gap_tactic", {
        "stage": stage, "tactic_id": tactic_id, "skill": best_skill,
        "covers": best_cover, "pending_total": len(pending),
    })
    return tactic

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


# Phase id → kill_chain_stage label (UI/trace coherence only; the phase
# walker bypasses the stage gate — the phase IS the authority).
_PHASE_TO_KC_STAGE: dict[str, str] = {
    **{f"P{n:02d}": "RECONNAISSANCE" for n in range(1, 11)},
    "P11": "VULNERABILITY_ANALYSIS",
    **{f"P{n:02d}": "EXPLOITATION" for n in range(12, 21)},
    "P21": "VULNERABILITY_ANALYSIS",
    "P22": "EXPLOITATION",
}


def _phase_walker_tactic(state: AgentState) -> dict[str, Any] | None:
    """DETERMINISTIC P01→P22 walker — THE authoritative pentest contract.

    Walks PENTEST_PHASES in strict order. For the current phase it runs
    EVERY installed tool the library defines for that phase; the phase
    index only advances when every tool of the phase has been attempted
    (success OR failure — a failing tool must not stall the chain).

    No phase is skipped. No randomness. P01, then P02, ... then P22.
    Returns None only when all 22 phases are done.
    """
    from app.graph.mission import PENTEST_PHASES, SKILL_CATALOG
    from app.services.tool_catalog import is_tool_installed

    distinct = _distinct_executed_tools(state)
    runtime = dict(state.get("tool_runtime") or {})

    def _attempted(tool: str) -> bool:
        if tool in distinct:
            return True
        return int((runtime.get(tool) or {}).get("attempts", 0) or 0) >= 1

    # phase id → first catalog skill that declares the phase
    phase_skill: dict[str, str] = {}
    for sk in SKILL_CATALOG:
        for ph in (sk.get("phases") or []):
            phase_skill.setdefault(str(ph), str(sk.get("id") or ""))
    node_default_skill = {
        "asset_discovery": "recon-web-crawl",
        "threat_intel": "osint-exposure-intel",
        "risk_assessment": "vuln-nuclei-cve",
    }

    idx = int(state.get("pentest_phase_index", 0) or 0)
    total = len(PENTEST_PHASES)
    while idx < total:
        phase = PENTEST_PHASES[idx]
        ph_id = str(phase.get("id") or f"P{idx + 1:02d}")
        node = str(phase.get("node") or "asset_discovery")
        all_tools = [str(t) for t in (phase.get("tools") or [])]
        installed = [t for t in all_tools if is_tool_installed(t)]
        not_installed = [t for t in all_tools if t not in installed]
        pending = [t for t in installed if not _attempted(t)]

        if not installed:
            state.setdefault("logs_terminais", []).append(
                f"[phase-walker] {ph_id} {phase.get('title')}: nenhuma ferramenta com "
                f"profile Kali ({all_tools}) — fase pulada."
            )
            idx += 1
            continue
        if not pending:
            state.setdefault("logs_terminais", []).append(
                f"[phase-walker] {ph_id} {phase.get('title')}: COMPLETA "
                f"({len(installed)} ferramentas tentadas)."
            )
            idx += 1
            continue

        # ── Build the tactic for THIS phase ──────────────────────────────
        state["pentest_phase_index"] = idx
        state["kill_chain_stage"] = _PHASE_TO_KC_STAGE.get(ph_id, "RECONNAISSANCE")
        skill_id = phase_skill.get(ph_id) or node_default_skill.get(node, "recon-web-crawl")
        tactic = {
            "tactic_id": f"phase:{ph_id}:remaining-{len(pending)}",
            "skill_id": skill_id,
            "capability": node,
            "objective": (
                f"{ph_id} {phase.get('title')}: validar a biblioteca e EXECUTAR "
                f"todas as {len(installed)} ferramentas da fase, em ordem."
            ),
            "hypothesis": (
                f"Fase {ph_id} do pentest sequencial. Biblioteca define ferramentas="
                f"{installed}. Tecnica/comando vem do skill_runtime."
            ),
            "allowed_tools": pending,
            "preferred_tool": pending[0],
            "extra_args": {},
            "strategy_source": "phase_walker",
            "strategy_score": 200,
            "learning_techniques": [],
            "evidence_required": [],
            "constraints": [],
            "phase_refs": [ph_id],
            "targets": [],
            "reason": (
                f"Phase walker deterministico {ph_id} ({phase.get('title')}): "
                f"{len(pending)} pendente(s) de {len(installed)} — {', '.join(pending[:12])}"
                + (f" | sem profile: {', '.join(not_installed)}" if not_installed else "")
            ),
            "lock_skill": True,
            "bypass_stage_gate": True,
        }
        state["pending_pentest_tactic"] = tactic
        _append_action(state, "phase_walker_tactic", {
            "phase": ph_id, "title": phase.get("title"), "node": node,
            "pending": pending, "installed": len(installed),
            "not_installed": not_installed,
        })
        return tactic

    # All 22 phases walked.
    state["pentest_phase_index"] = total
    return None


def _next_pentest_tactic(state: AgentState) -> dict[str, Any] | None:
    from app.graph.kill_chain import stage_allows_skill, next_kill_chain_stage, KILL_CHAIN_STAGES

    # ── PRIORITY 0: deterministic P01→P22 phase walker ───────────────────
    # The phase walker IS the pentest contract. While any of the 22 phases
    # still has an unrun tool it returns a tactic — the supervisor cannot
    # skip a phase, cannot go random, cannot finalize early.
    phase_tactic = _phase_walker_tactic(state)
    if phase_tactic:
        return phase_tactic

    # ── DEFINITIVE kill-chain ordering ───────────────────────────────────
    # The pentest MUST walk RECONNAISSANCE → VULNERABILITY_ANALYSIS →
    # EXPLOITATION before any reporting — you cannot exploit/bypass what
    # you have not first FOUND. The coverage tactic sweeps every tool of
    # the current stage; when that stage is fully swept we advance to the
    # next stage IN-PLACE and retry. So the coverage tactic keeps
    # returning work until ACTIONS_ON_OBJECTIVES — it is impossible for
    # the supervisor to finalize (governance/executive) with
    # vulnerability-analysis or exploitation skipped.
    for _hop in range(len(KILL_CHAIN_STAGES) + 1):
        coverage_gap = _coverage_gap_tactic_for_stage(state)
        if coverage_gap:
            return coverage_gap
        cur = str(state.get("kill_chain_stage") or "RECONNAISSANCE").upper()
        nxt = next_kill_chain_stage(cur)
        if nxt == cur:
            break  # terminal stage — nothing left to sweep
        state["kill_chain_stage"] = nxt
        _append_note(
            state,
            f"Kill-chain: stage '{cur}' totalmente varrida (todas as ferramentas "
            f"tentadas) → avancando para '{nxt}'.",
            phase="kill-chain-gate",
        )
        try:
            from app.graph.tracer import emit_trace as _emit_trace
            _sid = state.get("scan_id")
            if _sid:
                _emit_trace(
                    scan_id=int(_sid), iteration=int(state.get("loop_iteration", 0)),
                    event_type="stage_advanced", from_node="supervisor", to_node="supervisor",
                    status="success",
                    payload={"new_stage": nxt, "reason": "coverage_exhausted"},
                )
        except Exception:
            pass

    strategy = _ensure_pentest_strategy(state)
    completed_ids = _completed_pentest_tactic_ids(state)
    current_stage = str(state.get("kill_chain_stage") or "RECONNAISSANCE").upper()
    blocked_ids: list[str] = []
    for item in list(strategy.get("queue") or []):
        if not isinstance(item, dict):
            continue
        tactic_id = str(item.get("tactic_id") or "")
        if not tactic_id or tactic_id in completed_ids:
            continue
        # ── Kill-chain gate: skip queued tactics whose skill_id is not allowed
        # in the current stage. The supervisor will revisit them once we
        # advance to a stage that permits the skill.
        skill_id = str(item.get("skill_id") or "")
        if skill_id and not stage_allows_skill(current_stage, skill_id):
            blocked_ids.append(f"{tactic_id}({skill_id})")
            continue
        state["pending_pentest_tactic"] = dict(item)
        return dict(item)
    if blocked_ids:
        state.setdefault("logs_terminais", []).append(
            f"[kill-chain] stage={current_stage} bloqueou {len(blocked_ids)} tactic(s) da fila: "
            f"{', '.join(blocked_ids[:5])}"
        )
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
    kill_chain_stage: str | None = None,
) -> dict[str, Any] | None:
    """Pick the best skill from active_skills for the given capability node.

    Returns a selected_skill dict with skill_id, allowed_tools, preferred_tool,
    objective, and reason — the supervisor's executable decision.
    Returns None only when active_skills is completely empty.
    """
    # Import here to avoid circular dependency
    from app.graph.workflow import _tools_for_group
    from app.graph.kill_chain import STAGE_ALLOWED_SKILLS

    preferred_cats = set(CAPABILITY_SKILL_CATEGORIES.get(capability, ()))
    candidate_tools = _tools_for_group(scan_mode, capability)
    candidate_lower = {t.lower() for t in candidate_tools}
    stage_key = str(kill_chain_stage or "RECONNAISSANCE").upper()
    stage_allowed = STAGE_ALLOWED_SKILLS.get(stage_key, set())

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

    # Stage-aware: only consider skills the current kill-chain stage allows.
    candidate_skills_pool = (
        [s for s in active_skills if str(s.get("id") or "") in stage_allowed]
        if stage_allowed else list(active_skills)
    )
    # If active_skills got filtered to nothing, fall back to the full stage
    # allowlist from the catalog so the supervisor still has a path forward.
    if not candidate_skills_pool and stage_allowed:
        from app.graph.mission import SKILL_CATALOG
        candidate_skills_pool = [dict(s) for s in SKILL_CATALOG if str(s.get("id") or "") in stage_allowed]

    for skill in candidate_skills_pool:
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
        "matched_by": [
            f"category:{best_skill.get('category')}",
            f"tool_overlap:{best_score}",
        ],
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
    # Advance kill-chain BEFORE refreshing skills so the stage gate is current.
    _maybe_advance_kill_chain_stage(state)
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
    # Kill-chain has absolute priority: while the pentest has not walked
    # RECON → VULN_ANALYSIS → EXPLOITATION (i.e. stage != terminal), the
    # supervisor MUST keep pursuing pentest work — objective_met cannot
    # short-circuit it. You cannot finalize a report on exploitation that
    # was never reached. Only `remaining <= 2` (hard iteration budget)
    # forces finalize.
    _kc_terminal = str(state.get("kill_chain_stage") or "").upper() in {"ACTIONS_ON_OBJECTIVES"}
    if remaining > 2 and (not _kc_terminal or not state.get("objective_met")):
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

    # ── Kill-chain stage → capability safety net ─────────────────────────
    # The coverage tactics normally route next_node per stage, but when they
    # are exhausted the linear fallback (asset_discovery→threat_intel→...)
    # ignores the stage. If we are already in VULN_ANALYSIS/EXPLOITATION the
    # vuln tools (nuclei, nmap-vulscan, sqlmap, dalfox) live in
    # risk_assessment — never let the supervisor regress to asset_discovery
    # once the kill-chain has advanced past recon.
    _kc_stage = str(state.get("kill_chain_stage") or "RECONNAISSANCE").upper()
    if (
        _kc_stage in {"VULNERABILITY_ANALYSIS", "EXPLOITATION"}
        and next_node in {"asset_discovery", "threat_intel"}
        and "risk_assessment" not in completed
    ):
        _append_note(
            state,
            f"Kill-chain stage={_kc_stage}: roteando capability {next_node}→risk_assessment "
            "(ferramentas de vuln/exploit vivem em risk_assessment).",
            phase="kill-chain-gate",
        )
        next_node = "risk_assessment"

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
        # ── Tactic-selection priority ─────────────────────────────────────
        # 0. Kill-chain MANDATORY COVERAGE — the minimum pentest contract.
        #    A coverage-gap tactic (strategy_source=kill_chain_coverage_gap)
        #    means a stage still lacks mandatory evidence (P04 parameter
        #    discovery, nuclei+nikto web audit, etc). This MUST beat an
        #    isolated hypothesis — otherwise a single high-confidence
        #    hypothesis short-circuits the sweep ("rodou uma ferramenta e
        #    ficou satisfeito"). Coverage represents breadth; the
        #    hypothesis represents depth — breadth-first until the contract
        #    is met.
        # 1. Hypothesis-driven tactic (depth) — once coverage is satisfied.
        # 2. Tech-stack auto-lock.
        # 3. Remaining strategy queue.
        # 4. Heuristic skill selection.
        # Phase walker (strategy_source=phase_walker) and kill-chain coverage
        # both OUTRANK the isolated hypothesis. The phase walker is the
        # deterministic P01→P22 contract — when it produced next_tactic we
        # dispatch it directly, bypassing the stage gate and hypothesis.
        coverage_tactic = (
            next_tactic
            if next_tactic and str(next_tactic.get("strategy_source") or "") in
            {"kill_chain_coverage_gap", "phase_walker"}
            else None
        )
        if coverage_tactic and str(coverage_tactic.get("capability") or "") == next_node:
            chosen_skill = _selected_skill_from_tactic(coverage_tactic)
            state.setdefault("logs_terminais", []).append(
                f"[supervisor] {coverage_tactic.get('strategy_source')} dispatch: "
                f"tactic={coverage_tactic.get('tactic_id')} skill={coverage_tactic.get('skill_id')} "
                f"tools={coverage_tactic.get('allowed_tools')}"
            )
        else:
            hypothesis_tactic = _hypothesis_driven_tactic(state, capability=next_node)
            if hypothesis_tactic:
                chosen_skill = _selected_skill_from_tactic(hypothesis_tactic)
            else:
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
                        kill_chain_stage=str(state.get("kill_chain_stage") or "RECONNAISSANCE"),
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
                            # ── PORQUE essa skill ──
                            "reason": chosen_skill.get("reason", ""),
                            "matched_by": list(chosen_skill.get("matched_by") or [])[:8],
                            "tech_stack": list(state.get("detected_tech_stack") or [])[:8],
                            "lock_skill": bool(chosen_skill.get("lock_skill")),
                            "extra_args": dict(chosen_skill.get("extra_args") or {}),
                            "kill_chain_stage": str(state.get("kill_chain_stage") or "RECONNAISSANCE"),
                            # Hypothesis trail: when the tactic came from the
                            # hypothesis engine, expose family + signal so the
                            # UI can show "porque essa ferramenta".
                            "hypothesis_driver": (
                                {
                                    "family": (chosen_skill.get("tactic_id") or "").split(":")[1]
                                    if str(chosen_skill.get("tactic_id") or "").startswith("hypothesis:") else None,
                                    "tactic_id": chosen_skill.get("tactic_id"),
                                    "signal_expected": (chosen_skill.get("evidence_required") or [""])[0],
                                }
                                if str(chosen_skill.get("strategy_source") or "") == "hypothesis_engine"
                                else None
                            ),
                            "hypotheses_pending": len(state.get("pentest_hypotheses") or []),
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
