"""Per-scan methodology planning backed by Skill RAG and a bounded LLM choice.

The LLM chooses only identifiers from an allow-list retrieved through the MCP
client.  Code validates the answer and preserves mandatory governance tools.
The resulting plan is persisted in ``ScanJob.state_data`` and reused by every
Celery continuation, so parallel workers share one methodology decision.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime
from typing import Any

from app.services.mcp_client import MCPClient
from app.services.offensive_operator_core import PHASE_ORDER, default_phase_contracts
from app.services.skill_runtime import resolve_skill_for_phase


PLAN_VERSION = 1
MANDATORY_PHASE_TOOLS = {
    "P18": "credential-boundary-review",
    "P19": "post-exploitation-boundary-review",
    "P20": "attack-path-correlator",
    "P21": "evidence-adjudicator",
    "P22": "report-snapshot-builder",
}


def resolve_methodology_plan(job: Any, *, force: bool = False) -> dict[str, Any]:
    state = dict(getattr(job, "state_data", None) or {})
    existing = state.get("methodology_plan_v1")
    if not force and isinstance(existing, dict) and int(existing.get("version") or 0) == PLAN_VERSION:
        return existing

    from app.services.skill_rag_indexer import ensure_skill_index_ready

    ensure_skill_index_ready()
    base_contracts = default_phase_contracts()
    phase_context: dict[str, dict[str, Any]] = {}
    mcp = MCPClient()
    for phase_id in PHASE_ORDER:
        skills = resolve_skill_for_phase(phase_id)
        allowed_skills = [str(skill.get("skill_id") or "") for skill in skills if skill.get("skill_id")]
        allowed_tools = sorted({
            str(tool)
            for skill in skills
            for tool in (
                list(skill.get("required_tools") or [])
                + list(skill.get("optional_tools") or [])
                + list(skill.get("fallback_tools") or [])
            )
            if str(tool)
        } | set(base_contracts[phase_id].get("required_tools") or [])
          | set(base_contracts[phase_id].get("optional_tools") or []))
        retrieved = mcp.query_knowledge_sync(
            f"{phase_id} {base_contracts[phase_id]['name']} tools evidence exit criteria",
            top_k=6,
            filters={"type": "skill"},
        )
        phase_context[phase_id] = {
            "objective": base_contracts[phase_id]["description"],
            "allowed_skills": allowed_skills,
            "allowed_tools": allowed_tools,
            "rag": [
                {
                    "skill_id": (row.get("metadata") or {}).get("skill_id") or row.get("skill"),
                    "score": row.get("score"),
                    "excerpt": str(row.get("content") or "")[:700],
                }
                for row in retrieved
            ],
        }

    proposal, llm_meta = _llm_select(job, phase_context)
    contracts = _validate_and_compile(base_contracts, phase_context, proposal)
    plan = {
        "version": PLAN_VERSION,
        "source": "llm_mcp_rag" if not llm_meta.get("fallback") else "deterministic_mcp_rag_fallback",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "llm": llm_meta,
        "contracts": contracts,
        "decision_boundary": {
            "llm_may_select": ["skill_ids", "tool_ids", "rationale"],
            "llm_may_not_select": ["targets", "payloads", "arguments", "scope", "mandatory_control_removal"],
        },
    }
    state["methodology_plan_v1"] = plan
    job.state_data = state
    return plan


def contracts_from_plan(plan: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    contracts = (plan or {}).get("contracts") if isinstance(plan, dict) else None
    if not isinstance(contracts, dict):
        return default_phase_contracts()
    defaults = default_phase_contracts()
    return {
        phase_id: copy.deepcopy(contracts.get(phase_id) or defaults[phase_id])
        for phase_id in PHASE_ORDER
    }


def _llm_select(job: Any, context: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    compact = {
        phase_id: {
            "objective": row["objective"],
            "allowed_skills": row["allowed_skills"],
            "allowed_tools": row["allowed_tools"],
            "rag_ranked_skills": [item.get("skill_id") for item in row["rag"] if item.get("skill_id")],
        }
        for phase_id, row in context.items()
    }
    prompt = f"""Responda somente JSON valido.
Voce seleciona metodologia para um pentest defensivo autorizado. Celery executa em paralelo; voce apenas escolhe skills e tools.
Nunca invente identificadores, alvos, argumentos ou payloads. Nao remova P01-P22.
P18-P22 possuem controles obrigatorios que o codigo preserva.
Alvo (somente para contexto): {str(getattr(job, 'target_query', '') or '')[:300]}
Modo: {str((getattr(job, 'state_data', None) or {}).get('execution_mode') or 'controlled_pentest')}
Catalogo MCP/RAG por fase:
{json.dumps(compact, ensure_ascii=False)}

Formato:
{{"phases":{{"P01":{{"selected_skills":["id"],"selected_tools":["id"],"rationale":"curta"}}}}}}
Inclua todas as fases P01-P22. Se nao houver sinal para especializar, escolha o menor conjunto que cumpra o objetivo da fase.
"""
    try:
        from app.services.vulnerability_learning_service import _call_learning_llm, _extract_json_object

        model, raw = _call_learning_llm(prompt)
        parsed = _extract_json_object(raw or "")
        if not isinstance(parsed, dict) or not isinstance(parsed.get("phases"), dict):
            raise ValueError("invalid_methodology_json")
        return parsed, {"model": model, "fallback": False, "response_hash": _hash(raw or "")}
    except Exception as exc:  # noqa: BLE001
        return {"phases": {}}, {"model": "unavailable", "fallback": True, "error": f"{type(exc).__name__}:{exc}"[:300]}


def _validate_and_compile(
    defaults: dict[str, dict[str, Any]],
    context: dict[str, dict[str, Any]],
    proposal: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    rows = proposal.get("phases") if isinstance(proposal.get("phases"), dict) else {}
    compiled: dict[str, dict[str, Any]] = {}
    for phase_id in PHASE_ORDER:
        contract = copy.deepcopy(defaults[phase_id])
        candidate = rows.get(phase_id) if isinstance(rows.get(phase_id), dict) else {}
        allowed_skills = set(context[phase_id]["allowed_skills"])
        allowed_tools = set(context[phase_id]["allowed_tools"])
        selected_skills = [
            str(item) for item in list(candidate.get("selected_skills") or [])
            if str(item) in allowed_skills
        ]
        selected_tools = [
            str(item) for item in list(candidate.get("selected_tools") or [])
            if str(item) in allowed_tools
        ]
        if selected_skills:
            contract["required_skills"] = list(dict.fromkeys(selected_skills))
        if selected_tools:
            contract["required_tools"] = list(dict.fromkeys(selected_tools))
            contract["optional_tools"] = [
                tool for tool in contract.get("optional_tools") or [] if tool not in selected_tools
            ]
        mandatory = MANDATORY_PHASE_TOOLS.get(phase_id)
        if mandatory:
            contract["required_tools"] = list(dict.fromkeys([mandatory] + list(contract.get("required_tools") or [])))
            contract["exit_criteria"]["allow_skip"] = False
            contract["exit_criteria"]["allow_partial"] = False
        contract["planner"] = {
            "source": "llm_mcp_rag" if candidate else "deterministic_fallback",
            "rationale": str(candidate.get("rationale") or "")[:500],
            "allowed_skill_count": len(allowed_skills),
            "allowed_tool_count": len(allowed_tools),
        }
        compiled[phase_id] = contract
    return compiled


def _hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode()).hexdigest()
