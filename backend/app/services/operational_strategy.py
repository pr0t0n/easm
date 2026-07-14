"""Operational strategy used by the real scan workflow.

The capability blueprint is the product contract. This module is the runtime
adapter that makes that contract influence scan state, supervisor routing,
RAG queries, skill/tool selection, MCP execution and operator telemetry.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any


AGENT_ROSTER: tuple[dict[str, Any], ...] = (
    {
        "id": "scope_guardian",
        "name": "Scope Guardian",
        "capabilities": ["governance", "asset_discovery"],
        "mission": "Keep every action inside authorized scope and non-destructive guardrails.",
        "evidence_focus": ["authorized_scope", "blocked_out_of_scope", "guardrail_decision"],
    },
    {
        "id": "recon_agent",
        "name": "Recon Agent",
        "capabilities": ["asset_discovery"],
        "mission": "Map live assets, endpoints, technologies and expansion candidates.",
        "evidence_focus": ["asset_inventory", "service_banner", "endpoint_catalog", "tech_stack"],
    },
    {
        "id": "intel_agent",
        "name": "Threat Intel Agent",
        "capabilities": ["threat_intel"],
        "mission": "Correlate public exposure, CVEs, leaked signals and accepted learnings.",
        "evidence_focus": ["cve_context", "osint_signal", "learning_match", "rag_pattern"],
    },
    {
        "id": "api_auth_agent",
        "name": "API/Auth Agent",
        "capabilities": ["risk_assessment"],
        "mission": "Validate API exposure, auth flows, BOLA/BFLA and business logic safely.",
        "evidence_focus": ["identity_pair", "baseline_vs_exploit", "auth_context", "api_spec"],
    },
    {
        "id": "exploit_validator",
        "name": "Exploit Validator",
        "capabilities": ["risk_assessment"],
        "mission": "Turn hypotheses into confirmed or refuted findings with proof packs.",
        "evidence_focus": ["repro_steps", "payload", "response_diff", "oob_callback"],
    },
    {
        "id": "ai_security_agent",
        "name": "AI/RAG/MCP Security Agent",
        "capabilities": ["risk_assessment", "threat_intel"],
        "mission": "Test LLM, RAG, agent and MCP abuse surfaces with quarantined evidence.",
        "evidence_focus": ["probe", "transcript", "detector_result", "canary_leak"],
    },
    {
        "id": "evidence_judge",
        "name": "Evidence Judge",
        "capabilities": ["evidence_gate", "governance", "executive_analyst"],
        "mission": "Promote only reproducible findings and keep candidates/hypotheses separated.",
        "evidence_focus": ["proof_pack", "verification_status", "readiness_blocker"],
    },
)


CAPABILITY_RUNTIME_POLICY: dict[str, dict[str, Any]] = {
    "asset_discovery": {
        "agent_id": "recon_agent",
        "blueprint": "objective-driven-autonomy",
        "preferred_skills": ["recon-web-crawl", "recon-subdomain-enum", "tech-fingerprint"],
        "preferred_tools": ["subfinder", "httpx", "katana", "whatweb", "curl-headers"],
        "rag_topics": ["reconnaissance", "surface mapping", "endpoint discovery"],
        "evidence_required": ["asset_inventory", "endpoint_catalog", "tech_stack"],
        "priority": 10,
    },
    "threat_intel": {
        "agent_id": "intel_agent",
        "blueprint": "benchmark-regression-center",
        "preferred_skills": ["osint-exposure-intel", "code-secret-discovery", "vuln-cve-correlation"],
        "preferred_tools": ["shodan-cli", "theharvester", "h8mail", "trufflehog", "gitleaks"],
        "rag_topics": ["accepted learning", "cve exploitation", "osint exposure"],
        "evidence_required": ["rag_pattern", "osint_signal", "cve_context"],
        "priority": 20,
    },
    "risk_assessment": {
        "agent_id": "exploit_validator",
        "blueprint": "dast-sast-evidence-fusion",
        "preferred_skills": ["api-security", "idor-object-authorization", "vuln-nuclei-cve", "vuln-injection"],
        "preferred_tools": ["nuclei", "sqlmap", "dalfox", "zap-api", "bl-test", "code-analyzer"],
        "rag_topics": ["vulnerability validation", "proof pack", "safe exploitation"],
        "evidence_required": ["baseline_request", "exploit_request", "response_diff", "repro_steps"],
        "priority": 30,
    },
}


def build_operational_strategy(
    *,
    target: str,
    target_type: str,
    scan_mode: str,
    segment: str | None = None,
) -> dict[str, Any]:
    """Build the runtime strategy stored in AgentState."""
    is_ai_target_hint = any(token in str(target or "").lower() for token in ("llm", "rag", "ai", "chat", "agent", "mcp"))
    return {
        "id": "best_of_autonomous_pentest_v1",
        "version": "2026.07",
        "mode": "objective_driven_pentest",
        "north_star": (
            "Pentest automatizado orientado por objetivos, executado por agentes "
            "especialistas, governado por escopo, validado por evidencia e medido por benchmarks."
        ),
        "target": target,
        "target_type": target_type,
        "scan_mode": str(scan_mode),
        "segment": segment or "Digital Services",
        "created_at": datetime.now().isoformat(),
        "capability_policy": CAPABILITY_RUNTIME_POLICY,
        "agent_roster": list(AGENT_ROSTER),
        "active_modules": {
            "objective_driven_autonomy": True,
            "specialist_agents": True,
            "safe_tool_adapter_layer": True,
            "ai_rag_agent_security": is_ai_target_hint,
            "benchmark_regression": True,
            "dast_sast_evidence_fusion": True,
        },
        "route_order": ["asset_discovery", "threat_intel", "risk_assessment", "governance", "executive_analyst"],
        "mcp_adapter_policy": {
            "required": True,
            "allow_direct_kali_fallback": False,
            "require_scope_check": True,
            "require_guardrail_sanitization": True,
            "require_evidence_artifact": True,
            "require_tool_schema": True,
            "persist_tool_call_trace": True,
        },
        "rag_policy": {
            "enabled": True,
            "top_k": 6,
            "query_templates": [
                "{capability} {skill_id} {target} accepted learning",
                "{capability} {target} proof pack evidence requirements",
                "{capability} {target} false positive reduction",
            ],
            "quarantine_target_content": True,
        },
        "benchmark_policy": {
            "score_dimensions": ["phase_coverage", "tool_evidence", "proof_pack", "agent_boundary"],
            "safe_targets_only": True,
            "high_critical_requires_proof_pack": True,
        },
        "evidence_gates": [
            "candidate findings do not enter final report",
            "high/critical requires proof_pack or independent confirmation",
            "AI/RAG/MCP tests must keep target-controlled content wrapped",
            "tool execution must persist command, status, workspace and adapter contract",
        ],
        "events": [
            {
                "type": "strategy_initialized",
                "message": "Best-of platform strategy attached to scan runtime.",
                "ts": datetime.now().isoformat(),
            }
        ],
    }


def policy_for_capability(strategy: dict[str, Any] | None, capability: str) -> dict[str, Any]:
    policy = dict((strategy or {}).get("capability_policy") or {})
    return dict(policy.get(str(capability or "")) or {})


def agent_for_capability(strategy: dict[str, Any] | None, capability: str) -> dict[str, Any]:
    policy = policy_for_capability(strategy, capability)
    agent_id = str(policy.get("agent_id") or "")
    for agent in list((strategy or {}).get("agent_roster") or []):
        if str(agent.get("id") or "") == agent_id:
            return dict(agent)
    return {}


def append_strategy_event(state: dict[str, Any], event_type: str, payload: dict[str, Any]) -> None:
    strategy = dict(state.get("operational_strategy") or {})
    events = list(strategy.get("events") or [])
    events.append({"type": event_type, **payload, "ts": datetime.now().isoformat()})
    strategy["events"] = events[-120:]
    state["operational_strategy"] = strategy


def prioritize_tools(strategy: dict[str, Any] | None, capability: str, tools: list[str]) -> list[str]:
    preferred = [str(t).lower() for t in policy_for_capability(strategy, capability).get("preferred_tools") or []]
    if not preferred:
        return tools
    weights = {tool: idx for idx, tool in enumerate(preferred)}
    return sorted(
        list(dict.fromkeys([str(t) for t in tools if str(t or "").strip()])),
        key=lambda tool: (weights.get(tool.lower(), 999), tool.lower()),
    )


def build_mcp_adapter_contract(
    *,
    strategy: dict[str, Any] | None,
    capability: str,
    skill_id: str,
    tools: list[str],
    evidence_required: list[str] | None = None,
) -> dict[str, Any]:
    policy = dict((strategy or {}).get("mcp_adapter_policy") or {})
    cap_policy = policy_for_capability(strategy, capability)
    return {
        "contract_id": f"adapter:{capability}:{skill_id or 'unknown'}",
        "capability": capability,
        "skill_id": skill_id,
        "agent": agent_for_capability(strategy, capability),
        "tools": list(tools),
        "required": bool(policy.get("required", True)),
        "scope_check": bool(policy.get("require_scope_check", True)),
        "guardrail_sanitization": bool(policy.get("require_guardrail_sanitization", True)),
        "evidence_artifact_required": bool(policy.get("require_evidence_artifact", True)),
        "tool_schema_required": bool(policy.get("require_tool_schema", True)),
        "persist_tool_call_trace": bool(policy.get("persist_tool_call_trace", True)),
        "allow_direct_kali_fallback": bool(policy.get("allow_direct_kali_fallback", False)),
        "evidence_required": list(evidence_required or cap_policy.get("evidence_required") or []),
        "blueprint": cap_policy.get("blueprint"),
        "created_at": datetime.now().isoformat(),
    }


def scan_strategy_snapshot(scan_job: Any) -> dict[str, Any]:
    state = dict(getattr(scan_job, "state_data", None) or {})
    strategy = dict(state.get("operational_strategy") or {})
    selection = dict(state.get("tool_selection_contract") or {})
    selected_skill = dict(state.get("selected_skill") or {})
    invocation = dict(state.get("skill_invocation") or {})
    return {
        "scan_id": getattr(scan_job, "id", None),
        "target": getattr(scan_job, "target_query", ""),
        "status": getattr(scan_job, "status", ""),
        "strategy": strategy,
        "current": {
            "capability": selection.get("capability") or state.get("pending_capability_node") or state.get("current_phase"),
            "agent": agent_for_capability(strategy, str(selection.get("capability") or state.get("pending_capability_node") or "")),
            "selected_skill": selected_skill,
            "skill_invocation": invocation,
            "tool_selection_contract": selection,
            "rag_patterns": list(state.get("rag_patterns") or [])[:8],
            "strategic_rag_context": list(state.get("strategic_rag_context") or [])[:8],
            "mcp_adapter_contract": selection.get("mcp_adapter_contract") or {},
            "last_events": list(strategy.get("events") or [])[-12:],
            "authorization_gate": dict(state.get("authorization_gate") or {}),
            "scan_profile": dict(state.get("scan_profile") or {}),
        },
    }
