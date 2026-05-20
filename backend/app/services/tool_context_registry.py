"""Context-aware tool registry for MCP/Kali tools.

This module is the bridge between:
- MCP/Kali tool descriptions and profiles
- the local rich tool catalog
- runtime/dashboard metrics
- agent skill/phase context

It gives the supervisor variables that can be consumed by prompts, dashboards
and selection logic without coupling those callers to the MCP response shape.
"""
from __future__ import annotations

import re
from typing import Any

from app.services.kali_executor import TOOL_TO_PROFILE
from app.services.mcp_client import mcp_client
from app.services.tool_catalog import TOOL_CATALOG


def _clean(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def _clean_list(value: Any, limit: int = 50) -> list[str]:
    if isinstance(value, str):
        raw = re.split(r"[,|]", value)
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        raw = []
    out = [_clean(item) for item in raw if _clean(item)]
    return list(dict.fromkeys(out))[:limit]


def _tokens(value: Any) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-zA-Z0-9_\\-]{3,}", str(value or "").lower())
        if token
    }


def _target_traits(target: str) -> dict[str, Any]:
    raw = str(target or "").strip().lower()
    is_url = raw.startswith(("http://", "https://"))
    is_code = raw.startswith(("git@", "ssh://", "file://")) or "github.com/" in raw or raw.endswith(".git")
    host_like = bool(raw and not is_code and ("." in raw or raw.startswith(("http://", "https://"))))
    return {
        "target": target,
        "is_url": is_url,
        "is_code": is_code,
        "is_host_or_domain": host_like,
        "requires_url_tools": is_url or host_like,
    }


def _profile_by_tool(mcp_tools: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_tool: dict[str, dict[str, Any]] = {}
    for item in mcp_tools:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        profile = str(item.get("name") or "").strip()
        tool = str(metadata.get("tool") or profile).strip()
        if profile:
            by_tool[profile.lower()] = dict(item)
        if tool:
            by_tool[tool.lower()] = dict(item)
    return by_tool


def _context_query(context: dict[str, Any]) -> str:
    parts = [
        context.get("target"),
        context.get("capability"),
        context.get("skill_id"),
        context.get("kill_chain_stage"),
        context.get("hypothesis"),
        context.get("objective"),
        " ".join(_clean_list(context.get("phase_refs"), limit=12)),
        " ".join(_clean_list(context.get("detected_tech_stack"), limit=20)),
        " ".join(_clean_list(context.get("expected_telemetry"), limit=20)),
        " ".join(_clean_list(context.get("evidence_required"), limit=20)),
    ]
    skill = context.get("skill") if isinstance(context.get("skill"), dict) else {}
    if skill:
        parts.extend([
            skill.get("description"),
            skill.get("category"),
            " ".join(_clean_list(skill.get("triggers"), limit=20)),
            " ".join(_clean_list(skill.get("playbook"), limit=20)),
        ])
    technique = context.get("adversary_technique") if isinstance(context.get("adversary_technique"), dict) else {}
    if technique:
        parts.extend([
            technique.get("id"),
            technique.get("name"),
            technique.get("objective"),
            technique.get("when_to_use"),
            " ".join(_clean_list(technique.get("recommended_kali_tools"), limit=20)),
        ])
    return " ".join(_clean(part) for part in parts if _clean(part))


def _dashboard_tool_metrics(context: dict[str, Any], tool: str) -> dict[str, Any]:
    runtime = context.get("tool_runtime") if isinstance(context.get("tool_runtime"), dict) else {}
    tool_runtime = runtime.get(tool) or runtime.get(tool.lower()) or {}
    attempts = int(tool_runtime.get("attempts", 0) or 0) if isinstance(tool_runtime, dict) else 0
    successes = int((tool_runtime or {}).get("success", 0) or (tool_runtime or {}).get("successes", 0) or 0) if isinstance(tool_runtime, dict) else 0
    failures = int((tool_runtime or {}).get("failed", 0) or (tool_runtime or {}).get("failures", 0) or 0) if isinstance(tool_runtime, dict) else 0
    dashboard = context.get("dashboard_tool_metrics") if isinstance(context.get("dashboard_tool_metrics"), dict) else {}
    dashboard_tool = dashboard.get(tool) or dashboard.get(tool.lower()) or {}
    if isinstance(dashboard_tool, dict):
        attempts = attempts or int(dashboard_tool.get("attempts", 0) or 0)
        successes = successes or int(dashboard_tool.get("successes", 0) or 0)
        failures = failures or int(dashboard_tool.get("failures", 0) or 0)
    success_rate = round((successes / max(attempts, 1)) * 100.0, 1)
    return {
        "attempts": attempts,
        "successes": successes,
        "failures": failures,
        "success_rate": success_rate,
        "has_runtime_history": attempts > 0,
    }


def _tool_record(tool: str, mcp_by_tool: dict[str, dict[str, Any]]) -> dict[str, Any]:
    local = dict(TOOL_CATALOG.get(tool) or {})
    profile = TOOL_TO_PROFILE.get(tool.lower(), tool)
    mcp_item = mcp_by_tool.get(tool.lower()) or mcp_by_tool.get(profile.lower()) or {}
    metadata = mcp_item.get("metadata") if isinstance(mcp_item.get("metadata"), dict) else {}
    description = _clean(local.get("description") or mcp_item.get("description") or f"Kali tool {tool}")
    when_to_use = _clean(local.get("when_to_use") or metadata.get("when_to_use") or "")
    category = _clean(local.get("category") or metadata.get("category") or "")
    phase = _clean(local.get("phase") or metadata.get("phase") or "")
    return {
        "tool": tool,
        "profile": str(mcp_item.get("name") or profile),
        "description": description,
        "mcp_description": _clean(mcp_item.get("description") or ""),
        "category": category,
        "phase": phase,
        "when_to_use": when_to_use,
        "inputs": _clean(local.get("inputs") or ""),
        "outputs": _clean(local.get("outputs") or ""),
        "prerequisites": _clean(local.get("prerequisites") or ""),
        "metadata": {
            "mcp": metadata,
            "source": "mcp+local_catalog" if mcp_item and local else "mcp" if mcp_item else "local_catalog",
            "execution_path": metadata.get("execution_path") or "mcp_to_kali",
            "timeout": metadata.get("timeout"),
        },
    }


def _score_tool(record: dict[str, Any], context: dict[str, Any], query_tokens: set[str]) -> tuple[int, list[str]]:
    reasons: list[str] = []
    text = " ".join(
        [
            record.get("tool"),
            record.get("profile"),
            record.get("description"),
            record.get("when_to_use"),
            record.get("category"),
            record.get("phase"),
            record.get("inputs"),
            record.get("outputs"),
            record.get("prerequisites"),
        ]
    )
    tool_tokens = _tokens(text)
    overlap = query_tokens.intersection(tool_tokens)
    score = len(overlap) * 4
    if overlap:
        reasons.append(f"context_terms={','.join(sorted(list(overlap))[:8])}")

    capability = str(context.get("capability") or "").lower()
    category = str(record.get("category") or "").lower()
    if capability == "asset_discovery" and any(item in category for item in ["recon", "osint"]):
        score += 18
        reasons.append("capability_asset_discovery")
    if capability == "threat_intel" and any(item in category for item in ["osint", "code", "recon"]):
        score += 14
        reasons.append("capability_threat_intel")
    if capability == "risk_assessment" and any(item in category for item in ["vuln", "exploit", "code"]):
        score += 18
        reasons.append("capability_risk_assessment")

    phase_refs = {item.upper() for item in _clean_list(context.get("phase_refs"), limit=12)}
    record_phases = {item.upper() for item in _clean_list(record.get("phase"), limit=20)}
    if phase_refs and phase_refs.intersection(record_phases):
        score += 16
        reasons.append("phase_match")

    preferred = {item.lower() for item in _clean_list(context.get("preferred_tools"), limit=30)}
    if str(record.get("tool") or "").lower() in preferred:
        score += 24
        reasons.append("preferred_by_skill_or_learning")

    traits = _target_traits(str(context.get("target") or ""))
    if traits["is_code"] and "code" in category:
        score += 22
        reasons.append("target_code")
    if traits["requires_url_tools"] and any(item in str(record.get("inputs") or "").lower() for item in ["url", "domain", "host"]):
        score += 8
        reasons.append("target_input_fit")

    metrics = _dashboard_tool_metrics(context, str(record.get("tool") or ""))
    if metrics["has_runtime_history"]:
        if metrics["success_rate"] >= 80:
            score += 10
            reasons.append("dashboard_high_success")
        elif metrics["success_rate"] == 0 and metrics["attempts"] > 0:
            score -= 20
            reasons.append("dashboard_failed_recently")
        else:
            score += 3
            reasons.append("dashboard_partial_success")

    return score, reasons


def build_tool_context_registry(
    *,
    context: dict[str, Any] | None = None,
    candidate_tools: list[str] | None = None,
    mcp_tools: list[dict[str, Any]] | None = None,
    include_mcp: bool = True,
) -> dict[str, Any]:
    """Return an enriched registry and flat variables for prompt/dashboard use."""
    ctx = dict(context or {})
    if mcp_tools is None and include_mcp:
        try:
            mcp_tools = mcp_client.list_tools_sync()
        except Exception:  # noqa: BLE001
            mcp_tools = []
    mcp_tools = list(mcp_tools or [])
    mcp_by_tool = _profile_by_tool(mcp_tools)

    tools = _clean_list(candidate_tools, limit=200) if candidate_tools else sorted(set(TOOL_TO_PROFILE.keys()) | set(TOOL_CATALOG.keys()))
    query = _context_query(ctx)
    query_tokens = _tokens(query)
    records: list[dict[str, Any]] = []
    for tool in tools:
        record = _tool_record(tool, mcp_by_tool)
        score, reasons = _score_tool(record, ctx, query_tokens)
        metrics = _dashboard_tool_metrics(ctx, tool)
        record["context_score"] = score
        record["context_reasons"] = reasons
        record["dashboard_metrics"] = metrics
        record["selected_by_context"] = score > 0
        records.append(record)

    records.sort(key=lambda item: (-int(item.get("context_score") or 0), str(item.get("tool") or "")))
    by_name = {str(item.get("tool")): item for item in records}
    variables = {
        "TOOL_CONTEXT_QUERY": query,
        "TOOL_CONTEXT_TARGET_TRAITS": _target_traits(str(ctx.get("target") or "")),
        "TOOL_CONTEXT_AVAILABLE_TOOLS": [item["tool"] for item in records],
        "TOOL_CONTEXT_RECOMMENDED_TOOLS": [item["tool"] for item in records if int(item.get("context_score") or 0) > 0][:12],
        "TOOL_CONTEXT_MCP_PROFILES": {item["tool"]: item.get("profile") for item in records},
        "TOOL_CONTEXT_DESCRIPTIONS": {item["tool"]: item.get("description") for item in records},
        "TOOL_CONTEXT_WHEN_TO_USE": {item["tool"]: item.get("when_to_use") for item in records},
        "TOOL_CONTEXT_DASHBOARD_METRICS": {item["tool"]: item.get("dashboard_metrics") for item in records},
        "TOOL_CONTEXT_SELECTION_REASONS": {item["tool"]: item.get("context_reasons") for item in records},
    }
    return {
        "registry": records,
        "by_tool": by_name,
        "variables": variables,
        "mcp_tools_loaded": len(mcp_tools),
        "context": ctx,
    }


def rank_tools_for_context(
    candidate_tools: list[str],
    *,
    context: dict[str, Any] | None = None,
    limit: int | None = None,
    mcp_tools: list[dict[str, Any]] | None = None,
    include_mcp: bool = True,
) -> tuple[list[str], dict[str, Any]]:
    registry = build_tool_context_registry(
        context=context,
        candidate_tools=candidate_tools,
        mcp_tools=mcp_tools,
        include_mcp=include_mcp,
    )
    ordered = [str(item.get("tool")) for item in registry["registry"] if str(item.get("tool") or "").strip()]
    if limit is not None:
        ordered = ordered[: max(1, int(limit))]
    return ordered, registry


def dashboard_bas_variables(bas_command_center: dict[str, Any]) -> dict[str, Any]:
    """Flat variables for agents/prompts that consume dashboard BAS telemetry."""
    bas = dict(bas_command_center or {})
    summary = dict(bas.get("summary") or {})
    tools = list(bas.get("tools") or [])
    telemetry = list((bas.get("detection") or {}).get("telemetry_sources") or [])
    learning = dict(bas.get("learning") or {})
    workers = dict(bas.get("workers") or {})
    return {
        "BAS_RESILIENCE_INDEX": summary.get("bas_resilience_index", 0),
        "BAS_ATTACK_SUCCESS_INDEX": summary.get("attack_success_index", 0),
        "BAS_CONTROL_EFFICACY_INDEX": summary.get("control_efficacy_index", 0),
        "BAS_DETECTION_GAP_COUNT": summary.get("detection_gap_count", 0),
        "BAS_TOOL_EFFICIENCY_INDEX": summary.get("tool_efficiency_index", 0),
        "BAS_LEARNING_COVERAGE_PERCENT": summary.get("learning_coverage_percent", 0),
        "BAS_LEARNING_UTILIZATION_PERCENT": summary.get("learning_utilization_percent", 0),
        "BAS_TECHNIQUES_EXERCISED": summary.get("techniques_exercised", 0),
        "BAS_VALIDATED_RISK_FINDINGS": summary.get("validated_risk_findings", 0),
        "BAS_OPEN_FINDINGS": summary.get("open_findings", 0),
        "BAS_TOP_TOOLS": [str(item.get("tool") or "") for item in tools[:10] if isinstance(item, dict)],
        "BAS_TOOL_METRICS": {
            str(item.get("tool") or ""): {
                "attempts": item.get("attempts", 0),
                "success_rate": item.get("success_rate", 0),
                "findings": item.get("findings", 0),
                "failures": item.get("failures", 0),
            }
            for item in tools
            if isinstance(item, dict) and str(item.get("tool") or "").strip()
        },
        "BAS_TOP_TELEMETRY_SOURCES": [str(item.get("source") or "") for item in telemetry[:10] if isinstance(item, dict)],
        "BAS_LEARNING_ACCEPTED": learning.get("accepted", 0),
        "BAS_LEARNING_PENDING": learning.get("pending", 0),
        "BAS_RAG_TRACE_HITS": learning.get("rag_trace_hits", 0),
        "BAS_WORKERS_TOTAL": workers.get("total", 0),
        "BAS_WORKERS_ACTIVE": workers.get("active", 0),
        "BAS_WORKERS_STALE": workers.get("stale", 0),
    }
