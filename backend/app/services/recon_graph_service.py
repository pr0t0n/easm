from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services.recon_completion_gate import evaluate_recon_completion
from app.services.recon_signal_normalizer import normalize_recon_signals
from app.services.skill_recommendation_engine import recommend_skills_from_recon_graph


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _clean(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def _append_unique(rows: list[dict[str, Any]], item: dict[str, Any], key_fields: tuple[str, ...]) -> bool:
    key = tuple(str(item.get(field) or "").strip().lower() for field in key_fields)
    for row in rows:
        row_key = tuple(str(row.get(field) or "").strip().lower() for field in key_fields)
        if row_key == key:
            row.update({k: v for k, v in item.items() if v not in (None, "", [])})
            return False
    rows.append(item)
    return True


def empty_recon_graph(target: str = "") -> dict[str, Any]:
    return {
        "schema_version": "recon-graph.v1",
        "target": _clean(target),
        "assets": [],
        "services": [],
        "web_targets": [],
        "technologies": [],
        "endpoints": [],
        "parameters": [],
        "forms": [],
        "headers": [],
        "tls": [],
        "waf": [],
        "secrets_signals": [],
        "risk_signals": [],
        "signals": [],
        "skill_recommendations": [],
        "reanalyze_queue": [],
        "coverage": {},
        "coverage_gaps": [],
        "ready_for_phase_2": False,
        "updated_at": _now_iso(),
    }


def update_recon_graph(
    state: dict[str, Any],
    *,
    capability: str,
    target: str,
    tools: list[str],
    findings: list[dict[str, Any]],
    ports: list[int],
    assets: list[str],
    port_evidence: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    graph = dict(state.get("recon_graph") or empty_recon_graph(str(state.get("target") or target)))
    for key, default in empty_recon_graph(str(state.get("target") or target)).items():
        graph.setdefault(key, default)

    signals = normalize_recon_signals(
        target=target,
        tools=tools,
        findings=findings,
        ports=ports,
        assets=assets,
        port_evidence=port_evidence,
        tech_stack=list(state.get("detected_tech_stack") or []),
    )

    new_queue_items = 0
    for signal in signals:
        signal = dict(signal)
        signal.setdefault("capability", capability)
        signal.setdefault("observed_at", _now_iso())
        added = _append_unique(
            graph["signals"],
            signal,
            ("type", "asset", "url", "name", "port", "technology", "source_tool"),
        )
        if added and signal.get("next_phase") in {"risk_assessment", "asset_discovery"}:
            queue_item = {
                "reason": signal.get("type"),
                "target": signal.get("url") or signal.get("asset") or target,
                "signal": signal,
                "created_at": _now_iso(),
            }
            if _append_unique(graph["reanalyze_queue"], queue_item, ("reason", "target")):
                new_queue_items += 1

        typ = str(signal.get("type") or "")
        if typ == "asset":
            _append_unique(graph["assets"], {"asset": signal.get("asset"), "source_tool": signal.get("source_tool")}, ("asset",))
        elif typ == "service":
            _append_unique(
                graph["services"],
                {
                    "asset": signal.get("asset"),
                    "port": signal.get("port"),
                    "service": signal.get("service"),
                    "source_tool": signal.get("source_tool"),
                    "evidence": signal.get("evidence"),
                },
                ("asset", "port"),
            )
        elif typ == "endpoint":
            url = _clean(signal.get("url"))
            if url:
                _append_unique(graph["web_targets"], {"url": url, "source_tool": signal.get("source_tool")}, ("url",))
                _append_unique(graph["endpoints"], {"url": url, "source_tool": signal.get("source_tool"), "evidence": signal.get("evidence")}, ("url",))
        elif typ == "parameter":
            _append_unique(
                graph["parameters"],
                {
                    "url": signal.get("url"),
                    "name": signal.get("name"),
                    "method": signal.get("method") or "GET",
                    "source_tool": signal.get("source_tool"),
                    "recommended_skills": list(signal.get("recommended_skills") or []),
                },
                ("url", "name", "method"),
            )
        elif typ == "form":
            _append_unique(graph["forms"], {"url": signal.get("url"), "method": signal.get("method"), "source_tool": signal.get("source_tool")}, ("url", "method"))
        elif typ == "technology":
            tech = _clean(signal.get("technology")).lower()
            if tech and tech not in graph["technologies"]:
                graph["technologies"].append(tech)
        elif typ == "header":
            _append_unique(graph["headers"], {"asset": signal.get("asset"), "source_tool": signal.get("source_tool"), "evidence": signal.get("evidence")}, ("asset", "source_tool", "evidence"))
        elif typ == "defensive_context":
            _append_unique(graph["waf"], {"asset": signal.get("asset"), "source_tool": signal.get("source_tool"), "evidence": signal.get("evidence")}, ("asset", "source_tool", "evidence"))

    for tag in list(state.get("detected_tech_stack") or []):
        clean_tag = _clean(tag).lower()
        if clean_tag and clean_tag not in graph["technologies"]:
            graph["technologies"].append(clean_tag)

    graph["skill_recommendations"] = recommend_skills_from_recon_graph(graph, state)
    gate = evaluate_recon_completion(graph, state)
    graph["coverage"] = gate["coverage"]
    graph["coverage_gaps"] = gate["coverage_gaps"]
    graph["ready_for_phase_2"] = gate["ready_for_phase_2"]
    graph["updated_at"] = _now_iso()

    state["recon_graph"] = graph
    state["recon_skill_recommendations"] = list(graph.get("skill_recommendations") or [])
    state["recon_reanalyze_queue"] = list(graph.get("reanalyze_queue") or [])
    state["recon_coverage"] = dict(graph.get("coverage") or {})
    state["recon_coverage_gaps"] = list(graph.get("coverage_gaps") or [])
    if new_queue_items:
        state.setdefault("logs_terminais", []).append(
            f"[recon-graph] +{new_queue_items} reanalysis item(s); "
            f"skills={len(graph.get('skill_recommendations') or [])}; "
            f"ready_phase_2={graph.get('ready_for_phase_2')}"
        )
    return graph
