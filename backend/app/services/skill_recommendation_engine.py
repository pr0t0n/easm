from __future__ import annotations

from collections import defaultdict
from typing import Any


def _clean_list(value: Any) -> list[str]:
    if isinstance(value, str):
        raw = [value]
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        raw = []
    out: list[str] = []
    for item in raw:
        text = " ".join(str(item or "").strip().split())
        if text and text not in out:
            out.append(text)
    return out


def recommend_skills_from_recon_graph(recon_graph: dict[str, Any], state: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Rank vulnerability skills from structured RECON evidence.

    This is the bridge between Phase 1 and Phase 2/3: RECON produces signals;
    this engine produces executable skill decisions with target, reason,
    preferred tools and evidence inputs.
    """
    state = dict(state or {})
    signals = [dict(item) for item in list(recon_graph.get("signals") or []) if isinstance(item, dict)]
    tech_stack = {str(item).strip().lower() for item in list(state.get("detected_tech_stack") or recon_graph.get("technologies") or []) if str(item).strip()}

    scored: dict[str, dict[str, Any]] = {}
    evidence_by_skill: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tools_by_skill: dict[str, list[str]] = defaultdict(list)
    targets_by_skill: dict[str, list[str]] = defaultdict(list)
    reasons_by_skill: dict[str, list[str]] = defaultdict(list)

    weight_by_type = {
        "parameter": 28,
        "form": 24,
        "endpoint": 12,
        "technology": 10,
        "service": 8,
        "header": 12,
        "defensive_context": 12,
        "asset": 5,
    }

    for signal in signals:
        skills = _clean_list(signal.get("recommended_skills"))
        if not skills:
            continue
        signal_type = str(signal.get("type") or "").strip().lower()
        confidence = float(signal.get("confidence") or 0.5)
        base = weight_by_type.get(signal_type, 6)
        for skill_id in skills:
            row = scored.setdefault(
                skill_id,
                {
                    "skill_id": skill_id,
                    "score": 0.0,
                    "confidence": 0.0,
                    "reason": "",
                    "target": "",
                    "preferred_tools": [],
                    "evidence_inputs": [],
                    "required_evidence": ["request", "response", "payload or command", "non-destructive proof"],
                    "source": "recon_graph",
                },
            )
            row["score"] = float(row.get("score") or 0.0) + base * confidence
            evidence_by_skill[skill_id].append(signal)
            for tool in _clean_list(signal.get("recommended_tools")):
                if tool not in tools_by_skill[skill_id]:
                    tools_by_skill[skill_id].append(tool)
            target = str(signal.get("url") or signal.get("asset") or "").strip()
            if target and target not in targets_by_skill[skill_id]:
                targets_by_skill[skill_id].append(target)
            reason = str(signal.get("reason") or signal.get("type") or "").strip()
            if reason and reason not in reasons_by_skill[skill_id]:
                reasons_by_skill[skill_id].append(reason)

    if {"asp.net", "iis", "mssql"}.issubset(tech_stack):
        row = scored.setdefault(
            "vuln-injection",
            {
                "skill_id": "vuln-injection",
                "score": 0.0,
                "confidence": 0.0,
                "reason": "",
                "target": "",
                "preferred_tools": [],
                "evidence_inputs": [],
                "required_evidence": ["request", "response", "payload or command", "non-destructive proof"],
                "source": "recon_graph",
            },
        )
        row["score"] = float(row.get("score") or 0.0) + 30
        tools_by_skill["vuln-injection"].insert(0, "sqlmap")
        reasons_by_skill["vuln-injection"].append("asp.net+iis+mssql stack")

    recommendations: list[dict[str, Any]] = []
    for skill_id, row in scored.items():
        evidence = evidence_by_skill.get(skill_id, [])
        score = float(row.get("score") or 0.0)
        confidence = max(0.35, min(0.98, score / 100.0))
        evidence_inputs = []
        for signal in evidence[:10]:
            label = str(signal.get("type") or "signal")
            if signal.get("name"):
                label += f":{signal.get('name')}"
            elif signal.get("technology"):
                label += f":{signal.get('technology')}"
            elif signal.get("port"):
                label += f":{signal.get('port')}"
            evidence_inputs.append(label)
        target = (targets_by_skill.get(skill_id) or [str(state.get("target") or "")])[0]
        preferred_tools = list(dict.fromkeys(tools_by_skill.get(skill_id) or []))[:8]
        recommendations.append(
            dict(row)
            | {
                "score": round(score, 2),
                "confidence": round(confidence, 2),
                "target": target,
                "preferred_tools": preferred_tools,
                "evidence_inputs": evidence_inputs,
                "reason": "; ".join(reasons_by_skill.get(skill_id, [])[:5]) or f"{len(evidence)} recon signal(s)",
            }
        )

    recommendations.sort(key=lambda item: (-float(item.get("score") or 0), str(item.get("skill_id") or "")))
    return recommendations[:12]
