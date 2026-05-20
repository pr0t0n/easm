from __future__ import annotations

from typing import Any


def evaluate_recon_completion(recon_graph: dict[str, Any], state: dict[str, Any] | None = None) -> dict[str, Any]:
    """Quality gate for ending RECON.

    Tool execution count is not enough for BAS. RECON is useful only when it
    enriches assets, maps web surface, produces risk signals and recommends
    skills that Phase 2 can execute.
    """
    state = dict(state or {})
    assets = list(recon_graph.get("assets") or [])
    services = list(recon_graph.get("services") or [])
    web_targets = list(recon_graph.get("web_targets") or [])
    params = list(recon_graph.get("parameters") or [])
    technologies = list(recon_graph.get("technologies") or [])
    recommendations = list(recon_graph.get("skill_recommendations") or [])
    reanalyze_queue = list(recon_graph.get("reanalyze_queue") or [])
    command_fix_required = list(state.get("command_fix_required") or recon_graph.get("command_fix_required") or [])

    live_web_count = len(web_targets)
    assets_enriched_ratio = 1.0 if assets else (1.0 if web_targets else 0.0)
    live_web_targets_fingerprinted_ratio = 1.0 if not web_targets else min(1.0, len(technologies) / max(1, live_web_count))
    parameterized_endpoints_reviewed_ratio = 1.0 if not params else min(1.0, len(recommendations) / max(1, len(params)))
    tech_stack_confidence = min(1.0, len(technologies) / 3.0)
    skill_recommendations_count = len(recommendations)

    coverage = {
        "assets_enriched_ratio": round(assets_enriched_ratio, 3),
        "live_web_targets_fingerprinted_ratio": round(live_web_targets_fingerprinted_ratio, 3),
        "parameterized_endpoints_reviewed_ratio": round(parameterized_endpoints_reviewed_ratio, 3),
        "tech_stack_confidence": round(tech_stack_confidence, 3),
        "skill_recommendations_count": skill_recommendations_count,
        "unresolved_command_fixes": len(command_fix_required),
        "reanalyze_queue_size": len(reanalyze_queue),
    }
    gaps: list[str] = []
    if coverage["assets_enriched_ratio"] < 0.8:
        gaps.append("assets_not_enriched")
    if web_targets and coverage["live_web_targets_fingerprinted_ratio"] < 0.7:
        gaps.append("web_targets_not_fingerprinted")
    if params and coverage["parameterized_endpoints_reviewed_ratio"] < 0.7:
        gaps.append("parameterized_endpoints_without_skill_recommendation")
    if coverage["skill_recommendations_count"] < 1:
        gaps.append("no_skill_recommendations")
    if coverage["unresolved_command_fixes"] > 0:
        gaps.append("command_fix_required")

    return {
        "ready_for_phase_2": not gaps,
        "coverage": coverage,
        "coverage_gaps": gaps,
        "next_action": "advance_to_bas_execution" if not gaps else "continue_recon_or_fix_commands",
    }
