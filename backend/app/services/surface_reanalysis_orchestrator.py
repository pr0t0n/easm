from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import CoverageItem, OffensiveEndpoint, OffensiveHypothesis, ScanJob, ScanLog, ScanWorkItem


def _count_rows(db: Session, model: Any, scan_id: int) -> int:
    try:
        return int(db.query(model).filter(model.scan_job_id == int(scan_id)).count() or 0)
    except Exception:
        return 0


def _snapshot(db: Session, job: ScanJob) -> dict[str, int]:
    return {
        "endpoints": _count_rows(db, OffensiveEndpoint, job.id),
        "hypotheses": _count_rows(db, OffensiveHypothesis, job.id),
        "coverage": _count_rows(db, CoverageItem, job.id),
        "work_items": _count_rows(db, ScanWorkItem, job.id),
    }


def run_surface_reanalysis(
    db: Session,
    job: ScanJob,
    *,
    trigger: str,
    execution_context: str = "external",
    source_item_id: int | None = None,
    expansion_summary: dict[str, Any] | None = None,
    drain_batch_size: int = 80,
) -> dict[str, Any]:
    before = _snapshot(db, job)

    from app.services.endpoint_analysis_pipeline import analyze_endpoints_for_scan
    from app.services.execution_context_service import normalize_execution_context
    from app.services.finding_validation_lifecycle import enforce_high_risk_lifecycle
    from app.services.hypothesis_rules import generate_hypotheses_for_scan
    from app.services.hypothesis_planner import ensure_hypothesis_drain_work_item, plan_hypotheses
    from app.services.pentest_coverage_service import refresh_coverage

    try:
        context = normalize_execution_context(execution_context)
    except ValueError:
        context = "external"

    endpoint_analysis = analyze_endpoints_for_scan(db, job)
    hypotheses = generate_hypotheses_for_scan(db, job)
    planner = plan_hypotheses(db, job)
    drain = ensure_hypothesis_drain_work_item(db, job, batch_size=drain_batch_size)
    coverage = refresh_coverage(db, job)
    with db.begin_nested():
        validation_lifecycle = enforce_high_risk_lifecycle(db, job, limit=50)

    internal_result: dict[str, Any] = {}
    if context == "internal":
        from app.services.execution_context_service import compute_external_internal_diff, reopen_auth_blocked_hypotheses

        reopened = reopen_auth_blocked_hypotheses(db, job)
        diff = compute_external_internal_diff(db, job)
        if reopened:
            planner = plan_hypotheses(db, job)
            drain = ensure_hypothesis_drain_work_item(db, job, batch_size=drain_batch_size)
        internal_result = {
            "reopened_auth_blocked": reopened,
            "diff": {
                "external_only": len(diff.get("external_only") or []),
                "internal_only": len(diff.get("internal_only") or []),
                "shared_changed": len(diff.get("shared_changed") or []),
                "shared_equal": len(diff.get("shared_equal") or []),
            },
        }

    after = _snapshot(db, job)
    deltas = {key: after[key] - before.get(key, 0) for key in after}
    state = dict(job.state_data or {})
    events = list(state.get("surface_reanalysis_events") or [])
    event = {
        "trigger": str(trigger or "unknown")[:120],
        "execution_context": context,
        "source_item_id": source_item_id,
        "expansion": dict(expansion_summary or {}),
        "before": before,
        "after": after,
        "deltas": deltas,
        "endpoint_analysis": endpoint_analysis,
        "hypotheses_created_or_seen": int(hypotheses.get("hypotheses_created_or_seen") or 0),
        "planner": {
            "planned": int(planner.get("planned") or 0),
            "clusters": int(planner.get("clusters") or 0),
            "superseded_now": int(planner.get("superseded_now") or 0),
        },
        "drain": drain,
        "coverage": {
            "coverage_percent": coverage.get("coverage_percent"),
            "covered": coverage.get("covered"),
            "total": coverage.get("total"),
        },
        "validation_lifecycle": validation_lifecycle,
        **internal_result,
        "created_at": datetime.now().isoformat(),
    }
    events.append(event)
    state["surface_reanalysis_events"] = events[-50:]
    state["surface_reanalysis_latest"] = event
    job.state_data = state
    db.add(job)
    db.add(ScanLog(
        scan_job_id=job.id,
        source="surface-reanalysis",
        level="INFO",
        message=(
            f"surface_reanalysis trigger={event['trigger']} context={context} "
            f"delta_endpoints={deltas['endpoints']} delta_hypotheses={deltas['hypotheses']} "
            f"delta_work_items={deltas['work_items']} drain={drain}"
        )[:2000],
    ))
    db.flush()
    return event
