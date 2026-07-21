"""Risk-, evidence- and outcome-aware planning for offensive hypotheses."""
from __future__ import annotations

import os
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session

from app.models.models import OffensiveHypothesis, ScanJob, ScanWorkItem
from app.services.pentest_outcome_learning import calibration_map


OPEN_STATUSES = {"open", "queued"}
TERMINAL_STATUSES = {
    "validated", "tested_candidate", "refuted", "superseded",
    "blocked_precondition", "blocked_missing_auth", "blocked_missing_validator",
    "blocked_missing_authorization",
    "blocked_historical_not_reexecuted",
}
VALIDATOR_TYPES = {
    "idor_bola", "object_reference", "bfla_authz", "business_logic_mass_assignment",
    "ssrf_open_redirect", "lfi_ssti_path_traversal", "xss_sqli", "rce",
    "api_security", "api_graphql", "api_spec_exposure", "information_disclosure",
}
IMPACT = {
    "rce": 100, "idor_bola": 92, "object_reference": 88, "bfla_authz": 90,
    "business_logic_mass_assignment": 82, "xss_sqli": 80,
    "lfi_ssti_path_traversal": 78, "ssrf_open_redirect": 74,
    "api_security": 68, "api_graphql": 68, "api_spec_exposure": 58,
    "information_disclosure": 50,
}
COST = {
    "rce": 90, "business_logic_mass_assignment": 80, "idor_bola": 65,
    "object_reference": 65, "bfla_authz": 55, "xss_sqli": 45,
    "lfi_ssti_path_traversal": 45, "ssrf_open_redirect": 35,
}
_NUMERIC_OR_UUID = re.compile(r"(?<=/)(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,})(?=/|$)", re.I)


def _canonical_target(raw: str) -> str:
    value = str(raw or "").strip()
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc:
            path = _NUMERIC_OR_UUID.sub("{id}", parsed.path.rstrip("/") or "/")
            return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, ""))[:1000]
    except ValueError:
        pass
    return _NUMERIC_OR_UUID.sub("{id}", value.lower())[:1000]


def hypothesis_cluster_key(hypothesis: OffensiveHypothesis) -> str:
    metadata = dict(hypothesis.hypothesis_metadata or {})
    parameter = str(metadata.get("parameter") or "").strip().lower()
    return "|".join((str(hypothesis.hypothesis_type or "").lower(), _canonical_target(hypothesis.target_ref), parameter))


def _crown_jewel_match(job: ScanJob, hypothesis: OffensiveHypothesis) -> bool:
    target = str(hypothesis.target_ref or "").lower()
    crown = list((job.state_data or {}).get("crown_jewels") or [])
    return any(
        str(item.get("target") or item.get("subdomain") or "").lower() in target
        for item in crown if isinstance(item, dict) and str(item.get("target") or item.get("subdomain") or "")
    )


def score_hypothesis(
    job: ScanJob,
    hypothesis: OffensiveHypothesis,
    calibration: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    h_type = str(hypothesis.hypothesis_type or "").lower()
    confidence = max(0.0, min(100.0, float(hypothesis.confidence or 0)))
    impact = float(IMPACT.get(h_type, 45))
    cost = float(COST.get(h_type, 35))
    validator_available = h_type in VALIDATOR_TYPES
    requires_identities = bool(hypothesis.required_identities)
    crown = _crown_jewel_match(job, hypothesis)
    historical = dict((calibration or {}).get(h_type) or {})
    precision = float(historical.get("ema_precision", 0.5))
    success = float(historical.get("ema_success", 0.5))

    components = {
        "confidence": confidence * 0.24,
        "impact": impact * 0.28,
        "crown_jewel": 15.0 if crown else 0.0,
        "auth_boundary": 8.0 if requires_identities else 2.0,
        "validator_readiness": 12.0 if validator_available else -12.0,
        "historical_precision": precision * 8.0,
        "historical_success": success * 5.0,
        "cost_penalty": -(cost * 0.08),
    }
    score = round(max(0.0, min(100.0, sum(components.values()))), 2)
    return {
        "score": score,
        "impact": impact,
        "estimated_cost": cost,
        "validator_available": validator_available,
        "requires_identities": requires_identities,
        "crown_jewel": crown,
        "historical_precision": round(precision, 4),
        "historical_success": round(success, 4),
        "components": {key: round(value, 2) for key, value in components.items()},
    }


def plan_hypotheses(db: Session, job: ScanJob, *, limit: int | None = None) -> dict[str, Any]:
    rows = (
        db.query(OffensiveHypothesis)
        .filter(OffensiveHypothesis.scan_job_id == job.id, OffensiveHypothesis.status.in_(sorted(OPEN_STATUSES)))
        .order_by(OffensiveHypothesis.id.asc())
        .all()
    )
    calibration = calibration_map(db, job, "hypothesis")
    groups: dict[str, list[OffensiveHypothesis]] = defaultdict(list)
    for row in rows:
        groups[hypothesis_cluster_key(row)].append(row)

    candidates: list[tuple[float, int, OffensiveHypothesis, dict[str, Any]]] = []
    superseded = 0
    for cluster_key, grouped in groups.items():
        ranked = sorted(
            ((score_hypothesis(job, row, calibration), row) for row in grouped),
            key=lambda item: (-float(item[0]["score"]), -int(item[1].confidence or 0), int(item[1].id)),
        )
        leader_score, leader = ranked[0]
        for _, duplicate in ranked[1:]:
            metadata = dict(duplicate.hypothesis_metadata or {})
            metadata["planner"] = {
                "cluster_key": cluster_key,
                "superseded_by": leader.id,
                "reason": "equivalent_hypothesis_cluster",
                "planned_at": datetime.now().isoformat(),
            }
            duplicate.hypothesis_metadata = metadata
            duplicate.status = "superseded"
            duplicate.updated_at = datetime.now()
            db.add(duplicate)
            superseded += 1
        candidates.append((float(leader_score["score"]), int(leader.id), leader, leader_score))

    candidates.sort(key=lambda item: (-item[0], item[1]))
    selected = candidates[: max(0, int(limit))] if limit is not None else candidates
    planned: list[dict[str, Any]] = []
    for rank, (_, _, row, score) in enumerate(selected, start=1):
        metadata = dict(row.hypothesis_metadata or {})
        metadata["planner"] = {
            **score,
            "rank": rank,
            "cluster_key": hypothesis_cluster_key(row),
            "planned_at": datetime.now().isoformat(),
            "policy": "risk_evidence_outcome_v1",
        }
        row.hypothesis_metadata = metadata
        row.updated_at = datetime.now()
        db.add(row)
        planned.append({"id": row.id, "rank": rank, "score": score["score"], "type": row.hypothesis_type})

    state = dict(job.state_data or {})
    superseded_total = (
        db.query(OffensiveHypothesis)
        .filter(OffensiveHypothesis.scan_job_id == job.id, OffensiveHypothesis.status == "superseded")
        .count()
    )
    state["hypothesis_planner"] = {
        "policy": "risk_evidence_outcome_v1",
        "open_before": len(rows),
        "clusters": len(groups),
        "superseded": superseded_total,
        "superseded_now": superseded,
        "planned": len(planned),
        "top": planned[:20],
        "updated_at": datetime.now().isoformat(),
    }
    job.state_data = state
    db.add(job)
    db.flush()
    return {**state["hypothesis_planner"], "rows": [item[2] for item in selected]}


def drain_hypotheses(
    db: Session,
    job: ScanJob,
    *,
    batch_size: int = 100,
    max_total: int | None = None,
) -> dict[str, Any]:
    """Resolve every selected hypothesis or persist an explicit blocker."""
    from app.services.pentest_validators import validate_hypothesis
    from app.services.pentest_outcome_learning import record_outcome

    hard_limit = int(max_total or os.getenv("PENTEST_HYPOTHESIS_DRAIN_MAX", "2000"))
    total = 0
    counts: dict[str, int] = defaultdict(int)
    no_progress = False
    while total < hard_limit:
        plan = plan_hypotheses(db, job, limit=min(batch_size, hard_limit - total))
        rows = list(plan.get("rows") or [])
        if not rows:
            break
        prefetched = _prefetch_read_only_observations(db, job, rows)
        progressed = 0
        for hypothesis in rows:
            before = str(hypothesis.status or "")
            result = validate_hypothesis(
                db,
                job,
                hypothesis,
                prefetched_observation=prefetched.get(int(hypothesis.id)),
            )
            outcome = str(result.get("result") or "skipped")
            after = str(hypothesis.status or "")
            record_outcome(
                db, job, dimension="hypothesis", metric_key=str(hypothesis.hypothesis_type or "unknown"),
                outcome=after if after else outcome,
                metadata={"validator_result": outcome, "reason": str(result.get("reason") or "")[:300]},
            )
            counts[outcome] += 1
            if after != outcome:
                counts[after] += 1
            total += 1
            if after != before and after in TERMINAL_STATUSES:
                progressed += 1
        db.flush()
        if progressed == 0:
            no_progress = True
            break

    remaining = (
        db.query(OffensiveHypothesis)
        .filter(OffensiveHypothesis.scan_job_id == job.id, OffensiveHypothesis.status.in_(sorted(OPEN_STATUSES)))
        .count()
    )
    state = dict(job.state_data or {})
    previous_drain = dict(state.get("hypothesis_drain") or {})
    summary = {
        "processed": total,
        "processed_total": int(previous_drain.get("processed_total") or 0) + total,
        "remaining": remaining,
        "hard_limit": hard_limit,
        "limit_reached": bool(remaining and total >= hard_limit),
        "no_progress": no_progress,
        "counts": dict(counts),
        "completed_at": datetime.now().isoformat(),
    }
    state["hypothesis_drain"] = summary
    job.state_data = state
    db.add(job)
    db.flush()
    return summary


def _prefetch_read_only_observations(
    db: Session,
    job: ScanJob,
    hypotheses: list[OffensiveHypothesis],
) -> dict[int, dict[str, Any]]:
    """Fetch read-only probes concurrently while DB writes remain serial."""
    from app.services.pentest_validators import _endpoint_for_hypothesis, _safe_request
    from app.services.scan_scope import authorized_scope_from_target_query, host_from_scope_reference, is_host_in_scope

    read_only_types = {
        "api_security", "api_graphql", "api_spec_exposure",
        "information_disclosure", "sensitive_file_exposure",
    }
    probes: list[tuple[int, str, int]] = []
    observations: dict[int, dict[str, Any]] = {}
    scope = authorized_scope_from_target_query(str(job.target_query or ""))
    for hypothesis in hypotheses:
        hypothesis_type = str(hypothesis.hypothesis_type or "")
        if hypothesis_type not in read_only_types:
            continue
        endpoint = _endpoint_for_hypothesis(db, hypothesis)
        if endpoint:
            endpoint_url = str(endpoint.url)
            if not is_host_in_scope(host_from_scope_reference(endpoint_url), scope):
                observations[int(hypothesis.id)] = {
                    "ok": False,
                    "error": "OutOfScope",
                    "detail": "read_only_probe_discarded_by_scope_guard",
                }
                continue
            probes.append((
                int(hypothesis.id),
                endpoint_url,
                131072 if hypothesis_type == "sensitive_file_exposure" else 0,
            ))
    if not probes:
        return observations

    worker_count = max(1, min(32, int(os.getenv("PENTEST_HYPOTHESIS_HTTP_WORKERS", "12"))))
    with ThreadPoolExecutor(max_workers=min(worker_count, len(probes))) as pool:
        futures = {
            pool.submit(
                _safe_request,
                url,
                {},
                {},
                follow_redirects=False,
                analysis_bytes=analysis_bytes,
            ): hypothesis_id
            for hypothesis_id, url, analysis_bytes in probes
        }
        for future in as_completed(futures):
            hypothesis_id = futures[future]
            try:
                observations[hypothesis_id] = future.result()
            except Exception as exc:  # pragma: no cover - _safe_request catches network failures
                observations[hypothesis_id] = {
                    "ok": False,
                    "error": type(exc).__name__,
                    "detail": str(exc)[:300],
                }
    return observations


def ensure_hypothesis_drain_work_item(
    db: Session,
    job: ScanJob,
    *,
    batch_size: int = 100,
) -> dict[str, Any]:
    """Ensure that the persistent queue owns the remaining validation drain."""
    plan = plan_hypotheses(db, job)
    remaining = len(list(plan.get("rows") or []))
    active_statuses = ["blocked", "queued", "retry", "dispatched", "running", "submitted"]
    existing = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == job.id,
            ScanWorkItem.tool_name == "internal-hypothesis-validator",
            ScanWorkItem.status.in_(active_statuses),
        )
        .order_by(ScanWorkItem.id.desc())
        .first()
    )
    if not remaining:
        return {"remaining": 0, "scheduled": 0, "active_work_item_id": None}
    if existing:
        return {"remaining": remaining, "scheduled": 0, "active_work_item_id": int(existing.id)}
    failures = int((job.state_data or {}).get("hypothesis_drain_failures") or 0)
    if failures >= 3:
        return {
            "remaining": remaining,
            "scheduled": 0,
            "active_work_item_id": None,
            "blocked": True,
            "blocking_reason": "hypothesis_drain_failed_three_times",
            "failures": failures,
        }

    now = datetime.now()
    target = next(
        (piece.strip() for piece in re.split(r"[,;\n]+", str(job.target_query or "")) if piece.strip()),
        str(job.target_query or "").strip(),
    )
    # This validator is a persistent controller that processes many batches for
    # the same target. The queue uniqueness contract does not permit one row per
    # batch, so re-arm the existing terminal controller instead of inserting a
    # duplicate (scan, phase, tool, target) key.
    controller = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == job.id,
            ScanWorkItem.phase_id == "P21",
            ScanWorkItem.tool_name == "internal-hypothesis-validator",
            ScanWorkItem.target == target[:500],
        )
        .order_by(ScanWorkItem.id.desc())
        .first()
    )
    if controller:
        metadata = dict(controller.item_metadata or {})
        previous_status = str(controller.status or "")
        metadata.update({
            "source": "hypothesis_planner",
            "engine": "internal_safe_validator",
            "internal_hypothesis_batch": True,
            "batch_size": max(1, min(250, int(batch_size))),
            "queue_ready_at": now.isoformat(),
            "planner_policy": "risk_evidence_outcome_v1",
            "batch_iteration": int(metadata.get("batch_iteration") or 0) + 1,
            "previous_batch_status": previous_status,
        })
        controller.status = "queued"
        controller.attempts = 0
        controller.max_attempts = 1
        controller.lease_until = None
        controller.started_at = None
        controller.finished_at = None
        controller.last_error = None
        controller.result = {}
        controller.item_metadata = metadata
        controller.updated_at = now
        db.flush()
        return {
            "remaining": remaining,
            "scheduled": 1,
            "active_work_item_id": int(controller.id),
            "reused_controller": True,
            "previous_status": previous_status,
        }

    item = ScanWorkItem(
        scan_job_id=job.id,
        phase_id="P21",
        target=target[:500],
        tool_name="internal-hypothesis-validator",
        profile="internal-safe-validator",
        resource_class="light",
        priority=3,
        status="queued",
        attempts=0,
        max_attempts=1,
        item_metadata={
            "source": "hypothesis_planner",
            "engine": "internal_safe_validator",
            "internal_hypothesis_batch": True,
            "batch_size": max(1, min(250, int(batch_size))),
            "queue_ready_at": now.isoformat(),
            "planner_policy": "risk_evidence_outcome_v1",
        },
        created_at=now,
        updated_at=now,
    )
    db.add(item)
    db.flush()
    return {"remaining": remaining, "scheduled": 1, "active_work_item_id": int(item.id)}
