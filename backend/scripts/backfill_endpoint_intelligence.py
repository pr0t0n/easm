"""Reversible, offline backfill for canonical endpoint intelligence.

This script never sends network requests. It only canonicalizes persisted
inventory, merges duplicate route instances, rebuilds endpoint test matrices,
plans hypotheses and refreshes quality snapshots.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from sqlalchemy import text

from app.db.session import SessionLocal
from app.models.models import (
    CoverageItem,
    OffensiveEndpoint,
    OffensiveHypothesis,
    OffensiveJsAsset,
    OffensiveParameter,
    ScanJob,
)
from app.services.endpoint_analysis_pipeline import analyze_endpoints_for_scan
from app.services.hypothesis_planner import plan_hypotheses
from app.services.hypothesis_rules import generate_hypotheses_for_scan
from app.services.offensive_inventory_service import normalize_url
from app.services.scan_quality import build_scan_quality


BACKUP_SUFFIX = "20260720_endpoint_intelligence_v2"
BACKUP_TABLES = (
    "scan_jobs",
    "offensive_endpoints",
    "offensive_parameters",
    "offensive_js_assets",
    "coverage_items",
    "offensive_hypotheses",
)
STATUS_PRIORITY = {
    "confirmed": 8,
    "validated": 8,
    "tested": 7,
    "covered": 7,
    "completed": 7,
    "blocked": 4,
    "planned": 3,
    "not_tested": 1,
}


def _backup(db) -> None:
    for table in BACKUP_TABLES:
        backup = f"platform_backfill_backup_{table}_{BACKUP_SUFFIX}"
        db.execute(text(f'CREATE TABLE IF NOT EXISTS "{backup}" AS TABLE "{table}"'))


def _merge_parameter(db, canonical: OffensiveEndpoint, parameter: OffensiveParameter) -> None:
    existing = (
        db.query(OffensiveParameter)
        .filter(
            OffensiveParameter.endpoint_id == canonical.id,
            OffensiveParameter.name == parameter.name,
            OffensiveParameter.location == parameter.location,
        )
        .first()
    )
    if existing:
        existing.type_hint = existing.type_hint or parameter.type_hint
        existing.risk_hint = existing.risk_hint or parameter.risk_hint
        existing.sample_value = existing.sample_value or parameter.sample_value
        existing.source_tool = existing.source_tool or parameter.source_tool
        existing.parameter_metadata = {
            **dict(parameter.parameter_metadata or {}),
            **dict(existing.parameter_metadata or {}),
        }
        existing.last_seen = max(existing.last_seen, parameter.last_seen)
        db.delete(parameter)
    else:
        parameter.endpoint_id = canonical.id
        db.add(parameter)


def _merge_coverage(db, canonical: OffensiveEndpoint, coverage: CoverageItem) -> None:
    coverage.endpoint_id = canonical.id
    db.add(coverage)


def _merge_coverage_rows(canonical: CoverageItem, duplicate: CoverageItem) -> None:
    if STATUS_PRIORITY.get(str(duplicate.status or ""), 0) > STATUS_PRIORITY.get(str(canonical.status or ""), 0):
        canonical.status = duplicate.status
        canonical.blocking_reason = duplicate.blocking_reason
    canonical.endpoint_id = canonical.endpoint_id or duplicate.endpoint_id
    canonical.hypothesis_id = canonical.hypothesis_id or duplicate.hypothesis_id
    canonical.finding_id = canonical.finding_id or duplicate.finding_id
    canonical.coverage_metadata = {
        **dict(duplicate.coverage_metadata or {}),
        **dict(canonical.coverage_metadata or {}),
    }


def _canonicalize_coverage(db, scan_id: int) -> int:
    rows = db.query(CoverageItem).filter(CoverageItem.scan_job_id == scan_id).order_by(CoverageItem.id.asc()).all()
    groups: dict[tuple[str, str, str], list[CoverageItem]] = defaultdict(list)
    for row in rows:
        target_ref = normalize_url(row.target_ref)[:1000] if "://" in str(row.target_ref or "") else str(row.target_ref or "")
        groups[(str(row.coverage_type or ""), target_ref, str(row.test_class or ""))].append(row)
    merged = 0
    canonicals: list[tuple[CoverageItem, str]] = []
    for (_coverage_type, target_ref, _test_class), grouped in groups.items():
        canonical = grouped[0]
        for duplicate in grouped[1:]:
            _merge_coverage_rows(canonical, duplicate)
            db.delete(duplicate)
            merged += 1
        db.add(canonical)
        canonicals.append((canonical, target_ref))
    db.flush()
    for canonical, target_ref in canonicals:
        canonical.target_ref = target_ref
        db.add(canonical)
    db.flush()
    return merged


def _canonicalize_scan_endpoints(db, scan_id: int) -> dict[str, int]:
    coverage_merged = _canonicalize_coverage(db, scan_id)
    endpoints = (
        db.query(OffensiveEndpoint)
        .filter(OffensiveEndpoint.scan_job_id == scan_id)
        .order_by(OffensiveEndpoint.id.asc())
        .all()
    )
    groups: dict[tuple[str, str, str], list[OffensiveEndpoint]] = defaultdict(list)
    for endpoint in endpoints:
        groups[(str(endpoint.method or "GET").upper(), normalize_url(endpoint.url)[:1000], str(endpoint.auth_context or "anonymous"))].append(endpoint)

    merged = 0
    canonicalized = 0
    for (_method, normalized, _auth), rows in groups.items():
        canonical = rows[0]
        sample_urls: list[str] = []
        for row in rows:
            for sample in list((row.endpoint_metadata or {}).get("sample_urls") or []) + [row.url]:
                if sample and sample not in sample_urls:
                    sample_urls.append(sample)
        for duplicate in rows[1:]:
            for parameter in db.query(OffensiveParameter).filter(OffensiveParameter.endpoint_id == duplicate.id).all():
                _merge_parameter(db, canonical, parameter)
            db.query(OffensiveJsAsset).filter(OffensiveJsAsset.endpoint_id == duplicate.id).update(
                {"endpoint_id": canonical.id}, synchronize_session=False
            )
            for coverage in db.query(CoverageItem).filter(CoverageItem.endpoint_id == duplicate.id).all():
                _merge_coverage(db, canonical, coverage)
            canonical.status_code = canonical.status_code or duplicate.status_code
            canonical.content_type = canonical.content_type or duplicate.content_type
            canonical.auth_required = canonical.auth_required if canonical.auth_required is not None else duplicate.auth_required
            canonical.role_observed = canonical.role_observed or duplicate.role_observed
            canonical.source_tool = canonical.source_tool or duplicate.source_tool
            canonical.confidence = max(int(canonical.confidence or 0), int(duplicate.confidence or 0))
            canonical.tags = sorted(set(list(canonical.tags or []) + list(duplicate.tags or [])))
            canonical.endpoint_metadata = {
                **dict(duplicate.endpoint_metadata or {}),
                **dict(canonical.endpoint_metadata or {}),
            }
            canonical.first_seen = min(canonical.first_seen, duplicate.first_seen)
            canonical.last_seen = max(canonical.last_seen, duplicate.last_seen)
            db.delete(duplicate)
            merged += 1
        db.flush()
        if canonical.normalized_url != normalized:
            canonicalized += 1
        canonical.normalized_url = normalized
        canonical.endpoint_metadata = {
            **dict(canonical.endpoint_metadata or {}),
            "sample_urls": sample_urls[-50:],
            "canonicalized_at": datetime.now().isoformat(),
            "canonicalization_version": "endpoint-intelligence-v2",
        }
        db.add(canonical)
        db.flush()

    return {"endpoints_before": len(endpoints), "route_groups": len(groups), "endpoints_merged": merged, "endpoints_canonicalized": canonicalized, "coverage_merged": coverage_merged}


def run() -> dict:
    db = SessionLocal()
    summary: dict[str, int] = {
        "scans": 0,
        "endpoints_before": 0,
        "route_groups": 0,
        "endpoints_merged": 0,
        "endpoints_canonicalized": 0,
        "coverage_merged": 0,
        "endpoints_analyzed": 0,
        "tests_planned": 0,
        "hypotheses_created_or_seen": 0,
        "hypotheses_superseded": 0,
        "historical_hypotheses_blocked": 0,
    }
    try:
        _backup(db)
        db.commit()
        for job in db.query(ScanJob).order_by(ScanJob.id.asc()).all():
            summary["scans"] += 1
            merged = _canonicalize_scan_endpoints(db, int(job.id))
            for key, value in merged.items():
                summary[key] += int(value)
            analysis = analyze_endpoints_for_scan(db, job, force=True)
            summary["endpoints_analyzed"] += int(analysis.get("endpoints_analyzed") or 0)
            summary["tests_planned"] += int(analysis.get("tests_planned") or 0)
            hypotheses = generate_hypotheses_for_scan(db, job)
            summary["hypotheses_created_or_seen"] += int(hypotheses.get("hypotheses_created_or_seen") or 0)
            planner = plan_hypotheses(db, job)
            summary["hypotheses_superseded"] += int(planner.get("superseded_now") or 0)
            if str(job.status or "") in {"completed", "completed_with_gaps", "failed", "cancelled", "canceled"}:
                for hypothesis in (
                    db.query(OffensiveHypothesis)
                    .filter(OffensiveHypothesis.scan_job_id == job.id, OffensiveHypothesis.status.in_(["open", "queued"]))
                    .all()
                ):
                    metadata = dict(hypothesis.hypothesis_metadata or {})
                    metadata["historical_backfill"] = {
                        "reason": "not_reexecuted_offline_backfill",
                        "network_requests": 0,
                        "blocked_at": datetime.now().isoformat(),
                    }
                    hypothesis.hypothesis_metadata = metadata
                    hypothesis.status = "blocked_historical_not_reexecuted"
                    hypothesis.updated_at = datetime.now()
                    db.add(hypothesis)
                    summary["historical_hypotheses_blocked"] += 1
            quality = build_scan_quality(db, job)
            state = dict(job.state_data or {})
            state["quality_snapshot"] = {
                key: value for key, value in quality.items()
                if key not in {"runtime_visibility", "phase_monitor_issues"}
            }
            state["endpoint_intelligence_backfill"] = {
                "version": "endpoint-intelligence-v2",
                "network_requests": 0,
                "completed_at": datetime.now().isoformat(),
            }
            job.state_data = state
            db.add(job)
            db.commit()
        return summary
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    print(run())
