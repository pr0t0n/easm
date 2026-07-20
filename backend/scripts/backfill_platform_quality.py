"""One-shot reversible backfill for the 2026-07 quality/performance rollout."""
from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse, urlunparse

from sqlalchemy import text

from app.db.session import SessionLocal
from app.models.models import (
    ExecutedToolRun,
    OffensiveAsset,
    OffensiveEndpoint,
    OffensiveHypothesis,
    OffensiveService,
    ScanJob,
    ValidationRun,
)
from app.services.scan_execution_metrics import reconcile_tool_run_ledger
from app.services.scan_quality import QUALITY_GATE_SCORE_THRESHOLD, build_scan_quality, quality_gate_decision
from app.services.operational_sli import persist_scan_sli_alerts


BACKUP_SUFFIX = "20260720"
BACKUP_TABLES = (
    "scan_jobs",
    "offensive_assets",
    "offensive_services",
    "offensive_endpoints",
    "executed_tool_runs",
    "offensive_hypotheses",
)


def _origin(raw: str) -> str:
    parsed = urlparse(str(raw or ""))
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), "", "", "", ""))


def _backup(db) -> None:
    for table in BACKUP_TABLES:
        backup = f"platform_backfill_backup_{table}_{BACKUP_SUFFIX}"
        db.execute(text(f'CREATE TABLE IF NOT EXISTS "{backup}" AS TABLE "{table}"'))


def _merge_assets(db, scan_id: int) -> dict[str, int]:
    assets = db.query(OffensiveAsset).filter(OffensiveAsset.scan_job_id == scan_id).order_by(OffensiveAsset.id).all()
    groups: dict[tuple[str, str, str], list[OffensiveAsset]] = defaultdict(list)
    for asset in assets:
        groups[(str(asset.asset_type or ""), str(asset.host or ""), _origin(str(asset.url or "")))].append(asset)

    merged = 0
    services_merged = 0
    for (_asset_type, _host, origin), rows in groups.items():
        canonical = rows[0]
        duplicates = rows[1:]
        for duplicate in duplicates:
            db.query(OffensiveEndpoint).filter(OffensiveEndpoint.asset_id == duplicate.id).update(
                {"asset_id": canonical.id}, synchronize_session=False
            )
            for service in db.query(OffensiveService).filter(OffensiveService.asset_id == duplicate.id).all():
                existing = (
                    db.query(OffensiveService)
                    .filter(
                        OffensiveService.asset_id == canonical.id,
                        OffensiveService.port == service.port,
                        OffensiveService.protocol == service.protocol,
                    )
                    .first()
                )
                if existing:
                    existing.service_name = existing.service_name or service.service_name
                    existing.product = existing.product or service.product
                    existing.version = existing.version or service.version
                    existing.banner = existing.banner or service.banner
                    existing.tls = bool(existing.tls or service.tls)
                    db.delete(service)
                    services_merged += 1
                else:
                    service.asset_id = canonical.id
                    db.add(service)
            canonical.confidence = max(int(canonical.confidence or 0), int(duplicate.confidence or 0))
            canonical.source_tool = canonical.source_tool or duplicate.source_tool
            canonical.asset_metadata = {**dict(duplicate.asset_metadata or {}), **dict(canonical.asset_metadata or {})}
            db.delete(duplicate)
            merged += 1
        db.flush()
        canonical.url = origin
        db.add(canonical)
    db.flush()
    services_created = 0
    endpoints = db.query(OffensiveEndpoint).filter(OffensiveEndpoint.scan_job_id == scan_id).all()
    for endpoint in endpoints:
        parsed = urlparse(str(endpoint.url or ""))
        if not endpoint.asset_id or not parsed.hostname:
            continue
        tls = parsed.scheme.lower() == "https"
        port = parsed.port or (443 if tls else 80)
        existing = (
            db.query(OffensiveService)
            .filter(
                OffensiveService.asset_id == endpoint.asset_id,
                OffensiveService.port == port,
                OffensiveService.protocol == "tcp",
            )
            .first()
        )
        if existing:
            continue
        db.add(OffensiveService(
            scan_job_id=scan_id,
            asset_id=endpoint.asset_id,
            port=port,
            protocol="tcp",
            service_name="https" if tls else "http",
            tls=tls,
            source_tool=endpoint.source_tool,
            service_metadata={"inferred_from_endpoint_backfill": True},
        ))
        db.flush()
        services_created += 1
    return {"assets_merged": merged, "services_merged": services_merged, "services_created": services_created}


def _repair_hypothesis_statuses(db, scan_id: int) -> int:
    validated_ids = {
        int(row[0])
        for row in db.query(ValidationRun.hypothesis_id)
        .filter(ValidationRun.scan_job_id == scan_id, ValidationRun.hypothesis_id.is_not(None))
        .all()
    }
    updated = 0
    for hypothesis in db.query(OffensiveHypothesis).filter(OffensiveHypothesis.scan_job_id == scan_id).all():
        if hypothesis.id not in validated_ids:
            continue
        if str(hypothesis.status or "").lower() in {"open", "candidate"}:
            hypothesis.status = "tested_candidate"
            db.add(hypothesis)
            updated += 1
    return updated


def run() -> dict:
    db = SessionLocal()
    summary = {"scans": 0, "assets_merged": 0, "services_merged": 0, "services_created": 0, "tool_runs_reconciled": 0, "hypotheses_repaired": 0, "jobs_regraded": 0}
    try:
        _backup(db)
        db.commit()
        for job in db.query(ScanJob).order_by(ScanJob.id).all():
            summary["scans"] += 1
            asset_result = _merge_assets(db, job.id)
            summary["assets_merged"] += asset_result["assets_merged"]
            summary["services_merged"] += asset_result["services_merged"]
            summary["services_created"] += asset_result["services_created"]
            summary["tool_runs_reconciled"] += reconcile_tool_run_ledger(db, job)["updated"]
            summary["hypotheses_repaired"] += _repair_hypothesis_statuses(db, job.id)
            db.flush()

            quality = build_scan_quality(db, job)
            decision = quality_gate_decision(quality)
            state = dict(job.state_data or {})
            gate = dict(state.get("quality_gate") or {})
            gate.update({
                "status": "passed" if decision["passed"] else "completed_with_gaps",
                "passed": decision["passed"],
                "threshold": QUALITY_GATE_SCORE_THRESHOLD,
                "last_score": quality.get("score"),
                "last_grade": quality.get("grade"),
                "completion_status": decision["completion_status"],
                "blockers": decision["blockers"],
                "reason": "historical_backfill_20260720",
            })
            quality["quality_gate"] = gate
            state["quality_gate"] = gate
            state["quality_snapshot"] = {
                key: value for key, value in quality.items()
                if key not in {"runtime_visibility", "phase_monitor_issues"}
            }
            job.state_data = state
            if str(job.status or "") in {"completed", "completed_with_gaps"}:
                job.status = decision["completion_status"]
                summary["jobs_regraded"] += 1
            db.add(job)
            persist_scan_sli_alerts(db, job, quality)
            db.commit()
        return summary
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    print(run())
