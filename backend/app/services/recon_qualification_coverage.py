"""Materialize P02/P06 qualification evidence as durable coverage rows."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import ScanJob, ScanLog
from app.services.offensive_inventory_service import OffensiveInventoryService


def materialize_recon_qualification_coverage(db: Session, job: ScanJob) -> dict[str, int]:
    profiles = dict(((dict(job.state_data or {}).get("preflight") or {}).get("targets") or {}))
    counts = {"targets": 0, "p02": 0, "p06": 0, "rejected": 0}
    now = datetime.now()
    inventory = OffensiveInventoryService(db, job)
    for target, raw_profile in sorted(profiles.items()):
        profile = dict(raw_profile or {})
        if profile.get("non_public_rejected"):
            counts["rejected"] += 1
            continue
        counts["targets"] += 1
        for phase_id, complete_key, positive_key in (
            ("P02", "p02_complete", "p02_positive_evidence"),
            ("P06", "p06_complete", "p06_http_live"),
        ):
            complete = bool(profile.get(complete_key))
            positive = bool(profile.get(positive_key))
            inventory.upsert_coverage(
                coverage_type="recon_qualification",
                target_ref=str(target),
                test_class=phase_id,
                status="confirmed" if positive else ("tested" if complete else "not_tested"),
                blocking_reason="" if complete else str(profile.get("reason") or f"{phase_id.lower()}_not_complete"),
                metadata={
                    "phase_id": phase_id,
                    "target": str(target),
                    "complete": complete,
                    "positive_evidence": positive,
                    "status": profile.get(f"{phase_id.lower()}_status"),
                    "profile": profile.get(f"{phase_id.lower()}_profile"),
                    "checked_at": profile.get(f"{phase_id.lower()}_checked_at"),
                    "input_covered": profile.get(f"{phase_id.lower()}_input_covered"),
                    "open_ports": list(profile.get("open_ports") or []),
                    "http": list(profile.get("http") or []),
                    "scan_contracts": list(profile.get("p02_scan_contracts") or []) if phase_id == "P02" else [],
                    "materialized_at": now.isoformat(),
                },
            )
            counts[phase_id.lower()] += 1
    db.add(ScanLog(
        scan_job_id=job.id,
        source="recon-qualification",
        level="INFO",
        message=(
            "qualification_coverage_materialized "
            f"targets={counts['targets']} p02={counts['p02']} "
            f"p06={counts['p06']} rejected={counts['rejected']}"
        ),
    ))
    db.flush()
    return counts
