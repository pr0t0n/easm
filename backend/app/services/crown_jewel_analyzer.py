"""crown_jewel_analyzer.py — Crown jewel identification after early reconnaisance.

M1: After phases P01/P02 complete, identify high-value targets (crown jewels) and
reorder the remaining work queue to prioritize those targets.

Crown jewels = targets that match one or more high-value patterns:
  - Authentication endpoints (auth., login., sso.)
  - Data stores (db., mysql., postgres., redis., mongo.)
  - Payment / financial (pay., billing., invoice., pix.)
  - Admin panels (admin., portal., dashboard., manager.)
  - CI/CD and internal tooling (ci., jenkins., gitlab., artifactory.)
  - API gateways (api., gw., gateway.)
  - Secrets / config (vault., config., secrets.)
  - Customer-facing SPAs (app., platform.)

Crown jewel items in the work queue get their priority boosted (lower number = more urgent)
so Kali workers pick them up first.  Non-crown targets keep their original priority.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ── Crown jewel patterns ──────────────────────────────────────────────────────
# Each entry: (regex_pattern, boost, label)
# boost is NEGATIVE = higher priority (lower number wins in ORDER BY priority ASC)
CROWN_JEWEL_PATTERNS: list[tuple[str, int, str]] = [
    # Auth / identity
    (r"^(auth|sso|login|oauth|id|identity|iam)\.", -30, "identity/auth"),
    (r"^(accounts?|usuarios?|users?)\.", -25, "user_management"),

    # Payments / financials
    (r"^(pay|payment|billing|invoice|checkout|pix|boleto|financ)\.", -35, "payment/financial"),
    (r"^(wallet|credit|debit|card)\.", -30, "payment/financial"),

    # Admin / management
    (r"^(admin|administrator|portal|dashboard|manager|mgmt|backoffice)\.", -25, "admin_panel"),
    (r"^(control|painel|gestao|gerencia)\.", -20, "admin_panel"),

    # Data stores (often directly exposed in EASM scans)
    (r"^(db|mysql|postgres|redis|mongo|elastic|kibana|rabbitmq|kafka)\.", -30, "data_store"),
    (r"^(data|database|analytics|warehouse|bi|tableau|grafana)\.", -25, "data_store"),

    # CI/CD and dev tools
    (r"^(ci|cd|jenkins|gitlab|github|bitbucket|artifactory|nexus|sonar)\.", -25, "cicd"),
    (r"^(build|deploy|devops|release|pipeline|registry)\.", -20, "cicd"),

    # API gateways / microservices
    (r"^(api|gw|gateway|proxy|lb|loadbalancer)\.", -20, "api_gateway"),
    (r"^(internal|intranet|private)\.", -25, "internal_service"),

    # Secrets / config management
    (r"^(vault|config|secrets?|consul|etcd|zookeeper)\.", -30, "secrets_mgmt"),
    (r"^(env|settings?|credentials?)\.", -25, "secrets_mgmt"),

    # Customer-facing SPAs / critical products
    (r"^(app|platform|webapp|web|portal|service)\.", -15, "customer_app"),

    # Cloud metadata / infra
    (r"169\.254\.169\.254", -40, "cloud_metadata"),  # AWS/GCP/Azure metadata endpoint
    (r"^(backup|archive|dr|recovery)\.", -20, "backup_infra"),
]

# Minimum phase completions before crown jewel analysis runs
MIN_P01_DONE_ITEMS = 5


def identify_crown_jewels(targets: list[str]) -> list[tuple[str, int, str]]:
    """Score each target and return (target, boost, label) for crown jewels.

    Returns only targets with any matching pattern (boost != 0).
    """
    results: list[tuple[str, int, str]] = []
    for target in targets:
        t_lower = target.strip().lower()
        best_boost = 0
        best_label = "standard"
        for pattern, boost, label in CROWN_JEWEL_PATTERNS:
            if re.search(pattern, t_lower, re.IGNORECASE):
                if boost < best_boost:
                    best_boost = boost
                    best_label = label
        if best_boost < 0:
            results.append((target, best_boost, best_label))
    return sorted(results, key=lambda x: x[1])


def boost_crown_jewel_items(
    db: Session,
    scan_id: int,
    crown_jewels: list[tuple[str, int, str]],
) -> int:
    """Update priority of queued work items for crown jewel targets.

    Returns count of items boosted.
    """
    from app.models.models import ScanWorkItem, ScanLog

    if not crown_jewels:
        return 0

    boosted = 0
    crown_targets = {t: (boost, label) for t, boost, label in crown_jewels}

    items = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.status.in_(["queued", "retry"]),
            ScanWorkItem.target.in_(list(crown_targets.keys())),
        )
        .all()
    )

    for item in items:
        boost, label = crown_targets.get(item.target, (0, ""))
        if boost < 0:
            new_priority = max(1, int(item.priority or 100) + boost)
            if new_priority < int(item.priority or 100):
                old_meta = dict(item.item_metadata or {})
                old_meta["crown_jewel"] = True
                old_meta["crown_jewel_label"] = label
                old_meta["original_priority"] = item.priority
                item.item_metadata = old_meta
                item.priority = new_priority
                boosted += 1

    if boosted:
        from datetime import datetime
        db.add(ScanLog(
            scan_job_id=scan_id,
            source="crown-jewel-analyzer",
            level="INFO",
            message=(
                f"crown_jewel_boost scan={scan_id} "
                f"targets={len(crown_jewels)} items_boosted={boosted} "
                f"jewels={[t for t, _, _ in crown_jewels[:5]]}"
            ),
        ))
        db.commit()

    return boosted


def run_crown_jewel_analysis(db: Session, scan_id: int) -> dict[str, Any]:
    """Main entry point — called after P01/P02 work items complete.

    1. Collect all distinct targets discovered in the scan so far
    2. Score them against CROWN_JEWEL_PATTERNS
    3. Boost priority for crown jewel targets in the work queue
    4. Mark crown jewels in scan job state_data so the UI can show them
    """
    from app.models.models import ScanJob, ScanWorkItem, ScanLog
    from datetime import datetime

    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        return {"error": "scan not found"}

    # Check if already ran to avoid repeated boosts
    state = dict(job.state_data or {})
    if state.get("crown_jewel_analysis_done"):
        return {"skipped": "already_done"}

    # Collect unique targets from work items (excluding __batch__)
    target_rows = (
        db.query(ScanWorkItem.target)
        .filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.target != "__batch__",
        )
        .distinct()
        .all()
    )
    all_targets = [str(r[0] or "").strip() for r in target_rows if r[0] and r[0] != "__batch__"]

    # Also grab targets from batch items
    batch_rows = (
        db.query(ScanWorkItem.item_metadata)
        .filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.target == "__batch__",
        )
        .all()
    )
    for (meta,) in batch_rows:
        if meta and isinstance(meta, dict):
            for t in (meta.get("batch_targets") or []):
                if t and t not in all_targets:
                    all_targets.append(t)

    if not all_targets:
        return {"skipped": "no_targets"}

    crown_jewels = identify_crown_jewels(all_targets)
    boosted = boost_crown_jewel_items(db, scan_id, crown_jewels)

    # Mark in state_data so UI can highlight crown jewels
    state["crown_jewel_analysis_done"] = True
    state["crown_jewels"] = [
        {"target": t, "boost": b, "label": lbl}
        for t, b, lbl in crown_jewels
    ]
    job.state_data = state
    db.add(ScanLog(
        scan_job_id=scan_id,
        source="crown-jewel-analyzer",
        level="INFO",
        message=(
            f"crown_jewel_analysis scan={scan_id} "
            f"total_targets={len(all_targets)} "
            f"crown_jewels={len(crown_jewels)} "
            f"items_boosted={boosted}"
        ),
    ))
    db.commit()

    logger.info(
        "crown_jewel_analysis scan=%d targets=%d crown_jewels=%d boosted=%d",
        scan_id, len(all_targets), len(crown_jewels), boosted,
    )

    return {
        "total_targets": len(all_targets),
        "crown_jewels": len(crown_jewels),
        "items_boosted": boosted,
        "jewels": [{"target": t, "label": lbl} for t, _, lbl in crown_jewels],
    }
