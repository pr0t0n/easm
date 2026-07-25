"""Regras que transformam inventário em hipóteses testáveis."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.models import CoverageItem, OffensiveEndpoint, OffensiveHypothesis, ScanJob
from app.services.offensive_inventory_service import OffensiveInventoryService


def generate_hypotheses_for_scan(db: Session, scan: ScanJob) -> dict[str, int]:
    from app.services.endpoint_analysis_pipeline import analyze_endpoints_for_scan

    endpoint_summary = analyze_endpoints_for_scan(db, scan)
    inv = OffensiveInventoryService(db, scan)
    created_or_seen = 0
    active_keys: set[tuple[str, str, str]] = set()
    endpoints = (
        db.query(OffensiveEndpoint)
        .filter(OffensiveEndpoint.scan_job_id == scan.id)
        .order_by(OffensiveEndpoint.id.asc())
        .limit(10000)
        .all()
    )
    for endpoint in endpoints:
        analysis = dict((endpoint.endpoint_metadata or {}).get("analysis") or {})
        for test in list(analysis.get("test_matrix") or []):
            h_type = str(test.get("hypothesis_type") or "")
            if not h_type:
                continue
            target_ref = str(endpoint.normalized_url or "")
            source_signal = str(test.get("source_signal") or test.get("test_class") or "endpoint_analysis")
            hypothesis = inv.upsert_hypothesis(
                hypothesis_type=h_type,
                title=f"{h_type.replace('_', ' ').title()}: {analysis.get('route_template') or endpoint.url}"[:255],
                target_ref=target_ref,
                source_signal=source_signal,
                confidence=int(test.get("confidence") or 50),
                recommended_tools=list(test.get("validators") or []),
                required_identities=list(test.get("required_identities") or []),
                evidence_requirements=list(test.get("evidence_requirements") or []),
                metadata={"endpoint_id": endpoint.id, "url": endpoint.url, "test_class": test.get("test_class"), "analysis_version": analysis.get("version")},
                replace_contract=True,
            )
            if hypothesis.status == "superseded":
                hypothesis.status = "open"
            active_keys.add((h_type, target_ref, source_signal))
            created_or_seen += 1

    superseded = 0
    generated = (
        db.query(OffensiveHypothesis)
        .filter(OffensiveHypothesis.scan_job_id == scan.id)
        .order_by(OffensiveHypothesis.id.asc())
        .all()
    )
    for hypothesis in generated:
        metadata = dict(hypothesis.hypothesis_metadata or {})
        version = str(metadata.get("analysis_version") or "")
        if not version.startswith("endpoint-intelligence-v"):
            continue
        key = (
            str(hypothesis.hypothesis_type or ""),
            str(hypothesis.target_ref or ""),
            str(hypothesis.source_signal or ""),
        )
        if key in active_keys or hypothesis.status in {"validated"}:
            continue
        metadata["superseded_reason"] = "endpoint_contract_no_longer_evidence_backed"
        metadata["superseded_by_analysis_version"] = endpoint_summary.get("version")
        hypothesis.hypothesis_metadata = metadata
        hypothesis.required_identities = []
        hypothesis.status = "superseded"
        db.add(hypothesis)
        superseded += 1

    # Coverage generated from a superseded hypothesis is historical evidence,
    # not an active blocked test. Keep it auditable without reporting it as a
    # current authentication gap.
    superseded_ids = {
        int(hypothesis.id)
        for hypothesis in generated
        if str(hypothesis.status or "").lower() == "superseded"
    }
    coverage_superseded = 0
    if superseded_ids:
        coverage_rows = (
            db.query(CoverageItem)
            .filter(
                CoverageItem.scan_job_id == scan.id,
                CoverageItem.coverage_type == "hypothesis",
                CoverageItem.hypothesis_id.in_(superseded_ids),
                CoverageItem.status != "superseded",
            )
            .all()
        )
        for row in coverage_rows:
            row.status = "superseded"
            row.blocking_reason = "hypothesis_contract_no_longer_evidence_backed"
            row.coverage_metadata = {
                **dict(row.coverage_metadata or {}),
                "superseded_by_analysis_version": endpoint_summary.get("version"),
            }
            db.add(row)
            coverage_superseded += 1

    db.flush()
    return {
        "hypotheses_created_or_seen": created_or_seen,
        "hypotheses_superseded": superseded,
        "hypothesis_coverage_superseded": coverage_superseded,
        "endpoint_analysis": endpoint_summary,
    }
