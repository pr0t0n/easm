"""Regras que transformam inventário em hipóteses testáveis."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.models import OffensiveEndpoint, ScanJob
from app.services.offensive_inventory_service import OffensiveInventoryService


def generate_hypotheses_for_scan(db: Session, scan: ScanJob) -> dict[str, int]:
    from app.services.endpoint_analysis_pipeline import analyze_endpoints_for_scan

    endpoint_summary = analyze_endpoints_for_scan(db, scan)
    inv = OffensiveInventoryService(db, scan)
    created_or_seen = 0
    endpoints = db.query(OffensiveEndpoint).filter(OffensiveEndpoint.scan_job_id == scan.id).limit(10000).all()
    for endpoint in endpoints:
        analysis = dict((endpoint.endpoint_metadata or {}).get("analysis") or {})
        for test in list(analysis.get("test_matrix") or []):
            h_type = str(test.get("hypothesis_type") or "")
            if not h_type:
                continue
            inv.upsert_hypothesis(
                hypothesis_type=h_type,
                title=f"{h_type.replace('_', ' ').title()}: {analysis.get('route_template') or endpoint.url}"[:255],
                target_ref=endpoint.normalized_url,
                source_signal=str(test.get("source_signal") or test.get("test_class") or "endpoint_analysis"),
                confidence=int(test.get("confidence") or 50),
                recommended_tools=list(test.get("validators") or []),
                required_identities=list(test.get("required_identities") or []),
                evidence_requirements=list(test.get("evidence_requirements") or []),
                metadata={"endpoint_id": endpoint.id, "url": endpoint.url, "test_class": test.get("test_class"), "analysis_version": analysis.get("version")},
            )
            created_or_seen += 1

    db.flush()
    return {"hypotheses_created_or_seen": created_or_seen, "endpoint_analysis": endpoint_summary}
