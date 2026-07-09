#!/usr/bin/env python3
"""In-container helper for scripts/validate_authenticated_pentest_idor.py.

Runs INSIDE the backend container (real Postgres, real deps — the host .venv
in this dev machine is stale/broken and missing psycopg2, so DB-touching
checks are delegated here via `docker compose exec backend python ...`).

Seeds a Finding exactly the way a real sqlmap tool run would (via the real
findings_extractor.persist_finding_dicts pipeline), then proves the Item 4
fix: evidence_gate.py's CONFIRMED_TOOLS list blindly marks sqlmap findings
"confirmed" at creation with zero proof; generate_pentest_report must
recompute this via evidence_contract_service and downgrade it back to
"candidate" because there is no EvidenceArtifact backing it.
"""
from __future__ import annotations

import sys

sys.path.insert(0, "/app")

from app.db.session import SessionLocal  # noqa: E402
from app.models.models import Finding, ScanJob  # noqa: E402
from app.services.findings_extractor import persist_finding_dicts  # noqa: E402
from app.services.report_generator import generate_pentest_report  # noqa: E402


def main(scan_id: int) -> int:
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            print(f"NO_SCAN scan_id={scan_id}")
            return 1

        raw = [{
            "title": "SQL Injection confirmed via boolean-based payload — /api/orders",
            "severity": "critical",
            "risk_score": 9,
            "details": {"tool": "sqlmap", "url": str(job.target_query or "") + "/api/orders?id=1"},
        }]
        persist_finding_dicts(db, job, raw, default_tool="sqlmap", default_target=str(job.target_query or ""))
        db.commit()

        finding = (
            db.query(Finding)
            .filter(Finding.scan_job_id == scan_id, Finding.tool == "sqlmap")
            .order_by(Finding.id.desc())
            .first()
        )
        if not finding:
            print("NO_FINDING_CREATED")
            return 1
        status_before = finding.verification_status
        print(f"BEFORE_REPORT status={status_before}")

        generate_pentest_report(db, scan_id)
        db.refresh(finding)
        status_after = finding.verification_status
        print(f"AFTER_REPORT status={status_after}")

        # The bug this proves: evidence_gate.py's CONFIRMED_TOOLS auto-confirms
        # sqlmap with zero proof. The fix: generate_pentest_report must recompute
        # via evidence_contract_service and downgrade it — critical/high findings
        # with a proof-pack requirement never reach the deliverable as "confirmed"
        # without a real EvidenceArtifact.
        if status_before == "confirmed" and status_after == "candidate":
            print("RESULT=PASS")
            return 0
        print(f"RESULT=FAIL before={status_before} after={status_after}")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1])))
