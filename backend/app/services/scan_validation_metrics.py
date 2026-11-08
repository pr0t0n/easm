"""Métricas de eficácia da validação de candidates (Fase 4 do plano).

Computadas ao final do scan (via sweep pós-scan) e consultáveis pelo
endpoint admin. Meta do plano: candidate residual < 20%, zero órfãos.
"""
from __future__ import annotations

from typing import Any


def compute_scan_validation_metrics(db: Any, scan_id: int) -> dict[str, Any]:
    from datetime import datetime

    from app.models.models import (
        Finding, FindingAdjudication, JevDecision, ScanJob,
        ScanValidationMetrics, ValidationWire,
    )

    job = db.query(ScanJob).filter(ScanJob.id == int(scan_id)).first()
    if not job:
        return {"error": "scan_missing"}

    findings = db.query(Finding).filter(Finding.scan_job_id == job.id).all()
    counts: dict[str, int] = {}
    for f in findings:
        key = str(f.verification_status or "candidate").lower()
        counts[key] = counts.get(key, 0) + 1

    total = len(findings)
    candidates_n = counts.get("candidate", 0) + counts.get("hypothesis", 0)

    # Órfãos: candidate/hypothesis sem NENHUMA adjudicação.
    orphan_ids = {
        f.id for f in findings
        if str(f.verification_status or "").lower() in {"candidate", "hypothesis"}
    }
    if orphan_ids:
        adjudicated_ids = {
            row[0]
            for row in db.query(FindingAdjudication.finding_id)
            .filter(FindingAdjudication.finding_id.in_(orphan_ids))
            .all()
        }
        orphans = len(orphan_ids - adjudicated_ids)
    else:
        orphans = 0

    wires_total = db.query(ValidationWire).filter(ValidationWire.scan_job_id == job.id).count()
    wires_completed = (
        db.query(ValidationWire)
        .filter(ValidationWire.scan_job_id == job.id, ValidationWire.status == "completed")
        .count()
    )
    wires_failed = (
        db.query(ValidationWire)
        .filter(ValidationWire.scan_job_id == job.id, ValidationWire.status.in_(["failed", "blocked"]))
        .count()
    )
    jev_n = db.query(JevDecision).filter(JevDecision.scan_job_id == job.id).count()

    gate = dict(job.state_data or {}).get("quality_gate") or {}
    grade = None
    history = list(gate.get("history") or [])
    if history:
        grade = str(history[-1].get("grade") or "") or None

    residual = round((candidates_n / total) * 100, 1) if total else 0.0

    row = db.query(ScanValidationMetrics).filter(ScanValidationMetrics.scan_job_id == job.id).first()
    if row is None:
        row = ScanValidationMetrics(scan_job_id=job.id)
        db.add(row)
    row.findings_total = total
    row.candidates = candidates_n
    row.confirmed = counts.get("confirmed", 0)
    row.refuted = counts.get("refuted", 0)
    row.not_applicable = counts.get("not_applicable", 0)
    row.needs_human_review = counts.get("needs_human_review", 0)
    row.blocked = counts.get("blocked", 0)
    row.inconclusive = counts.get("inconclusive", 0)
    row.hypothesis = counts.get("hypothesis", 0)
    row.orphans_total = orphans
    row.orphans_adjudicated = int(orphans == 0) if not orphans else 0
    row.wires_total = int(wires_total)
    row.wires_completed = int(wires_completed)
    row.wires_failed = int(wires_failed)
    row.jev_decisions = int(jev_n)
    row.candidate_residual_pct = residual
    row.quality_gate_grade = grade
    row.computed_at = datetime.now()
    db.add(row)
    db.flush()
    return {
        "scan_id": job.id,
        "findings_total": total,
        "candidates": candidates_n,
        "confirmed": row.confirmed,
        "refuted": row.refuted,
        "not_applicable": row.not_applicable,
        "needs_human_review": row.needs_human_review,
        "blocked": row.blocked,
        "orphans": orphans,
        "wires_total": row.wires_total,
        "wires_completed": row.wires_completed,
        "jev_decisions": row.jev_decisions,
        "candidate_residual_pct": residual,
        "quality_gate_grade": grade,
    }
