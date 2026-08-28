"""One-shot reversible backfill for BasJob/Finding rows created before the
proof-attachment feature (commit a9343d9, 2026-08-27 22:37:14 -03) landed,
plus two rows (ids 90/91) that ran on a stale celery worker process after
the commit landed but before that worker was restarted to pick it up.

Recomputes bas_proof the exact same way _finding_from_job_result does
today, using the job's already-stored raw result -- no new tool execution,
no fabricated data. Updates the existing Finding in place (never creates a
duplicate) so BasJob.result and Finding.details stay consistent with what a
fresh run would produce right now.
"""
from __future__ import annotations

from sqlalchemy import text

from app.db.session import SessionLocal
from app.models.models import BasAgent, BasJob, BasSchedule, Finding
from app.services.bas_proof import build_bas_proof
from app.services.bas_scheduler import _derive_severity, _extract_key_findings
from app.services.bas_technique_catalog import get_technique

BACKUP_SUFFIX = "20260828_bas_proof"


def _backup(db) -> None:
    db.execute(text(
        f'CREATE TABLE IF NOT EXISTS "platform_backfill_backup_bas_jobs_{BACKUP_SUFFIX}" AS TABLE "bas_jobs"'
    ))
    db.execute(text(
        f'CREATE TABLE IF NOT EXISTS "platform_backfill_backup_findings_{BACKUP_SUFFIX}" AS '
        f'SELECT f.* FROM "findings" f '
        f'WHERE f.id IN (SELECT finding_id FROM bas_jobs WHERE finding_id IS NOT NULL)'
    ))


def run() -> None:
    db = SessionLocal()
    try:
        jobs = (
            db.query(BasJob, BasAgent, BasSchedule)
            .join(BasAgent, BasAgent.id == BasJob.agent_id)
            .join(BasSchedule, BasSchedule.id == BasJob.schedule_id)
            .filter(BasJob.status == "completed")
            .all()
        )
        missing = [(j, a, s) for j, a, s in jobs if not isinstance(j.result, dict) or "bas_proof" not in (j.result or {})]
        print(f"{len(jobs)} completed BasJob rows total; {len(missing)} missing bas_proof")
        if not missing:
            return

        _backup(db)
        db.commit()

        updated_jobs = 0
        updated_findings = 0
        for job, agent, schedule in missing:
            technique = get_technique(job.technique_key)
            if not technique:
                print(f"  job {job.id}: unknown technique_key {job.technique_key!r}, skipping")
                continue
            result = job.result or {}
            is_stub = agent.kind != "real"
            key_findings = [] if is_stub else _extract_key_findings(technique["technique_key"], technique["category"], result)
            severity = "info" if is_stub else _derive_severity(technique["technique_key"], key_findings)
            proof = build_bas_proof(
                technique=technique, job=job, agent=agent, result=result, key_findings=key_findings, severity=severity,
            )
            counts = bool(proof.get("valid"))

            job_result = dict(result)
            job_result["bas_proof"] = proof
            job.result = job_result
            updated_jobs += 1

            if job.finding_id:
                finding = db.query(Finding).filter(Finding.id == job.finding_id).first()
                if finding:
                    finding.severity = severity
                    finding.verification_status = "confirmed" if counts else "hypothesis"
                    finding.confidence_score = 90 if counts else 20
                    details = dict(finding.details or {})
                    details.update({
                        "counts_towards_score": counts,
                        "counts_towards_attack_path": counts,
                        "key_findings": key_findings,
                        "proof": proof,
                        "proof_status": proof.get("status"),
                    })
                    finding.details = details
                    updated_findings += 1

        db.commit()
        print(f"backfilled bas_proof on {updated_jobs} BasJob row(s), updated {updated_findings} Finding row(s)")
    finally:
        db.close()


if __name__ == "__main__":
    run()
