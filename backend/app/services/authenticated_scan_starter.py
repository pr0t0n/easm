"""Start a fresh internal-first scan from an existing validated session.

This service is the product path for "reuse the same captured credential/session
and rerun the pentest".  It deliberately mirrors the identity-confirm flow:
create a new scan, copy only the valid session material, activate G1, hold G0
until internal work drains, seed the authenticated kill-chain, then let workers
dispatch normally.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.models.models import (
    ScanAuthSession,
    ScanIdentity,
    ScanJob,
    ScanLog,
)
from app.services.execution_context_service import activate_internal_context, get_context
from app.services.scan_profiles import normalize_scan_level, scan_profile
from app.services.scan_scope import authorized_scope_for_scan
from app.services.scan_work_queue import seed_internal_first_work_items
from app.services.skill_execution_engine import seed_skill_probe_items
from app.services.strategy_runtime import parse_scope_targets


def _latest_valid_session(
    db: Session,
    source_scan_id: int,
    *,
    identity_key: str | None = None,
) -> tuple[ScanIdentity, ScanAuthSession]:
    query = (
        db.query(ScanAuthSession, ScanIdentity)
        .join(ScanIdentity, ScanIdentity.id == ScanAuthSession.scan_identity_id)
        .filter(
            ScanAuthSession.scan_job_id == int(source_scan_id),
            ScanAuthSession.status.in_(["valid", "static"]),
            ScanIdentity.status == "valid",
            ScanIdentity.session_valid.is_(True),
        )
    )
    if identity_key:
        query = query.filter(ScanIdentity.identity_key == identity_key)
    row = query.order_by(ScanAuthSession.id.desc()).first()
    if row is None:
        raise ValueError("valid_source_session_not_found")
    session, identity = row
    return identity, session


def start_scan_from_valid_session(
    db: Session,
    *,
    source_scan_id: int,
    target_scan_id: int | None = None,
    identity_key: str | None = None,
    target_query: str | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
    """Create and seed a new G1-first scan from an existing valid session."""
    if target_scan_id is not None and db.query(ScanJob.id).filter(ScanJob.id == int(target_scan_id)).first():
        raise ValueError("target_scan_already_exists")

    source = db.query(ScanJob).filter(ScanJob.id == int(source_scan_id)).first()
    if source is None:
        raise ValueError("source_scan_not_found")
    source_identity, source_session = _latest_valid_session(
        db,
        int(source_scan_id),
        identity_key=identity_key,
    )

    now = datetime.now()
    selected_target = str(target_query or source.target_query or "").strip()
    if not selected_target:
        raise ValueError("target_query_required")
    scan_level = normalize_scan_level((source.state_data or {}).get("scan_level") or "full")
    requested_targets = parse_scope_targets(selected_target)
    profile = scan_profile(scan_level)
    source_state = dict(source.state_data or {})
    authorization_gate = dict(source_state.get("authorization_gate") or {})
    if not authorization_gate:
        authorization_gate = {
            "approved": True,
            "mode": "copied_from_authorized_scan",
            "reason": "new_scan_started_from_valid_authenticated_session",
            "authorized_scope": requested_targets,
            "public_targets": requested_targets,
        }

    state: dict[str, Any] = {
        "scan_level": scan_level,
        "scan_profile": profile,
        "execution_plan": "internal_then_external",
        "execution_plan_stage": "internal_running",
        "external_release_pending": True,
        "parallelize": bool(source_state.get("parallelize", True)),
        "parallel_target_batch_size": int(source_state.get("parallel_target_batch_size") or 1024),
        "explicit_inventory_execution_batch_size": int(source_state.get("explicit_inventory_execution_batch_size") or 10),
        "parallel_wait_seconds": int(source_state.get("parallel_wait_seconds") or 60),
        "authorization_gate": authorization_gate,
        "active_exploit_authorized": bool(source_state.get("active_exploit_authorized", True)),
        "provided_targets": requested_targets,
        "target_input_mode": "explicit_target_inventory",
        "explicit_inventory_execution": True,
        "explicit_target_inventory": True,
        "skip_p01_subdomain_enumeration": True,
        "reused_auth_from_scan_id": int(source.id),
        "authenticated_scan_source_id": int(source.id),
        "authenticated_scan_source_auth_session_id": int(source_session.id),
        "authenticated_scan_source_identity_id": int(source_identity.id),
        "authenticated_scan_identity_key": source_identity.identity_key,
        "reused_auth_session_source_id": int(source_session.id),
        "strategy_runtime_timeline": [
            {
                "type": "scan_created_from_existing_authenticated_session",
                "ts": now.isoformat(),
                "source_scan_id": int(source.id),
                "source_auth_session_id": int(source_session.id),
                "identity_key": source_identity.identity_key,
            }
        ],
    }
    job_kwargs = {
        "owner_id": source.owner_id,
        "access_group_id": source.access_group_id,
        "target_query": selected_target,
        "authorization_code": source.authorization_code,
        "mode": mode or source.mode or "unit",
        "status": "running",
        "compliance_status": "approved",
        "authorization_id": source.authorization_id,
        "current_step": "G1 interno em execução; G0 externo aguardando conclusão do interno",
        "mission_progress": 0,
        "state_data": state,
        "created_at": now,
        "updated_at": now,
        "retry_attempt": 0,
        "retry_max": 0,
        "tech_stack": [],
    }
    if target_scan_id is not None:
        job_kwargs["id"] = int(target_scan_id)
    job = ScanJob(**job_kwargs)
    db.add(job)
    db.flush()

    identity = ScanIdentity(
        scan_job_id=job.id,
        identity_key=source_identity.identity_key,
        role=source_identity.role,
        username_ref=source_identity.username_ref,
        auth_type=source_identity.auth_type,
        status="valid",
        session_valid=True,
        last_error="",
        session_metadata={
            **dict(source_identity.session_metadata or {}),
            "copied_from_scan_id": int(source.id),
            "copied_from_identity_id": int(source_identity.id),
        },
        created_at=now,
        updated_at=now,
    )
    db.add(identity)
    db.flush()

    session = ScanAuthSession(
        scan_job_id=job.id,
        scan_identity_id=identity.id,
        session_key=source_session.session_key,
        auth_type=source_session.auth_type,
        status="valid",
        headers=dict(source_session.headers or {}),
        cookies=dict(source_session.cookies or {}),
        validation_result={
            **dict(source_session.validation_result or {}),
            "copied_from_scan_id": int(source.id),
            "copied_from_auth_session_id": int(source_session.id),
        },
        expires_at=source_session.expires_at,
        last_validated_at=source_session.last_validated_at,
        last_error="",
        created_at=now,
        updated_at=now,
    )
    db.add(session)
    db.flush()

    internal_context = activate_internal_context(db, job, session, identity)
    external_context = get_context(db, job.id, "external")
    if external_context is not None:
        external_context.status = "waiting_for_internal"
        db.add(external_context)

    internal_items = seed_internal_first_work_items(db, job, identity.identity_key)
    skill_probes = 0
    for host in authorized_scope_for_scan(db, job.id):
        for phase_id in ("P13", "P16", "P19"):
            skill_probes += seed_skill_probe_items(db, job, phase_id, f"https://{host}")

    db.add(ScanLog(
        scan_job_id=job.id,
        source="authenticated-scan-starter",
        level="INFO",
        message=(
            f"authenticated_scan_started source_scan={source.id} "
            f"identity={identity.identity_key} session_revision={internal_context.session_revision} "
            f"internal_items={internal_items} skill_probes={skill_probes}"
        ),
    ))
    if target_scan_id is not None:
        db.execute(sa.text("select setval('scan_jobs_id_seq', (select max(id) from scan_jobs))"))
    db.flush()
    return {
        "scan_id": int(job.id),
        "target": job.target_query,
        "identity_key": identity.identity_key,
        "auth_session_id": int(session.id),
        "internal_items": int(internal_items),
        "skill_probes": int(skill_probes),
        "session_revision": int(internal_context.session_revision or 1),
    }
