"""G0 external / G1 authenticated execution context orchestration.

The platform intentionally has exactly two contexts.  Re-capturing a session
updates G1's session revision instead of creating G2, and no G1 work item ever
overwrites its G0 counterpart.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.models import (
    EndpointObservation,
    OffensiveEndpoint,
    OffensiveHypothesis,
    ProcessorCheckpoint,
    ScanAuthSession,
    ScanExecutionContext,
    ScanIdentity,
    ScanJob,
    ScanLog,
    ScanWorkItem,
)


EXTERNAL = "external"
INTERNAL = "internal"
VALID_CONTEXTS = {EXTERNAL, INTERNAL}


def normalize_execution_context(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"internal", "authenticated", "g1"}:
        return INTERNAL
    if raw in {"", "external", "anonymous", "g0"}:
        return EXTERNAL
    raise ValueError(f"unsupported_execution_context:{raw}")


def inventory_auth_context(execution_context: str) -> str:
    return "authenticated" if normalize_execution_context(execution_context) == INTERNAL else "anonymous"


_ACTIVE_ITEM_STATUSES = {"queued", "retry", "dispatched", "running", "submitted", "blocked"}
_TERMINAL_ITEM_STATUSES = {"completed", "done", "failed", "timeout", "skipped"}


def _summarize_context_work_items(db: Session, scan_id: int, context_type: str) -> dict[str, Any]:
    context_type = normalize_execution_context(context_type)
    rows = (
        db.query(ScanWorkItem.status, func.count(ScanWorkItem.id))
        .filter(
            ScanWorkItem.scan_job_id == int(scan_id),
            ScanWorkItem.execution_context == context_type,
        )
        .group_by(ScanWorkItem.status)
        .all()
    )
    counts = {str(status or "unknown"): int(count or 0) for status, count in rows}
    total = sum(counts.values())
    active = sum(count for status, count in counts.items() if status in _ACTIVE_ITEM_STATUSES)
    terminal = sum(count for status, count in counts.items() if status in _TERMINAL_ITEM_STATUSES)
    return {
        "context": context_type,
        "counts": counts,
        "total": total,
        "active": active,
        "terminal": terminal,
    }


def reconcile_execution_plan_state(db: Session, job: ScanJob) -> dict[str, Any]:
    """Keep the user-visible G0/G1 execution state derived from durable rows.

    Celery/Redis are transport; ``scan_work_items`` and
    ``scan_execution_contexts`` are the source of truth.  This reconciler makes
    the internal/external split observable even after worker restarts, lost
    broker messages or authenticated reruns that were created before the UI
    state fields existed.
    """
    state = dict(job.state_data or {})
    if (
        str(state.get("execution_plan") or "") != "internal_then_external"
        and not state.get("internal_first_seed")
        and not state.get("external_release_pending")
    ):
        return state

    now = datetime.now()
    internal = _summarize_context_work_items(db, int(job.id), INTERNAL)
    external = _summarize_context_work_items(db, int(job.id), EXTERNAL)

    internal_status = "not_started"
    if internal["total"] > 0:
        internal_status = "running" if internal["active"] > 0 else "completed"

    external_waiting = bool(state.get("external_release_pending")) and not bool(
        state.get("external_released_after_internal")
    )
    external_status = "waiting_for_internal" if external_waiting else "not_started"
    if not external_waiting:
        if external["total"] > 0:
            external_status = "running" if external["active"] > 0 else "completed"
        elif bool(state.get("external_released_after_internal")):
            external_status = "running"

    current_surface = None
    if internal_status == "running":
        current_surface = "G1"
    elif external_status == "waiting_for_internal":
        current_surface = "G1"
    elif external_status == "running":
        current_surface = "G0"
    elif internal_status == "completed" and external_status in {"not_started", "waiting_for_internal"}:
        current_surface = "G1"
    elif external_status == "completed":
        current_surface = "G0"

    state.update(
        {
            "execution_plan": state.get("execution_plan") or "internal_then_external",
            "g1_status": internal_status,
            "g0_status": external_status,
            "internal_execution_status": internal_status,
            "external_execution_status": external_status,
            "current_surface": current_surface,
            "execution_tracks": {
                "G1": {
                    "label": "Interno autenticado",
                    "context": INTERNAL,
                    "status": internal_status,
                    "counts": internal["counts"],
                    "total": internal["total"],
                    "active": internal["active"],
                },
                "G0": {
                    "label": "Externo anônimo",
                    "context": EXTERNAL,
                    "status": external_status,
                    "counts": external["counts"],
                    "total": external["total"],
                    "active": external["active"],
                },
                "updated_at": now.isoformat(),
            },
        }
    )

    for context_type, status in ((INTERNAL, internal_status), (EXTERNAL, external_status)):
        row = get_context(db, int(job.id), context_type)
        if row is None:
            continue
        if str(row.status or "") != status:
            row.status = status
            row.updated_at = now
            if status == "completed" and row.finished_at is None:
                row.finished_at = now
            if status in {"running", "waiting_for_internal"}:
                row.finished_at = None
            db.add(row)

    job.state_data = state
    return state


def ensure_external_context(db: Session, scan: ScanJob) -> ScanExecutionContext:
    row = (
        db.query(ScanExecutionContext)
        .filter(
            ScanExecutionContext.scan_job_id == scan.id,
            ScanExecutionContext.context_type == EXTERNAL,
        )
        .first()
    )
    if row is None:
        row = ScanExecutionContext(
            scan_job_id=scan.id,
            context_type=EXTERNAL,
            status="running",
            session_revision=0,
            started_at=scan.created_at or datetime.now(),
            context_metadata={"generation": "G0"},
        )
        db.add(row)
        db.flush()
    return row


def activate_internal_context(
    db: Session,
    scan: ScanJob,
    session: ScanAuthSession,
    identity: ScanIdentity | None,
) -> ScanExecutionContext:
    if str(session.status or "").lower() not in {"valid", "static"}:
        raise ValueError("authenticated_session_not_valid")
    ensure_external_context(db, scan)
    row = (
        db.query(ScanExecutionContext)
        .filter(
            ScanExecutionContext.scan_job_id == scan.id,
            ScanExecutionContext.context_type == INTERNAL,
        )
        .first()
    )
    now = datetime.now()
    if row is None:
        row = ScanExecutionContext(
            scan_job_id=scan.id,
            context_type=INTERNAL,
            session_revision=1,
            created_at=now,
        )
    else:
        row.session_revision = int(row.session_revision or 0) + 1
    row.auth_session_id = session.id
    row.identity_key = str(identity.identity_key if identity else "") or None
    row.role = str(identity.role if identity else "") or None
    row.status = "running"
    row.blocking_reason = None
    row.started_at = row.started_at or now
    row.finished_at = None
    row.context_metadata = {
        **dict(row.context_metadata or {}),
        "generation": "G1",
        "activated_at": now.isoformat(),
        "session_revision": int(row.session_revision or 1),
        "validation_result": dict(session.validation_result or {}),
    }
    row.updated_at = now
    db.add(row)
    db.flush()
    db.add(ScanLog(
        scan_job_id=scan.id,
        source="execution-context",
        level="INFO",
        message=(
            f"internal_context_activated identity={row.identity_key or ''} "
            f"session_revision={row.session_revision}"
        ),
    ))
    return row


def get_context(db: Session, scan_id: int, context_type: str) -> ScanExecutionContext | None:
    return (
        db.query(ScanExecutionContext)
        .filter(
            ScanExecutionContext.scan_job_id == int(scan_id),
            ScanExecutionContext.context_type == normalize_execution_context(context_type),
        )
        .first()
    )


def context_from_item(item: Any) -> str:
    explicit = getattr(item, "execution_context", None)
    if explicit:
        return normalize_execution_context(explicit)
    metadata = dict(getattr(item, "item_metadata", None) or {})
    return normalize_execution_context(metadata.get("execution_context"))


def upsert_endpoint_observation(
    db: Session,
    scan: ScanJob,
    endpoint: OffensiveEndpoint,
    *,
    execution_context: str,
    source_tool: str,
    source_artifact_id: int | None = None,
    status_code: int | None = None,
    content_type: str = "",
    body_fingerprint: str = "",
    redirect_location: str = "",
    metadata: dict[str, Any] | None = None,
) -> EndpointObservation:
    context_type = normalize_execution_context(execution_context)
    context = get_context(db, scan.id, context_type)
    revision = int(context.session_revision or 0) if context else 0
    row = (
        db.query(EndpointObservation)
        .filter(
            EndpointObservation.endpoint_id == endpoint.id,
            EndpointObservation.execution_context == context_type,
            EndpointObservation.method == str(endpoint.method or "GET").upper(),
            EndpointObservation.source_tool == str(source_tool or "")[:120],
        )
        .first()
    )
    if row is None:
        row = EndpointObservation(
            scan_job_id=scan.id,
            endpoint_id=endpoint.id,
            execution_context=context_type,
            method=str(endpoint.method or "GET").upper(),
            source_tool=str(source_tool or "")[:120],
        )
    row.auth_session_revision = revision
    row.identity_key = context.identity_key if context else None
    row.role_observed = context.role if context else None
    row.status_code = status_code if status_code is not None else endpoint.status_code
    row.content_type = content_type or endpoint.content_type
    row.body_fingerprint = body_fingerprint or row.body_fingerprint
    row.redirect_location = redirect_location or row.redirect_location
    row.source_artifact_id = source_artifact_id or row.source_artifact_id
    row.observation_metadata = {**dict(row.observation_metadata or {}), **dict(metadata or {})}
    row.last_seen = datetime.now()
    db.add(row)
    db.flush()
    return row


def _fingerprint(rows: list[tuple[str, str, int | None, str | None]]) -> str:
    # Python cannot sort tuples that contain mixed ``None`` and ``int`` values
    # in the same position. Endpoint observations commonly have status_code=None
    # for static/crawler-only discoveries, so normalize every sortable component
    # before generating the deterministic inventory fingerprint.
    normalized = [
        tuple("" if value is None else str(value) for value in row)
        for row in rows
    ]
    payload = json.dumps(sorted(normalized), ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def context_inventory_fingerprint(db: Session, scan_id: int, context_type: str) -> str:
    rows = (
        db.query(
            OffensiveEndpoint.normalized_url,
            EndpointObservation.method,
            EndpointObservation.status_code,
            EndpointObservation.body_fingerprint,
        )
        .join(EndpointObservation, EndpointObservation.endpoint_id == OffensiveEndpoint.id)
        .filter(
            OffensiveEndpoint.scan_job_id == int(scan_id),
            EndpointObservation.execution_context == normalize_execution_context(context_type),
        )
        .all()
    )
    return _fingerprint([(str(a), str(b), c, d) for a, b, c, d in rows])


def compute_external_internal_diff(db: Session, scan: ScanJob) -> dict[str, Any]:
    observations = (
        db.query(OffensiveEndpoint, EndpointObservation)
        .join(EndpointObservation, EndpointObservation.endpoint_id == OffensiveEndpoint.id)
        .filter(OffensiveEndpoint.scan_job_id == scan.id)
        .all()
    )
    by_context: dict[str, dict[tuple[str, str], EndpointObservation]] = {EXTERNAL: {}, INTERNAL: {}}

    def _observation_score(observation: EndpointObservation) -> tuple[int, str]:
        has_response = int(observation.status_code is not None) + int(bool(observation.body_fingerprint))
        has_redirect = int(bool(observation.redirect_location))
        freshness = observation.last_seen.isoformat() if observation.last_seen else ""
        return (has_response * 2 + has_redirect, freshness)

    for endpoint, observation in observations:
        context = normalize_execution_context(observation.execution_context)
        key = (str(endpoint.normalized_url), str(observation.method or endpoint.method or "GET").upper())
        current = by_context[context].get(key)
        if current is None or _observation_score(observation) >= _observation_score(current):
            by_context[context][key] = observation
    external_keys = set(by_context[EXTERNAL])
    internal_keys = set(by_context[INTERNAL])
    shared = external_keys & internal_keys
    changed = []
    equal = []
    for key in sorted(shared):
        left = by_context[EXTERNAL][key]
        right = by_context[INTERNAL][key]
        left_sig = (left.status_code, left.content_type or "", left.body_fingerprint or "", left.redirect_location or "")
        right_sig = (right.status_code, right.content_type or "", right.body_fingerprint or "", right.redirect_location or "")
        (changed if left_sig != right_sig else equal).append(key)
    result = {
        "external_only": [{"url": u, "method": m} for u, m in sorted(external_keys - internal_keys)],
        "internal_only": [{"url": u, "method": m} for u, m in sorted(internal_keys - external_keys)],
        "shared_changed": [{"url": u, "method": m} for u, m in changed],
        "shared_equal": [{"url": u, "method": m} for u, m in equal],
        "computed_at": datetime.now().isoformat(),
    }
    state = dict(scan.state_data or {})
    state["execution_context_diff"] = result
    scan.state_data = state
    for context_type in (EXTERNAL, INTERNAL):
        context = get_context(db, scan.id, context_type)
        if context:
            context.inventory_fingerprint = context_inventory_fingerprint(db, scan.id, context_type)
            context.updated_at = datetime.now()
            db.add(context)
    db.add(ScanLog(
        scan_job_id=scan.id,
        source="execution-context",
        level="INFO",
        message=(
            f"external_internal_diff external_only={len(result['external_only'])} "
            f"internal_only={len(result['internal_only'])} changed={len(result['shared_changed'])}"
        ),
    ))
    db.flush()
    return result


def reopen_auth_blocked_hypotheses(db: Session, scan: ScanJob) -> int:
    rows = (
        db.query(OffensiveHypothesis)
        .filter(
            OffensiveHypothesis.scan_job_id == scan.id,
            OffensiveHypothesis.status == "blocked_missing_auth",
        )
        .all()
    )
    reopened = 0
    for row in rows:
        required = {str(value) for value in list(row.required_identities or []) if str(value)}
        if len(required) > 1:
            row.status = "blocked_missing_second_identity"
            continue
        row.status = "open"
        row.execution_context = INTERNAL
        metadata = dict(row.hypothesis_metadata or {})
        metadata["reopened_after_internal_auth"] = datetime.now().isoformat()
        row.hypothesis_metadata = metadata
        row.updated_at = datetime.now()
        db.add(row)
        reopened += 1
    db.flush()
    return reopened


def processor_should_run(
    db: Session,
    scan: ScanJob,
    *,
    execution_context: str,
    processor_name: str,
    processor_version: str = "v1",
) -> tuple[bool, ProcessorCheckpoint, str]:
    context_type = normalize_execution_context(execution_context)
    fingerprint = context_inventory_fingerprint(db, scan.id, context_type)
    row = (
        db.query(ProcessorCheckpoint)
        .filter(
            ProcessorCheckpoint.scan_job_id == scan.id,
            ProcessorCheckpoint.execution_context == context_type,
            ProcessorCheckpoint.processor_name == processor_name,
            ProcessorCheckpoint.processor_version == processor_version,
            ProcessorCheckpoint.input_fingerprint == fingerprint,
        )
        .first()
    )
    if row is not None:
        return row.status != "completed", row, fingerprint
    row = ProcessorCheckpoint(
        scan_job_id=scan.id,
        execution_context=context_type,
        processor_name=processor_name,
        processor_version=processor_version,
        input_fingerprint=fingerprint,
        status="pending",
    )
    db.add(row)
    db.flush()
    return True, row, fingerprint


def complete_processor_checkpoint(
    db: Session,
    checkpoint: ProcessorCheckpoint,
    result: dict[str, Any] | None = None,
) -> None:
    checkpoint.status = "completed"
    checkpoint.processed_at = datetime.now()
    checkpoint.updated_at = datetime.now()
    checkpoint.checkpoint_metadata = {**dict(checkpoint.checkpoint_metadata or {}), "result": dict(result or {})}
    db.add(checkpoint)
    db.flush()
