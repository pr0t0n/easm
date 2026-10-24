"""API Security module — standalone OWASP API Top 10 testing.

A first-class module alongside SCAN and BAS. It takes a base URL plus an API
spec (OpenAPI/Swagger, Postman collection, HAR or GraphQL) and runs ONLY the
API security phase (P16): the OWASP API Top 10 skills (BOLA, BFLA, broken
authentication, injection, mass assignment, SSRF, etc.) plus parameter fuzzing
and spec-driven DAST.

Implementation note: this reuses the existing scan engine instead of
duplicating it. An API test is a ScanJob with mode="api" and scan_level="api"
(a profile restricted to phase P16 — see scan_profiles.API_PHASES). Spec
ingestion, endpoint inventory, the api-skill-top20 runner, finding persistence
and the report endpoints are all shared with SCAN; nothing in SCAN is changed.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.models import ScanJob, User
from app.schemas.scan import ScanCreate, ScanResponse

# Reuse the SCAN implementation wholesale — do not reimplement creation,
# listing, lifecycle or reporting.
from app.api.routes_scans import (
    _TERMINAL_SCAN_STATUSES,
    _authorized_scan_query,
    _effective_mission_progress,
    _open_finding_counts_by_scan,
    create_scan,
    finalize_scan,
    scan_report,
    stop_scan,
)

router = APIRouter(prefix="/api/apitest", tags=["api-test"])


class ApiTestCreate(BaseModel):
    # Base URL / host of the API under test (authorized scope root).
    target_url: str
    # Spec source: a URL to fetch, OR an inline spec body (Swagger/OpenAPI/
    # Postman collection / HAR / GraphQL introspection), OR both.
    spec_url: str | None = None
    spec_payload: dict[str, Any] | None = None
    spec_type: str = "openapi"  # openapi | swagger | postman | har | graphql
    # Safe by default: no mutating (POST/PUT/DELETE) active DAST unless the
    # operator explicitly authorizes it for this target.
    allow_mutations: bool = False
    active_level: str = "safe"
    # Optional authenticated testing (bearer/headers/cookies/userlist).
    auth_config: dict[str, Any] | None = None
    access_group_id: int | None = None
    access_group_name: str | None = None
    authorization_code: str | None = None
    scope_authorization_attested: bool = False


def _api_scan_payload(payload: ApiTestCreate) -> ScanCreate:
    if not (payload.spec_url or payload.spec_payload):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Informe spec_url ou spec_payload (Swagger/OpenAPI/Postman/HAR).",
        )
    api_scan_config = {
        "enabled": True,
        "spec_url": payload.spec_url or "",
        "spec_payload": payload.spec_payload,
        "spec_type": payload.spec_type,
        "allow_mutations": bool(payload.allow_mutations),
        "active_level": payload.active_level,
    }
    return ScanCreate(
        target_query=payload.target_url,
        mode="api",
        scan_level="api",
        execution_plan="external_only",
        access_group_id=payload.access_group_id,
        access_group_name=payload.access_group_name,
        authorization_code=payload.authorization_code,
        scope_authorization_attested=payload.scope_authorization_attested,
        auth_config=payload.auth_config,
        api_scan_config=api_scan_config,
    )


def _scan_to_response(db: Session, s: ScanJob) -> ScanResponse:
    sev = _open_finding_counts_by_scan(db, [s.id]).get(s.id, {})
    terminal = str(s.status or "").lower() in _TERMINAL_SCAN_STATUSES
    state = dict(s.state_data or {})
    card_state: dict[str, Any] = {}
    for key in ("api_scan_config", "api_scan_observability", "broken_glass"):
        if key in state:
            card_state[key] = state.get(key)
    return ScanResponse(
        id=s.id,
        target_query=s.target_query,
        mode=s.mode,
        access_group_id=s.access_group_id,
        status=s.status,
        compliance_status=s.compliance_status,
        current_step=s.current_step,
        mission_progress=_effective_mission_progress(s),
        retry_attempt=s.retry_attempt,
        retry_max=s.retry_max,
        next_retry_at=s.next_retry_at,
        last_error=s.last_error,
        created_at=s.created_at,
        updated_at=s.updated_at,
        started_at=s.created_at,
        finished_at=s.updated_at if terminal else None,
        open_critical=int(sev.get("critical", 0)),
        open_high=int(sev.get("high", 0)),
        open_medium=int(sev.get("medium", 0)),
        open_low=int(sev.get("low", 0)),
        open_info=int(sev.get("info", 0)),
        state_data=card_state,
    )


@router.post("", response_model=ScanResponse)
@router.post("/", response_model=ScanResponse)
def create_api_test(
    payload: ApiTestCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> ScanResponse:
    """Create and dispatch an API security test from a spec. Reuses create_scan
    (auth gate, spec ingestion, P16 OWASP API Top 10 seeding/dispatch)."""
    return create_scan(_api_scan_payload(payload), db=db, current_user=current_user)


@router.get("", response_model=list[ScanResponse])
@router.get("/", response_model=list[ScanResponse])
def list_api_tests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ScanResponse]:
    rows = (
        _authorized_scan_query(db, current_user)
        .filter(ScanJob.mode == "api")
        .order_by(ScanJob.created_at.desc())
        .all()
    )
    return [_scan_to_response(db, s) for s in rows]


def _get_api_job(db: Session, current_user: User, test_id: int) -> ScanJob:
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == test_id).first()
    if not job or str(job.mode or "") != "api":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Teste de API nao encontrado")
    return job


@router.get("/{test_id}", response_model=ScanResponse)
def get_api_test(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanResponse:
    return _scan_to_response(db, _get_api_job(db, current_user, test_id))


@router.post("/{test_id}/stop")
def stop_api_test(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _get_api_job(db, current_user, test_id)
    return stop_scan(test_id, db=db, current_user=current_user)


@router.post("/{test_id}/finalize")
def finalize_api_test(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _get_api_job(db, current_user, test_id)
    return finalize_scan(test_id, db=db, current_user=current_user)


@router.get("/{test_id}/report")
def api_test_report(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _get_api_job(db, current_user, test_id)
    # Pass explicit values: scan_report's pagination params use FastAPI Query()
    # defaults that only resolve under request DI, not on a direct call.
    return scan_report(
        test_id,
        prioritized_limit=10,
        prioritized_offset=0,
        findings_limit=300,
        findings_offset=0,
        include_targets=None,
        db=db,
        current_user=current_user,
    )
