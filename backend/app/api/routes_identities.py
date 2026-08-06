"""First dedicated CRUD-ish surface for ScanIdentity/ScanAuthSession.

Until this file, the only route-level touch on these tables was bulk-delete
as part of scan reset (routes_scans.py) — everything else is a read-only
downstream consumer (business_logic_probe.py, worker_dispatcher.py, etc.)
that picks up a newly captured identity automatically once persisted here.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import apply_company_scope, get_db, require_admin
from app.models.models import ScanAuthSession, ScanIdentity, ScanJob, User
from app.services import credential_capture_service

router = APIRouter(prefix="/api", tags=["identities"])


def _scan_or_404(db: Session, scan_id: int, current_user: User) -> ScanJob:
    query = apply_company_scope(db.query(ScanJob).filter(ScanJob.id == scan_id), current_user, ScanJob)
    scan = query.first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")
    return scan


def _retrigger_authenticated_zap(db: Session, scan: ScanJob) -> int:
    """Re-run ZAP (baseline + AJAX spider + active scan, all authenticated) for
    every in-scope host once a session is confirmed — mirrors what
    requeue_authenticated_crawl_items does for katana/gospider/etc, but ZAP is
    never a ScanWorkItem row (it's dispatched ad-hoc via
    _schedule_scan_postprocessor), so there's no queued row to flip back —
    this clears the postprocessor ledger entry directly and reschedules.
    Best-effort: never raises, confirm_capture already succeeded and committed.
    """
    from app.models.models import ScanWorkItem
    from app.services.scan_scope import authorized_scope_for_scan, host_from_scope_reference
    from app.workers.tasks import _schedule_scan_postprocessor

    try:
        authorized_scope = authorized_scope_for_scan(db, scan.id)
        if not authorized_scope:
            return 0

        # _schedule_scan_postprocessor requires an existing ScanWorkItem row
        # (only used for its id — the "zap" branch uses the target string
        # passed explicitly, not item.target) — any row for this scan works.
        anchor_item = db.query(ScanWorkItem.id).filter(ScanWorkItem.scan_job_id == scan.id).first()
        if not anchor_item:
            return 0
        anchor_item_id = anchor_item[0]

        state = dict(scan.state_data or {})
        ledger = dict(state.get("postprocessor_ledger") or {})
        # Clear any existing "zap:<target>" ledger entry whose host is in scope,
        # regardless of exact target-string format (bare host vs full URL) —
        # the original entry's key may not match a freshly-built string exactly.
        cleared = 0
        for key in list(ledger.keys()):
            if not key.startswith("zap:"):
                continue
            host = host_from_scope_reference(key.split(":", 1)[1])
            if host and host in authorized_scope:
                ledger.pop(key, None)
                cleared += 1
        if cleared:
            state["postprocessor_ledger"] = ledger
            scan.state_data = state
            db.commit()

        rescheduled = 0
        for host in authorized_scope:
            target = f"https://{host}"
            try:
                if _schedule_scan_postprocessor(
                    scan.id, anchor_item_id, "zap", target,
                    queue="worker.unit.exploitation", db=db,
                ):
                    rescheduled += 1
            except Exception:
                continue
        return rescheduled
    except Exception:
        return 0


class CaptureStartPayload(BaseModel):
    identity_key: str
    role: str = ""
    username_ref: str = ""


@router.post("/scans/{scan_id}/identities/capture/start")
async def start_identity_capture(
    scan_id: int,
    payload: CaptureStartPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    scan = _scan_or_404(db, scan_id, current_user)
    try:
        capture = await credential_capture_service.start_capture(
            db, scan, payload.identity_key, payload.role, payload.username_ref
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"falha ao iniciar captura: {exc}")
    return {
        "capture_session_id": capture.capture_session_id,
        "ws_url_path": f"/ws/scans/{scan_id}/identities/capture/{capture.capture_session_id}",
        "status": capture.status,
    }


@router.get("/scans/{scan_id}/identities/capture/{capture_session_id}/status")
def get_identity_capture_status(
    scan_id: int,
    capture_session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _scan_or_404(db, scan_id, current_user)
    status_payload = credential_capture_service.get_capture_status(capture_session_id, scan_id)
    if status_payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sessao de captura nao encontrada")
    return status_payload


@router.post("/scans/{scan_id}/identities/capture/{capture_session_id}/confirm")
async def confirm_identity_capture(
    scan_id: int,
    capture_session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    scan = _scan_or_404(db, scan_id, current_user)
    try:
        result = await credential_capture_service.confirm_capture(db, scan, capture_session_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sessao de captura nao encontrada")

    from app.services.hypothesis_rules import generate_hypotheses_for_scan
    from app.services.scan_work_queue import (
        requeue_authenticated_crawl_items,
        requeue_evidence_ready_work_items,
    )

    try:
        generate_hypotheses_for_scan(db, scan)
        evidence_requeued = requeue_evidence_ready_work_items(db, scan)
        crawl_requeued = requeue_authenticated_crawl_items(db, scan, result.get("identity_key") or "")
        _retrigger_authenticated_zap(db, scan)
        skill_probes_seeded = 0
        try:
            from app.services.scan_scope import authorized_scope_for_scan
            from app.services.skill_execution_engine import seed_skill_probe_items

            for host in authorized_scope_for_scan(db, scan.id):
                for phase in ("P13", "P16", "P19"):
                    skill_probes_seeded += seed_skill_probe_items(db, scan, phase, f"https://{host}")
        except Exception:
            pass
        # dispatch_scan_work_items no-ops for a terminal scan (TERMINAL_SCAN_STATUSES
        # includes completed_with_gaps) — requeued items would sit in "queued"
        # forever without this. Only flip it back when there is requeued work,
        # so a capture against an otherwise-idle scan doesn't reopen it for nothing.
        if (evidence_requeued or crawl_requeued or skill_probes_seeded) and str(scan.status or "").lower() in {"completed", "completed_with_gaps"}:
            scan.status = "running"
        db.commit()
        from app.workers.tasks import dispatch_scan_work_items

        dispatch_scan_work_items.delay(scan.id)
    except Exception:
        pass  # re-integration is best-effort — the capture itself already succeeded and committed

    return result


@router.post("/scans/{scan_id}/identities/capture/{capture_session_id}/cancel")
async def cancel_identity_capture(
    scan_id: int,
    capture_session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _scan_or_404(db, scan_id, current_user)
    cancelled = await credential_capture_service.cancel_capture(capture_session_id, scan_id)
    if not cancelled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sessao de captura nao encontrada")
    return {"status": "cancelled"}


@router.get("/scans/{scan_id}/identities")
def list_scan_identities(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _scan_or_404(db, scan_id, current_user)
    identities = db.query(ScanIdentity).filter(ScanIdentity.scan_job_id == scan_id).order_by(ScanIdentity.id.asc()).all()
    items = []
    for identity in identities:
        session = (
            db.query(ScanAuthSession)
            .filter(ScanAuthSession.scan_identity_id == identity.id, ScanAuthSession.session_key == "default")
            .first()
        )
        items.append(
            {
                "id": identity.id,
                "identity_key": identity.identity_key,
                "role": identity.role,
                "auth_type": identity.auth_type,
                "status": identity.status,
                "session_valid": identity.session_valid,
                "last_error": identity.last_error,
                "last_validated_at": session.last_validated_at.isoformat() if session and session.last_validated_at else None,
            }
        )
    return {"items": items}
