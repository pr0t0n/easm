from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.models import FalsePositiveMemory, Finding, ScanAuthorization, ScanJob, ScanLog, User
from app.schemas.scan import LogResponse, ReportResponse, ScanCreate, ScanResponse, ScanStatusResponse
from app.services.audit_service import log_audit
from app.services.chroma_service import FalsePositiveVectorStore
from app.services.policy_service import is_target_allowed
from app.workers.tasks import run_scan_job, run_scan_job_unit


router = APIRouter(prefix="/api", tags=["scans"])
vector_store = FalsePositiveVectorStore()


def _resolve_valid_authorization(db: Session, authorization_code: str | None) -> ScanAuthorization | None:
    if not authorization_code:
        return None
    now = datetime.now(timezone.utc)
    candidates = (
        db.query(ScanAuthorization)
        .filter(
            ScanAuthorization.authorization_code == authorization_code,
            ScanAuthorization.status == "approved",
        )
        .order_by(ScanAuthorization.created_at.desc())
        .all()
    )
    for auth in candidates:
        if auth.expires_at is None or auth.expires_at.replace(tzinfo=timezone.utc) > now:
            return auth
    return None


@router.post("/scans", response_model=ScanResponse)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    access_group_id = payload.access_group_id
    if access_group_id is not None and not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        if access_group_id not in allowed_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Grupo de acesso nao permitido")

    authorization = _resolve_valid_authorization(db, payload.authorization_code)
    allowlist_ok = is_target_allowed(db, current_user.id, payload.target_query, "*")

    if not authorization:
        compliance_status = "blocked_authorization"
    elif not allowlist_ok:
        compliance_status = "blocked_policy"
    else:
        compliance_status = "approved"

    job = ScanJob(
        owner_id=current_user.id,
        access_group_id=access_group_id,
        target_query=payload.target_query,
        authorization_code=payload.authorization_code,
        mode=payload.mode,
        status="queued" if compliance_status == "approved" else "blocked",
        compliance_status=compliance_status,
        authorization_id=authorization.id if authorization else None,
        current_step="1. Amass Subdomain Recon",
    )
    db.add(job)
    db.flush()
    log_audit(
        db,
        event_type="scan.created",
        message=f"Scan criado para alvo {payload.target_query}",
        actor_user_id=current_user.id,
        scan_job_id=job.id,
        metadata={"target": payload.target_query, "mode": payload.mode},
    )

    if compliance_status == "approved":
        log_audit(
            db,
            event_type="compliance.gate_pass",
            message="Gate de compliance aprovado para execucao",
            actor_user_id=current_user.id,
            scan_job_id=job.id,
            metadata={"authorization_id": authorization.id},
        )
    else:
        log_audit(
            db,
            event_type="compliance.gate_block",
            message="Scan bloqueado pelo gate de compliance/policy",
            actor_user_id=current_user.id,
            scan_job_id=job.id,
            level="WARNING",
            metadata={"target": payload.target_query, "reason": compliance_status},
        )

    db.commit()
    db.refresh(job)

    if compliance_status == "approved":
        try:
            run_scan_job_unit.delay(job.id)
        except Exception as exc:
            log_audit(
                db,
                event_type="scan.queue_fallback",
                message="Fila indisponivel, executando scan unitario de forma imediata",
                actor_user_id=current_user.id,
                scan_job_id=job.id,
                level="WARNING",
                metadata={"error": str(exc)},
            )
            db.commit()
            run_scan_job(job.id)

    return ScanResponse(
        id=job.id,
        target_query=job.target_query,
        authorization_code=job.authorization_code,
        mode=job.mode,
        access_group_id=job.access_group_id,
        status=job.status,
        compliance_status=job.compliance_status,
        current_step=job.current_step,
        mission_progress=job.mission_progress,
        retry_attempt=job.retry_attempt,
        retry_max=job.retry_max,
        next_retry_at=job.next_retry_at,
        last_error=job.last_error,
        created_at=job.created_at,
    )


@router.get("/scans", response_model=list[ScanResponse])
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(ScanJob)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter(
            (ScanJob.owner_id == current_user.id)
            | (ScanJob.access_group_id.in_(allowed_ids))
        )
    rows = query.order_by(ScanJob.created_at.desc()).all()
    return [
        ScanResponse(
            id=s.id,
            target_query=s.target_query,
            authorization_code=s.authorization_code,
            mode=s.mode,
            access_group_id=s.access_group_id,
            status=s.status,
            compliance_status=s.compliance_status,
            current_step=s.current_step,
            mission_progress=s.mission_progress,
            retry_attempt=s.retry_attempt,
            retry_max=s.retry_max,
            next_retry_at=s.next_retry_at,
            last_error=s.last_error,
            created_at=s.created_at,
        )
        for s in rows
    ]


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
def scan_status(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    job = query.first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    state_data = job.state_data or {}
    return ScanStatusResponse(
        id=job.id,
        status=job.status,
        compliance_status=job.compliance_status,
        current_step=job.current_step,
        mission_progress=job.mission_progress,
        discovered_ports=state_data.get("discovered_ports", []),
        pending_port_tests=state_data.get("pending_port_tests", []),
        retry_attempt=job.retry_attempt,
        retry_max=job.retry_max,
        next_retry_at=job.next_retry_at,
        last_error=job.last_error,
    )


@router.get("/scans/{scan_id}/logs", response_model=list[LogResponse])
def scan_logs(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    job = query.first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    logs = db.query(ScanLog).filter(ScanLog.scan_job_id == scan_id).order_by(ScanLog.created_at.asc()).all()
    return [
        LogResponse(
            id=l.id,
            source=l.source,
            level=l.level,
            message=l.message,
            created_at=l.created_at,
        )
        for l in logs
    ]


@router.get("/scans/{scan_id}/report", response_model=ReportResponse)
def scan_report(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    job = query.first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    findings = db.query(Finding).filter(Finding.scan_job_id == scan_id).all()
    return ReportResponse(
        scan_id=scan_id,
        status=job.status,
        findings=[
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "sn1per_priority": f.sn1per_priority,
                "cve": f.cve,
                "risk_score": f.risk_score,
                "confidence_score": f.confidence_score,
                "is_false_positive": f.is_false_positive,
                "fp_notes": f.fp_notes,
                "fp_reviewed_by_id": f.fp_reviewed_by_id,
                "fp_reviewed_at": f.fp_reviewed_at,
                "retest_status": f.retest_status,
                "details": f.details,
            }
            for f in findings
        ],
        state_data=job.state_data or {},
    )


@router.post("/findings/{finding_id}/false-positive")
def mark_false_positive(
    finding_id: int,
    payload: dict | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Marca ou desmarca um finding como falso positivo.

    Payload opcional:
      - is_false_positive (bool, default true)  — permite toggle (desmarcar FP)
      - fp_notes (str)                           — justificativa obrigatória na prática
    """
    query = db.query(Finding).join(ScanJob, ScanJob.id == Finding.scan_job_id).filter(Finding.id == finding_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    finding = query.first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding nao encontrado")

    body = payload or {}
    new_fp_value = bool(body.get("is_false_positive", True))
    fp_notes = (body.get("fp_notes") or "").strip() or None

    finding.is_false_positive = new_fp_value
    finding.fp_notes = fp_notes
    finding.fp_reviewed_by_id = current_user.id
    finding.fp_reviewed_at = datetime.now(timezone.utc)
    # Ao marcar como FP, limpa retest pendente (o finding foi validado pelo analista)
    if new_fp_value:
        finding.retest_status = None

    if new_fp_value:
        # Persiste na memória vetorial para prevenir reincidência
        signature = f"{finding.title}|{finding.severity}|{finding.details}"
        vector_id = f"fp-{finding.id}"
        vector_store.add_false_positive(vector_id, signature, {"finding_id": finding.id})
        fp_mem = FalsePositiveMemory(
            finding_id=finding.id,
            signature=signature,
            embedding_ref=vector_id,
            metadata={"severity": finding.severity, "fp_notes": fp_notes},
        )
        db.add(fp_mem)
    else:
        # Desmarcando FP: remove da memória vetorial se existir
        try:
            vector_store.remove_false_positive(f"fp-{finding.id}")
        except Exception:
            pass

    log_audit(
        db,
        event_type="finding.false_positive_updated",
        message=f"Finding #{finding.id} marcado como FP={new_fp_value} por {current_user.email}",
        actor_user_id=current_user.id,
        metadata={
            "finding_id": finding.id,
            "is_false_positive": new_fp_value,
            "fp_notes": fp_notes,
        },
    )
    db.commit()
    return {"ok": True, "is_false_positive": new_fp_value}


@router.post("/findings/{finding_id}/retest")
def request_retest(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Solicita retest de um finding (ex: após patch aplicado ou FP questionado).
    Define retest_status='pending_retest' e remove is_false_positive.
    O worker, ao encontrar este status, re-executa a verificação do finding.
    """
    query = db.query(Finding).join(ScanJob, ScanJob.id == Finding.scan_job_id).filter(Finding.id == finding_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    finding = query.first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding nao encontrado")

    finding.retest_status = "pending_retest"
    finding.is_false_positive = False
    finding.fp_notes = None
    finding.fp_reviewed_by_id = current_user.id
    finding.fp_reviewed_at = datetime.now(timezone.utc)

    log_audit(
        db,
        event_type="finding.retest_requested",
        message=f"Retest solicitado para finding #{finding.id} por {current_user.email}",
        actor_user_id=current_user.id,
        metadata={"finding_id": finding.id},
    )
    db.commit()
    return {"ok": True, "retest_status": "pending_retest"}


@router.post("/findings/bulk-false-positive")
def bulk_mark_false_positive(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Marca/desmarca múltiplos findings como falso positivo em uma única operação.

    Payload: { "finding_ids": [1,2,3], "is_false_positive": true, "fp_notes": "..." }
    """
    finding_ids: list[int] = payload.get("finding_ids") or []
    if not finding_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="finding_ids nao pode ser vazio")
    new_fp_value = bool(payload.get("is_false_positive", True))
    fp_notes = (payload.get("fp_notes") or "").strip() or None

    query = db.query(Finding).join(ScanJob, ScanJob.id == Finding.scan_job_id).filter(Finding.id.in_(finding_ids))
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    findings = query.all()

    updated_ids = []
    for finding in findings:
        finding.is_false_positive = new_fp_value
        finding.fp_notes = fp_notes
        finding.fp_reviewed_by_id = current_user.id
        finding.fp_reviewed_at = datetime.now(timezone.utc)
        if new_fp_value:
            finding.retest_status = None
            signature = f"{finding.title}|{finding.severity}|{finding.details}"
            vector_id = f"fp-{finding.id}"
            vector_store.add_false_positive(vector_id, signature, {"finding_id": finding.id})
            db.add(FalsePositiveMemory(
                finding_id=finding.id,
                signature=signature,
                embedding_ref=vector_id,
                metadata={"severity": finding.severity, "fp_notes": fp_notes},
            ))
        updated_ids.append(finding.id)

    log_audit(
        db,
        event_type="finding.bulk_false_positive",
        message=f"{len(updated_ids)} findings marcados como FP={new_fp_value} por {current_user.email}",
        actor_user_id=current_user.id,
        metadata={"finding_ids": updated_ids, "is_false_positive": new_fp_value, "fp_notes": fp_notes},
    )
    db.commit()
    return {"ok": True, "updated": len(updated_ids), "ids": updated_ids}


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.is_admin:
        jobs = db.query(ScanJob).all()
        findings = db.query(Finding).all()
    else:
        allowed_ids = [g.id for g in current_user.groups]
        jobs = db.query(ScanJob).filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids))).all()
        findings = (
            db.query(Finding)
            .join(ScanJob, ScanJob.id == Finding.scan_job_id)
            .filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
            .all()
        )

    total = len(findings)
    mitigated = len([f for f in findings if f.is_false_positive])
    open_issues = total - mitigated

    return {
        "stats": {
            "scans": len(jobs),
            "findings_total": total,
            "findings_open": open_issues,
            "findings_triaged": mitigated,
        },
        "frameworks": {
            "iso27001": {"score": max(0, 100 - open_issues)},
            "nist": {"score": max(0, 100 - int(open_issues * 0.8))},
            "cis_v8": {"score": max(0, 100 - int(open_issues * 0.7))},
            "pci": {"score": max(0, 100 - int(open_issues * 0.9))},
        },
    }
