from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.models import FalsePositiveMemory, Finding, ScanAuthorization, ScanJob, ScanLog, User
from app.schemas.scan import LogResponse, ReportResponse, ScanCreate, ScanResponse, ScanStatusResponse
from app.services.audit_service import log_audit
from app.services.chroma_service import FalsePositiveVectorStore
from app.services.policy_service import is_target_allowed
from app.services.risk_service import build_priority_reason, compute_age_metrics, compute_fair_metrics
from app.workers.tasks import run_scan_job, run_scan_job_unit


router = APIRouter(prefix="/api", tags=["scans"])
vector_store = FalsePositiveVectorStore()


def _authorized_scan_query(db: Session, current_user: User):
    query = db.query(ScanJob)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    return query


def _authorized_finding_query(db: Session, current_user: User):
    query = db.query(Finding).join(ScanJob, ScanJob.id == Finding.scan_job_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    return query


def _sev_weight(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(severity or "low").lower(), 1)


def _infer_asset_type(name: str) -> str:
    value = str(name or "").strip().lower()
    if not value:
        return "asset"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    if "*" in value:
        return "wildcard"
    if value.replace(".", "").isdigit() and value.count(".") == 3:
        return "ip"
    if "." in value:
        return "domain"
    return "asset"


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
    query = _authorized_scan_query(db, current_user)
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


@router.get("/targets/summary")
def list_targets_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scans = _authorized_scan_query(db, current_user).order_by(ScanJob.created_at.desc()).all()
    findings = _authorized_finding_query(db, current_user).all()

    findings_by_scan: dict[int, list[Finding]] = {}
    for finding in findings:
        findings_by_scan.setdefault(finding.scan_job_id, []).append(finding)

    targets: dict[str, dict] = {}
    for scan in scans:
        key = str(scan.target_query)
        item = targets.get(key)
        if not item:
            item = {
                "target": key,
                "scans": 0,
                "last_status": scan.status,
                "last_mode": scan.mode,
                "last_scan_at": scan.created_at,
                "findings_total": 0,
                "findings_open": 0,
                "highest_severity": "low",
            }
            targets[key] = item

        item["scans"] += 1
        if scan.created_at and scan.created_at >= item["last_scan_at"]:
            item["last_status"] = scan.status
            item["last_mode"] = scan.mode
            item["last_scan_at"] = scan.created_at

        current_findings = findings_by_scan.get(scan.id, [])
        item["findings_total"] += len(current_findings)
        item["findings_open"] += len([f for f in current_findings if not f.is_false_positive])
        for finding in current_findings:
            sev = str(finding.severity or "low").lower()
            if _sev_weight(sev) > _sev_weight(item["highest_severity"]):
                item["highest_severity"] = sev

    rows = list(targets.values())
    rows.sort(key=lambda item: item["last_scan_at"] or datetime.min, reverse=True)
    return rows


@router.get("/assets")
def list_assets(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scans = _authorized_scan_query(db, current_user).order_by(ScanJob.created_at.desc()).all()
    findings = _authorized_finding_query(db, current_user).all()

    findings_by_scan: dict[int, list[Finding]] = {}
    for finding in findings:
        findings_by_scan.setdefault(finding.scan_job_id, []).append(finding)

    assets_map: dict[str, dict] = {}
    for scan in scans:
        state = scan.state_data or {}
        raw_assets: list[str] = []
        raw_assets.extend(state.get("lista_ativos", []) or [])
        raw_assets.extend(state.get("discovered_assets", []) or [])
        raw_assets.extend(state.get("hosts", []) or [])
        raw_assets.append(scan.target_query)

        # Remove vazios e mantem apenas ativos unicos por scan.
        unique_scan_assets = {str(asset).strip() for asset in raw_assets if str(asset).strip()}
        scan_risk = "low"
        for finding in findings_by_scan.get(scan.id, []):
            sev = str(finding.severity or "low").lower()
            if _sev_weight(sev) > _sev_weight(scan_risk):
                scan_risk = sev

        for asset in unique_scan_assets:
            item = assets_map.get(asset)
            if not item:
                item = {
                    "name": asset,
                    "type": _infer_asset_type(asset),
                    "source_target": scan.target_query,
                    "last_seen_at": scan.created_at,
                    "risk": scan_risk,
                    "seen_in_scans": 0,
                }
                assets_map[asset] = item

            item["seen_in_scans"] += 1
            if scan.created_at and scan.created_at >= item["last_seen_at"]:
                item["last_seen_at"] = scan.created_at
                item["source_target"] = scan.target_query
            if _sev_weight(scan_risk) > _sev_weight(item["risk"]):
                item["risk"] = scan_risk

    rows = list(assets_map.values())
    rows.sort(key=lambda item: item["last_seen_at"] or datetime.min, reverse=True)
    return rows[:500]


@router.get("/findings")
def list_findings(
    severity: str | None = None,
    status_filter: str = "all",
    target: str | None = None,
    limit: int = 500,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    max_limit = max(1, min(limit, 1000))
    query = _authorized_finding_query(db, current_user)

    if severity:
        query = query.filter(Finding.severity == severity.lower())
    if target:
        query = query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))

    normalized_status = status_filter.strip().lower()
    if normalized_status == "open":
        query = query.filter(Finding.is_false_positive.is_(False))
    elif normalized_status == "false_positive":
        query = query.filter(Finding.is_false_positive.is_(True))

    rows = query.order_by(Finding.created_at.desc()).limit(max_limit).all()
    response = []
    for finding in rows:
        details = finding.details or {}
        age = compute_age_metrics(finding.created_at, details)
        fair = compute_fair_metrics(finding.severity, finding.confidence_score, details, age)
        response.append(
            {
                "id": finding.id,
                "scan_job_id": finding.scan_job_id,
                "target_query": finding.scan_job.target_query if finding.scan_job else None,
                "scan_status": finding.scan_job.status if finding.scan_job else None,
                "title": finding.title,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "confidence_score": finding.confidence_score,
                "is_false_positive": finding.is_false_positive,
                "retest_status": finding.retest_status,
                "cve": finding.cve,
                "details": details,
                "age": age,
                "fair": fair,
                "created_at": finding.created_at,
            }
        )
    return response


@router.get("/findings/page")
def list_findings_paginated(
    severity: str | None = None,
    status_filter: str = "all",
    target: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=50000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = _authorized_finding_query(db, current_user)

    if severity:
        query = query.filter(Finding.severity == severity.lower())
    if target:
        query = query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))

    normalized_status = status_filter.strip().lower()
    if normalized_status == "open":
        query = query.filter(Finding.is_false_positive.is_(False))
    elif normalized_status == "false_positive":
        query = query.filter(Finding.is_false_positive.is_(True))

    total = query.count()
    rows = query.order_by(Finding.created_at.desc()).offset(offset).limit(limit).all()

    items = []
    for finding in rows:
        details = finding.details or {}
        age = compute_age_metrics(finding.created_at, details)
        fair = compute_fair_metrics(finding.severity, finding.confidence_score, details, age)
        items.append(
            {
                "id": finding.id,
                "scan_job_id": finding.scan_job_id,
                "target_query": finding.scan_job.target_query if finding.scan_job else None,
                "scan_status": finding.scan_job.status if finding.scan_job else None,
                "title": finding.title,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "confidence_score": finding.confidence_score,
                "is_false_positive": finding.is_false_positive,
                "retest_status": finding.retest_status,
                "cve": finding.cve,
                "details": details,
                "age": age,
                "fair": fair,
                "created_at": finding.created_at,
            }
        )

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/jobs/registry")
def jobs_registry(limit: int = 200, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    max_limit = max(1, min(limit, 1000))
    scans = _authorized_scan_query(db, current_user).order_by(ScanJob.created_at.desc()).limit(max_limit).all()
    findings = _authorized_finding_query(db, current_user).all()

    findings_count: dict[int, int] = {}
    for finding in findings:
        findings_count[finding.scan_job_id] = findings_count.get(finding.scan_job_id, 0) + 1

    rows = []
    for scan in scans:
        duration_seconds = None
        if scan.updated_at and scan.created_at:
            duration_seconds = int(max((scan.updated_at - scan.created_at).total_seconds(), 0))

        rows.append(
            {
                "id": scan.id,
                "target_query": scan.target_query,
                "mode": scan.mode,
                "status": scan.status,
                "compliance_status": scan.compliance_status,
                "current_step": scan.current_step,
                "mission_progress": scan.mission_progress,
                "retry_attempt": scan.retry_attempt,
                "retry_max": scan.retry_max,
                "last_error": scan.last_error,
                "findings_count": findings_count.get(scan.id, 0),
                "duration_seconds": duration_seconds,
                "created_at": scan.created_at,
                "updated_at": scan.updated_at,
            }
        )

    return rows


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
def scan_report(
    scan_id: int,
    prioritized_limit: int = Query(default=10, ge=1, le=100),
    prioritized_offset: int = Query(default=0, ge=0, le=10000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    job = query.first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    findings = db.query(Finding).filter(Finding.scan_job_id == scan_id).all()

    enriched_findings = []
    prioritized_actions = []
    for finding in findings:
        details = finding.details or {}
        age = compute_age_metrics(finding.created_at, details)
        fair = compute_fair_metrics(finding.severity, finding.confidence_score, details, age)
        reasons = build_priority_reason(finding.title, finding.severity, fair, age)

        enriched_findings.append(
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "sn1per_priority": finding.sn1per_priority,
                "cve": finding.cve,
                "risk_score": finding.risk_score,
                "confidence_score": finding.confidence_score,
                "is_false_positive": finding.is_false_positive,
                "fp_notes": finding.fp_notes,
                "fp_reviewed_by_id": finding.fp_reviewed_by_id,
                "fp_reviewed_at": finding.fp_reviewed_at,
                "retest_status": finding.retest_status,
                "details": details,
                "age": age,
                "fair": fair,
            }
        )

        if not finding.is_false_positive:
            prioritized_actions.append(
                {
                    "finding_id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "fair_score": fair["fair_score"],
                    "annualized_loss_exposure_usd": fair["annualized_loss_exposure_usd"],
                    "age": age,
                    "operational_reason": reasons["operational"],
                    "financial_reason": reasons["financial"],
                }
            )

    prioritized_actions.sort(key=lambda item: item.get("annualized_loss_exposure_usd", 0), reverse=True)

    paged_prioritized = prioritized_actions[prioritized_offset:prioritized_offset + prioritized_limit]

    return ReportResponse(
        scan_id=scan_id,
        status=job.status,
        findings=enriched_findings,
        state_data={
            **(job.state_data or {}),
            "prioritized_actions": paged_prioritized,
            "prioritized_actions_page": {
                "items": paged_prioritized,
                "total": len(prioritized_actions),
                "limit": prioritized_limit,
                "offset": prioritized_offset,
            },
        },
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


@router.get("/dashboard/insights")
def dashboard_insights(
    prioritized_limit: int = Query(default=10, ge=1, le=100),
    prioritized_offset: int = Query(default=0, ge=0, le=10000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.is_admin:
        jobs = db.query(ScanJob).order_by(ScanJob.created_at.desc()).all()
        findings = db.query(Finding).all()
    else:
        allowed_ids = [g.id for g in current_user.groups]
        jobs = (
            db.query(ScanJob)
            .filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
            .order_by(ScanJob.created_at.desc())
            .all()
        )
        findings = (
            db.query(Finding)
            .join(ScanJob, ScanJob.id == Finding.scan_job_id)
            .filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
            .all()
        )

    findings_by_scan: dict[int, list[Finding]] = {}
    for f in findings:
        findings_by_scan.setdefault(f.scan_job_id, []).append(f)

    total = len(findings)
    mitigated = len([f for f in findings if f.is_false_positive])
    open_issues = total - mitigated

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    fair_total = 0.0
    ale_total = 0.0
    age_env_samples: list[int] = []
    age_market_samples: list[int] = []
    age_exploit_samples: list[int] = []
    prioritized_actions: list[dict] = []
    vuln_counter: dict[tuple[str, str], int] = {}
    for f in findings:
        sev = str(f.severity or "low").lower()
        if sev in sev_count:
            sev_count[sev] += 1
        key = (str(f.title or "Finding"), sev)
        vuln_counter[key] = vuln_counter.get(key, 0) + 1

        details = f.details or {}
        age = compute_age_metrics(f.created_at, details)
        fair = compute_fair_metrics(f.severity, f.confidence_score, details, age)
        fair_total += float(fair.get("fair_score") or 0.0)
        ale_total += float(fair.get("annualized_loss_exposure_usd") or 0.0)

        if age.get("known_in_environment_days") is not None:
            age_env_samples.append(int(age["known_in_environment_days"]))
        if age.get("known_in_market_days") is not None:
            age_market_samples.append(int(age["known_in_market_days"]))
        if age.get("exploit_published_days") is not None:
            age_exploit_samples.append(int(age["exploit_published_days"]))

        if not f.is_false_positive:
            reasons = build_priority_reason(f.title, f.severity, fair, age)
            prioritized_actions.append(
                {
                    "finding_id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "target_query": f.scan_job.target_query if f.scan_job else None,
                    "fair_score": fair["fair_score"],
                    "annualized_loss_exposure_usd": fair["annualized_loss_exposure_usd"],
                    "age": age,
                    "operational_reason": reasons["operational"],
                    "financial_reason": reasons["financial"],
                }
            )

    def _sev_weight(sev: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev, 1)

    asset_risk: dict[str, str] = {}
    for job in jobs:
        target = str(job.target_query)
        current = asset_risk.get(target, "low")
        for f in findings_by_scan.get(job.id, []):
            sev = str(f.severity or "low").lower()
            if _sev_weight(sev) > _sev_weight(current):
                current = sev
        asset_risk[target] = current

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=6)
    day_labels = ["Dom", "Seg", "Ter", "Qua", "Qui", "Sex", "Sab"]
    activity_map: dict[int, dict[str, int]] = {i: {"scans": 0, "findings": 0} for i in range(7)}
    for job in jobs:
        created = job.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created < cutoff:
            continue
        weekday = int(created.strftime("%w"))
        activity_map[weekday]["scans"] += 1
        activity_map[weekday]["findings"] += len(findings_by_scan.get(job.id, []))

    recent_scans = [
        {
            "id": j.id,
            "target_query": j.target_query,
            "status": j.status,
            "mode": j.mode,
            "mission_progress": j.mission_progress,
            "created_at": j.created_at,
            "findings": len(findings_by_scan.get(j.id, [])),
        }
        for j in jobs[:8]
    ]

    top_vulns = [
        {"title": title, "severity": severity, "count": count}
        for (title, severity), count in sorted(vuln_counter.items(), key=lambda item: item[1], reverse=True)[:7]
    ]

    assets = [
        {
            "name": target,
            "type": "wildcard" if "*." in target else ("domain" if "." in target else "asset"),
            "risk": risk,
        }
        for target, risk in list(asset_risk.items())[:12]
    ]

    activity = [
        {
            "day": day_labels[idx],
            "scans": activity_map[idx]["scans"],
            "findings": activity_map[idx]["findings"],
        }
        for idx in range(7)
    ]

    prioritized_actions.sort(key=lambda item: item.get("annualized_loss_exposure_usd", 0), reverse=True)

    def _avg(values: list[int]) -> float:
        return round(sum(values) / len(values), 2) if values else 0.0

    avg_fair = round(fair_total / max(len(findings), 1), 2)

    paged_prioritized = prioritized_actions[prioritized_offset:prioritized_offset + prioritized_limit]

    return {
        "stats": {
            "scans": len(jobs),
            "findings_total": total,
            "findings_open": open_issues,
            "findings_triaged": mitigated,
            "critical": sev_count["critical"],
            "high": sev_count["high"],
            "medium": sev_count["medium"],
            "low": sev_count["low"],
            "fair_avg_score": avg_fair,
            "fair_ale_total_usd": round(ale_total, 2),
            "age_env_avg_days": _avg(age_env_samples),
            "age_market_avg_days": _avg(age_market_samples),
            "age_exploit_avg_days": _avg(age_exploit_samples),
        },
        "frameworks": {
            "iso27001": {"score": max(0, 100 - open_issues)},
            "nist": {"score": max(0, 100 - int(open_issues * 0.8))},
            "cis_v8": {"score": max(0, 100 - int(open_issues * 0.7))},
            "pci": {"score": max(0, 100 - int(open_issues * 0.9))},
        },
        "recent_scans": recent_scans,
        "top_vulns": top_vulns,
        "assets": assets,
        "activity": activity,
        "prioritized_actions": paged_prioritized,
        "prioritized_actions_page": {
            "items": paged_prioritized,
            "total": len(prioritized_actions),
            "limit": prioritized_limit,
            "offset": prioritized_offset,
        },
    }
