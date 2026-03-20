from datetime import datetime
import secrets

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.db.session import get_db
from app.models.models import AccessGroup, AppSetting, AuditEvent, OperationLine, ScanAuthorization, ScanJob, ScanLog, ScheduledScan, User
from app.services.audit_service import log_audit
from app.services.policy_service import ensure_default_policy
from app.models.models import ClientPolicy, PolicyAllowlistEntry
from app.workers.worker_groups import WORKER_GROUPS


router = APIRouter(prefix="/api", tags=["management"])


def _parse_targets(targets_text: str) -> list[str]:
    return [item.strip() for item in targets_text.split(";") if item.strip()]


@router.post("/compliance/authorizations/request")
def request_authorization(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    target_query = (payload.get("target_query") or "").strip()
    ownership_proof = (payload.get("ownership_proof") or "").strip()
    notes = (payload.get("notes") or "").strip()

    if not target_query or not ownership_proof:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="target_query e ownership_proof sao obrigatorios")

    auth = ScanAuthorization(
        requester_id=current_user.id,
        authorization_code=secrets.token_hex(8),
        target_query=target_query,
        ownership_proof=ownership_proof,
        notes=notes,
        status="requested",
    )
    db.add(auth)
    db.flush()
    log_audit(
        db,
        event_type="authorization.requested",
        message=f"Solicitada autorizacao para alvo {target_query}",
        actor_user_id=current_user.id,
        metadata={"authorization_id": auth.id, "target": target_query},
    )
    db.commit()
    return {"ok": True, "authorization_id": auth.id, "authorization_code": auth.authorization_code}


@router.get("/compliance/authorizations")
def list_authorizations(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(ScanAuthorization)
    if not current_user.is_admin:
        query = query.filter(ScanAuthorization.requester_id == current_user.id)
    rows = query.order_by(ScanAuthorization.created_at.desc()).all()
    return [
        {
            "id": row.id,
            "authorization_code": row.authorization_code,
            "target_query": row.target_query,
            "status": row.status,
            "requester_id": row.requester_id,
            "approved_by_id": row.approved_by_id,
            "approved_at": row.approved_at,
            "expires_at": row.expires_at,
            "notes": row.notes,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@router.put("/compliance/authorizations/{authorization_id}/approve")
def approve_authorization(authorization_id: int, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    row = db.query(ScanAuthorization).filter(ScanAuthorization.id == authorization_id).first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Autorizacao nao encontrada")

    expires_at_raw = payload.get("expires_at")
    expires_at = datetime.fromisoformat(expires_at_raw) if expires_at_raw else None
    row.status = "approved"
    row.approved_by_id = current_user.id
    row.approved_at = datetime.utcnow()
    row.expires_at = expires_at
    row.notes = (payload.get("notes") or row.notes or "").strip()

    log_audit(
        db,
        event_type="authorization.approved",
        message=f"Autorizacao {row.id} aprovada",
        actor_user_id=current_user.id,
        metadata={"authorization_id": row.id, "target": row.target_query},
    )
    db.commit()
    return {"ok": True}


@router.put("/compliance/authorizations/{authorization_id}/revoke")
def revoke_authorization(authorization_id: int, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    row = db.query(ScanAuthorization).filter(ScanAuthorization.id == authorization_id).first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Autorizacao nao encontrada")
    row.status = "revoked"
    row.notes = (payload.get("notes") or row.notes or "").strip()
    log_audit(
        db,
        event_type="authorization.revoked",
        message=f"Autorizacao {row.id} revogada",
        actor_user_id=current_user.id,
        level="WARNING",
        metadata={"authorization_id": row.id, "target": row.target_query},
    )
    db.commit()
    return {"ok": True}


@router.get("/audit/events")
def list_audit_events(limit: int = 100, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    rows = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(max(1, min(limit, 500))).all()
    return [
        {
            "id": row.id,
            "actor_user_id": row.actor_user_id,
            "scan_job_id": row.scan_job_id,
            "event_type": row.event_type,
            "level": row.level,
            "message": row.message,
            "metadata": row.event_metadata,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@router.get("/policy/allowlist")
def list_allowlist(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    policy = ensure_default_policy(db, current_user.id)
    entries = (
        db.query(PolicyAllowlistEntry)
        .filter(PolicyAllowlistEntry.policy_id == policy.id)
        .order_by(PolicyAllowlistEntry.id.asc())
        .all()
    )
    return {
        "policy": {"id": policy.id, "name": policy.name, "enabled": policy.enabled},
        "entries": [
            {
                "id": e.id,
                "target_pattern": e.target_pattern,
                "tool_group": e.tool_group,
                "is_active": e.is_active,
            }
            for e in entries
        ],
    }


@router.post("/policy/allowlist")
def create_allowlist_entry(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    target_pattern = (payload.get("target_pattern") or "").strip().lower()
    tool_group = (payload.get("tool_group") or "*").strip().lower()
    if not target_pattern:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="target_pattern obrigatorio")

    policy = ensure_default_policy(db, current_user.id)
    entry = PolicyAllowlistEntry(
        policy_id=policy.id,
        target_pattern=target_pattern,
        tool_group=tool_group,
        is_active=bool(payload.get("is_active", True)),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    log_audit(
        db,
        event_type="policy.allowlist_created",
        message=f"Allowlist adicionada: {target_pattern}",
        actor_user_id=current_user.id,
        metadata={"entry_id": entry.id, "tool_group": tool_group},
    )
    db.commit()
    return {"ok": True, "id": entry.id}


@router.put("/policy/allowlist/{entry_id}")
def update_allowlist_entry(entry_id: int, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    policy = ensure_default_policy(db, current_user.id)
    entry = (
        db.query(PolicyAllowlistEntry)
        .filter(PolicyAllowlistEntry.id == entry_id, PolicyAllowlistEntry.policy_id == policy.id)
        .first()
    )
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entrada nao encontrada")

    if "target_pattern" in payload:
        entry.target_pattern = (payload.get("target_pattern") or entry.target_pattern).strip().lower()
    if "tool_group" in payload:
        entry.tool_group = (payload.get("tool_group") or "*").strip().lower()
    if "is_active" in payload:
        entry.is_active = bool(payload.get("is_active"))
    db.commit()
    return {"ok": True}


@router.delete("/policy/allowlist/{entry_id}")
def delete_allowlist_entry(entry_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    policy = ensure_default_policy(db, current_user.id)
    entry = (
        db.query(PolicyAllowlistEntry)
        .filter(PolicyAllowlistEntry.id == entry_id, PolicyAllowlistEntry.policy_id == policy.id)
        .first()
    )
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entrada nao encontrada")
    db.delete(entry)
    db.commit()
    return {"ok": True}


@router.get("/dashboard/scans")
def dashboard_scans(
    target: str | None = Query(default=None),
    start_date: str | None = Query(default=None),
    end_date: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(ScanJob)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))

    if target:
        query = query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))

    if start_date:
        start_dt = datetime.fromisoformat(start_date + "T00:00:00")
        query = query.filter(ScanJob.created_at >= start_dt)

    if end_date:
        end_dt = datetime.fromisoformat(end_date + "T23:59:59")
        query = query.filter(ScanJob.created_at <= end_dt)

    scans = query.order_by(ScanJob.created_at.desc()).all()
    return [
        {
            "id": s.id,
            "target_query": s.target_query,
            "mode": s.mode,
            "status": s.status,
            "current_step": s.current_step,
            "mission_progress": s.mission_progress,
            "created_at": s.created_at,
        }
        for s in scans
    ]


@router.get("/schedules")
def list_schedules(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(ScheduledScan)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScheduledScan.owner_id == current_user.id) | (ScheduledScan.access_group_id.in_(allowed_ids)))
    rows = query.order_by(ScheduledScan.created_at.desc()).all()
    return [
        {
            "id": row.id,
            "access_group_id": row.access_group_id,
            "authorization_code": row.authorization_code,
            "targets_text": row.targets_text,
            "targets": _parse_targets(row.targets_text),
            "scan_type": row.scan_type,
            "frequency": row.frequency,
            "run_time": row.run_time,
            "day_of_week": row.day_of_week,
            "day_of_month": row.day_of_month,
            "enabled": row.enabled,
        }
        for row in rows
    ]


@router.post("/schedules")
def create_schedule(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    targets_text = (payload.get("targets_text") or "").strip()
    if not targets_text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="targets_text obrigatorio")

    frequency = (payload.get("frequency") or "daily").strip().lower()
    if frequency not in {"daily", "weekly", "monthly"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="frequency invalido")

    access_group_id = payload.get("access_group_id")
    if access_group_id in ["", 0]:
        access_group_id = None
    if access_group_id is not None:
        access_group_id = int(access_group_id)
        if not current_user.is_admin:
            allowed_ids = [g.id for g in current_user.groups]
            if access_group_id not in allowed_ids:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Grupo de acesso nao permitido")

    row = ScheduledScan(
        owner_id=current_user.id,
        access_group_id=access_group_id,
        authorization_code=(payload.get("authorization_code") or None),
        targets_text=targets_text,
        scan_type=(payload.get("scan_type") or "full").strip().lower(),
        frequency=frequency,
        run_time=(payload.get("run_time") or "00:00").strip(),
        day_of_week=(payload.get("day_of_week") or None),
        day_of_month=payload.get("day_of_month"),
        enabled=bool(payload.get("enabled", True)),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"ok": True, "id": row.id}


@router.put("/schedules/{schedule_id}")
def update_schedule(schedule_id: int, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    query = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScheduledScan.owner_id == current_user.id) | (ScheduledScan.access_group_id.in_(allowed_ids)))
    row = query.first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento nao encontrado")

    if "access_group_id" in payload:
        access_group_id = payload.get("access_group_id")
        if access_group_id in ["", 0]:
            access_group_id = None
        if access_group_id is not None:
            access_group_id = int(access_group_id)
            if not current_user.is_admin:
                allowed_ids = [g.id for g in current_user.groups]
                if access_group_id not in allowed_ids:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Grupo de acesso nao permitido")
        row.access_group_id = access_group_id

    for field in ["authorization_code", "targets_text", "scan_type", "frequency", "run_time", "day_of_week", "day_of_month", "enabled"]:
        if field in payload:
            setattr(row, field, payload[field])

    db.commit()
    return {"ok": True}


@router.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    query = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScheduledScan.owner_id == current_user.id) | (ScheduledScan.access_group_id.in_(allowed_ids)))
    row = query.first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento nao encontrado")

    db.delete(row)
    db.commit()
    return {"ok": True}


@router.get("/config/shodan")
def get_shodan_config(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    row = (
        db.query(AppSetting)
        .filter(AppSetting.owner_id == current_user.id, AppSetting.key == "shodan_api_key")
        .first()
    )
    if not row:
        return {"api_key": ""}
    return {"api_key": row.value}


@router.put("/config/shodan")
def save_shodan_config(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    api_key = (payload.get("api_key") or "").strip()
    row = (
        db.query(AppSetting)
        .filter(AppSetting.owner_id == current_user.id, AppSetting.key == "shodan_api_key")
        .first()
    )
    if row:
        row.value = api_key
    else:
        row = AppSetting(owner_id=current_user.id, key="shodan_api_key", value=api_key)
        db.add(row)

    db.commit()
    return {"ok": True}


def _get_setting(db: Session, owner_id: int, key: str, default: str = "") -> str:
    row = db.query(AppSetting).filter(AppSetting.owner_id == owner_id, AppSetting.key == key).first()
    if not row:
        return default
    return row.value


def _set_setting(db: Session, owner_id: int, key: str, value: str):
    row = db.query(AppSetting).filter(AppSetting.owner_id == owner_id, AppSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(AppSetting(owner_id=owner_id, key=key, value=value))


@router.get("/config/runtime")
def get_runtime_flags(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    debug_mode = _get_setting(db, current_user.id, "debug_mode", "false") == "true"
    verbose_mode = _get_setting(db, current_user.id, "verbose_mode", "false") == "true"
    return {"debug_mode": debug_mode, "verbose_mode": verbose_mode}


@router.put("/config/runtime")
def save_runtime_flags(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    debug_mode = bool(payload.get("debug_mode", False))
    verbose_mode = bool(payload.get("verbose_mode", False))
    _set_setting(db, current_user.id, "debug_mode", "true" if debug_mode else "false")
    _set_setting(db, current_user.id, "verbose_mode", "true" if verbose_mode else "false")
    db.commit()
    return {"ok": True}


@router.get("/config/ai-status")
def ai_status(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    health = "offline"
    models: list[str] = []
    error_message = ""

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(f"{settings.ollama_base_url}/api/tags")
            if resp.status_code == 200:
                payload = resp.json()
                models = [m.get("name", "") for m in payload.get("models", []) if m.get("name")]
                health = "online"
            else:
                error_message = f"Ollama retornou status {resp.status_code}"
    except Exception as exc:
        error_message = str(exc)

    error_logs = (
        db.query(ScanLog)
        .join(ScanJob, ScanJob.id == ScanLog.scan_job_id)
        .filter(ScanJob.owner_id == current_user.id, ScanLog.level == "ERROR")
        .order_by(ScanLog.created_at.desc())
        .limit(20)
        .all()
    )

    return {
        "ollama": {
            "health": health,
            "base_url": settings.ollama_base_url,
            "configured_model": settings.ollama_model,
            "available_models": models,
            "error": error_message,
        },
        "runtime": {
            "debug_mode": _get_setting(db, current_user.id, "debug_mode", "false") == "true",
            "verbose_mode": _get_setting(db, current_user.id, "verbose_mode", "false") == "true",
        },
        "recent_errors": [
            {
                "id": row.id,
                "source": row.source,
                "message": row.message,
                "created_at": row.created_at,
            }
            for row in error_logs
        ],
    }


@router.get("/worker-manager/lines")
def list_operation_lines(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    rows = (
        db.query(OperationLine)
        .filter(OperationLine.owner_id == current_user.id)
        .order_by(OperationLine.position.asc(), OperationLine.id.asc())
        .all()
    )
    return [
        {
            "id": row.id,
            "name": row.name,
            "category": row.category,
            "enabled": row.enabled,
            "position": row.position,
            "definition": row.definition,
        }
        for row in rows
    ]


@router.get("/worker-manager/groups")
def list_worker_groups_config(current_user: User = Depends(require_admin)):
    return WORKER_GROUPS


@router.get("/worker-manager/overview")
def worker_manager_overview(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    lines = (
        db.query(OperationLine)
        .filter(OperationLine.owner_id == current_user.id)
        .order_by(OperationLine.position.asc(), OperationLine.id.asc())
        .all()
    )
    scans = db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(100).all()

    durations_by_node: dict[str, list[float]] = {}
    transition_counter: dict[str, int] = {}
    lateral_assets: list[int] = []
    discovered_ports_sizes: list[int] = []

    for scan in scans:
        state = scan.state_data or {}
        metrics = state.get("activity_metrics", [])
        for m in metrics:
            node = str(m.get("node", "unknown"))
            duration = float(m.get("duration_ms", 0))
            durations_by_node.setdefault(node, []).append(duration)

        history = state.get("node_history", [])
        for idx in range(len(history) - 1):
            edge = f"{history[idx]}->{history[idx + 1]}"
            transition_counter[edge] = transition_counter.get(edge, 0) + 1

        assets = state.get("lista_ativos", [])
        lateral_assets.append(max(0, len(assets) - 1))
        discovered_ports_sizes.append(len(state.get("discovered_ports", [])))

    node_timing = {
        node: {
            "avg_ms": round(sum(values) / len(values), 2) if values else 0.0,
            "max_ms": round(max(values), 2) if values else 0.0,
            "samples": len(values),
        }
        for node, values in durations_by_node.items()
    }

    return {
        "worker_groups": WORKER_GROUPS,
        "priorities": [
            {
                "line_id": row.id,
                "name": row.name,
                "category": row.category,
                "priority": row.position,
                "enabled": row.enabled,
            }
            for row in lines
        ],
        "interaction_metrics": {
            "transition_counts": transition_counter,
            "node_timing": node_timing,
            "avg_lateral_growth_assets": round(sum(lateral_assets) / len(lateral_assets), 2) if lateral_assets else 0.0,
            "avg_discovered_ports": round(sum(discovered_ports_sizes) / len(discovered_ports_sizes), 2) if discovered_ports_sizes else 0.0,
            "scans_analyzed": len(scans),
        },
    }


@router.post("/worker-manager/lines")
def create_operation_line(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    row = OperationLine(
        owner_id=current_user.id,
        name=(payload.get("name") or "Nova linha").strip(),
        category=(payload.get("category") or "recon").strip(),
        enabled=bool(payload.get("enabled", True)),
        position=int(payload.get("position", 0)),
        definition=payload.get("definition") or {},
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"ok": True, "id": row.id}


@router.put("/worker-manager/lines/{line_id}")
def update_operation_line(line_id: int, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    row = (
        db.query(OperationLine)
        .filter(OperationLine.id == line_id, OperationLine.owner_id == current_user.id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linha nao encontrada")

    for field in ["name", "category", "enabled", "position", "definition"]:
        if field in payload:
            setattr(row, field, payload[field])

    db.commit()
    return {"ok": True}


@router.delete("/worker-manager/lines/{line_id}")
def delete_operation_line(line_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    row = (
        db.query(OperationLine)
        .filter(OperationLine.id == line_id, OperationLine.owner_id == current_user.id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linha nao encontrada")

    db.delete(row)
    db.commit()
    return {"ok": True}


@router.get("/access-groups")
def list_access_groups(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(AccessGroup)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter(AccessGroup.id.in_(allowed_ids))
    rows = query.order_by(AccessGroup.name.asc()).all()
    return [{"id": g.id, "name": g.name, "description": g.description} for g in rows]


@router.post("/access-groups")
def create_access_group(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nome do grupo obrigatorio")
    exists = db.query(AccessGroup).filter(AccessGroup.name == name).first()
    if exists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Grupo ja existe")
    row = AccessGroup(owner_id=current_user.id, name=name, description=(payload.get("description") or "").strip())
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"ok": True, "id": row.id}


@router.put("/access-groups/{group_id}")
def update_access_group(group_id: int, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    row = db.query(AccessGroup).filter(AccessGroup.id == group_id).first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grupo nao encontrado")
    if "name" in payload:
        row.name = (payload.get("name") or row.name).strip()
    if "description" in payload:
        row.description = (payload.get("description") or "").strip()
    db.commit()
    return {"ok": True}


@router.delete("/access-groups/{group_id}")
def delete_access_group(group_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    row = db.query(AccessGroup).filter(AccessGroup.id == group_id).first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grupo nao encontrado")
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.get("/users")
def list_users(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    rows = db.query(User).order_by(User.email.asc()).all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "is_admin": u.is_admin,
            "is_active": u.is_active,
            "group_ids": [g.id for g in u.groups],
        }
        for u in rows
    ]


@router.post("/users")
def create_user(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    email = (payload.get("email") or "").strip().lower()
    password = (payload.get("password") or "").strip()
    if not email or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="email e password obrigatorios")
    exists = db.query(User).filter(User.email == email).first()
    if exists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email ja cadastrado")

    user = User(email=email, password_hash=get_password_hash(password), is_admin=bool(payload.get("is_admin", False)))
    group_ids = payload.get("group_ids") or []
    if group_ids:
        groups = db.query(AccessGroup).filter(AccessGroup.id.in_(group_ids)).all()
        user.groups = groups

    db.add(user)
    db.commit()
    db.refresh(user)
    return {"ok": True, "id": user.id}


@router.put("/users/{user_id}")
def update_user(user_id: int, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario nao encontrado")

    if "is_admin" in payload:
        user.is_admin = bool(payload["is_admin"])
    if "is_active" in payload:
        user.is_active = bool(payload["is_active"])
    if "group_ids" in payload:
        group_ids = payload.get("group_ids") or []
        groups = db.query(AccessGroup).filter(AccessGroup.id.in_(group_ids)).all()
        user.groups = groups

    db.commit()
    return {"ok": True}


@router.put("/users/{user_id}/password")
def admin_change_user_password(user_id: int, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario nao encontrado")
    new_password = (payload.get("new_password") or "").strip()
    if not new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nova senha obrigatoria")
    user.password_hash = get_password_hash(new_password)
    db.commit()
    return {"ok": True}


@router.put("/users/me/password")
def change_own_password(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    current_password = (payload.get("current_password") or "").strip()
    new_password = (payload.get("new_password") or "").strip()
    if not verify_password(current_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Senha atual invalida")
    if not new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nova senha obrigatoria")

    current_user.password_hash = get_password_hash(new_password)
    db.commit()
    return {"ok": True}
