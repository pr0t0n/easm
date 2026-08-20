"""BAS (Breach & Attack Simulation) module API.

Phase 1: real platform (enrollment, agents, schedules, guardrail, dispatch)
against a stub tunnel (bas_agent_stub) -- the real Kali tool traffic is real,
the tunnel's response content is simulated. See the BAS plan doc for the
full architecture and the Phase 1 vs future-agent boundary.
"""
from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import (
    apply_company_scope,
    get_current_bas_agent,
    get_current_user,
    get_db,
    require_admin,
    resolve_company_group_id,
)
from app.core.config import settings
from app.core.security import create_bas_agent_token, get_password_hash, verify_password
from app.models.models import (
    AppSetting,
    BasAgent,
    BasEnrollmentToken,
    BasJob,
    BasSchedule,
    Finding,
    ScanJob,
    User,
)
from app.services.bas_dispatcher import dispatch_bas_technique
from app.services.bas_guardrail_policy import check_bas_authorization
from app.services.bas_technique_catalog import get_technique, list_techniques

router = APIRouter(prefix="/api/bas", tags=["bas"])


# ── Enrollment tokens ────────────────────────────────────────────────────────

class EnrollmentTokenCreate(BaseModel):
    access_group_id: int | None = None
    access_group_name: str | None = None
    username: str = "bas-agent"
    expires_in_hours: int | None = 24
    max_uses: int = 1


@router.post("/enrollment-tokens")
def create_enrollment_token(
    payload: EnrollmentTokenCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    access_group_id = resolve_company_group_id(
        db, current_user, payload.access_group_id, payload.access_group_name, required=False,
    )
    code = secrets.token_urlsafe(24)
    password = secrets.token_urlsafe(18)
    expires_at = (
        datetime.now() + timedelta(hours=payload.expires_in_hours)
        if payload.expires_in_hours else None
    )
    token = BasEnrollmentToken(
        owner_id=current_user.id,
        access_group_id=access_group_id,
        issued_by_id=current_user.id,
        username=payload.username,
        code=code,
        secret_hash=get_password_hash(password),
        max_uses=max(1, int(payload.max_uses)),
        expires_at=expires_at,
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return {
        "id": token.id,
        "username": token.username,
        "code": token.code,
        "password": password,  # shown once, never stored/retrievable again
        "expires_at": token.expires_at,
        "warning": "A senha e o código só são exibidos agora — copie antes de sair desta tela.",
    }


@router.get("/enrollment-tokens")
def list_enrollment_tokens(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    tokens = apply_company_scope(db.query(BasEnrollmentToken), current_user, BasEnrollmentToken).order_by(
        BasEnrollmentToken.created_at.desc()
    ).all()
    return [
        {
            "id": t.id, "username": t.username, "code": t.code, "status": t.status,
            "max_uses": t.max_uses, "used_count": t.used_count,
            "expires_at": t.expires_at, "last_used_at": t.last_used_at, "created_at": t.created_at,
        }
        for t in tokens
    ]


@router.delete("/enrollment-tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_enrollment_token(token_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    token = apply_company_scope(db.query(BasEnrollmentToken), current_user, BasEnrollmentToken).filter(
        BasEnrollmentToken.id == token_id
    ).first()
    if not token:
        raise HTTPException(status_code=404, detail="Token não encontrado")
    token.status = "revoked"
    db.commit()


# ── Agent enrollment / heartbeat (agent-authenticated, not user JWT) ────────

class AgentEnrollRequest(BaseModel):
    code: str
    username: str
    password: str
    hostname: str = ""
    os: str = ""
    os_version: str = ""
    arch: str = ""
    agent_version: str = ""
    tunnel_host: str = ""
    tunnel_port: int | None = None
    reported_host: str = ""
    reported_port: int | None = None
    # Optional: a PEM-encoded PKCS#10 CSR generated locally by the agent (its
    # private key never leaves the agent). When present, enroll additionally
    # signs it with the BAS root CA and returns a client certificate the
    # agent must present on every subsequent mTLS call (heartbeat, etc.) --
    # see bas_ca.py. Agents that don't send one (e.g. bas_agent_stub, which
    # only exercises the plain-HTTP enroll/heartbeat flow as a smoke-test
    # tunnel) simply don't get mTLS-protected heartbeat access.
    csr_pem: str = ""


@router.post("/agents/enroll")
def enroll_agent(payload: AgentEnrollRequest, db: Session = Depends(get_db)):
    token = db.query(BasEnrollmentToken).filter(BasEnrollmentToken.code == payload.code).first()
    if not token:
        raise HTTPException(status_code=401, detail="Token de enrollment inválido")
    if token.status != "active":
        raise HTTPException(status_code=401, detail=f"Token de enrollment {token.status}")
    if token.expires_at and token.expires_at < datetime.now():
        token.status = "expired"
        db.commit()
        raise HTTPException(status_code=401, detail="Token de enrollment expirado")
    if token.used_count >= token.max_uses:
        token.status = "exhausted"
        db.commit()
        raise HTTPException(status_code=401, detail="Token de enrollment já utilizado o número máximo de vezes")
    if token.username != payload.username or not verify_password(payload.password, token.secret_hash):
        raise HTTPException(status_code=401, detail="Credenciais de enrollment inválidas")

    agent = BasAgent(
        owner_id=token.owner_id,
        access_group_id=token.access_group_id,
        enrollment_token_id=token.id,
        hostname=payload.hostname,
        os=payload.os,
        os_version=payload.os_version,
        arch=payload.arch,
        agent_version=payload.agent_version,
        status="online",
        tunnel_host=payload.tunnel_host,
        tunnel_port=payload.tunnel_port,
        last_heartbeat_at=datetime.now(),
        enrolled_via_host=payload.reported_host,
        enrolled_via_port=payload.reported_port,
    )
    db.add(agent)
    token.used_count += 1
    token.last_used_at = datetime.now()
    if token.used_count >= token.max_uses:
        token.status = "exhausted"
    db.commit()
    db.refresh(agent)

    agent_jwt = create_bas_agent_token(agent.id)
    response: dict[str, Any] = {"agent_id": agent.id, "agent_jwt": agent_jwt}

    if payload.csr_pem.strip():
        from app.services import bas_ca
        try:
            client_cert_pem = bas_ca.sign_agent_csr(payload.csr_pem, agent_id=agent.id)
        except ValueError:
            raise HTTPException(status_code=400, detail="CSR inválido")
        response["client_cert_pem"] = client_cert_pem
        response["ca_cert_pem"] = bas_ca.ca_cert_pem()
        response["mtls_port"] = settings.bas_mtls_external_port
        response["relay_port"] = settings.bas_relay_external_port
        # Stamped server-side, from cryptographic proof (a CA-signed cert
        # this agent actually obtained) -- never a client-declared flag.
        # This is what "simulated" vs real downstream (Finding.details,
        # bas_exclusion.py) keys off.
        agent.kind = "real"
        db.commit()

    return response


@router.post("/agents/heartbeat")
def agent_heartbeat(db: Session = Depends(get_db), agent: BasAgent = Depends(get_current_bas_agent)):
    agent.last_heartbeat_at = datetime.now()
    agent.status = "online"
    db.commit()
    return {"status": "ok", "server_time": datetime.now()}


# ── Agents (user-facing) ────────────────────────────────────────────────────

@router.get("/agents")
def list_agents(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    agents = apply_company_scope(db.query(BasAgent), current_user, BasAgent).order_by(BasAgent.created_at.desc()).all()
    return [
        {
            "id": a.id, "label": a.label, "hostname": a.hostname, "os": a.os,
            "os_version": a.os_version, "status": a.status, "kind": a.kind,
            "last_heartbeat_at": a.last_heartbeat_at, "last_seen_ip": a.last_seen_ip,
            "created_at": a.created_at,
        }
        for a in agents
    ]


class AgentPatch(BaseModel):
    label: str | None = None
    status: str | None = None


@router.patch("/agents/{agent_id}")
def patch_agent(agent_id: int, payload: AgentPatch, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    agent = apply_company_scope(db.query(BasAgent), current_user, BasAgent).filter(BasAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agente não encontrado")
    if payload.label is not None:
        agent.label = payload.label
    if payload.status is not None:
        agent.status = payload.status
    db.commit()
    db.refresh(agent)
    return {"id": agent.id, "label": agent.label, "status": agent.status}


@router.get("/agents/{agent_id}/revocation-status")
def agent_revocation_status(agent_id: int, db: Session = Depends(get_db)):
    """Called by bas-relay (never by a user/browser) to enforce revocation
    on the reverse-tunnel path -- the mTLS handshake alone only proves the
    agent holds a CA-signed cert, it says nothing about whether that agent
    has since been revoked. No auth here: this is internal docker-network
    traffic (relay -> backend), and the only thing it reveals is a single
    agent id's revoked bool, which is not sensitive. Deliberately does NOT
    404 on an unknown agent_id -- bas-relay should treat "unknown" the same
    as "revoked" (fail closed), so this returns revoked=True either way."""
    agent = db.query(BasAgent).filter(BasAgent.id == agent_id).first()
    revoked = agent is None or str(agent.status or "") == "revoked"
    return {"agent_id": agent_id, "revoked": revoked}


# ── Technique catalog ────────────────────────────────────────────────────────

@router.get("/techniques")
def techniques(current_user: User = Depends(get_current_user)):
    return list_techniques()


@router.get("/chains")
def chains(current_user: User = Depends(get_current_user)):
    from app.services.bas_chain_catalog import list_chains
    return list_chains()


# ── Schedules ("cardápio") ───────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    access_group_id: int | None = None
    access_group_name: str | None = None
    name: str = ""
    agent_id: int
    target_hint: str = ""
    technique_keys: list[str] = []
    # When set, technique_keys above is ignored -- the server stamps the
    # ordered sequence from bas_chain_catalog.py instead (an operator never
    # supplies a chain's step order directly), and stop_on_failure is forced
    # True: a chain models a real kill-chain process, so a genuine failure
    # partway through should stop it, not silently keep firing later steps
    # whose premise (the earlier step succeeding) no longer holds.
    chain_key: str | None = None
    frequency: str = "daily"
    run_time: str = "00:00"
    day_of_week: str | None = None
    day_of_month: int | None = None
    max_authorized_risk_tier: str = "safe"
    authorization_attested: bool = False


def _resolve_chain_technique_keys(chain_key: str, requested_keys: list[str]) -> tuple[list[str], bool]:
    """Returns (technique_keys, stop_on_failure) for a schedule. A chain_key
    always wins over any client-supplied technique_keys -- the sequence is a
    trusted, code-reviewed catalog property (bas_chain_catalog.py), not
    something a request body should be able to override."""
    from app.services.bas_chain_catalog import get_chain

    if not chain_key:
        return requested_keys, False
    chain = get_chain(chain_key)
    if chain is None:
        raise HTTPException(status_code=400, detail=f"Chain desconhecida: {chain_key}")
    return list(chain["technique_keys"]), True


def _schedule_to_dict(s: BasSchedule, db: Session | None = None) -> dict[str, Any]:
    last_job = None
    if db is not None:
        last_job = (
            db.query(BasJob)
            .filter(BasJob.schedule_id == s.id)
            .order_by(BasJob.created_at.desc())
            .first()
        )
    return {
        "id": s.id, "name": s.name, "agent_id": s.agent_id, "target_hint": s.target_hint,
        "technique_keys": s.technique_keys, "chain_key": s.chain_key, "stop_on_failure": s.stop_on_failure,
        "frequency": s.frequency, "run_time": s.run_time,
        "day_of_week": s.day_of_week, "day_of_month": s.day_of_month, "enabled": s.enabled,
        "max_authorized_risk_tier": s.max_authorized_risk_tier,
        "authorization_attested": s.authorization_attested,
        "authorization_attested_by_id": s.authorization_attested_by_id,
        "authorization_attested_at": s.authorization_attested_at,
        "last_run_at": s.last_run_at,
        # Surfaces WHY the last dispatch failed instead of leaving it as an
        # opaque timestamp -- a schedule targeting a blocked/unreachable
        # host (e.g. 127.0.0.1) previously just looked "run" with no visible
        # explanation anywhere in the UI.
        "last_job_status": last_job.status if last_job else None,
        "last_job_error": (last_job.last_error if last_job else None) or (
            (last_job.result or {}).get("dispatch_error") if last_job else None
        ),
    }


@router.post("/schedules")
def create_schedule(payload: ScheduleCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    access_group_id = resolve_company_group_id(
        db, current_user, payload.access_group_id, payload.access_group_name, required=False,
    )
    agent = apply_company_scope(db.query(BasAgent), current_user, BasAgent).filter(BasAgent.id == payload.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agente não encontrado")

    technique_keys, stop_on_failure = _resolve_chain_technique_keys(payload.chain_key, payload.technique_keys)

    schedule = BasSchedule(
        owner_id=current_user.id,
        access_group_id=access_group_id,
        name=payload.name,
        agent_id=payload.agent_id,
        target_hint=payload.target_hint,
        technique_keys=technique_keys,
        chain_key=payload.chain_key,
        stop_on_failure=stop_on_failure,
        frequency=payload.frequency,
        run_time=payload.run_time,
        day_of_week=payload.day_of_week,
        day_of_month=payload.day_of_month,
        max_authorized_risk_tier=payload.max_authorized_risk_tier,
        authorization_attested=payload.authorization_attested,
        authorization_attested_by_id=current_user.id if payload.authorization_attested else None,
        authorization_attested_at=datetime.now() if payload.authorization_attested else None,
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return _schedule_to_dict(schedule, db)


@router.get("/schedules")
def list_schedules(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    schedules = apply_company_scope(db.query(BasSchedule), current_user, BasSchedule).order_by(BasSchedule.created_at.desc()).all()
    return [_schedule_to_dict(s, db) for s in schedules]


class SchedulePatch(BaseModel):
    name: str | None = None
    target_hint: str | None = None
    technique_keys: list[str] | None = None
    # Providing a chain_key here always switches the schedule to that
    # chain's sequence server-side, overriding any technique_keys in the
    # same request -- see ScheduleCreate.chain_key. There is no way to CLEAR
    # a chain back to a flat list via patch in this phase; delete and
    # recreate the schedule instead.
    chain_key: str | None = None
    frequency: str | None = None
    run_time: str | None = None
    day_of_week: str | None = None
    day_of_month: int | None = None
    enabled: bool | None = None
    max_authorized_risk_tier: str | None = None
    authorization_attested: bool | None = None


@router.patch("/schedules/{schedule_id}")
def patch_schedule(schedule_id: int, payload: SchedulePatch, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    schedule = apply_company_scope(db.query(BasSchedule), current_user, BasSchedule).filter(BasSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Agendamento não encontrado")
    if payload.chain_key is not None:
        technique_keys, stop_on_failure = _resolve_chain_technique_keys(payload.chain_key, payload.technique_keys or [])
        schedule.chain_key = payload.chain_key
        schedule.technique_keys = technique_keys
        schedule.stop_on_failure = stop_on_failure
    for field in ("name", "target_hint", "technique_keys", "frequency", "run_time", "day_of_week", "day_of_month", "enabled", "max_authorized_risk_tier"):
        if payload.chain_key is not None and field == "technique_keys":
            continue  # already stamped from the chain above -- don't let a raw list overwrite it
        value = getattr(payload, field)
        if value is not None:
            setattr(schedule, field, value)
    if payload.authorization_attested is not None:
        # Server stamps who/when attested -- never trust a client-supplied attester.
        schedule.authorization_attested = payload.authorization_attested
        schedule.authorization_attested_by_id = current_user.id if payload.authorization_attested else None
        schedule.authorization_attested_at = datetime.now() if payload.authorization_attested else None
    db.commit()
    db.refresh(schedule)
    return _schedule_to_dict(schedule, db)


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(schedule_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    schedule = apply_company_scope(db.query(BasSchedule), current_user, BasSchedule).filter(BasSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Agendamento não encontrado")
    db.delete(schedule)
    db.commit()


@router.post("/schedules/{schedule_id}/run-now")
def run_schedule_now(schedule_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from app.services.bas_scheduler import fire_schedule

    schedule = apply_company_scope(db.query(BasSchedule), current_user, BasSchedule).filter(BasSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Agendamento não encontrado")

    rejected = [
        {"technique_key": key, "reason": check_bas_authorization(schedule, key)["reason"]}
        for key in schedule.technique_keys
        if not check_bas_authorization(schedule, key)["allowed"]
    ]
    if rejected:
        raise HTTPException(status_code=403, detail={"message": "Uma ou mais técnicas não autorizadas", "rejected": rejected})

    result = fire_schedule(db, schedule)
    return result


# ── Report ───────────────────────────────────────────────────────────────────

@router.get("/report")
def report(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from app.api.deps import user_company_group_ids
    from app.services import bas_reporting

    group_ids = None if current_user.is_admin else user_company_group_ids(current_user)
    return bas_reporting.executive_report(db, group_ids=group_ids)


# ── Dashboard / Operations Center ────────────────────────────────────────────

@router.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    agents = apply_company_scope(db.query(BasAgent), current_user, BasAgent).all()
    schedules = apply_company_scope(db.query(BasSchedule), current_user, BasSchedule).all()
    jobs_today = apply_company_scope(db.query(BasJob), current_user, BasJob).filter(
        BasJob.created_at >= datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    ).count()
    return {
        "agents_online": sum(1 for a in agents if a.status == "online"),
        "agents_offline": sum(1 for a in agents if a.status == "offline"),
        "agents_pending": sum(1 for a in agents if a.status == "pending"),
        "agents_total": len(agents),
        "schedules_active": sum(1 for s in schedules if s.enabled),
        "schedules_total": len(schedules),
        "jobs_today": jobs_today,
    }


@router.get("/operations-center")
def operations_center(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from app.api.deps import user_company_group_ids
    from app.services import bas_reporting
    from app.services.bas_technique_catalog import list_techniques

    agents = apply_company_scope(db.query(BasAgent), current_user, BasAgent).all()
    # Full history (uncapped) feeds technique_stats -- capping this would
    # under-count older techniques. "Jobs recentes" below is a separate,
    # explicitly-capped query so the two don't fight over one limit.
    all_jobs = apply_company_scope(db.query(BasJob), current_user, BasJob).all()
    recent_jobs = apply_company_scope(db.query(BasJob), current_user, BasJob) \
        .order_by(BasJob.created_at.desc()).limit(10).all()
    group_ids = None if current_user.is_admin else user_company_group_ids(current_user)

    # Seeded from the full catalog first -- every cataloged technique shows
    # up here (0 counts) even if it has never been dispatched yet, same
    # "coverage gaps are visible, not hidden" rule as attack_heatmap.
    by_technique: dict[str, dict[str, Any]] = {
        t["technique_key"]: {
            "display_name": t["display_name"], "category": t["category"], "availability": t["availability"],
            "completed": 0, "failed": 0, "skipped": 0, "other": 0,
        }
        for t in list_techniques()
    }
    for job in all_jobs:
        bucket = by_technique.setdefault(job.technique_key, {
            "display_name": job.technique_key, "category": "", "availability": "",
            "completed": 0, "failed": 0, "skipped": 0, "other": 0,
        })
        key = job.status if job.status in {"completed", "failed", "skipped"} else "other"
        bucket[key] += 1

    agent_kind_by_id = {a.id: a.kind for a in agents}

    return {
        "agents": [
            {"id": a.id, "label": a.label or a.hostname, "os": a.os, "status": a.status,
             "kind": a.kind, "last_heartbeat_at": a.last_heartbeat_at}
            for a in agents
        ],
        "technique_stats": by_technique,
        "recent_jobs": [
            {
                "id": j.id, "technique_key": j.technique_key, "risk_tier": j.risk_tier,
                "status": j.status, "agent_id": j.agent_id, "created_at": j.created_at,
                "finished_at": j.finished_at,
                # Per-job, sourced from the actual dispatching agent's kind --
                # only a stub-agent job is simulated (see bas_exclusion.py).
                "simulated": agent_kind_by_id.get(j.agent_id, "stub") != "real",
            }
            for j in recent_jobs
        ],
        "framework_coverage": bas_reporting.framework_coverage(db, group_ids=group_ids),
        "exposure": bas_reporting.exposure_summary(db, group_ids=group_ids),
        "findings": bas_reporting.bas_findings_view(db, group_ids=group_ids),
        "crown_jewels": bas_reporting.crown_jewels_view(db, group_ids=group_ids),
        "attack_heatmap": bas_reporting.attack_heatmap(db, group_ids=group_ids),
        "risk_score": bas_reporting.risk_score(db, group_ids=group_ids),
        "chain_attack_paths": bas_reporting.chain_attack_path(db, group_ids=group_ids),
    }


# ── Agent binary download + install config ──────────────────────────────────

@router.get("/install-config")
def install_config(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    def _setting(key: str, default: str) -> str:
        row = db.query(AppSetting).filter(AppSetting.owner_id == current_user.id, AppSetting.key == key).first()
        return row.value if row and row.value else default

    return {
        "callback_host": _setting("bas_agent_callback_host", "backend"),
        "callback_port": _setting("bas_agent_callback_port", "8000"),
        "mtls_port": settings.bas_mtls_external_port,
    }


_AGENT_BINARY_FILENAMES = {
    "linux": "bas-agent-linux",
    "windows": "bas-agent-windows.exe",
}


@router.get("/download/agent/{os_name}")
def download_agent(os_name: str, current_user: User = Depends(get_current_user)):
    if os_name not in _AGENT_BINARY_FILENAMES:
        raise HTTPException(status_code=404, detail="Sistema operacional não suportado")
    # Phase 1 / smoke-test grade: real Go binary (not the future Rust agent),
    # cross-compiled for real via bas-agent/build.sh -- its enroll/mTLS
    # heartbeat/SOCKS5 handshake are all real; only the tunnel's post-
    # handshake response content is simulated. bas_agent_stub (Python,
    # docker-compose) is kept in place unchanged to validate Kali<->agent
    # traffic in dev; this binary is the separate, real downloadable
    # deliverable a customer would actually install.
    filename = _AGENT_BINARY_FILENAMES[os_name]
    binary_path = os.path.join(os.path.dirname(__file__), "..", "..", "bas_agent_dist", filename)
    binary_path = os.path.normpath(binary_path)
    if not os.path.isfile(binary_path):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Binário do agente ({filename}) não encontrado no servidor.",
        )
    with open(binary_path, "rb") as fh:
        content = fh.read()
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
