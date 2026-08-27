"""BAS (Breach & Attack Simulation) module API.

Phase 1: real platform (enrollment, agents, schedules, guardrail, dispatch)
against a stub tunnel (bas_agent_stub) -- the real Kali tool traffic is real,
the tunnel's response content is simulated. See the BAS plan doc for the
full architecture and the Phase 1 vs future-agent boundary.
"""
from __future__ import annotations

import os
import secrets
import socket
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Response, status
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
    # Self-reported real interface CIDR (see bas-agent/network.go /
    # stub_agent.py._local_network_cidr) -- never guessed server-side from a
    # single observed peer IP, which cannot reveal the actual netmask.
    local_network_cidr: str = ""
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
        local_network_cidr=payload.local_network_cidr.strip() or None,
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


class AgentHeartbeatRequest(BaseModel):
    # Recalculated by the agent every heartbeat (not just at enroll), so the
    # platform self-corrects if the agent's network changes without needing
    # a re-enroll. Optional: older agent binaries (pre-Marco 3.6) send no
    # body at all -- payload stays None, existing value is left untouched.
    local_network_cidr: str = ""


@router.post("/agents/heartbeat")
def agent_heartbeat(
    payload: AgentHeartbeatRequest | None = Body(default=None),
    db: Session = Depends(get_db),
    agent: BasAgent = Depends(get_current_bas_agent),
):
    agent.last_heartbeat_at = datetime.now()
    agent.status = "online"
    if payload is not None and payload.local_network_cidr.strip():
        agent.local_network_cidr = payload.local_network_cidr.strip()
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
            "local_network_cidr": a.local_network_cidr,
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


def _purge_bas_scan_jobs(db: Session, scan_job_ids: list[int]) -> int:
    """Deletes the BAS shadow ScanJob rows for `scan_job_ids` plus every
    dependent row they've accumulated. A BAS shadow scan dispatches through
    the exact same execute_via_kali/watchdog/asset-upsert machinery a normal
    scan uses (see bas_dispatcher.py), so it picks up the same generic
    dependent rows -- confirmed live: scan_logs (watchdog heartbeats logged
    every minute the shadow scan stays non-terminal), executed_tool_runs,
    agent_trace_events, skill_scores, audit_events, a stale worker_heartbeats
    lease, and even a discovered Asset row -- and a plain ScanJob delete
    500s with a ForeignKeyViolation on the first one it hits. Same table
    order/logic as routes_scans.py's reset_operational_scans. The BAS
    pipeline never reaches the full offensive-pentest pipeline (hypotheses,
    evidence artifacts, coverage, etc.), so those tables are deliberately
    not touched here.

    A shadow scan can also trigger a real deeper recon pipeline against a
    host it discovers (confirmed live: a firewall_segmentation_test hit
    fired off a genuine naabu/nmap/ffuf/katana pass against the internal IP
    it found, logging WAF-bypass/port/endpoint Finding rows against the same
    scan_job_id, none of them tool="bas-agent"). Those are real findings, not
    BAS-test residue -- any scan_job_id that still has ANY Finding row left
    after the caller's own BAS-tagged Finding cleanup is skipped entirely
    here (ScanJob kept, Asset/Vulnerability kept) so a deleted test can never
    take real findings down with it."""
    if not scan_job_ids:
        return 0
    from app.models.models import (
        AgentTraceEvent,
        Asset,
        AssetRatingHistory,
        AuditEvent,
        ExecutedToolRun,
        PentestOutcomeMetric,
        ScanAuditLog,
        ScanLog,
        SkillScore,
        Vulnerability,
        WorkerHeartbeat,
    )

    still_referenced = {
        row[0] for row in db.query(Finding.scan_job_id).filter(Finding.scan_job_id.in_(scan_job_ids)).distinct().all()
    }
    deletable_ids = [sid for sid in scan_job_ids if sid not in still_referenced]
    if not deletable_ids:
        return 0

    db.query(WorkerHeartbeat).filter(WorkerHeartbeat.current_scan_id.in_(deletable_ids)).update(
        {WorkerHeartbeat.current_scan_id: None, WorkerHeartbeat.status: "idle", WorkerHeartbeat.last_task_name: None},
        synchronize_session=False,
    )
    asset_ids = [row[0] for row in db.query(Asset.id).filter(Asset.last_scan_id.in_(deletable_ids)).all()]
    if asset_ids:
        db.query(Vulnerability).filter(Vulnerability.asset_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(AssetRatingHistory).filter(AssetRatingHistory.asset_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(Asset).filter(Asset.id.in_(asset_ids)).delete(synchronize_session=False)
    db.query(AssetRatingHistory).filter(AssetRatingHistory.scan_id.in_(deletable_ids)).update(
        {AssetRatingHistory.scan_id: None}, synchronize_session=False,
    )
    db.query(ExecutedToolRun).filter(ExecutedToolRun.scan_job_id.in_(deletable_ids)).delete(synchronize_session=False)
    db.query(ScanAuditLog).filter(ScanAuditLog.scan_job_id.in_(deletable_ids)).delete(synchronize_session=False)
    db.query(AgentTraceEvent).filter(AgentTraceEvent.scan_id.in_(deletable_ids)).delete(synchronize_session=False)
    db.query(SkillScore).filter(SkillScore.scan_id.in_(deletable_ids)).delete(synchronize_session=False)
    db.query(AuditEvent).filter(AuditEvent.scan_job_id.in_(deletable_ids)).delete(synchronize_session=False)
    db.query(PentestOutcomeMetric).filter(PentestOutcomeMetric.last_scan_job_id.in_(deletable_ids)).update(
        {PentestOutcomeMetric.last_scan_job_id: None}, synchronize_session=False,
    )
    db.query(ScanLog).filter(ScanLog.scan_job_id.in_(deletable_ids)).delete(synchronize_session=False)
    return db.query(ScanJob).filter(ScanJob.id.in_(deletable_ids), ScanJob.mode == "bas").delete(synchronize_session=False)


@router.delete("/agents/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_agent(agent_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    """Hard-deletes an agent and everything scoped to it -- its schedules
    (BasSchedule.agent_id is NOT NULL, so a schedule can't outlive its
    agent), their jobs, and the BAS findings those jobs produced. Manual
    dependency-order cleanup, same reason as the earlier DELETE /scans/{id}
    fix (see git history): no ON DELETE CASCADE configured on these FKs, so
    deleting the agent row directly would 500 on the first dependent row
    instead of actually removing anything."""
    from app.services.bas_exclusion import BAS_FINDING_TOOL

    agent = apply_company_scope(db.query(BasAgent), current_user, BasAgent).filter(BasAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agente não encontrado")

    jobs = db.query(BasJob).filter(BasJob.agent_id == agent_id).all()
    finding_ids = [j.finding_id for j in jobs if j.finding_id]
    scan_job_ids = [j.scan_job_id for j in jobs if j.scan_job_id]
    # BasJob.finding_id -> findings.id, so the job row (the referencING side)
    # must go before the finding row it points to -- deleting findings first
    # 500s with a ForeignKeyViolation on bas_jobs_finding_id_fkey (confirmed
    # live testing this endpoint).
    db.query(BasJob).filter(BasJob.agent_id == agent_id).delete(synchronize_session=False)
    if finding_ids:
        db.query(Finding).filter(Finding.id.in_(finding_ids), Finding.tool == BAS_FINDING_TOOL).delete(
            synchronize_session=False
        )
    _purge_bas_scan_jobs(db, scan_job_ids)
    db.query(BasSchedule).filter(BasSchedule.agent_id == agent_id).delete(synchronize_session=False)
    db.delete(agent)
    db.commit()


@router.delete("/jobs")
def delete_jobs(
    schedule_id: int | None = None,
    agent_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Wipes BAS test-run history (jobs + the BAS findings they produced)
    without touching agents/schedules -- resets risk score, exposure,
    vulnerabilities and the attack heatmap back to empty, since every one of
    those panels is computed live from BasJob/Finding rows, never a stored
    total (see bas_reporting.py). Scope with schedule_id/agent_id to clear
    just one test's history, or call with neither to wipe everything this
    user can see."""
    from app.services.bas_exclusion import BAS_FINDING_TOOL

    query = apply_company_scope(db.query(BasJob), current_user, BasJob)
    if schedule_id is not None:
        query = query.filter(BasJob.schedule_id == schedule_id)
    if agent_id is not None:
        query = query.filter(BasJob.agent_id == agent_id)
    jobs = query.all()
    job_ids = [j.id for j in jobs]
    finding_ids = [j.finding_id for j in jobs if j.finding_id]
    scan_job_ids = [j.scan_job_id for j in jobs if j.scan_job_id]

    # Same FK direction as delete_agent above: jobs before findings.
    if job_ids:
        db.query(BasJob).filter(BasJob.id.in_(job_ids)).delete(synchronize_session=False)
    if finding_ids:
        db.query(Finding).filter(Finding.id.in_(finding_ids), Finding.tool == BAS_FINDING_TOOL).delete(
            synchronize_session=False
        )
    scans_deleted = _purge_bas_scan_jobs(db, scan_job_ids)
    db.commit()
    return {"ok": True, "jobs_deleted": len(job_ids), "findings_deleted": len(finding_ids), "scan_jobs_deleted": scans_deleted}


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


def _schedule_requires_target_hint(technique_keys: list[str]) -> bool:
    """A schedule may omit target_hint only when every selected technique can
    derive targets from the dispatching BasAgent's own local_network_cidr."""
    if not technique_keys:
        return True  # nothing selected yet -- fall back to the safe default
    for key in technique_keys:
        technique = get_technique(key)
        if technique is None:
            return True
        if technique.get("accepts_range"):
            continue
        if technique.get("target_format", "host") in {"host", "host_port"}:
            continue
        else:
            return True
    return False


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
    # Pure, DB-free validation first (mirrors the resolution create_schedule
    # itself does further down, but doesn't need db/current_user to run) --
    # fail fast before touching the database.
    technique_keys, stop_on_failure = _resolve_chain_technique_keys(payload.chain_key, payload.technique_keys)
    if not payload.target_hint.strip() and _schedule_requires_target_hint(technique_keys):
        # bas_scheduler._create_shadow_scan_job() falls back to a synthetic
        # "bas-unset-target-schedule-{id}" label when target_hint is blank
        # AND no technique can default to the agent's own network -- a
        # deliberate fail-closed placeholder (kali_runner needs a real
        # authorized_scope), so a schedule saved without a target doesn't
        # error loudly here, it just fails every single future firing
        # (enqueue_error: 400 Bad Request) with no clear signal why. Reject
        # it up front instead.
        raise HTTPException(
            status_code=400,
            detail="Alvo (target_hint) é obrigatório quando alguma técnica selecionada exige URL ou domínio explícito",
        )

    access_group_id = resolve_company_group_id(
        db, current_user, payload.access_group_id, payload.access_group_name, required=False,
    )
    agent = apply_company_scope(db.query(BasAgent), current_user, BasAgent).filter(BasAgent.id == payload.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agente não encontrado")

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
    if payload.target_hint is not None and not payload.target_hint.strip():
        # Effective technique set after this patch: payload.technique_keys if
        # this request set it (or the chain resolved above already wrote it
        # onto `schedule`), otherwise whatever the schedule already has.
        effective_keys = schedule.technique_keys if payload.chain_key is not None else (
            payload.technique_keys if payload.technique_keys is not None else schedule.technique_keys
        )
        if _schedule_requires_target_hint(effective_keys or []):
            raise HTTPException(
                status_code=400,
                detail="Alvo (target_hint) é obrigatório quando alguma técnica selecionada exige URL ou domínio explícito",
            )
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
    """Deleting a test wipes everything it produced -- its BasJobs, the BAS
    findings those jobs raised, and the shadow ScanJob rows -- so the
    dashboard/report/heatmap stop showing data for a test that no longer
    exists. Same FK order as delete_agent/delete_jobs: bas_jobs before
    findings (bas_jobs.finding_id -> findings.id references the finding, so
    the referencing row has to go first)."""
    from app.services.bas_exclusion import BAS_FINDING_TOOL

    schedule = apply_company_scope(db.query(BasSchedule), current_user, BasSchedule).filter(BasSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Agendamento não encontrado")

    jobs = db.query(BasJob).filter(BasJob.schedule_id == schedule_id).all()
    finding_ids = [j.finding_id for j in jobs if j.finding_id]
    scan_job_ids = [j.scan_job_id for j in jobs if j.scan_job_id]
    db.query(BasJob).filter(BasJob.schedule_id == schedule_id).delete(synchronize_session=False)
    if finding_ids:
        db.query(Finding).filter(Finding.id.in_(finding_ids), Finding.tool == BAS_FINDING_TOOL).delete(
            synchronize_session=False
        )
    _purge_bas_scan_jobs(db, scan_job_ids)
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
def report(
    schedule_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.api.deps import user_company_group_ids
    from app.services import bas_reporting

    group_ids = None if current_user.is_admin else user_company_group_ids(current_user)
    return bas_reporting.executive_report(db, group_ids=group_ids, schedule_id=schedule_id)


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
    # A job now becomes visible here the instant it's dispatched (bas_scheduler
    # commits before the blocking kali_runner call, not just after it returns)
    # -- these are the ones actually in flight right now, separate from the
    # already-resolved "recent_jobs" list above so the UI can show a live
    # "running now" section instead of only ever showing final outcomes.
    active_jobs = apply_company_scope(db.query(BasJob), current_user, BasJob) \
        .filter(BasJob.status.in_(["queued", "dispatched_to_kali", "running"])) \
        .order_by(BasJob.dispatched_at.desc()).all()
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
             "kind": a.kind, "last_heartbeat_at": a.last_heartbeat_at, "local_network_cidr": a.local_network_cidr}
            for a in agents
        ],
        "schedules": [
            {
                "id": s.id,
                "name": s.name,
                "agent_id": s.agent_id,
                "enabled": s.enabled,
                "target_hint": s.target_hint,
                "technique_keys": s.technique_keys,
                "last_run_at": s.last_run_at,
            }
            for s in schedules
        ],
        "technique_stats": by_technique,
        "active_jobs": [
            {
                "id": j.id, "technique_key": j.technique_key, "risk_tier": j.risk_tier,
                "target": j.target, "status": j.status, "agent_id": j.agent_id,
                "dispatched_at": j.dispatched_at,
                "simulated": agent_kind_by_id.get(j.agent_id, "stub") != "real",
            }
            for j in active_jobs
        ],
        "recent_jobs": [
            {
                "id": j.id, "technique_key": j.technique_key, "risk_tier": j.risk_tier,
                "target": j.target,
                "status": j.status, "agent_id": j.agent_id, "created_at": j.created_at,
                "dispatched_at": j.dispatched_at, "finished_at": j.finished_at,
                # Why it didn't complete cleanly -- a skip reason (e.g.
                # "range_too_large_..." back when that existed, or a guardrail
                # denial) or a dispatch/tunnel failure. None for a clean
                # "completed" job.
                "last_error": j.last_error,
                # Per-job, sourced from the actual dispatching agent's kind --
                # only a stub-agent job is simulated (see bas_exclusion.py).
                "simulated": agent_kind_by_id.get(j.agent_id, "stub") != "real",
            }
            for j in recent_jobs
        ],
        "framework_coverage": bas_reporting.framework_coverage(db, group_ids=group_ids),
        "exposure": bas_reporting.exposure_summary(db, group_ids=group_ids),
        "findings": bas_reporting.bas_findings_view(db, group_ids=group_ids),
        "action_priorities": bas_reporting.action_priorities(db, group_ids=group_ids),
        "attack_path_inventory": bas_reporting.attack_path_inventory(db, group_ids=group_ids),
        "crown_jewels": bas_reporting.crown_jewels_view(db, group_ids=group_ids),
        "attack_heatmap": bas_reporting.attack_heatmap(db, group_ids=group_ids),
        "risk_score": bas_reporting.risk_score(db, group_ids=group_ids),
        "chain_attack_paths": bas_reporting.chain_attack_path(db, group_ids=group_ids),
    }


# ── Agent binary download + install config ──────────────────────────────────

def _detect_container_network_ip() -> str | None:
    """The backend container's own address on the docker-compose bridge
    network (e.g. 172.20.0.13) -- what a BAS agent running as a *sibling
    container on the same docker network* needs to dial. Distinct from
    window.location.hostname (the frontend's guess, correct only for an
    agent reachable via the operator's own browser path -- LAN/host, not
    docker-internal). UDP connect() doesn't send any packet, it only asks
    the kernel to pick the local address for that route, so this works
    even with no real egress and without any container-internal env var.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


@router.get("/install-config")
def install_config(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    def _setting(key: str, default: str) -> str:
        row = db.query(AppSetting).filter(AppSetting.owner_id == current_user.id, AppSetting.key == key).first()
        return row.value if row and row.value else default

    return {
        "callback_host": _setting("bas_agent_callback_host", "backend"),
        "callback_port": _setting("bas_agent_callback_port", str(settings.backend_host_port)),
        "mtls_port": settings.bas_mtls_external_port,
        "container_network_ip": _detect_container_network_ip(),
    }


@router.put("/install-config")
def save_install_config(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    # "backend"/"8000" (this endpoint's GET defaults) are the internal Docker
    # service name and container port -- meaningless to a real agent
    # installed on another machine/VM, which needs the platform's actual
    # externally-reachable IP/hostname and the HOST-mapped plain-HTTP port
    # (BACKEND_HOST_PORT, default 8001) enroll() posts to. Nothing wrote
    # these AppSetting rows before this endpoint existed, so the dashboard's
    # "Credenciais de instalação" card always showed the unusable defaults.
    host = str(payload.get("callback_host") or "").strip()
    port = str(payload.get("callback_port") or "").strip()
    for key, value in (("bas_agent_callback_host", host), ("bas_agent_callback_port", port)):
        if not value:
            continue
        row = db.query(AppSetting).filter(AppSetting.owner_id == current_user.id, AppSetting.key == key).first()
        if row:
            row.value = value
        else:
            db.add(AppSetting(owner_id=current_user.id, key=key, value=value))
    db.commit()
    return {"ok": True}


_AGENT_BINARY_FILENAMES = {
    # A single "linux" binary used to be amd64-only, which silently segfaults
    # deep in the Go runtime's epoll syscall handling when run under
    # binfmt/QEMU x86 emulation on an arm64 host -- e.g. any Kali VM under
    # VirtualBox on Apple Silicon, which can only run arm64 guests. Split by
    # architecture so the customer downloads a native binary.
    "linux-amd64": "bas-agent-linux-amd64",
    "linux-arm64": "bas-agent-linux-arm64",
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
