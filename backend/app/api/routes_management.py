from datetime import datetime, timedelta
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from importlib.util import find_spec

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.db.session import get_db
from app.models.models import AccessGroup, AppSetting, AuditEvent, ExecutedToolRun, OperationLine, ScanAuthorization, ScanJob, ScanLog, ScheduledScan, User, WorkerHeartbeat
from app.services.audit_service import log_audit
from app.services.policy_service import ensure_default_policy
from app.services.policy_service import is_target_allowed
from app.models.models import ClientPolicy, PolicyAllowlistEntry
from app.workers.celery_app import celery
from app.workers.tasks import run_scan_job, run_scan_job_scheduled, run_scan_job_unit
from app.workers.worker_groups import WORKER_GROUPS, UNIT_WORKER_GROUPS, SCHEDULED_WORKER_GROUPS, get_worker_agent_profiles
from app.graph.mission import MISSION_ITEMS


router = APIRouter(prefix="/api", tags=["management"])

TOOL_REQUIREMENTS: dict[str, dict[str, str]] = {
    "subfinder": {"url": "https://github.com/projectdiscovery/subfinder", "requirements": "Go 1.22+, acesso HTTP externo e DNS funcional."},
    "amass": {"url": "https://github.com/owasp-amass/amass", "requirements": "Go, memória moderada e conectividade DNS/HTTP."},
    "assetfinder": {"url": "https://github.com/tomnomnom/assetfinder", "requirements": "Go e acesso HTTP externo."},
    "dnsx": {"url": "https://github.com/projectdiscovery/dnsx", "requirements": "Go e resolução DNS liberada."},
    "naabu": {"url": "https://github.com/projectdiscovery/naabu", "requirements": "Go, libpcap-dev e acesso de rede para probe."},
    "httpx": {"url": "https://github.com/projectdiscovery/httpx", "requirements": "Go e saída HTTP/HTTPS liberada."},
    "katana": {"url": "https://github.com/projectdiscovery/katana", "requirements": "Go e saída HTTP/HTTPS liberada."},
    "uro": {"url": "https://github.com/s0md3v/uro", "requirements": "Python 3.10+ e pip."},
    "ffuf": {"url": "https://github.com/ffuf/ffuf", "requirements": "Go e wordlists locais/remotas."},
    "feroxbuster": {"url": "https://github.com/epi052/feroxbuster", "requirements": "Rust ou binário dedicado; instalação manual recomendada."},
    "arjun": {"url": "https://github.com/s0md3v/Arjun", "requirements": "Python 3.10+ e pip."},
    "nessus": {"url": "https://www.tenable.com/products/nessus", "requirements": "Credenciais Nessus, URL do scanner e pynessus instalado."},
    "nmap-vulscan": {"url": "https://github.com/scipag/vulscan", "requirements": "Nmap instalado e script NSE vulscan em /root/vulscan ou /opt/vulscan."},
    "dalfox": {"url": "https://github.com/hahwul/dalfox", "requirements": "Go e saída HTTP/HTTPS liberada."},
    "nikto": {"url": "https://github.com/sullo/nikto", "requirements": "Perl/apt compatível; pode exigir instalação manual."},
    "wpscan": {"url": "https://github.com/wpscanteam/wpscan", "requirements": "Ruby, gem e acesso HTTP/HTTPS."},
    "zap": {"url": "https://www.zaproxy.org/", "requirements": "Java 11+ ou container dedicado; recomendado serviço separado."},
    "burp-cli": {"url": "https://portswigger.net/burp/documentation/desktop/tools/command-line", "requirements": "Burp Professional CLI instalado e chave de licenca valida configurada."},
    "secretfinder": {"url": "https://github.com/m4ll0k/SecretFinder", "requirements": "Python e instalação manual do projeto."},
    "trufflehog": {"url": "https://github.com/trufflesecurity/trufflehog", "requirements": "Go moderno e acesso a repositórios/targets."},
    "kiterunner": {"url": "https://github.com/assetnote/kiterunner", "requirements": "Go moderno; binário pode variar por arquitetura."},
    "theharvester": {"url": "https://github.com/laramies/theHarvester", "requirements": "Python, APIs opcionais e saída HTTP externa."},
    "shodan-cli": {"url": "https://github.com/achillean/shodan-python", "requirements": "Python, pacote shodan e chave API configurada."},
    "whatweb": {"url": "https://github.com/urbanadventurer/WhatWeb", "requirements": "Ruby/apt compatível."},
    "urlscan-cli": {"url": "https://urlscan.io/docs/api/", "requirements": "Cliente compatível e API key do urlscan quando aplicável."},
    "subjack": {"url": "https://github.com/haccer/subjack", "requirements": "Go e listas de fingerprints."},
    "findomain": {"url": "https://github.com/findomain/findomain", "requirements": "Binário próprio; instalação manual recomendada."},
    "sublist3r": {"url": "https://github.com/aboul3la/Sublist3r", "requirements": "Python 3 e pip."},
    "chaos": {"url": "https://github.com/projectdiscovery/chaos-client", "requirements": "Go e API key Chaos quando usada."},
    "cloudenum": {"url": "https://github.com/initstring/cloud_enum", "requirements": "Python e instalação manual do projeto."},
    "puredns": {"url": "https://github.com/d3mondev/puredns", "requirements": "Go, massdns e resolução DNS liberada."},
    "massdns": {"url": "https://github.com/blechschmidt/massdns", "requirements": "Compilação nativa/manual; não empacotado por padrão."},
    "dnsenum": {"url": "https://github.com/fwaeytens/dnsenum", "requirements": "Perl e pacote do sistema."},
    "alterx": {"url": "https://github.com/projectdiscovery/alterx", "requirements": "Go moderno."},
    "dnsgen": {"url": "https://github.com/ProjectAnte/dnsgen", "requirements": "Python e instalação manual do projeto."},
    "gowitness": {"url": "https://github.com/sensepost/gowitness", "requirements": "Go e engine headless/chromium."},
    "webanalyze": {"url": "https://github.com/rverton/webanalyze", "requirements": "Go moderno."},
    "cmsmap": {"url": "https://github.com/Dionach/CMSmap", "requirements": "Python e dependências específicas do projeto."},
    "dirb": {"url": "http://dirb.sourceforge.net/", "requirements": "Pacote apt ou binário Linux."},
    "linkfinder": {"url": "https://github.com/GerbenJavado/LinkFinder", "requirements": "Python 3 e pip."},
    "postman-to-k6": {"url": "https://github.com/grafana/postman-to-k6", "requirements": "Node.js e npm."},
    "h8mail": {"url": "https://github.com/khast3x/h8mail", "requirements": "Python 3 e pip."},
    "metagoofil": {"url": "https://github.com/opsdisk/metagoofil", "requirements": "Projeto externo; instalação manual recomendada."},
    "openvas": {"url": "https://greenbone.github.io/docs/latest/", "requirements": "Stack dedicada Greenbone/OpenVAS; serviço separado."},
    "waymore": {"url": "https://github.com/xnl-h4ck3r/waymore", "requirements": "Python 3 e pip."},
    "gobuster": {"url": "https://github.com/OJ/gobuster", "requirements": "Go moderno e wordlists locais para dir, vhost e fuzz."},
    "wapiti": {"url": "https://github.com/wapiti-scanner/wapiti", "requirements": "Python 3.12+ e pacote wapiti3; cobre SQLi, XSS, SSRF, XXE, file/include e CRLF."},
    "wfuzz": {"url": "https://github.com/xmendez/wfuzz", "requirements": "Python 3, pip e wordlists locais para fuzzing HTTP."},
    "wafw00f": {"url": "https://github.com/EnableSecurity/wafw00f", "requirements": "Python 3 e pip para fingerprinting de WAF."},
    "sslscan": {"url": "https://github.com/rbsec/sslscan", "requirements": "Binário sslscan instalado via apt no worker."},
    "shcheck": {"url": "https://github.com/santoru/shcheck", "requirements": "Python 3 e pip install shcheck."},
}

INSTALL_SUPPORTED_TOOLS = {
    "nessus", "arjun", "semgrep", "h8mail", "metagoofil", "theharvester", "shodan-cli", "urlscan-cli",
    "uro", "subfinder", "amass", "assetfinder", "dnsx", "naabu", "httpx", "katana", "ffuf",
    "dalfox", "kiterunner", "subjack", "wpscan", "nikto", "nmap-vulscan", "whatweb", "sublist3r", "waymore", "linkfinder",
    "alterx", "chaos", "puredns", "webanalyze", "gobuster", "wapiti", "wfuzz",
    "wafw00f",
    "sslscan", "shcheck", "burp-cli",
}

TOOL_BINARY_ALIASES = {
    "kiterunner": "kr",
    "theharvester": "theHarvester",
    "linkfinder": "linkfinder.py",
    "secretfinder": "SecretFinder.py",
    "shodan-cli": "shodan",
    "urlscan-cli": "urlscan",
    "sublist3r": "python3",
    "nmap-vulscan": "nmap",
    "burp-cli": "burp-cli",
}


def _tool_metadata(tool_name: str) -> dict[str, str | bool]:
    normalized = tool_name.strip().lower()
    base = TOOL_REQUIREMENTS.get(normalized, {})
    requirements = str(base.get("requirements") or "Instalação manual ou externa pode ser necessária.")
    return {
        "url": str(base.get("url") or ""),
        "requirements": requirements,
        "install_supported": normalized in INSTALL_SUPPORTED_TOOLS,
        "requires_credentials": normalized in {"nessus", "shodan-cli", "urlscan-cli", "chaos", "burp-cli"},
    }


def _parse_targets(targets_text: str) -> list[str]:
    return [item.strip() for item in targets_text.split(";") if item.strip()]


DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _normalize_domain_candidate(raw_target: str) -> str | None:
    raw = str(raw_target or "").strip().lower()
    if not raw:
        return None

    if raw.startswith("http://"):
        raw = raw[7:]
    elif raw.startswith("https://"):
        raw = raw[8:]

    raw = raw.split("/")[0].split(":")[0].strip(".")
    wildcard = raw.startswith("*.")
    host = raw[2:] if wildcard else raw

    if not host or not DOMAIN_RE.match(host):
        return None
    return f"*.{host}" if wildcard else host


def _validate_schedule_targets(targets_text: str) -> tuple[list[str], list[str]]:
    parsed = _parse_targets(targets_text)
    valid_targets: list[str] = []
    invalid_targets: list[str] = []

    for target in parsed:
        normalized = _normalize_domain_candidate(target)
        if normalized:
            valid_targets.append(normalized)
        else:
            invalid_targets.append(target)

    deduped_valid = list(dict.fromkeys(valid_targets))
    return deduped_valid, invalid_targets


SCHEDULE_TARGETS_PER_SCAN = max(1, min(200, int(os.getenv("SCHEDULE_TARGETS_PER_SCAN", "25"))))


def _chunk_targets(targets: list[str], chunk_size: int) -> list[list[str]]:
    return [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]


def _resolve_valid_authorization_code(db: Session, authorization_code: str | None) -> ScanAuthorization | None:
    if not authorization_code:
        return None
    row = (
        db.query(ScanAuthorization)
        .filter(
            ScanAuthorization.authorization_code == authorization_code,
            ScanAuthorization.status == "approved",
        )
        .order_by(ScanAuthorization.created_at.desc())
        .first()
    )
    if not row:
        return None
    if row.expires_at and row.expires_at < datetime.utcnow():
        return None
    return row


def _create_scan_from_schedule(
    db: Session,
    actor_user: User,
    owner_id: int,
    target: str,
    authorization_code: str | None,
    access_group_id: int | None,
    mode: str = "scheduled",
) -> ScanJob:
    batch_targets = _parse_targets(target)
    compliance_status = "approved"

    job = ScanJob(
        owner_id=owner_id,
        access_group_id=access_group_id,
        target_query=target,
        authorization_code=authorization_code,
        mode=mode,
        status="queued" if compliance_status == "approved" else "blocked",
        compliance_status=compliance_status,
        authorization_id=None,
        current_step="1. Amass Subdomain Recon",
    )
    db.add(job)
    db.flush()
    log_audit(
        db,
        event_type="scan.created_from_schedule",
        message=f"Scan criado via agendamento para alvo {target}",
        actor_user_id=actor_user.id,
        scan_job_id=job.id,
        metadata={"target": target, "mode": mode, "owner_id": owner_id},
    )
    return job


@router.post("/compliance/authorizations/request")
def request_authorization(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    target_query = (payload.get("target_query") or payload.get("scope_ref") or "").strip()
    ownership_proof = (payload.get("ownership_proof") or "").strip()
    notes = (payload.get("notes") or "").strip()

    if not target_query or not ownership_proof:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="scope_ref/target_query e ownership_proof sao obrigatorios")

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
def list_audit_events(
    limit: int = 100,
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(AuditEvent)
    if active_only:
        existing_ids = db.query(ScanJob.id)
        query = query.filter(
            (AuditEvent.scan_job_id == None) | (AuditEvent.scan_job_id.in_(existing_ids))  # noqa: E711
        )
    rows = query.order_by(AuditEvent.created_at.desc()).limit(max(1, min(limit, 500))).all()
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


@router.get("/admin/worker-logs")
def admin_worker_logs(
    scan_id: int | None = None,
    tool: str | None = None,
    limit: int = 500,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Retorna logs completos de execução dos workers: ExecutedToolRun + ScanLog associados.
    - scan_id: filtra por scan específico (obrigatório para máxima verbosidade)
    - tool: filtra por ferramenta específica dentro do scan
    - limit: máximo de linhas de ScanLog retornadas (padrão 500)
    """
    max_limit = max(1, min(int(limit), 2000))

    # ── Scans disponíveis para o seletor ────────────────────────────────────
    all_scans = (
        db.query(ScanJob.id, ScanJob.target_query, ScanJob.status, ScanJob.created_at)
        .order_by(ScanJob.created_at.desc())
        .limit(200)
        .all()
    )
    scans_list = [
        {"id": row.id, "target_query": row.target_query, "status": row.status, "created_at": row.created_at}
        for row in all_scans
    ]

    if scan_id is None:
        return {"scans": scans_list, "executions": [], "logs": [], "scan": None}

    # ── Scan selecionado ─────────────────────────────────────────────────────
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    # ── ExecutedToolRun ──────────────────────────────────────────────────────
    runs_query = db.query(ExecutedToolRun).filter(ExecutedToolRun.scan_job_id == scan_id)
    if tool:
        runs_query = runs_query.filter(ExecutedToolRun.tool_name == tool.strip().lower())
    runs = runs_query.order_by(ExecutedToolRun.created_at.asc()).all()

    executions = [
        {
            "id": r.id,
            "tool": r.tool_name,
            "target": r.target,
            "status": r.status,
            "error_message": r.error_message or "",
            "execution_time_seconds": r.execution_time_seconds,
            "created_at": r.created_at,
        }
        for r in runs
    ]

    # ── ScanLog ──────────────────────────────────────────────────────────────
    logs_query = db.query(ScanLog).filter(ScanLog.scan_job_id == scan_id)
    if tool:
        normalized = tool.strip().lower()
        logs_query = logs_query.filter(ScanLog.message.ilike(f"%tool={normalized}%"))
    logs = (
        logs_query
        .order_by(ScanLog.created_at.asc())
        .limit(max_limit)
        .all()
    )

    logs_list = [
        {
            "id": row.id,
            "source": row.source,
            "level": row.level,
            "message": row.message,
            "created_at": row.created_at,
        }
        for row in logs
    ]

    # ── Resumo por ferramenta ────────────────────────────────────────────────
    tool_summary: dict[str, dict] = {}
    for r in runs:
        t = r.tool_name
        if t not in tool_summary:
            tool_summary[t] = {"tool": t, "executed": 0, "failed": 0, "skipped": 0, "total": 0}
        tool_summary[t]["total"] += 1
        s_ = str(r.status or "").lower()
        if s_ in ("success", "executed"):
            tool_summary[t]["executed"] += 1
        elif s_ == "failed":
            tool_summary[t]["failed"] += 1
        elif s_ == "skipped":
            tool_summary[t]["skipped"] += 1

    return {
        "scans": scans_list,
        "scan": {
            "id": job.id,
            "target_query": job.target_query,
            "status": job.status,
            "current_step": job.current_step,
            "mission_progress": job.mission_progress,
            "created_at": job.created_at,
            "updated_at": job.updated_at,
        },
        "tool_summary": list(tool_summary.values()),
        "executions": executions,
        "logs": logs_list,
    }


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

    valid_targets, invalid_targets = _validate_schedule_targets(targets_text)
    if invalid_targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Dominios invalidos no agendamento: {', '.join(invalid_targets[:10])}",
        )
    if not valid_targets:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nenhum dominio valido informado")

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
        authorization_code=None,
        targets_text="; ".join(valid_targets),
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

    for field in ["targets_text", "scan_type", "frequency", "run_time", "day_of_week", "day_of_month", "enabled"]:
        if field in payload:
            if field == "targets_text":
                candidate_targets = str(payload[field] or "").strip()
                valid_targets, invalid_targets = _validate_schedule_targets(candidate_targets)
                if invalid_targets:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Dominios invalidos no agendamento: {', '.join(invalid_targets[:10])}",
                    )
                if not valid_targets:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nenhum dominio valido informado")
                setattr(row, field, "; ".join(valid_targets))
            else:
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


@router.post("/schedules/{schedule_id}/execute")
def execute_schedule_now(schedule_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    row = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento nao encontrado")
    if not row.enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Agendamento desabilitado")

    targets, invalid_targets = _validate_schedule_targets(row.targets_text)
    if invalid_targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Agendamento contem dominios invalidos: {', '.join(invalid_targets[:10])}",
        )
    if not targets:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Agendamento sem dominios validos")

    chunks = _chunk_targets(targets, SCHEDULE_TARGETS_PER_SCAN)
    created_scan_ids: list[int] = []
    for chunk in chunks:
        target_batch = "; ".join(chunk)
        job = _create_scan_from_schedule(
            db=db,
            actor_user=current_user,
            owner_id=row.owner_id,
            target=target_batch,
            authorization_code=None,
            access_group_id=row.access_group_id,
            mode="scheduled",
        )
        created_scan_ids.append(job.id)

    db.commit()

    for scan_id in created_scan_ids:
        try:
            run_scan_job_scheduled.delay(scan_id)
        except Exception:
            run_scan_job(scan_id)

    return {
        "ok": True,
        "created_scans": created_scan_ids,
        "total_targets": len(targets),
        "validated_domains": targets,
        "batch_size": SCHEDULE_TARGETS_PER_SCAN,
        "batches_created": len(created_scan_ids),
    }


@router.get("/config/shodan")
def get_shodan_config(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    row = (
        db.query(AppSetting)
        .filter(AppSetting.owner_id == current_user.id, AppSetting.key == "shodan_api_key")
        .first()
    )
    api_key = row.value if row else ""
    return {
        "api_key": api_key,
        "configured": bool(api_key),
        "enabled": bool(api_key),
        "status": "ativo" if api_key else "desativado",
    }


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


def _parse_int(payload: dict, key: str, default: int, min_value: int, max_value: int) -> int:
    raw = payload.get(key, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(min_value, min(max_value, value))


def _parse_bool(payload: dict, key: str, default: bool) -> bool:
    raw = payload.get(key, default)
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return bool(raw)


def _setting_int(db: Session, owner_id: int, key: str, default: int, min_value: int, max_value: int) -> int:
    raw = _get_setting(db, owner_id, key, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(min_value, min(max_value, value))


def _tool_installed(tool_name: str) -> bool:
    normalized = tool_name.strip().lower()
    if normalized == "nessus":
        return find_spec("nessus") is not None or find_spec("pynessus") is not None

    if normalized == "sublist3r":
        # Sublist3r costuma existir como modulo Python sem binario dedicado no PATH.
        return (
            find_spec("sublist3r") is not None
            or shutil.which("sublist3r") is not None
            or shutil.which("Sublist3r") is not None
        )

    if normalized == "nmap-vulscan":
        if shutil.which("nmap") is None:
            return False
        return any(
            os.path.exists(path)
            for path in [
                "/root/vulscan/vulscan.nse",
                "/opt/vulscan/vulscan.nse",
            ]
        )

    if normalized == "nikto":
        return (
            shutil.which("nikto") is not None
            or os.path.exists("/usr/bin/nikto")
            or os.path.exists("/opt/nikto/program/nikto.pl")
        )

    if normalized == "burp-cli":
        return shutil.which("burp-cli") is not None

    cmd = TOOL_BINARY_ALIASES.get(normalized, normalized)
    return shutil.which(cmd) is not None


def _run_install_command(command: list[str]) -> bool:
    try:
        proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=600)
        return proc.returncode == 0
    except Exception:
        return False


def _install_tool(tool_name: str) -> bool:
    normalized = tool_name.strip().lower()

    install_map: dict[str, list[list[str]]] = {
        "nessus": [[sys.executable, "-m", "pip", "install", "pynessus"]],
        "arjun": [[sys.executable, "-m", "pip", "install", "arjun"]],
        "semgrep": [[sys.executable, "-m", "pip", "install", "semgrep"]],
        "h8mail": [[sys.executable, "-m", "pip", "install", "h8mail"]],
        "metagoofil": [[sys.executable, "-m", "pip", "install", "metagoofil"]],
        "theharvester": [[sys.executable, "-m", "pip", "install", "theHarvester"]],
        "shodan-cli": [[sys.executable, "-m", "pip", "install", "shodan"]],
        "urlscan-cli": [[sys.executable, "-m", "pip", "install", "urlscanio"]],
        "uro": [[sys.executable, "-m", "pip", "install", "uro"]],
        "subfinder": [["go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"]],
        "amass": [["go", "install", "github.com/owasp-amass/amass/v4/...@master"]],
        "assetfinder": [["go", "install", "github.com/tomnomnom/assetfinder@latest"]],
        "dnsx": [["go", "install", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"]],
        "naabu": [["go", "install", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"]],
        "httpx": [["go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"]],
        "katana": [["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"]],
        "ffuf": [["go", "install", "github.com/ffuf/ffuf/v2@latest"]],
        "nmap-vulscan": [
            ["apt-get", "update"],
            ["apt-get", "install", "-y", "nmap", "git"],
            ["git", "clone", "--depth", "1", "https://github.com/scipag/vulscan.git", "/root/vulscan"],
        ],
        "dalfox": [["go", "install", "github.com/hahwul/dalfox/v2@latest"]],
        "kiterunner": [["go", "install", "github.com/assetnote/kiterunner@latest"]],
        "subjack": [["go", "install", "github.com/haccer/subjack@latest"]],
        "trufflehog": [["go", "install", "github.com/trufflesecurity/trufflehog/v3@latest"]],
        "wpscan": [["gem", "install", "--no-document", "wpscan"]],
        "nikto": [
            ["apt-get", "update"],
            ["apt-get", "install", "-y", "nikto"],
            ["apt-get", "install", "-y", "git", "perl"],
            ["sh", "-lc", "if [ ! -d /opt/nikto ]; then git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto; fi"],
            ["sh", "-lc", "if [ -f /opt/nikto/program/nikto.pl ]; then ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && chmod +x /opt/nikto/program/nikto.pl; fi"],
        ],
        "whatweb": [["apt-get", "update"], ["apt-get", "install", "-y", "whatweb"]],
        "sublist3r": [
            [sys.executable, "-m", "pip", "install", "git+https://github.com/aboul3la/Sublist3r.git"],
            ["sh", "-lc", "printf '#!/bin/sh\nexec python3 -m sublist3r \"$@\"\n' >/usr/local/bin/sublist3r && chmod +x /usr/local/bin/sublist3r"],
        ],
        "waymore": [[sys.executable, "-m", "pip", "install", "waymore"]],
        "linkfinder": [[sys.executable, "-m", "pip", "install", "linkfinder"]],
        "alterx": [["go", "install", "github.com/projectdiscovery/alterx/cmd/alterx@latest"]],
        "chaos": [["go", "install", "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"]],
        "puredns": [["go", "install", "github.com/d3mondev/puredns/v2@latest"]],
        "webanalyze": [["go", "install", "github.com/rverton/webanalyze/cmd/webanalyze@latest"]],
        "gobuster": [["sh", "-lc", "ARCH=$(uname -m); if [ \"$ARCH\" = \"aarch64\" ] || [ \"$ARCH\" = \"arm64\" ]; then URL=https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_arm64.tar.gz; else URL=https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_x86_64.tar.gz; fi; curl -fsSL \"$URL\" -o /tmp/gobuster.tar.gz && tar -xzf /tmp/gobuster.tar.gz -C /tmp && install -m 0755 /tmp/gobuster /usr/local/bin/gobuster"]],
        "wapiti": [[sys.executable, "-m", "pip", "install", "wapiti3"]],
        "wfuzz": [[sys.executable, "-m", "pip", "install", "git+https://github.com/xmendez/wfuzz.git"]],
        "wafw00f": [[sys.executable, "-m", "pip", "install", "wafw00f"]],
        "burp-cli": [["sh", "-lc", "npm install -g @portswigger/burp-cli || npm install -g burp-cli"]],
    }

    commands = install_map.get(normalized)
    if not commands:
        return False

    for cmd in commands:
        _run_install_command(cmd)
        if _tool_installed(normalized):
            return True
    return _tool_installed(normalized)


def _burp_api_host() -> str:
    host = str(os.getenv("BURP_API_HOST", "burp_rest")).strip()
    return host or "burp_rest"


def _burp_api_port() -> str:
    port = str(os.getenv("BURP_API_PORT", "1337")).strip()
    return port or "1337"


def _burp_api_key() -> str:
    return str(os.getenv("BURP_API_KEY", "")).strip()


def _burp_api_base_url() -> str:
    host = _burp_api_host()
    port = _burp_api_port()
    api_key = _burp_api_key()
    if api_key:
        return f"http://{host}:{port}/{api_key}/v0.1"
    return f"http://{host}:{port}/v0.1"


def _burp_cli_list_scans_output() -> str:
    cli = shutil.which("burp-api-cli") or shutil.which("burp-cli")
    if not cli:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="burp-cli nao instalado no backend")

    cmd = [cli, "-t", _burp_api_host(), "-p", _burp_api_port(), "-L"]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=30)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"falha ao listar scans burp: {exc}")

    text = "\n".join(part for part in [proc.stdout or "", proc.stderr or ""] if part).strip()
    if proc.returncode != 0 and text:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=text[:500])
    return text


def _parse_burp_cli_list_output(output: str) -> list[dict[str, str]]:
    scans: list[dict[str, str]] = []
    seen_ids: set[str] = set()

    # burp-cli -L pode retornar tabela em largura fixa com quebras de linha.
    # Fazemos busca no texto inteiro para capturar id/url/status mesmo quebrados.
    pattern = re.compile(
        r"(?<!\d)(?P<id>\d+)\s+(?P<url>https?://\S+|scan_\d+)\s+(?P<status>paused|auditing|running|succeeded|failed|cancelled)\b",
        re.IGNORECASE,
    )
    for match in pattern.finditer(output or ""):
        scan_id = str(match.group("id") or "").strip()
        if not scan_id or scan_id in seen_ids:
            continue
        seen_ids.add(scan_id)
        scans.append(
            {
                "id": scan_id,
                "url": str(match.group("url") or "").strip(),
                "status": str(match.group("status") or "").strip().lower(),
            }
        )
    return scans


def _burp_api_call(method: str, path: str, timeout: int = 12) -> tuple[bool, int, str]:
    req = urllib.request.Request(_burp_api_base_url() + path, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = (response.read() or b"").decode("utf-8", "ignore")
            return True, int(response.status), body
    except urllib.error.HTTPError as exc:
        body = (exc.read() or b"").decode("utf-8", "ignore")
        return False, int(getattr(exc, "code", 0) or 0), body
    except Exception as exc:
        return False, 0, str(exc)


def _burp_cli_history_path() -> str:
    custom_path = str(os.getenv("BURP_CLI_HISTORY_FILE", "")).strip()
    if custom_path:
        return custom_path
    return "/root/.burp-cli/scan_history.json"


def _prune_burp_cli_history(scan_ids_to_remove: list[str]) -> int:
    targets = {str(item).strip() for item in (scan_ids_to_remove or []) if str(item).strip()}
    if not targets:
        return 0

    path = _burp_cli_history_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception:
        return 0

    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        return 0

    kept_records = [
        row
        for row in records
        if str((row or {}).get("scan_id") or "").strip() not in targets
    ]
    removed = len(records) - len(kept_records)
    if removed <= 0:
        return 0

    payload["records"] = kept_records
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    except Exception:
        return 0
    return removed


@router.get("/config/runtime")
def get_runtime_flags(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    debug_mode = _get_setting(db, current_user.id, "debug_mode", "false") == "true"
    verbose_mode = _get_setting(db, current_user.id, "verbose_mode", "false") == "true"
    scan_retry_enabled = _get_setting(db, current_user.id, "scan_retry_enabled", "true") == "true"
    scan_retry_max_attempts = _setting_int(db, current_user.id, "scan_retry_max_attempts", 3, 1, 10)
    scan_retry_delay_seconds = _setting_int(db, current_user.id, "scan_retry_delay_seconds", 10, 5, 3600)
    worker_health_stale_after_seconds = _setting_int(db, current_user.id, "worker_health_stale_after_seconds", 60, 10, 3600)
    worker_orphan_cutoff_minutes = _setting_int(db, current_user.id, "worker_orphan_cutoff_minutes", 8, 1, 180)
    worker_orphan_requeue_limit = _setting_int(db, current_user.id, "worker_orphan_requeue_limit", 100, 1, 2000)
    return {
        "debug_mode": debug_mode,
        "verbose_mode": verbose_mode,
        "scan_retry_enabled": scan_retry_enabled,
        "scan_retry_max_attempts": scan_retry_max_attempts,
        "scan_retry_delay_seconds": scan_retry_delay_seconds,
        "worker_health_stale_after_seconds": worker_health_stale_after_seconds,
        "worker_orphan_cutoff_minutes": worker_orphan_cutoff_minutes,
        "worker_orphan_requeue_limit": worker_orphan_requeue_limit,
    }


@router.put("/config/runtime")
def save_runtime_flags(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    debug_mode = _parse_bool(payload, "debug_mode", False)
    verbose_mode = _parse_bool(payload, "verbose_mode", False)
    scan_retry_enabled = _parse_bool(payload, "scan_retry_enabled", True)
    scan_retry_max_attempts = _parse_int(payload, "scan_retry_max_attempts", 3, 1, 10)
    scan_retry_delay_seconds = _parse_int(payload, "scan_retry_delay_seconds", 10, 5, 3600)
    worker_health_stale_after_seconds = _parse_int(payload, "worker_health_stale_after_seconds", 60, 10, 3600)
    worker_orphan_cutoff_minutes = _parse_int(payload, "worker_orphan_cutoff_minutes", 8, 1, 180)
    worker_orphan_requeue_limit = _parse_int(payload, "worker_orphan_requeue_limit", 100, 1, 2000)

    _set_setting(db, current_user.id, "debug_mode", "true" if debug_mode else "false")
    _set_setting(db, current_user.id, "verbose_mode", "true" if verbose_mode else "false")
    _set_setting(db, current_user.id, "scan_retry_enabled", "true" if scan_retry_enabled else "false")
    _set_setting(db, current_user.id, "scan_retry_max_attempts", str(scan_retry_max_attempts))
    _set_setting(db, current_user.id, "scan_retry_delay_seconds", str(scan_retry_delay_seconds))
    _set_setting(db, current_user.id, "worker_health_stale_after_seconds", str(worker_health_stale_after_seconds))
    _set_setting(db, current_user.id, "worker_orphan_cutoff_minutes", str(worker_orphan_cutoff_minutes))
    _set_setting(db, current_user.id, "worker_orphan_requeue_limit", str(worker_orphan_requeue_limit))
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
            "scan_retry_enabled": _get_setting(db, current_user.id, "scan_retry_enabled", "true") == "true",
            "scan_retry_max_attempts": _setting_int(db, current_user.id, "scan_retry_max_attempts", 3, 1, 10),
            "scan_retry_delay_seconds": _setting_int(db, current_user.id, "scan_retry_delay_seconds", 10, 5, 3600),
            "worker_health_stale_after_seconds": _setting_int(db, current_user.id, "worker_health_stale_after_seconds", 60, 10, 3600),
            "worker_orphan_cutoff_minutes": _setting_int(db, current_user.id, "worker_orphan_cutoff_minutes", 8, 1, 180),
            "worker_orphan_requeue_limit": _setting_int(db, current_user.id, "worker_orphan_requeue_limit", 100, 1, 2000),
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


@router.get("/config/tools")
def list_tools_catalog(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    def _group_payload(mode_name: str, groups: dict) -> list[dict]:
        result: list[dict] = []
        for group_name, group in groups.items():
            tools = []
            for tool in group.get("tools", []):
                metadata = _tool_metadata(tool)
                tools.append(
                    {
                        "name": tool,
                        "installed": _tool_installed(tool),
                        **metadata,
                    }
                )
            result.append(
                {
                    "mode": mode_name,
                    "group": group_name,
                    "queue": group.get("queue"),
                    "description": group.get("description", ""),
                    "tools": tools,
                }
            )
        return result

    nessus_enabled = _get_setting(db, current_user.id, "nessus_enabled", "false") == "true"
    nessus_url = _get_setting(db, current_user.id, "nessus_url", "")
    burp_enabled = _get_setting(db, current_user.id, "burp_enabled", "false") == "true"
    burp_license_key = _get_setting(db, current_user.id, "burp_license_key", "")
    shodan_key = _get_setting(db, current_user.id, "shodan_api_key", "")

    unique_tools: dict[str, dict] = {}
    for groups in [UNIT_WORKER_GROUPS, SCHEDULED_WORKER_GROUPS]:
        for group in groups.values():
            for tool in group.get("tools", []):
                if tool not in unique_tools:
                    unique_tools[tool] = {
                        "name": tool,
                        "installed": _tool_installed(tool),
                        **_tool_metadata(tool),
                    }

    return {
        "catalog": {
            "unit": _group_payload("unit", UNIT_WORKER_GROUPS),
            "scheduled": _group_payload("scheduled", SCHEDULED_WORKER_GROUPS),
        },
        "requirements_catalog": sorted(unique_tools.values(), key=lambda item: item["name"]),
        "nessus": {
            "enabled": nessus_enabled,
            "url": nessus_url,
            "pynessus_installed": _tool_installed("nessus"),
            "configured": bool(nessus_url and _get_setting(db, current_user.id, "nessus_access_key", "") and _get_setting(db, current_user.id, "nessus_secret_key", "")),
            "status": "ativo" if bool(nessus_url and _get_setting(db, current_user.id, "nessus_access_key", "") and _get_setting(db, current_user.id, "nessus_secret_key", "")) else "desativado",
        },
        "burp": {
            "enabled": burp_enabled,
            "configured": bool(burp_license_key),
            "burp_cli_installed": _tool_installed("burp-cli"),
            "status": "ativo" if bool(burp_enabled and burp_license_key) else "desativado",
        },
        "shodan": {
            "configured": bool(shodan_key),
            "enabled": bool(shodan_key),
            "status": "ativo" if shodan_key else "desativado",
        },
    }


@router.post("/config/tools/install-one")
def install_tool(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    tool = str(payload.get("tool") or "").strip().lower()
    if not tool:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tool obrigatorio")

    already_installed = _tool_installed(tool)
    installed = already_installed or _install_tool(tool)

    log_audit(
        db,
        event_type="tools.install_attempt",
        message=f"Instalacao de tool solicitada: {tool}",
        actor_user_id=current_user.id,
        level="INFO" if installed else "WARNING",
        metadata={"tool": tool, "installed": installed, "already_installed": already_installed},
    )
    db.commit()

    return {"ok": installed, "tool": tool, "installed": installed, "already_installed": already_installed}


@router.get("/config/nessus")
def get_nessus_config(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    enabled = _get_setting(db, current_user.id, "nessus_enabled", "false") == "true"
    url = _get_setting(db, current_user.id, "nessus_url", "")
    access_key = _get_setting(db, current_user.id, "nessus_access_key", "")
    secret_key = _get_setting(db, current_user.id, "nessus_secret_key", "")
    verify_tls = _get_setting(db, current_user.id, "nessus_verify_tls", "true") == "true"

    return {
        "enabled": enabled,
        "url": url,
        "access_key": access_key,
        "secret_key": "***" if secret_key else "",
        "verify_tls": verify_tls,
        "configured": bool(url and access_key and secret_key),
        "pynessus_installed": _tool_installed("nessus"),
    }


@router.put("/config/nessus")
def save_nessus_config(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    enabled = _parse_bool(payload, "enabled", False)
    url = str(payload.get("url") or "").strip()
    access_key = str(payload.get("access_key") or "").strip()
    secret_key = str(payload.get("secret_key") or "").strip()
    verify_tls = _parse_bool(payload, "verify_tls", True)

    _set_setting(db, current_user.id, "nessus_enabled", "true" if enabled else "false")
    _set_setting(db, current_user.id, "nessus_url", url)
    if access_key:
        _set_setting(db, current_user.id, "nessus_access_key", access_key)
    if secret_key and secret_key != "***":
        _set_setting(db, current_user.id, "nessus_secret_key", secret_key)
    _set_setting(db, current_user.id, "nessus_verify_tls", "true" if verify_tls else "false")
    db.commit()

    return {"ok": True}


@router.get("/config/burp")
def get_burp_config(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    enabled = _get_setting(db, current_user.id, "burp_enabled", "false") == "true"
    license_key = _get_setting(db, current_user.id, "burp_license_key", "")
    return {
        "enabled": enabled,
        "license_key": f"***{license_key[-4:]}" if license_key else "",
        "configured": bool(license_key),
        "burp_cli_installed": _tool_installed("burp-cli"),
    }


@router.put("/config/burp")
def save_burp_config(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    enabled = _parse_bool(payload, "enabled", False)
    license_key = str(payload.get("license_key") or "").strip()

    _set_setting(db, current_user.id, "burp_enabled", "true" if enabled else "false")
    if license_key and not license_key.startswith("***"):
        _set_setting(db, current_user.id, "burp_license_key", license_key)
    db.commit()
    return {"ok": True}


@router.get("/config/burp/scans")
def get_burp_scans(current_user: User = Depends(require_admin)):
    raw_output = _burp_cli_list_scans_output()
    scans = _parse_burp_cli_list_output(raw_output)

    by_status: dict[str, int] = {
        "running": 0,
        "auditing": 0,
        "paused": 0,
        "succeeded": 0,
        "failed": 0,
        "cancelled": 0,
    }
    for scan in scans:
        st = str(scan.get("status") or "").lower()
        if st in by_status:
            by_status[st] += 1

    return {
        "total": len(scans),
        "status_counts": by_status,
        "scans": scans,
        "api_host": _burp_api_host(),
        "api_port": _burp_api_port(),
    }


@router.post("/config/burp/scans/actions")
def burp_scans_actions(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    action = str(payload.get("action") or "").strip().lower()
    scan_ids_payload = payload.get("scan_ids") or []
    only_active = bool(payload.get("only_active", False))

    if action not in {"cancel", "remove", "cancel_and_remove"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="acao invalida")

    known_scans = _parse_burp_cli_list_output(_burp_cli_list_scans_output())
    known_ids = {str(item.get("id") or "").strip() for item in known_scans}
    active_ids = {
        str(item.get("id") or "").strip()
        for item in known_scans
        if str(item.get("status") or "").strip().lower() in {"running", "auditing", "paused"}
    }

    requested_ids = [str(v).strip() for v in scan_ids_payload if str(v).strip()]
    if not requested_ids:
        requested_ids = sorted(active_ids if only_active else known_ids)

    scan_ids = [sid for sid in requested_ids if sid in known_ids]

    results: list[dict[str, object]] = []
    for scan_id in scan_ids:
        row: dict[str, object] = {"scan_id": scan_id, "cancel": None, "remove": None}

        if action in {"cancel", "cancel_and_remove"}:
            ok, code, _ = _burp_api_call("POST", f"/scan/{scan_id}/cancel")
            row["cancel"] = {"ok": ok, "code": code}

        if action in {"remove", "cancel_and_remove"}:
            ok, code, _ = _burp_api_call("DELETE", f"/scan/{scan_id}")
            row["remove"] = {"ok": ok, "code": code}

        results.append(row)

    removed_history_count = 0
    if action in {"remove", "cancel_and_remove"}:
        removable_ids = [
            str(item.get("scan_id") or "").strip()
            for item in results
            if isinstance(item.get("remove"), dict)
            and bool(item.get("remove", {}).get("ok"))
            and int(item.get("remove", {}).get("code") or 0) in {200, 202, 204, 404}
        ]
        removed_history_count = _prune_burp_cli_history(removable_ids)

    # Mantem o tracker local consistente para o -L
    refresh_output = _burp_cli_list_scans_output()
    refresh_scans = _parse_burp_cli_list_output(refresh_output)

    log_audit(
        db,
        event_type="burp.scans.action",
        message=f"Acao em scans Burp: {action}",
        actor_user_id=current_user.id,
        metadata={
            "action": action,
            "requested": requested_ids,
            "applied": scan_ids,
            "results": results,
            "removed_history_count": removed_history_count,
        },
    )
    db.commit()

    return {
        "ok": True,
        "action": action,
        "requested": requested_ids,
        "applied": scan_ids,
        "results": results,
        "removed_history_count": removed_history_count,
        "remaining_total": len(refresh_scans),
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
    return {
        "unit": UNIT_WORKER_GROUPS,
        "scheduled": SCHEDULED_WORKER_GROUPS,
        "agents": {
            "unit": get_worker_agent_profiles("unit"),
            "scheduled": get_worker_agent_profiles("scheduled"),
        },
    }


@router.get("/worker-manager/pipeline")
def worker_manager_pipeline(current_user: User = Depends(require_admin)):
    """Retorna pipeline supervisor-centric e agentes operacionais mapeados."""
    unit_agents = get_worker_agent_profiles("unit")

    pipeline_agents = [
        {
            "id": "supervisor",
            "name": "Supervisor",
            "internal_only": True,
            "purpose": "Planeja, roteia capacidades e aplica contratos de validação/evidência.",
            "tools": ["supervisor", "strategic_planning", "evidence_adjudication"],
            "queue": None,
        },
        {
            "id": unit_agents["reconhecimento"]["agent_id"],
            "name": unit_agents["reconhecimento"]["agent_name"],
            "internal_only": False,
            "purpose": unit_agents["reconhecimento"]["purpose"],
            "tools": unit_agents["reconhecimento"]["tools"],
            "queue": unit_agents["reconhecimento"]["queue"],
        },
        {
            "id": unit_agents["analise_vulnerabilidade"]["agent_id"],
            "name": unit_agents["analise_vulnerabilidade"]["agent_name"],
            "internal_only": False,
            "purpose": unit_agents["analise_vulnerabilidade"]["purpose"],
            "tools": unit_agents["analise_vulnerabilidade"]["tools"],
            "queue": unit_agents["analise_vulnerabilidade"]["queue"],
        },
        {
            "id": unit_agents["osint"]["agent_id"],
            "name": unit_agents["osint"]["agent_name"],
            "internal_only": False,
            "purpose": unit_agents["osint"]["purpose"],
            "tools": unit_agents["osint"]["tools"],
            "queue": unit_agents["osint"]["queue"],
        },
    ]

    return {
        "architecture": "supervisor_centric",
        "linear_flow": ["supervisor", "agent.recon", "agent.vuln", "agent.osint", "END"],
        "edges": [
            {"from": "supervisor", "to": "agent.recon"},
            {"from": "supervisor", "to": "agent.vuln"},
            {"from": "supervisor", "to": "agent.osint"},
            {"from": "agent.recon", "to": "supervisor"},
            {"from": "agent.vuln", "to": "supervisor"},
            {"from": "agent.osint", "to": "supervisor"},
            {"from": "supervisor", "to": "END"},
        ],
        "agents": pipeline_agents,
        "mission_items_full": MISSION_ITEMS,
        "total_mission_items": len(MISSION_ITEMS),
    }


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
        for metric in metrics:
            node = str(metric.get("node", "unknown"))
            duration = float(metric.get("duration_ms", 0))
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
        "worker_groups": {
            "unit": UNIT_WORKER_GROUPS,
            "scheduled": SCHEDULED_WORKER_GROUPS,
            "agents": {
                "unit": get_worker_agent_profiles("unit"),
                "scheduled": get_worker_agent_profiles("scheduled"),
            },
        },
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


LEGACY_SUPERVISOR_WORKER_NODES = {"recon", "scan", "fuzzing", "vuln", "analista_ia", "osint"}
SENIOR_ANALYST_PIPELINE = [
    "supervisor",
    "strategic_planning",
    "asset_discovery",
    "threat_intel",
    "adversarial_hypothesis",
    "risk_assessment",
    "evidence_adjudication",
    "governance",
    "executive_analyst",
]


def _validate_supervisor_path(node_history: list[str]) -> dict:
    if not node_history:
        return {
            "valid": False,
            "starts_with_supervisor": False,
            "has_osint_node": False,
            "invalid_edges": [],
            "transitions": [],
        }

    transitions: list[str] = []
    invalid_edges: list[str] = []
    starts_with_supervisor = node_history[0] == "supervisor"
    has_osint_node = "osint" in node_history
    starts_with_framework = node_history[0] == "supervisor"

    senior_capabilities = {
        "asset_discovery",
        "threat_intel",
        "adversarial_hypothesis",
        "risk_assessment",
        "evidence_adjudication",
        "governance",
        "executive_analyst",
    }

    framework_detected = "legacy-supervisor"
    senior_capabilities_only = set(SENIOR_ANALYST_PIPELINE[1:])
    if any(node in senior_capabilities_only for node in node_history):
        framework_detected = "senior-analyst"

    for idx in range(len(node_history) - 1):
        src = str(node_history[idx])
        dst = str(node_history[idx + 1])
        edge = f"{src}->{dst}"
        transitions.append(edge)

        if framework_detected == "senior-analyst":
            if src == "supervisor":
                if dst not in senior_capabilities:
                    invalid_edges.append(edge)
                continue
            if src in senior_capabilities:
                if dst not in {"supervisor"}:
                    invalid_edges.append(edge)
                continue
            invalid_edges.append(edge)
            continue

        if src == "supervisor":
            if dst not in LEGACY_SUPERVISOR_WORKER_NODES:
                invalid_edges.append(edge)
            continue

        if src in LEGACY_SUPERVISOR_WORKER_NODES:
            if dst != "supervisor":
                invalid_edges.append(edge)
            continue

        invalid_edges.append(edge)

    return {
        "valid": (
            (framework_detected == "senior-analyst" and starts_with_framework and len(invalid_edges) == 0)
            or (framework_detected != "senior-analyst" and starts_with_supervisor and len(invalid_edges) == 0)
        ),
        "starts_with_supervisor": starts_with_supervisor,
        "has_osint_node": has_osint_node,
        "starts_with_framework": starts_with_framework,
        "framework_detected": framework_detected,
        "invalid_edges": invalid_edges,
        "transitions": transitions,
    }


@router.get("/worker-manager/supervisor-trail")
def worker_manager_supervisor_trail(
    scan_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=20, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(ScanJob)
    if scan_id is not None:
        query = query.filter(ScanJob.id == scan_id)

    scans = query.order_by(ScanJob.created_at.desc()).limit(limit).all()
    items: list[dict] = []
    valid_count = 0
    osint_count = 0

    for scan in scans:
        state = scan.state_data or {}
        node_history = [str(n) for n in (state.get("node_history") or [])]
        logs = [str(line) for line in (state.get("logs_terminais") or [])]
        supervisor_logs = [line for line in logs if line.startswith("Supervisor:")]

        validation = _validate_supervisor_path(node_history)
        if validation["valid"]:
            valid_count += 1
        if validation["has_osint_node"]:
            osint_count += 1

        items.append(
            {
                "scan_id": scan.id,
                "target_query": scan.target_query,
                "status": scan.status,
                "mode": scan.mode,
                "created_at": scan.created_at,
                "updated_at": scan.updated_at,
                "validation": validation,
                "node_history": node_history,
                "supervisor_logs": supervisor_logs,
            }
        )

    return {
        "summary": {
            "scans_analyzed": len(scans),
            "valid_supervisor_flow": valid_count,
            "invalid_supervisor_flow": max(0, len(scans) - valid_count),
            "scans_with_osint_node": osint_count,
            "scans_without_osint_node": max(0, len(scans) - osint_count),
            "required_worker_nodes": sorted(LEGACY_SUPERVISOR_WORKER_NODES),
            "senior_analyst_pipeline": SENIOR_ANALYST_PIPELINE,
        },
        "scans": items,
    }


def _extract_scan_id(task: dict) -> int | None:
    kwargs = task.get("kwargs") or {}
    if isinstance(kwargs, dict) and "scan_id" in kwargs:
        try:
            return int(kwargs.get("scan_id"))
        except (TypeError, ValueError):
            return None

    args = task.get("args")
    if isinstance(args, (list, tuple)) and args:
        try:
            return int(args[0])
        except (TypeError, ValueError):
            return None

    # Alguns brokers serializam args como string "(123,)".
    if isinstance(args, str):
        digits = "".join(ch for ch in args if ch.isdigit())
        if digits:
            try:
                return int(digits)
            except ValueError:
                return None
    return None


def _active_scan_ids() -> tuple[dict[str, set[int]], bool]:
    inspector = celery.control.inspect(timeout=1.5)
    active = inspector.active()
    if active is None:
        return {"unit": set(), "scheduled": set()}, False

    result = {"unit": set(), "scheduled": set()}
    for _, tasks in active.items():
        for task in tasks or []:
            name = str(task.get("name") or "")
            scan_id = _extract_scan_id(task)
            if scan_id is None:
                continue
            if name == "run_scan_job_unit":
                result["unit"].add(scan_id)
            elif name == "run_scan_job_scheduled":
                result["scheduled"].add(scan_id)
    return result, True


def _phase_from_task_name(task_name: str | None) -> str:
    value = str(task_name or "").strip().lower()
    if ".reconhecimento." in value or "recon" in value:
        return "reconhecimento"
    if ".analise_vulnerabilidade." in value or "vulnerab" in value or "vuln" in value:
        return "analise_vulnerabilidade"
    if ".osint." in value or "osint" in value:
        return "osint"
    return "desconhecido"


def _phase_from_scan(scan: ScanJob | None) -> str:
    if not scan:
        return "desconhecido"

    state = scan.state_data or {}
    node_history = [str(n or "").strip().lower() for n in (state.get("node_history") or []) if str(n or "").strip()]
    current_step = str(scan.current_step or "").strip().lower()

    if node_history:
        last_node = node_history[-1]
        if last_node in {"recon", "scan", "fingerprint", "crawler"}:
            return "reconhecimento"
        if last_node in {"vuln", "fuzzing", "api", "code_js"}:
            return "analise_vulnerabilidade"
        if last_node == "osint":
            return "osint"

    if any(token in current_step for token in ["recon", "subdomain", "dns", "asset", "scan de superficie", "amass", "subfinder", "naabu", "nmap"]):
        return "reconhecimento"
    if any(token in current_step for token in ["vulnerab", "vuln", "nikto", "wapiti", "waf", "sslscan", "dalfox"]):
        return "analise_vulnerabilidade"
    if any(token in current_step for token in ["osint", "theharvester", "h8mail", "metagoofil", "urlscan", "shodan"]):
        return "osint"

    return "desconhecido"


@router.get("/worker-manager/health")
def worker_manager_health(
    stale_after_seconds: int | None = Query(default=None, ge=10, le=3600),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if stale_after_seconds is None:
        stale_after_seconds = _setting_int(db, current_user.id, "worker_health_stale_after_seconds", 60, 10, 3600)

    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=stale_after_seconds)

    active_scan_ids, inspect_ok = _active_scan_ids()
    active_unit = active_scan_ids.get("unit", set())
    active_scheduled = active_scan_ids.get("scheduled", set())

    active_scan_union = set(active_unit) | set(active_scheduled)
    active_scan_map: dict[int, ScanJob] = {}
    if active_scan_union:
        scan_rows = db.query(ScanJob).filter(ScanJob.id.in_(list(active_scan_union))).all()
        active_scan_map = {row.id: row for row in scan_rows}

    rows = db.query(WorkerHeartbeat).order_by(WorkerHeartbeat.last_seen_at.desc()).all()

    heartbeat_scan_ids = {int(row.current_scan_id) for row in rows if row.current_scan_id is not None}
    linked_scan_map: dict[int, ScanJob] = {}
    if heartbeat_scan_ids:
        linked_rows = db.query(ScanJob).filter(ScanJob.id.in_(list(heartbeat_scan_ids))).all()
        linked_scan_map = {row.id: row for row in linked_rows}

    workers = []
    online_count = 0
    phase_counts = {"reconhecimento": 0, "analise_vulnerabilidade": 0, "osint": 0, "desconhecido": 0}

    for row in rows:
        heartbeat_online = bool(row.last_seen_at and row.last_seen_at >= cutoff)

        running_scan = None
        if row.current_scan_id:
            running_scan = active_scan_map.get(row.current_scan_id) or linked_scan_map.get(row.current_scan_id)

        scan_indicates_alive = False
        if running_scan and str(row.status or "").lower() in {"busy", "alive", "running"}:
            scan_updated_at = running_scan.updated_at or running_scan.created_at
            if scan_updated_at and scan_updated_at >= (now - timedelta(seconds=max(120, stale_after_seconds * 5))):
                if str(running_scan.status or "").lower() in {"queued", "running", "retrying"}:
                    scan_indicates_alive = True

        online = bool(heartbeat_online or scan_indicates_alive)
        online_count += 1 if online else 0

        task_phase = _phase_from_task_name(row.last_task_name)
        scan_phase = _phase_from_scan(running_scan)
        execution_phase = scan_phase if scan_phase != "desconhecido" else task_phase
        if execution_phase not in phase_counts:
            execution_phase = "desconhecido"
        phase_counts[execution_phase] += 1

        last_seen_lag_seconds = None
        if row.last_seen_at:
            last_seen_lag_seconds = max(0, int((now - row.last_seen_at).total_seconds()))

        workers.append(
            {
                "worker_name": row.worker_name,
                "mode": row.mode,
                "status": row.status,
                "current_scan_id": row.current_scan_id,
                "last_task_name": row.last_task_name,
                "last_seen_at": row.last_seen_at,
                "online": online,
                "online_reason": "heartbeat" if heartbeat_online else ("active_scan" if scan_indicates_alive else "stale"),
                "execution_phase": execution_phase,
                "execution_phase_from_task": task_phase,
                "execution_phase_from_scan": scan_phase,
                "last_seen_lag_seconds": last_seen_lag_seconds,
                "active_scan": {
                    "id": running_scan.id,
                    "target_query": running_scan.target_query,
                    "mode": running_scan.mode,
                    "status": running_scan.status,
                    "current_step": running_scan.current_step,
                }
                if running_scan
                else None,
            }
        )

    return {
        "summary": {
            "total_workers": len(rows),
            "online_workers": online_count,
            "offline_workers": max(0, len(rows) - online_count),
            "stale_after_seconds": stale_after_seconds,
            "inspect_ok": inspect_ok,
            "phase_counts": phase_counts,
        },
        "workers": workers,
    }


@router.post("/worker-manager/requeue-orphans")
def requeue_orphan_scans(
    payload: dict | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Recoloca em fila scans com status=running sem task ativa correspondente.

    payload:
      - older_than_seconds (int, default=300)
      - limit (int, default=100)
      - dry_run (bool, default=true)
    """
    body = payload or {}
    default_cutoff_minutes = _setting_int(db, current_user.id, "worker_orphan_cutoff_minutes", 8, 1, 180)
    default_requeue_limit = _setting_int(db, current_user.id, "worker_orphan_requeue_limit", 100, 1, 2000)

    older_than_seconds = int(body.get("older_than_seconds", default_cutoff_minutes * 60))
    limit = int(body.get("limit", default_requeue_limit))
    dry_run = bool(body.get("dry_run", True))

    if older_than_seconds < 30:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="older_than_seconds deve ser >= 30")

    cutoff = datetime.utcnow() - timedelta(seconds=older_than_seconds)
    active_by_mode, inspect_ok = _active_scan_ids()
    if not inspect_ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nao foi possivel consultar workers ativos no Celery inspect",
        )

    candidates = (
        db.query(ScanJob)
        .filter(ScanJob.status == "running", ScanJob.updated_at < cutoff)
        .order_by(ScanJob.updated_at.asc())
        .limit(limit)
        .all()
    )

    orphan_ids: list[int] = []
    requeued_ids: list[int] = []
    skipped_active: list[int] = []

    for job in candidates:
        mode = "scheduled" if job.mode == "scheduled" else "unit"
        if job.id in active_by_mode[mode]:
            skipped_active.append(job.id)
            continue

        orphan_ids.append(job.id)
        if dry_run:
            continue

        job.status = "queued"
        job.current_step = "Reenfileirado por reconciliacao de orfao"
        db.add(
            ScanLog(
                scan_job_id=job.id,
                source="worker-manager",
                level="WARNING",
                message="Scan running sem worker ativo detectado; reenfileirando automaticamente",
            )
        )
        if mode == "scheduled":
            run_scan_job_scheduled.delay(job.id)
        else:
            run_scan_job_unit.delay(job.id)
        requeued_ids.append(job.id)

    log_audit(
        db,
        event_type="worker_manager.requeue_orphans",
        message="Reconciliacao de scans orfaos executada",
        actor_user_id=current_user.id,
        metadata={
            "dry_run": dry_run,
            "older_than_seconds": older_than_seconds,
            "candidates": [j.id for j in candidates],
            "orphans": orphan_ids,
            "requeued": requeued_ids,
            "skipped_active": skipped_active,
        },
    )
    db.commit()

    return {
        "ok": True,
        "dry_run": dry_run,
        "older_than_seconds": older_than_seconds,
        "candidates": len(candidates),
        "orphans": orphan_ids,
        "requeued": requeued_ids,
        "skipped_active": skipped_active,
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

    if "email" in payload:
        email = str(payload.get("email") or "").strip().lower()
        if not email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email obrigatorio")
        exists = db.query(User).filter(User.email == email, User.id != user_id).first()
        if exists:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email ja cadastrado")
        user.email = email

    if "is_admin" in payload:
        if user.id == current_user.id and not bool(payload["is_admin"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nao e permitido remover seu proprio perfil admin")
        user.is_admin = bool(payload["is_admin"])
    if "is_active" in payload:
        if user.id == current_user.id and not bool(payload["is_active"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nao e permitido desativar seu proprio usuario")
        user.is_active = bool(payload["is_active"])
    if "group_ids" in payload:
        group_ids = payload.get("group_ids") or []
        groups = db.query(AccessGroup).filter(AccessGroup.id.in_(group_ids)).all()
        user.groups = groups

    db.commit()
    return {"ok": True}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario nao encontrado")
    if user.id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nao e permitido excluir seu proprio usuario")

    admins_count = db.query(User).filter(User.is_admin.is_(True)).count()
    if user.is_admin and admins_count <= 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nao e permitido excluir o ultimo administrador")

    db.delete(user)
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
