from datetime import datetime, timedelta, timezone
import csv
import io
import json
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.models import AuditEvent, FalsePositiveMemory, Finding, ScanAuthorization, ScanJob, ScanLog, User
from app.models.models import WorkerHeartbeat
from app.schemas.scan import LogResponse, ReportResponse, ScanCreate, ScanResponse, ScanStatusResponse
from app.services.audit_service import log_audit
from app.services.chroma_service import FalsePositiveVectorStore
from app.services.policy_service import is_target_allowed
from app.services.risk_service import build_priority_reason, compute_age_metrics, compute_fair_metrics
from app.workers.celery_app import celery
from app.workers.tasks import run_scan_job, run_scan_job_unit


router = APIRouter(prefix="/api", tags=["scans"])
vector_store = FalsePositiveVectorStore()


def _extract_scan_id_from_task(task: dict) -> int | None:
    kwargs = task.get("kwargs")
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

    if isinstance(args, str):
        digits = "".join(ch for ch in args if ch.isdigit())
        if digits:
            try:
                return int(digits)
            except ValueError:
                return None
    return None


def _active_scan_task_ids(scan_id: int) -> list[str]:
    inspector = celery.control.inspect(timeout=1.5)
    buckets = [inspector.active() or {}, inspector.reserved() or {}, inspector.scheduled() or {}]
    task_ids: list[str] = []
    for tasks_by_worker in buckets:
        for _, tasks in tasks_by_worker.items():
            for task in tasks or []:
                name = str(task.get("name") or "")
                if name not in {"run_scan_job_unit", "run_scan_job_scheduled"}:
                    continue
                resolved_scan_id = _extract_scan_id_from_task(task)
                if resolved_scan_id != scan_id:
                    continue
                task_id = str(task.get("id") or "").strip()
                if task_id:
                    task_ids.append(task_id)
    return list(dict.fromkeys(task_ids))


def _reconcile_orphan_running_scans(db: Session) -> int:
    inspector = celery.control.inspect(timeout=1.5)
    active = inspector.active()
    if active is None:
        return 0

    active_scan_ids: set[int] = set()
    for _, tasks in active.items():
        for task in tasks or []:
            if str(task.get("name") or "") not in {"run_scan_job_unit", "run_scan_job_scheduled"}:
                continue
            scan_id = _extract_scan_id_from_task(task)
            if scan_id is not None:
                active_scan_ids.add(scan_id)

    cutoff = datetime.utcnow() - timedelta(minutes=10)
    stale_rows = (
        db.query(ScanJob)
        .filter(ScanJob.status.in_(["running", "retrying"]), ScanJob.updated_at < cutoff)
        .all()
    )

    fixed = 0
    for row in stale_rows:
        if row.id in active_scan_ids:
            continue
        row.status = "failed"
        row.current_step = "Scan encerrado por reconciliacao de orfao"
        row.last_error = "Scan marcado como falho por estar running sem task ativa no worker"
        row.next_retry_at = None
        db.add(
            ScanLog(
                scan_job_id=row.id,
                source="reconciler",
                level="WARNING",
                message="Scan running/retrying sem task ativa; status corrigido para failed",
            )
        )
        fixed += 1

    if fixed:
        db.commit()
    return fixed


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


def _sanitize_text(value: str | None) -> str:
    if not value:
        return ""
    ansi_pattern = re.compile(r"\x1b\[[0-9;]*m")
    sanitized = ansi_pattern.sub("", str(value))
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized


def _normalize_finding_title(value: str | None) -> str:
    title = _sanitize_text(value)
    lowered = title.lower()
    for prefix in ["nuclei:", "nuclei -", "nikto:", "ffuf:"]:
        if lowered.startswith(prefix):
            title = title[len(prefix):].strip(" -:")
            break
    return title or "Vulnerabilidade sem titulo"


def _normalize_recommendation(details: dict) -> str:
    rec = _extract_recommendation_payload(details)
    mitigacoes = rec.get("mitigacoes") or []
    if mitigacoes:
        return _sanitize_text("; ".join(str(m) for m in mitigacoes[:3] if str(m).strip()))
    if rec.get("resumo"):
        return _sanitize_text(str(rec.get("resumo")))

    severity = str((details or {}).get("severity") or "").lower()
    if severity == "critical":
        return "Aplicar mitigacao imediata, corrigir configuracao e validar por reteste priorizado."
    if severity == "high":
        return "Corrigir nesta sprint, aplicar hardening e validar com novo scan."
    if severity == "medium":
        return "Planejar correcao em curto prazo e monitorar exposicao residual."
    return "Registrar no backlog de seguranca, corrigir e confirmar por reteste."


def _extract_ports_from_text(value: str | None) -> set[int]:
    text = str(value or "")
    ports: set[int] = set()

    for match in re.finditer(r"porta\s+(\d{1,5})", text, re.IGNORECASE):
        try:
            port = int(match.group(1))
        except Exception:
            continue
        if 1 <= port <= 65535:
            ports.add(port)

    for match in re.finditer(r":(\d{1,5})\b", text):
        try:
            port = int(match.group(1))
        except Exception:
            continue
        if 1 <= port <= 65535:
            ports.add(port)

    return ports


def _build_top_recommendations(vulnerability_rows: list[dict], recommendations: list[dict]) -> list[dict]:
    top: list[dict] = []
    seen: set[str] = set()
    all_ports: set[int] = set()

    for row in vulnerability_rows or []:
        for field in [
            row.get("name"),
            row.get("problem"),
            row.get("target"),
            row.get("error"),
            row.get("recommendation"),
        ]:
            all_ports.update(_extract_ports_from_text(str(field or "")))

    if all_ports:
        ports = ",".join(str(p) for p in sorted(all_ports)[:20])
        top.append(
            {
                "id": "R-PORTS",
                "name": "Exposicao de portas externas",
                "recommendation": f"Desabilitar porta {ports}. Manter somente portas estritamente necessarias com filtro de origem e segmentacao.",
                "kind": "consolidated",
            }
        )
        seen.add(f"ports:{ports}")

    for rec in recommendations or []:
        text = _sanitize_text(rec.get("recommendation") or "")
        if not text:
            continue
        normalized = re.sub(r"\s+", " ", text).strip().lower()[:220]
        if normalized in seen:
            continue
        seen.add(normalized)
        top.append(
            {
                "id": _sanitize_text(rec.get("id") or f"R-{len(top) + 1}"),
                "name": _sanitize_text(rec.get("name") or "Correcao recomendada"),
                "recommendation": text,
                "kind": "consolidated",
            }
        )
        if len(top) >= 5:
            break

    return top[:5]


def _build_strategic_points(
    target: str,
    summary: dict[str, int],
    fair_total: dict[str, float],
    lifecycle: dict[str, int],
    category_scores: list[dict],
) -> list[str]:
    points: list[str] = []
    open_count = int(summary.get("open") or 0)
    critical = int(summary.get("critical") or 0)
    high = int(summary.get("high") or 0)
    corrected = int(lifecycle.get("corrected") or 0)
    ale_open = float(fair_total.get("ale_total_open_usd") or 0.0)

    points.append(
        f"Risco atual do alvo {target}: {open_count} vulnerabilidades abertas, com {critical} criticas e {high} altas exigindo prioridade executiva."
    )
    points.append(
        f"Exposicao financeira anual estimada (ALE aberto): USD {ale_open:,.0f}. Recomendado tratar como meta de reducao trimestral com dono e prazo definidos."
    )
    if corrected > 0:
        points.append(
            f"Evolucao positiva detectada: {corrected} vulnerabilidades nao reapareceram no re-scan. Manter cadencia de validacao para evitar reabertura de risco."
        )

    weak_categories = sorted(category_scores, key=lambda item: item.get("score", 100))[:2]
    if weak_categories:
        categories = ", ".join(str(item.get("category") or "-") for item in weak_categories)
        points.append(
            f"Prioridade de governanca: reforcar controles nas categorias com menor pontuacao ({categories}), com acompanhamento no comite de seguranca."
        )

    return points[:5]


def _build_technical_points(vulnerability_rows: list[dict], recommendations: list[dict]) -> list[str]:
    points: list[str] = []
    seen: set[str] = set()

    ports: set[int] = set()
    for row in vulnerability_rows:
        for field in [row.get("target"), row.get("name"), row.get("problem"), row.get("error"), row.get("recommendation")]:
            ports.update(_extract_ports_from_text(str(field or "")))
    if ports:
        ports_list = ",".join(str(p) for p in sorted(ports)[:20])
        points.append(
            f"Rede: desabilitar porta {ports_list} quando nao houver justificativa de negocio; aplicar ACL por origem e segmentacao por ambiente."
        )
        seen.add(f"ports:{ports_list}")

    for rec in recommendations or []:
        text = _sanitize_text(rec.get("recommendation") or "")
        if not text:
            continue
        normalized = text.lower()[:220]
        if normalized in seen:
            continue
        seen.add(normalized)
        points.append(f"Aplicacao: {text}")
        if len(points) >= 8:
            break

    if not points:
        points.append("Sem recomendacoes tecnicas disponiveis para este scan.")
    return points[:8]


def _try_parse_json_dict(value) -> dict | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _extract_recommendation_payload(details: dict) -> dict[str, object]:
    details = details if isinstance(details, dict) else {}
    candidates = [
        details.get("qwen_recomendacao_pt"),
        details.get("cloudcode_recomendacao_pt"),
    ]
    for candidate in candidates:
        parsed = _try_parse_json_dict(candidate)
        if not parsed:
            continue
        mitigacoes = parsed.get("mitigacoes")
        if not isinstance(mitigacoes, list):
            mitigacoes = []
        validacoes = parsed.get("validacoes")
        if not isinstance(validacoes, list):
            validacoes = []
        return {
            "resumo": _sanitize_text(parsed.get("resumo") or ""),
            "impacto": _sanitize_text(parsed.get("impacto") or ""),
            "mitigacoes": [_sanitize_text(str(item)) for item in mitigacoes if _sanitize_text(str(item))],
            "prioridade": _sanitize_text(parsed.get("prioridade") or ""),
            "validacoes": [_sanitize_text(str(item)) for item in validacoes if _sanitize_text(str(item))],
        }

    # fallback simples para texto cru quando IA nao devolve JSON
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return {
                "resumo": _sanitize_text(candidate),
                "impacto": "",
                "mitigacoes": [],
                "prioridade": "",
                "validacoes": [],
            }

    return {
        "resumo": "",
        "impacto": "",
        "mitigacoes": [],
        "prioridade": "",
        "validacoes": [],
    }


def _pick_first_text(details: dict, keys: list[str]) -> str:
    for key in keys:
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            return _sanitize_text(value)
    return ""


def _extract_technical_details(details: dict, default_target: str) -> dict[str, str]:
    details = details if isinstance(details, dict) else {}
    full_url = _pick_first_text(details, ["url", "full_url", "endpoint", "target", "asset"])
    if not full_url:
        full_url = _sanitize_text(default_target)

    exploit = _pick_first_text(details, ["exploit", "exploit_url", "exploitdb", "exploitdb_url", "poc", "payload"])
    error = _pick_first_text(details, ["error", "stderr", "exception", "message", "http_error", "status_code"])
    evidence = _pick_first_text(details, ["evidence", "stdout", "output", "matched", "matched_at", "response"])

    return {
        "full_url": full_url,
        "exploit": exploit,
        "error": error,
        "evidence": evidence,
    }


CATEGORY_ORDER = [
    "Software Patching",
    "Application Security",
    "Web Encryption",
    "Network Filtering",
    "Authentication",
    "Authorization",
    "Data Exposure",
    "DNS Security",
    "System Hosting",
]


def _infer_category(title: str, details: dict) -> str:
    blob = " ".join(
        [
            str(title or ""),
            str(details.get("service") or ""),
            str(details.get("protocol") or ""),
            str(details.get("url") or details.get("target") or ""),
            str(details.get("error") or details.get("stderr") or ""),
            str(details.get("output") or ""),
        ]
    ).lower()

    if any(k in blob for k in ["tls", "ssl", "cipher", "https", "hsts", "certificate"]):
        return "Web Encryption"
    if any(k in blob for k in ["dns", "subdomain takeover", "subdomain", "cname", "ns ", "mx "]):
        return "DNS Security"
    if any(k in blob for k in ["auth", "login", "jwt", "token", "session", "password", "credential"]):
        return "Authentication"
    if any(k in blob for k in ["idor", "forbidden", "403", "access control", "authorization", "privilege"]):
        return "Authorization"
    if any(k in blob for k in ["open port", "nmap", "naabu", "firewall", "exposed service", "waf"]):
        return "Network Filtering"
    if any(k in blob for k in ["xss", "sqli", "sql", "ssti", "rce", "xxe", "csrf", "command injection", "template"]):
        return "Application Security"
    if any(k in blob for k in ["cve", "version", "outdated", "vuln", "patch", "upgrade"]):
        return "Software Patching"
    if any(k in blob for k in ["secret", "leak", "exposure", "directory listing", "bucket", "metadata"]):
        return "Data Exposure"
    if any(k in blob for k in ["hosting", "server", "docker", "kubernetes", "cloud", "misconfig"]):
        return "System Hosting"

    return "Application Security"


def _build_category_scores(rows: list[dict]) -> list[dict]:
    sev_weight = {"critical": 20, "high": 12, "medium": 7, "low": 3, "info": 1}
    aggregate: dict[str, dict[str, int]] = {category: {"findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_points": 0} for category in CATEGORY_ORDER}

    for row in rows:
        category = row.get("category") or "Application Security"
        sev = str(row.get("severity") or "low").lower()
        if category not in aggregate:
            aggregate[category] = {"findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_points": 0}
        aggregate[category]["findings"] += 1
        if sev in aggregate[category]:
            aggregate[category][sev] += 1
        aggregate[category]["risk_points"] += sev_weight.get(sev, 1)

    results: list[dict] = []
    for category in CATEGORY_ORDER:
        item = aggregate.get(category)
        if not item:
            continue
        score = max(0, 100 - min(95, int(item["risk_points"] * 3)))
        results.append({"category": category, "score": score, **item})
    return results


def _finding_signature(title: str, severity: str, target: str) -> str:
    return "|".join(
        [
            _sanitize_text(title).lower(),
            _sanitize_text(severity).lower(),
            _sanitize_text(target).lower(),
        ]
    )


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


def _append_technology(counter: dict[str, int], value) -> None:
    if isinstance(value, str):
        name = value.strip()
        if len(name) >= 2:
            counter[name] = counter.get(name, 0) + 1
        return
    if isinstance(value, list):
        for item in value:
            _append_technology(counter, item)
        return
    if isinstance(value, dict):
        preferred_keys = [
            "name", "product", "technology", "tech", "server", "framework", "cms", "vendor",
            "technologies", "stack", "web_server", "x_powered_by",
        ]
        for key in preferred_keys:
            if key in value:
                _append_technology(counter, value[key])


def _collect_technologies(job: ScanJob, scan_findings: list[Finding]) -> dict[str, int]:
    counter: dict[str, int] = {}
    state = job.state_data or {}
    for key in ["technologies", "technology", "tech", "tech_stack", "stack", "fingerprint", "fingerprints"]:
        if key in state:
            _append_technology(counter, state.get(key))
    for finding in scan_findings:
        details = finding.details or {}
        for key in ["technologies", "technology", "tech", "tech_stack", "stack", "server", "web_server", "x_powered_by", "framework", "cms"]:
            if key in details:
                _append_technology(counter, details.get(key))
    return counter


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
    _reconcile_orphan_running_scans(db)
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


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    if job.status in {"queued", "running", "retrying"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nao e permitido excluir scan em execucao")

    # Limpar referências de audit_events antes de deletar o scan
    db.query(AuditEvent).filter(AuditEvent.scan_job_id == scan_id).delete(synchronize_session=False)
    
    db.delete(job)
    log_audit(
        db,
        event_type="scan.deleted",
        message=f"Scan {scan_id} excluido",
        actor_user_id=current_user.id,
        metadata={"scan_id": scan_id},
    )
    db.commit()
    return {"ok": True}


@router.post("/scans/reset-operational")
def reset_operational_scans(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    scan_rows = db.query(ScanJob.id, ScanJob.status).all()
    scan_ids = [row.id for row in scan_rows]
    active_scan_ids = [row.id for row in scan_rows if row.status in {"queued", "running", "retrying"}]

    revoked_task_ids: list[str] = []
    for scan_id in active_scan_ids:
        task_ids = _active_scan_task_ids(scan_id)
        for task_id in task_ids:
            try:
                celery.control.revoke(task_id, terminate=True, signal="SIGTERM")
                revoked_task_ids.append(task_id)
            except Exception:
                continue

    try:
        # Limpa primeiro as referencias de workers para evitar violacao de FK em scan_jobs.
        db.query(WorkerHeartbeat).filter(WorkerHeartbeat.current_scan_id.is_not(None)).update(
            {
                WorkerHeartbeat.current_scan_id: None,
                WorkerHeartbeat.status: "idle",
                WorkerHeartbeat.last_task_name: None,
            },
            synchronize_session=False,
        )

        deleted_audit_events = db.query(AuditEvent).filter(AuditEvent.scan_job_id.is_not(None)).delete(synchronize_session=False)
        deleted_scan_logs = db.query(ScanLog).delete(synchronize_session=False)
        deleted_findings = db.query(Finding).delete(synchronize_session=False)
        deleted_scan_jobs = db.query(ScanJob).delete(synchronize_session=False)

        db.execute(text("ALTER SEQUENCE scan_jobs_id_seq RESTART WITH 1"))
        db.execute(text("ALTER SEQUENCE findings_id_seq RESTART WITH 1"))
        db.execute(text("ALTER SEQUENCE scan_logs_id_seq RESTART WITH 1"))

        log_audit(
            db,
            event_type="scan.reset_operational",
            message="Reset operacional executado: scans, findings e logs removidos",
            actor_user_id=current_user.id,
            metadata={
                "scan_ids": scan_ids,
                "revoked_task_ids": revoked_task_ids,
                "deleted": {
                    "scan_jobs": deleted_scan_jobs,
                    "findings": deleted_findings,
                    "scan_logs": deleted_scan_logs,
                    "audit_events": deleted_audit_events,
                },
            },
        )
        db.commit()

        return {
            "ok": True,
            "deleted": {
                "scan_jobs": deleted_scan_jobs,
                "findings": deleted_findings,
                "scan_logs": deleted_scan_logs,
                "audit_events": deleted_audit_events,
            },
            "revoked_task_ids": list(dict.fromkeys(revoked_task_ids)),
        }
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Falha ao executar reset operacional: {exc.__class__.__name__}") from exc


@router.post("/scans/{scan_id}/stop")
def stop_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    if job.status not in {"queued", "running", "retrying"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Somente scans em execucao/fila podem ser interrompidos")

    task_ids = _active_scan_task_ids(scan_id)
    for task_id in task_ids:
        try:
            celery.control.revoke(task_id, terminate=True, signal="SIGTERM")
        except Exception:
            continue

    job.status = "stopped"
    job.current_step = "Scan interrompido manualmente"
    job.next_retry_at = None
    job.last_error = "Interrompido manualmente por administrador"
    db.add(
        ScanLog(
            scan_job_id=scan_id,
            source="manager",
            level="WARNING",
            message=f"Scan interrompido manualmente (task_ids={task_ids or ['nao_encontrada']})",
        )
    )
    log_audit(
        db,
        event_type="scan.stopped",
        message=f"Scan {scan_id} interrompido manualmente",
        actor_user_id=current_user.id,
        metadata={"scan_id": scan_id, "task_ids": task_ids},
    )
    db.commit()
    return {"ok": True, "scan_id": scan_id, "revoked_task_ids": task_ids}


@router.delete("/scans/{scan_id}/report")
def delete_scan_report(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    if job.status in {"queued", "running", "retrying"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nao e permitido excluir relatorio de scan em execucao")

    findings_deleted = db.query(Finding).filter(Finding.scan_job_id == scan_id).delete(synchronize_session=False)
    job.state_data = {}
    job.mission_progress = 0
    job.current_step = "Relatorio removido"

    log_audit(
        db,
        event_type="scan.report_deleted",
        message=f"Relatorio do scan {scan_id} removido",
        actor_user_id=current_user.id,
        metadata={"scan_id": scan_id, "findings_deleted": findings_deleted},
    )
    db.commit()
    return {"ok": True, "findings_deleted": findings_deleted}


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
    previous_scan = (
        db.query(ScanJob)
        .filter(
            ScanJob.target_query == job.target_query,
            ScanJob.id < scan_id,
            ScanJob.status == "completed",
        )
        .order_by(ScanJob.id.desc())
        .first()
    )
    previous_findings = []
    if previous_scan:
        previous_findings = db.query(Finding).filter(Finding.scan_job_id == previous_scan.id, Finding.is_false_positive.is_(False)).all()

    enriched_findings = []
    prioritized_actions = []
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    fair_ale_total_open = 0.0
    fair_ale_total_all = 0.0
    fair_score_samples: list[float] = []
    vulnerability_rows: list[dict] = []

    for finding in findings:
        details = finding.details or {}
        normalized_title = _normalize_finding_title(finding.title)
        recommendation_payload = _extract_recommendation_payload(details)
        technical = _extract_technical_details(details, job.target_query)
        category = _infer_category(normalized_title, details)
        age = compute_age_metrics(finding.created_at, details)
        fair = compute_fair_metrics(finding.severity, finding.confidence_score, details, age)
        reasons = build_priority_reason(normalized_title, finding.severity, fair, age)

        sev = str(finding.severity or "low").lower()
        if sev in severity_count:
            severity_count[sev] += 1

        ale_value = float(fair.get("annualized_loss_exposure_usd") or 0.0)
        fair_ale_total_all += ale_value
        fair_score_samples.append(float(fair.get("fair_score") or 0.0))

        target_value = technical.get("full_url") or _sanitize_text(details.get("url") or details.get("target") or job.target_query)
        cve_or_id = _sanitize_text(finding.cve or f"F-{finding.id}")
        signature = _finding_signature(normalized_title, sev, target_value)
        vulnerability_rows.append(
            {
                "index": len(vulnerability_rows) + 1,
                "signature": signature,
                "id": cve_or_id,
                "cve": _sanitize_text(finding.cve or ""),
                "target": target_value,
                "name": normalized_title,
                "problem": normalized_title,
                "service": _sanitize_text(details.get("service") or details.get("protocol") or "-"),
                "cvss": details.get("cvss_score") or details.get("cvss") or finding.risk_score or "-",
                "severity": sev,
                "category": category,
                "nist_control": _sanitize_text(details.get("nist_control") or details.get("nist") or "-"),
                "iso_control": _sanitize_text(details.get("iso_control") or details.get("iso27001") or "-"),
                "recommendation": _normalize_recommendation({**details, "severity": sev}),
                "recommendation_structured": recommendation_payload,
                "exploit": technical.get("exploit") or "-",
                "error": technical.get("error") or "-",
                "evidence": technical.get("evidence") or "-",
                "is_false_positive": bool(finding.is_false_positive),
            }
        )

        enriched_findings.append(
            {
                "id": finding.id,
                "title": normalized_title,
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
            fair_ale_total_open += ale_value
            prioritized_actions.append(
                {
                    "finding_id": finding.id,
                    "title": normalized_title,
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

    score = max(
        0,
        min(
            100,
            100 - (severity_count["critical"] * 30 + severity_count["high"] * 15 + severity_count["medium"] * 8 + severity_count["low"] * 2),
        ),
    )
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

    open_findings = len([f for f in findings if not f.is_false_positive])
    frameworks = {
        "iso27001": {"score": max(0, 100 - open_findings)},
        "nist": {"score": max(0, 100 - int(open_findings * 0.8))},
        "cis_v8": {"score": max(0, 100 - int(open_findings * 0.7))},
        "pci": {"score": max(0, 100 - int(open_findings * 0.9))},
    }

    fair_score_avg = round(sum(fair_score_samples) / max(1, len(fair_score_samples)), 2)
    fair_total = {
        "enabled": True,
        "ale_total_open_usd": round(fair_ale_total_open, 2),
        "ale_total_all_usd": round(fair_ale_total_all, 2),
        "daily_impact_open_usd": round(fair_ale_total_open / 365.0, 2),
        "mitigation_cost_estimate_open_usd": round(fair_ale_total_open * 0.057, 2),
        "fair_avg_score": fair_score_avg,
    }

    open_vulnerability_table = [row for row in vulnerability_rows if not row["is_false_positive"]]

    prev_signatures: set[str] = set()
    resolved_vulnerabilities: list[dict] = []
    for prev in previous_findings:
        prev_details = prev.details or {}
        prev_target = _sanitize_text(prev_details.get("url") or prev_details.get("target") or job.target_query)
        prev_signature = _finding_signature(_normalize_finding_title(prev.title), str(prev.severity or "low"), prev_target)
        prev_signatures.add(prev_signature)

    curr_signatures = {row["signature"] for row in open_vulnerability_table}
    for prev in previous_findings:
        prev_details = prev.details or {}
        prev_title = _normalize_finding_title(prev.title)
        prev_sev = str(prev.severity or "low").lower()
        prev_target = _sanitize_text(prev_details.get("url") or prev_details.get("target") or job.target_query)
        prev_signature = _finding_signature(prev_title, prev_sev, prev_target)
        if prev_signature not in curr_signatures:
            resolved_vulnerabilities.append(
                {
                    "id": _sanitize_text(prev.cve or f"F-{prev.id}"),
                    "target": prev_target,
                    "name": prev_title,
                    "severity": prev_sev,
                    "status": "corrected",
                    "correction_note": "Vulnerabilidade nao reapareceu no scan mais recente do mesmo alvo.",
                }
            )

    for row in open_vulnerability_table:
        row["status"] = "open" if row["signature"] in prev_signatures else "new"
        row.pop("signature", None)

    category_scores = _build_category_scores(open_vulnerability_table)

    detailed_recommendations = [
        {
            "id": row["id"],
            "cve": row.get("cve") or "",
            "name": row["name"],
            "problem": row.get("problem") or row["name"],
            "category": row.get("category") or "Application Security",
            "severity": row["severity"],
            "target": row["target"],
            "technical": {
                "exploit": row.get("exploit") or "-",
                "error": row.get("error") or "-",
                "evidence": row.get("evidence") or "-",
            },
            "recommendation": row["recommendation"],
            "recommendation_structured": row.get("recommendation_structured") or {},
        }
        for row in open_vulnerability_table[:50]
    ]
    top_recommendations = _build_top_recommendations(open_vulnerability_table, detailed_recommendations)

    lifecycle = {
        "open": len([r for r in open_vulnerability_table if r.get("status") == "open"]),
        "new": len([r for r in open_vulnerability_table if r.get("status") == "new"]),
        "corrected": len(resolved_vulnerabilities),
    }
    summary_data = {
        "total": len(findings),
        "critical": severity_count["critical"],
        "high": severity_count["high"],
        "medium": severity_count["medium"],
        "low": severity_count["low"],
        "info": severity_count["info"],
        "open": open_findings,
        "triaged": len(findings) - open_findings,
    }
    strategic_points = _build_strategic_points(
        target=job.target_query,
        summary=summary_data,
        fair_total=fair_total,
        lifecycle=lifecycle,
        category_scores=category_scores,
    )
    technical_points = _build_technical_points(open_vulnerability_table, detailed_recommendations)

    return ReportResponse(
        scan_id=scan_id,
        status=job.status,
        findings=enriched_findings,
        state_data={
            **(job.state_data or {}),
            "report_v2": {
                "domain": job.target_query,
                "scan_type": "ASM_EXTERNAL",
                "risk_score": score,
                "grade": grade,
                "summary": summary_data,
                "fair": fair_total,
                "frameworks": frameworks,
                "category_scores": category_scores,
                "vulnerability_table": open_vulnerability_table,
                "recommendations": top_recommendations,
                "recommendations_detailed": detailed_recommendations,
                "strategic_points": strategic_points,
                "technical_points": technical_points,
                "lifecycle": lifecycle,
                "resolved_vulnerabilities": resolved_vulnerabilities,
                "comparison": {
                    "current_scan_id": scan_id,
                    "previous_scan_id": previous_scan.id if previous_scan else None,
                },
            },
            "prioritized_actions": paged_prioritized,
            "prioritized_actions_page": {
                "items": paged_prioritized,
                "total": len(prioritized_actions),
                "limit": prioritized_limit,
                "offset": prioritized_offset,
            },
        },
    )


@router.get("/scans/{scan_id}/report.csv")
def scan_report_csv(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    report = scan_report(
        scan_id=scan_id,
        prioritized_limit=100,
        prioritized_offset=0,
        db=db,
        current_user=current_user,
    )

    report_v2 = (report.state_data or {}).get("report_v2") or {}
    rows = report_v2.get("vulnerability_table") or []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "index",
            "id",
            "cve",
            "target",
            "problem",
            "service",
            "severity",
            "category",
            "cvss",
            "status",
            "exploit",
            "error",
            "evidence",
            "recommendation",
            "priority",
            "mitigations",
            "validations",
        ]
    )

    for row in rows:
        rec = row.get("recommendation_structured") or {}
        mitigations = rec.get("mitigacoes") if isinstance(rec, dict) else []
        validations = rec.get("validacoes") if isinstance(rec, dict) else []
        writer.writerow(
            [
                row.get("index"),
                row.get("id") or "",
                row.get("cve") or "",
                row.get("target") or "",
                row.get("problem") or row.get("name") or "",
                row.get("service") or "",
                row.get("severity") or "",
                row.get("category") or "",
                row.get("cvss") or "",
                row.get("status") or "",
                row.get("exploit") or "",
                row.get("error") or "",
                row.get("evidence") or "",
                row.get("recommendation") or "",
                rec.get("prioridade") if isinstance(rec, dict) else "",
                "; ".join(str(item) for item in mitigations) if isinstance(mitigations, list) else "",
                "; ".join(str(item) for item in validations) if isinstance(validations, list) else "",
            ]
        )

    csv_text = output.getvalue()
    filename = f"scan_{scan_id}_report.csv"
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
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
            memory_metadata={"severity": finding.severity, "fp_notes": fp_notes},
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
                memory_metadata={"severity": finding.severity, "fp_notes": fp_notes},
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
    target: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.is_admin:
        jobs_query = db.query(ScanJob)
        findings_query = db.query(Finding).join(ScanJob, ScanJob.id == Finding.scan_job_id)
    else:
        allowed_ids = [g.id for g in current_user.groups]
        jobs_query = db.query(ScanJob).filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
        findings_query = (
            db.query(Finding)
            .join(ScanJob, ScanJob.id == Finding.scan_job_id)
            .filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
        )

    normalized_target = (target or "").strip()
    if normalized_target:
        jobs_query = jobs_query.filter(ScanJob.target_query.ilike(f"%{normalized_target}%"))
        findings_query = findings_query.filter(ScanJob.target_query.ilike(f"%{normalized_target}%"))

    jobs = jobs_query.order_by(ScanJob.created_at.desc()).all()
    findings = findings_query.all()

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
    technologies_counter: dict[str, int] = {}
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

    for job in jobs:
        techs = _collect_technologies(job, findings_by_scan.get(job.id, []))
        for name, count in techs.items():
            technologies_counter[name] = technologies_counter.get(name, 0) + count

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

    ongoing_scans = [
        {
            "id": j.id,
            "target_query": j.target_query,
            "status": j.status,
            "mode": j.mode,
            "current_step": j.current_step,
            "mission_progress": j.mission_progress,
            "created_at": j.created_at,
        }
        for j in jobs if j.status in {"queued", "running", "retrying"}
    ][:8]

    top_vulns = [
        {"title": title, "severity": severity, "count": count}
        for (title, severity), count in sorted(vuln_counter.items(), key=lambda item: item[1], reverse=True)[:7]
    ]

    top_technologies = [
        {"name": name, "count": count}
        for name, count in sorted(technologies_counter.items(), key=lambda item: item[1], reverse=True)[:10]
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
        "ongoing_scans": ongoing_scans,
        "top_vulns": top_vulns,
        "top_technologies": top_technologies,
        "assets": assets,
        "activity": activity,
        "prioritized_actions": paged_prioritized,
        "filters": {"target": normalized_target},
        "targets": sorted(list({j.target_query for j in jobs if j.target_query})),
        "prioritized_actions_page": {
            "items": paged_prioritized,
            "total": len(prioritized_actions),
            "limit": prioritized_limit,
            "offset": prioritized_offset,
        },
    }
