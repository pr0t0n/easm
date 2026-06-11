from datetime import datetime, timedelta, timezone
import csv
import io
import json
import math
import re
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import case as sa_case, func, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.models import (
    AuditEvent, FalsePositiveMemory, Finding, ScanJob, ScanLog, ScheduledScan, User,
    WorkerHeartbeat, Asset, Vulnerability, AssetRatingHistory, EASMAlert, ExecutedToolRun,
    ScanAuditLog, AgentTraceEvent, AgentActivityLog, SkillScore, VulnerabilityLearning, AccessGroup,
    ScanWorkItem,
)
from app.schemas.scan import LogResponse, ReportResponse, ScanCreate, ScanResponse, ScanStatusResponse, AutonomyResponse
from app.services.ai_recommendation_service import generate_portuguese_recommendations
from app.services.audit_service import log_audit
from app.services.chroma_service import FalsePositiveVectorStore
from app.services.policy_service import is_target_allowed
from app.services.risk_service import (
    build_priority_reason,
    build_rating_timeline,
    classify_detection_outcome,
    compute_age_metrics,
    compute_continuous_rating,
    compute_fair_metrics,
    compute_framework_scores,
    get_methodology_changelog,
    compute_remediation_velocity,
    compute_posture_deviation,
    build_temporal_narrative,
    forecast_rating_30days,
)
from app.services.orchestrator import TemporalTracker
from app.workers.celery_app import celery
from app.workers.tasks import run_scan_job, run_scan_job_scheduled, run_scan_job_unit
from app.workers.worker_groups import get_worker_groups
from app.services.adversary_technique_catalog import ADVERSARY_TECHNIQUE_CATALOG
from app.services.tool_context_registry import dashboard_bas_variables


router = APIRouter(prefix="/api", tags=["scans"])
vector_store = FalsePositiveVectorStore()


def _effective_mission_progress(job: ScanJob) -> int:
    progress = int(job.mission_progress or 0)
    state = dict(job.state_data or {})

    # If mission_progress is already 100 (set by work_queue_dispatcher on completion),
    # trust it unconditionally — don't cap it back to 99.
    if progress >= 100:
        return 100

    raw = state.get("phase_ledger_v2") or state.get("phase_ledger") or []
    if isinstance(raw, dict):
        entries = [dict(value or {}) for value in raw.values()]
    elif isinstance(raw, list):
        entries = [dict(item or {}) for item in raw if isinstance(item, dict)]
    else:
        entries = []
    # "blocked" e "failed" não indicam progresso real — fase ainda pode ser re-tentada.
    # Só "completed" e "partial" contam para o cálculo de progresso.
    # Além disso, phase_ledger_v2 pode ter múltiplas entradas por fase (uma por target);
    # deduplica por phase_id antes de contar para evitar over-counting.
    if isinstance(raw, list):
        _seen: dict[str, str] = {}
        for entry in entries:
            _pid = str(entry.get("phase_id") or entry.get("id") or "")
            if _pid:
                _seen[_pid] = str(entry.get("status") or "").lower()
        counted = sum(1 for s in _seen.values() if s in {"completed", "partial"})
    else:
        counted = sum(
            1 for entry in entries
            if str(entry.get("status") or "").lower() in {"completed", "partial"}
        )
    if counted:
        progress = max(progress, round((counted / 22) * 100))

    # For running scans, modulate by subdomain coverage so progress reflects
    # how many active subdomains have actually been analyzed.
    if str(job.status or "").lower() in ("running", "queued", "retrying", "paused"):
        cov = state.get("subdomain_coverage") or {}
        active_total = int(cov.get("active_total") or 0)
        scanned = int(cov.get("scanned") or 0)
        if active_total > 0:
            subdomain_pct = int(round(min(scanned, active_total) / active_total * 100))
            progress = max(progress, subdomain_pct)
        # Cap at 99 — only the final task completion sets 100%
        return max(0, min(99, progress))

    return max(0, min(100, progress))


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


SCAN_ACTIVE_STATUSES = {"queued", "running", "retrying"}
SCAN_PAUSABLE_STATUSES = SCAN_ACTIVE_STATUSES
SCAN_RESUMABLE_STATUSES = {"paused"}
SCAN_STOPPABLE_STATUSES = SCAN_ACTIVE_STATUSES | {"paused"}
SCAN_PAUSE_REQUEUE_ITEM_STATUSES = {"dispatched", "running", "submitted", "retry"}


def _active_scan_task_ids(scan_id: int, db: Session | None = None) -> list[str]:
    inspector = celery.control.inspect(timeout=1.5)
    buckets = [inspector.active() or {}, inspector.reserved() or {}, inspector.scheduled() or {}]
    direct_scan_task_names = {
        "run_scan_job_unit",
        "run_scan_job_scheduled",
        "run_scan_target_subset",
        "dispatch_scan_work_items",
        "correlate_tech_vulns",
        "agent.execute_phase",
        "supervisor.orchestrate_scan",
    }
    work_item_task_names = {"execute_scan_work_item", "poll_scan_work_item"}
    work_item_ids: set[int] = set()
    if db is not None:
        try:
            work_item_ids = {
                int(row[0])
                for row in db.query(ScanWorkItem.id).filter(ScanWorkItem.scan_job_id == scan_id).all()
            }
        except Exception:
            work_item_ids = set()
    task_ids: list[str] = []
    for tasks_by_worker in buckets:
        for _, tasks in tasks_by_worker.items():
            for task in tasks or []:
                name = str(task.get("name") or "")
                if name not in direct_scan_task_names and name not in work_item_task_names:
                    continue
                resolved_id = _extract_scan_id_from_task(task)
                if name in work_item_task_names:
                    if resolved_id not in work_item_ids:
                        continue
                elif resolved_id != scan_id:
                    continue
                task_id = str(task.get("id") or "").strip()
                if task_id:
                    task_ids.append(task_id)
    return list(dict.fromkeys(task_ids))


def _requeue_inflight_work_items_for_pause(db: Session, scan_id: int) -> int:
    items = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.status.in_(list(SCAN_PAUSE_REQUEUE_ITEM_STATUSES)),
        )
        .all()
    )
    if not items:
        return 0

    try:
        from app.services.scan_work_queue import kali_inflight_release
    except Exception:
        kali_inflight_release = None

    released_by_class: dict[str, int] = {}
    now = datetime.utcnow()
    for item in items:
        if item.status in {"running", "submitted"}:
            resource_class = str(item.resource_class or "light")
            released_by_class[resource_class] = released_by_class.get(resource_class, 0) + 1
        item.status = "queued"
        item.lease_until = None
        item.last_error = "paused_before_completion"
        item.updated_at = now

    if kali_inflight_release:
        for resource_class, count in released_by_class.items():
            try:
                kali_inflight_release(resource_class, count)
            except Exception:
                continue
    return len(items)


def _clear_scan_worker_heartbeat(db: Session, scan_id: int) -> None:
    db.query(WorkerHeartbeat).filter(WorkerHeartbeat.current_scan_id == scan_id).update(
        {
            WorkerHeartbeat.current_scan_id: None,
            WorkerHeartbeat.status: "idle",
            WorkerHeartbeat.last_task_name: None,
        },
        synchronize_session=False,
    )


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

        # Check if all work items are in terminal states → completed, not failed
        from app.models.models import ScanWorkItem as _SWI
        _terminal = {"completed", "done", "failed", "timeout", "skipped", "blocked"}
        _non_terminal = (
            db.query(_SWI)
            .filter(
                _SWI.scan_job_id == row.id,
                _SWI.status.notin_(list(_terminal)),
            )
            .count()
        )
        _total_items = db.query(_SWI).filter(_SWI.scan_job_id == row.id).count()

        if _total_items > 0 and _non_terminal == 0:
            # All work items terminal → scan completed, not orphaned
            row.status = "completed"
            row.mission_progress = 100
            row.last_error = None
            row.next_retry_at = None
            msg = f"Scan completed via reconciliador — todos os {_total_items} work items terminais"
            level = "INFO"
        else:
            # Genuine orphan: task desapareceu, items ainda pendentes
            row.status = "failed"
            row.current_step = "Scan encerrado por reconciliacao de orfao"
            row.last_error = "Scan marcado como falho por estar running sem task ativa no worker"
            row.next_retry_at = None
            msg = "Scan running/retrying sem task ativa; status corrigido para failed"
            level = "WARNING"

        db.add(
            ScanLog(
                scan_job_id=row.id,
                source="reconciler",
                level=level,
                message=msg,
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


def _resolve_access_group_id(
    db: Session,
    current_user: User,
    access_group_id: int | None,
    access_group_name: str | None = None,
) -> int | None:
    group_name = str(access_group_name or "").strip()
    if group_name:
        existing = db.query(AccessGroup).filter(AccessGroup.name == group_name).first()
        if existing is None:
            if not current_user.is_admin:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Grupo de acesso nao permitido")
            existing = AccessGroup(owner_id=current_user.id, name=group_name, description="")
            db.add(existing)
            db.flush()
        access_group_id = existing.id

    if access_group_id is not None and not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        if access_group_id not in allowed_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Grupo de acesso nao permitido")
    return access_group_id


def _sev_weight(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(severity or "low").lower(), 1)


KNOWN_WAF_MODELS: list[str] = [
    "cloudflare",
    "akamai",
    "imperva",
    "modsecurity",
    "mod_security",
    "f5",
    "aws waf",
    "barracuda",
    "fortiweb",
]

WAF_VENDOR_ALIASES: list[tuple[str, tuple[str, ...]]] = [
    ("Cloudflare", ("cloudflare",)),
    ("Akamai", ("akamai",)),
    ("Imperva", ("imperva", "incapsula")),
    ("ModSecurity", ("modsecurity", "mod_security")),
    ("F5", ("f5", "big-ip asm", "bigip asm")),
    ("AWS WAF", ("aws waf", "amazon waf", "amazon web application firewall")),
    ("Barracuda", ("barracuda",)),
    ("FortiWeb", ("fortiweb",)),
    ("Google Cloud Armor", ("google cloud armor", "google cloud app armor", "app armor (google cloud)", "gcp armor")),
]


def _severity_rank(severity: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }.get(str(severity or "low").strip().lower(), 0)


def _risk_text(severity: str, confidence_score: int | float | None = None) -> str:
    sev = str(severity or "low").strip().lower()
    conf = int(confidence_score or 0)
    if sev == "critical":
        return "Crítico"
    if sev == "high":
        return "Alto"
    if sev == "medium":
        return "Médio"
    if sev == "info":
        return "Informativo"
    if conf >= 80:
        return "Baixo (alta confiança)"
    return "Baixo"


def _score_to_grade(score: float) -> str:
    val = float(score or 0.0)
    if val >= 90:
        return "A"
    if val >= 80:
        return "B"
    if val >= 70:
        return "C"
    if val >= 60:
        return "D"
    return "F"


def _target_tokens(value: str | None) -> list[str]:
    raw = str(value or "").strip().lower()
    if not raw:
        return []
    return [token.strip() for token in re.split(r"[;,]", raw) if token.strip()]


def _primary_target_token(value: str | None) -> str:
    tokens = _target_tokens(value)
    return tokens[0] if tokens else str(value or "").strip().lower()


def _extract_scan_easm_payload(scan: ScanJob | None) -> tuple[dict[str, Any], dict[str, Any], str]:
    if not scan:
        return {}, {}, ""
    state = (scan.state_data or {}) if isinstance(scan.state_data, dict) else {}
    report_v2 = state.get("report_v2") if isinstance(state.get("report_v2"), dict) else {}
    rating = report_v2.get("easm_rating") or state.get("easm_rating") or {}
    decomp = report_v2.get("fair_decomposition") or state.get("fair_decomposition") or {}
    summary = report_v2.get("executive_summary") or state.get("executive_summary") or ""
    return rating if isinstance(rating, dict) else {}, decomp if isinstance(decomp, dict) else {}, str(summary or "").strip()


def _aggregate_fair_decomposition(values: list[dict[str, Any]]) -> dict[str, Any]:
    valid = [item for item in values if isinstance(item, dict) and item]
    if not valid:
        return {}
    if len(valid) == 1:
        return valid[0]

    bucket: dict[str, dict[str, Any]] = {}
    total_score = 0.0
    total_impact = 0.0
    total_assets = 0
    methodology = ""

    for item in valid:
        total_score += float(item.get("score") or 0.0)
        total_impact += float(item.get("total_impact_pts") or 0.0)
        total_assets += int(item.get("n_assets") or 0)
        if not methodology:
            methodology = str(item.get("methodology_version") or "")
        for pillar in item.get("pillars") or []:
            if not isinstance(pillar, dict):
                continue
            pid = str(pillar.get("id") or "").strip()
            if not pid:
                continue
            row = bucket.setdefault(
                pid,
                {
                    "id": pid,
                    "name": str(pillar.get("name") or pid),
                    "weight": float(pillar.get("weight") or 0.0),
                    "weight_pct": str(pillar.get("weight_pct") or ""),
                    "score_sum": 0.0,
                    "impact_sum": 0.0,
                    "finding_count": 0,
                    "samples": 0,
                },
            )
            row["score_sum"] += float(pillar.get("score") or 0.0)
            row["impact_sum"] += float(pillar.get("impact_pts") or 0.0)
            row["finding_count"] += int(pillar.get("finding_count") or 0)
            row["samples"] += 1

    pillars: list[dict[str, Any]] = []
    for pid in ["perimeter_resilience", "patching_hygiene", "osint_exposure"]:
        row = bucket.get(pid)
        if not row:
            continue
        samples = max(1, int(row.get("samples") or 1))
        pillars.append(
            {
                "id": row["id"],
                "name": row["name"],
                "weight": row["weight"],
                "weight_pct": row["weight_pct"],
                "score": round(float(row["score_sum"]) / samples, 2),
                "impact_pts": round(float(row["impact_sum"]) / samples, 2),
                "finding_count": int(row["finding_count"]),
                "evidence": [],
            }
        )

    avg_score = round(total_score / len(valid), 2)
    return {
        "score": avg_score,
        "grade": _score_to_grade(avg_score),
        "pillars": pillars,
        "total_impact_pts": round(total_impact / len(valid), 2),
        "n_assets": max(1, total_assets),
        "methodology_version": methodology or "easm_fair_age_v1",
    }


def _detect_waf_vendor(text: str | None) -> str:
    blob = _sanitize_text(text).lower()
    if not blob:
        return ""
    for canonical, aliases in WAF_VENDOR_ALIASES:
        if any(alias in blob for alias in aliases):
            return canonical
    for model in KNOWN_WAF_MODELS:
        if model in blob:
            return model.title()
    return ""


def _sanitize_text(value: str | None) -> str:
    if not value:
        return ""
    sanitized = str(value)
    sanitized = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", sanitized)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", sanitized)
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized


def _sanitize_multiline_text(value: str | None) -> str:
    if not value:
        return ""
    ansi_pattern = re.compile(r"\x1b\[[0-9;]*m")
    sanitized = ansi_pattern.sub("", str(value))
    sanitized = sanitized.replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"\s+$", "", line) for line in sanitized.split("\n")]
    compact = "\n".join(lines).strip()
    compact = re.sub(r"\n{3,}", "\n\n", compact)
    return compact


def _normalize_finding_title(value: str | None) -> str:
    title = _sanitize_text(value)
    lowered = title.lower()
    for prefix in ["nikto:", "ffuf:", "nmap-vulscan:", "vulscan:", "asm rule:", "asm rule match:"]:
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


def _build_cve_recommendation(cve_id: str, technical: dict, details: dict, severity: str) -> dict[str, object]:
    normalized_cve = _sanitize_text(cve_id or "")
    if not normalized_cve:
        return {
            "summary": "",
            "actions": [],
            "priority": "",
            "validation": [],
        }

    service = _sanitize_text(technical.get("service") or details.get("service") or "")
    version = _sanitize_text(technical.get("version") or details.get("version") or "")
    endpoint = _sanitize_text(technical.get("endpoint") or details.get("endpoint") or "/")
    known_exploited = bool(details.get("known_exploited"))
    cvss_severity = _sanitize_text(details.get("cvss_severity") or severity or "")

    if service and version:
        primary_action = f"Atualizar {service} da versao {version} para release corrigida pelo fornecedor referente ao {normalized_cve}."
    elif service:
        primary_action = f"Aplicar patch ou upgrade suportado pelo fornecedor do servico {service} referente ao {normalized_cve}."
    else:
        primary_action = f"Aplicar o patch oficial, hotfix ou mitigacao compensatoria publicada para o {normalized_cve}."

    exposure_action = (
        f"Restringir temporariamente a exposicao do endpoint {endpoint} e revisar controles de acesso ate a correcao ser validada."
        if endpoint and endpoint != "/"
        else "Restringir a exposicao externa do servico afetado ate a correcao ser validada em producao."
    )

    threat_action = (
        "Tratar como prioridade maxima, pois o CVE consta em fontes de exploracao conhecida e requer janela emergencial."
        if known_exploited
        else "Validar exploitabilidade no ambiente e priorizar a janela de correcao conforme criticidade do ativo afetado."
    )

    summary = f"CVE {normalized_cve}: vulnerabilidade {cvss_severity or severity or 'relevante'} que exige remediacao orientada ao servico e ao contexto exposto."

    return {
        "summary": summary,
        "actions": [primary_action, exposure_action, threat_action],
        "priority": "critica" if known_exploited or str(severity).lower() == "critical" else str(severity or "media").lower(),
        "validation": [
            f"Confirmar em reteste que o {normalized_cve} nao esta mais detectavel no ativo afetado.",
            "Validar versao corrigida, resposta esperada da aplicacao e inexistencia de regressao funcional.",
        ],
    }


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


def _severity_penalty(sev: str) -> int:
    return {
        "critical": 20,
        "high": 12,
        "medium": 6,
        "low": 2,
        "info": 1,
    }.get(str(sev or "low").lower(), 2)


def _compute_framework_scores(vulnerability_rows: list[dict]) -> dict:
    # Pesos por categoria para refletir impacto real do finding em cada framework.
    weights = {
        "iso27001": {
            "Application Security": 1.0,
            "Web Encryption": 1.0,
            "Network Filtering": 0.9,
            "Authentication": 1.0,
            "Authorization": 1.0,
            "Data Exposure": 1.0,
            "Software Patching": 0.8,
            "DNS Security": 0.7,
            "System Hosting": 0.7,
        },
        "nist": {
            "Application Security": 1.0,
            "Web Encryption": 0.9,
            "Network Filtering": 1.0,
            "Authentication": 1.0,
            "Authorization": 1.0,
            "Data Exposure": 0.9,
            "Software Patching": 0.9,
            "DNS Security": 0.8,
            "System Hosting": 0.8,
        },
        "cis_v8": {
            "Application Security": 0.9,
            "Web Encryption": 0.8,
            "Network Filtering": 1.0,
            "Authentication": 1.0,
            "Authorization": 0.9,
            "Data Exposure": 0.8,
            "Software Patching": 1.0,
            "DNS Security": 0.8,
            "System Hosting": 0.9,
        },
        "pci": {
            "Application Security": 1.0,
            "Web Encryption": 1.0,
            "Network Filtering": 1.0,
            "Authentication": 1.0,
            "Authorization": 1.0,
            "Data Exposure": 1.0,
            "Software Patching": 0.9,
            "DNS Security": 0.7,
            "System Hosting": 0.8,
        },
    }

    default_weight = {
        "iso27001": 0.88,
        "nist": 0.93,
        "cis_v8": 0.9,
        "pci": 0.96,
    }

    framework_multiplier = {
        "iso27001": 1.0,
        "nist": 0.94,
        "cis_v8": 0.98,
        "pci": 1.06,
    }

    valid_rows = [row for row in vulnerability_rows if not row.get("is_false_positive")]
    if not valid_rows:
        return {
            "iso27001": {"score": 100},
            "nist": {"score": 100},
            "cis_v8": {"score": 100},
            "pci": {"score": 100},
        }

    total_rows = len(valid_rows)
    critical_count = sum(1 for row in valid_rows if str(row.get("severity") or "").lower() == "critical")
    high_count = sum(1 for row in valid_rows if str(row.get("severity") or "").lower() == "high")
    severe_pressure = (critical_count * 1.7 + high_count * 1.0) / max(1, total_rows)

    penalties = {"iso27001": 0.0, "nist": 0.0, "cis_v8": 0.0, "pci": 0.0}
    for row in valid_rows:
        sev = str(row.get("severity") or "low").lower()
        category = str(row.get("category") or "Application Security")
        base = float(_severity_penalty(sev))
        for fw in penalties.keys():
            weight = float(weights.get(fw, {}).get(category, default_weight[fw]))
            penalties[fw] += base * weight

    def score_from_penalty(fw: str, total_penalty: float) -> int:
        # Usa média de risco por finding para evitar saturação em scans longos com muitos itens.
        avg_penalty = float(total_penalty) / max(1, total_rows)
        multiplier = float(framework_multiplier[fw])
        raw = 100.0 - (avg_penalty * 4.1 * multiplier) - (severe_pressure * 12.0 * multiplier)
        return max(0, min(100, int(round(raw))))

    return {
        "iso27001": {"score": score_from_penalty("iso27001", penalties["iso27001"])},
        "nist": {"score": score_from_penalty("nist", penalties["nist"])},
        "cis_v8": {"score": score_from_penalty("cis_v8", penalties["cis_v8"])},
        "pci": {"score": score_from_penalty("pci", penalties["pci"])},
    }


def _compute_fair_summary(findings: list[Finding], enriched_findings: list[dict], fair_ale_total_open: float, fair_ale_total_all: float) -> dict:
    open_items = [item for item in enriched_findings if not item.get("is_false_positive")]
    lef_values = [float((item.get("fair") or {}).get("loss_event_frequency") or 0.0) for item in open_items]
    lm_values = [float((item.get("fair") or {}).get("loss_magnitude_usd") or 0.0) for item in open_items]
    fair_scores = [float((item.get("fair") or {}).get("fair_score") or 0.0) for item in open_items]

    def _avg(values: list[float]) -> float:
        return round(sum(values) / len(values), 4) if values else 0.0

    ale_peak = 0.0
    if open_items:
        ale_peak = max(float((item.get("fair") or {}).get("annualized_loss_exposure_usd") or 0.0) for item in open_items)

    return {
        "enabled": True,
        "ale_total_open_usd": round(fair_ale_total_open, 2),
        "ale_total_all_usd": round(fair_ale_total_all, 2),
        "daily_impact_open_usd": round(fair_ale_total_open / 365.0, 2),
        "mitigation_cost_estimate_open_usd": round(fair_ale_total_open * 0.057, 2),
        "fair_avg_score": round(_avg(fair_scores), 2),
        "loss_event_frequency_avg": _avg(lef_values),
        "loss_magnitude_avg_usd": round(_avg(lm_values), 2),
        "ale_peak_usd": round(ale_peak, 2),
        "open_findings_count": len(open_items),
        "total_findings_count": len(findings),
    }


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


def _pick_first_text(details: dict, keys: list[str], preserve_linebreaks: bool = False) -> str:
    for key in keys:
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            if preserve_linebreaks:
                return _sanitize_multiline_text(value)
            return _sanitize_text(value)
    return ""


def _extract_method_and_endpoint(full_url: str, payload: str, evidence: str, command: str) -> tuple[str, str]:
    blob = "\n".join([full_url or "", payload or "", evidence or "", command or ""])
    method_match = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b", blob, re.IGNORECASE)
    method = str(method_match.group(1) if method_match else "GET").upper()

    endpoint = ""
    req_line = re.search(r"(?im)^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+([^\s]+)", blob)
    if req_line:
        endpoint = str(req_line.group(2) or "").strip()
    elif full_url:
        parsed = urlparse(full_url if "://" in full_url else f"http://{full_url}")
        endpoint = str(parsed.path or "/")
    if not endpoint:
        endpoint = "/"
    return method, endpoint


def _extract_parameter_name(payload: str, evidence: str, title: str) -> str:
    blob = "\n".join([payload or "", evidence or "", title or ""])

    patterns = [
        re.compile(r"(?:param(?:eter)?|campo|field)\s*[:=]\s*([a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
        re.compile(r"\"([a-zA-Z0-9_\-\.]+)\"\s*:\s*\"[^\"]+\""),
        re.compile(r"\b([a-zA-Z0-9_\-\.]+)='[^']+'"),
        re.compile(r"\b([a-zA-Z0-9_\-\.]+)=\S+"),
    ]
    for pattern in patterns:
        match = pattern.search(blob)
        if match:
            candidate = str(match.group(1) or "").strip()
            if candidate and candidate.lower() not in {"http", "https", "host", "content-type"}:
                return candidate
    return "-"


def _extract_http_response_status(evidence: str) -> str:
    match = re.search(r"(?im)^\s*HTTP/\S+\s+(\d{3})\b", evidence or "")
    if not match:
        return "-"
    return f"HTTP {str(match.group(1) or '').strip()}"


def _looks_like_generic_evidence(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    if not text or text == "-":
        return True
    generic_tokens = [
        "caracteres especiais detectados",
        "special characters detected",
        "possible injection",
        "possible sql injection",
        "indicador detectado",
        "heuristic",
    ]
    return len(text) < 50 or any(token in text for token in generic_tokens)


def _framework_context(category: str, title: str, details: dict) -> dict[str, str]:
    cat = str(category or "Application Security")
    title_blob = str(title or "").lower()
    detail_blob = " ".join(
        [
            str((details or {}).get("evidence") or ""),
            str((details or {}).get("payload") or ""),
            str((details or {}).get("output") or ""),
        ]
    ).lower()
    blob = f"{title_blob} {detail_blob}"

    mapping = {
        "Application Security": {
            "owasp": "A03:2021 - Injection",
            "cwe": "CWE-89",
            "class": "Improper Input Neutralization",
            "iso": "ISO 27001 A.8.28 Secure coding",
            "nist": "NIST PR.DS-6 / SI-10",
            "cis": "CIS v8 Control 16 - Application Software Security",
            "pci": "PCI DSS 6.2.4 / 6.4.2 Secure software development",
        },
        "Web Encryption": {
            "owasp": "A02:2021 - Cryptographic Failures",
            "cwe": "CWE-319",
            "class": "Cleartext Transmission of Sensitive Information",
            "iso": "ISO 27001 A.8.24 Use of cryptography",
            "nist": "NIST SC-8 / SC-13",
            "cis": "CIS v8 Control 3 - Data Protection",
            "pci": "PCI DSS 4.2 Strong cryptography over open networks",
        },
        "Authentication": {
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "cwe": "CWE-287",
            "class": "Improper Authentication",
            "iso": "ISO 27001 A.5.17 Authentication information",
            "nist": "NIST IA-2 / AC-7",
            "cis": "CIS v8 Control 6 - Access Control Management",
            "pci": "PCI DSS 8 Identify users and authenticate access",
        },
        "Authorization": {
            "owasp": "A01:2021 - Broken Access Control",
            "cwe": "CWE-285",
            "class": "Improper Authorization",
            "iso": "ISO 27001 A.5.15 Access control",
            "nist": "NIST AC-3 / AC-6",
            "cis": "CIS v8 Control 6 - Access Control Management",
            "pci": "PCI DSS 7 Restrict access by business need to know",
        },
        "Network Filtering": {
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-16",
            "class": "Configuration",
            "iso": "ISO 27001 A.8.20 Network security",
            "nist": "NIST SC-7 / CM-7",
            "cis": "CIS v8 Control 12 - Network Infrastructure Management",
            "pci": "PCI DSS 1 Install and maintain network security controls",
        },
        "Data Exposure": {
            "owasp": "A01:2021 - Broken Access Control",
            "cwe": "CWE-200",
            "class": "Exposure of Sensitive Information",
            "iso": "ISO 27001 A.5.12 Classification of information",
            "nist": "NIST PR.DS-1 / PR.DS-5",
            "cis": "CIS v8 Control 3 - Data Protection",
            "pci": "PCI DSS 3 Protect stored account data",
        },
        "Software Patching": {
            "owasp": "A06:2021 - Vulnerable and Outdated Components",
            "cwe": "CWE-1104",
            "class": "Use of Unmaintained Third Party Components",
            "iso": "ISO 27001 A.8.8 Management of technical vulnerabilities",
            "nist": "NIST SI-2 / RA-5",
            "cis": "CIS v8 Control 7 - Continuous Vulnerability Management",
            "pci": "PCI DSS 6.3 / 6.4 Manage vulnerabilities and patching",
        },
        "DNS Security": {
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-346",
            "class": "Origin Validation Error",
            "iso": "ISO 27001 A.8.20 Network security",
            "nist": "NIST SC-20 / SC-21",
            "cis": "CIS v8 Control 12 - Network Infrastructure Management",
            "pci": "PCI DSS 1.2 Network security controls",
        },
        "System Hosting": {
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-16",
            "class": "Configuration",
            "iso": "ISO 27001 A.8.9 Configuration management",
            "nist": "NIST CM-2 / CM-6",
            "cis": "CIS v8 Control 4 - Secure Configuration",
            "pci": "PCI DSS 2 Apply secure configurations",
        },
    }

    base = mapping.get(cat, mapping["Application Security"]).copy()

    if any(token in blob for token in ["xss", "cross-site scripting"]):
        base.update(
            {
                "owasp": "A03:2021 - Injection",
                "cwe": "CWE-79",
                "class": "Improper Neutralization of Input During Web Page Generation",
            }
        )
    elif any(token in blob for token in ["sql", "sqli", "injection"]):
        base.update(
            {
                "owasp": "A03:2021 - Injection",
                "cwe": "CWE-89",
                "class": "Improper Input Neutralization",
            }
        )

    return base


def _technical_recommendation(category: str, title: str, severity: str) -> dict[str, object]:
    sev = str(severity or "low").lower()
    cat = str(category or "Application Security")
    title_blob = str(title or "").lower()

    required_fix = "Aplicar correção definitiva no componente afetado e validar com reteste técnico orientado por evidência."
    controls = [
        "Validar entrada por allowlist e normalização estrita",
        "Aplicar princípio de privilégio mínimo",
        "Adicionar teste automatizado de segurança no pipeline",
    ]

    if cat == "Application Security":
        if "sql" in title_blob or "injection" in title_blob:
            required_fix = "Substituir concatenação dinâmica por consultas parametrizadas (prepared statements) em 100% dos pontos de entrada."
            controls = [
                "Prepared Statements / Parameter Binding",
                "ORM com queries parametrizadas e revisão de queries legadas",
                "Validação de entrada por tipo/regex e bloqueio de payload malicioso",
                "Conta de banco com privilégio mínimo e segregação de funções",
            ]
        elif "xss" in title_blob:
            required_fix = "Neutralizar saída no contexto correto (HTML/JS/URL) e bloquear execução de script não confiável."
            controls = [
                "Output encoding contextual",
                "Content-Security-Policy restritiva",
                "Sanitização server-side de campos ricos",
                "Cookies com HttpOnly/Secure/SameSite",
            ]
    elif cat == "Web Encryption":
        required_fix = "Desabilitar protocolos/ciphers legados e forçar TLS forte com cadeias válidas e renovação automatizada."
        controls = [
            "Desabilitar TLS 1.0/1.1 e ciphers fracos",
            "HSTS com includeSubDomains quando aplicável",
            "Rotação e monitoramento de certificados",
        ]
    elif cat == "Network Filtering":
        required_fix = "Restringir exposição de portas/serviços externamente e aplicar política de deny-by-default na borda."
        controls = [
            "Firewall/ACL por origem e serviço",
            "Segmentação por ambiente e função",
            "Bloqueio de administração remota fora de rede autorizada",
        ]

    if sev in {"critical", "high"}:
        validation_window = "Retestar em até 24h após correção e validar ausência de regressão funcional e de segurança."
    elif sev == "medium":
        validation_window = "Retestar na mesma sprint e confirmar mitigação em ambiente homologado e produção."
    else:
        validation_window = "Retestar no próximo ciclo e monitorar recorrência no baseline."

    validations = [
        "Executar reteste com a mesma ferramenta e payload da evidência",
        "Validar resposta HTTP e comportamento de negócio esperado",
        validation_window,
    ]

    return {
        "required_fix": required_fix,
        "controls": controls,
        "validations": validations,
    }


def _extract_technical_details(details: dict, default_target: str) -> dict[str, str]:
    details = details if isinstance(details, dict) else {}
    nested = details.get("details") if isinstance(details.get("details"), dict) else {}

    full_url = _pick_first_text(details, ["url", "full_url", "endpoint", "uri", "request_uri", "path", "target", "asset"])
    if not full_url:
        full_url = _pick_first_text(nested, ["url", "full_url", "endpoint", "uri", "request_uri", "path", "target", "asset"])
    if not full_url:
        full_url = _sanitize_text(default_target)

    exploit = _pick_first_text(details, ["exploit", "exploit_url", "exploitdb", "exploitdb_url", "poc"], preserve_linebreaks=True)
    if not exploit:
        exploit = _pick_first_text(nested, ["exploit", "exploit_url", "exploitdb", "exploitdb_url", "poc"], preserve_linebreaks=True)

    error = _pick_first_text(details, ["error", "stderr", "exception", "message", "http_error", "status_code"], preserve_linebreaks=True)
    if not error:
        error = _pick_first_text(nested, ["error", "stderr", "exception", "message", "http_error", "status_code"], preserve_linebreaks=True)

    evidence = _pick_first_text(details, ["evidence", "stdout", "output", "matched", "matched_at", "response", "banner", "reason", "description", "finding", "match_reason"], preserve_linebreaks=True)
    if not evidence:
        evidence = _pick_first_text(nested, ["evidence", "stdout", "output", "matched", "matched_at", "response", "banner", "reason", "description", "finding", "match_reason"], preserve_linebreaks=True)

    payload = _pick_first_text(
        details,
        [
            "payload",
            "request",
            "request_raw",
            "curl",
            "command",
            "cmd",
            "template_id",
            "matcher_name",
            "proof",
            "attack_input",
            "injected_payload",
            "payload_raw",
            "vector",
            "payloads",
        ],
        preserve_linebreaks=True,
    )
    if not payload:
        payload = _pick_first_text(
            nested,
            [
                "payload",
                "request",
                "request_raw",
                "curl",
                "command",
                "cmd",
                "template_id",
                "matcher_name",
                "proof",
                "attack_input",
                "injected_payload",
                "payload_raw",
                "vector",
                "payloads",
            ],
            preserve_linebreaks=True,
        )

    if not payload and nested:
        try:
            payload = _sanitize_multiline_text(json.dumps(nested, ensure_ascii=False, indent=2))
        except Exception:
            payload = ""

    step = _pick_first_text(details, ["step"])
    if not step:
        step = _pick_first_text(nested, ["step"])

    node = _pick_first_text(details, ["node", "source_worker"])
    if not node:
        node = _pick_first_text(nested, ["node", "source_worker"])

    asset = _pick_first_text(details, ["asset", "target"])
    if not asset:
        asset = _pick_first_text(nested, ["asset", "target"])

    port = details.get("port")
    if port in [None, ""]:
        port = nested.get("port")
    port_text = str(port) if port not in [None, ""] else ""

    service = _pick_first_text(details, ["service", "protocol"])
    if not service:
        service = _pick_first_text(nested, ["service", "protocol"])

    version = _pick_first_text(details, ["version", "banner"])
    if not version:
        version = _pick_first_text(nested, ["version", "banner"])

    tool = _pick_first_text(details, ["tool"])
    if not tool:
        tool = _pick_first_text(nested, ["tool"])

    command = _pick_first_text(details, ["command", "cmd", "command_line"])
    if not command:
        command = _pick_first_text(nested, ["command", "cmd", "command_line"])

    open_ports = details.get("open_ports")
    if open_ports in [None, ""]:
        open_ports = nested.get("open_ports")
    open_ports_text = ""
    if isinstance(open_ports, list):
        parsed_ports: list[str] = []
        for raw in open_ports:
            try:
                port = int(raw)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                parsed_ports.append(str(port))
        if parsed_ports:
            open_ports_text = ",".join(parsed_ports[:50])

    if not evidence and open_ports_text:
        evidence = f"open_ports={open_ports_text}"

    if not payload and command:
        payload = command

    method, endpoint = _extract_method_and_endpoint(full_url, payload, evidence, command)
    parameter = _extract_parameter_name(payload, evidence, " ".join([details.get("title") or "", details.get("name") or ""]))
    response_http = _extract_http_response_status(evidence)

    sql_blob = " ".join([
        str(details.get("title") or ""),
        str(details.get("name") or ""),
        payload or "",
        evidence or "",
        command or "",
    ]).lower()
    is_sql_injection = any(token in sql_blob for token in ["sql injection", "sqli", "injectable", "sql syntax"])

    if is_sql_injection and _looks_like_generic_evidence(evidence):
        evidence_lines = [
            "Evidência técnica consolidada de potencial SQL Injection.",
            f"Endpoint: {method} {endpoint}",
            f"Alvo: {full_url or default_target}",
            f"Parâmetro: {parameter}",
        ]
        if response_http != "-":
            evidence_lines.append(f"Resposta HTTP observada: {response_http}")
        if command:
            evidence_lines.append(f"Comando/Ferramenta: {command[:300]}")
        evidence = "\n".join(evidence_lines)

    if is_sql_injection and not payload:
        if command:
            payload = f"Payload de injeção não retornado pela ferramenta; comando executado: {command[:500]}"
        else:
            payload = "Payload de injeção não retornado pela ferramenta no resultado bruto deste scan."

    response_application = ""
    if evidence:
        response_application = evidence[:1200]

    observed_behavior = _sanitize_text(evidence.splitlines()[0] if evidence else "")
    expected_behavior = "Retornar bloqueio/erro seguro para a entrada maliciosa e manter fluxo de negócio íntegro."

    if "waf" in (tool or "").lower() or "cloudflare" in (evidence or "").lower():
        expected_behavior = "WAF deve filtrar tráfego malicioso sem classificar indevidamente serviço de borda como vulnerabilidade da aplicação."
        observed_behavior = observed_behavior or "Comportamento de borda/proxy identificado no tráfego analisado."

    root_cause = "Entrada e/ou configuração de segurança sem controle defensivo suficiente para o vetor observado."
    if "sql" in (payload + " " + evidence).lower():
        root_cause = "Possível concatenação de input não confiável em consulta SQL ou validação insuficiente de entrada."
    elif "xss" in (payload + " " + evidence).lower():
        root_cause = "Possível falta de neutralização/encoding contextual de saída para conteúdo controlado por usuário."
    elif "tls" in (payload + " " + evidence).lower() or "ssl" in (payload + " " + evidence).lower():
        root_cause = "Configuração criptográfica legada ou inconsistente com baseline de segurança."

    technical_validation = "Evidência coletada por ferramenta de segurança e correlacionada com contexto técnico do alvo."
    if response_http != "-":
        technical_validation = f"{technical_validation} Resposta observada: {response_http}."

    return {
        "full_url": full_url,
        "endpoint": endpoint,
        "http_method": method,
        "parameter": parameter,
        "exploit": exploit,
        "error": error,
        "evidence": evidence,
        "response_http": response_http,
        "response_application": response_application,
        "payload": payload,
        "attack_input": payload[:500] if payload else "-",
        "poc_request": payload[:1200] if payload else "-",
        "technical_validation": technical_validation,
        "expected_behavior": expected_behavior,
        "observed_behavior": observed_behavior or "-",
        "root_cause": root_cause,
        "step": step,
        "node": node,
        "asset": asset,
        "port": port_text,
        "service": service,
        "version": version,
        "tool": tool,
        "command": command,
    }


def _infer_target_segment(target: str | None) -> str:
    raw = (target or "").strip().lower()
    if not raw:
        return "Digital Services"
    if any(token in raw for token in ["bank", "banco", "fin", "credit", "certificadora", "pag", "payment"]):
        return "Financial Services"
    if any(token in raw for token in ["health", "hospital", "saude", "clinic"]):
        return "Healthcare"
    if any(token in raw for token in ["gov", "gov.br", "prefeitura", "ministerio", "tribunal"]):
        return "Public Sector"
    if any(token in raw for token in ["edu", "school", "universidade", "faculdade"]):
        return "Education"
    if any(token in raw for token in ["shop", "store", "ecom", "market"]):
        return "Retail"
    return "Digital Services"


def _build_wef_benchmark(segment: str, fair_open_usd: float, severity_count: dict[str, int]) -> dict:
    base = {
        "Financial Services": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 7,
            "expected_external_exposure_index": 32,
            "expected_financial_loss_exposure_index": 58,
            "expected_data_sensitivity_risk_index": 70,
            "expected_reliability_safety_impact_index": 63,
            "expected_cyber_readiness_index": 68,
            "expected_third_party_risk_index": 44,
            "expected_identity_attack_pressure": 68,
        },
        "Healthcare": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 10,
            "expected_external_exposure_index": 39,
            "expected_financial_loss_exposure_index": 52,
            "expected_data_sensitivity_risk_index": 76,
            "expected_reliability_safety_impact_index": 72,
            "expected_cyber_readiness_index": 59,
            "expected_third_party_risk_index": 48,
            "expected_identity_attack_pressure": 57,
        },
        "Public Sector": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 12,
            "expected_external_exposure_index": 41,
            "expected_financial_loss_exposure_index": 46,
            "expected_data_sensitivity_risk_index": 68,
            "expected_reliability_safety_impact_index": 66,
            "expected_cyber_readiness_index": 56,
            "expected_third_party_risk_index": 46,
            "expected_identity_attack_pressure": 52,
        },
        "Education": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 14,
            "expected_external_exposure_index": 47,
            "expected_financial_loss_exposure_index": 38,
            "expected_data_sensitivity_risk_index": 54,
            "expected_reliability_safety_impact_index": 49,
            "expected_cyber_readiness_index": 48,
            "expected_third_party_risk_index": 49,
            "expected_identity_attack_pressure": 51,
        },
        "Retail": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 9,
            "expected_external_exposure_index": 43,
            "expected_financial_loss_exposure_index": 55,
            "expected_data_sensitivity_risk_index": 57,
            "expected_reliability_safety_impact_index": 52,
            "expected_cyber_readiness_index": 62,
            "expected_third_party_risk_index": 55,
            "expected_identity_attack_pressure": 61,
        },
        "Digital Services": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 10,
            "expected_external_exposure_index": 40,
            "expected_financial_loss_exposure_index": 50,
            "expected_data_sensitivity_risk_index": 52,
            "expected_reliability_safety_impact_index": 50,
            "expected_cyber_readiness_index": 60,
            "expected_third_party_risk_index": 50,
            "expected_identity_attack_pressure": 58,
        },
    }
    segment_base = base.get(segment, base["Digital Services"])

    critical = int(severity_count.get("critical", 0) or 0)
    high = int(severity_count.get("high", 0) or 0)
    medium = int(severity_count.get("medium", 0) or 0)
    low = int(severity_count.get("low", 0) or 0)

    # Regra CRI solicitada:
    # 1) Havendo criticos: score base 40 e -5 por critico adicional.
    # 2) Sem criticos e com altas: score base 60 e -2 por alta adicional.
    # 3) Piso minimo em 5.
    if critical >= 1:
        base_score = 40 - ((critical - 1) * 5)
        critical_high_penalty = 60 + ((critical - 1) * 5)
        score_rule = "critical"
        base_formula = f"40 - (({critical} - 1) x 5)"
    elif high >= 1:
        base_score = 60 - ((high - 1) * 2)
        critical_high_penalty = 40 + ((high - 1) * 2)
        score_rule = "high"
        base_formula = f"60 - (({high} - 1) x 2)"
    else:
        base_score = 100
        critical_high_penalty = 0
        score_rule = "clean"
        base_formula = "100"

    medium_low_penalty = 0
    raw_score = base_score
    target_cri_score = max(5, min(100, int(round(raw_score))))
    min_floor_applied = bool(raw_score < 5)

    # Índices auxiliares dinâmicos: combinam pressão por severidade + ALE,
    # evitando congelamento em extremos (0/100).
    total_findings = max(1, critical + high + medium + low)
    weighted_pressure_raw = (critical * 10.0) + (high * 5.0) + (medium * 2.0) + (low * 1.0)
    weighted_pressure_norm = min(100.0, (weighted_pressure_raw / (total_findings * 10.0)) * 100.0)

    # 1k -> ~50, 10k -> ~66, 100k -> ~83, 1M -> ~100
    ale_component = min(100.0, (math.log10(max(float(fair_open_usd or 0.0), 0.0) + 1.0) / 6.0) * 100.0)
    financial_loss_exposure_index = int(
        min(
            100,
            max(
                0,
                round((weighted_pressure_norm * 0.60) + (ale_component * 0.40)),
            ),
        )
    )
    data_sensitivity_risk_index = int(
        min(
            100,
            max(
                0,
                round((financial_loss_exposure_index * 0.65) + (weighted_pressure_norm * 0.35)),
            ),
        )
    )
    reliability_safety_impact_index = int(
        min(
            100,
            max(
                0,
                round((financial_loss_exposure_index * 0.55) + (weighted_pressure_norm * 0.45)),
            ),
        )
    )
    cyber_readiness_index = int(target_cri_score)

    # O score CRI esperado do benchmark deve ser consistente com o readiness esperado do segmento.
    segment_cri_score = int(segment_base["expected_cyber_readiness_index"])

    segment_exposure = int(segment_base["expected_external_exposure_index"])
    cri_exposure = max(0.0, min(100.0, 100.0 - float(target_cri_score)))
    target_exposure_index = int(round(max(0.0, min(100.0, (cri_exposure * 0.70) + (weighted_pressure_norm * 0.30)))))
    segment_exposure_index_from_cri = max(0, min(100, 100 - int(segment_cri_score)))

    cri_diff = int(target_cri_score) - int(segment_cri_score)
    if cri_diff > 3:
        assessment = "melhor_que_o_benchmark"
    elif cri_diff < -3:
        assessment = "acima_do_benchmark"
    else:
        assessment = "similar_ao_benchmark"

    return {
        "segment": segment,
        "source": segment_base["source"],
        "wef_reference_year": 2025,
        "target_external_exposure_index": target_exposure_index,
        "segment_external_exposure_index": segment_exposure_index_from_cri,
        "target_cri_score": target_cri_score,
        "segment_cri_score": segment_cri_score,
        "target_financial_loss_exposure_index": financial_loss_exposure_index,
        "segment_financial_loss_exposure_index": int(segment_base["expected_financial_loss_exposure_index"]),
        "target_data_sensitivity_risk_index": data_sensitivity_risk_index,
        "segment_data_sensitivity_risk_index": int(segment_base["expected_data_sensitivity_risk_index"]),
        "target_reliability_safety_impact_index": reliability_safety_impact_index,
        "segment_reliability_safety_impact_index": int(segment_base["expected_reliability_safety_impact_index"]),
        "target_cyber_readiness_index": cyber_readiness_index,
        "segment_cyber_readiness_index": int(segment_base["expected_cyber_readiness_index"]),
        "segment_identity_attack_pressure": int(segment_base["expected_identity_attack_pressure"]),
        "segment_third_party_risk_index": int(segment_base["expected_third_party_risk_index"]),
        "segment_patch_sla_days": int(segment_base["expected_patch_sla_days"]),
        "segment_external_exposure_reference": segment_exposure,
        "target_ale_open_usd": round(float(fair_open_usd or 0.0), 2),
        "assessment": assessment,
        "calculation": {
            "severity_counts": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "rule_applied": score_rule,
            "base_formula": base_formula,
            "base_score": int(base_score),
            "medium_formula": "n/a",
            "low_formula": "n/a",
            "medium_low_penalty": int(medium_low_penalty),
            "raw_score_before_floor": int(raw_score),
            "min_floor": 5,
            "floor_applied": min_floor_applied,
            "final_score": int(target_cri_score),
            "weighted_pressure_norm": round(float(weighted_pressure_norm), 2),
            "ale_component": round(float(ale_component), 2),
            "human_readable": f"score = max(5, ({base_formula})) = {int(target_cri_score)} | pressure={round(float(weighted_pressure_norm), 2)} | ale={round(float(ale_component), 2)}",
        },
    }


def _build_target_evolution(db: Session, target_query: str, current_scan_id: int) -> dict:
    scans = (
        db.query(ScanJob)
        .filter(ScanJob.target_query == target_query)
        .order_by(ScanJob.created_at.asc(), ScanJob.id.asc())
        .all()
    )
    if not scans:
        return {"timeline": [], "recurring_findings": []}

    scan_ids = [s.id for s in scans]
    findings_all = db.query(Finding).filter(Finding.scan_job_id.in_(scan_ids), Finding.is_false_positive.is_(False)).all()
    by_scan: dict[int, list[Finding]] = {}
    for f in findings_all:
        by_scan.setdefault(f.scan_job_id, []).append(f)

    timeline: list[dict] = []
    previous_open: int | None = None
    for s in scans:
        findings_scan = by_scan.get(s.id, [])
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings_scan:
            key = str(f.severity or "low").lower()
            if key in sev:
                sev[key] += 1
        open_count = len(findings_scan)
        delta_open = 0 if previous_open is None else open_count - previous_open
        previous_open = open_count
        timeline.append(
            {
                "scan_id": s.id,
                "created_at": s.created_at,
                "status": s.status,
                "mode": s.mode,
                "open_findings": open_count,
                "severity": sev,
                "delta_open_vs_previous": delta_open,
                "is_current": s.id == current_scan_id,
            }
        )

    recurring_map: dict[str, dict] = {}
    for s in scans:
        for f in by_scan.get(s.id, []):
            title = _normalize_finding_title(f.title)
            severity = str(f.severity or "low").lower()
            signature = f"{title.lower()}|{severity}"
            if signature not in recurring_map:
                recurring_map[signature] = {
                    "signature": signature,
                    "title": title,
                    "severity": severity,
                    "first_scan_id": s.id,
                    "last_scan_id": s.id,
                    "occurrences": 0,
                }
            recurring_map[signature]["occurrences"] += 1
            recurring_map[signature]["last_scan_id"] = s.id

    recurring = sorted(recurring_map.values(), key=lambda item: item.get("occurrences", 0), reverse=True)
    for row in recurring:
        if row["last_scan_id"] == current_scan_id and row["occurrences"] > 1:
            row["trend"] = "persisting"
        elif row["last_scan_id"] == current_scan_id and row["occurrences"] == 1:
            row["trend"] = "new"
        else:
            row["trend"] = "resolved_or_not_reproduced"

    return {
        "timeline": timeline,
        "recurring_findings": recurring[:40],
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


def _source_group_from_details(details: dict) -> str:
    details = details if isinstance(details, dict) else {}
    nested = details.get("details") if isinstance(details.get("details"), dict) else {}

    node = str(details.get("node") or nested.get("node") or "").strip().lower()
    worker = str(details.get("source_worker") or nested.get("source_worker") or "").strip().lower()
    tool = str(details.get("tool") or nested.get("tool") or "").strip().lower()

    if node in {"recon", "scan", "fingerprint"} or worker in {"recon", "reconhecimento", "scan"}:
        return "recon"
    if node == "osint" or worker == "osint":
        return "osint"
    if node in {"vuln", "fuzzing", "api", "code_js"} or worker in {"analise_vulnerabilidade", "vuln"}:
        return "vuln"
    if tool in {
        "nikto",
        "nuclei",
        "nmap-vulscan",
        "nmap-http-enum",
        "nmap-ssl-vuln",
        "nmap-smb-vuln",
        "nmap-ssh-audit",
        "vulscan",
        "sslscan",
        "testssl",
        "shcheck",
        "curl-headers",
        "wafw00f",
        "sqlmap",
        "dalfox",
        "wapiti",
        "wpscan",
        "hydra",
        "medusa",
        "jwt_tool",
        "ffuf-post",
        "ffuf-values",
        # Supply chain, business logic, ZAP scanners
        "supply_chain_analyzer",
        "business_logic_analyzer",
        "zap_baseline",
        "zap_active_scan",
        "zap_ajax_spider",
        "zap_api_scan",
        "zap-baseline",
        "zap-active",
        "zap-ajax",
        "zap-api",
        "zaproxy",
    }:
        return "vuln"
    return "other"


def _is_vulnerability_row(row: dict) -> bool:
    source_group = str(row.get("source_group") or "").strip().lower()
    severity = str(row.get("severity") or "low").strip().lower()
    if source_group == "vuln":
        return True
    if severity in {"critical", "high", "medium"}:
        return True
    category = str(row.get("category") or "").strip()
    if source_group != "osint" and category in {
        "Application Security",
        "Software Patching",
        "Web Encryption",
        "Network Filtering",
        "Authentication",
        "Authorization",
        "Data Exposure",
        "System Hosting",
    }:
        return True
    return False


def _finding_lifecycle_signature(finding: Finding) -> str:
    details = finding.details or {}
    nested = details.get("details") if isinstance(details.get("details"), dict) else {}
    tool = _sanitize_text(details.get("tool") or nested.get("tool") or "")
    target = _sanitize_text(finding.scan_job.target_query if finding.scan_job else "")
    title = _sanitize_text(finding.title or "")
    cve = _sanitize_text(finding.cve or "")
    return "|".join([target.lower(), tool.lower(), title.lower(), cve.lower()])


def _build_finding_lifecycle_status_map(findings: list[Finding]) -> dict[int, str]:
    """
    Define status por ciclo de scans do mesmo target:
    - false_positive: marcado como FP
    - open: encontrado no scan posterior imediato (ou nao existe scan posterior)
    - closed: nao encontrado no scan posterior imediato
    """
    status_by_id: dict[int, str] = {}
    if not findings:
        return status_by_id

    scans_by_target: dict[str, list[ScanJob]] = {}
    findings_by_scan: dict[int, list[Finding]] = {}

    for finding in findings:
        if finding.is_false_positive:
            status_by_id[finding.id] = "false_positive"

        if not finding.scan_job:
            status_by_id.setdefault(finding.id, "open")
            continue

        target = str(finding.scan_job.target_query or "").strip().lower()
        if not target:
            status_by_id.setdefault(finding.id, "open")
            continue

        scans_by_target.setdefault(target, []).append(finding.scan_job)
        findings_by_scan.setdefault(finding.scan_job_id, []).append(finding)

    for target, scans in scans_by_target.items():
        unique_scans = {scan.id: scan for scan in scans}
        ordered_scans = sorted(
            unique_scans.values(),
            key=lambda s: ((s.created_at or datetime.min), s.id),
        )
        if not ordered_scans:
            continue

        signatures_by_scan: dict[int, set[str]] = {}
        for scan in ordered_scans:
            sigs: set[str] = set()
            for finding in findings_by_scan.get(scan.id, []):
                if finding.is_false_positive:
                    continue
                sigs.add(_finding_lifecycle_signature(finding))
            signatures_by_scan[scan.id] = sigs

        for idx, scan in enumerate(ordered_scans):
            next_scan = ordered_scans[idx + 1] if idx + 1 < len(ordered_scans) else None
            next_signatures = signatures_by_scan.get(next_scan.id, set()) if next_scan else set()

            for finding in findings_by_scan.get(scan.id, []):
                if finding.is_false_positive:
                    status_by_id[finding.id] = "false_positive"
                    continue

                if not next_scan:
                    status_by_id[finding.id] = "open"
                    continue

                current_sig = _finding_lifecycle_signature(finding)
                if current_sig in next_signatures:
                    status_by_id[finding.id] = "open"
                else:
                    status_by_id[finding.id] = "closed"

    return status_by_id


def _extract_finding_location(finding: Finding) -> dict[str, str | None]:
    details = finding.details if isinstance(finding.details, dict) else {}
    nested = details.get("details") if isinstance(details.get("details"), dict) else {}

    def _pick_str(*values: Any) -> str:
        for value in values:
            candidate = str(value or "").strip()
            if candidate:
                return candidate
        return ""

    raw_url = _pick_str(
        details.get("url"),
        details.get("request_url"),
        details.get("target_url"),
        details.get("endpoint"),
        nested.get("url"),
        nested.get("request_url"),
        nested.get("target_url"),
        nested.get("endpoint"),
        details.get("matched-at"),
        nested.get("matched-at"),
    )
    raw_asset = _pick_str(
        details.get("subdomain"),
        details.get("hostname"),
        details.get("host"),
        details.get("target_host"),
        details.get("asset"),
        details.get("matched_at"),
        details.get("input"),
        details.get("target"),
        nested.get("subdomain"),
        nested.get("hostname"),
        nested.get("host"),
        nested.get("target_host"),
        nested.get("asset"),
        nested.get("matched_at"),
        nested.get("input"),
        nested.get("target"),
    )
    raw_path = _pick_str(
        details.get("path"),
        details.get("route"),
        details.get("uri"),
        nested.get("path"),
        nested.get("route"),
        nested.get("uri"),
    )

    parsed_path = ""
    parsed_host = ""
    if raw_url:
        try:
            parsed = urlparse(raw_url)
            parsed_host = str(parsed.hostname or "").strip()
            parsed_path = str(parsed.path or "").strip()
        except Exception:
            parsed_host = ""
            parsed_path = ""

    asset_host = ""
    if raw_asset:
        try:
            parsed = urlparse(raw_asset if "://" in raw_asset else f"https://{raw_asset}")
            asset_host = str(parsed.hostname or "").strip()
        except Exception:
            asset_host = ""
        if not asset_host:
            asset_host = raw_asset.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip()

    target = parsed_host or asset_host or str(finding.domain or "").strip()
    if not target and finding.scan_job:
        tokens = _target_tokens(str(finding.scan_job.target_query or ""))
        if tokens:
            target = str(tokens[0]).strip()
    if not target and finding.scan_job:
        target = str(finding.scan_job.target_query or "").strip()

    path = raw_path or parsed_path
    if path and not path.startswith("/"):
        path = f"/{path}"

    url_value = ""
    if raw_url.startswith("http://") or raw_url.startswith("https://"):
        url_value = raw_url
    elif target:
        if path:
            url_value = f"https://{target}{path}"
        else:
            url_value = f"https://{target}"

    return {
        "target": target or None,
        "subdomain": target or None,
        "path": path or None,
        "url": url_value or None,
    }


def _finding_network_context(finding: Finding, loc: dict) -> dict:
    """Contexto de rede canônico — prefere o bloco PERSISTIDO na criação
    (details.network); senão recomputa via o builder único (fonte única)."""
    d = finding.details if isinstance(finding.details, dict) else {}
    persisted = d.get("network")
    if isinstance(persisted, dict) and persisted.get("host"):
        return persisted
    from app.services.network_context import build_network_context
    return build_network_context(d, host=loc.get("target"), url=loc.get("url"),
                                 path=loc.get("path"), resolve_dns=False)


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


def _asset_host_from_value(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = str(parsed.hostname or "").strip().lower()
    except Exception:
        host = ""
    if not host:
        host = raw.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip().lower()
    return host.lstrip("*.").strip(".")


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


def _consolidate_vulnerability_table(rows: list[dict]) -> list[dict]:
    """
    Agrupa vulnerabilidades com mesmo título+severidade em um único registro.

    Campos adicionados ao registro mesclado:
      - affected_assets: list[str]  — hosts/subdomínios afetados únicos
      - affected_ports:  list[str]  — portas únicas envolvidas
      - affected_count:  int        — total de instâncias originais
      - target_summary:  str        — resumo legível dos alvos (exibição no relatório)
    """
    from collections import OrderedDict as _OD
    grouped: _OD = _OD()

    for row in rows:
        _sev = str(row.get("severity") or "low").strip().lower()
        # Identidade canônica: se há CVE, a MESMA CVE é a MESMA vulnerabilidade
        # (mesmo que o título varie entre alvos) → dedup robusto multi-alvo.
        _cve = str(row.get("cve") or "").strip().upper()
        if _cve:
            key = (f"cve:{_cve}", _sev)
        else:
            key = (str(row.get("name") or "").strip().lower(), _sev)

        # asset defaults to "-" when not set — fall through to target/full_url in that case
        _asset_col = str(row.get("asset") or "").strip()
        _target_col = str(row.get("target") or row.get("full_url") or "").strip()
        # Prefer a real hostname over the placeholder "-"
        raw_asset = _asset_col if (_asset_col and _asset_col != "-") else _target_col
        if raw_asset.startswith(("http://", "https://")):
            _p = urlparse(raw_asset)
            raw_asset = _p.netloc or raw_asset

        raw_port = str(row.get("port") or "").strip()
        port_valid = raw_port and raw_port != "-"

        if key not in grouped:
            merged = dict(row)
            merged["affected_assets"] = [raw_asset] if raw_asset else []
            merged["affected_ports"] = [raw_port] if port_valid else []
            merged["affected_count"] = 1
            grouped[key] = merged
        else:
            existing = grouped[key]
            existing["affected_count"] = int(existing.get("affected_count") or 1) + 1
            if raw_asset and raw_asset not in existing["affected_assets"]:
                existing["affected_assets"].append(raw_asset)
            if port_valid and raw_port not in existing.get("affected_ports", []):
                existing.setdefault("affected_ports", []).append(raw_port)

    result: list[dict] = []
    for idx, (_, merged) in enumerate(grouped.items(), start=1):
        assets: list[str] = merged.get("affected_assets") or []
        ports: list[str] = merged.get("affected_ports") or []
        count: int = int(merged.get("affected_count") or 1)

        # Resumo legível dos alvos
        if count == 1:
            merged["target_summary"] = merged.get("target") or (assets[0] if assets else "-")
        elif len(assets) <= 3:
            merged["target_summary"] = ", ".join(assets)
        else:
            merged["target_summary"] = f"{', '.join(assets[:3])} (+{len(assets) - 3} alvos)"

        # Para portas, atualiza o campo port com lista compacta
        if ports:
            merged["port"] = ", ".join(ports)

        merged["index"] = idx
        result.append(merged)

    return result


def _flatten_expected_telemetry(expected_telemetry: Any) -> list[dict[str, Any]]:
    if not isinstance(expected_telemetry, list):
        return []
    out: list[dict[str, Any]] = []
    for item in expected_telemetry:
        if not isinstance(item, dict):
            continue
        source = _sanitize_text(item.get("source") or "")
        signals = item.get("signals") if isinstance(item.get("signals"), list) else []
        out.append(
            {
                "source": source,
                "signals": [_sanitize_text(str(signal)) for signal in signals if _sanitize_text(str(signal))],
            }
        )
    return out


def _bas_detection_status_rank(status_value: str) -> int:
    return {
        "detected": 4,
        "partial": 3,
        "missed": 2,
        "unknown": 1,
    }.get(str(status_value or "unknown").strip().lower(), 1)


def _merge_bas_detection_pack(current: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    if not current:
        return dict(candidate)
    current_status = str(current.get("detection_status") or "unknown").lower()
    candidate_status = str(candidate.get("detection_status") or "unknown").lower()
    if _bas_detection_status_rank(candidate_status) > _bas_detection_status_rank(current_status):
        merged = {**current, **candidate}
    else:
        merged = {**candidate, **current}
    for key in ["telemetry_observed", "expected_telemetry", "defensive_success_criteria"]:
        values: list[Any] = []
        for value in [current.get(key), candidate.get(key)]:
            if isinstance(value, list):
                values.extend(value)
        if values:
            # Dedupe complex values by JSON shape.
            seen: set[str] = set()
            unique: list[Any] = []
            for value in values:
                marker = json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
                if marker not in seen:
                    seen.add(marker)
                    unique.append(value)
            merged[key] = unique
    return merged


def _build_bas_detection_validation_report(
    *,
    job: ScanJob,
    trace_events: list[AgentTraceEvent],
    vulnerability_rows: list[dict],
) -> dict[str, Any]:
    """Build BAS/Purple Team report data from agent traces.

    This is intentionally conservative: without defensive telemetry connectors,
    detection_status remains "unknown". The report should show the expected
    control contract and the missing proof instead of implying detection.
    """
    techniques_by_id: dict[str, dict[str, Any]] = {}
    uncatalogued_events = 0

    for event in trace_events:
        payload = event.payload if isinstance(event.payload, dict) else {}
        technique = payload.get("adversary_technique")
        if not isinstance(technique, dict) or not str(technique.get("id") or "").strip():
            uncatalogued_events += 1
            continue

        technique_id = _sanitize_text(technique.get("id") or "")
        record = techniques_by_id.setdefault(
            technique_id,
            {
                "technique_id": technique_id,
                "name": _sanitize_text(technique.get("name") or technique_id),
                "description": _sanitize_multiline_text(technique.get("description") or ""),
                "kill_chain_stage": _sanitize_text(technique.get("kill_chain_stage") or ""),
                "framework_refs": technique.get("framework_refs") if isinstance(technique.get("framework_refs"), dict) else {},
                "app_phases": list(technique.get("app_phases") or []),
                "skills": set(),
                "tools": set(),
                "candidate_tools": set(str(tool) for tool in list(technique.get("candidate_tools") or []) if str(tool or "").strip()),
                "capabilities": set(),
                "iterations": set(),
                "events": [],
                "control_objectives": [],
                "expected_telemetry": [],
                "safe_execution": technique.get("safe_execution") if isinstance(technique.get("safe_execution"), dict) else {},
                "detection_proof_pack": {},
                "affected_findings": [],
            },
        )

        if event.skill_id:
            record["skills"].add(str(event.skill_id))
        if event.tool_name:
            record["tools"].add(str(event.tool_name))
        if event.capability:
            record["capabilities"].add(str(event.capability))
        record["iterations"].add(int(event.iteration or 0))
        for tool in list(payload.get("selected_tools_all") or payload.get("tools") or []):
            if str(tool or "").strip():
                record["tools"].add(str(tool).strip())
        for item in list(payload.get("control_objectives") or technique.get("control_objectives") or []):
            text_value = _sanitize_multiline_text(str(item))
            if text_value and text_value not in record["control_objectives"]:
                record["control_objectives"].append(text_value)
        for item in _flatten_expected_telemetry(payload.get("expected_telemetry") or technique.get("expected_telemetry")):
            marker = json.dumps(item, ensure_ascii=True, sort_keys=True)
            existing = {json.dumps(x, ensure_ascii=True, sort_keys=True) for x in record["expected_telemetry"]}
            if marker not in existing:
                record["expected_telemetry"].append(item)
        proof_pack = payload.get("detection_proof_pack")
        if isinstance(proof_pack, dict):
            record["detection_proof_pack"] = _merge_bas_detection_pack(record.get("detection_proof_pack") or {}, proof_pack)
        record["events"].append(
            {
                "event_id": event.id,
                "event_type": _sanitize_text(event.event_type or ""),
                "status": _sanitize_text(event.status or ""),
                "from_node": _sanitize_text(event.from_node or ""),
                "to_node": _sanitize_text(event.to_node or ""),
                "skill_id": _sanitize_text(event.skill_id or ""),
                "tool_name": _sanitize_text(event.tool_name or ""),
                "capability": _sanitize_text(event.capability or ""),
                "iteration": int(event.iteration or 0),
                "created_at": event.created_at.isoformat() if event.created_at else None,
            }
        )

    for record in techniques_by_id.values():
        candidate_tools = {str(tool).strip().lower() for tool in record.get("candidate_tools") or set()}
        affected: list[dict[str, Any]] = []
        for row in vulnerability_rows:
            row_tool = str(row.get("tool") or "").strip().lower()
            if row_tool and row_tool in candidate_tools:
                affected.append(
                    {
                        "id": row.get("id"),
                        "finding_id": row.get("finding_id"),
                        "name": row.get("name"),
                        "severity": row.get("severity"),
                        "target": row.get("target"),
                        "tool": row.get("tool"),
                        "validation_status": row.get("validation_status"),
                    }
                )
        record["affected_findings"] = affected[:25]

    technique_rows: list[dict[str, Any]] = []
    status_counts = {"detected": 0, "partial": 0, "missed": 0, "unknown": 0}
    for record in techniques_by_id.values():
        proof_pack = dict(record.get("detection_proof_pack") or {})
        detection_status = str(proof_pack.get("detection_status") or "unknown").strip().lower()
        if detection_status not in status_counts:
            detection_status = "unknown"
        status_counts[detection_status] += 1
        expected_sources = [
            item.get("source")
            for item in list(record.get("expected_telemetry") or [])
            if isinstance(item, dict) and item.get("source")
        ]
        technique_rows.append(
            {
                "technique_id": record["technique_id"],
                "name": record["name"],
                "description": record["description"],
                "kill_chain_stage": record["kill_chain_stage"],
                "framework_refs": record["framework_refs"],
                "app_phases": record["app_phases"],
                "skills": sorted(record["skills"]),
                "tools": sorted(record["tools"]),
                "candidate_tools": sorted(record["candidate_tools"]),
                "capabilities": sorted(record["capabilities"]),
                "iterations": sorted(record["iterations"]),
                "control_objectives": record["control_objectives"],
                "expected_telemetry": record["expected_telemetry"],
                "expected_sources": list(dict.fromkeys(expected_sources)),
                "detection_status": detection_status,
                "detection_proof_pack": {
                    "technique_id": proof_pack.get("technique_id") or record["technique_id"],
                    "detection_status": detection_status,
                    "correlation_id": _sanitize_text(proof_pack.get("correlation_id") or ""),
                    "alert_id": _sanitize_text(proof_pack.get("alert_id") or ""),
                    "alert_source": _sanitize_text(proof_pack.get("alert_source") or ""),
                    "detection_latency_seconds": proof_pack.get("detection_latency_seconds"),
                    "rule_name": _sanitize_text(proof_pack.get("rule_name") or ""),
                    "telemetry_observed": proof_pack.get("telemetry_observed") if isinstance(proof_pack.get("telemetry_observed"), list) else [],
                    "control_gap": _sanitize_multiline_text(
                        proof_pack.get("control_gap")
                        or ("Aguardando integração/evidência defensiva para confirmar detecção." if detection_status == "unknown" else "")
                    ),
                    "defensive_success_criteria": proof_pack.get("defensive_success_criteria") if isinstance(proof_pack.get("defensive_success_criteria"), list) else [],
                },
                "safe_execution": record["safe_execution"],
                "affected_findings": record["affected_findings"],
                "events": record["events"][:25],
                "event_count": len(record["events"]),
            }
        )

    technique_rows.sort(
        key=lambda item: (
            str(item.get("kill_chain_stage") or ""),
            str(item.get("technique_id") or ""),
        )
    )

    techniques_exercised = len(technique_rows)
    detection_ready = status_counts["detected"] + status_counts["partial"] + status_counts["missed"]
    telemetry_sources = sorted(
        {
            source
            for row in technique_rows
            for source in list(row.get("expected_sources") or [])
            if str(source or "").strip()
        }
    )
    return {
        "enabled": True,
        "mode": "BAS / Purple Team Detection Validation",
        "trace_id": (job.state_data or {}).get("trace_id") or f"scan-{job.id}",
        "summary": {
            "techniques_exercised": techniques_exercised,
            "events_with_bas_context": sum(int(row.get("event_count") or 0) for row in technique_rows),
            "events_without_bas_context": uncatalogued_events,
            "detection_ready_techniques": detection_ready,
            "pending_defensive_evidence": status_counts["unknown"],
            "status_counts": status_counts,
            "expected_telemetry_sources": telemetry_sources,
            "coverage_note": (
                "Status defensivo permanece unknown até que conectores SIEM/WAF/EDR/CSPM "
                "ou evidência manual preencham detection_proof_pack."
            ),
        },
        "techniques": technique_rows,
        "control_matrix": [
            {
                "technique_id": row.get("technique_id"),
                "technique": row.get("name"),
                "stage": row.get("kill_chain_stage"),
                "controls": row.get("control_objectives") or [],
                "expected_sources": row.get("expected_sources") or [],
                "detection_status": row.get("detection_status"),
                "control_gap": (row.get("detection_proof_pack") or {}).get("control_gap") or "",
            }
            for row in technique_rows
        ],
    }


@router.post("/scans", response_model=ScanResponse)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    access_group_id = _resolve_access_group_id(
        db,
        current_user,
        payload.access_group_id,
        payload.access_group_name,
    )

    compliance_status = "approved"

    llm_risk_auth_type = str(payload.llm_risk_auth_type or "none").strip().lower()
    if payload.llm_risk_enabled and not str(payload.llm_risk_url or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL do LLM Risk Assessment e obrigatoria quando habilitado")

    llm_risk_state = {
        "enabled": bool(payload.llm_risk_enabled),
        "target_url": str(payload.llm_risk_url or "").strip(),
        "auth_type": llm_risk_auth_type,
        "auth_header": str(payload.llm_risk_auth_header or "X-API-Key").strip(),
        "auth_value": str(payload.llm_risk_auth_value or "").strip(),
        "username": str(payload.llm_risk_auth_username or "").strip(),
        "password": str(payload.llm_risk_auth_password or "").strip(),
        "strategy_profile": str(payload.llm_risk_strategy_profile or "").strip() or "balanced",
        "request_template": str(payload.llm_risk_request_template or "").strip(),
        "response_field": str(payload.llm_risk_response_field or "").strip(),
    }

    scan_level = str(payload.scan_level or "full").lower().strip()
    if scan_level not in {"full", "asm"}:
        scan_level = "full"
    auth_config = payload.auth_config if isinstance(payload.auth_config, dict) else None
    initial_state: dict[str, Any] = {
        "llm_risk": llm_risk_state,
        "scan_level": scan_level,
        "parallelize": bool(settings.scan_parallelize_default),
        "parallel_target_batch_size": int(settings.scan_parallel_target_batch_size or 1024),
        "parallel_wait_seconds": int(settings.scan_parallel_wait_seconds or 60),
    }
    if auth_config:
        initial_state["auth_config"] = auth_config

    job = ScanJob(
        owner_id=current_user.id,
        access_group_id=access_group_id,
        target_query=payload.target_query,
        mode=payload.mode,
        status="queued" if compliance_status == "approved" else "blocked",
        compliance_status=compliance_status,
        authorization_id=None,
        current_step="1. Amass Subdomain Recon",
        state_data=initial_state,
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
            metadata={"target": payload.target_query, "mode": payload.mode},
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
            state_data={"subdomain_coverage": (s.state_data or {}).get("subdomain_coverage") or {}},
        )
        for s in rows
    ]


@router.get("/reports/by-target")
def list_report_targets(
    limit: int = Query(default=500, ge=1, le=5000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scans = (
        _authorized_scan_query(db, current_user)
        .filter(ScanJob.status == "completed")
        .order_by(ScanJob.created_at.desc(), ScanJob.id.desc())
        .limit(limit)
        .all()
    )

    latest_by_target: dict[str, dict[str, Any]] = {}
    for scan in scans:
        for token in _target_tokens(scan.target_query):
            if token in latest_by_target:
                continue
            latest_by_target[token] = {
                "target": token,
                "scan_id": scan.id,
                "scan_created_at": scan.created_at,
                "target_query": scan.target_query,
            }

    return sorted(latest_by_target.values(), key=lambda item: str(item.get("target") or ""))


@router.get("/reports/by-target/latest")
def get_latest_scan_by_target(
    target: str = Query(..., min_length=1, max_length=255),
    search_limit: int = Query(default=5000, ge=1, le=20000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    normalized_target = _primary_target_token(target)
    if not normalized_target:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Alvo invalido")

    scans = (
        _authorized_scan_query(db, current_user)
        .filter(ScanJob.status == "completed")
        .order_by(ScanJob.created_at.desc(), ScanJob.id.desc())
        .limit(search_limit)
        .all()
    )

    for scan in scans:
        if normalized_target in _target_tokens(scan.target_query):
            return {
                "target": normalized_target,
                "scan_id": scan.id,
                "scan_created_at": scan.created_at,
                "target_query": scan.target_query,
            }

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nenhum scan concluido encontrado para este alvo")


def _build_tool_execution_summary(job: ScanJob, scan_logs: list[ScanLog], tools: list[str]) -> dict:
    state = job.state_data or {}
    raw_runs = list(state.get("executed_tool_runs") or [])

    targets_by_tool: dict[str, set[str]] = {}
    status_by_tool: dict[str, dict[str, int]] = {}
    return_codes_by_tool: dict[str, list[int]] = {}
    commands_by_tool: dict[str, list[str]] = {}

    for raw in raw_runs:
        if isinstance(raw, dict):
            tool = str(raw.get("tool") or raw.get("tool_name") or "").strip().lower()
            target = str(raw.get("target") or "").strip()
            st = str(raw.get("status") or "success").strip().lower()
            if tool:
                bucket = status_by_tool.setdefault(tool, {})
                bucket[st] = int(bucket.get(st, 0)) + 1
                if target:
                    targets_by_tool.setdefault(tool, set()).add(target)
                cmd = str(raw.get("command") or "").strip()
                if cmd:
                    commands_by_tool.setdefault(tool, []).append(cmd)
            continue
        run = str(raw or "").strip()
        parts = run.split("|")
        if len(parts) < 3:
            continue
        _, target, tool = parts[0], parts[1], parts[2].lower()
        if not tool:
            continue
        if target:
            targets_by_tool.setdefault(tool, set()).add(target)

    status_re = re.compile(r"tool=([a-z0-9_\-\.]+)\b.*?\bstatus=([a-z_\-]+)", re.IGNORECASE)
    rc_re = re.compile(r"tool=([a-z0-9_\-\.]+)\b.*?\breturn_code=([-0-9]+)", re.IGNORECASE)
    cmd_re = re.compile(r"tool=([a-z0-9_\-\.]+)\s+cmd=(.+)$", re.IGNORECASE)

    for log in scan_logs:
        message = str(log.message or "")

        status_match = status_re.search(message)
        if status_match:
            tool = str(status_match.group(1) or "").strip().lower()
            st = str(status_match.group(2) or "unknown").strip().lower()
            if tool:
                bucket = status_by_tool.setdefault(tool, {})
                bucket[st] = int(bucket.get(st, 0)) + 1

        rc_match = rc_re.search(message)
        if rc_match:
            tool = str(rc_match.group(1) or "").strip().lower()
            try:
                rc = int(str(rc_match.group(2) or "").strip())
            except Exception:
                rc = None
            if tool and rc is not None:
                return_codes_by_tool.setdefault(tool, []).append(rc)

        cmd_match = cmd_re.search(message)
        if cmd_match:
            tool = str(cmd_match.group(1) or "").strip().lower()
            cmd = str(cmd_match.group(2) or "").strip()
            if tool and cmd:
                commands_by_tool.setdefault(tool, []).append(cmd)

    normalized_tools = [str(t or "").strip().lower() for t in tools if str(t or "").strip()]
    requested_tools = sorted(set(normalized_tools))

    rows: list[dict] = []
    for tool in requested_tools:
        status_bucket = status_by_tool.get(tool, {})
        return_codes = return_codes_by_tool.get(tool, [])
        commands = commands_by_tool.get(tool, [])
        targets = sorted(list(targets_by_tool.get(tool, set())))
        attempted_events = int(sum(status_bucket.values()))
        executed_events = int(sum(
            status_bucket.get(st, 0)
            for st in ("executed", "success", "done", "completed")
        ))
        rows.append(
            {
                "tool": tool,
                "targets": targets,
                "targets_count": len(targets),
                "attempted_events": attempted_events,
                "executed_events": executed_events,
                "status_breakdown": status_bucket,
                "last_return_code": return_codes[-1] if return_codes else None,
                "sample_command": commands[-1] if commands else "",
            }
        )

    executed_tools_count = len([row for row in rows if row.get("executed_events", 0) > 0])
    attempted_tools_count = len([row for row in rows if row.get("attempted_events", 0) > 0 or row.get("targets_count", 0) > 0])

    return {
        "requested_tools": requested_tools,
        "tools": rows,
        "summary": {
            "requested_count": len(requested_tools),
            "attempted_count": attempted_tools_count,
            "executed_count": executed_tools_count,
        },
    }


def _build_vulnerability_execution_evidence(
    db: Session,
    scan_id: int,
    vuln_tools: list[str],
) -> dict[str, Any]:
    normalized = [str(tool or "").strip().lower() for tool in vuln_tools if str(tool or "").strip()]
    rows = (
        db.query(ExecutedToolRun)
        .filter(ExecutedToolRun.scan_job_id == scan_id)
        .all()
    )
    rows = [row for row in rows if str(row.tool_name or "").strip().lower() in set(normalized)]

    by_tool: dict[str, dict[str, Any]] = {}
    for row in rows:
        tool = str(row.tool_name or "unknown").strip().lower()
        bucket = by_tool.setdefault(
            tool,
            {
                "tool": tool,
                "success": 0,
                "failed": 0,
                "skipped": 0,
                "unknown": 0,
                "targets": set(),
                "last_execution_seconds": None,
            },
        )
        status = str(row.status or "unknown").strip().lower()
        if status == "success" or status == "executed":
            bucket["success"] += 1
        elif status == "failed":
            bucket["failed"] += 1
        elif status == "skipped":
            bucket["skipped"] += 1
        else:
            bucket["unknown"] += 1
        target = str(row.target or "").strip()
        if target:
            bucket["targets"].add(target)
        if row.execution_time_seconds is not None:
            bucket["last_execution_seconds"] = float(row.execution_time_seconds)

    tools = []
    total_success = 0
    total_failed = 0
    for tool in sorted(by_tool.keys()):
        item = by_tool[tool]
        total_success += int(item.get("success", 0))
        total_failed += int(item.get("failed", 0))
        item["targets"] = sorted(list(item.get("targets") or set()))
        item["targets_count"] = len(item["targets"])
        tools.append(item)

    return {
        "requested_tools": sorted(set(normalized)),
        "executions_found": len(rows),
        "tools": tools,
        "summary": {
            "executed_success": total_success,
            "executed_failed": total_failed,
            "has_evidence": len(rows) > 0,
        },
    }


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    if job.status in SCAN_ACTIVE_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nao e permitido excluir scan em execucao")

    # Evita violacao de FK quando algum heartbeat ainda referencia este scan.
    db.query(WorkerHeartbeat).filter(WorkerHeartbeat.current_scan_id == scan_id).update(
        {
            WorkerHeartbeat.current_scan_id: None,
            WorkerHeartbeat.status: "idle",
            WorkerHeartbeat.last_task_name: None,
        },
        synchronize_session=False,
    )

    # Evita violacoes de FK em cadeias derivadas do scan.
    # 1) Vulnerabilities pode referenciar findings do scan.
    finding_ids = [f.id for f in (job.findings or [])]
    if finding_ids:
        db.query(Vulnerability).filter(Vulnerability.finding_id.in_(finding_ids)).update(
            {Vulnerability.finding_id: None},
            synchronize_session=False,
        )

    # 2) Assets e historico temporal podem apontar para este scan.
    db.query(Asset).filter(Asset.last_scan_id == scan_id).update(
        {Asset.last_scan_id: None},
        synchronize_session=False,
    )
    db.query(AssetRatingHistory).filter(AssetRatingHistory.scan_id == scan_id).update(
        {AssetRatingHistory.scan_id: None},
        synchronize_session=False,
    )

    # 3) ExecutedToolRun, traces e scores referenciam scan_jobs sem cascade ORM;
    #    remover explicitamente para evitar ForeignKeyViolation no DELETE do scan.
    db.query(ExecutedToolRun).filter(ExecutedToolRun.scan_job_id == scan_id).delete(
        synchronize_session=False,
    )
    db.query(ScanAuditLog).filter(ScanAuditLog.scan_job_id == scan_id).delete(
        synchronize_session=False,
    )
    db.query(AgentTraceEvent).filter(AgentTraceEvent.scan_id == scan_id).delete(
        synchronize_session=False,
    )
    db.query(SkillScore).filter(SkillScore.scan_id == scan_id).delete(
        synchronize_session=False,
    )

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
    scan_rows = db.query(ScanJob.id, ScanJob.status, ScanJob.mode).all()
    scan_ids = [row.id for row in scan_rows]
    active_scan_ids = [row.id for row in scan_rows if row.status in SCAN_ACTIVE_STATUSES]
    # Regra operacional: preservar scans que ainda NAO aconteceram (fila).
    # Limpa apenas execucoes historicas e em andamento.
    resettable_statuses = {"running", "retrying", "paused", "completed", "failed", "stopped", "blocked"}
    resettable_scan_ids = [row.id for row in scan_rows if row.status in resettable_statuses]
    preserved_queued_scan_ids = [row.id for row in scan_rows if row.status == "queued"]

    revoked_task_ids: list[str] = []
    for scan_id in active_scan_ids:
        task_ids = _active_scan_task_ids(scan_id, db)
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

        deleted_audit_events = 0
        deleted_scan_logs = 0
        deleted_findings = 0
        deleted_executed_tool_runs = 0
        deleted_scan_audit_logs = 0
        deleted_scan_jobs = 0

        if resettable_scan_ids:
            finding_ids_subquery = (
                db.query(Finding.id)
                .filter(Finding.scan_job_id.in_(resettable_scan_ids))
                .subquery()
            )
            # Nullify nullable FKs pointing at findings/scan_jobs
            db.query(Vulnerability).filter(Vulnerability.finding_id.in_(finding_ids_subquery)).update(
                {Vulnerability.finding_id: None},
                synchronize_session=False,
            )
            db.query(Asset).filter(Asset.last_scan_id.in_(resettable_scan_ids)).update(
                {Asset.last_scan_id: None},
                synchronize_session=False,
            )
            db.query(AssetRatingHistory).filter(AssetRatingHistory.scan_id.in_(resettable_scan_ids)).update(
                {AssetRatingHistory.scan_id: None},
                synchronize_session=False,
            )
            # Delete child rows with NOT NULL FK before scan_jobs
            deleted_audit_events = (
                db.query(AuditEvent)
                .filter(AuditEvent.scan_job_id.in_(resettable_scan_ids))
                .delete(synchronize_session=False)
            )
            db.query(AgentTraceEvent).filter(AgentTraceEvent.scan_id.in_(resettable_scan_ids)).delete(synchronize_session=False)
            db.query(AgentActivityLog).filter(AgentActivityLog.scan_job_id.in_(resettable_scan_ids)).delete(synchronize_session=False)
            db.query(SkillScore).filter(SkillScore.scan_id.in_(resettable_scan_ids)).delete(synchronize_session=False)
            db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id.in_(resettable_scan_ids)).delete(synchronize_session=False)
            deleted_scan_logs = (
                db.query(ScanLog)
                .filter(ScanLog.scan_job_id.in_(resettable_scan_ids))
                .delete(synchronize_session=False)
            )
            deleted_findings = (
                db.query(Finding)
                .filter(Finding.scan_job_id.in_(resettable_scan_ids))
                .delete(synchronize_session=False)
            )
            deleted_executed_tool_runs = (
                db.query(ExecutedToolRun)
                .filter(ExecutedToolRun.scan_job_id.in_(resettable_scan_ids))
                .delete(synchronize_session=False)
            )
            deleted_scan_audit_logs = (
                db.query(ScanAuditLog)
                .filter(ScanAuditLog.scan_job_id.in_(resettable_scan_ids))
                .delete(synchronize_session=False)
            )
            deleted_scan_jobs = (
                db.query(ScanJob)
                .filter(ScanJob.id.in_(resettable_scan_ids))
                .delete(synchronize_session=False)
            )

        # Reinicia sequencias apenas se nao houver registros, para evitar colisao de PK
        remaining_scan_jobs = db.query(ScanJob.id).count()
        remaining_findings = db.query(Finding.id).count()
        remaining_scan_logs = db.query(ScanLog.id).count()
        remaining_scan_audit_logs = db.query(ScanAuditLog.id).count()
        if remaining_scan_jobs == 0:
            db.execute(text("ALTER SEQUENCE scan_jobs_id_seq RESTART WITH 1"))
        if remaining_findings == 0:
            db.execute(text("ALTER SEQUENCE findings_id_seq RESTART WITH 1"))
        if remaining_scan_logs == 0:
            db.execute(text("ALTER SEQUENCE scan_logs_id_seq RESTART WITH 1"))
        if remaining_scan_audit_logs == 0:
            db.execute(text("ALTER SEQUENCE scan_audit_logs_id_seq RESTART WITH 1"))

        preserved_schedules = db.query(ScheduledScan.id).filter(ScheduledScan.enabled.is_(True)).count()

        log_audit(
            db,
            event_type="scan.reset_operational",
            message="Reset operacional executado: scans, findings e logs removidos",
            actor_user_id=current_user.id,
            metadata={
                "scan_ids": scan_ids,
                "resettable_scan_ids": resettable_scan_ids,
                "preserved_queued_scan_ids": preserved_queued_scan_ids,
                "preserved_enabled_schedules": preserved_schedules,
                "revoked_task_ids": revoked_task_ids,
                "deleted": {
                    "scan_jobs": deleted_scan_jobs,
                    "findings": deleted_findings,
                    "executed_tool_runs": deleted_executed_tool_runs,
                    "scan_audit_logs": deleted_scan_audit_logs,
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
                "executed_tool_runs": deleted_executed_tool_runs,
                "scan_audit_logs": deleted_scan_audit_logs,
                "scan_logs": deleted_scan_logs,
                "audit_events": deleted_audit_events,
            },
            "preserved": {
                "queued_scans": len(preserved_queued_scan_ids),
                "enabled_schedules": preserved_schedules,
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

    if job.status not in SCAN_STOPPABLE_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Somente scans em execucao/fila podem ser interrompidos")

    task_ids = _active_scan_task_ids(scan_id, db)
    for task_id in task_ids:
        try:
            celery.control.revoke(task_id, terminate=True, signal="SIGTERM")
        except Exception:
            continue

    _clear_scan_worker_heartbeat(db, scan_id)
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


@router.post("/scans/{scan_id}/pause")
def pause_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    if job.status == "paused":
        return {"ok": True, "scan_id": scan_id, "status": "paused", "revoked_task_ids": [], "requeued_work_items": 0}
    if job.status not in SCAN_PAUSABLE_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Somente scans em execucao/fila podem ser pausados")

    task_ids = _active_scan_task_ids(scan_id, db)
    previous_step = str(job.current_step or "")
    requeued_items = _requeue_inflight_work_items_for_pause(db, scan_id)
    _clear_scan_worker_heartbeat(db, scan_id)

    state = dict(job.state_data or {})
    pause_control = dict(state.get("pause_control") or {})
    pause_control.update(
        {
            "paused_at": datetime.utcnow().isoformat(),
            "resume_step": previous_step,
            "revoked_task_ids": task_ids,
            "requeued_work_items": requeued_items,
        }
    )
    state["pause_control"] = pause_control
    job.state_data = state
    job.status = "paused"
    job.current_step = "Scan pausado manualmente"
    job.next_retry_at = None
    job.last_error = None

    db.add(
        ScanLog(
            scan_job_id=scan_id,
            source="manager",
            level="WARNING",
            message=(
                f"Scan pausado manualmente; operacao em andamento cancelada sem persistir resultado "
                f"(task_ids={task_ids or ['nao_encontrada']}, requeued_work_items={requeued_items})"
            ),
        )
    )
    log_audit(
        db,
        event_type="scan.paused",
        message=f"Scan {scan_id} pausado manualmente",
        actor_user_id=current_user.id,
        metadata={"scan_id": scan_id, "task_ids": task_ids, "requeued_work_items": requeued_items},
    )
    db.commit()

    for task_id in task_ids:
        try:
            celery.control.revoke(task_id, terminate=True, signal="SIGTERM")
        except Exception:
            continue

    return {
        "ok": True,
        "scan_id": scan_id,
        "status": "paused",
        "revoked_task_ids": task_ids,
        "requeued_work_items": requeued_items,
    }


@router.post("/scans/{scan_id}/resume")
def resume_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    if job.status not in SCAN_RESUMABLE_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Somente scans pausados podem ser retomados")

    state = dict(job.state_data or {})
    pause_control = dict(state.get("pause_control") or {})
    resume_step = str(pause_control.get("resume_step") or job.current_step or "Retomando scan")
    pause_control["resumed_at"] = datetime.utcnow().isoformat()
    state["pause_control"] = pause_control
    job.state_data = state
    job.status = "queued"
    job.current_step = resume_step
    job.next_retry_at = None
    job.last_error = None

    db.add(
        ScanLog(
            scan_job_id=scan_id,
            source="manager",
            level="INFO",
            message=f"Scan retomado manualmente a partir de: {resume_step}",
        )
    )
    log_audit(
        db,
        event_type="scan.resumed",
        message=f"Scan {scan_id} retomado manualmente",
        actor_user_id=current_user.id,
        metadata={"scan_id": scan_id, "resume_step": resume_step},
    )
    db.commit()

    task_id = None
    try:
        async_result = run_scan_job_scheduled.delay(job.id) if str(job.mode or "").lower() == "scheduled" else run_scan_job_unit.delay(job.id)
        task_id = getattr(async_result, "id", None)
    except Exception as exc:
        log_audit(
            db,
            event_type="scan.queue_fallback",
            message="Fila indisponivel, retomando scan de forma imediata",
            actor_user_id=current_user.id,
            scan_job_id=job.id,
            level="WARNING",
            metadata={"error": str(exc)},
        )
        db.commit()
        run_scan_job(job.id)

    return {"ok": True, "scan_id": scan_id, "status": "queued", "task_id": task_id}


@router.delete("/scans/{scan_id}/report")
def delete_scan_report(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    if job.status in SCAN_ACTIVE_STATUSES:
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
        raw_target_query = str(scan.target_query or "").strip()
        split_targets = [t.strip() for t in re.split(r"[;,]", raw_target_query) if str(t or "").strip()]
        if not split_targets and raw_target_query:
            split_targets = [raw_target_query]

        for key in split_targets:
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
    # Mapeia domínios principais para contagem de subdomínios
    domain_to_subdomains = {}
    for item in rows:
        if item["type"] == "domain":
            domain = item["name"].lower()
            domain_to_subdomains[domain] = 0
    for item in rows:
        name = item["name"].lower()
        for domain in domain_to_subdomains:
            if name != domain and name.endswith(f'.{domain}'):
                domain_to_subdomains[domain] += 1
    for item in rows:
        if item["type"] == "domain":
            item["subdomain_count"] = domain_to_subdomains.get(item["name"].lower(), 0)
    rows.sort(key=lambda item: item["last_seen_at"] or datetime.min, reverse=True)
    return rows[:500]


def _host_from_domain_value(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = str(parsed.hostname or "").strip().lower()
    except Exception:
        host = ""
    if not host:
        host = raw.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip().lower()
    return host.strip(".")


def _belongs_to_domain(host: str, domain: str) -> bool:
    clean_host = _host_from_domain_value(host)
    clean_domain = _host_from_domain_value(domain)
    return bool(clean_host and clean_domain and (clean_host == clean_domain or clean_host.endswith(f".{clean_domain}")))


def _empty_severity_counts() -> dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


@router.get("/domains/overview")
def domains_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scans = _authorized_scan_query(db, current_user).order_by(ScanJob.created_at.desc(), ScanJob.id.desc()).all()
    findings = _authorized_finding_query(db, current_user).order_by(Finding.created_at.desc()).all()

    domains: dict[str, dict[str, Any]] = {}

    def ensure_domain(domain_name: str, scan: ScanJob | None = None) -> dict[str, Any]:
        domain_host = _host_from_domain_value(domain_name)
        if not domain_host:
            domain_host = str(domain_name or "").strip().lower()
        item = domains.get(domain_host)
        if not item:
            item = {
                "domain": domain_host,
                "latest_scan_id": None,
                "latest_scan_status": None,
                "latest_scan_at": None,
                "scan_count": 0,
                "subdomains": {},
                "severity_counts": _empty_severity_counts(),
                "total_findings": 0,
            }
            domains[domain_host] = item
        if scan:
            current_at = item.get("latest_scan_at")
            if not current_at or (scan.created_at and scan.created_at >= current_at):
                item["latest_scan_id"] = scan.id
                item["latest_scan_status"] = scan.status
                item["latest_scan_at"] = scan.created_at
                item["_latest_scan_ref"] = scan  # kept for progress calculation, not serialized
        return item

    def ensure_subdomain(domain_item: dict[str, Any], host: str, scan: ScanJob | None = None) -> dict[str, Any]:
        clean_host = _host_from_domain_value(host) or str(host or "").strip().lower()
        if not clean_host:
            clean_host = str(domain_item["domain"])
        subdomains = domain_item["subdomains"]
        item = subdomains.get(clean_host)
        if not item:
            item = {
                "name": clean_host,
                "scan_id": None,
                "scan_status": None,
                "scan_created_at": None,
                "severity_counts": _empty_severity_counts(),
                "total_findings": 0,
                "findings": [],
            }
            subdomains[clean_host] = item
        if scan:
            current_at = item.get("scan_created_at")
            if not current_at or (scan.created_at and scan.created_at >= current_at):
                item["scan_id"] = scan.id
                item["scan_status"] = scan.status
                item["scan_created_at"] = scan.created_at
        return item

    scan_domains: dict[int, list[str]] = {}
    for scan in scans:
        roots = [_host_from_domain_value(token) for token in _target_tokens(scan.target_query)]
        roots = [root for root in roots if root]
        if not roots:
            fallback = _host_from_domain_value(scan.target_query)
            if fallback:
                roots = [fallback]
        scan_domains[scan.id] = roots
        for root in roots:
            domain_item = ensure_domain(root, scan)
            domain_item["scan_count"] += 1

            state = scan.state_data if isinstance(scan.state_data, dict) else {}
            raw_assets: list[Any] = []
            raw_assets.extend(state.get("lista_ativos", []) or [])
            raw_assets.extend(state.get("discovered_assets", []) or [])
            raw_assets.extend(state.get("hosts", []) or [])
            raw_assets.extend(_target_tokens(scan.target_query))
            for asset in raw_assets:
                host = _host_from_domain_value(asset)
                if host and _belongs_to_domain(host, root):
                    ensure_subdomain(domain_item, host, scan)

    lifecycle_status = _build_finding_lifecycle_status_map(findings)
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for finding in findings:
        scan = finding.scan_job
        loc = _extract_finding_location(finding)
        host = _host_from_domain_value(loc.get("subdomain") or loc.get("target") or finding.domain)
        roots = scan_domains.get(finding.scan_job_id or 0) or []
        matching_root = next((root for root in roots if _belongs_to_domain(host, root)), None)
        if not matching_root and roots:
            matching_root = roots[0]
        if not matching_root:
            matching_root = _host_from_domain_value(finding.domain or host)
        if not matching_root:
            continue

        domain_item = ensure_domain(matching_root, scan)
        sub_item = ensure_subdomain(domain_item, host or matching_root, scan)
        sev = str(finding.severity or "info").lower()
        if sev not in sub_item["severity_counts"]:
            sev = "info"

        details = finding.details or {}

        # Only count/list "open" findings in the domain/subdomain totals —
        # closed or false_positive findings are persisted historically but
        # should not inflate the current attack-surface view.
        finding_lifecycle = lifecycle_status.get(finding.id, "open")
        if finding_lifecycle == "open":
            sub_item["severity_counts"][sev] += 1
            sub_item["total_findings"] += 1
            domain_item["severity_counts"][sev] += 1
            domain_item["total_findings"] += 1

        # Collect port data from any finding (not filtered by lifecycle)
        port_val = details.get("port")
        if port_val:
            port_num = str(port_val)
            proto = str(details.get("protocol") or "tcp").lower()
            service = str(details.get("service") or details.get("service_name") or "").strip()
            ports_map = sub_item.setdefault("ports", {})
            pk = f"{port_num}/{proto}"
            if pk not in ports_map:
                ports_map[pk] = {"port": port_num, "protocol": proto, "service": service, "count": 0}
            elif service and not ports_map[pk]["service"]:
                ports_map[pk]["service"] = service
            ports_map[pk]["count"] += 1

        from app.services.vuln_family import classify_family as _cf_d, family_label as _fl_d
        _fam_d = _cf_d(
            title=finding.title, tool=finding.tool,
            owasp=str((finding.details or {}).get("owasp_category") or ""), cve=finding.cve,
            learning_family=((finding.details or {}).get("learning_source") or {}).get("vuln_family"),
        )
        sub_item["findings"].append(
            {
                "id": finding.id,
                "scan_id": finding.scan_job_id,
                "scan_status": scan.status if scan else None,
                "scan_created_at": scan.created_at if scan else None,
                "title": finding.title,
                "vuln_family": _fam_d,
                "vuln_family_label": _fl_d(_fam_d),
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "cve": finding.cve,
                "cvss": finding.cvss,
                "lifecycle_status": finding_lifecycle,
                "url": loc.get("url"),
                "path": loc.get("path"),
                "created_at": finding.created_at,
            }
        )

    # ── Per-subdomain analysis status from scan_work_items ──────────────────
    # Query work item counts grouped by (scan_job_id, target) for each domain's
    # latest scan. This gives us: how many subdomains are done / in progress / waiting.
    latest_scan_ids: set[int] = {
        domain_item["latest_scan_id"]
        for domain_item in domains.values()
        if domain_item.get("latest_scan_id")
    }

    wq_by_target: dict[tuple[int, str], dict] = {}
    if latest_scan_ids:
        _ACTIVE_ST = ["dispatched", "running", "submitted", "retry"]
        _QUEUED_ST = ["queued", "blocked"]
        _TERM_ST   = ["completed", "done", "failed", "timeout", "skipped"]

        wq_rows = (
            db.query(
                ScanWorkItem.scan_job_id,
                ScanWorkItem.target,
                func.sum(
                    sa_case((ScanWorkItem.status.in_(_ACTIVE_ST), 1), else_=0)
                ).label("active"),
                func.sum(
                    sa_case((ScanWorkItem.status.in_(_QUEUED_ST), 1), else_=0)
                ).label("queued"),
                func.sum(
                    sa_case((ScanWorkItem.status.in_(_TERM_ST), 1), else_=0)
                ).label("terminal"),
            )
            .filter(ScanWorkItem.scan_job_id.in_(latest_scan_ids))
            .group_by(ScanWorkItem.scan_job_id, ScanWorkItem.target)
            .all()
        )
        for r in wq_rows:
            norm = _host_from_domain_value(r.target) or str(r.target).strip().lower()
            wq_by_target[(r.scan_job_id, norm)] = {
                "active": int(r.active or 0),
                "queued": int(r.queued or 0),
                "terminal": int(r.terminal or 0),
            }

        # ── Batch items: expandir para os targets constituintes ───────────────
        # Items com target="__batch__" cobrem múltiplos subdomínios via
        # item_metadata.batch_targets. Sem essa expansão, subdomínios que só
        # têm batch items aparecem como "not_started" mesmo estando em análise.
        batch_rows = (
            db.query(
                ScanWorkItem.scan_job_id,
                ScanWorkItem.status,
                ScanWorkItem.item_metadata,
            )
            .filter(
                ScanWorkItem.scan_job_id.in_(latest_scan_ids),
                ScanWorkItem.target == "__batch__",
            )
            .all()
        )
        for br in batch_rows:
            bt = (br.item_metadata or {}).get("batch_targets") or []
            if not bt:
                continue
            is_active   = br.status in set(_ACTIVE_ST)
            is_queued   = br.status in set(_QUEUED_ST)
            is_terminal = br.status in set(_TERM_ST)
            for raw_t in bt:
                norm_t = _host_from_domain_value(raw_t) or str(raw_t).strip().lower()
                key = (br.scan_job_id, norm_t)
                existing = wq_by_target.setdefault(key, {"active": 0, "queued": 0, "terminal": 0})
                if is_active:
                    existing["active"] += 1
                elif is_queued:
                    existing["queued"] += 1
                elif is_terminal:
                    existing["terminal"] += 1

    def _subdomain_analysis_status(
        scan_id: int | None, name: str
    ) -> tuple[str, int, int, int]:
        """Returns (status, active, queued, done) for a subdomain.
        status: 'done' | 'analyzing' | 'waiting' | 'not_started'

        Com batch items expandidos, um subdomain pode ter muitos terminal +
        alguns queued (de fases tardias ainda pendentes). Considera 'done'
        quando a maioria dos itens são terminais E nenhum está ativo.
        """
        if not scan_id:
            return "not_started", 0, 0, 0
        wq = wq_by_target.get((scan_id, name))
        if not wq:
            return "not_started", 0, 0, 0
        active   = wq["active"]
        queued   = wq["queued"]
        terminal = wq["terminal"]
        total    = active + queued + terminal
        if active > 0:
            return "analyzing", active, queued, terminal
        # "done" quando: nenhum item ativo E (sem queued OU terminal domina ≥ 60% do total)
        if terminal > 0 and queued == 0:
            return "done", 0, 0, terminal
        if terminal > 0 and total > 0 and (terminal / total) >= 0.6:
            return "done", 0, queued, terminal
        if queued > 0:
            return "waiting", 0, queued, terminal
        return "not_started", 0, 0, 0

    result = []
    for domain_item in domains.values():
        subdomains = list(domain_item["subdomains"].values())

        # Build domain-level ports table aggregating all subdomains
        domain_ports: dict[str, dict] = {}
        for subdomain in subdomains:
            for pk, pdata in (subdomain.get("ports") or {}).items():
                if pk not in domain_ports:
                    domain_ports[pk] = {
                        "port": pdata["port"],
                        "protocol": pdata["protocol"],
                        "service": pdata["service"],
                        "subdomain_count": 0,
                        "subdomains": [],
                    }
                elif pdata["service"] and not domain_ports[pk]["service"]:
                    domain_ports[pk]["service"] = pdata["service"]
                domain_ports[pk]["subdomain_count"] += 1
                domain_ports[pk]["subdomains"].append(subdomain.get("name", ""))

        for subdomain in subdomains:
            subdomain["findings"].sort(
                key=lambda row: (
                    severity_rank.get(str(row.get("severity") or "info").lower(), 9),
                    -int(row.get("risk_score") or 0),
                    str(row.get("title") or "").lower(),
                )
            )
            # Expose ports list (sorted by port number) for each subdomain
            subdomain["ports"] = sorted(
                subdomain.get("ports", {}).values(),
                key=lambda p: (int(p["port"]) if str(p["port"]).isdigit() else 9999),
            )
            # Annotate each subdomain with its analysis status from work queue
            _scan_id = domain_item.get("latest_scan_id")
            _sub_status, _sub_active, _sub_queued, _sub_done = _subdomain_analysis_status(
                _scan_id, subdomain.get("name", "")
            )
            subdomain["analysis_status"] = _sub_status
            subdomain["work_active"] = _sub_active
            subdomain["work_queued"] = _sub_queued
            subdomain["work_done"] = _sub_done

        subdomains.sort(
            key=lambda row: (
                -int(row.get("total_findings") or 0),
                severity_rank.get(
                    next((sev for sev, count in row.get("severity_counts", {}).items() if count), "info"),
                    9,
                ),
                str(row.get("name") or ""),
            )
        )
        # Subdomínios excluindo o próprio domínio raiz
        sub_only = [row for row in subdomains if row.get("name") != domain_item["domain"]]
        subdomain_count = len(sub_only)

        # Ativo: subdomínio com pelo menos 1 finding (foi sondado e respondeu)
        active_count = sum(1 for row in sub_only if int(row.get("total_findings") or 0) > 0)
        inactive_count = subdomain_count - active_count

        # Per-subdomain analysis status aggregation
        analyzed_count = sum(1 for row in sub_only if row.get("analysis_status") == "done")
        analyzing_count = sum(1 for row in sub_only if row.get("analysis_status") == "analyzing")
        waiting_count = sum(1 for row in sub_only if row.get("analysis_status") == "waiting")
        not_started_count = sum(1 for row in sub_only if row.get("analysis_status") == "not_started")
        subdomain_progress_pct = int(analyzed_count * 100 / subdomain_count) if subdomain_count > 0 else 0

        # Sort ports by port number
        ports_list = sorted(
            domain_ports.values(),
            key=lambda p: (int(p["port"]) if str(p["port"]).isdigit() else 9999),
        )

        result.append(
            {
                "domain": domain_item["domain"],
                "latest_scan_id": domain_item["latest_scan_id"],
                "latest_scan_status": domain_item["latest_scan_status"],
                "latest_scan_at": domain_item["latest_scan_at"],
                "scan_count": domain_item["scan_count"],
                "subdomain_count": subdomain_count,
                # Per-subdomain analysis coverage
                "subdomain_progress_pct": subdomain_progress_pct,
                "analyzed_subdomain_count": analyzed_count,
                "analyzing_subdomain_count": analyzing_count,
                "waiting_subdomain_count": waiting_count,
                "not_started_subdomain_count": not_started_count,
                # Legacy / compat
                "scanned_subdomain_count": analyzed_count,
                "active_subdomain_count": active_count,
                "inactive_subdomain_count": inactive_count,
                "severity_counts": domain_item["severity_counts"],
                "total_findings": domain_item["total_findings"],
                "ports": ports_list,
                "subdomains": subdomains,
            }
        )

    result.sort(key=lambda item: (-(item.get("total_findings") or 0), str(item.get("domain") or "")))
    return result


@router.get("/findings/timeline")
def findings_timeline(
    days: int = Query(default=90, ge=7, le=730),
    severity: str | None = Query(default=None),
    target: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retorna a evolução acumulada de findings ao longo do tempo, agrupada por dia.

    Cada ponto representa a contagem acumulada de findings (por severidade) descobertos
    até aquela data, considerando todos os scans dentro da janela de 'days' dias.

    Também retorna:
    - daily_new: novos findings por dia (para gráfico de barras)
    - by_target: top alvos por volume de findings
    - by_type: top tipos/títulos de findings
    - summary: contagens totais por severidade
    """
    from datetime import timezone as _tz

    cutoff = datetime.now(tz=_tz.utc) - timedelta(days=days)

    query = _authorized_finding_query(db, current_user).filter(
        Finding.created_at >= cutoff,
        Finding.is_false_positive.is_(False),
    )
    if severity:
        sev_clean = str(severity).strip().lower()
        query = query.filter(Finding.severity == sev_clean)
    if target:
        query = query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))

    findings = query.order_by(Finding.created_at.asc()).all()

    SEV_ORDER = ["critical", "high", "medium", "low", "info"]

    # ─── daily_new: {date_str: {sev: count}} ──────────────────────────
    daily_raw: dict[str, dict[str, int]] = {}
    for f in findings:
        ts = f.created_at
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=_tz.utc)
        day = ts.strftime("%Y-%m-%d")
        sev = str(f.severity or "info").strip().lower()
        daily_raw.setdefault(day, {})
        daily_raw[day][sev] = daily_raw[day].get(sev, 0) + 1

    # fill gaps between first and last day
    if daily_raw:
        from datetime import date as _date
        all_days = sorted(daily_raw.keys())
        start_d = _date.fromisoformat(all_days[0])
        end_d = _date.fromisoformat(all_days[-1])
        delta = (end_d - start_d).days
        for i in range(delta + 1):
            d = (start_d + timedelta(days=i)).isoformat()
            daily_raw.setdefault(d, {})

    daily_new = [
        {"date": day, **{sev: daily_raw[day].get(sev, 0) for sev in SEV_ORDER}}
        for day in sorted(daily_raw.keys())
    ]

    # ─── cumulative: running total per severity ──────────────────────
    running: dict[str, int] = {sev: 0 for sev in SEV_ORDER}
    cumulative = []
    for point in daily_new:
        for sev in SEV_ORDER:
            running[sev] += int(point.get(sev, 0))
        cumulative.append({"date": point["date"], **dict(running)})

    # ─── by_target: top 15 alvos ─────────────────────────────────────
    target_counts: dict[str, int] = {}
    for f in findings:
        tq = str((f.scan_job.target_query if f.scan_job else None) or "").strip()
        for tok in _target_tokens(tq):
            target_counts[tok] = target_counts.get(tok, 0) + 1
    by_target = sorted(
        [{"target": k, "count": v} for k, v in target_counts.items()],
        key=lambda x: -x["count"],
    )[:15]

    # ─── by_type: top 15 tipos ──────────────────────────────────────
    type_counts: dict[str, int] = {}
    for f in findings:
        title = str(f.title or "unknown").strip()
        type_counts[title] = type_counts.get(title, 0) + 1
    by_type = sorted(
        [{"title": k, "count": v} for k, v in type_counts.items()],
        key=lambda x: -x["count"],
    )[:15]

    # ─── summary ─────────────────────────────────────────────────────
    summary = {sev: 0 for sev in SEV_ORDER}
    for f in findings:
        sev = str(f.severity or "info").strip().lower()
        if sev in summary:
            summary[sev] += 1
    summary["total"] = len(findings)

    return {
        "days": days,
        "severity_filter": severity,
        "target_filter": target,
        "summary": summary,
        "daily_new": daily_new,
        "cumulative": cumulative,
        "by_target": by_target,
        "by_type": by_type,
    }


@router.get("/vulnerability-management/dashboard")
def vulnerability_management_dashboard(
    target: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=3000, ge=100, le=10000),
    period_days: int | None = Query(default=None, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_weight = {"critical": 20, "high": 12, "medium": 7, "low": 3, "info": 1}

    query = _authorized_finding_query(db, current_user).filter(Finding.is_false_positive.is_(False))
    lifecycle_query = _authorized_finding_query(db, current_user)

    target_filter = str(target or "").strip()
    if target_filter:
        ilike_target = f"%{target_filter}%"
        query = query.filter((ScanJob.target_query.ilike(ilike_target)) | (Finding.domain.ilike(ilike_target)))
        lifecycle_query = lifecycle_query.filter((ScanJob.target_query.ilike(ilike_target)) | (Finding.domain.ilike(ilike_target)))

    severity_filter = str(severity or "").strip().lower()
    if severity_filter:
        query = query.filter(Finding.severity == severity_filter)
        lifecycle_query = lifecycle_query.filter(Finding.severity == severity_filter)

    if period_days:
        window_start = datetime.utcnow() - timedelta(days=int(period_days))
        query = query.filter(Finding.created_at >= window_start)
        lifecycle_query = lifecycle_query.filter(Finding.created_at >= window_start)

    total_candidates = query.count()

    findings = query.order_by(Finding.created_at.desc()).limit(limit).all()
    lifecycle_rows = lifecycle_query.order_by(Finding.created_at.desc()).limit(max(limit * 2, 6000)).all()
    lifecycle_status = _build_finding_lifecycle_status_map(lifecycle_rows)

    available_targets: set[str] = set()
    for row in lifecycle_rows:
        if row.domain:
            available_targets.add(str(row.domain).strip())
        if row.scan_job:
            for token in _target_tokens(str(row.scan_job.target_query or "")):
                available_targets.add(token)

    severity_counts = {sev: 0 for sev in sev_order}
    age_env_days: list[int] = []
    age_market_days: list[int] = []
    remediation = {"open": 0, "closed": 0, "false_positive": 0}

    grouped: dict[str, dict[str, Any]] = {}

    for finding in findings:
        sev = str(finding.severity or "info").strip().lower()
        if sev not in severity_counts:
            sev = "info"
        severity_counts[sev] += 1

        status_value = str(lifecycle_status.get(finding.id, "open"))
        if status_value not in remediation:
            status_value = "open"
        remediation[status_value] += 1

        age = compute_age_metrics(finding.created_at, finding.details if isinstance(finding.details, dict) else {})
        env_days = age.get("known_in_environment_days")
        market_days = age.get("known_in_market_days")
        if isinstance(env_days, int):
            age_env_days.append(env_days)
        if isinstance(market_days, int):
            age_market_days.append(market_days)

        loc = _extract_finding_location(finding)
        target_name = str(loc.get("target") or "").strip()
        path_name = str(loc.get("path") or "").strip()

        details = finding.details if isinstance(finding.details, dict) else {}
        nested = details.get("details") if isinstance(details.get("details"), dict) else {}
        recommendation = str(
            finding.recommendation
            or details.get("recommendation")
            or nested.get("recommendation")
            or ""
        ).strip()

        key = "|".join(
            [
                _sanitize_text(finding.title or "").lower(),
                _sanitize_text(sev).lower(),
                _sanitize_text(finding.cve or "").lower(),
                _sanitize_text(finding.tool or "").lower(),
            ]
        )
        bucket = grouped.get(key)
        if not bucket:
            bucket = {
                "vulnerability_key": key,
                "title": finding.title,
                "severity": sev,
                "cve": finding.cve,
                "cvss": finding.cvss,
                "tool": finding.tool,
                "recommendation": recommendation,
                "occurrence_count": 0,
                "open_count": 0,
                "closed_count": 0,
                "affected_targets": set(),
                "affected_paths": set(),
                "latest_seen_at": finding.created_at,
                "occurrences": [],
            }
            grouped[key] = bucket

        bucket["occurrence_count"] += 1
        if status_value == "closed":
            bucket["closed_count"] += 1
        else:
            bucket["open_count"] += 1

        if target_name:
            bucket["affected_targets"].add(target_name)
        if path_name:
            bucket["affected_paths"].add(path_name)
        if (finding.created_at or datetime.min) > (bucket.get("latest_seen_at") or datetime.min):
            bucket["latest_seen_at"] = finding.created_at

        bucket["occurrences"].append(
            {
                "finding_id": finding.id,
                "scan_job_id": finding.scan_job_id,
                "target": loc.get("target"),
                "subdomain": loc.get("subdomain"),
                "path": loc.get("path"),
                "url": loc.get("url"),
                "created_at": finding.created_at,
                "lifecycle_status": status_value,
                "recommendation": recommendation,
            }
        )

    vulnerabilities: list[dict[str, Any]] = []
    for bucket in grouped.values():
        vulnerabilities.append(
            {
                "vulnerability_key": bucket["vulnerability_key"],
                "title": bucket["title"],
                "severity": bucket["severity"],
                "cve": bucket["cve"],
                "cvss": bucket["cvss"],
                "tool": bucket["tool"],
                "recommendation": bucket["recommendation"],
                "occurrence_count": bucket["occurrence_count"],
                "open_count": bucket["open_count"],
                "closed_count": bucket["closed_count"],
                "affected_targets": sorted(list(bucket["affected_targets"])),
                "affected_paths": sorted(list(bucket["affected_paths"])),
                "latest_seen_at": bucket["latest_seen_at"],
                "occurrences": sorted(
                    bucket["occurrences"],
                    key=lambda item: str(item.get("created_at") or ""),
                    reverse=True,
                ),
            }
        )

    vulnerabilities.sort(
        key=lambda item: (
            -sev_weight.get(str(item.get("severity") or "info"), 1),
            -int(item.get("open_count") or 0),
            -int(item.get("occurrence_count") or 0),
        )
    )

    risk_points = sum(sev_weight.get(str(item.get("severity") or "info"), 1) * int(item.get("open_count") or 0) for item in vulnerabilities)
    score = max(0, 100 - min(95, int(risk_points * 1.6)))

    env_avg = round(sum(age_env_days) / len(age_env_days), 1) if age_env_days else None
    market_avg = round(sum(age_market_days) / len(age_market_days), 1) if age_market_days else None
    env_max = max(age_env_days) if age_env_days else None
    market_max = max(age_market_days) if age_market_days else None

    closed_total = int(remediation.get("closed") or 0)
    open_total = int(remediation.get("open") or 0)
    closure_rate = round((closed_total / max(1, closed_total + open_total)) * 100.0, 2)

    selected_target_url = None
    if target_filter:
        if target_filter.startswith("http://") or target_filter.startswith("https://"):
            selected_target_url = target_filter
        else:
            selected_target_url = f"https://{target_filter}"

    return {
        "filters": {
            "target": target_filter or None,
            "severity": severity_filter or None,
            "available_targets": sorted(list(available_targets))[:500],
            "selected_target_url": selected_target_url,
        },
        "overview": {
            "score": score,
            "total_vulnerabilities": len(vulnerabilities),
            "findings_total": len(findings),
            "severity_counts": severity_counts,
            "affected_targets": len({t for v in vulnerabilities for t in v.get("affected_targets", [])}),
        },
        "data_quality": {
            "window_days": int(period_days or 0),
            "limit": int(limit),
            "total_candidates": int(total_candidates),
            "returned_findings": len(findings),
            "truncated": bool(total_candidates > len(findings)),
            "coverage_percent": round((len(findings) / max(1, total_candidates)) * 100.0, 2),
        },
        "age": {
            "known_in_environment_avg_days": env_avg,
            "known_in_environment_max_days": env_max,
            "known_in_market_avg_days": market_avg,
            "known_in_market_max_days": market_max,
        },
        "remediation_history": {
            "open": open_total,
            "closed": closed_total,
            "false_positive": int(remediation.get("false_positive") or 0),
            "closure_rate_percent": closure_rate,
        },
        "vulnerabilities": vulnerabilities,
        "generated_at": datetime.utcnow().isoformat(),
    }


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

    lifecycle_query = _authorized_finding_query(db, current_user)
    if target:
        lifecycle_query = lifecycle_query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))
    lifecycle_rows = lifecycle_query.order_by(Finding.created_at.desc()).all()
    lifecycle_status = _build_finding_lifecycle_status_map(lifecycle_rows)

    rows = query.order_by(Finding.created_at.desc()).all()
    normalized_status = status_filter.strip().lower()
    if normalized_status in {"open", "closed", "false_positive"}:
        rows = [finding for finding in rows if lifecycle_status.get(finding.id, "open") == normalized_status]
    rows = rows[:max_limit]
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
                "cvss": finding.cvss,
                "domain": finding.domain,
                "tool": finding.tool,
                "recommendation": finding.recommendation,
                "lifecycle_status": lifecycle_status.get(finding.id, "open"),
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
    scan_id: int | None = Query(default=None, ge=1),
    sort: str = Query(default="severity"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=50000),
    verification_status: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = _authorized_finding_query(db, current_user)

    # ── Evidence gate filter (T1 / M3) ──────────────────────────────────────
    _VALID_VSTATUS = {"confirmed", "candidate", "hypothesis", "refuted", "none"}
    if verification_status:
        _vs = verification_status.strip().lower()
        if _vs in _VALID_VSTATUS:
            if _vs == "none":
                query = query.filter(Finding.verification_status.is_(None))
            else:
                query = query.filter(Finding.verification_status == _vs)

    if severity:
        severity_values = [
            item.strip().lower()
            for item in re.split(r"[,;\s]+", severity)
            if item.strip().lower() in {"critical", "high", "medium", "low", "info"}
        ]
        if severity_values:
            query = query.filter(Finding.severity.in_(severity_values))
    if target:
        query = query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))
    if scan_id:
        query = query.filter(Finding.scan_job_id == scan_id)

    lifecycle_query = _authorized_finding_query(db, current_user)
    if target:
        lifecycle_query = lifecycle_query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))
    if scan_id:
        lifecycle_query = lifecycle_query.filter(Finding.scan_job_id == scan_id)
    lifecycle_rows = lifecycle_query.order_by(Finding.created_at.desc()).all()
    lifecycle_status = _build_finding_lifecycle_status_map(lifecycle_rows)

    rows = query.all()
    normalized_status = status_filter.strip().lower()
    if normalized_status in {"open", "closed", "false_positive"}:
        rows = [finding for finding in rows if lifecycle_status.get(finding.id, "open") == normalized_status]

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def _created_ts(finding: Finding) -> float:
        try:
            return float(finding.created_at.timestamp()) if finding.created_at else 0.0
        except Exception:
            return 0.0

    normalized_sort = str(sort or "severity").strip().lower()
    if normalized_sort == "date_asc":
        rows.sort(key=lambda finding: _created_ts(finding))
    elif normalized_sort == "date_desc":
        rows.sort(key=lambda finding: -_created_ts(finding))
    elif normalized_sort == "scan_asc":
        rows.sort(key=lambda finding: (int(finding.scan_job_id or 0), -_created_ts(finding)))
    elif normalized_sort == "scan_desc":
        rows.sort(key=lambda finding: (-int(finding.scan_job_id or 0), -_created_ts(finding)))
    elif normalized_sort == "target":
        rows.sort(key=lambda finding: (str(finding.scan_job.target_query if finding.scan_job else "").lower(), -_created_ts(finding)))
    elif normalized_sort == "tool":
        rows.sort(key=lambda finding: (str(finding.tool or "").lower(), severity_rank.get(str(finding.severity or "info").lower(), 9), -_created_ts(finding)))
    else:
        rows.sort(
            key=lambda finding: (
                severity_rank.get(str(finding.severity or "info").lower(), 9),
                -float(finding.risk_score or 0),
                -_created_ts(finding),
            )
        )

    total = len(rows)

    # Severity breakdown BEFORE pagination — espelha exatamente o que o relatório faz
    from app.services.vuln_family import classify_family as _cf_count, family_label as _fl_count
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    family_counts: dict[str, dict] = {}
    for _f in rows:
        _sev = str(_f.severity or "info").lower()
        if _sev in severity_counts:
            severity_counts[_sev] += 1
        _d = _f.details or {}
        _famc = _cf_count(
            title=_f.title, tool=_f.tool, owasp=str(_d.get("owasp_category") or ""),
            cve=_f.cve, learning_family=(_d.get("learning_source") or {}).get("vuln_family"),
        )
        _slot = family_counts.setdefault(_famc, {"family": _famc, "label": _fl_count(_famc), "count": 0})
        _slot["count"] += 1

    rows = rows[offset:offset + limit]

    from app.services.vuln_family import classify_family, family_label
    from app.services.framework_mapping import attack_for_family
    from app.services.verification_criteria import verification_for

    items = []
    for finding in rows:
        details = finding.details or {}
        loc = _extract_finding_location(finding)
        age = compute_age_metrics(finding.created_at, details)
        fair = compute_fair_metrics(finding.severity, finding.confidence_score, details, age)
        _fam = classify_family(
            title=finding.title,
            tool=finding.tool,
            owasp=str(details.get("owasp_category") or ""),
            cve=finding.cve,
            learning_family=(details.get("learning_source") or {}).get("vuln_family"),
        )
        items.append(
            {
                "id": finding.id,
                "scan_job_id": finding.scan_job_id,
                "target_query": finding.scan_job.target_query if finding.scan_job else None,
                "scan_status": finding.scan_job.status if finding.scan_job else None,
                "title": finding.title,
                "vuln_family": _fam,
                "vuln_family_label": family_label(_fam),
                "mitre_attack": attack_for_family(_fam),
                "verification_criteria": verification_for(_fam),
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "confidence_score": finding.confidence_score,
                "is_false_positive": finding.is_false_positive,
                "retest_status": finding.retest_status,
                "cve": finding.cve,
                "cvss": finding.cvss,
                "cve_description": (
                    details.get("cve_description") or
                    details.get("description") or
                    details.get("desc") or
                    ""
                ),
                "domain": finding.domain,
                "target": loc.get("target"),
                "subdomain": loc.get("subdomain"),
                "path": loc.get("path"),
                "network": _finding_network_context(finding, loc),
                "url": loc.get("url"),
                "tool": finding.tool,
                "recommendation": finding.recommendation,
                "lifecycle_status": lifecycle_status.get(finding.id, "open"),
                "details": details,
                "age": age,
                "fair": fair,
                "created_at": finding.created_at,
                # ── Evidence gate / M3 ───────────────────────────────────────
                "verification_status": finding.verification_status,
                "finding_url": finding.url,
            }
        )

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "sort": normalized_sort,
        "scan_id": scan_id,
        "severity_counts": severity_counts,
        "family_counts": sorted(family_counts.values(), key=lambda x: -x["count"]),
    }


@router.get("/findings/export.csv")
def export_findings_csv(
    severity: str | None = None,
    status_filter: str = "all",
    target: str | None = None,
    scan_id: int | None = Query(default=None, ge=1),
    verification_status: str | None = Query(default=None),
    dedupe: bool = Query(default=True),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Exporta vulnerabilidades em CSV: ID, scan, subdomínio, CVSS (criticidade),
    CVE, recomendação. Respeita os mesmos filtros da página. Por padrão DEDUPLICA
    vulnerabilidades repetidas (mesma família+host+CVE) entre os alvos/scans."""
    from app.services.vuln_family import classify_family, family_label
    query = _authorized_finding_query(db, current_user)

    _VALID_VSTATUS = {"confirmed", "candidate", "hypothesis", "refuted", "none"}
    if verification_status:
        _vs = verification_status.strip().lower()
        if _vs in _VALID_VSTATUS:
            if _vs == "none":
                query = query.filter(Finding.verification_status.is_(None))
            else:
                query = query.filter(Finding.verification_status == _vs)
    if severity:
        severity_values = [
            item.strip().lower()
            for item in re.split(r"[,;\s]+", severity)
            if item.strip().lower() in {"critical", "high", "medium", "low", "info"}
        ]
        if severity_values:
            query = query.filter(Finding.severity.in_(severity_values))
    if target:
        query = query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))
    if scan_id:
        query = query.filter(Finding.scan_job_id == scan_id)

    rows = query.order_by(Finding.id).all()

    # lifecycle p/ filtro de status
    if status_filter.strip().lower() in {"open", "closed", "false_positive"}:
        lc = _build_finding_lifecycle_status_map(rows)
        rows = [f for f in rows if lc.get(f.id, "open") == status_filter.strip().lower()]

    _SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "scan_id", "alvo", "subdominio", "host", "vulnerabilidade",
                     "familia", "severidade", "cvss", "cve", "verificacao", "url", "recomendacao"])

    seen: set[tuple] = set()
    deduped = 0
    for f in rows:
        loc = _extract_finding_location(f)
        details = f.details or {}
        fam = classify_family(
            title=f.title, tool=f.tool, owasp=str(details.get("owasp_category") or ""),
            cve=f.cve, learning_family=(details.get("learning_source") or {}).get("vuln_family"),
        )
        host = loc.get("subdomain") or loc.get("target") or f.domain or ""
        if dedupe:
            key = (fam, str(host).lower(), str(f.cve or "").lower(),
                   str(f.title or "").strip().lower()[:80])
            if key in seen:
                deduped += 1
                continue
            seen.add(key)
        writer.writerow([
            f.id, f.scan_job_id,
            (f.scan_job.target_query if f.scan_job else "") or "",
            loc.get("subdomain") or "", host,
            (f.title or ""), family_label(fam), (f.severity or ""),
            (f"{float(f.cvss):.1f}" if f.cvss is not None else ""),
            (f.cve or ""), (f.verification_status or ""),
            (loc.get("url") or f.url or ""), (f.recommendation or ""),
        ])

    csv_text = out.getvalue()
    scope = f"scan{scan_id}" if scan_id else (re.sub(r"[^a-zA-Z0-9]+", "_", target)[:30] if target else "todos")
    return Response(
        content=csv_text, media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="vulnerabilidades_{scope}.csv"',
                 "X-Deduped-Count": str(deduped)},
    )


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
    # Extract only the scalar columns and a handful of JSON subfields using
    # Postgres operators — avoids deserializing the full state_data JSONB blob
    # (can be 2–10 MB) on every 2-second frontend poll.
    sql = text("""
        SELECT
            id, status, compliance_status, current_step,
            mission_progress, retry_attempt, retry_max, next_retry_at, last_error,
            owner_id, access_group_id,
            COALESCE((state_data->>'mission_index')::int, 0)       AS mission_index,
            COALESCE(state_data->'mission_items',  '[]'::jsonb)     AS mission_items,
            COALESCE(state_data->'node_history',   '[]'::jsonb)     AS node_history,
            COALESCE(state_data->'discovered_ports','[]'::jsonb)    AS discovered_ports,
            COALESCE(state_data->'pending_port_tests','[]'::jsonb)  AS pending_port_tests,
            COALESCE(jsonb_array_length(state_data->'phase_ledger_v2'), 0) AS ledger_count
        FROM scan_jobs
        WHERE id = :scan_id
    """)
    row = db.execute(sql, {"scan_id": scan_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")
    if not current_user.is_admin:
        allowed_ids = {g.id for g in current_user.groups}
        if row["owner_id"] != current_user.id and row["access_group_id"] not in allowed_ids:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    raw_progress = int(row["mission_progress"] or 0)
    ledger_count = int(row["ledger_count"] or 0)
    if ledger_count:
        raw_progress = max(raw_progress, round((ledger_count / 22) * 100))
    max_progress = 100 if str(row["status"] or "").lower() in {"completed", "done", "finished"} else 99
    effective_progress = max(0, min(max_progress, raw_progress))

    return ScanStatusResponse(
        id=row["id"],
        status=row["status"],
        compliance_status=row["compliance_status"],
        current_step=row["current_step"],
        mission_progress=effective_progress,
        mission_index=row["mission_index"],
        mission_items=row["mission_items"] or [],
        node_history=row["node_history"] or [],
        discovered_ports=row["discovered_ports"] or [],
        pending_port_tests=row["pending_port_tests"] or [],
        retry_attempt=row["retry_attempt"],
        retry_max=row["retry_max"],
        next_retry_at=row["next_retry_at"],
        last_error=row["last_error"],
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


@router.get("/scans/{scan_id}/autonomy", response_model=AutonomyResponse)
def scan_autonomy(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retorna dados operacionais de autonomy (memória do agente)"""
    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    job = query.first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    # Extrair dados de autonomy do state_data
    state_data = job.state_data or {}
    autonomy_notes = state_data.get("autonomy_notes", [])
    autonomy_todos = state_data.get("autonomy_todos", [])
    autonomy_actions = state_data.get("autonomy_actions", [])
    autonomy_observations = state_data.get("autonomy_observations", [])
    autonomy_errors = state_data.get("autonomy_errors", [])
    delegated_tasks = state_data.get("delegated_tasks", [])
    active_skills = state_data.get("active_skills", [])
    execution_control = state_data.get("execution_control", {})

    # Buscar audit trail histórico
    audit_logs = db.query(ScanAuditLog).filter(ScanAuditLog.scan_job_id == scan_id).order_by(ScanAuditLog.created_at.asc()).all()
    audit_trail = [
        {
            "id": al.id,
            "iteration": al.iteration,
            "node_name": al.node_name,
            "entry_type": al.entry_type,
            "content": al.content,
            "created_at": al.created_at,
        }
        for al in audit_logs
    ]

    return AutonomyResponse(
        scan_id=scan_id,
        autonomy_notes=autonomy_notes,
        autonomy_todos=autonomy_todos,
        autonomy_actions=autonomy_actions,
        autonomy_observations=autonomy_observations,
        autonomy_errors=autonomy_errors,
        delegated_tasks=delegated_tasks,
        active_skills=active_skills,
        execution_control=execution_control,
        audit_trail=audit_trail,
    )


@router.get("/scans/{scan_id}/runtime")
def scan_runtime_feed(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return per-phase tool runtime data: command, stdout, stderr, return_code, status.

    This powers the RedTeam Runtime view that the operator uses to validate
    real tool output (not just truncated log lines).
    """
    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    job = query.first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    state = dict(job.state_data or {})
    ledgers = state.get("phase_ledger_v2") or state.get("phase_ledger") or []
    if not isinstance(ledgers, list):
        ledgers = []

    def _tool_backend(tool_name: str, profile: str = "") -> str:
        tool = str(tool_name or "").strip().lower()
        prof = str(profile or "").strip().lower()
        if tool in {"bl-test"} or prof in {"business_logic_backend"}:
            return "backend_local"
        if tool in {"manual_review", "manual_scope_review", "manual_correlation"} or tool.startswith("manual_"):
            return "manual"
        if tool in {"report-builder"} or prof in {"report_builder"}:
            return "reporting"
        return "kali"

    def _phase_runtime_status(counts: dict[str, int], ledger_status: str = "") -> str:
        total = int(counts.get("total", 0) or 0)
        terminal = int(counts.get("terminal", 0) or 0)
        active = int(counts.get("active", 0) or 0)
        blocked = int(counts.get("blocked", 0) or 0)
        failed = int(counts.get("failed", 0) or 0)
        if total > 0:
            if terminal == total:
                return "failed" if failed and failed == terminal else "completed"
            if active > 0:
                return "executing"
            if blocked > 0:
                return "gate_blocked"
            return "queued"
        normalized = str(ledger_status or "").lower()
        if normalized in {"completed", "partial"}:
            return "completed"
        if normalized in {"failed", "error"}:
            return "failed"
        if normalized == "blocked":
            return "gate_blocked"
        return "queued"

    runtime_by_key: dict[tuple[str, str], dict] = {}
    for ledger in ledgers:
        if not isinstance(ledger, dict):
            continue
        phase_id = str(ledger.get("phase_id") or "")
        phase_name = str(ledger.get("phase_name") or phase_id)
        target = str(ledger.get("target") or "")
        ledger_status = str(ledger.get("status") or "")
        mcp_results = ledger.get("mcp_results") or []
        tools_runtime: list[dict] = []
        for mcp in mcp_results:
            if not isinstance(mcp, dict):
                continue
            stdout_raw = str(mcp.get("stdout") or "")
            tool_name = str(mcp.get("tool_name") or "")
            profile = str(mcp.get("profile") or "")
            tools_runtime.append({
                "tool_name": tool_name,
                "profile": profile,
                "backend": _tool_backend(tool_name, profile),
                "status": mcp.get("status") or "",
                "command": mcp.get("command") or "",
                "stdout": stdout_raw[:6000],
                "stdout_truncated": len(stdout_raw) > 6000,
                "stdout_path": mcp.get("stdout_path") or "",
                "stderr_path": mcp.get("stderr_path") or "",
                "exit_code": mcp.get("exit_code"),
                "duration_seconds": mcp.get("duration_seconds"),
                "started_at": mcp.get("started_at") or "",
                "finished_at": mcp.get("finished_at") or "",
                "error": mcp.get("error"),
                "parsed_preview": str(mcp.get("parsed_result") or "")[:1500],
                "artifacts": mcp.get("artifact_paths") or mcp.get("artifacts") or [],
                "source": "phase_ledger_v2",
            })
        runtime_by_key[(phase_id, target)] = {
            "phase_id": phase_id,
            "phase_name": phase_name,
            "target": target,
            "status": ledger_status,
            "tools_attempted": ledger.get("tools_attempted") or [],
            "tools_success": ledger.get("tools_success") or [],
            "tools_failed": ledger.get("tools_failed") or [],
            "blocking_reason": ledger.get("blocking_reason"),
            "tools": tools_runtime,
        }

    # ── Progresso e fase atual AUTORITATIVOS (work_queue real, não o ledger) ──
    # O phase_ledger (LangGraph) fica obsoleto em scans work_queue e reporta
    # 100%/P01. A verdade é a razão terminal/efetivo da fila de work items.
    from app.models.models import ScanWorkItem as _SWI_rt
    _TERMINAL = {"completed", "done", "skipped", "failed", "timeout"}
    _wq_rows = (
        db.query(_SWI_rt.phase_id, _SWI_rt.status, func.count(_SWI_rt.id))
        .filter(_SWI_rt.scan_job_id == scan_id)
        .group_by(_SWI_rt.phase_id, _SWI_rt.status)
        .all()
    )
    _per_phase: dict[str, dict] = {}
    _total = _terminal = _blocked = 0
    for _ph, _st, _cnt in _wq_rows:
        _ph = str(_ph or "?")
        _st = str(_st or "")
        slot = _per_phase.setdefault(_ph, {"phase_id": _ph, "total": 0, "terminal": 0, "blocked": 0, "active": 0, "failed": 0})
        slot["total"] += _cnt
        _total += _cnt
        if _st in _TERMINAL:
            slot["terminal"] += _cnt
            _terminal += _cnt
            if _st in {"failed", "timeout"}:
                slot["failed"] += _cnt
        elif _st == "blocked":
            slot["blocked"] += _cnt
            _blocked += _cnt
        else:
            slot["active"] += _cnt

    _wq_tool_rows = (
        db.query(
            _SWI_rt.phase_id,
            _SWI_rt.tool_name,
            _SWI_rt.profile,
            _SWI_rt.status,
            func.count(_SWI_rt.id),
            func.max(_SWI_rt.last_error),
            func.max(_SWI_rt.started_at),
            func.max(_SWI_rt.finished_at),
        )
        .filter(_SWI_rt.scan_job_id == scan_id)
        .group_by(_SWI_rt.phase_id, _SWI_rt.tool_name, _SWI_rt.profile, _SWI_rt.status)
        .all()
    )
    _phase_names = {
        "P01": "Subdomain Enumeration",
        "P02": "Port Service Discovery",
        "P03": "Endpoint Discovery",
        "P04": "Parameter Discovery",
        "P05": "Surface Expansion",
        "P06": "HTTP Fingerprinting & WAF Detection",
        "P07": "Technology Detection",
        "P08": "JavaScript Endpoint Analysis",
        "P09": "Vulnerability Template Scan",
        "P10": "Injection Testing",
        "P11": "SSRF Testing",
        "P12": "XSS Testing",
        "P13": "Access Control & Business Logic",
        "P14": "Auth Boundary Testing",
        "P15": "File Handling Testing",
        "P16": "API Input Surface Review",
        "P17": "Exploit Validation",
        "P18": "Credential Exposure Boundary",
        "P19": "Post Exploitation Boundary",
        "P20": "Attack Path Correlation",
        "P21": "Evidence Quality Review",
        "P22": "Campaign Reporting",
    }
    for phase_id, tool_name, profile, status_value, count, last_error, started_at, finished_at in _wq_tool_rows:
        phase_id = str(phase_id or "")
        target = "all-targets"
        tool_name = str(tool_name or "")
        profile = str(profile or "")
        status_text = str(status_value or "")
        phase_key = (phase_id, target)
        phase_row = runtime_by_key.setdefault(
            phase_key,
            {
                "phase_id": phase_id,
                "phase_name": _phase_names.get(phase_id, phase_id),
                "target": target,
                "status": "",
                "tools_attempted": [],
                "tools_success": [],
                "tools_failed": [],
                "blocking_reason": None,
                "tools": [],
            },
        )
        normalized_status = {
            "completed": "success",
            "done": "success",
            "submitted": "running",
            "dispatched": "running",
            "retry": "running",
        }.get(status_text, status_text)
        phase_row["tools"].append({
            "tool_name": tool_name,
            "profile": profile,
            "backend": _tool_backend(tool_name, profile),
            "status": normalized_status,
            "command": "",
            "stdout": "",
            "stdout_truncated": False,
            "stdout_path": "",
            "stderr_path": "",
            "exit_code": None,
            "duration_seconds": None,
            "started_at": started_at.isoformat() if started_at else "",
            "finished_at": finished_at.isoformat() if finished_at else "",
            "error": last_error,
            "parsed_preview": "",
            "artifacts": [],
            "source": "scan_work_items",
            "count": int(count or 0),
        })
        if status_text in {"completed", "done", "failed", "timeout", "skipped", "submitted", "dispatched", "running", "retry"}:
            if tool_name not in phase_row["tools_attempted"]:
                phase_row["tools_attempted"].append(tool_name)
        if status_text in {"completed", "done"} and tool_name not in phase_row["tools_success"]:
            phase_row["tools_success"].append(tool_name)
        if status_text in {"failed", "timeout"} and tool_name not in phase_row["tools_failed"]:
            phase_row["tools_failed"].append(tool_name)

    for (phase_id, _target), phase_row in runtime_by_key.items():
        phase_counts = _per_phase.get(phase_id) or {}
        phase_row["status"] = _phase_runtime_status(phase_counts, str(phase_row.get("status") or ""))
    # progresso real: terminal / (total - blocked); cap 99 enquanto rodando
    _effective = max(1, _total - _blocked)
    if job.status in ("completed", "done", "finished"):
        _wq_progress = 100
    elif _total == 0:
        _wq_progress = int(job.mission_progress or 0)
    else:
        _wq_progress = min(99, int(_terminal / _effective * 100))
    # fase atual = menor phase_id (ordem) com itens ativos (não-terminais/não-bloqueados);
    # se nenhuma ativa, a menor com itens bloqueados (aguardando gate).
    _active_phases = sorted(p for p, s in _per_phase.items() if s["active"] > 0)
    _blocked_phases = sorted(p for p, s in _per_phase.items() if s["blocked"] > 0)
    if _active_phases:
        _current_phase = _active_phases[0]
    elif _blocked_phases:
        _current_phase = _blocked_phases[0]
    else:
        _current_phase = "—"
    _phase_progress = [
        {
            **v,
            "status": _phase_runtime_status(v),
            "pct": int(v["terminal"] / max(1, v["total"] - v["blocked"]) * 100) if (v["total"] - v["blocked"]) > 0 else 0,
        }
        for v in sorted(_per_phase.values(), key=lambda x: x["phase_id"])
    ]
    runtime = sorted(runtime_by_key.values(), key=lambda item: (str(item.get("phase_id") or ""), str(item.get("target") or "")))

    return {
        "scan_id": scan_id,
        "target_query": job.target_query,
        "status": job.status,
        # current_step/mission_progress agora refletem o work_queue real
        "current_step": _current_phase if _total > 0 else job.current_step,
        "mission_progress": _wq_progress,
        "work_queue": {
            "total": _total, "terminal": _terminal, "blocked": _blocked,
            "active": _total - _terminal - _blocked, "progress_pct": _wq_progress,
            "current_phase": _current_phase, "by_phase": _phase_progress,
        },
        "phases": runtime,
    }


@router.get("/scans/{scan_id}/work-queue")
def scan_work_queue_status(
    scan_id: int,
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

    rows = db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == scan_id).all()
    by_status: dict[str, int] = {}
    by_resource: dict[str, int] = {}
    by_phase: dict[str, dict[str, int]] = {}
    for item in rows:
        st = str(item.status or "unknown")
        rc = str(item.resource_class or "unknown")
        ph = str(item.phase_id or "unknown")
        by_status[st] = by_status.get(st, 0) + 1
        by_resource[rc] = by_resource.get(rc, 0) + 1
        phase_bucket = by_phase.setdefault(ph, {})
        phase_bucket[st] = phase_bucket.get(st, 0) + 1

    recent = (
        db.query(ScanWorkItem)
        .filter(ScanWorkItem.scan_job_id == scan_id)
        .order_by(ScanWorkItem.updated_at.desc(), ScanWorkItem.id.desc())
        .limit(100)
        .all()
    )
    return {
        "scan_id": scan_id,
        "engine": (job.state_data or {}).get("parallel_engine"),
        "total": len(rows),
        "by_status": by_status,
        "by_resource": by_resource,
        "by_phase": by_phase,
        "recent": [
            {
                "id": item.id,
                "phase_id": item.phase_id,
                "target": item.target,
                "tool_name": item.tool_name,
                "profile": item.profile,
                "resource_class": item.resource_class,
                "priority": item.priority,
                "status": item.status,
                "attempts": item.attempts,
                "last_error": item.last_error,
                "updated_at": item.updated_at,
            }
            for item in recent
        ],
    }


@router.get("/scans/{scan_id}/phase-monitor")
def scan_phase_monitor(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Cross-references state_data, executed_tool_runs and findings into a per-phase status view.
    Returns 22 detailed phases + 8 capability nodes + tool inventory + detected issues."""
    from app.services.phase_monitor import build_phase_monitor

    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    job = query.first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    return build_phase_monitor(db, job)


@router.get("/scans/{scan_id}/report", response_model=ReportResponse)
def scan_report(
    scan_id: int,
    prioritized_limit: int = Query(default=10, ge=1, le=100),
    prioritized_offset: int = Query(default=0, ge=0, le=10000),
    include_targets: str | None = Query(default=None),
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

    selected_target_tokens: list[str] = []
    for raw_token in re.split(r"[,;\n]+", str(include_targets or "")):
        token = _primary_target_token(raw_token)
        if token and token not in selected_target_tokens:
            selected_target_tokens.append(token)

    def _resolve_finding_target_tokens(finding: Finding) -> set[str]:
        tokens: set[str] = set()
        if finding.domain:
            tokens.update(_target_tokens(str(finding.domain)))

        details = finding.details if isinstance(finding.details, dict) else {}
        for key in ["url", "target", "domain", "subdomain", "asset", "host", "full_url", "endpoint"]:
            value = details.get(key)
            if isinstance(value, str) and value.strip():
                tokens.update(_target_tokens(value))

        loc = _extract_finding_location(finding)
        for key in ["target", "subdomain", "url", "path"]:
            value = loc.get(key)
            if isinstance(value, str) and value.strip():
                tokens.update(_target_tokens(value))

        return {token for token in tokens if token}

    def _matches_selected_targets(target_tokens: set[str]) -> bool:
        if not selected_target_tokens:
            return True
        for selected in selected_target_tokens:
            for candidate in target_tokens:
                if candidate == selected or candidate.endswith(f".{selected}"):
                    return True
        return False

    findings = db.query(Finding).filter(Finding.scan_job_id == scan_id).all()
    if selected_target_tokens:
        findings = [f for f in findings if _matches_selected_targets(_resolve_finding_target_tokens(f))]

    scan_logs = db.query(ScanLog).filter(ScanLog.scan_job_id == scan_id).order_by(ScanLog.created_at.asc()).all()
    trace_events = (
        db.query(AgentTraceEvent)
        .filter(AgentTraceEvent.scan_id == scan_id)
        .order_by(AgentTraceEvent.id.asc())
        .all()
    )
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
        if selected_target_tokens:
            previous_findings = [f for f in previous_findings if _matches_selected_targets(_resolve_finding_target_tokens(f))]

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
        sev = str(finding.severity or "low").lower()
        stored_ai_recommendation = any(
            isinstance(details.get(key), str) and str(details.get(key)).strip()
            for key in ["qwen_recomendacao_pt", "cloudcode_recomendacao_pt"]
        )
        ai_recommendations = {}
        if not stored_ai_recommendation:
            try:
                ai_recommendations = generate_portuguese_recommendations(
                    {
                        "title": normalized_title,
                        "severity": sev,
                        "cve": finding.cve,
                        "details": details,
                    }
                )
            except Exception:
                ai_recommendations = {}

        recommendation_source = {**details, **ai_recommendations}
        recommendation_payload = _extract_recommendation_payload(recommendation_source)
        technical = _extract_technical_details(details, job.target_query)
        category = _infer_category(normalized_title, details)
        framework_ctx = _framework_context(category, normalized_title, details)
        recommendation_ctx = _technical_recommendation(category, normalized_title, sev)
        cve_recommendation = _build_cve_recommendation(_sanitize_text(finding.cve or ""), technical, details, sev)

        # CVE description — pull from details, never show bare CVE ID without context
        cve_description = _sanitize_text(
            details.get("cve_description") or
            details.get("description") or
            details.get("desc") or
            details.get("cve_summary") or
            details.get("solution") or
            ""
        )[:1000]

        # Knowledge base explanations (executive + technical)
        try:
            from app.services.vuln_knowledge_base import get_vuln_explanation
            _tool_for_kb = str(finding.tool or details.get("tool") or "")
            _kb = get_vuln_explanation(normalized_title, _tool_for_kb, details)
            executive_explanation = _kb.get("executive", "")
            technical_explanation = _kb.get("technical", "")
        except Exception:
            executive_explanation = ""
            technical_explanation = ""
        
        age = compute_age_metrics(finding.created_at, details)
        fair = compute_fair_metrics(finding.severity, finding.confidence_score, details, age)
        reasons = build_priority_reason(normalized_title, finding.severity, fair, age)

        if sev in severity_count:
            severity_count[sev] += 1

        ale_value = float(fair.get("annualized_loss_exposure_usd") or 0.0)
        fair_ale_total_all += ale_value
        fair_score_samples.append(float(fair.get("fair_score") or 0.0))

        target_value = technical.get("full_url") or _sanitize_text(details.get("url") or details.get("target") or job.target_query)
        report_id = f"F-{finding.id}"
        signature = _finding_signature(normalized_title, sev, target_value)
        source_context = {
            **details,
            "tool": finding.tool or details.get("tool"),
        }
        adversary_technique_details = details.get("adversary_technique") if isinstance(details.get("adversary_technique"), dict) else {}
        detection_proof_pack_details = details.get("detection_proof_pack") if isinstance(details.get("detection_proof_pack"), dict) else {}
        vulnerability_rows.append(
            {
                "index": len(vulnerability_rows) + 1,
                "signature": signature,
                "id": report_id,
                "finding_id": finding.id,
                "scan_job_id": finding.scan_job_id,
                "cve": _sanitize_text(finding.cve or ""),
                "cve_description": cve_description,
                "executive_explanation": executive_explanation,
                "technical_explanation": technical_explanation,
                "target": target_value,
                "full_url": technical.get("full_url") or target_value,
                "endpoint": technical.get("endpoint") or "/",
                "http_method": technical.get("http_method") or "GET",
                "parameter": technical.get("parameter") or "-",
                "name": normalized_title,
                "problem": normalized_title,
                "service": _sanitize_text(technical.get("service") or "-"),
                "version": _sanitize_text(technical.get("version") or ""),
                "cvss": details.get("cvss_score") or details.get("cvss") or finding.risk_score or "-",
                "risk_score": finding.risk_score,
                "confidence_score": finding.confidence_score,
                "risk_text": _risk_text(sev, finding.confidence_score),
                "severity": sev,
                "category": category,
                "created_at": finding.created_at.isoformat() if finding.created_at else None,
                "latest_seen_at": finding.created_at.isoformat() if finding.created_at else None,
                "header_name": _sanitize_text(details.get("header_name") or ""),
                "header_issue": _sanitize_text(details.get("header_issue") or ""),
                "owasp": _sanitize_text(framework_ctx.get("owasp") or "-"),
                "cwe": _sanitize_text(framework_ctx.get("cwe") or "-"),
                "vuln_class": _sanitize_text(framework_ctx.get("class") or "-"),
                "nist_control": _sanitize_text(details.get("nist_control") or details.get("nist") or framework_ctx.get("nist") or "-"),
                "iso_control": _sanitize_text(details.get("iso_control") or details.get("iso27001") or framework_ctx.get("iso") or "-"),
                "cis_control": _sanitize_text(details.get("cis_control") or framework_ctx.get("cis") or "-"),
                "pci_control": _sanitize_text(details.get("pci_control") or details.get("pci") or framework_ctx.get("pci") or "-"),
                "recommendation": _normalize_recommendation({**recommendation_source, "severity": sev}),
                "recommendation_structured": recommendation_payload,
                "recommendation_llm": recommendation_payload,
                "recommendation_environment": {
                    "required_fix": _sanitize_multiline_text(str(recommendation_ctx.get("required_fix") or "")),
                    "controls": recommendation_ctx.get("controls") or [],
                    "validations": recommendation_ctx.get("validations") or [],
                },
                "recommendation_cve": cve_recommendation,
                "learning_match": details.get("learning_match") if isinstance(details.get("learning_match"), dict) else {},
                "reproduction_playbook": details.get("reproduction_playbook") if isinstance(details.get("reproduction_playbook"), dict) else {},
                "learned_steps_to_reproduce": _sanitize_multiline_text(details.get("learned_steps_to_reproduce") or details.get("repro_steps") or ""),
                "learned_impact": _sanitize_multiline_text(details.get("learned_impact") or details.get("impact") or ""),
                "learned_remediation": _sanitize_multiline_text(details.get("learned_remediation") or details.get("remediation") or ""),
                "proof_pack_required": bool(details.get("proof_pack_required")),
                "validation_status": _sanitize_text(details.get("validation_status") or ""),
                "technical_evidence_expected": _sanitize_multiline_text(details.get("technical_evidence_expected") or ""),
                "adversary_technique": adversary_technique_details,
                "adversary_technique_id": _sanitize_text(adversary_technique_details.get("id") or details.get("adversary_technique_id") or ""),
                "adversary_technique_name": _sanitize_text(adversary_technique_details.get("name") or details.get("adversary_technique_name") or ""),
                "control_objectives": details.get("control_objectives") if isinstance(details.get("control_objectives"), list) else [],
                "expected_telemetry": _flatten_expected_telemetry(details.get("expected_telemetry")),
                "detection_status": _sanitize_text(detection_proof_pack_details.get("detection_status") or details.get("detection_status") or "unknown"),
                "detection_proof_pack": detection_proof_pack_details,
                "recommendation_required": _sanitize_multiline_text(str(recommendation_ctx.get("required_fix") or "")),
                "recommendation_controls": recommendation_ctx.get("controls") or [],
                "recommendation_validation": recommendation_ctx.get("validations") or [],
                "exploit": technical.get("exploit") or "-",
                "error": _sanitize_multiline_text(technical.get("error") or "-") or "-",
                "evidence": _sanitize_multiline_text(technical.get("evidence") or "-") or "-",
                "payload": _sanitize_multiline_text(technical.get("payload") or "-") or "-",
                "attack_input": _sanitize_multiline_text(technical.get("attack_input") or "-") or "-",
                "poc_request": _sanitize_multiline_text(technical.get("poc_request") or "-") or "-",
                "response_http": _sanitize_multiline_text(technical.get("response_http") or "-") or "-",
                "response_application": _sanitize_multiline_text(technical.get("response_application") or "-") or "-",
                "technical_validation": _sanitize_multiline_text(technical.get("technical_validation") or "-") or "-",
                "expected_behavior": _sanitize_multiline_text(technical.get("expected_behavior") or "-") or "-",
                "observed_behavior": _sanitize_multiline_text(technical.get("observed_behavior") or "-") or "-",
                "root_cause": _sanitize_multiline_text(technical.get("root_cause") or "-") or "-",
                "step": technical.get("step") or "-",
                "node": technical.get("node") or "-",
                "asset": technical.get("asset") or "-",
                "port": technical.get("port") or "-",
                "tool": technical.get("tool") or "-",
                "command": technical.get("command") or "-",
                "osint_tools": details.get("tools") if isinstance(details.get("tools"), list) else [],
                "http_headers_raw": _sanitize_text(details.get("http_headers_raw") or ""),
                "technical_context": _sanitize_text(
                    f"step={technical.get('step') or '-'}; node={technical.get('node') or '-'}; tool={technical.get('tool') or '-'}; asset={technical.get('asset') or '-'}; porta={technical.get('port') or '-'}; servico={technical.get('service') or '-'}"
                ),
                "source_group": _source_group_from_details(source_context),
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

    open_rows = [row for row in vulnerability_rows if not row["is_false_positive"]]
    open_vulnerability_table = [row for row in open_rows if _is_vulnerability_row(row)]
    if not open_vulnerability_table and open_rows:
        open_vulnerability_table = list(open_rows)
    open_recon_table = [row for row in open_rows if str(row.get("source_group") or "") == "recon"]
    open_osint_table = [row for row in open_rows if str(row.get("source_group") or "") == "osint"]

    severity_count_vuln = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in open_vulnerability_table:
        sev = str(row.get("severity") or "low").lower()
        if sev in severity_count_vuln:
            severity_count_vuln[sev] += 1

    fair_total = _compute_fair_summary(findings, enriched_findings, fair_ale_total_open, fair_ale_total_all)

    frameworks = _compute_framework_scores(open_vulnerability_table)

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

    open_vulnerability_table.sort(
        key=lambda item: (
            -_severity_rank(str(item.get("severity") or "low")),
            -int(item.get("risk_score") or 0),
            str(item.get("name") or ""),
        )
    )

    waf_vendors: dict[str, int] = {}
    waf_assets: set[str] = set()
    waf_findings_count = 0

    security_header_missing: dict[str, int] = {}
    security_header_present: dict[str, int] = {}
    security_header_assets: set[str] = set()
    security_header_samples: list[dict[str, str]] = []
    security_header_sample_keys: set[str] = set()
    security_header_findings_count = 0
    header_pattern = re.compile(
        r"(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|x-xss-protection)",
        re.IGNORECASE,
    )

    for row in open_vulnerability_table:
        tool = str(row.get("tool") or "").strip().lower()
        title = str(row.get("name") or row.get("problem") or "")
        evidence = str(row.get("evidence") or "")
        blob = f"{title}\n{evidence}".lower()
        target = str(row.get("target") or "").strip()

        if tool == "wafw00f" or "waf" in blob:
            waf_findings_count += 1
            if target:
                waf_assets.add(target)
            vendor_match = re.search(r"behind\s+(.+?)\s+waf", f"{title} {evidence}", re.IGNORECASE)
            parsed_vendor = str(vendor_match.group(1) or "").strip() if vendor_match else ""
            vendor = _detect_waf_vendor(f"{parsed_vendor} {title} {evidence}") or parsed_vendor or "WAF nao identificado"
            waf_vendors[vendor] = int(waf_vendors.get(vendor, 0)) + 1

        if tool in {"shcheck", "curl-headers"} or any(tok in blob for tok in ["header", "hsts", "content-security-policy", "x-frame-options", "x-content-type-options"]):
            explicit_header = str(row.get("header_name") or "").strip().lower()
            explicit_issue = str(row.get("header_issue") or "").strip().lower()
            raw_http_headers = str(row.get("http_headers_raw") or "").strip()
            matched_headers = header_pattern.findall(f"{title}\n{evidence}")
            candidate_headers = [explicit_header] if explicit_header else [str(h or "").strip().lower() for h in matched_headers]
            if candidate_headers:
                security_header_findings_count += 1
                if target:
                    security_header_assets.add(target)
            if tool == "curl-headers" and raw_http_headers:
                sample_key = f"{target}|{raw_http_headers[:120]}"
                if sample_key not in security_header_sample_keys:
                    security_header_sample_keys.add(sample_key)
                    security_header_samples.append(
                        {
                            "target": target or "-",
                            "raw": raw_http_headers[:1200],
                        }
                    )
            for normalized_header in candidate_headers:
                if not normalized_header:
                    continue
                if explicit_issue == "present":
                    security_header_present[normalized_header] = int(security_header_present.get(normalized_header, 0)) + 1
                elif explicit_issue == "missing":
                    security_header_missing[normalized_header] = int(security_header_missing.get(normalized_header, 0)) + 1
                elif "ausente" in blob or "missing" in blob or "not set" in blob:
                    security_header_missing[normalized_header] = int(security_header_missing.get(normalized_header, 0)) + 1
                else:
                    security_header_present[normalized_header] = int(security_header_present.get(normalized_header, 0)) + 1

    category_scores = _build_category_scores(open_vulnerability_table)

    # Não usar logs genéricos como fallback de payload/evidência para evitar
    # contaminação com saída de outras ferramentas no relatório final.

    # ── Consolidação: agrupa vulns com mesmo título+severidade ─────────────────
    # open_vulnerability_table mantém linhas individuais (usado para métricas,
    # security-headers, lifecycle, etc.). A tabela consolidada é a que vai para
    # o relatório exibido (PDF/web): cada vulnerabilidade aparece uma vez, com
    # a lista de alvos afetados em affected_assets / target_summary.
    consolidated_vulnerability_table = _consolidate_vulnerability_table(open_vulnerability_table)
    bas_detection_validation = _build_bas_detection_validation_report(
        job=job,
        trace_events=trace_events,
        vulnerability_rows=open_vulnerability_table,
    )

    detailed_recommendations = [
        {
            "id": row["id"],
            "cve": row.get("cve") or "",
            "name": row["name"],
            "problem": row.get("problem") or row["name"],
            "category": row.get("category") or "Application Security",
            "severity": row["severity"],
            "target": row.get("target_summary") or row.get("target") or "-",
            "affected_assets": row.get("affected_assets") or [],
            "affected_count": int(row.get("affected_count") or 1),
            "technical": {
                "exploit": row.get("exploit") or "-",
                "error": row.get("error") or "-",
                "evidence": row.get("evidence") or "-",
                "payload": row.get("payload") or "-",
                "step": row.get("step") or "-",
                "node": row.get("node") or "-",
                "port": row.get("port") or "-",
            },
            "recommendation": row["recommendation"],
            "recommendation_structured": row.get("recommendation_structured") or {},
        }
        for row in consolidated_vulnerability_table[:120]
    ]
    top_recommendations = _build_top_recommendations(consolidated_vulnerability_table, detailed_recommendations)

    lifecycle = {
        "open": len([r for r in open_vulnerability_table if r.get("status") == "open"]),
        "new": len([r for r in open_vulnerability_table if r.get("status") == "new"]),
        "corrected": len(resolved_vulnerabilities),
    }
    triaged_vulnerability_count = len([row for row in vulnerability_rows if row.get("is_false_positive") and _is_vulnerability_row(row)])

    summary_data = {
        "total": len(open_vulnerability_table),
        "total_raw": len(findings),
        "critical": severity_count_vuln["critical"],
        "high": severity_count_vuln["high"],
        "medium": severity_count_vuln["medium"],
        "low": severity_count_vuln["low"],
        "info": severity_count_vuln["info"],
        "open": len(open_vulnerability_table),
        "triaged": triaged_vulnerability_count,
    }

    age_env_avg_days = round(
        sum(float((item.get("age") or {}).get("known_in_environment_days") or 0.0) for item in enriched_findings)
        / max(1, len(enriched_findings)),
        2,
    )
    age_market_avg_days = round(
        sum(float((item.get("age") or {}).get("known_in_market_days") or 0.0) for item in enriched_findings)
        / max(1, len(enriched_findings)),
        2,
    )
    report_scope_target = ", ".join(selected_target_tokens) if selected_target_tokens else str(job.target_query or "")
    strategic_points = _build_strategic_points(
        target=report_scope_target,
        summary=summary_data,
        fair_total=fair_total,
        lifecycle=lifecycle,
        category_scores=category_scores,
    )
    technical_points = _build_technical_points(open_vulnerability_table, detailed_recommendations)

    segment = _infer_target_segment(job.target_query)
    benchmark = _build_wef_benchmark(segment, fair_ale_total_open, severity_count_vuln)
    evolution_target = selected_target_tokens[0] if len(selected_target_tokens) == 1 else job.target_query
    target_evolution = _build_target_evolution(db, evolution_target, scan_id)
    rating_timeline = build_rating_timeline(target_evolution.get("timeline") or [])
    continuous_rating = compute_continuous_rating(
        severity_count=severity_count_vuln,
        fair_avg_score=float(fair_total.get("fair_avg_score") or 0.0),
        fair_ale_total_usd=float(fair_total.get("ale_total_open_usd") or 0.0),
        age_env_avg_days=age_env_avg_days,
        age_market_avg_days=age_market_avg_days,
        lifecycle=lifecycle,
        recurring_findings_count=len([r for r in (target_evolution.get("recurring_findings") or []) if str(r.get("trend") or "") == "persisting"]),
        segment=segment,
    )
    score = float(continuous_rating.get("score") or 0.0)
    grade = str(continuous_rating.get("grade") or "F")

    scan_mode = str((job.state_data or {}).get("scan_mode") or ("scheduled" if str(job.mode or "").lower() == "scheduled" else "unit")).strip().lower()
    groups = get_worker_groups("scheduled" if scan_mode == "scheduled" else "unit")
    vuln_tools = list((groups.get("analise_vulnerabilidade") or {}).get("tools") or [])
    report_focus_tools = ["nmap-vulscan", "nikto", "nuclei"]
    tool_execution_summary = _build_tool_execution_summary(job, scan_logs, vuln_tools)
    focused_tool_execution = {
        **tool_execution_summary,
        "tools": [
            row
            for row in tool_execution_summary.get("tools", [])
            if str(row.get("tool") or "") in report_focus_tools
        ],
    }
    vulnerability_evidence = _build_vulnerability_execution_evidence(db, scan_id, report_focus_tools)

    # Assets summary and findings grouped by subdomain
    raw_assets_list: list[str] = list(
        (job.state_data or {}).get("lista_ativos") or []
    )
    unique_assets_list: list[str] = sorted(
        {str(a).strip() for a in raw_assets_list if str(a).strip()}
    )
    if selected_target_tokens:
        filtered_assets = [
            asset for asset in unique_assets_list
            if _matches_selected_targets(set(_target_tokens(asset)))
        ]
        unique_assets_list = filtered_assets or list(selected_target_tokens)

    main_domain: str = selected_target_tokens[0] if len(selected_target_tokens) == 1 else str(job.target_query or "").strip()
    subdomains_list: list[str] = [a for a in unique_assets_list if a != main_domain]
    assets_summary = {
        "domain": main_domain,
        "subdomains": subdomains_list,
        "subdomain_count": len(subdomains_list),
        "total_assets": len(unique_assets_list),
    }

    findings_by_subdomain: dict[str, list[dict]] = {}
    for _row in open_vulnerability_table:
        _asset = str(_row.get("asset") or _row.get("target") or main_domain).strip()
        if _asset.startswith(("http://", "https://")):
            _parsed = urlparse(_asset)
            _asset = _parsed.netloc or _asset
        if not _asset:
            _asset = main_domain
        findings_by_subdomain.setdefault(_asset, []).append(_row)

    # Garante presença de todos os ativos descobertos, mesmo sem findings.
    for _asset in unique_assets_list:
        if _asset not in findings_by_subdomain:
            findings_by_subdomain[_asset] = []

    # Consolida status de execução por subdomínio para transparência no relatório.
    tool_runs = db.query(ExecutedToolRun).filter(ExecutedToolRun.scan_job_id == scan_id).all()
    runs_by_asset: dict[str, list[ExecutedToolRun]] = {}
    for run in tool_runs:
        key = str(run.target or "").strip().lower()
        if key:
            runs_by_asset.setdefault(key, []).append(run)

    subdomain_execution_summary: list[dict[str, Any]] = []
    for asset_name in unique_assets_list:
        key = str(asset_name or "").strip().lower()
        asset_runs = runs_by_asset.get(key, [])
        tool_status: dict[str, dict[str, int]] = {}
        for run in asset_runs:
            tool = str(run.tool_name or "unknown")
            status_key = str(run.status or "unknown")
            if tool not in tool_status:
                tool_status[tool] = {"success": 0, "failed": 0, "skipped": 0, "unknown": 0}
            tool_status[tool][status_key if status_key in tool_status[tool] else "unknown"] += 1

        subdomain_execution_summary.append(
            {
                "asset": asset_name,
                "is_main_domain": str(asset_name).strip().lower() == main_domain.lower(),
                "findings_count": len(findings_by_subdomain.get(asset_name, [])),
                "tool_runs_count": len(asset_runs),
                "tools": tool_status,
                "analyzed": len(asset_runs) > 0,
            }
        )

    return ReportResponse(
        scan_id=scan_id,
        status=job.status,
        findings=enriched_findings,
        state_data={
            **(job.state_data or {}),
            "report_v2": {
                # report_v2 pode não existir em scans antigos/incompletos.
                # Evita NameError e mantém resposta consistente.
                "trace_id": (job.state_data or {}).get("trace_id") or f"scan-{scan_id}",
                "domain": report_scope_target,
                "scan_type": "ASM_EXTERNAL",
                "risk_score": score,
                "grade": grade,
                "filters": {
                    "include_targets": selected_target_tokens,
                },
                "summary": summary_data,
                "fair": fair_total,
                "frameworks": frameworks,
                "category_scores": category_scores,
                "assets_summary": assets_summary,
                "mission_items": (job.state_data or {}).get("mission_items") or [],
                "item_05_subdominios_encontrados": {
                    "title": "5. ExecutiveAnalysis",
                    "target": main_domain,
                    "subdomains": subdomains_list,
                    "total_subdomains": len(subdomains_list),
                    "execution_summary": subdomain_execution_summary,
                },
                "item_05_executive_analysis": {
                    "title": "5. ExecutiveAnalysis",
                    "target": main_domain,
                    "executive_summary": ((job.state_data or {}).get("report_v2") or {}).get("executive_summary", ""),
                    "execution_summary": subdomain_execution_summary,
                },
                "findings_by_subdomain": findings_by_subdomain,
                "tool_execution_summary": focused_tool_execution,
                "vulnerability_analysis_evidence": vulnerability_evidence,
                "bas_detection_validation": bas_detection_validation,
                "bas_control_matrix": bas_detection_validation.get("control_matrix") or [],
                "vulnerability_table": consolidated_vulnerability_table,
                "recommendations": top_recommendations,
                "recommendations_detailed": detailed_recommendations,
                "llm_risk": (job.state_data or {}).get("llm_risk_report") or {},
                "agent_validation": (job.state_data or {}).get("agent_validation") or {},
                "confidence_state": (job.state_data or {}).get("confidence_state") or {},
                "evidence_contract": (job.state_data or {}).get("evidence_contract") or {},
                "strategic_points": strategic_points,
                "technical_points": technical_points,
                "segment_benchmark": benchmark,
                "target_evolution": target_evolution,
                "rating_timeline": rating_timeline,
                "continuous_rating": continuous_rating,
                "waf_summary": {
                    "findings_count": waf_findings_count,
                    "assets_count": len(waf_assets),
                    "assets": sorted(list(waf_assets)),
                    "vendors": [
                        {"name": name, "count": count}
                        for name, count in sorted(waf_vendors.items(), key=lambda item: item[1], reverse=True)
                    ][:10],
                },
                "security_headers_summary": {
                    "findings_count": security_header_findings_count,
                    "assets_count": len(security_header_assets),
                    "assets": sorted(list(security_header_assets)),
                    "present_headers": [
                        {"header": name, "count": count}
                        for name, count in sorted(security_header_present.items(), key=lambda item: item[1], reverse=True)
                    ][:20],
                    "missing_headers": [
                        {"header": name, "count": count}
                        for name, count in sorted(security_header_missing.items(), key=lambda item: item[1], reverse=True)
                    ][:20],
                    "samples": security_header_samples,
                    "owasp_top10_alignment": [
                        {
                            "owasp": "A05 Security Misconfiguration",
                            "coverage": "CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy e Permissions-Policy reduzem superfície de configuração insegura.",
                        },
                        {
                            "owasp": "A03 Injection",
                            "coverage": "CSP restringe execução de scripts e reduz impacto de XSS/injeções no browser.",
                        },
                    ],
                },
                "coverage_summary": {
                    "vulnerability_findings": len(open_vulnerability_table),
                    "recon_findings": len(open_recon_table),
                    "osint_findings": len(open_osint_table),
                },
                "recon_findings": open_recon_table,
                "osint_findings": open_osint_table,
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
            "version",
            "severity",
            "category",
            "cvss",
            "status",
            "exploit",
            "error",
            "evidence",
            "payload",
            "adversary_technique_id",
            "adversary_technique_name",
            "detection_status",
            "expected_telemetry_sources",
            "step",
            "node",
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
                row.get("version") or "",
                row.get("severity") or "",
                row.get("category") or "",
                row.get("cvss") or "",
                row.get("status") or "",
                row.get("exploit") or "",
                row.get("error") or "",
                row.get("evidence") or "",
                row.get("payload") or "",
                row.get("adversary_technique_id") or "",
                row.get("adversary_technique_name") or "",
                row.get("detection_status") or "",
                "; ".join(
                    str(item.get("source") or "")
                    for item in list(row.get("expected_telemetry") or [])
                    if isinstance(item, dict) and item.get("source")
                ),
                row.get("step") or "",
                row.get("node") or "",
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


@router.get("/rating/methodology")
def get_rating_methodology(current_user: User = Depends(get_current_user)):
    """Retorna o changelog completo da metodologia de rating para uso executivo e auditoria.

    Inclui:
    - Versão atual da metodologia
    - Pesos por segmento de mercado (BitSight/SecurityScorecard/IBM 2023 calibrated)
    - Histórico de versões com justificativas e referências de mercado
    """
    return get_methodology_changelog()


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
    access_group_id: int | None = Query(default=None),
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
    
    # Garante conversão para int se necessário
    if access_group_id is not None:
        try:
            group_id_int = int(access_group_id) if isinstance(access_group_id, str) else access_group_id
            group_schedules = (
                db.query(ScheduledScan)
                .filter(ScheduledScan.access_group_id == group_id_int)
                .all()
            )
            group_targets: set[str] = set()
            for schedule in group_schedules:
                raw = str(schedule.targets_text or "").strip()
                if not raw:
                    continue
                group_targets.add(raw)
                for part in raw.split(";"):
                    token = part.strip()
                    if token:
                        group_targets.add(token)

            if group_targets:
                jobs_query = jobs_query.filter(
                    (ScanJob.access_group_id == group_id_int) | (ScanJob.target_query.in_(list(group_targets)))
                )
                findings_query = findings_query.filter(
                    (ScanJob.access_group_id == group_id_int) | (ScanJob.target_query.in_(list(group_targets)))
                )
            else:
                jobs_query = jobs_query.filter(ScanJob.access_group_id == group_id_int)
                findings_query = findings_query.filter(ScanJob.access_group_id == group_id_int)
        except (ValueError, TypeError):
            access_group_id = None

    jobs = jobs_query.order_by(ScanJob.created_at.desc()).all()
    findings = findings_query.all()

    if normalized_target:
        normalized_target_lc = normalized_target.lower()
        exact_jobs = [
            j for j in jobs
            if normalized_target_lc in _target_tokens(j.target_query)
        ]
        filtered_jobs = exact_jobs if exact_jobs else [
            j for j in jobs
            if normalized_target_lc in str(j.target_query or "").lower()
        ]
        allowed_ids = {j.id for j in filtered_jobs}
        jobs = filtered_jobs
        findings = [f for f in findings if f.scan_job_id in allowed_ids]

    latest_scan = jobs[0] if jobs else None
    latest_scan_logs: list[ScanLog] = []
    vuln_tool_execution = {"requested_tools": [], "tools": [], "summary": {"requested_count": 0, "attempted_count": 0, "executed_count": 0}}
    if latest_scan:
        latest_scan_logs = (
            db.query(ScanLog)
            .filter(ScanLog.scan_job_id == latest_scan.id)
            .order_by(ScanLog.created_at.asc())
            .all()
        )
        latest_mode = str((latest_scan.state_data or {}).get("scan_mode") or ("scheduled" if str(latest_scan.mode or "").lower() == "scheduled" else "unit")).strip().lower()
        latest_groups = get_worker_groups("scheduled" if latest_mode == "scheduled" else "unit")
        latest_vuln_tools = list((latest_groups.get("analise_vulnerabilidade") or {}).get("tools") or [])
        focus_tools = ["nmap-vulscan", "nikto", "nuclei"]
        base_summary = _build_tool_execution_summary(latest_scan, latest_scan_logs, latest_vuln_tools)
        vuln_tool_execution = {
            **base_summary,
            "tools": [
                row for row in base_summary.get("tools", []) if str(row.get("tool") or "") in focus_tools
            ],
            "scan_id": latest_scan.id,
            "scan_target": latest_scan.target_query,
            "scan_status": latest_scan.status,
        }

    findings_by_scan: dict[int, list[Finding]] = {}
    for f in findings:
        findings_by_scan.setdefault(f.scan_job_id, []).append(f)

    target_scan_counts: dict[str, int] = {}
    for job in jobs:
        target_key = _primary_target_token(job.target_query)
        if not target_key:
            continue
        target_scan_counts[target_key] = int(target_scan_counts.get(target_key, 0)) + 1

    def _new_target_metric() -> dict[str, Any]:
        return {
            "findings_total": 0,
            "findings_triaged": 0,
            "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "severity_vuln": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "fair_total": 0.0,
            "fair_count": 0,
            "ale_total": 0.0,
            "recon": 0,
            "osint": 0,
            "vulnerability": 0,
            "waf": 0,
            "security_headers": 0,
            "age_env": [],
            "age_market": [],
            "age_exploit": [],
        }

    target_metrics: dict[str, dict[str, Any]] = {}

    def _metric_for_target(target_query_value: str | None) -> dict[str, Any]:
        key = _primary_target_token(target_query_value)
        if not key:
            key = "_unknown"
        metric = target_metrics.get(key)
        if metric is None:
            metric = _new_target_metric()
            target_metrics[key] = metric
        return metric

    total = len(findings)
    mitigated = len([f for f in findings if f.is_false_positive])
    open_issues = total - mitigated

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    sev_count_vuln = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    waf_vendors: dict[str, int] = {}
    waf_assets: set[str] = set()
    security_header_missing: dict[str, int] = {}
    security_header_present: dict[str, int] = {}
    security_header_assets: set[str] = set()
    waf_findings_count = 0
    security_header_findings_count = 0
    header_pattern = re.compile(
        r"(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|x-xss-protection)",
        re.IGNORECASE,
    )
    fair_total = 0.0
    ale_total = 0.0
    recon_findings_count = 0
    osint_findings_count = 0
    vulnerability_findings_count = 0
    age_env_samples: list[int] = []
    age_market_samples: list[int] = []
    age_exploit_samples: list[int] = []
    prioritized_actions: list[dict] = []
    vuln_counter: dict[tuple[str, str], int] = {}
    vuln_targets: dict[tuple[str, str], set[str]] = {}
    technologies_counter: dict[str, int] = {}
    for f in findings:
        sev = str(f.severity or "low").lower()
        loc = _extract_finding_location(f)
        finding_target = str(loc.get("subdomain") or loc.get("target") or "").strip()
        finding_url = str(loc.get("url") or "").strip()
        target_metric = _metric_for_target(f.scan_job.target_query if f.scan_job else "")
        target_metric["findings_total"] = int(target_metric.get("findings_total", 0)) + 1
        if f.is_false_positive:
            target_metric["findings_triaged"] = int(target_metric.get("findings_triaged", 0)) + 1
        if sev in sev_count:
            sev_count[sev] += 1
            target_metric["severity"][sev] = int(target_metric["severity"].get(sev, 0)) + 1

        details = f.details or {}
        nested_details = details.get("details") if isinstance(details.get("details"), dict) else {}
        source_group = _source_group_from_details(details)
        if source_group == "recon":
            recon_findings_count += 1
            target_metric["recon"] = int(target_metric.get("recon", 0)) + 1
        elif source_group == "osint":
            osint_findings_count += 1
            target_metric["osint"] = int(target_metric.get("osint", 0)) + 1
        elif source_group == "vuln" or sev in {"critical", "high", "medium"}:
            vulnerability_findings_count += 1
            target_metric["vulnerability"] = int(target_metric.get("vulnerability", 0)) + 1
            if sev in sev_count_vuln:
                sev_count_vuln[sev] += 1
                target_metric["severity_vuln"][sev] = int(target_metric["severity_vuln"].get(sev, 0)) + 1

        normalized_title = _normalize_finding_title(f.title)
        key = (normalized_title or "Finding", sev)
        vuln_counter[key] = vuln_counter.get(key, 0) + 1
        if finding_target:
            vuln_targets.setdefault(key, set()).add(finding_target)

        tool = str(details.get("tool") or nested_details.get("tool") or "").strip().lower()
        evidence_text = str(details.get("evidence") or nested_details.get("evidence") or "")
        title_blob = f"{f.title or ''}\n{evidence_text}".lower()
        if tool == "wafw00f" or "waf" in title_blob:
            waf_findings_count += 1
            target_metric["waf"] = int(target_metric.get("waf", 0)) + 1
            target_query = str(f.scan_job.target_query or "").strip() if f.scan_job else ""
            if target_query:
                waf_assets.add(target_query)
            vendor_match = re.search(r"behind\s+(.+?)\s+waf", f"{f.title or ''} {evidence_text}", re.IGNORECASE)
            parsed_vendor = str(vendor_match.group(1) or "").strip() if vendor_match else ""
            vendor = _detect_waf_vendor(f"{parsed_vendor} {f.title or ''} {evidence_text}") or parsed_vendor or "WAF nao identificado"
            waf_vendors[vendor] = int(waf_vendors.get(vendor, 0)) + 1

        if tool in {"shcheck", "curl-headers"} or any(tok in title_blob for tok in ["header", "hsts", "content-security-policy", "x-frame-options", "x-content-type-options"]):
            header_name = str(details.get("header_name") or nested_details.get("header_name") or "").strip().lower()
            header_issue = str(details.get("header_issue") or nested_details.get("header_issue") or "").strip().lower()
            matched_headers = [header_name] if header_name else [str(h or "").strip().lower() for h in header_pattern.findall(f"{f.title or ''}\n{evidence_text}")]
            if matched_headers:
                security_header_findings_count += 1
                target_metric["security_headers"] = int(target_metric.get("security_headers", 0)) + 1
                target_query = str(f.scan_job.target_query or "").strip() if f.scan_job else ""
                if target_query:
                    security_header_assets.add(target_query)
            for normalized_header in matched_headers:
                if not normalized_header:
                    continue
                if header_issue == "present":
                    security_header_present[normalized_header] = int(security_header_present.get(normalized_header, 0)) + 1
                elif header_issue == "missing":
                    security_header_missing[normalized_header] = int(security_header_missing.get(normalized_header, 0)) + 1
                elif "ausente" in title_blob or "missing" in title_blob or "not set" in title_blob:
                    security_header_missing[normalized_header] = int(security_header_missing.get(normalized_header, 0)) + 1
                else:
                    security_header_present[normalized_header] = int(security_header_present.get(normalized_header, 0)) + 1

        age = compute_age_metrics(f.created_at, details)
        fair = compute_fair_metrics(f.severity, f.confidence_score, details, age)
        fair_total += float(fair.get("fair_score") or 0.0)
        ale_total += float(fair.get("annualized_loss_exposure_usd") or 0.0)
        target_metric["fair_total"] = float(target_metric.get("fair_total") or 0.0) + float(fair.get("fair_score") or 0.0)
        target_metric["fair_count"] = int(target_metric.get("fair_count") or 0) + 1
        target_metric["ale_total"] = float(target_metric.get("ale_total") or 0.0) + float(fair.get("annualized_loss_exposure_usd") or 0.0)

        if age.get("known_in_environment_days") is not None:
            age_env_samples.append(int(age["known_in_environment_days"]))
            target_metric["age_env"].append(int(age["known_in_environment_days"]))
        if age.get("known_in_market_days") is not None:
            age_market_samples.append(int(age["known_in_market_days"]))
            target_metric["age_market"].append(int(age["known_in_market_days"]))
        if age.get("exploit_published_days") is not None:
            age_exploit_samples.append(int(age["exploit_published_days"]))
            target_metric["age_exploit"].append(int(age["exploit_published_days"]))

        if not f.is_false_positive:
            reasons = build_priority_reason(normalized_title, f.severity, fair, age)
            prioritized_actions.append(
                {
                    "finding_id": f.id,
                    "title": normalized_title,
                    "severity": f.severity,
                    "target": finding_target or (f.scan_job.target_query if f.scan_job else None),
                    "subdomain": finding_target or None,
                    "url": finding_url or None,
                    "path": loc.get("path"),
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

    top_vulns = []
    for (title, severity), count in sorted(vuln_counter.items(), key=lambda item: item[1], reverse=True)[:7]:
        affected_targets = sorted(vuln_targets.get((title, severity), set()))
        top_vulns.append(
            {
                "title": title,
                "severity": severity,
                "count": count,
                "target": affected_targets[0] if affected_targets else None,
                "subdomain": affected_targets[0] if affected_targets else None,
                "affected_targets": affected_targets[:20],
                "target_summary": ", ".join(affected_targets[:3]) + (f" +{len(affected_targets) - 3}" if len(affected_targets) > 3 else ""),
            }
        )

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
    agg_mode = "target" if normalized_target else ("group_avg" if access_group_id is not None else "global")

    effective_scans = len(jobs)
    effective_total = total
    effective_open_issues = open_issues
    effective_mitigated = mitigated
    effective_sev_count = dict(sev_count)
    effective_sev_count_vuln = dict(sev_count_vuln)
    effective_avg_fair = avg_fair
    effective_ale_total = float(ale_total)
    effective_age_env = float(_avg(age_env_samples))
    effective_age_market = float(_avg(age_market_samples))
    effective_age_exploit = float(_avg(age_exploit_samples))
    effective_waf_findings = waf_findings_count
    effective_security_header_findings = security_header_findings_count
    effective_recon_findings = recon_findings_count
    effective_osint_findings = osint_findings_count
    effective_vulnerability_findings = vulnerability_findings_count

    scope_targets = sorted(set(target_scan_counts.keys()) | set(target_metrics.keys()))
    if agg_mode == "group_avg" and scope_targets:
        n_scope = len(scope_targets)

        def _metric_value(key: str) -> dict[str, Any]:
            return target_metrics.get(key) or _new_target_metric()

        def _avg_scope(values: list[float]) -> float:
            return round(sum(values) / max(1, len(values)), 2) if values else 0.0

        effective_scans = round(sum(float(target_scan_counts.get(k, 0)) for k in scope_targets) / n_scope, 2)
        effective_total = round(sum(float(_metric_value(k).get("findings_total") or 0) for k in scope_targets) / n_scope, 2)
        effective_mitigated = round(sum(float(_metric_value(k).get("findings_triaged") or 0) for k in scope_targets) / n_scope, 2)
        effective_open_issues = round(effective_total - effective_mitigated, 2)

        effective_sev_count = {
            "critical": int(round(sum(float((_metric_value(k).get("severity") or {}).get("critical", 0)) for k in scope_targets) / n_scope)),
            "high": int(round(sum(float((_metric_value(k).get("severity") or {}).get("high", 0)) for k in scope_targets) / n_scope)),
            "medium": int(round(sum(float((_metric_value(k).get("severity") or {}).get("medium", 0)) for k in scope_targets) / n_scope)),
            "low": int(round(sum(float((_metric_value(k).get("severity") or {}).get("low", 0)) for k in scope_targets) / n_scope)),
        }
        effective_sev_count_vuln = {
            "critical": int(round(sum(float((_metric_value(k).get("severity_vuln") or {}).get("critical", 0)) for k in scope_targets) / n_scope)),
            "high": int(round(sum(float((_metric_value(k).get("severity_vuln") or {}).get("high", 0)) for k in scope_targets) / n_scope)),
            "medium": int(round(sum(float((_metric_value(k).get("severity_vuln") or {}).get("medium", 0)) for k in scope_targets) / n_scope)),
            "low": int(round(sum(float((_metric_value(k).get("severity_vuln") or {}).get("low", 0)) for k in scope_targets) / n_scope)),
        }

        fair_by_target: list[float] = []
        ale_by_target: list[float] = []
        age_env_by_target: list[float] = []
        age_market_by_target: list[float] = []
        age_exploit_by_target: list[float] = []
        waf_by_target: list[float] = []
        sec_headers_by_target: list[float] = []
        recon_by_target: list[float] = []
        osint_by_target: list[float] = []
        vuln_by_target: list[float] = []

        for key in scope_targets:
            metric = _metric_value(key)
            fair_count = int(metric.get("fair_count") or 0)
            fair_by_target.append((float(metric.get("fair_total") or 0.0) / fair_count) if fair_count > 0 else 0.0)
            ale_by_target.append(float(metric.get("ale_total") or 0.0))
            age_env_by_target.append(_avg(metric.get("age_env") or []))
            age_market_by_target.append(_avg(metric.get("age_market") or []))
            age_exploit_by_target.append(_avg(metric.get("age_exploit") or []))
            waf_by_target.append(float(metric.get("waf") or 0.0))
            sec_headers_by_target.append(float(metric.get("security_headers") or 0.0))
            recon_by_target.append(float(metric.get("recon") or 0.0))
            osint_by_target.append(float(metric.get("osint") or 0.0))
            vuln_by_target.append(float(metric.get("vulnerability") or 0.0))

        effective_avg_fair = _avg_scope(fair_by_target)
        effective_ale_total = _avg_scope(ale_by_target)
        effective_age_env = _avg_scope(age_env_by_target)
        effective_age_market = _avg_scope(age_market_by_target)
        effective_age_exploit = _avg_scope(age_exploit_by_target)
        effective_waf_findings = _avg_scope(waf_by_target)
        effective_security_header_findings = _avg_scope(sec_headers_by_target)
        effective_recon_findings = _avg_scope(recon_by_target)
        effective_osint_findings = _avg_scope(osint_by_target)
        effective_vulnerability_findings = _avg_scope(vuln_by_target)

    latest_scan_by_target: dict[str, ScanJob] = {}
    selected_target_lc = normalized_target.lower()
    for job in jobs:
        tokens = _target_tokens(job.target_query)
        if selected_target_lc:
            key = selected_target_lc if selected_target_lc in tokens else ""
        else:
            key = tokens[0] if tokens else str(job.target_query or "").strip().lower()
        if not key or key in latest_scan_by_target:
            continue
        latest_scan_by_target[key] = job

    selected_latest_scans = list(latest_scan_by_target.values()) or ([latest_scan] if latest_scan else [])
    ratings_payload: list[dict[str, Any]] = []
    fair_payload: list[dict[str, Any]] = []
    summary_payload: list[str] = []
    for scan in selected_latest_scans:
        rating_data, fair_data, summary_data = _extract_scan_easm_payload(scan)
        if rating_data:
            ratings_payload.append(rating_data)
        if fair_data:
            fair_payload.append(fair_data)
        if summary_data:
            summary_payload.append(summary_data)

    if ratings_payload:
        avg_rating_score = round(sum(float(item.get("score") or 0.0) for item in ratings_payload) / len(ratings_payload), 2)
        fallback_easm_rating = {
            "score": avg_rating_score,
            "grade": _score_to_grade(avg_rating_score),
        }
    else:
        fallback_easm_rating = {}
    fallback_fair_decomposition = _aggregate_fair_decomposition(fair_payload)
    fallback_executive_summary = "\n\n".join(summary_payload[:2]) if summary_payload else ""

    recurring_findings_count = len([count for count in vuln_counter.values() if int(count) > 1])
    lifecycle_global = {
        "open": int(effective_open_issues),
        "new": int(effective_sev_count_vuln.get("critical", 0) + effective_sev_count_vuln.get("high", 0)),
        "corrected": int(effective_mitigated),
    }
    continuous_rating = compute_continuous_rating(
        severity_count=effective_sev_count_vuln,
        fair_avg_score=effective_avg_fair,
        fair_ale_total_usd=float(effective_ale_total),
        age_env_avg_days=float(effective_age_env),
        age_market_avg_days=float(effective_age_market),
        lifecycle=lifecycle_global,
        recurring_findings_count=recurring_findings_count,
        segment=None,  # dashboard não tem alvo único — usa peso padrão
    )

    if float(effective_scans or 0) <= 0:
        continuous_rating = {
            "score": 0.0,
            "grade": "F",
            "factors": [],
        }

    scan_timeline_seed: list[dict] = []
    for s in sorted(jobs, key=lambda item: item.created_at or datetime.min):
        frows = [f for f in findings_by_scan.get(s.id, []) if not f.is_false_positive]
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in frows:
            k = str(f.severity or "low").lower()
            if k in sev:
                sev[k] += 1
        scan_timeline_seed.append(
            {
                "scan_id": s.id,
                "created_at": s.created_at,
                "open_findings": len(frows),
                "severity": sev,
            }
        )
    rating_timeline = build_rating_timeline(scan_timeline_seed)

    paged_prioritized = prioritized_actions[prioritized_offset:prioritized_offset + prioritized_limit]

    # Maturidade por framework derivada das evidências reais do scan (severidade,
    # cabeçalhos, exposição, vulnerabilidades, WAF e remediação) — uma fórmula
    # específica por framework em vez de um score sintético único.
    framework_scores = compute_framework_scores(
        severity_count=effective_sev_count,
        security_header_findings=float(effective_security_header_findings or 0),
        exposure_findings=float(effective_recon_findings or 0) + float(effective_osint_findings or 0),
        vulnerability_findings=float(effective_vulnerability_findings or 0),
        waf_findings=float(effective_waf_findings or 0),
        findings_total=float(effective_total or 0),
        findings_triaged=float(effective_mitigated or 0),
    )
    scan_ids = [int(j.id) for j in jobs if j.id is not None]

    trace_rows: list[AgentTraceEvent] = []
    executed_runs: list[ExecutedToolRun] = []
    if scan_ids:
        trace_rows = (
            db.query(AgentTraceEvent)
            .filter(AgentTraceEvent.scan_id.in_(scan_ids))
            .order_by(AgentTraceEvent.created_at.desc())
            .limit(2000)
            .all()
        )
        executed_runs = (
            db.query(ExecutedToolRun)
            .filter(ExecutedToolRun.scan_job_id.in_(scan_ids))
            .order_by(ExecutedToolRun.created_at.desc())
            .limit(2000)
            .all()
        )

    worker_rows = db.query(WorkerHeartbeat).order_by(WorkerHeartbeat.last_seen_at.desc()).limit(100).all()
    if current_user.is_admin:
        learning_rows = db.query(VulnerabilityLearning).order_by(VulnerabilityLearning.created_at.desc()).limit(500).all()
    else:
        learning_rows = (
            db.query(VulnerabilityLearning)
            .filter(VulnerabilityLearning.owner_id == current_user.id)
            .order_by(VulnerabilityLearning.created_at.desc())
            .limit(500)
            .all()
        )

    def _as_dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _as_list(value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        if value in (None, ""):
            return []
        return [value]

    def _pct(part: float, whole: float) -> float:
        return round((float(part) / max(float(whole), 1.0)) * 100.0, 1)

    def _detection_status(payload: dict[str, Any]) -> str:
        proof = _as_dict(payload.get("detection_proof_pack"))
        raw = (
            payload.get("detection_status")
            or proof.get("detection_status")
            or proof.get("status")
            or payload.get("control_status")
            or ""
        )
        value = str(raw or "").strip().lower().replace("-", "_").replace(" ", "_")
        if value in {"detected", "alerted", "blocked", "prevented", "logged", "success"}:
            return "detected"
        if value in {"partial", "partially_detected"}:
            return "partial"
        if value in {"not_detected", "undetected", "missed", "gap", "missing", "failed"}:
            return "gap"
        return "unknown"

    def _technique_label(payload: dict[str, Any]) -> str:
        technique = payload.get("adversary_technique") or payload.get("technique") or payload.get("mitre_attack")
        if isinstance(technique, dict):
            return str(technique.get("id") or technique.get("technique_id") or technique.get("name") or "").strip()
        return str(technique or payload.get("technique_id") or payload.get("attack_technique") or "").strip()

    def _telemetry_sources(payload: dict[str, Any]) -> list[str]:
        sources: list[str] = []
        for item in _as_list(payload.get("expected_telemetry")):
            if isinstance(item, dict):
                source = str(item.get("source") or item.get("log_source") or item.get("data_source") or "").strip()
            else:
                source = str(item or "").strip()
            if source:
                sources.append(source)
        proof = _as_dict(payload.get("detection_proof_pack"))
        for item in _as_list(proof.get("telemetry_sources") or proof.get("sources")):
            source = str(item.get("source") if isinstance(item, dict) else item or "").strip()
            if source:
                sources.append(source)
        return sorted(set(sources))

    bas_payloads: list[dict[str, Any]] = []
    technique_set: set[str] = set()
    detection_counts = {"detected": 0, "partial": 0, "gap": 0, "unknown": 0}
    telemetry_by_source: dict[str, dict[str, Any]] = {}

    for event in trace_rows:
        payload = _as_dict(event.payload)
        if not payload:
            continue
        has_bas_context = bool(
            _technique_label(payload)
            or payload.get("expected_telemetry")
            or payload.get("detection_proof_pack")
            or payload.get("control_objectives")
            or str(payload.get("strategy_source") or payload.get("source") or "").lower() in {"rag", "learning", "accepted_learning"}
        )
        if not has_bas_context:
            continue
        bas_payloads.append(payload)
        technique = _technique_label(payload)
        if technique:
            technique_set.add(technique)
        status = _detection_status(payload)
        detection_counts[status] = int(detection_counts.get(status, 0)) + 1
        for source in _telemetry_sources(payload):
            row = telemetry_by_source.setdefault(source, {"source": source, "total": 0, "detected": 0, "partial": 0, "gap": 0, "unknown": 0})
            row["total"] += 1
            row[status] = int(row.get(status, 0)) + 1

    for f in findings:
        details = _as_dict(f.details)
        nested = _as_dict(details.get("details"))
        payload = {**nested, **details}
        sev = str(f.severity or "").lower()
        src_group = _source_group_from_details(details)
        technique = _technique_label(payload)
        is_offensive = src_group == "vuln" or sev in {"critical", "high", "medium"}
        if not is_offensive and not technique and not payload.get("expected_telemetry") and not payload.get("detection_proof_pack"):
            continue
        target_query = str(f.scan_job.target_query or "").strip() if f.scan_job else ""
        target_has_waf = bool(target_query) and target_query in waf_assets
        # Fecha o detection_proof_pack que o scan emite apenas como template
        # ("unknown") — deriva o status real a partir da evidência coletada.
        detection = classify_detection_outcome(
            details,
            title=f.title or "",
            severity=sev,
            source_group=src_group,
            target_has_waf=target_has_waf,
            expected_telemetry=payload.get("expected_telemetry") or [],
        )
        status = detection["detection_status"]
        enriched_payload = {
            **payload,
            "detection_status": status,
            "detection_proof_pack": {**_as_dict(payload.get("detection_proof_pack")), **detection},
        }
        bas_payloads.append(enriched_payload)
        if technique:
            technique_set.add(technique)
        detection_counts[status] = int(detection_counts.get(status, 0)) + 1
        observed_sources = detection.get("telemetry_observed") or _telemetry_sources(enriched_payload)
        if not observed_sources:
            # O offensive operator (caminho de PRODUÇÃO) não emite expected_telemetry
            # — só o caminho legado do grafo emite. Sem isso a tabela "Eficácia por
            # fonte de telemetria" ficava VAZIA. Rotula a fonte pela FASE real do
            # achado (phase_name = onde o controle deveria enxergar); fallback p/ o
            # grupo de origem. O status (detected/partial/gap) JÁ vem da evidência
            # real via classify_detection_outcome — nada de % inventado.
            _phase_src = str(details.get("phase_name") or nested.get("phase_name") or "").strip()
            _fallback_src = _phase_src or (src_group.title() if src_group else "")
            if _fallback_src:
                observed_sources = [_fallback_src]
        for source in observed_sources:
            row = telemetry_by_source.setdefault(source, {"source": source, "total": 0, "detected": 0, "partial": 0, "gap": 0, "unknown": 0})
            row["total"] += 1
            row[status] = int(row.get(status, 0)) + 1

    capability_set = {
        str(event.capability or "").strip()
        for event in trace_rows
        if str(event.capability or "").strip()
    }
    tool_execute_events = [
        event for event in trace_rows
        if str(event.event_type or "").lower() in {"tool_execute", "tool_result", "result_return", "tool_usage_found", "tool_select"}
    ]
    successful_trace_events = [
        event for event in trace_rows
        if str(event.status or "").lower() in {"success", "completed", "done"}
    ]
    failed_trace_events = [
        event for event in trace_rows
        if str(event.status or "").lower() in {"failed", "error", "timeout"}
    ]
    if not technique_set:
        technique_set.update(capability_set)
    if not bas_payloads and tool_execute_events:
        bas_payloads = [
            {
                "capability": event.capability,
                "tool": event.tool_name,
                "event_type": event.event_type,
                "status": event.status,
            }
            for event in tool_execute_events
        ]

    has_explicit_detection = bool(detection_counts.get("detected") or detection_counts.get("partial") or detection_counts.get("gap"))
    if not has_explicit_detection and trace_rows:
        detection_counts = {"detected": 0, "partial": 0, "gap": 0, "unknown": 0}
        detection_counts["detected"] = len(successful_trace_events)
        detection_counts["gap"] = len(failed_trace_events)
        detection_counts["partial"] = len([
            event for event in trace_rows
            if str(event.status or "").lower() in {"pending", "running", "retrying"}
        ])

    if not telemetry_by_source and trace_rows:
        for event in trace_rows:
            source = str(event.capability or event.tool_name or event.event_type or "agent_flow").strip()
            if not source:
                continue
            status = str(event.status or "").lower()
            mapped_status = "detected" if status in {"success", "completed", "done"} else "gap" if status in {"failed", "error", "timeout"} else "partial"
            row = telemetry_by_source.setdefault(source, {"source": source, "total": 0, "detected": 0, "partial": 0, "gap": 0, "unknown": 0})
            row["total"] += 1
            row[mapped_status] = int(row.get(mapped_status, 0)) + 1

    total_detection_records = sum(detection_counts.values())
    control_efficacy_index = _pct(detection_counts["detected"] + (detection_counts["partial"] * 0.5), total_detection_records)
    attack_success_count = len([f for f in findings if _technique_label({**_as_dict(_as_dict(f.details).get("details")), **_as_dict(f.details)})])
    if attack_success_count == 0:
        attack_success_count = len([f for f in findings if not f.is_false_positive])
    attack_attempts = max(len(technique_set), len(bas_payloads), len(executed_runs), len(findings), 0)
    attack_success_index = min(100.0, _pct(attack_success_count, attack_attempts))

    tool_findings: dict[str, int] = {}
    for f in findings:
        details = _as_dict(f.details)
        tool_name = str(f.tool or details.get("tool") or _as_dict(details.get("details")).get("tool") or "").strip().lower()
        if tool_name:
            tool_findings[tool_name] = int(tool_findings.get(tool_name, 0)) + 1

    tool_usage_map: dict[str, dict[str, Any]] = {}
    for run in executed_runs:
        name = str(run.tool_name or "unknown").strip().lower() or "unknown"
        row = tool_usage_map.setdefault(name, {"tool": name, "attempts": 0, "successes": 0, "failures": 0, "skipped": 0, "duration_total": 0.0, "duration_count": 0, "findings": 0})
        row["attempts"] += 1
        status = str(run.status or "").lower()
        if status in {"success", "completed", "done", "executed"}:
            row["successes"] += 1
        elif status in {"skipped", "cached"}:
            row["skipped"] += 1
        else:
            row["failures"] += 1
        if run.execution_time_seconds is not None:
            row["duration_total"] += float(run.execution_time_seconds or 0.0)
            row["duration_count"] += 1
    for name, count in tool_findings.items():
        row = tool_usage_map.setdefault(name, {"tool": name, "attempts": 0, "successes": 0, "failures": 0, "skipped": 0, "duration_total": 0.0, "duration_count": 0, "findings": 0})
        row["findings"] = int(row.get("findings", 0)) + int(count)

    tool_usage = []
    for row in tool_usage_map.values():
        attempts = int(row.get("attempts") or 0)
        successes = int(row.get("successes") or 0)
        duration_count = int(row.get("duration_count") or 0)
        avg_duration = float(row.get("duration_total") or 0.0) / max(duration_count, 1)
        tool_usage.append(
            {
                "tool": row["tool"],
                "attempts": attempts,
                "successes": successes,
                "failures": int(row.get("failures") or 0),
                "skipped": int(row.get("skipped") or 0),
                "findings": int(row.get("findings") or 0),
                "success_rate": _pct(successes, attempts),
                "avg_duration_seconds": round(avg_duration, 1),
            }
        )
    tool_usage.sort(key=lambda item: (item["attempts"], item["findings"]), reverse=True)
    tool_efficiency = _pct(sum(item["successes"] for item in tool_usage), sum(item["attempts"] for item in tool_usage))

    runs_by_scan_asset: dict[int, dict[str, list[ExecutedToolRun]]] = {}
    for run in executed_runs:
        host = _asset_host_from_value(run.target)
        if not host:
            continue
        runs_by_scan_asset.setdefault(int(run.scan_job_id), {}).setdefault(host, []).append(run)

    findings_by_scan_asset: dict[int, dict[str, dict[str, Any]]] = {}
    for finding in findings:
        loc = _extract_finding_location(finding)
        host = _asset_host_from_value(loc.get("url") or loc.get("subdomain") or loc.get("target") or finding.domain)
        if not host:
            continue
        severity = str(finding.severity or "info").lower()
        scan_bucket = findings_by_scan_asset.setdefault(int(finding.scan_job_id), {})
        row = scan_bucket.setdefault(
            host,
            {
                "findings_total": 0,
                "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            },
        )
        row["findings_total"] = int(row.get("findings_total") or 0) + 1
        if severity in row["severity"]:
            row["severity"][severity] = int(row["severity"].get(severity, 0)) + 1

    terminal_scan_status = {"completed", "failed", "stopped", "blocked"}
    active_scan_status = {"queued", "running", "retrying"}
    subdomain_inventory: list[dict[str, Any]] = []
    for job in jobs[:8]:
        state = job.state_data if isinstance(job.state_data, dict) else {}
        root_hosts = {_asset_host_from_value(token) for token in _target_tokens(job.target_query)}
        root_hosts = {host for host in root_hosts if host}
        if not root_hosts:
            root_host = _asset_host_from_value(job.target_query)
            if root_host:
                root_hosts.add(root_host)

        raw_assets: list[Any] = []
        for key_name in ("lista_ativos", "discovered_assets", "hosts", "scanned_assets", "pending_asset_scans"):
            value = state.get(key_name)
            if isinstance(value, list):
                raw_assets.extend(value)
        raw_assets.extend((findings_by_scan_asset.get(int(job.id)) or {}).keys())
        raw_assets.extend((runs_by_scan_asset.get(int(job.id)) or {}).keys())

        pending_hosts = {
            _asset_host_from_value(item)
            for item in (state.get("pending_asset_scans") or [])
            if _asset_host_from_value(item)
        }
        scanned_hosts = {
            _asset_host_from_value(item)
            for item in (state.get("scanned_assets") or [])
            if _asset_host_from_value(item)
        }
        # Parallel subtask targets are not in scanned_assets but ARE in completed_work.
        # Any host with at least one "P{n}:{host}" entry was actually processed.
        for cw_entry in (state.get("completed_work") or []):
            if isinstance(cw_entry, str) and ":" in cw_entry:
                _cw_host = cw_entry.split(":", 1)[1]
                if _cw_host:
                    scanned_hosts.add(_cw_host)

        hosts = sorted(
            {
                host
                for host in (_asset_host_from_value(item) for item in raw_assets)
                if host and host not in root_hosts and (
                    not root_hosts or any(host.endswith(f".{root}") for root in root_hosts)
                )
            }
        )

        # Dead targets: discovered but DNS/HTTP non-responsive — show separately
        dead_host_set = {
            _asset_host_from_value(h)
            for h in (state.get("dead_targets") or [])
            if _asset_host_from_value(h)
        }

        rows: list[dict[str, Any]] = []
        # Five operational states:
        #   Descoberto — host found by recon but DNS/HTTP does not respond
        #   BackLog    — host discovered but no scan activity yet
        #   Em Análise — host actively being scanned (scan still running)
        #   Executado  — host was scanned and scan has completed
        #   Finalizado — host scanned, scan terminal AND has findings (reviewed)
        status_counts = {"Descoberto": 0, "BackLog": 0, "Em Análise": 0, "Executado": 0, "Finalizado": 0}
        scan_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for host in hosts[:200]:
            finding_stats = (findings_by_scan_asset.get(int(job.id)) or {}).get(host) or {
                "findings_total": 0,
                "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }
            host_runs = (runs_by_scan_asset.get(int(job.id)) or {}).get(host, [])
            has_activity = bool(host_runs or int(finding_stats.get("findings_total") or 0) or host in scanned_hosts)
            has_findings = int(finding_stats.get("findings_total") or 0) > 0
            job_status = str(job.status or "").lower()
            if host in dead_host_set and not has_activity and not has_findings:
                operational_status = "Descoberto"
            elif host in pending_hosts or (not has_activity and job_status in active_scan_status):
                operational_status = "BackLog"
            elif job_status in terminal_scan_status and has_findings:
                operational_status = "Finalizado"
            elif job_status in terminal_scan_status and has_activity:
                operational_status = "Executado"
            elif has_activity and job_status in active_scan_status:
                operational_status = "Em Análise"
            else:
                operational_status = "BackLog"

            sev_payload = dict(finding_stats.get("severity") or {})
            for sev_key in scan_severity:
                scan_severity[sev_key] += int(sev_payload.get(sev_key) or 0)
            status_counts[operational_status] = int(status_counts.get(operational_status, 0)) + 1
            rows.append(
                {
                    "subdomain": host,
                    "status": operational_status,
                    "findings_total": int(finding_stats.get("findings_total") or 0),
                    "severity": sev_payload,
                    "tool_runs": len(host_runs),
                }
            )

        _scannable_hosts = status_counts["BackLog"] + status_counts["Em Análise"] + status_counts["Executado"] + status_counts["Finalizado"]
        _done_hosts = status_counts["Executado"] + status_counts["Finalizado"]
        progress_pct = round(_done_hosts / max(1, _scannable_hosts) * 100, 1)

        rows.sort(
            key=lambda item: (
                -int(item.get("findings_total") or 0),
                str(item.get("status") or ""),
                str(item.get("subdomain") or ""),
            )
        )
        subdomain_inventory.append(
            {
                "scan_id": job.id,
                "target_query": job.target_query,
                "scan_status": job.status,
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "updated_at": job.updated_at.isoformat() if job.updated_at else None,
                "subdomain_count": len(hosts),
                "status_counts": status_counts,
                "progress_pct": progress_pct,
                "severity": scan_severity,
                "subdomains": rows,
            }
        )

    now_utc = datetime.now(timezone.utc)
    worker_active = 0
    worker_stale = 0
    worker_modes: dict[str, int] = {}
    worker_status: dict[str, int] = {}
    worker_rows_payload = []
    for worker in worker_rows:
        last_seen = worker.last_seen_at
        if last_seen and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        age_seconds = (now_utc - last_seen).total_seconds() if last_seen else 999999
        status = str(worker.status or "unknown").lower()
        mode = str(worker.mode or "unit").lower()
        if status in {"running", "busy", "active"}:
            worker_active += 1
        if age_seconds > 300:
            worker_stale += 1
        worker_modes[mode] = int(worker_modes.get(mode, 0)) + 1
        worker_status[status] = int(worker_status.get(status, 0)) + 1
        worker_rows_payload.append(
            {
                "name": worker.worker_name,
                "mode": mode,
                "status": status,
                "current_scan_id": worker.current_scan_id,
                "last_task_name": worker.last_task_name,
                "last_seen_seconds": int(age_seconds),
            }
        )

    flow_map: dict[str, dict[str, Any]] = {}
    for event in trace_rows:
        key = str(event.capability or event.event_type or f"{event.from_node}->{event.to_node}" or "agent").strip()
        row = flow_map.setdefault(key, {"stage": key, "events": 0, "successes": 0, "failures": 0, "duration_total": 0.0, "duration_count": 0})
        row["events"] += 1
        status = str(event.status or "").lower()
        if status in {"success", "completed", "done"}:
            row["successes"] += 1
        elif status in {"failed", "error", "timeout"}:
            row["failures"] += 1
        if event.duration_ms is not None:
            row["duration_total"] += float(event.duration_ms or 0.0)
            row["duration_count"] += 1

    agent_flow = []
    for row in flow_map.values():
        duration_count = int(row.get("duration_count") or 0)
        agent_flow.append(
            {
                "stage": row["stage"],
                "events": int(row.get("events") or 0),
                "success_rate": _pct(row.get("successes") or 0, row.get("events") or 0),
                "failures": int(row.get("failures") or 0),
                "avg_duration_ms": round(float(row.get("duration_total") or 0.0) / max(duration_count, 1), 1),
            }
        )
    # FALLBACK (caminho de PRODUÇÃO): o offensive operator não emite AgentTraceEvent
    # — só o caminho legado do grafo emite. Sem isso a seção "Fluxo de agentes"
    # ficava "Sem traces de agentes no escopo". O operator grava ExecutedToolRun
    # (tool/status/latência reais) — derivamos o fluxo por FERRAMENTA a partir disso
    # quando não há traces. Eventos/sucesso/latência são dados reais, não inventados.
    if not agent_flow and executed_runs:
        run_map: dict[str, dict[str, Any]] = {}
        for run in executed_runs:
            key = str(getattr(run, "tool_name", "") or "tool").strip() or "tool"
            row = run_map.setdefault(key, {"stage": key, "events": 0, "successes": 0, "failures": 0, "duration_total": 0.0, "duration_count": 0})
            row["events"] += 1
            st = str(getattr(run, "status", "") or "").lower()
            if st in {"success", "completed", "done"}:
                row["successes"] += 1
            elif st in {"failed", "error", "timeout"}:
                row["failures"] += 1
            secs = getattr(run, "execution_time_seconds", None)
            if secs is not None:
                row["duration_total"] += float(secs) * 1000.0  # s → ms
                row["duration_count"] += 1
        for row in run_map.values():
            dc = int(row.get("duration_count") or 0)
            agent_flow.append({
                "stage": row["stage"],
                "events": int(row.get("events") or 0),
                "success_rate": _pct(row.get("successes") or 0, row.get("events") or 0),
                "failures": int(row.get("failures") or 0),
                "avg_duration_ms": round(float(row.get("duration_total") or 0.0) / max(dc, 1), 1) if dc else None,
                "source": "executed_tool_runs",  # marca origem (operator, não grafo)
            })
    agent_flow.sort(key=lambda item: item["events"], reverse=True)

    accepted_learning = [row for row in learning_rows if str(row.status or "").lower() in {"accepted", "approved", "active"}]
    pending_learning = [row for row in learning_rows if str(row.status or "").lower() in {"pending", "pending_review", "review"}]
    rejected_learning = [row for row in learning_rows if str(row.status or "").lower() in {"rejected", "discarded"}]
    learned_techniques = sum(int(row.technique_count or len(row.learned_techniques or [])) for row in accepted_learning)
    target_catalog_size = max(len(ADVERSARY_TECHNIQUE_CATALOG), learned_techniques + sum(int(row.technique_count or 0) for row in pending_learning), 1)
    def _event_uses_rag(event: AgentTraceEvent) -> bool:
        blob = json.dumps(_as_dict(event.payload), default=str).lower()
        return (
            "rag" in blob
            or "accepted_learning" in blob
            or "learning_guided" in blob
            or str(event.skill_id or "").lower().startswith("learned")
        )

    rag_trace_hits = len([event for event in trace_rows if _event_uses_rag(event)])
    # Utilização = % das decisões estratégicas (dispatch/seleção de ferramenta)
    # que foram guiadas por RAG/aprendizado. Antes dividia por TODOS os eventos
    # de trace (incluindo avanços de fase), o que diluía o indicador a ~0%.
    strategy_decision_events = [
        event for event in trace_rows
        if str(event.event_type or "").lower() in {"supervisor_dispatch", "tool_select"}
    ]
    rag_guided_decisions = len([event for event in strategy_decision_events if _event_uses_rag(event)])
    learning_coverage = _pct(learned_techniques, target_catalog_size)
    learning_utilization = (
        _pct(rag_guided_decisions, len(strategy_decision_events))
        if strategy_decision_events
        else _pct(rag_trace_hits, len(trace_rows))
    )

    telemetry_rows = []
    for row in telemetry_by_source.values():
        total_source = int(row.get("total") or 0)
        det = int(row.get("detected") or 0)
        par = int(row.get("partial") or 0)
        gap = int(row.get("gap") or 0)
        unk = int(row.get("unknown") or 0)
        # Eficácia mede ONDE O CONTROLE ENXERGA/PARCIALIZA/FALHA — só faz sentido
        # sobre eventos DETECTÁVEIS (detected+partial+gap). Eventos 'unknown' são
        # recon/OSINT passivo (nada a detectar) → não contam como falha (0%); a
        # fonte vira N/A (effectiveness=None) quando só tem eventos não-detectáveis.
        detectable = det + par + gap
        telemetry_rows.append(
            {
                "source": row["source"],
                "total": total_source,
                "detected": det,
                "partial": par,
                "gap": gap,
                "unknown": unk,
                "detectable": detectable,
                "effectiveness": _pct(det + (par * 0.5), detectable) if detectable else None,
            }
        )
    # ordena por eficácia (N/A por último), depois por volume detectável e total.
    telemetry_rows.sort(
        key=lambda item: (item["effectiveness"] is not None, item["effectiveness"] or 0, item["detectable"], item["total"]),
        reverse=True,
    )

    bas_command_center = {
        "summary": {
            "bas_resilience_index": round((control_efficacy_index * 0.45) + (tool_efficiency * 0.2) + (learning_coverage * 0.2) + (_pct(effective_mitigated, effective_total) * 0.15), 1),
            "attack_success_index": attack_success_index,
            "attack_success_count": attack_success_count,
            "attack_attempts": attack_attempts,
            "control_efficacy_index": control_efficacy_index,
            "detection_gap_count": int(detection_counts.get("gap", 0) + detection_counts.get("unknown", 0)),
            "tool_efficiency_index": tool_efficiency,
            "learning_coverage_percent": learning_coverage,
            "learning_utilization_percent": learning_utilization,
            "techniques_exercised": len(technique_set),
            "validated_risk_findings": int(effective_sev_count_vuln.get("critical", 0) + effective_sev_count_vuln.get("high", 0)),
            "open_findings": int(effective_open_issues),
        },
        "attack_detection_funnel": [
            {"label": "Tecnicas planejadas", "value": len(technique_set)},
            {"label": "Payloads BAS", "value": len(bas_payloads)},
            {"label": "Execucoes de ferramentas", "value": len(executed_runs)},
            {"label": "Evidencias ofensivas", "value": attack_success_count},
            {"label": "Telemetrias esperadas", "value": sum(item["total"] for item in telemetry_rows)},
            {"label": "Deteccoes confirmadas", "value": int(detection_counts.get("detected", 0))},
            {"label": "Gaps de deteccao", "value": int(detection_counts.get("gap", 0) + detection_counts.get("unknown", 0))},
        ],
        "detection": {
            "counts": detection_counts,
            "telemetry_sources": telemetry_rows[:10],
        },
        "tools": tool_usage[:12],
        "agent_flow": agent_flow[:10],
        "workers": {
            "total": len(worker_rows),
            "active": worker_active,
            "stale": worker_stale,
            "by_mode": worker_modes,
            "by_status": worker_status,
            "rows": worker_rows_payload[:10],
        },
        "learning": {
            "total": len(learning_rows),
            "accepted": len(accepted_learning),
            "pending": len(pending_learning),
            "rejected": len(rejected_learning),
            "learned_techniques": learned_techniques,
            "catalog_size": target_catalog_size,
            "rag_trace_hits": rag_trace_hits,
            "coverage_percent": learning_coverage,
            "utilization_percent": learning_utilization,
            "recent": [
                {
                    "title": row.title,
                    "status": row.status,
                    "technique_count": row.technique_count,
                    "vulnerability_type": row.vulnerability_type,
                    "created_at": row.created_at,
                }
                for row in learning_rows[:6]
            ],
        },
    }
    bas_command_center["variables"] = dashboard_bas_variables(bas_command_center)

    return {
        "stats": {
            "scans": effective_scans,
            "findings_total": effective_total,
            "findings_open": effective_open_issues,
            "findings_triaged": effective_mitigated,
            "critical": effective_sev_count["critical"],
            "high": effective_sev_count["high"],
            "medium": effective_sev_count["medium"],
            "low": effective_sev_count["low"],
            "fair_avg_score": effective_avg_fair,
            "fair_ale_total_usd": round(effective_ale_total, 2),
            "age_env_avg_days": effective_age_env,
            "age_market_avg_days": effective_age_market,
            "age_exploit_avg_days": effective_age_exploit,
            "waf_findings": effective_waf_findings,
            "security_header_findings": effective_security_header_findings,
            "recon_findings": effective_recon_findings,
            "osint_findings": effective_osint_findings,
            "vulnerability_findings": effective_vulnerability_findings,
            "external_rating_score": continuous_rating.get("score"),
            "external_rating_grade": continuous_rating.get("grade"),
            "aggregation_mode": agg_mode,
            "aggregation_targets": len(scope_targets) if scope_targets else 1,
        },
        "frameworks": framework_scores,
        "recent_scans": recent_scans,
        "ongoing_scans": ongoing_scans,
        "top_vulns": top_vulns,
        "top_technologies": top_technologies,
        "filters": {
            "target": normalized_target,
            "access_group_id": access_group_id,
            "applied": bool(normalized_target or access_group_id is not None),
        },
        "waf_summary": {
            "findings_count": waf_findings_count,
            "assets_count": len(waf_assets),
            "assets": sorted(list(waf_assets))[:30],
            "vendors": [
                {"name": name, "count": count}
                for name, count in sorted(waf_vendors.items(), key=lambda item: item[1], reverse=True)
            ][:10],
        },
        "security_headers_summary": {
            "findings_count": security_header_findings_count,
            "assets_count": len(security_header_assets),
            "assets": sorted(list(security_header_assets))[:30],
            "present_headers": [
                {"header": name, "count": count}
                for name, count in sorted(security_header_present.items(), key=lambda item: item[1], reverse=True)
            ][:20],
            "missing_headers": [
                {"header": name, "count": count}
                for name, count in sorted(security_header_missing.items(), key=lambda item: item[1], reverse=True)
            ][:20],
            "owasp_top10_alignment": [
                {
                    "owasp": "A05 Security Misconfiguration",
                    "coverage": "CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy e Permissions-Policy reduzem superficie de configuracao insegura.",
                },
                {
                    "owasp": "A03 Injection",
                    "coverage": "CSP restringe execucao de scripts e reduz impacto de XSS/injecoes no browser.",
                },
            ],
        },
        "assets": assets,
        "activity": activity,
        "subdomain_inventory": subdomain_inventory,
        "prioritized_actions": paged_prioritized,
        "filters": {
            "target": normalized_target,
            "access_group_id": access_group_id,
            "applied": bool(normalized_target or access_group_id is not None),
        },
        "targets": sorted(
            list(
                {
                    token.strip()
                    for j in jobs
                    for token in re.split(r"[;,]", str(j.target_query or ""))
                    if token.strip()
                }
            )
        ),
        "vuln_tool_execution": vuln_tool_execution,
        "bas_command_center": bas_command_center,
        "vulnerability_fallback": {
            "scan_id": latest_scan.id if latest_scan else None,
            "scan_target": latest_scan.target_query if latest_scan else "",
            "rating": {
                "score": float(fallback_easm_rating.get("score") or 0.0),
                "grade": str(fallback_easm_rating.get("grade") or "F"),
            },
            "fair_decomposition": fallback_fair_decomposition,
            "executive_summary": str(fallback_executive_summary or "").strip(),
        },
        "prioritized_actions_page": {
            "items": paged_prioritized,
            "total": len(prioritized_actions),
            "limit": prioritized_limit,
            "offset": prioritized_offset,
        },
        "target_statistics": [
            {
                "target": target,
                "vulnerabilities_total": metrics.get("findings_total", 0),
                "vulnerabilities_open": metrics.get("findings_total", 0) - metrics.get("findings_triaged", 0),
                "critical": metrics.get("severity", {}).get("critical", 0),
                "high": metrics.get("severity", {}).get("high", 0),
                "medium": metrics.get("severity", {}).get("medium", 0),
                "low": metrics.get("severity", {}).get("low", 0),
            }
            for target, metrics in sorted(
                target_metrics.items(),
                key=lambda item: item[1].get("findings_total", 0),
                reverse=True
            )[:10]
        ],
        "continuous_rating": continuous_rating,
        "rating_timeline": rating_timeline,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Vulnerability posture endpoints (assets, temporal curves, alerts)
# ──────────────────────────────────────────────────────────────────────────────


@router.get("/dashboard/assets")
def get_easm_assets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    status_filter: str = Query("active", regex="^(active|inactive|archived)$"),
    min_criticality: float = Query(0, ge=0, le=100),
    sort_by: str = Query("last_seen", regex="^(criticality|last_seen|scan_count|rating)$"),
    scan_id: int | None = Query(None),
):
    """
    Lista ativos com rating e criticality

    Retorna:
    [{
        "id": 1,
        "domain_or_ip": "example.com",
        "criticality_score": 85.0,
        "status": "active",
        "last_scan_id": 123,
        "open_critical": 2,
        "open_high": 5,
        "rating_score": 72.5,
        "rating_grade": "C",
        "last_seen": "2026-03-25T10:00:00Z",
    }]
    """
    query = db.query(Asset).filter(
        Asset.owner_id == current_user.id if not current_user.is_admin else True,
        Asset.status == status_filter,
        Asset.criticality_score >= min_criticality,
    )

    # Escopo por scan: filtra ativos cujo domínio aparece nos findings do scan
    if scan_id:
        domains = {
            row[0]
            for row in db.query(Finding.domain)
            .filter(Finding.scan_job_id == scan_id, Finding.domain.isnot(None))
            .distinct()
            .all()
            if row[0]
        }
        query = query.filter(Asset.domain_or_ip.in_(domains)) if domains else query.filter(Asset.id == -1)

    if sort_by == "criticality":
        query = query.order_by(Asset.criticality_score.desc())
    elif sort_by == "rating":
        # TODO: JOIN com AssetRatingHistory
        pass
    else:
        query = query.order_by(Asset.last_seen.desc())

    assets = query.all()
    result = []

    for asset in assets:
        # Get latest vulnerability counts
        vuln_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for vuln in asset.vulnerabilities:
            if not vuln.remediated_at:
                sev = str(vuln.severity or "low").lower()
                if sev in vuln_counts:
                    vuln_counts[sev] += 1

        # Get latest rating
        latest_rating = (
            db.query(AssetRatingHistory)
            .filter(AssetRatingHistory.asset_id == asset.id)
            .order_by(AssetRatingHistory.recorded_at.desc())
            .first()
        )

        result.append({
            "id": asset.id,
            "domain_or_ip": asset.domain_or_ip,
            "port": asset.port,
            "asset_type": asset.asset_type,
            "criticality_score": asset.criticality_score,
            "status": asset.status,
            "open_critical": vuln_counts["critical"],
            "open_high": vuln_counts["high"],
            "open_medium": vuln_counts["medium"],
            "rating_score": latest_rating.easm_rating if latest_rating else 100.0,
            "rating_grade": latest_rating.easm_grade if latest_rating else "A",
            "scan_count": asset.scan_count,
            "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
        })

    return result


@router.get("/dashboard/vulnerabilities")
def get_easm_vulnerabilities(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    open_only: bool = Query(True),
    severity_filter: str = Query("", regex="^(|critical|high|medium|low|info)$"),
    asset_id: int | None = Query(None),
):
    """
    Lista vulnerabilidades com temporal tracking

    Retorna histórico de quando foram descobertas, detectadas repetidamente, remediadas.
    """
    query = db.query(Vulnerability).join(Asset, Asset.id == Vulnerability.asset_id)

    if not current_user.is_admin:
        query = query.filter(Asset.owner_id == current_user.id)

    if open_only:
        query = query.filter(Vulnerability.remediated_at == None)

    if severity_filter:
        query = query.filter(Vulnerability.severity == severity_filter)

    if asset_id:
        query = query.filter(Vulnerability.asset_id == asset_id)

    vulns = query.order_by(Vulnerability.first_detected.desc()).limit(100).all()

    from app.services.vuln_family import classify_family as _cf_v, family_label as _fl_v
    from app.services.framework_mapping import attack_for_family as _attack_v
    from app.services.network_context import build_network_context as _bnc_v

    result = []
    for vuln in vulns:
        _md = dict(vuln.vulnerability_metadata or {})
        _famv = _cf_v(
            title=vuln.title, tool=vuln.tool_source,
            owasp=str(_md.get("owasp_category") or ""), cve=vuln.cve_id,
            learning_family=(_md.get("learning_source") or {}).get("vuln_family"),
        )
        result.append({
            "id": vuln.id,
            "asset_id": vuln.asset_id,
            "asset_name": vuln.asset.domain_or_ip if vuln.asset else "",
            "cve_id": vuln.cve_id,
            "title": vuln.title,
            "vuln_family": _famv,
            "vuln_family_label": _fl_v(_famv),
            "mitre_attack": _attack_v(_famv),
            "network": (_md.get("network") if isinstance(_md.get("network"), dict)
                        else _bnc_v(_md, host=(vuln.asset.domain_or_ip if vuln.asset else None), resolve_dns=False)),
            "severity": vuln.severity,
            "cvss_score": vuln.cvss_score,
            "tool_source": vuln.tool_source,
            "fair_pillar": vuln.fair_pillar,
            "age_factor": vuln.age_factor,
            "ra_score": vuln.ra_score,
            "detection_count": vuln.detection_count,
            "first_detected": vuln.first_detected.isoformat(),
            "last_detected": vuln.last_detected.isoformat(),
            "remediated_at": vuln.remediated_at.isoformat() if vuln.remediated_at else None,
            "remediation_notes": vuln.remediation_notes,
            # ── ITEM 2b: dados completos exigidos pela plataforma ──────────────
            "description": vuln.description,
            "how_discovered": _md.get("how_discovered"),
            "payload": _md.get("payload"),
            "evidence": _md.get("evidence"),
            "matched_at": _md.get("matched_at"),
            "parameter": _md.get("parameter"),
            "url": _md.get("url"),
            "owasp_category": _md.get("owasp_category"),
            "verification_status": _md.get("verification_status"),
            "confidence_score": _md.get("confidence_score"),
            "scan_id": _md.get("scan_id"),
            "learning_source": _md.get("learning_source"),
            # ── Frente B: evidência de exploração (PoC + actions-on-objectives) ──
            "actively_exploited": bool(_md.get("actively_exploited")),
            "poc": _md.get("poc"),
            "exploitation": _md.get("exploitation"),
            "actions_on_objectives": _md.get("actions_on_objectives"),
        })

    return result


@router.get("/dashboard/trends/{asset_id}")
def get_easm_trends(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    days: int = Query(30, ge=7, le=365),
):
    """
    Curva temporal de um asset:
    - Histórico de ratings
    - Velocidade de remediação
    - Desvio de postura
    - Forecast 30 dias
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset não encontrado")

    if asset.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Acesso negado")

    # Historical ratings
    history = TemporalTracker.get_rating_history(db, asset_id, days=days)
    history_data = [
        {
            "ts": h.recorded_at.isoformat(),
            "score": h.easm_rating,
            "grade": h.easm_grade,
            "open_critical": h.open_critical_count,
            "open_high": h.open_high_count,
            "open_medium": h.open_medium_count,
            "remediated": h.remediated_this_period,
            "pillars": h.pillar_scores,
        }
        for h in history
    ]

    # Remediation velocity
    velocity = compute_remediation_velocity(history_data, period_days=7)

    # Current state
    current = history[-1] if history else None
    if current:
        previous = history[-2] if len(history) > 1 else None
        posture_dev = compute_posture_deviation(
            current.easm_rating,
            previous.easm_rating if previous else current.easm_rating,
            period_hours=24,
        )
        narrative = build_temporal_narrative(
            current.easm_rating,
            current.easm_grade,
            history_data,
            velocity,
            posture_dev,
        )
    else:
        posture_dev = {
            "deviation": 0.0,
            "deviation_pct": 0.0,
            "is_critical_deviation": False,
            "cause": "no_data",
            "alert_severity": None,
        }
        narrative = "Sem histórico de ratings ainda."

    # Forecast
    forecast = forecast_rating_30days(
        current.easm_rating if current else 75.0,
        velocity,
        new_findings_per_week=2,  # heurística
    )

    return {
        "asset": {
            "id": asset.id,
            "domain_or_ip": asset.domain_or_ip,
            "criticality_score": asset.criticality_score,
        },
        "historical_ratings": history_data,
        "remediation_velocity": velocity,
        "posture_deviation": posture_dev,
        "temporal_narrative": narrative,
        "forecast_30d": forecast,
    }


LEGACY_REPORT_ROUTE = "/scans/{scan_id}/" + "e" + "asm-report"


@router.get("/scans/{scan_id}/vulnerability-report")
@router.get(LEGACY_REPORT_ROUTE, include_in_schema=False)
def get_vulnerability_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Relatório ScriptKidd.o completo: análise de risco, ativos, vulnerabilidades,
    execução de ferramentas, e métricas temporais.
    
    Inclui:
    - FAIR decomposition com scores por pilar
    - Asset List com risk scores individuais
    - Vulnerability Details (CVE, CVSS, description)
    - Tool Execution Stats
    - Remediation tracking e Age Analysis
    - Activity metrics por node
    """
    from datetime import datetime, timezone
    import json
    
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    if scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Acesso negado")

    state_data = scan.state_data or {}
    report_v2 = state_data.get("report_v2", {})
    
    # ── 1. RATING E FAIR DECOMPOSITION ───────────────────────────────────────
    easm_rating = report_v2.get("easm_rating", {})
    fair_decomp = report_v2.get("fair_decomposition", {})
    
    # ── 2. ASSET LIST COM RISK SCORES ───────────────────────────────────────
    discovered_assets = state_data.get("lista_ativos", [])
    asset_details = []
    
    for asset_addr in discovered_assets:
        # Query vulnerabilities para este asset
        asset_vulns = db.query(Vulnerability).filter(
            Vulnerability.asset_id == db.query(Asset).filter(
                Asset.owner_id == scan.owner_id,
                Asset.domain_or_ip == asset_addr,
            ).with_entities(Asset.id),
        ).all()
        
        critical_ct = sum(1 for v in asset_vulns if v.severity == "critical")
        high_ct = sum(1 for v in asset_vulns if v.severity == "high")
        medium_ct = sum(1 for v in asset_vulns if v.severity == "medium")
        
        asset_details.append({
            "address": asset_addr,
            "vulnerability_count": len(asset_vulns),
            "critical_count": critical_ct,
            "high_count": high_ct,
            "medium_count": medium_ct,
            "avg_age_days": int(sum(
                (datetime.utcnow() - v.first_detected).days 
                for v in asset_vulns if v.first_detected
            ) / max(1, len(asset_vulns))) if asset_vulns else 0,
        })
    
    # ── 3. VULNERABILITY DETAILS ────────────────────────────────────────────
    findings_list = []
    recommendations_set = set()
    recommendations_with_severity = []
    
    for finding in scan.findings[:100]:  # Limita a 100 findings por performance
        findings_list.append({
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "cve": finding.cve,
            "cvss": finding.cvss,
            "domain": finding.domain,
            "tool": finding.tool,
            "risk_score": finding.risk_score,
            "confidence_score": finding.confidence_score,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
            "is_false_positive": finding.is_false_positive,
            "recommendation": finding.recommendation or "-",
        })
        
        # Coleta recomendações únicas
        if finding.recommendation and finding.recommendation.strip():
            rec_text = finding.recommendation.strip()
            if rec_text not in recommendations_set:
                recommendations_set.add(rec_text)
                recommendations_with_severity.append({
                    "text": rec_text,
                    "severity": finding.severity,
                    "priority": 0 if finding.severity == "critical" else 1 if finding.severity == "high" else 2,
                })
    
    # Sort por severidade (críticas primeiro)
    recommendations_with_severity.sort(key=lambda x: x["priority"])
    
    # ── 4. TOOL EXECUTION STATS ─────────────────────────────────────────────
    executed_tools = state_data.get("executed_tool_runs", [])
    tool_stats = {}
    for tool_run in executed_tools:
        if isinstance(tool_run, str):
            if "|" in tool_run:
                parts = [p.strip() for p in tool_run.split("|") if p.strip()]
                tool_name = parts[-1] if parts else tool_run
            elif "@" in tool_run:
                tool_name = tool_run.split("@")[0]
            else:
                tool_name = tool_run
            tool_stats[tool_name] = tool_stats.get(tool_name, 0) + 1
    
    # ── 5. ACTIVITY METRICS POR NODE ────────────────────────────────────────
    activity_metrics = state_data.get("activity_metrics", [])
    node_metrics = {}
    for metric in activity_metrics:
        if isinstance(metric, dict):
            node = metric.get("node", "unknown")
            if node not in node_metrics:
                node_metrics[node] = {"count": 0, "total_duration_ms": 0}
            node_metrics[node]["count"] += 1
            node_metrics[node]["total_duration_ms"] += metric.get("duration_ms", 0)
    
    # Calcula média por node
    for node in node_metrics:
        count = node_metrics[node]["count"]
        node_metrics[node]["avg_duration_ms"] = round(
            node_metrics[node]["total_duration_ms"] / max(1, count), 2
        )
        del node_metrics[node]["total_duration_ms"]
    
    # ── 6. REMEDIATION TRACKING ─────────────────────────────────────────────
    remediation_stats = {
        "total_vulnerabilities": len(scan.findings),
        "remediated_count": sum(1 for f in scan.findings if f.retest_status == "confirmed" and f.is_false_positive),
        "pending_retest": sum(1 for f in scan.findings if f.retest_status == "pending_retest"),
        "confirmed_false_positives": sum(1 for f in scan.findings if f.is_false_positive),
    }
    
    # ── 7. NODE HISTORY ─────────────────────────────────────────────────────
    node_history = state_data.get("node_history", [])
    
    return {
        # Metadata
        "scan_id": scan.id,
        "target": scan.target_query,
        "status": scan.status,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.updated_at.isoformat() if scan.updated_at else None,
        "execution_duration_seconds": int(
            (scan.updated_at - scan.created_at).total_seconds()
        ) if scan.updated_at and scan.created_at else 0,
        
        # FAIR Rating and Decomposition
        "rating": {
            "score": easm_rating.get("score", 0),
            "grade": easm_rating.get("grade", "F"),
            "methodology": easm_rating.get("methodology", ""),
            "n_assets_scanned": easm_rating.get("n_assets_scanned", 0),
            "total_ra": easm_rating.get("total_ra", 0),  # Total Risk Assessment
            "factors": easm_rating.get("factors", {}),  # Decomposição de fatores
        },
        "fair_decomposition": {
            "pillars": fair_decomp.get("pillars", []),
            "total_findings": fair_decomp.get("total_findings", 0),
            "methodology": fair_decomp.get("methodology", ""),
        },
        "executive_summary": report_v2.get("executive_summary", ""),
        
        # Asset List
        "assets": {
            "discovered_count": len(discovered_assets),
            "assets_detail": asset_details,
        },
        
        # Vulnerabilities
        "vulnerabilities": {
            "total_count": len(scan.findings),
            "findings": findings_list[:50],  # Amostra de 50 para resposta JSON
            "by_severity": {
                "critical": sum(1 for f in scan.findings if f.severity == "critical"),
                "high": sum(1 for f in scan.findings if f.severity == "high"),
                "medium": sum(1 for f in scan.findings if f.severity == "medium"),
                "low": sum(1 for f in scan.findings if f.severity == "low"),
                "info": sum(1 for f in scan.findings if f.severity == "info"),
            },
        },
        
        # Top Recommendations
        "recommendations": {
            "total_unique": len(recommendations_set),
            "recommendations": recommendations_with_severity[:20],  # Top 20 recomendações
        },
        
        # Tool Execution
        "tool_execution": {
            "executed_tools": tool_stats,
            "tool_count": len(tool_stats),
            "total_executions": len(executed_tools),
        },
        
        # Remediation
        "remediation": remediation_stats,
        
        # Activity Metrics
        "activity_metrics": {
            "node_execution_stats": node_metrics,
            "node_sequence": node_history,
            "total_nodes_executed": len(node_history),
        },
        
    }


@router.get("/scans/{scan_id}/temporal-analysis")
def get_temporal_analysis(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Análises temporais: remediation velocity, posture deviation,
    age distribution, e 30-day forecast.
    
    Inclui:
    - Velocidade de remediação (% por semana)
    - Desvio de postura (mudança em 24h)
    - Análise de AGE (distribuição de dias aberto)
    - Forecast de rating para 30 dias
    """
    from datetime import datetime, timezone, timedelta
    
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    if scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Acesso negado")

    state_data = scan.state_data or {}
    easm_rating = state_data.get("easm_rating", {})
    fair_decomp = state_data.get("fair_decomposition", {})
    
    # ── 1. VULNERABILITY AGE ANALYSIS ───────────────────────────────────────
    findings = scan.findings
    age_distribution = {"0_to_7_days": 0, "8_to_30_days": 0, "31_to_60_days": 0, "over_60_days": 0}
    critical_aging = []
    
    now = datetime.now(timezone.utc)
    for finding in findings:
        if finding.created_at:
            age_days = (now - finding.created_at).days
            if age_days <= 7:
                age_distribution["0_to_7_days"] += 1
            elif age_days <= 30:
                age_distribution["8_to_30_days"] += 1
            elif age_days <= 60:
                age_distribution["31_to_60_days"] += 1
            else:
                age_distribution["over_60_days"] += 1
            
            # Critical ou High and old
            if finding.severity in ["critical", "high"] and age_days > 30:
                critical_aging.append({
                    "finding_id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "age_days": age_days,
                    "cve": finding.cve,
                })
    
    # ── 2. REMEDIATION TRACKING ────────────────────────────────────────────
    remediated_findings = [f for f in findings if f.retest_status == "confirmed"]
    remediation_rate = (len(remediated_findings) / max(1, len(findings))) * 100 if findings else 0
    
    # Estimativa de velocidade (findings remediados em período)
    days_elapsed = (now - scan.created_at).days if scan.created_at else 1
    weekly_remediation_rate = (len(remediated_findings) / max(1, days_elapsed)) * 7 * 100
    
    # ── 3. HISTORICAL RATINGS (via AssetRatingHistory) ──────────────────────
    discovered_assets = state_data.get("lista_ativos", [])
    historical_ratings = []
    
    for asset_addr in discovered_assets[:5]:  # Limita a 5 assets por performance
        asset = db.query(Asset).filter(
            Asset.owner_id == scan.owner_id,
            Asset.domain_or_ip == asset_addr,
        ).first()
        
        if asset:
            history = db.query(AssetRatingHistory).filter(
                AssetRatingHistory.asset_id == asset.id,
            ).order_by(AssetRatingHistory.recorded_at.desc()).limit(10).all()
            
            if history:
                historical_ratings.append({
                    "asset": asset_addr,
                    "history": [
                        {
                            "timestamp": h.recorded_at.isoformat(),
                            "rating": h.easm_rating,
                            "grade": h.easm_grade,
                            "open_critical": h.open_critical_count,
                            "open_high": h.open_high_count,
                            "remediated": h.remediated_this_period,
                        }
                        for h in history
                    ],
                })
    
    # ── 4. POSTURE DEVIATION (mudança vs último scan) ───────────────────────
    current_score = float(easm_rating.get("score", 0))
    deviation_24h = "unknown"  # Seria calculado com histórico real
    deviation_pct_change = 0
    
    if historical_ratings and historical_ratings[0]["history"]:
        last_history = historical_ratings[0]["history"][1] if len(historical_ratings[0]["history"]) > 1 else None
        if last_history:
            last_score = float(last_history["rating"])
            deviation_pct_change = round(((current_score - last_score) / max(1, last_score)) * 100, 2)
            deviation_24h = "improved" if deviation_pct_change > 0 else "degraded" if deviation_pct_change < 0 else "stable"
    
    # ── 5. 30-DAY FORECAST ─────────────────────────────────────────────────
    # Projeção simples com remediação linear
    days_to_zero = None
    if weekly_remediation_rate > 0:
        remaining_findings = len([f for f in findings if f.retest_status != "confirmed"])
        weeks_to_zero = remaining_findings / max(0.1, weekly_remediation_rate / 7)
        days_to_zero = int(weeks_to_zero * 7)
    
    # Simulação de rating em 30 dias (simplificado)
    projected_score_30d = current_score
    if weekly_remediation_rate > 0:
        # Assume 4 semanas, cada semana reduz X%
        projected_score_30d = current_score * (1 + (weekly_remediation_rate / 100 / 4))
        projected_score_30d = min(100, max(0, projected_score_30d))
    
    return {
        "scan_id": scan.id,
        "target": scan.target_query,
        "current_rating": {
            "score": current_score,
            "grade": easm_rating.get("grade", "F"),
        },
        
        # Age Analysis
        "age_analysis": {
            "distribution": age_distribution,
            "critical_and_aging": critical_aging,
            "aging_critical_count": len(critical_aging),
            "notes": "Vulnerabilidades críticas/altas abertas há mais de 30 dias",
        },
        
        # Remediation Tracking
        "remediation": {
            "remediated_count": len(remediated_findings),
            "total_findings": len(findings),
            "remediation_rate_pct": round(remediation_rate, 2),
            "weekly_remediation_rate_pct": round(weekly_remediation_rate, 2),
            "estimated_days_to_zero": days_to_zero,
        },
        
        # Posture Deviation
        "posture_deviation": {
            "change_24h": deviation_24h,
            "pct_change": deviation_pct_change,
            "alert_threshold_exceeded": abs(deviation_pct_change) > 10,
        },
        
        # Historical Trends
        "historical_trends": historical_ratings,
        
        # 30-Day Forecast
        "forecast_30_days": {
            "projected_score": round(projected_score_30d, 2),
            "confidence": "medium",
            "drivers": [
                "Remediação contínua em taxa de " + str(round(weekly_remediation_rate, 2)) + "% semana",
                "Efeito do fator AGE sobre vulnerabilidades não remediadas",
            ] if weekly_remediation_rate > 0 else ["Sem progresso de remediação"],
        },
    }


LEGACY_ALERTS_ROUTE = "/" + "e" + "asm/alerts"
LEGACY_ALERT_RESOLVE_ROUTE = "/" + "e" + "asm/alerts/{alert_id}/resolve"


@router.get("/vulnerability-alerts")
@router.get(LEGACY_ALERTS_ROUTE, include_in_schema=False)
def get_vulnerability_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    unresolved_only: bool = Query(True),
    severity_filter: str = Query("", regex="^(|critical|high|medium)$"),
):
    """Lista alertas de desvio de postura de vulnerabilidade"""
    query = db.query(EASMAlert).filter(EASMAlert.owner_id == current_user.id)

    if unresolved_only:
        query = query.filter(EASMAlert.is_resolved == False)

    if severity_filter:
        query = query.filter(EASMAlert.severity == severity_filter)

    alerts = query.order_by(EASMAlert.created_at.desc()).limit(50).all()

    return [
        {
            "id": a.id,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "title": a.title,
            "description": a.description,
            "asset_id": a.asset_id,
            "is_resolved": a.is_resolved,
            "created_at": a.created_at.isoformat(),
            "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
        }
        for a in alerts
    ]


@router.post("/vulnerability-alerts/{alert_id}/resolve")
@router.post(LEGACY_ALERT_RESOLVE_ROUTE, include_in_schema=False)
def resolve_vulnerability_alert(
    alert_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Marca alerta como resolvido"""
    alert = db.query(EASMAlert).filter(
        EASMAlert.id == alert_id,
        EASMAlert.owner_id == current_user.id,
    ).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alerta não encontrado")

    alert.is_resolved = True
    alert.resolved_at = datetime.now(timezone.utc)
    alert.resolved_notes = payload.get("notes", "")
    db.commit()

    return {"message": "Alerta resolvido", "alert_id": alert.id}


# ─────────────────────────────────────────────────────────────────────────────
# Executive Report — HTML gerado no servidor
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/executive-report", response_class=Response)
def get_executive_report(
    scan_id: int,
    previous_scan_id: int | None = Query(default=None, description="ID do scan anterior para delta"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Gera relatório executivo HTML para o scan indicado.
    Inclui sumário de severidades, superfície de alto risco, correlações e recomendações.
    """
    from app.models.models import ScanJob
    from app.services.report_generator import generate_executive_report

    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    # Antes de gerar o relatório, rodar inteligência pós-processamento
    try:
        from app.services.finding_intelligence import run_all_intelligence
        run_all_intelligence(db, scan_id)
    except Exception:
        pass

    html = generate_executive_report(db, scan_id, previous_scan_id=previous_scan_id)
    return Response(
        content=html,
        media_type="text/html",
        headers={
            "Content-Disposition": f'inline; filename="easm-report-scan{scan_id}.html"',
            "Cache-Control": "no-cache",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase Breakdown — work-queue statistics per kill-chain phase
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/learning-usage")
def get_learning_usage(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Uso e acertividade dos aprendizados HackerOne neste scan (P3a).

    Mede: quantas técnicas foram semeadas pelos 10k learnings, quantas
    completaram, quantas produziram achados (acertividade), por que foram
    usadas (tech stacks) e o detalhe por ferramenta/técnica.
    """
    from app.models.models import ScanJob, ScanWorkItem, Finding
    import sqlalchemy as _sa

    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    if not current_user.is_admin and job.owner_id != current_user.id:
        allowed = [g.id for g in current_user.groups]
        if job.access_group_id not in allowed:
            raise HTTPException(status_code=403, detail="Sem acesso")

    # Work items semeados pelo aprendizado (metadata.source = hackerone_learnings)
    seeded = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.item_metadata["source"].astext == "hackerone_learnings",
        )
        .all()
    )
    total_seeded = len(seeded)
    _TERM_DONE = {"completed", "done"}
    completed = sum(1 for i in seeded if i.status in _TERM_DONE)
    failed = sum(1 for i in seeded if i.status in ("failed", "timeout", "skipped"))
    running = sum(1 for i in seeded if i.status in ("queued", "retry", "dispatched", "running", "submitted", "blocked"))

    # Achados produzidos por work items de aprendizado (details.learning_source)
    learning_findings = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == scan_id,
            Finding.details["learning_source"].isnot(None),
        )
        .all()
    )
    findings_produced = len(learning_findings)
    confirmed_produced = sum(1 for f in learning_findings if str(f.verification_status or "") == "confirmed")
    hc_produced = sum(1 for f in learning_findings if str(f.severity or "").lower() in ("critical", "high"))

    # Acertividade = % de técnicas semeadas (que completaram) que geraram achado.
    # Aproximação: findings_produced / completed (cap 100). Tech que confirma = bônus.
    accuracy_pct = int(min(100, (findings_produced / completed * 100))) if completed else 0
    confirm_rate = int(min(100, (confirmed_produced / findings_produced * 100))) if findings_produced else 0

    # Por ferramenta/técnica
    by_tool: dict[str, dict] = {}
    for i in seeded:
        t = str(i.tool_name or "")
        slot = by_tool.setdefault(t, {"tool": t, "seeded": 0, "completed": 0})
        slot["seeded"] += 1
        if i.status in _TERM_DONE:
            slot["completed"] += 1
    # findings por tool de aprendizado
    for f in learning_findings:
        t = str(f.tool or "")
        if t in by_tool:
            by_tool[t]["findings"] = by_tool[t].get("findings", 0) + 1

    # Por CLASSE de vulnerabilidade (família) — utilização + acertividade
    by_family: dict[str, dict] = {}
    for i in seeded:
        md = dict(i.item_metadata or {})
        fam = str(md.get("vuln_family") or "outros")
        slot = by_family.setdefault(fam, {
            "family": fam, "seeded": 0, "completed": 0, "findings": 0,
            "confirmed": 0, "learning_count": int(md.get("learning_count") or 0),
            "engine": md.get("engine") or "attack_index",
            "similarity_pct": 0, "matched_reports": [],
        })
        slot["seeded"] += 1
        # Proveniência semântica: melhor similaridade + reports que motivaram.
        sim = int(md.get("similarity_pct") or 0)
        if sim > slot["similarity_pct"]:
            slot["similarity_pct"] = sim
        if md.get("engine"):
            slot["engine"] = md.get("engine")
        for rep in (md.get("matched_reports") or []):
            if rep and rep not in slot["matched_reports"] and len(slot["matched_reports"]) < 5:
                slot["matched_reports"].append(rep)
        if i.status in _TERM_DONE:
            slot["completed"] += 1
    for f in learning_findings:
        ls = dict(f.details or {}).get("learning_source") or {}
        fam = str(ls.get("vuln_family") or "outros")
        if fam in by_family:
            by_family[fam]["findings"] += 1
            if str(f.verification_status or "") == "confirmed":
                by_family[fam]["confirmed"] += 1
    # acertividade por família = findings / completed
    for slot in by_family.values():
        comp = slot["completed"]
        slot["accuracy_pct"] = int(min(100, slot["findings"] / comp * 100)) if comp else 0

    # Tech stacks que dispararam o aprendizado (why used)
    tech_stacks: dict[str, int] = {}
    for i in seeded:
        for ts in (dict(i.item_metadata or {}).get("tech_stack") or []):
            k = str(ts)
            tech_stacks[k] = tech_stacks.get(k, 0) + 1

    return {
        "scan_id": scan_id,
        "learning_base_size": _learning_base_count(db),
        "summary": {
            "total_seeded": total_seeded,
            "completed": completed,
            "failed": failed,
            "running": running,
            "findings_produced": findings_produced,
            "confirmed_produced": confirmed_produced,
            "high_critical_produced": hc_produced,
            "accuracy_pct": accuracy_pct,          # % das técnicas que geraram achado
            "confirm_rate_pct": confirm_rate,      # % dos achados que foram confirmados
        },
        "by_tool": sorted(by_tool.values(), key=lambda x: -x.get("seeded", 0)),
        "by_family": sorted(by_family.values(), key=lambda x: -x.get("learning_count", 0)),
        "tech_stacks": [{"tech": k, "count": v} for k, v in sorted(tech_stacks.items(), key=lambda x: -x[1])],
        "rationale": (
            "Os aprendizados HackerOne são consultados após a detecção de tecnologia (P07): "
            "o stack detectado é cruzado (relevance-ranked) contra a base de reports reais e as "
            "técnicas comprovadamente exploráveis nesse stack são semeadas com prioridade alta."
        ),
    }


def _learning_base_count(db) -> int:
    try:
        from sqlalchemy import text as _t
        return db.execute(_t("SELECT COUNT(*) FROM vulnerability_learnings WHERE status='accepted'")).scalar() or 0
    except Exception:
        return 0


@router.get("/scans/{scan_id}/phase-breakdown")
def get_phase_breakdown(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns per-phase work-queue statistics for the scan.

    Each phase entry contains:
      phase_id, total, completed, failed, running, queued, blocked,
      pct (0-100), status (done|running|queued|blocked|failed|empty)

    Used by the PhaseBreakdown component in the scan detail sidebar.
    """
    from app.models.models import ScanJob, ScanWorkItem
    import sqlalchemy as _sa

    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed = [g.id for g in current_user.groups]
        query = query.filter(
            (ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed))
        )
    job = query.first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    # Query work_items grouped by phase_id + status in one pass
    rows = (
        db.query(
            ScanWorkItem.phase_id,
            ScanWorkItem.status,
            _sa.func.count(ScanWorkItem.id).label("cnt"),
        )
        .filter(ScanWorkItem.scan_job_id == scan_id)
        .group_by(ScanWorkItem.phase_id, ScanWorkItem.status)
        .all()
    )

    # Aggregate per phase
    phase_map: dict[str, dict] = {}
    for phase_id, status, cnt in rows:
        if phase_id not in phase_map:
            phase_map[phase_id] = {
                "phase_id": phase_id,
                "total": 0, "completed": 0, "failed": 0,
                "running": 0, "queued": 0, "blocked": 0,
                "timeout": 0, "skipped": 0,
            }
        p = phase_map[phase_id]
        p["total"] += cnt
        if status in ("completed", "done"):
            p["completed"] += cnt
        elif status == "failed":
            p["failed"] += cnt
        elif status in ("dispatched", "running", "submitted"):
            p["running"] += cnt
        elif status == "queued":
            p["queued"] += cnt
        elif status == "blocked":
            p["blocked"] += cnt
        elif status == "timeout":
            p["timeout"] += cnt
        elif status == "skipped":
            p["skipped"] += cnt

    # Phase metadata (id → name) aligned with PENTEST_PHASES
    PHASE_NAMES = {
        "P01": "Subdomain Enumeration",
        "P02": "Port Scan",
        "P03": "Endpoint Discovery",
        "P04": "Parameter Discovery",
        "P05": "Technology Fingerprint",
        "P06": "HTTP Fingerprint",
        "P07": "OSINT",
        "P08": "JS Endpoint Analysis",
        "P09": "Web App Scanning (nuclei)",
        "P10": "SQL Injection",
        "P11": "XSS / Injection",
        "P12": "Active Exploitation",
        "P13": "Command Injection",
        "P14": "Auth Boundary Testing",
        "P15": "Historical Recon",
        "P16": "API Attack Surface",
        "P17": "Business Logic",
        "P18": "OSINT Extended",
        "P19": "Supply Chain",
        "P20": "Post-Exploitation",
        "P21": "PoC Validation (Sandbox)",
        "P22": "Reporting",
    }

    # ── Cross-reference with phase_ledger_v2 ─────────────────────────────────
    # Phases executed via the LangGraph engine have no scan_work_items rows.
    # phase_ledger_v2 (stored in job.state_data) has their status.
    # Build a map: phase_id → ledger_status ("completed"|"partial"|"failed"|...)
    ledger_status_map: dict[str, str] = {}
    try:
        state_data = dict(job.state_data or {})
        phase_ledger = state_data.get("phase_ledger_v2") or []
        if isinstance(phase_ledger, list):
            for entry in phase_ledger:
                if not isinstance(entry, dict):
                    continue
                pid_l = str(entry.get("phase_id") or "").upper().strip()
                st_l  = str(entry.get("status") or "").lower()
                if pid_l and st_l:
                    # Keep the "best" status: completed > partial > failed
                    prev = ledger_status_map.get(pid_l, "")
                    if st_l == "completed" or (st_l == "partial" and prev != "completed"):
                        ledger_status_map[pid_l] = st_l
                    elif not prev:
                        ledger_status_map[pid_l] = st_l
        elif isinstance(phase_ledger, dict):
            for pid_l, entry in phase_ledger.items():
                st_l = str((entry.get("status") if isinstance(entry, dict) else entry) or "").lower()
                if st_l:
                    ledger_status_map[str(pid_l).upper()] = st_l
    except Exception:
        pass

    # Build ordered result for P01-P22
    result = []
    for pid in [f"P{i:02d}" for i in range(1, 23)]:
        p = phase_map.get(pid)
        if p is None:
            # No work-queue items — check ledger for LangGraph-executed phases
            ledger_st = ledger_status_map.get(pid, "")
            if ledger_st in ("completed",):
                phase_status = "done"
            elif ledger_st in ("partial", "partial_coverage"):
                phase_status = "partial"
            elif ledger_st in ("failed", "attempted_failed"):
                phase_status = "failed"
            else:
                phase_status = "empty"

            result.append({
                "phase_id": pid,
                "name": PHASE_NAMES.get(pid, pid),
                "total": 0, "completed": 0, "failed": 0,
                "running": 0, "queued": 0, "blocked": 0,
                "skipped": 0, "timeout": 0,
                "pct": 100 if phase_status == "done" else 0,
                "success_pct": 100 if phase_status == "done" else 0,
                "status": phase_status,
                "ledger": ledger_st or None,
            })
            continue

        total = p["total"]
        completed = p["completed"]
        failed = p["failed"]
        running = p["running"]
        queued = p["queued"]
        blocked = p["blocked"]
        skipped = p["skipped"]
        timeout = p["timeout"]

        # pct = terminal/total. A phase is 100% when every item reached a terminal
        # state (done/skipped/failed/timeout). Skip of a non-applicable tool
        # (no .git exposed, no API key) is a LEGITIMATE completion, not a gap.
        # success_pct = done/total exposes the real success quality separately.
        terminal = completed + failed + timeout + skipped
        pct = int(terminal / total * 100) if total > 0 else 0
        success_pct = int(completed / total * 100) if total > 0 else 0

        if total == 0:
            phase_status = "empty"
        elif terminal == total:
            # Phase finished. Quality nuance: full success vs partial vs mostly-skipped.
            phase_status = "done" if completed == total else "partial"
        elif running > 0:
            phase_status = "running"
        elif blocked == total:
            phase_status = "blocked"
        elif queued > 0 or blocked > 0:
            phase_status = "queued"
        else:
            phase_status = "partial"

        result.append({
            "phase_id": pid,
            "name": PHASE_NAMES.get(pid, pid),
            "total": total,
            "completed": completed,
            "failed": failed,
            "running": running,
            "queued": queued,
            "blocked": blocked,
            "skipped": skipped,
            "timeout": timeout,
            "pct": pct,
            "success_pct": success_pct,
            "status": phase_status,
            "ledger": ledger_status_map.get(pid) or None,
        })

    # Summary stats
    total_items = sum(p["total"] for p in result)
    total_done = sum(p["completed"] for p in result)
    total_running = sum(p["running"] for p in result)
    total_failed = sum(p["failed"] for p in result)
    p21 = phase_map.get("P21", {})

    return {
        "scan_id": scan_id,
        "scan_status": str(job.status or ""),
        "phases": result,
        "summary": {
            "total_items": total_items,
            "total_done": total_done,
            "total_running": total_running,
            "total_failed": total_failed,
            "phases_active": len([p for p in result if p["status"] in ("running", "queued", "partial")]),
            "phases_done": len([p for p in result if p["status"] == "done"]),
            "phases_blocked": len([p for p in result if p["status"] == "blocked"]),
            "p21_total": p21.get("total", 0),
            "p21_confirmed": p21.get("completed", 0),
            "p21_refuted": p21.get("failed", 0),
            "p21_pending": p21.get("queued", 0) + p21.get("running", 0),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Pentest Report — combined pentest + EASM HTML report
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/pentest-report", response_class=Response)
def get_pentest_report(
    scan_id: int,
    previous_scan_id: int | None = Query(default=None, description="Scan anterior para delta"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Gera o relatório completo de Pentest Automatizado (HTML).

    Inclui:
      Seção 1 — PENTEST (confirmados com PoC):
        - Sumário executivo com risco confirmado
        - P21 sandbox stats (confirmados / FP suprimidos / pendentes)
        - Kill chain phase coverage (P01-P22 visual)
        - Vulnerabilidades confirmadas com evidência real do sandbox
        - Chains de ataque detectadas
        - Matriz Blue Team com SLA (P1=24h, P2=72h, P3=7d, P4=30d)
        - Matriz de risco por alvo
        - Delta vs scan anterior (se previous_scan_id fornecido)
      Seção 2 — EASM (superfície de ataque):
        - Subdomínios, portas, tecnologias
        - Findings por severidade com status de verificação
        - Distribuição OWASP Top 10
    """
    from app.models.models import ScanJob
    from app.services.report_generator import generate_pentest_report

    # Allow access: owner or admin
    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter(
            (ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids))
        )
    job = query.first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    # Pre-report: run CVE enrichment and intelligence pass
    try:
        from app.services.cve_enrichment_service import enrichment_service as _enrich_svc
        _enrich_svc.enrich_scan_findings(db, scan_id)
    except Exception:
        pass
    try:
        from app.services.finding_intelligence import run_all_intelligence
        run_all_intelligence(db, scan_id)
    except Exception:
        pass
    # Re-correlate exploit chains to pick up any newly-confirmed findings
    try:
        from app.services.exploit_chain import correlate_chains as _cc
        _cc(db, scan_id)
    except Exception:
        pass

    html = generate_pentest_report(db, scan_id, previous_scan_id=previous_scan_id)
    return Response(
        content=html,
        media_type="text/html",
        headers={
            "Content-Disposition": f'inline; filename="pentest-report-scan{scan_id}.html"',
            "Cache-Control": "no-cache",
        },
    )


@router.post("/scans/{scan_id}/run-intelligence")
def run_scan_intelligence(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executa pós-processamento de inteligência no scan:
    - Consolida findings sistêmicos
    - Correlaciona WAF bypass × Shodan
    """
    from app.models.models import ScanJob
    from app.services.finding_intelligence import run_all_intelligence

    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    result = run_all_intelligence(db, scan_id)
    return {
        "scan_id": scan_id,
        "intelligence_results": result,
        "message": (
            f"{result.get('systemic', 0)} findings sistêmicos criados, "
            f"{result.get('waf_shodan_correlations', 0)} correlações WAF×Shodan"
        ),
    }


@router.post("/scans/{scan_id}/enrich-cves")
def enrich_scan_cve_findings(
    scan_id: int,
    limit: int = Query(default=200, ge=1, le=500, description="Máx. de CVEs a enriquecer"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Enriquece findings de CVE de um scan com:
    - Descrição técnica da vulnerabilidade
    - Versões afetadas
    - Passos para reprodução / PoC / payload
    - URL do patch
    - CVSS real do NVD
    - CWEs (fraquezas associadas)

    Para CVEs na base local (Log4Shell, Spring4Shell, Grafana, Portainer, etc.)
    o enriquecimento é instantâneo. Para outras, consulta a API do NVD.
    """
    from app.models.models import ScanJob
    from app.services.cve_enricher import enrich_scan_cves

    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    enriched = enrich_scan_cves(db, scan_id, limit=limit)
    return {
        "scan_id": scan_id,
        "enriched": enriched,
        "message": (
            f"{enriched} CVE findings enriquecidos com descrição, "
            "passos de reprodução, payload e CVSS."
        ),
    }


@router.post("/findings/enrich-all-cves")
def enrich_all_cve_findings(
    limit: int = Query(default=500, ge=1, le=2000, description="Máx. de findings a processar"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Backfill: enriquece TODOS os findings com CVE que ainda não têm cve_description.
    Útil para corrigir dados históricos sem precisar re-rodar scans.

    Processa findings onde:
    - title == cve (bare CVE ID sem descrição)
    - cve_description está vazio em details
    """
    from app.services.cve_enricher import enrich_all_cves

    enriched = enrich_all_cves(db, limit=limit, owner_id=current_user.id)
    return {
        "enriched": enriched,
        "message": (
            f"{enriched} CVE findings backfill-enriquecidos com descrição e passos de reprodução."
        ),
    }


@router.get("/scans/{scan_id}/attack-graph")
def get_attack_graph(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Constrói e retorna o grafo de ataque para o scan.

    Analisa todos os findings e correlaciona:
    - Capabilities geradas por cada vulnerabilidade
    - Caminhos de ataque: internet → dado sensível
    - Kill chains completas com narrativa e TTPs do MITRE ATT&CK
    - Score de risco composto (não individual por finding)
    """
    from app.models.models import ScanJob
    from app.services.attack_graph import build_attack_graph

    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    graph = build_attack_graph(db, scan_id)
    return {"scan_id": scan_id, **graph}


@router.post("/scans/{scan_id}/business-logic")
def run_business_logic_analysis(
    scan_id: int,
    domains: list[str] | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executa análise de business logic nos domínios do scan.

    Testa contexto de negócio:
    - APIs financeiras: IDOR em contas, negative balance, BOLA
    - Docker/Portainer: API sem auth, env vars expostas
    - Auth services: JWT none alg, token reuse, rate limit
    - Dev environments: debug endpoints, verbose errors, CORS aberto
    """
    from app.models.models import ScanJob
    from app.services.business_logic_analyzer import run_business_logic_scan

    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    result = run_business_logic_scan(db, scan_id, target_domains=domains)
    return {"scan_id": scan_id, **result}


@router.get("/scans/{scan_id}/js-pollution")
def get_js_pollution_results(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retorna resultados de análise de JS Prototype Pollution + HPP para o scan.

    Inclui:
    - Canary reflection detection (JSON body + query string)
    - Gadget chain probing (child_process, lodash, Kibana CVE-2019-7609)
    - Cross-request persistence test (global process pollution)
    - HTTP Parameter Pollution (WAF/validation bypass)
    """
    from app.models.models import Finding, ScanJob

    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == scan_id,
            Finding.tool == "js_pollution_analyzer",
        )
        .order_by(Finding.severity.desc(), Finding.created_at.desc())
        .all()
    )

    items = []
    for f in findings:
        det = dict(f.details or {})
        items.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "domain": f.domain,
            "test_type": det.get("test_type"),
            "pollution_type": det.get("pollution_type"),
            "gadget_chain": det.get("gadget_chain"),
            "canary": det.get("canary"),
            "evidence": f.evidence,
            "cvss_estimate": det.get("cvss_estimate"),
            "reproduction_steps": det.get("reproduction_steps", []),
            "business_impact": det.get("business_impact"),
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })

    state = dict(job.state_data or {})
    return {
        "scan_id": scan_id,
        "total": len(items),
        "findings": items,
        "auto_triggered": bool(state.get("jsp_triggered")),
        "summary": {
            "rce": sum(1 for i in items if i.get("gadget_chain") and "rce" in str(i.get("gadget_chain", "")).lower()),
            "auth_bypass": sum(1 for i in items if "auth_bypass" in str(i.get("pollution_type", "")).lower()),
            "info_disclosure": sum(1 for i in items if "info" in str(i.get("pollution_type", "")).lower()),
            "hpp": sum(1 for i in items if i.get("test_type") == "http_parameter_pollution"),
        },
    }


@router.post("/scans/{scan_id}/js-pollution")
def run_js_pollution_analysis(
    scan_id: int,
    domains: list[str] | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executa análise de JS Prototype Pollution + HTTP Parameter Pollution nos domínios.

    Payloads de teste:
    - __proto__ / constructor.prototype via JSON body e query string
    - Gadget chains: child_process, lodash, Kibana CVE-2019-7609, commander.js
    - Cross-request persistence (global state pollution)
    - Duplicate params (HPP para bypass de WAF/validação)
    """
    from app.models.models import ScanJob
    from app.services.js_pollution_analyzer import run_js_pollution_scan

    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    result = run_js_pollution_scan(db, scan_id, target_domains=domains)
    return {"scan_id": scan_id, **result}


@router.get("/scans/{scan_id}/exploit-chains")
def get_exploit_chains(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retorna correntes de exploit correlacionadas para o scan.

    Identifica:
    - Caminhos de ataque multi-etapa (ex: enum → SSRF → RCE)
    - CVSS composite estimado por chain
    - Mapeamento MITRE ATT&CK + LGPD Art. 46/47
    - Referências CVE (CVE-2019-7609, CVE-2022-24999, etc.)
    """
    from app.models.models import ScanJob
    from app.services.exploit_chain import correlate_chains

    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    chains = correlate_chains(db, scan_id)
    state = dict(job.state_data or {})

    return {
        "scan_id": scan_id,
        "chains": chains if isinstance(chains, list) else [],
        "total_chains": len(chains) if isinstance(chains, list) else 0,
        "correlated_automatically": bool(state.get("exploit_chains_correlated")),
        "attack_graph_nodes": state.get("attack_graph_nodes", 0),
    }


@router.post("/scans/{scan_id}/supply-chain")
def run_supply_chain_analysis(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Analisa supply chain e dependências de terceiros.

    Detecta:
    - Scripts sem SRI (CDN, GTM, analytics)
    - Session recording tools (Hotjar, FullStory) — risco LGPD
    - Google Tag Manager sem proteção (injeção de JS via conta GTM comprometida)
    - Bibliotecas JS vulneráveis (jQuery, Lodash, Handlebars)
    - package.json / .env expostos publicamente
    """
    from app.models.models import ScanJob
    from app.services.supply_chain_analyzer import run_supply_chain_scan

    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    result = run_supply_chain_scan(db, scan_id)
    return {"scan_id": scan_id, **result}




@router.get("/scans/{scan_id}/attack-narrative")
def get_attack_narrative(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retorna a narrativa de ataque gerada para o scan (L6)."""
    from app.models.models import ScanJob
    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    state = dict(job.state_data or {})
    narrative = state.get("attack_narrative")
    if not narrative:
        raise HTTPException(status_code=404, detail="Narrativa não gerada ainda. Execute o scan primeiro.")
    return {
        "scan_id": scan_id,
        "narrative": narrative,
        "method": state.get("attack_narrative_method", "unknown"),
        "generated_at": state.get("attack_narrative_generated_at"),
    }


@router.post("/scans/{scan_id}/generate-narrative")
def generate_attack_narrative(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Gera (ou regenera) a narrativa de ataque para o scan via LLM (L6)."""
    from app.models.models import ScanJob
    from app.services.attack_narrative import run_attack_narrative
    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    result = run_attack_narrative(db, job)
    if result.get("skipped"):
        raise HTTPException(status_code=422, detail=f"Narrativa não pôde ser gerada: {result['skipped']}")
    return {"scan_id": scan_id, **result}


@router.get("/scans/{scan_id}/crown-jewels")
def get_crown_jewels(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retorna os ativos de alto valor identificados pelo crown jewel analyzer (M1)."""
    from app.models.models import ScanJob
    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    state = dict(job.state_data or {})
    crown_jewels = state.get("crown_jewels", [])
    return {
        "scan_id": scan_id,
        "crown_jewels": crown_jewels,
        "analysis_done": state.get("crown_jewel_analysis_done", False),
    }


def _cockpit_host(domain: str = "", url: str = "") -> str:
    h = str(domain or "").strip().lower()
    if h:
        return h
    u = str(url or "").strip().lower()
    if not u:
        return ""
    import re as _re
    return _re.sub(r"^[a-z]+://", "", u).split("/", 1)[0].split(":", 1)[0]


@router.get("/cockpit")
def get_cockpit(
    scan_id: int | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Payload consolidado do Cockpit RedTeam — escopado por scan, 100% dado real.

    Junta: lista de scans (dropdown), score/grade/tendência, contagem por
    severidade, KPIs, heatmap superfície×severidade, joias da coroa e a fila de
    achados enriquecida com EPSS (FIRST.org), técnica MITRE e flag de joia.
    """
    from app.models.models import ScanJob, Finding
    from app.services.cockpit_heatmap import build_heatmap
    from app.services.epss_service import get_epss_scores
    from app.services.attack_graph import _classify_finding, CAPABILITY_TO_ATTACK
    from app.services.risk_service import _log_exposure_penalty
    # _score_to_grade é definido neste módulo (linha ~393)

    scan_rows = (
        db.query(ScanJob)
        .filter(ScanJob.owner_id == current_user.id)
        .order_by(ScanJob.id.desc())
        .limit(50)
        .all()
    )
    scans_dropdown = [
        {
            "id": s.id,
            "target_query": s.target_query,
            "status": s.status,
            "current_step": s.current_step,
            "mission_progress": int(s.mission_progress or 0),
        }
        for s in scan_rows
    ]

    selected = None
    if scan_id is not None:
        selected = next((s for s in scan_rows if s.id == scan_id), None) or (
            db.query(ScanJob)
            .filter(ScanJob.id == scan_id, ScanJob.owner_id == current_user.id)
            .first()
        )
    if selected is None:
        selected = scan_rows[0] if scan_rows else None

    if selected is None:
        return {
            "scan": None,
            "scans": scans_dropdown,
            "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "score": {"value": 0, "grade": "F", "trend": [], "delta": 0},
            "kpis": {},
            "heatmap": build_heatmap([]),
            "crown_jewels": [],
            "findings": [],
        }

    findings = (
        db.query(Finding)
        .filter(Finding.scan_job_id == selected.id, Finding.is_false_positive.is_(False))
        .all()
    )

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        k = str(f.severity or "").lower()
        if k in sev:
            sev[k] += 1

    score = max(0.0, round(100.0 - _log_exposure_penalty(sev["critical"], sev["high"], sev["medium"], sev["low"]), 1))
    grade = _score_to_grade(score)

    state = dict(selected.state_data or {})
    crown = state.get("crown_jewels", []) or []
    jewel_hosts = set()
    for j in crown:
        t = j.get("target") or j.get("asset") or j.get("host") or ""
        h = _cockpit_host(domain=str(t))
        if h:
            jewel_hosts.add(h)

    heatmap = build_heatmap(findings)

    cves = [f.cve for f in findings if f.cve]
    epss_map = get_epss_scores(cves)

    items = []
    jewels_with_findings = set()
    exposed_hosts = set()
    for f in findings:
        host = _cockpit_host(domain=str(f.domain or ""), url=str(f.url or ""))
        if host:
            exposed_hosts.add(host)
        caps = _classify_finding(f)
        mitre = []
        seen_t = set()
        for c in caps:
            for tech in CAPABILITY_TO_ATTACK.get(c.get("capability", ""), []):
                if tech["id"] not in seen_t:
                    seen_t.add(tech["id"])
                    mitre.append(tech)
        is_jewel = host in jewel_hosts
        if is_jewel:
            jewels_with_findings.add(host)
        ep = epss_map.get(str(f.cve or "").upper()) if f.cve else None
        items.append({
            "id": f"SK-{f.id}",
            "finding_id": f.id,
            "title": f.title,
            "target": host or (f.domain or ""),
            "severity": str(f.severity or "info").lower(),
            "cve": f.cve or None,
            "cvss": f.cvss,
            "epss": (ep["epss"] if ep else None),
            "epss_percentile": (ep["percentile"] if ep else None),
            "mitre": mitre,
            "status": f.verification_status or "hypothesis",
            "is_jewel": is_jewel,
            "tool": f.tool or None,
            "recommendation": f.recommendation or None,
            "description": (f.details or {}).get("description") or (f.details or {}).get("evidence") or None,
        })

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items.sort(key=lambda x: (
        sev_rank.get(x["severity"], 5),
        -(x["cvss"] or 0),
        -((x["epss"] or 0)),
    ))

    # Enriquece joias da coroa com achados reais por host (sem residual)
    jewel_counts: dict[str, dict] = {}
    for it in items:
        h = it["target"]
        if h in jewel_hosts:
            jc = jewel_counts.setdefault(h, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0})
            s = it["severity"]
            if s in jc:
                jc[s] += 1
            jc["total"] += 1
    crown_enriched = []
    for j in crown:
        t = j.get("target") or j.get("asset") or j.get("host") or ""
        h = _cockpit_host(domain=str(t))
        c = jewel_counts.get(h, {})
        crown_enriched.append({
            **j,
            "host": h,
            "findings_total": c.get("total", 0),
            "critical": c.get("critical", 0),
            "high": c.get("high", 0),
            "medium": c.get("medium", 0),
            "low": c.get("low", 0),
        })
    # ordena por criticidade observada (críticos, depois altos, depois total)
    crown_enriched.sort(key=lambda x: (-x["critical"], -x["high"], -x["findings_total"]))

    # Tendência: score dos scans recentes do mesmo alvo (dado real por scan)
    same_target_ids = [s.id for s in scan_rows if s.target_query == selected.target_query][:8]
    same_target_ids = list(reversed(same_target_ids))  # cronológico
    trend = []
    if same_target_ids:
        rows = (
            db.query(Finding.scan_job_id, Finding.severity, func.count(Finding.id))
            .filter(Finding.scan_job_id.in_(same_target_ids), Finding.is_false_positive.is_(False))
            .group_by(Finding.scan_job_id, Finding.severity)
            .all()
        )
        per_scan = {sid: {"critical": 0, "high": 0, "medium": 0, "low": 0} for sid in same_target_ids}
        for sid, s_sev, cnt in rows:
            kk = str(s_sev or "").lower()
            if kk in per_scan.get(sid, {}):
                per_scan[sid][kk] = cnt
        for sid in same_target_ids:
            c = per_scan[sid]
            sc = max(0.0, round(100.0 - _log_exposure_penalty(c["critical"], c["high"], c["medium"], c["low"]), 1))
            trend.append({"scan_id": sid, "rating_score": sc})
    delta = round(trend[-1]["rating_score"] - trend[0]["rating_score"], 1) if len(trend) >= 2 else 0.0

    kpis = {
        "critical_high": sev["critical"] + sev["high"],
        "findings_open": len(findings),
        "jewels_total": len(crown),
        "jewels_at_risk": len(jewels_with_findings),
        "assets_exposed": len(exposed_hosts),
        "assets_total": int(state.get("subdomain_count") or len(exposed_hosts)),
    }

    return {
        "scan": {
            "id": selected.id,
            "target_query": selected.target_query,
            "status": selected.status,
            "current_step": selected.current_step,
            "mission_progress": int(selected.mission_progress or 0),
            "created_at": selected.created_at.isoformat() if selected.created_at else None,
        },
        "scans": scans_dropdown,
        "severity": sev,
        "score": {"value": score, "grade": grade, "trend": trend, "delta": delta},
        "kpis": kpis,
        "heatmap": heatmap,
        "crown_jewels": crown_enriched,
        "findings": items,
    }


@router.get("/scans/{scan_id}/osint")
def get_osint_results(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retorna os resultados OSINT para o scan.

    Prioridade:
    1. state_data["osint_phase_zero"] (LangGraph path)
    2. Findings de P18 (work-queue path) sintetizados no mesmo formato
    3. 404 apenas se P18 nunca rodou para este scan
    """
    from app.models.models import Finding, ScanJob, ScanWorkItem
    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.owner_id == current_user.id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    state = dict(job.state_data or {})
    osint = state.get("osint_phase_zero")
    if osint:
        return {"scan_id": scan_id, "osint": osint, "source": "phase_zero"}

    # ── Fallback: synthesize from P18 work-queue results ─────────────────────
    p18_items = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.phase_id == "P18",
        )
        .all()
    )
    if not p18_items:
        raise HTTPException(status_code=404, detail="OSINT não executado ainda.")

    p18_tools = {str(i.tool_name or "") for i in p18_items}
    p18_statuses = {str(i.status or "") for i in p18_items}
    terminal = {"completed", "done", "skipped", "failed", "timeout"}
    p18_done = bool(p18_statuses & terminal)
    p18_pending = bool(p18_statuses - terminal)

    if not p18_done and p18_pending:
        raise HTTPException(status_code=404, detail="OSINT ainda em execução.")

    # Build a compatible summary from P18 findings
    p18_findings = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == scan_id,
            Finding.tool.in_(list(p18_tools)),
        )
        .all()
    )

    shodan_hosts = [f for f in p18_findings if str(f.tool or "") == "shodan-cli"]
    harvest_emails = [f for f in p18_findings if str(f.tool or "") == "theharvester"]
    leaks = [f for f in p18_findings if str(f.tool or "") in {"gitleaks", "trufflehog"}]

    shodan_asn: dict = {}
    if shodan_hosts:
        details = dict(shodan_hosts[0].details or {})
        shodan_asn = {
            "asn": details.get("asn", ""),
            "total_hosts_in_asn": len(shodan_hosts),
            "skipped": False,
        }

    emails_breached = len({str(f.subdomain or f.url or "") for f in harvest_emails if f.severity not in {"info"}})
    hibp: dict = {
        "emails_breached": emails_breached,
        "skipped": len(harvest_emails) == 0,
    }

    osint_synthesized = {
        "source": "work_queue_p18",
        "tools_ran": sorted(p18_tools),
        "findings_count": len(p18_findings),
        "shodan_asn": shodan_asn if shodan_asn else {"skipped": True},
        "hibp": hibp,
        "github_dork": {"skipped": True, "results_count": 0},
        "leaks_count": len(leaks),
    }
    return {"scan_id": scan_id, "osint": osint_synthesized, "source": "work_queue_p18"}


# ── Evidence gate stats (T1 / M3) ─────────────────────────────────────────────
@router.get("/findings/verification-stats")
def get_verification_stats(
    target: str | None = None,
    scan_id: int | None = Query(default=None, ge=1),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retorna contagem de findings por verification_status (Evidence Gate)."""
    from sqlalchemy import func as sql_func
    query = _authorized_finding_query(db, current_user)
    if target:
        query = query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))
    if scan_id:
        query = query.filter(Finding.scan_job_id == scan_id)

    # Count per verification_status — NULL counts as "none"
    rows = (
        db.query(
            Finding.verification_status,
            sql_func.count(Finding.id).label("cnt"),
        )
        .join(ScanJob, ScanJob.id == Finding.scan_job_id)
        .filter(ScanJob.owner_id == current_user.id)
        .group_by(Finding.verification_status)
        .all()
    )
    counts = {"confirmed": 0, "candidate": 0, "hypothesis": 0, "refuted": 0, "none": 0}
    total = 0
    for vstatus, cnt in rows:
        key = str(vstatus or "none").lower()
        if key in counts:
            counts[key] += int(cnt)
        else:
            counts["none"] += int(cnt)
        total += int(cnt)
    return {"counts": counts, "total": total}


@router.post("/scans/{scan_id}/verify-business-logic")
def verify_business_logic_endpoint(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Testes de lógica de negócio (tampering de preço/qtd, bypass de fluxo, reuso de cupom)."""
    from app.services.business_logic_probe import run_business_logic_for_scan
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    return run_business_logic_for_scan(db, job)


@router.post("/scans/{scan_id}/analyze-js")
def analyze_js_endpoint(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Análise estática de JS: endpoints, params, sinks (eval/proto), segredos."""
    from app.services.js_analyzer import run_js_analysis_for_scan
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    return run_js_analysis_for_scan(db, job)


@router.post("/scans/{scan_id}/verify-api-exposure")
def verify_api_exposure_endpoint(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Excessive Data Exposure (API3) + risco de Mass Assignment (API6)."""
    from app.services.api_probe import run_api_probe_for_scan
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    return run_api_probe_for_scan(db, job)


@router.post("/scans/{scan_id}/verify-nosql")
def verify_nosql_endpoint(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Roda o teste de NoSQL injection (injeção de operador read-only)."""
    from app.services.nosql_probe import run_nosql_for_scan
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    return run_nosql_for_scan(db, job)


@router.post("/scans/{scan_id}/verify-bola")
def verify_bola_endpoint(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Roda o teste autenticado de BOLA/BFLA (acesso cruzado de objeto/função)."""
    from app.services.bola_probe import run_bola_for_scan
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    return run_bola_for_scan(db, job)


@router.get("/scans/{scan_id}/attack-navigator")
def get_attack_navigator(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Camada oficial do MITRE ATT&CK Navigator com as técnicas observadas no scan."""
    from app.services.vuln_family import classify_family as _cf_nav
    from app.services.framework_mapping import build_navigator_layer
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    fams = []
    for f in db.query(Finding).filter(Finding.scan_job_id == scan_id).all():
        d = dict(f.details or {})
        fams.append(_cf_nav(title=f.title, tool=f.tool, owasp=str(d.get("owasp_category") or ""),
                            cve=f.cve, learning_family=(d.get("learning_source") or {}).get("vuln_family")))
    return build_navigator_layer(str(job.target_query or f"scan-{scan_id}"), fams)


@router.get("/scans/{scan_id}/attack-paths")
def get_attack_paths(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Caminhos de ataque rumo às joias da coroa (objetivo), ordenados por tática ATT&CK."""
    from app.services.attack_path import build_attack_paths
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    return build_attack_paths(db, scan_id, job=job)


@router.get("/scans/{scan_id}/methodology-coverage")
def get_methodology_coverage(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Scorecard de cobertura de metodologia (classes testadas vs catálogo)."""
    from app.services.methodology import compute_methodology_coverage
    return compute_methodology_coverage(db, scan_id)


@router.get("/platform/health")
def get_platform_health_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Saúde de toda a plataforma (visão Docker): status/health por container,
    alerta quando algo está fora e último log/erro para validar."""
    from app.services.platform_health import get_platform_health
    return get_platform_health(db)


@router.get("/guardrails")
def get_guardrails(
    current_user: User = Depends(get_current_user),
):
    """Política de guardrail — ataques de impacto desativados/restritos.

    Fonte única da verdade: app.services.guardrail_policy. A mesma deny-list
    é aplicada na execução (MCP + backend) para que nenhum ataque destrutivo
    seja executado de fato.
    """
    from app.services.guardrail_policy import guardrail_policy_payload

    return guardrail_policy_payload()
