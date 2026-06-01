import os
import random
import re
import threading
import time
import json
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.core.config import settings
from app.graph.workflow import build_graph, initial_state
from app.models.models import AppSetting, Asset, ExecutedToolRun, Finding, ScanJob, ScanLog, ScheduledScan, Vulnerability, WorkerHeartbeat, ScanAuditLog
from app.services.ai_recommendation_service import generate_portuguese_recommendations
from app.services.audit_service import log_audit
from app.services.cyber_autoagent_alignment import evaluate_execution_quality
from app.services.cve_enrichment_service import enrichment_service
from app.services.llm_risk_service import parse_scan_llm_risk_config, run_llm_risk_assessment
from app.services.tool_adapters import run_tool_execution
from app.workers.celery_app import celery
from app.workers.worker_groups import (
    UNIT_WORKER_GROUPS,
    SCHEDULED_WORKER_GROUPS,
    SCAN_UNIT_QUEUE,
    SCAN_SCHEDULED_QUEUE,
    SCAN_PARALLEL_QUEUE,
    ScanMode,
    find_group_by_tool,
    get_worker_agent_profile,
)


SCHEDULE_TARGETS_PER_SCAN = max(1, min(200, int(os.getenv("SCHEDULE_TARGETS_PER_SCAN", "25"))))

# ── FAIR pillar mapping (duplicated from risk_service to avoid circular import) ───
_TOOL_FAIR_PILLAR: dict[str, str] = {
    "naabu": "perimeter_resilience", "nmap": "perimeter_resilience",
    "nmap-vulscan": "patching_hygiene",
    "nikto": "patching_hygiene", "wapiti": "patching_hygiene",
    "wafw00f": "perimeter_resilience", "sslscan": "patching_hygiene",
    "shcheck": "patching_hygiene", "curl-headers": "patching_hygiene",
    "theharvester": "osint_exposure",
    "h8mail": "osint_exposure", "shodan-cli": "osint_exposure",
    "subjack": "osint_exposure", "whatweb": "perimeter_resilience",
    "trufflehog": "osint_exposure",
}

_SEV_CVSS_FALLBACK: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5,
}


def _get_or_create_asset(
    db: Session, owner_id: int, domain_or_ip: str, scan_job_id: int,
    port: int | None = None, protocol: str = "http",
) -> Asset:
    """Upsert an Asset row keyed on (owner_id, domain_or_ip, port)."""
    now = datetime.utcnow()
    q = db.query(Asset).filter(
        Asset.owner_id == owner_id,
        Asset.domain_or_ip == domain_or_ip,
    )
    if port is not None:
        q = q.filter(Asset.port == port)
    else:
        q = q.filter(Asset.port.is_(None))
    asset = q.first()
    if asset:
        asset.last_seen = now
        asset.scan_count = (asset.scan_count or 0) + 1
        asset.last_scan_id = scan_job_id
        asset.status = "active"
    else:
        asset = Asset(
            owner_id=owner_id,
            domain_or_ip=domain_or_ip,
            port=port,
            protocol=protocol,
            first_seen=now,
            last_seen=now,
            scan_count=1,
            last_scan_id=scan_job_id,
        )
        db.add(asset)
        db.flush()
    return asset


def _upsert_vulnerability(
    db: Session, asset: Asset, finding: Finding,
    tool: str, cve_id: str | None, cvss: float | None,
    severity: str, title: str,
) -> None:
    """Create or update a Vulnerability row linked to the given asset/finding."""
    import math

    now = datetime.utcnow()
    fair_pillar = _TOOL_FAIR_PILLAR.get(tool, "patching_hygiene")
    cvss_score = cvss or _SEV_CVSS_FALLBACK.get(severity, 5.0)

    existing = db.query(Vulnerability).filter(
        Vulnerability.asset_id == asset.id,
        Vulnerability.tool_source == tool,
        Vulnerability.title == title[:255],
    ).first()

    if existing:
        existing.last_detected = now
        existing.detection_count = (existing.detection_count or 1) + 1
        existing.finding_id = finding.id
        existing.remediated_at = None
        days_open = max(0, (now - existing.first_detected).days)
        existing.age_factor = round(1 + math.log10(days_open + 1), 3)
        existing.ra_score = round(cvss_score * existing.age_factor, 2)
        if cve_id:
            existing.cve_id = cve_id
        if cvss is not None:
            existing.cvss_score = cvss
    else:
        db.add(Vulnerability(
            asset_id=asset.id,
            finding_id=finding.id,
            tool_source=tool[:100],
            cve_id=cve_id,
            severity=severity,
            cvss_score=cvss_score,
            title=title[:255],
            first_detected=now,
            last_detected=now,
            fair_pillar=fair_pillar,
            age_factor=1.0,
            ra_score=round(cvss_score * 1.0, 2),
        ))

def _chunk_targets(targets: list[str], chunk_size: int) -> list[list[str]]:
    return [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]


def _get_scan_retry_policy(db: Session, owner_id: int) -> tuple[bool, int, int]:
    defaults = {
        "scan_retry_enabled": "true",
        "scan_retry_max_attempts": "3",
        "scan_retry_delay_seconds": "10",
    }

    rows = (
        db.query(AppSetting.key, AppSetting.value)
        .filter(
            AppSetting.owner_id == owner_id,
            AppSetting.key.in_(list(defaults.keys())),
        )
        .all()
    )
    values = {k: v for k, v in rows}

    def _as_int(raw: str, default: int, min_v: int, max_v: int) -> int:
        try:
            return max(min_v, min(max_v, int(raw)))
        except Exception:
            return default

    retry_enabled = str(values.get("scan_retry_enabled", defaults["scan_retry_enabled"]).strip()).lower() == "true"
    max_attempts = _as_int(str(values.get("scan_retry_max_attempts", defaults["scan_retry_max_attempts"])), 3, 1, 10)
    delay_seconds = _as_int(str(values.get("scan_retry_delay_seconds", defaults["scan_retry_delay_seconds"])), 10, 5, 3600)

    return retry_enabled, max_attempts, delay_seconds


def _progress_from_state(final_state: dict) -> tuple[int, dict]:
    mission_items = final_state.get("mission_items") or []
    total_steps = max(1, len(mission_items))
    metrics = final_state.get("mission_metrics") or {}
    steps_done = int(metrics.get("steps_done", 0) or 0)
    steps_success = int(metrics.get("steps_success", 0) or 0)
    tools_attempted = int(metrics.get("tools_attempted", 0) or 0)
    tools_success = int(metrics.get("tools_success", 0) or 0)

    step_ratio = min(1.0, steps_done / total_steps)
    quality_ratio = (tools_success / tools_attempted) if tools_attempted > 0 else 0.0
    progress = int(round((step_ratio * 0.85 + quality_ratio * 0.15) * 100))
    return progress, {
        "steps_done": steps_done,
        "steps_success": steps_success,
        "tools_attempted": tools_attempted,
        "tools_success": tools_success,
        "total_steps": total_steps,
    }


def _touch_worker_heartbeat(
    db: Session,
    *,
    scan_mode: ScanMode,
    status: str,
    scan_id: int | None = None,
    task_name: str | None = None,
) -> WorkerHeartbeat:
    worker_name = os.getenv("WORKER_NAME") or os.getenv("HOSTNAME") or "unknown-worker"
    hb = db.query(WorkerHeartbeat).filter(WorkerHeartbeat.worker_name == worker_name).first()
    if hb is None:
        hb = WorkerHeartbeat(worker_name=worker_name)

    hb.mode = scan_mode
    hb.status = status
    hb.current_scan_id = scan_id
    hb.last_task_name = task_name
    hb.last_seen_at = datetime.utcnow()
    db.add(hb)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        hb = db.query(WorkerHeartbeat).filter(WorkerHeartbeat.worker_name == worker_name).first()
        if hb is None:
            raise
        hb.mode = scan_mode
        hb.status = status
        hb.current_scan_id = scan_id
        hb.last_task_name = task_name
        hb.last_seen_at = datetime.utcnow()
        db.add(hb)
        db.flush()
    return hb


@celery.task(name="worker.heartbeat")
def worker_heartbeat() -> dict[str, Any]:
    """Heartbeat periódico de worker para health-check operacional."""
    db: Session = SessionLocal()
    try:
        hb = _touch_worker_heartbeat(db, scan_mode="unit", status="alive")
        db.commit()
        return {
            "ok": True,
            "worker_name": hb.worker_name,
            "status": hb.status,
            "last_seen_at": hb.last_seen_at.isoformat() if hb.last_seen_at else None,
        }
    except Exception as exc:
        db.rollback()
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()


# Executado a cada minuto pelo Celery Beat (já existente)
@celery.task(name="scheduler.tick", queue=SCAN_SCHEDULED_QUEUE)

def scheduler_tick():
    from zoneinfo import ZoneInfo

    tz = ZoneInfo("America/Sao_Paulo")
    now = datetime.now(tz)

    current_hhmm = now.strftime("%H:%M")
    current_dow = now.strftime("%A").lower()
    current_dom = now.day
    current_hour = now.hour
    current_minute = now.minute

    db: Session = SessionLocal()
    try:
        schedules = db.query(ScheduledScan).filter(ScheduledScan.enabled.is_(True)).all()
        fired = 0

        for sched in schedules:
            run_time = str(sched.run_time or "00:00").strip()
            try:
                run_hour_str, run_minute_str = run_time.split(":", 1)
                run_hour = int(run_hour_str)
                run_minute = int(run_minute_str)
                if not (0 <= run_hour <= 23 and 0 <= run_minute <= 59):
                    continue
            except Exception:
                continue

            # frequência
            freq = (sched.frequency or "daily").lower()

            # horário para frequências diárias/semanais/mensais
            if freq in {"daily", "weekly", "monthly"} and run_time != current_hhmm:
                continue

            # horário para frequências de intervalo (3h/6h/12h)
            if freq in {"every_3_hours", "every_6_hours", "every_12_hours"}:
                interval = {
                    "every_3_hours": 3,
                    "every_6_hours": 6,
                    "every_12_hours": 12,
                }.get(freq, 0)
                if interval <= 0:
                    continue
                # Usa run_time como âncora do minuto e da fase de hora
                if current_minute != run_minute:
                    continue
                if ((current_hour - run_hour) % interval) != 0:
                    continue

            if freq == "weekly" and (sched.day_of_week or "").lower() != current_dow:
                continue

            if freq == "monthly" and sched.day_of_month != current_dom:
                continue

            # idempotência (não rodar 2x no mesmo minuto)
            if sched.last_run_at:
                from zoneinfo import ZoneInfo as _ZI
                slot_start = now.replace(second=0, microsecond=0)
                last_run_local = sched.last_run_at.replace(tzinfo=_ZI("UTC")).astimezone(tz)
                if last_run_local >= slot_start:
                    continue

            # targets
            raw_targets = [
                t.strip()
                for t in sched.targets_text.replace(",", ";").split(";")
                if t.strip()
            ]

            if not raw_targets:
                continue

            job = ScanJob(
                    owner_id=sched.owner_id,
                    access_group_id=sched.access_group_id,
                    target_query="; ".join(raw_targets),
                    status="pending",
                    mode="scheduled",
                    compliance_status="approved",
                    current_step="Aguardando worker",
                    state_data={},
                )

            db.add(job)
            db.flush()

            db.add(
                ScanLog(
                    scan_job_id=job.id,
                    source="scheduler",
                    level="INFO",
                    message=(
                        f"Scan agendado disparado automaticamente | "
                        f"schedule_id={sched.id} | freq={freq} | "
                        f"targets={len(raw_targets)} | celery_batch_size={SCHEDULE_TARGETS_PER_SCAN}"
                    ),
                )
            )

            # marca execução
            sched.last_run_at = datetime.utcnow()
            db.add(sched)
            db.commit()

            celery.send_task(
                "run_scan_job_scheduled",
                kwargs={"scan_id": job.id},
                queue=SCAN_SCHEDULED_QUEUE,
            )

            fired += 1

        return {
            "ok": True,
            "checked": len(schedules),
            "fired": fired,
            "slot": current_hhmm,
        }

    finally:
        db.close()


# Scheduler separado
@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(
        30.0,
        worker_heartbeat.s(),
        name="worker-heartbeat"
    )


def _format_mission_progress(state_data: dict, current_step: str) -> str:
    """
    Formata um resumo visual das missões mostrando quais foram completadas,
    qual está rodando e quais faltam.
    
    Retorna string formatada tipo:
      ✅ 1. Reconhecimento (2m 30s)
      ▶️ 2. Analise de Vulnerabilidade (1m 15s em andamento)
      ⏳ 3. OSINT
    """
    mission_items = state_data.get("mission_items", [
        "1. Reconhecimento",
        "2. OSINT",
        "3. Analise de Vulnerabilidade"
    ])
    mission_index = state_data.get("mission_index", 0)
    node_history = state_data.get("node_history", [])
    activity_metrics = state_data.get("activity_metrics", [])
    
    # Rastreia tempo de início de cada missão pelos logs de atividade
    mission_start_times = {}
    for metric in activity_metrics:
        if isinstance(metric, dict):
            node = metric.get("node", "")
            timestamp = metric.get("timestamp")
            # Identifica qual missão o nó pertence
            for idx, mission_name in enumerate(mission_items):
                mission_base = mission_name.split(". ")[1].lower() if ". " in mission_name else ""
                if mission_base and mission_base in node.lower():
                    if idx not in mission_start_times and timestamp:
                        mission_start_times[idx] = timestamp
                    break
    
    lines = []
    current_time = datetime.utcnow()
    
    for idx, mission_name in enumerate(mission_items):
        if idx < mission_index:
            # Missão já completada
            start_time = mission_start_times.get(idx)
            end_time = mission_start_times.get(idx + 1, current_time)
            
            if start_time and isinstance(start_time, (int, float)):
                duration_sec = int((end_time if isinstance(end_time, (int, float)) else time.time()) - start_time)
                duration_str = f"{duration_sec // 60}m {duration_sec % 60}s"
                lines.append(f"  ✅ {mission_name} ({duration_str})")
            else:
                lines.append(f"  ✅ {mission_name}")
                
        elif idx == mission_index:
            # Missão em execução
            start_time = mission_start_times.get(idx)
            if start_time and isinstance(start_time, (int, float)):
                elapsed_sec = int(time.time() - start_time)
                elapsed_str = f"{elapsed_sec // 60}m {elapsed_sec % 60}s"
                lines.append(f"  ▶️  {mission_name} ({elapsed_str} em andamento)")
            else:
                lines.append(f"  ▶️  {mission_name} (iniciando...)")
            lines.append(f"     └─ Etapa: {current_step}")
            
        else:
            # Missão ainda não iniciada
            lines.append(f"  ⏳ {mission_name}")
    
    return "\n".join(lines)


def _start_scan_progress_pulse(scan_id: int, scan_mode: ScanMode, interval_seconds: int = 20):
    """
    Emite logs periódicos durante execução longa para evitar sensação de travamento.
    Mostra progresso detalhado das missões (concluidas, em execução, pendentes).
    """
    stop_event = threading.Event()
    started_at = time.time()

    def _pulse_loop():
        last_state_data = {}
        
        while not stop_event.wait(interval_seconds):
            pulse_db: Session = SessionLocal()
            try:
                job = pulse_db.query(ScanJob).filter(ScanJob.id == scan_id).first()
                if not job:
                    break

                status = str(job.status or "").lower()
                if status in {"completed", "failed", "blocked", "stopped"}:
                    break

                elapsed = int(max(0, time.time() - started_at))
                current_step = str(job.current_step or "em execucao")
                state_data = job.state_data or {}

                # ── Propaga mission_index / current_step do state para o job ──
                mi = state_data.get("mission_index")
                mission_items = state_data.get("mission_items") or []
                if mi is not None and isinstance(mi, int) and mission_items:
                    step_label = mission_items[mi] if mi < len(mission_items) else mission_items[-1]
                    if job.current_step != step_label:
                        job.current_step = step_label
                        current_step = step_label
                    total = max(1, len(mission_items))
                    phase_pct = int(round(min(mi, total) / total * 100))

                    # Subdomain-coverage progress from snapshot
                    cov = state_data.get("subdomain_coverage") or {}
                    active_total = max(1, int(cov.get("active_total") or 1))
                    scanned_count = int(cov.get("scanned") or 0)
                    total_disc = int(cov.get("total_discovered") or 0)
                    if total_disc > 0:
                        subdomain_pct = int(round(min(scanned_count, active_total) / active_total * 100))
                        raw_pct = max(phase_pct, subdomain_pct)
                    else:
                        raw_pct = phase_pct
                    job.mission_progress = min(99, raw_pct)
                
                # Emite log simples de progresso a cada pulse
                pulse_db.add(
                    ScanLog(
                        scan_job_id=scan_id,
                        source="worker.progress",
                        level="INFO",
                        message=(
                            f"Execucao [{scan_mode}] em andamento ({elapsed}s) | "
                            f"etapa atual: {current_step}"
                        ),
                    )
                )
                
                # A cada 60s (3 pulses), emite um resumo detalhado das missões
                if elapsed % 60 == 0 and elapsed > 0:
                    mission_summary = _format_mission_progress(state_data, current_step)
                    pulse_db.add(
                        ScanLog(
                            scan_job_id=scan_id,
                            source="worker.progress_detail",
                            level="INFO",
                            message=f"PROGRESSO DAS MISSOES (tempo total: {elapsed}s):\n{mission_summary}",
                        )
                    )
                
                pulse_db.commit()
                last_state_data = state_data
            except Exception as e:
                pulse_db.rollback()
            finally:
                pulse_db.close()

    thread = threading.Thread(target=_pulse_loop, name=f"scan-progress-{scan_id}", daemon=True)
    thread.start()

    def _stop():
        stop_event.set()
        thread.join(timeout=1.0)

    return _stop


# ──────────────────────────────────────────────────────────────────────────────
# Tasks de ferramentas — UNITARIOS (scan.unit / worker.unit.*)
# ──────────────────────────────────────────────────────────────────────────────

def _worker_result(
    worker_group: str,
    tool: str,
    target: str,
    scan_mode: ScanMode,
    params: dict | None = None,
) -> dict[str, Any]:
    """Executa ferramenta preservando contrato legado de worker com identidade de agente."""
    mode: ScanMode = "scheduled" if str(scan_mode).strip().lower() == "scheduled" else "unit"
    agent = get_worker_agent_profile(worker_group, mode=mode)
    knowledge_context: dict[str, Any] = {}
    try:
        from app.services.agent_context_service import build_worker_knowledge_context

        knowledge_bundle = build_worker_knowledge_context(
            worker_group=worker_group,
            skill=str(agent.get("agent_id") or worker_group),
            phase=",".join(list(agent.get("phases") or [])[:3]),
            target=target,
            candidate_tools=[tool],
            mode=mode,
            top_k=3,
        )
        knowledge_context = dict(knowledge_bundle.get("prompt_context") or {})
    except Exception:
        knowledge_context = {}

    result = run_tool_execution(
        tool_name=tool,
        target=target,
        scan_mode=mode,
        scan_id=(params or {}).get("scan_id") if isinstance(params, dict) else None,
    )
    normalized = dict(result) if isinstance(result, dict) else {}

    normalized.setdefault("tool", tool)
    normalized.setdefault("target", target)
    normalized.setdefault("scan_mode", mode)
    normalized.setdefault("worker_group", worker_group)
    normalized.setdefault("worker_role", "operational_agent")
    normalized.setdefault("source_worker", worker_group)
    normalized.setdefault("source_agent_id", agent.get("agent_id"))
    normalized.setdefault("source_agent_name", agent.get("agent_name"))
    normalized.setdefault("worker_mission", agent.get("mission"))
    normalized.setdefault("worker_techniques", list(agent.get("techniques") or []))
    normalized.setdefault("agent_profile", {
        "agent_id": agent.get("agent_id"),
        "agent_name": agent.get("agent_name"),
        "purpose": agent.get("purpose"),
        "mission": agent.get("mission"),
        "techniques": list(agent.get("techniques") or []),
        "phases": list(agent.get("phases") or []),
        "evidence_focus": list(agent.get("evidence_focus") or []),
        "decision_rules": list(agent.get("decision_rules") or []),
        "tools": list(agent.get("tools") or []),
        "skill_context": dict(agent.get("skill_context") or {}),
        "operational_sequence": list(agent.get("operational_sequence") or []),
    })
    if knowledge_context:
        normalized.setdefault("skill_memory", knowledge_context)
    if params:
        normalized.setdefault("runtime_params", dict(params))

    return normalized


@celery.task(name="worker.unit.scope_validation.execute", queue="worker.unit.scope_validation")
def unit_scope_validation_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("scope_validation", tool, target, "unit", params)


@celery.task(name="worker.unit.reconnaissance.execute", queue="worker.unit.reconnaissance")
def unit_reconnaissance_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("reconnaissance", tool, target, "unit", params)


@celery.task(name="worker.unit.weaponization.execute", queue="worker.unit.weaponization")
def unit_weaponization_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("weaponization", tool, target, "unit", params)


@celery.task(name="worker.unit.delivery.execute", queue="worker.unit.delivery")
def unit_delivery_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("delivery", tool, target, "unit", params)


@celery.task(name="worker.unit.exploitation.execute", queue="worker.unit.exploitation")
def unit_exploitation_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("exploitation", tool, target, "unit", params)


@celery.task(name="worker.unit.installation.execute", queue="worker.unit.installation")
def unit_installation_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("installation", tool, target, "unit", params)


@celery.task(name="worker.unit.command_control.execute", queue="worker.unit.command_control")
def unit_command_control_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("command_control", tool, target, "unit", params)


@celery.task(name="worker.unit.actions_on_objectives.execute", queue="worker.unit.actions_on_objectives")
def unit_actions_on_objectives_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("actions_on_objectives", tool, target, "unit", params)


@celery.task(name="worker.unit.reporting.execute", queue="worker.unit.reporting")
def unit_reporting_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("reporting", tool, target, "unit", params)


@celery.task(name="worker.unit.reconhecimento.execute", queue="worker.unit.reconhecimento")
def unit_reconhecimento_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("reconhecimento", tool, target, "unit", params)


@celery.task(name="worker.unit.analise_vulnerabilidade.execute", queue="worker.unit.analise_vulnerabilidade")
def unit_analise_vulnerabilidade_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("analise_vulnerabilidade", tool, target, "unit", params)


@celery.task(name="worker.unit.osint.execute", queue="worker.unit.osint")
def unit_osint_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("osint", tool, target, "unit", params)


@celery.task(name="worker.unit.dispatch", queue=SCAN_UNIT_QUEUE)
def unit_dispatch_tool(tool: str, target: str, params: dict | None = None):
    group = find_group_by_tool(tool, mode="unit")
    task_name = f"worker.unit.{group}.execute"
    return celery.send_task(task_name, kwargs={"tool": tool, "target": target, "params": params or {}}).id


# ──────────────────────────────────────────────────────────────────────────────
# Tasks de ferramentas — AGENDADOS (scan.scheduled / worker.scheduled.*)
# ──────────────────────────────────────────────────────────────────────────────

@celery.task(name="worker.scheduled.scope_validation.execute", queue="worker.scheduled.scope_validation")
def scheduled_scope_validation_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("scope_validation", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.reconnaissance.execute", queue="worker.scheduled.reconnaissance")
def scheduled_reconnaissance_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("reconnaissance", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.weaponization.execute", queue="worker.scheduled.weaponization")
def scheduled_weaponization_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("weaponization", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.delivery.execute", queue="worker.scheduled.delivery")
def scheduled_delivery_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("delivery", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.exploitation.execute", queue="worker.scheduled.exploitation")
def scheduled_exploitation_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("exploitation", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.installation.execute", queue="worker.scheduled.installation")
def scheduled_installation_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("installation", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.command_control.execute", queue="worker.scheduled.command_control")
def scheduled_command_control_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("command_control", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.actions_on_objectives.execute", queue="worker.scheduled.actions_on_objectives")
def scheduled_actions_on_objectives_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("actions_on_objectives", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.reporting.execute", queue="worker.scheduled.reporting")
def scheduled_reporting_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("reporting", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.reconhecimento.execute", queue="worker.scheduled.reconhecimento")
def scheduled_reconhecimento_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("reconhecimento", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.analise_vulnerabilidade.execute", queue="worker.scheduled.analise_vulnerabilidade")
def scheduled_analise_vulnerabilidade_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("analise_vulnerabilidade", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.osint.execute", queue="worker.scheduled.osint")
def scheduled_osint_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("osint", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.dispatch", queue=SCAN_SCHEDULED_QUEUE)
def scheduled_dispatch_tool(tool: str, target: str, params: dict | None = None):
    group = find_group_by_tool(tool, mode="scheduled")
    task_name = f"worker.scheduled.{group}.execute"
    return celery.send_task(task_name, kwargs={"tool": tool, "target": target, "params": params or {}}).id


# ──────────────────────────────────────────────────────────────────────────────
# Introspeccao
# ──────────────────────────────────────────────────────────────────────────────

@celery.task(name="worker.unit.groups")
def list_unit_worker_groups():
    return UNIT_WORKER_GROUPS


@celery.task(name="worker.scheduled.groups")
def list_scheduled_worker_groups():
    return SCHEDULED_WORKER_GROUPS


# ──────────────────────────────────────────────────────────────────────────────
# Nucleo de execucao — compartilhado pelos dois modos
# ──────────────────────────────────────────────────────────────────────────────

def _execute_scan(scan_id: int, scan_mode: ScanMode) -> dict:
    """Logica central de execucao do scan, usada por ambas as tasks."""
    db: Session = SessionLocal()
    stop_pulse = None
    try:
        _touch_worker_heartbeat(db, scan_mode=scan_mode, status="alive")
        db.commit()

        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            return {"ok": False, "error": "scan not found", "retryable": False}

        if job.status == "stopped":
            return {"ok": False, "error": "scan_stopped", "retryable": False}

        # Se já completou (via work_queue_dispatcher), não re-inicia
        if job.status == "completed":
            return {"ok": True, "error": "scan_already_completed", "retryable": False}

        job.status = "running"
        job.current_step = "Iniciando grafo"
        _touch_worker_heartbeat(
            db,
            scan_mode=scan_mode,
            status="busy",
            scan_id=job.id,
            task_name=f"run_scan_job_{scan_mode}",
        )
        db.add(ScanLog(
            scan_job_id=job.id,
            source="worker",
            level="INFO",
            message=f"Execucao [{scan_mode}] iniciada",
        ))
        db.add(ScanLog(
            scan_job_id=job.id,
            source="worker",
            level="INFO",
            message="Execucao em andamento: ferramentas de varredura podem levar varios minutos por alvo.",
        ))
        db.add(ScanLog(
            scan_job_id=job.id,
            source="worker.plan",
            level="INFO",
            message=(
                "PLANO DE EXECUCAO:\n"
                "  1️⃣  Strategic Planning - Definicao de hipoteses e contrato de evidencia\n"
                "  2️⃣  Attack Surface Mapping - Descoberta de ativos, exposicoes e contexto\n"
                "  3️⃣  Adversarial Validation - Testes orientados por hipotese e prioridade\n"
                "  4️⃣  Evidence Adjudication - Separacao de hipotese vs achado comprovado\n"
                "  5️⃣  Governance + Executive - FAIR/AGE e narrativa executiva\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "Acompanhe o progresso nos logs abaixo com source=worker.progress_detail"
            ),
        ))
        log_audit(
            db,
            event_type="scan.execution_started",
            message=f"Execucao do scan [{scan_mode}] iniciada",
            scan_job_id=job.id,
            metadata={"scan_mode": scan_mode},
        )
        db.commit()

        if settings.offensive_operator_enabled:
            from app.services.offensive_operator_runner import run_offensive_operator_scan

            result = run_offensive_operator_scan(db, job, scan_mode=scan_mode)
            _touch_worker_heartbeat(db, scan_mode=scan_mode, status="idle", scan_id=None, task_name=None)
            db.add(ScanLog(scan_job_id=job.id, source="worker", level="INFO", message="Execucao offensive_operator finalizada"))
            db.commit()
            return {"ok": job.status == "completed", "scan_id": job.id, "offensive_operator": True, "result": result}

        stop_pulse = _start_scan_progress_pulse(scan_id=job.id, scan_mode=scan_mode, interval_seconds=20)


        shodan_api_key = str(
            (
                db.query(AppSetting.value)
                .filter(AppSetting.owner_id == job.owner_id, AppSetting.key == "shodan_api_key")
                .scalar()
            ) or ""
        ).strip()
        if shodan_api_key:
            os.environ["SHODAN_API_KEY"] = shodan_api_key
        else:
            os.environ.pop("SHODAN_API_KEY", None)

        app = build_graph(mode=scan_mode)
        known_patterns = [
            row[0]
            for row in db.query(Finding.title).filter(Finding.title.isnot(None)).distinct().limit(500).all()
            if row and row[0]
        ]
        # ── Divide alvos em lotes de SCHEDULE_TARGETS_PER_SCAN para o Celery ─────
        all_targets = [t.strip() for t in job.target_query.replace(",", ";").split(";") if t.strip()]
        target_batches = _chunk_targets(all_targets, SCHEDULE_TARGETS_PER_SCAN) if len(all_targets) > 1 else [[job.target_query]]

        # Estado acumulado entre lotes (será o final_state ao fim do último lote)
        final_state: dict = {}
        trace_id = f"scan-{job.id}"

        for batch_index, batch in enumerate(target_batches, start=1):
            batch_target = "; ".join(batch)
            if len(target_batches) > 1:
                db.add(ScanLog(
                    scan_job_id=job.id,
                    source="worker.batch",
                    level="INFO",
                    message=f"Processando lote {batch_index}/{len(target_batches)} | {len(batch)} alvos",
                ))
                db.commit()

            state = initial_state(
                scan_id=job.id,
                owner_id=job.owner_id,
                target=batch_target,
                scan_mode=scan_mode,
                known_vulnerability_patterns=known_patterns,
            )
            if batch_index == 1:
                trace_id = str(state.get("trace_id") or trace_id)
                db.add(ScanLog(
                    scan_job_id=job.id,
                    source="worker.trace",
                    level="INFO",
                    message=f"trace_id={trace_id}",
                ))
                db.commit()

            # Propaga descobertas acumuladas de lotes anteriores
            if final_state:
                state["vulnerabilidades_encontradas"] = list(final_state.get("vulnerabilidades_encontradas", []))
                state["lista_ativos"] = list(final_state.get("lista_ativos", []))
                state["discovered_ports"] = list(final_state.get("discovered_ports", []))

            recursion_limit = max(160, len(state.get("mission_items", [])) * 20)
            batch_result = app.invoke(
                state,
                config={
                    "configurable": {"thread_id": f"scan-{job.id}-b{batch_index}"},
                    "recursion_limit": recursion_limit,
                },
            )

            # Mescla resultados acumulativos
            if final_state:
                merged_vulns = list(final_state.get("vulnerabilidades_encontradas", []))
                for v in batch_result.get("vulnerabilidades_encontradas", []):
                    if v not in merged_vulns:
                        merged_vulns.append(v)
                batch_result["vulnerabilidades_encontradas"] = merged_vulns

                merged_assets = list(final_state.get("lista_ativos", []))
                for a in batch_result.get("lista_ativos", []):
                    if a not in merged_assets:
                        merged_assets.append(a)
                batch_result["lista_ativos"] = merged_assets

                merged_ports = list(final_state.get("discovered_ports", []))
                for p in batch_result.get("discovered_ports", []):
                    if p not in merged_ports:
                        merged_ports.append(p)
                batch_result["discovered_ports"] = merged_ports

                merged_logs = list(final_state.get("logs_terminais", [])) + batch_result.get("logs_terminais", [])
                batch_result["logs_terminais"] = merged_logs

            final_state = batch_result

        final_state["trace_id"] = trace_id

        # Persiste dados de autonomy em ScanAuditLog
        _persist_autonomy_audit_log(db, job.id, final_state)

        llm_risk_cfg = parse_scan_llm_risk_config(job.state_data or {})
        if llm_risk_cfg.enabled:
            db.add(
                ScanLog(
                    scan_job_id=job.id,
                    source="llm-risk",
                    level="INFO",
                    message=(
                        "LLM Risk Assessment iniciado "
                        f"(profile={llm_risk_cfg.strategy_profile}, strategies={','.join(llm_risk_cfg.strategies)})"
                    ),
                )
            )

        agent_validation = evaluate_execution_quality(final_state)
        final_state["agent_validation"] = agent_validation
        db.add(
            ScanLog(
                scan_job_id=job.id,
                source="validation",
                level="INFO",
                message=(
                    "VALIDACAO CYBER AUTOAGENT: "
                    f"overall={agent_validation.get('scores', {}).get('overall', 0)} "
                    f"methodology={agent_validation.get('scores', {}).get('methodology', 0)} "
                    f"tooling={agent_validation.get('scores', {}).get('tooling', 0)} "
                    f"evidence={agent_validation.get('scores', {}).get('evidence', 0)} "
                    f"outcome={agent_validation.get('scores', {}).get('outcome', 0)}"
                ),
            )
        )
        if llm_risk_cfg.enabled:
            db.commit()
            llm_risk_report = run_llm_risk_assessment(llm_risk_cfg)
            final_state["llm_risk_report"] = llm_risk_report
            db.add(
                ScanLog(
                    scan_job_id=job.id,
                    source="llm-risk",
                    level="INFO",
                    message=(
                        "LLM Risk Assessment concluido "
                        f"(failed={llm_risk_report.get('failed_tests', 0)}/{llm_risk_report.get('total_tests', 0)}, "
                        f"risk={llm_risk_report.get('risk_level', '-')})"
                    ),
                )
            )

        db.refresh(job)
        if job.status == "stopped":
            db.add(ScanLog(scan_job_id=job.id, source="worker", level="WARNING", message="Execucao interrompida apos solicitacao de stop"))
            _touch_worker_heartbeat(db, scan_mode=scan_mode, status="idle", scan_id=None, task_name=None)
            db.commit()
            return {"ok": False, "error": "scan_stopped", "retryable": False}

        for line in final_state.get("logs_terminais", []):
            db.add(ScanLog(scan_job_id=job.id, source="graph", level="INFO", message=line))

        findings_to_persist = list(final_state.get("vulnerabilidades_encontradas", []))
        try:
            from app.services.vulnerability_learning_service import enrich_findings_with_accepted_learning

            findings_to_persist = enrich_findings_with_accepted_learning(findings_to_persist)
            final_state["vulnerabilidades_encontradas"] = findings_to_persist
        except Exception:
            pass

        seen_findings: set[tuple[str, str, str, str]] = set()
        for vuln in findings_to_persist:
            source_worker = vuln.get("source_worker", "vuln")
            details = dict(vuln)
            nested_details = details.get("details") if isinstance(details.get("details"), dict) else {}

            asset_hint = str(
                vuln.get("asset")
                or details.get("asset")
                or nested_details.get("asset")
                or nested_details.get("target")
                or ""
            ).strip().lower()
            port_hint = str(
                vuln.get("port")
                or details.get("port")
                or nested_details.get("port")
                or ""
            ).strip().lower()
            step_hint = str(
                vuln.get("step")
                or details.get("step")
                or nested_details.get("step")
                or ""
            ).strip().lower()
            tool_hint = str(
                vuln.get("tool")
                or details.get("tool")
                or nested_details.get("tool")
                or ""
            ).strip().lower()

            dedupe_key = (
                str(vuln.get("title") or "").strip().lower(),
                str(vuln.get("severity") or "low").strip().lower(),
                str(source_worker).strip().lower(),
                "|".join([asset_hint, port_hint, step_hint, tool_hint]),
            )
            if dedupe_key in seen_findings:
                continue
            seen_findings.add(dedupe_key)

            try:
                recommendations = generate_portuguese_recommendations(vuln, known_patterns=known_patterns)
            except Exception as rec_exc:
                db.add(
                    ScanLog(
                        scan_job_id=job.id,
                        source="ia",
                        level="WARNING",
                        message=f"Falha ao gerar recomendacao IA: {rec_exc}",
                    )
                )
                recommendations = {
                    "qwen_recomendacao_pt": "{\"resumo\":\"Recomendacao indisponivel temporariamente\",\"impacto\":\"Servico de IA indisponivel\",\"mitigacoes\":[\"Aplicar hardening baseline\",\"Executar reteste\"],\"prioridade\":\"media\",\"validacoes\":[\"Reexecutar analise\"]}",
                    "cloudcode_recomendacao_pt": "{\"resumo\":\"Recomendacao indisponivel temporariamente\",\"impacto\":\"Servico de IA indisponivel\",\"mitigacoes\":[\"Aplicar hardening baseline\",\"Executar reteste\"],\"prioridade\":\"media\",\"validacoes\":[\"Reexecutar analise\"]}",
                }
            details.update(recommendations)

            # Normaliza campos tecnicos no nivel raiz para facilitar consultas,
            # dashboard e geração de relatorio sem depender de parsing profundo.
            nested = details.get("details") if isinstance(details.get("details"), dict) else {}
            flattened_details = {**nested, **details}
            if "details" in flattened_details:
                flattened_details.pop("details", None)
            flattened_details["source_worker"] = source_worker
            flattened_details["scan_mode"] = scan_mode

            cve_id = enrichment_service.extract_cve(details, title=vuln.get("title"))
            if cve_id:
                details.update(enrichment_service.enrich(cve_id))
                flattened_details.update(enrichment_service.enrich(cve_id))

            # ── Extrai campos estruturados para colunas dedicadas ─────────────
            _cvss_raw = flattened_details.get("cvss") or details.get("cvss")
            _cvss = None
            if _cvss_raw is not None:
                try:
                    _cvss = float(_cvss_raw)
                except (TypeError, ValueError):
                    _cvss = None

            _tool_col = str(
                tool_hint
                or flattened_details.get("tool")
                or details.get("tool")
                or ""
            ).strip()[:100] or None

            _domain_col = str(
                asset_hint
                or flattened_details.get("asset")
                or flattened_details.get("target")
                or job.target_query
                or ""
            ).strip()[:255] or None

            _recommendation = str(
                flattened_details.get("qwen_recomendacao_pt")
                or flattened_details.get("cloudcode_recomendacao_pt")
                or ""
            ).strip() or None

            finding_obj = Finding(
                    scan_job_id=job.id,
                    title=vuln.get("title", "Potential issue"),
                    severity=vuln.get("severity", "low"),
                    cve=cve_id,
                    cvss=_cvss,
                    domain=_domain_col,
                    tool=_tool_col,
                    recommendation=_recommendation,
                    confidence_score=int(vuln.get("confidence_score", 50) or 50),
                    risk_score=vuln.get("risk_score", 1),
                    details=flattened_details,
                )
            db.add(finding_obj)

            # ── Persist Vulnerability + Asset ────────────────────────────────
            if _domain_col:
                try:
                    _port_int = None
                    if port_hint:
                        try:
                            _port_int = int(port_hint)
                        except (TypeError, ValueError):
                            pass
                    _proto = "https" if "443" in str(port_hint) else "http"
                    asset_obj = _get_or_create_asset(
                        db, job.owner_id, _domain_col, job.id,
                        port=_port_int, protocol=_proto,
                    )
                    db.flush()
                    _upsert_vulnerability(
                        db, asset_obj, finding_obj,
                        tool=_tool_col or "unknown",
                        cve_id=cve_id, cvss=_cvss,
                        severity=vuln.get("severity", "low"),
                        title=vuln.get("title", "Potential issue"),
                    )
                except Exception:
                    pass

        progress, progress_ctx = _progress_from_state(final_state)
        final_state["mission_progress_context"] = progress_ctx

        # Propaga campos de governança dos agentes 4 e 5 para report_v2.
        existing_report_v2 = (job.state_data or {}).get("report_v2") or {}
        existing_report_v2.update({
            "easm_rating":        final_state.get("easm_rating") or {},
            "fair_decomposition": final_state.get("fair_decomposition") or {},
            "executive_summary":  final_state.get("executive_summary") or "",
            "agent_validation":   final_state.get("agent_validation") or {},
            "confidence_state":   final_state.get("confidence_state") or {},
            "evidence_contract":  final_state.get("evidence_contract") or {},
        })
        final_state["report_v2"] = existing_report_v2
        # ───────────────────────────────────────────────────────────────────────

        # Persiste histórico de ratings por ativo.
        from app.models.models import Asset, AssetRatingHistory
        easm_rating = final_state.get("easm_rating") or {}
        fair_decomp = final_state.get("fair_decomposition") or {}
        discovered_assets = final_state.get("lista_ativos", [])
        
        for asset_addr in discovered_assets:
            # Encontra ou cria o asset
            asset = db.query(Asset).filter(
                Asset.owner_id == job.owner_id,
                Asset.domain_or_ip == asset_addr,
            ).first()
            
            if asset:
                # Calcula contagem de vulnerabilidades por severidade
                asset_vulns = db.query(Vulnerability).filter(
                    Vulnerability.asset_id == asset.id
                ).all()
                
                open_counts = {
                    "critical": sum(1 for v in asset_vulns if v.severity == "critical" and not v.remediated_at),
                    "high": sum(1 for v in asset_vulns if v.severity == "high" and not v.remediated_at),
                    "medium": sum(1 for v in asset_vulns if v.severity == "medium" and not v.remediated_at),
                }
                remediated_count = sum(1 for v in asset_vulns if v.remediated_at)
                
                # Extrai scores dos pillares
                pillar_scores = {}
                if isinstance(fair_decomp, dict) and "pillars" in fair_decomp:
                    for pillar in fair_decomp.get("pillars", []):
                        pillar_scores[pillar.get("name", "unknown")] = pillar.get("score", 0)
                
                # Grava histórico
                history = AssetRatingHistory(
                    asset_id=asset.id,
                    scan_id=job.id,
                    easm_rating=float(easm_rating.get("score", 0)),
                    easm_grade=easm_rating.get("grade", "F"),
                    open_critical_count=open_counts.get("critical", 0),
                    open_high_count=open_counts.get("high", 0),
                    open_medium_count=open_counts.get("medium", 0),
                    remediated_this_period=remediated_count,
                    pillar_scores=pillar_scores,
                    recorded_at=datetime.utcnow(),
                )
                db.add(history)
        
        db.flush()
        # ───────────────────────────────────────────────────────────────────────

        # ── Guard: only mark completed when the work queue is truly done ─────────
        # The LangGraph engine reaches this point when the graph finishes, but the
        # capacity_work_queue engine may still have active or blocked items running
        # asynchronously. Marking 'completed' here while blocked items exist causes
        # the scan to appear done while P08-P22 phases are still queued.
        _wq_engine_active = str(final_state.get("parallel_engine") or "") == "capacity_work_queue"
        if _wq_engine_active:
            try:
                from app.services.scan_work_queue import has_pending_work as _hpw
                if _hpw(db, job.id):
                    # Work queue still has items — checkpoint and let the dispatcher
                    # mark completion when everything truly finishes.
                    import logging as _wq_guard_log
                    _wq_guard_log.getLogger(__name__).info(
                        "langgraph_completion_guard: scan=%d work_queue not empty — "
                        "deferring completion to dispatcher", job.id
                    )
                    job.current_step = "5. ExecutiveAnalysis"
                    job.state_data = final_state
                    db.commit()
                    return {"checkpointed": True, "reason": "work_queue_still_active"}
            except Exception as _guard_exc:
                import logging as _wq_guard_log2
                _wq_guard_log2.getLogger(__name__).debug(
                    "langgraph_completion_guard failed: %s", _guard_exc
                )

        progress_ctx["computed_progress"] = progress
        progress_ctx["ui_progress"] = 100
        final_state["mission_progress_context"] = progress_ctx
        final_state["mission_progress"] = 100
        job.state_data = final_state
        job.mission_progress = 100
        job.current_step = "5. ExecutiveAnalysis"
        job.status = "completed"
        job.last_error = None
        job.next_retry_at = None
        
        # Log resumo final
        mission_summary = _format_mission_progress(final_state, job.current_step)
        easm_rating = final_state.get("easm_rating") or {}
        db.add(ScanLog(
            scan_job_id=job.id,
            source="worker.summary",
            level="INFO",
            message=(
                f"EXECUCAO SCRIPTKIDD.O CONCLUIDA COM SUCESSO!\n"
                f"\n"
                f"FRAMEWORK SUPERVISOR-CENTRIC:\n"
                f"{mission_summary}\n"
                f"\n"
                f"RESUMO:\n"
                f"  • Vulnerabilidades encontradas: {len(final_state.get('vulnerabilidades_encontradas', []))}\n"
                f"  • Portas descobertas: {len(final_state.get('discovered_ports', []))}\n"
                f"  • Ativos mapeados: {len(final_state.get('lista_ativos', []))}\n"
                f"  • Rating ScriptKidd.o: {easm_rating.get('score', 'N/A')}/100 (Grau {easm_rating.get('grade', 'N/A')})\n"
                f"  • Validation Score: {final_state.get('agent_validation', {}).get('scores', {}).get('overall', 'N/A')}\n"
                f"  • Taxa de sucesso: {progress_ctx.get('tools_success', 0)}/{progress_ctx.get('tools_attempted', 0)} ferramentas"
            )
        ))
        
        # ── Post-processing intelligence (correlação + consolidação) ──────────
        try:
            from app.services.finding_intelligence import run_all_intelligence as _intel
            _intel_result = _intel(db, job.id)
            db.add(ScanLog(
                scan_job_id=job.id, source="intelligence", level="INFO",
                message=f"Post-processing intelligence: {_intel_result}",
            ))
        except Exception as _ie:
            import logging as _ilog
            _ilog.getLogger(__name__).warning("finding_intelligence failed: %s", _ie)

        # ── CVE enrichment (descrição + reprodução + payload) ─────────────────
        try:
            from app.services.cve_enricher import enrich_scan_cves as _enrich_cves
            _enriched_cve_count = _enrich_cves(db, job.id, limit=200)
            if _enriched_cve_count:
                db.add(ScanLog(
                    scan_job_id=job.id, source="cve_enricher", level="INFO",
                    message=f"CVE enrichment: {_enriched_cve_count} findings enriquecidos com descrição e reprodução",
                ))
        except Exception as _ce:
            import logging as _clog
            _clog.getLogger(__name__).warning("cve_enricher failed: %s", _ce)

        # ── L6: Attack narrative generation ─────────────────────────────────────
        try:
            from app.services.attack_narrative import run_attack_narrative as _run_narrative
            _narrative_result = _run_narrative(db, job)
            if _narrative_result.get("narrative"):
                db.add(ScanLog(
                    scan_job_id=job.id, source="attack-narrative", level="INFO",
                    message=f"attack_narrative generated: method={_narrative_result.get('method')} findings={_narrative_result.get('findings_used')}",
                ))
        except Exception as _ne:
            import logging as _nlog
            _nlog.getLogger(__name__).warning("attack_narrative failed: %s", _ne)

        db.add(ScanLog(scan_job_id=job.id, source="worker", level="INFO", message=f"Execucao [{scan_mode}] finalizada"))
        log_audit(
            db,
            event_type="scan.execution_completed",
            message=f"Execucao [{scan_mode}] concluida com sucesso",
            scan_job_id=job.id,
            metadata={
                "scan_mode": scan_mode,
                "discovered_ports": final_state.get("discovered_ports", []),
                "pending_port_tests": final_state.get("pending_port_tests", []),
            },
        )
        _touch_worker_heartbeat(db, scan_mode=scan_mode, status="idle", scan_id=None, task_name=None)
        db.commit()
        return {"ok": True, "scan_id": scan_id, "scan_mode": scan_mode, "retryable": False}
    except Exception as exc:
        db.rollback()
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if job:
            if job.status == "stopped":
                _touch_worker_heartbeat(db, scan_mode=scan_mode, status="idle", scan_id=None, task_name=None)
                db.commit()
                return {"ok": False, "error": "scan_stopped", "retryable": False}
            job.status = "failed"
            job.last_error = str(exc)
            db.add(ScanLog(scan_job_id=job.id, source="worker", level="ERROR", message=str(exc)))
            log_audit(
                db,
                event_type="scan.execution_failed",
                message=f"Execucao [{scan_mode}] falhou",
                scan_job_id=job.id,
                level="ERROR",
                metadata={"error": str(exc), "scan_mode": scan_mode},
            )
            _touch_worker_heartbeat(db, scan_mode=scan_mode, status="error", scan_id=scan_id, task_name=f"run_scan_job_{scan_mode}")
            db.commit()
        return {"ok": False, "error": str(exc), "retryable": True}
    finally:
        if stop_pulse:
            try:
                stop_pulse()
            except Exception:
                pass
        db.close()


def _run_scan_with_retry(task_ctx, scan_id: int, scan_mode: ScanMode) -> dict:
    db: Session = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            return {"ok": False, "error": "scan not found", "retryable": False}

        if job.status == "stopped":
            return {"ok": False, "error": "scan_stopped", "retryable": False}

        retry_enabled, max_attempts, delay_seconds = _get_scan_retry_policy(db, job.owner_id)
        if not retry_enabled:
            max_attempts = 1

        attempt = int(getattr(task_ctx.request, "retries", 0)) + 1
        attempt = max(1, attempt)

        job.retry_attempt = attempt
        job.retry_max = max_attempts
        job.current_step = f"Execucao tentativa {attempt}/{max_attempts}"
        db.add(
            ScanLog(
                scan_job_id=scan_id,
                source="worker.retry",
                level="INFO",
                message=f"Tentativa {attempt}/{max_attempts} iniciada (modo={scan_mode})",
            )
        )
        db.commit()
    finally:
        db.close()

    result = _execute_scan(scan_id, scan_mode)
    if result.get("ok"):
        return result

    if not result.get("retryable"):
        return result

    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            return result

        if job.status == "stopped":
            return {"ok": False, "error": "scan_stopped", "retryable": False}

        retry_enabled, max_attempts, delay_seconds = _get_scan_retry_policy(db, job.owner_id)
        if not retry_enabled:
            max_attempts = 1
        attempt = int(getattr(task_ctx.request, "retries", 0)) + 1

        if attempt < max_attempts:
            max_delay = int(delay_seconds * 8)
            exponential_delay = int(min(max_delay, delay_seconds * (2 ** max(0, attempt - 1))))
            jitter = random.randint(0, max(1, min(15, delay_seconds // 2)))
            countdown = exponential_delay + jitter
            next_retry_at = datetime.utcnow() + timedelta(seconds=countdown)
            job.status = "retrying"
            job.next_retry_at = next_retry_at
            job.current_step = f"Retry agendado ({attempt + 1}/{max_attempts})"
            job.last_error = result.get("error", "falha desconhecida")
            db.add(
                ScanLog(
                    scan_job_id=scan_id,
                    source="worker.retry",
                    level="WARNING",
                    message=(
                        f"Falha na tentativa {attempt}/{max_attempts}: {result.get('error', 'erro')} | "
                        f"novo retry em {countdown}s"
                    ),
                )
            )
            db.commit()
            raise task_ctx.retry(exc=Exception(result.get("error", "scan failed")), countdown=countdown)

        job.status = "failed"
        job.next_retry_at = None
        job.current_step = f"Falha definitiva apos {attempt}/{max_attempts} tentativas"
        db.add(
            ScanLog(
                scan_job_id=scan_id,
                source="worker.retry",
                level="ERROR",
                message=f"Retry esgotado em {attempt}/{max_attempts} tentativas",
            )
        )
        db.commit()
        return result
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────────────────────
# Tasks orquestradoras publicas — uma por modo de execucao
# ──────────────────────────────────────────────────────────────────────────────

def _persist_autonomy_audit_log(db: Session, scan_id: int, final_state: dict[str, Any]) -> None:
    """Persiste dados de autonomy (notes, todos, actions, observations, errors) em ScanAuditLog"""
    try:
        autonomy_notes = final_state.get("autonomy_notes", [])
        autonomy_todos = final_state.get("autonomy_todos", [])
        autonomy_actions = final_state.get("autonomy_actions", [])
        autonomy_observations = final_state.get("autonomy_observations", [])
        autonomy_errors = final_state.get("autonomy_errors", [])
        
        iteration = int(final_state.get("loop_iteration", 0))
        
        # Persiste notes
        for note in autonomy_notes:
            db.add(ScanAuditLog(
                scan_job_id=scan_id,
                iteration=note.get("iteration", iteration),
                node_name=note.get("phase", "supervisor"),
                entry_type="note",
                content=f"{note.get('text', '')} | ts: {note.get('ts', '')}",
            ))
        
        # Persiste todos
        for todo in autonomy_todos:
            db.add(ScanAuditLog(
                scan_job_id=scan_id,
                iteration=todo.get("iteration", iteration),
                node_name="supervisor",
                entry_type="todo",
                content=f"[{todo.get('priority', 'medium')}] {todo.get('title', '')} | status: {todo.get('status', 'open')}",
            ))
        
        # Persiste actions
        for action in autonomy_actions:
            db.add(ScanAuditLog(
                scan_job_id=scan_id,
                iteration=action.get("iteration", iteration),
                node_name="supervisor",
                entry_type="action",
                content=f"{action.get('action', '')} | data: {json.dumps(action.get('data', {}))}",
            ))
        
        # Persiste observations
        for obs in autonomy_observations:
            db.add(ScanAuditLog(
                scan_job_id=scan_id,
                iteration=obs.get("iteration", iteration),
                node_name=obs.get("source", "unknown"),
                entry_type="observation",
                content=obs.get("text", ""),
            ))
        
        # Persiste errors
        for error in autonomy_errors:
            db.add(ScanAuditLog(
                scan_job_id=scan_id,
                iteration=error.get("iteration", iteration),
                node_name=error.get("source", "unknown"),
                entry_type="error",
                content=error.get("text", ""),
            ))
        
        db.commit()
    except Exception as e:
        print(f"Erro ao persistir autonomy audit log: {e}")


@celery.task(bind=True, name="run_scan_job_unit", queue=SCAN_UNIT_QUEUE)
def run_scan_job_unit(self, scan_id: int):
    """
    Task para scans UNITARIOS (execucao manual/pontual).
    Consumida exclusivamente pelos workers 'worker_unit' no docker-compose.
    Prioridade alta | concurrency=1 | escopo focado.
    """
    return _run_scan_with_retry(self, scan_id, "unit")


@celery.task(bind=True, name="run_scan_target_subset", queue=SCAN_PARALLEL_QUEUE, ignore_result=True)
def run_scan_target_subset(self, scan_id: int, target: str):
    """Parallel fan-out: process P02-P22 for ONE target inside an ongoing scan.

    Dispatched by the main scan when state.parallelize is True, after P01 has
    built the target_set. Each subtask processes its target's phases and
    persists findings/ledgers idempotently to the same scan_job row.
    """
    from app.db.session import SessionLocal
    from app.models.models import ScanJob, ScanLog
    from app.services.offensive_operator_runner import _run_target_phases_subset
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            return {"error": f"scan {scan_id} not found"}
        db.add(ScanLog(scan_job_id=scan_id, source="offensive-operator", level="INFO",
                       message=f"parallel_subtask started target={target}"))
        db.commit()
        return _run_target_phases_subset(db, job, target)
    finally:
        db.close()


@celery.task(name="correlate_tech_vulns", queue=SCAN_PARALLEL_QUEUE, ignore_result=True)
def correlate_tech_vulns(scan_id: int, target: str, tool_name: str, work_item_id: int):
    """Correlate detected technologies with CVEs and queue targeted nuclei scans."""
    from app.db.session import SessionLocal
    from app.services.tech_vuln_correlator import correlate_tech_vulns as _correlate

    db = SessionLocal()
    try:
        return _correlate(db, scan_id, target, tool_name, work_item_id)
    except Exception as exc:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).warning("correlate_tech_vulns error scan=%s: %s", scan_id, exc)
        return {"error": str(exc)}
    finally:
        db.close()


@celery.task(name="dispatch_scan_work_items", queue=SCAN_PARALLEL_QUEUE, ignore_result=True)
def dispatch_scan_work_items(scan_id: int, limit: int | None = None):
    """Capacity-aware dispatcher for persistent scan_work_items."""
    from app.db.session import SessionLocal
    from app.models.models import ScanJob, ScanLog
    from app.services.scan_work_queue import claim_work_items, work_queue_counts

    # ── Distributed lock: prevent concurrent dispatchers for the same scan ──
    # Multiple dispatch chains accumulate after worker restarts, starving poll/execute
    # tasks of thread-pool slots.  A simple Redis SETNX lock ensures at most one
    # dispatch task is processing a given scan_id at any moment.
    _lock_key = f"dispatch_lock:{scan_id}"
    _lock_ttl = 45  # seconds — longer than the task itself (~6-8s) but short enough
    _r_lock = None
    try:
        from app.services.scan_work_queue import _redis_client as _rl_fn
        _r_lock = _rl_fn()
        _acquired = _r_lock.set(_lock_key, "1", nx=True, ex=_lock_ttl)
        if not _acquired:
            # Another dispatch is already running for this scan — skip silently.
            # The running one will re-schedule itself in 30 s.
            return {"skipped": True, "reason": "dispatch_lock_held", "scan_id": scan_id}
    except Exception:
        pass  # Redis unavailable — proceed without the lock (fail-open)

    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            return {"error": f"scan {scan_id} not found"}

        # ── Gate reconciler (self-healing) ───────────────────────────────────────
        # The per-item gate-unblock hook lives in poll_scan_work_item, but items
        # marked terminal at SUBMIT time (e.g. MCP returns 'skipped' for a missing
        # tool) never get polled → the hook never fires → the gate stays closed →
        # downstream phases stall forever. This periodic reconciler is idempotent
        # and catches ALL cases: for each gate phase that is fully terminal, unblock
        # its dependents. Runs every dispatch cycle (~30s) so the flow self-heals.
        try:
            from app.services.scan_work_queue import (
                unblock_phase_items as _gr_unblock,
                _GATE_UNLOCKS as _gr_unlocks,
                triage_post_p09_injection as _gr_triage,
            )
            from app.models.models import ScanWorkItem as _GR_SWI
            from sqlalchemy import func as _gr_func
            _GR_TERM = ["completed", "done", "failed", "timeout", "skipped"]
            _gr_targets = [
                r[0] for r in db.query(_GR_SWI.target)
                .filter(_GR_SWI.scan_job_id == scan_id, _GR_SWI.target != "__batch__")
                .distinct().all()
            ] + ["__batch__"]
            for _gate_pid in ("P02", "P06", "P09"):
                # Is this gate phase fully terminal (and has items)?
                _gp = dict(
                    db.query(_GR_SWI.status, _gr_func.count(_GR_SWI.id))
                    .filter(_GR_SWI.scan_job_id == scan_id, _GR_SWI.phase_id == _gate_pid)
                    .group_by(_GR_SWI.status).all()
                )
                _gp_total = sum(_gp.values())
                if _gp_total == 0:
                    continue
                _gp_pending = sum(v for k, v in _gp.items() if k not in _GR_TERM)
                if _gp_pending > 0:
                    continue  # gate not done yet
                # Are dependents still blocked? (avoid redundant work)
                _deps = _gr_unlocks.get(_gate_pid, [])
                if not _deps:
                    continue
                _blocked_deps = (
                    db.query(_gr_func.count(_GR_SWI.id))
                    .filter(
                        _GR_SWI.scan_job_id == scan_id,
                        _GR_SWI.phase_id.in_(_deps),
                        _GR_SWI.status == "blocked",
                    ).scalar() or 0
                )
                if _blocked_deps == 0:
                    continue
                # P09 gate: triage first (skip exploitation on targets w/o findings)
                _unb_targets = _gr_targets
                if _gate_pid == "P09":
                    try:
                        _tr = _gr_triage(db, scan_id)
                        _twf = _tr.get("targets_with_findings") or []
                        if _twf:
                            _unb_targets = _twf + ["__batch__"]
                    except Exception:
                        pass
                _n = _gr_unblock(db, scan_id, _unb_targets, _gate_pid)
                if _n:
                    db.commit()
                    import logging as _grlog
                    _grlog.getLogger(__name__).info(
                        "gate_reconciler: scan=%d gate=%s fully-terminal → unblocked %d deps",
                        scan_id, _gate_pid, _n,
                    )
        except Exception as _gr_err:
            import logging as _grlog2
            _grlog2.getLogger(__name__).debug("gate_reconciler failed: %s", _gr_err)

        item_ids = claim_work_items(db, scan_id, limit=limit)

        # ── Target priority scoring: exploitation phases first for targets with findings ──
        # Inspired by Pentest-Swarm-AI pheromone model + LuaN1aoAgent DAG parallelism.
        # Targets that already have HIGH/CRITICAL findings get their exploitation
        # items dispatched first — focuses worker slots on targets that matter most.
        if item_ids:
            try:
                from app.models.models import Finding as _FindingDisp, ScanWorkItem as _SWIDisp
                from sqlalchemy import func as _sfunc_disp

                # Count HIGH/CRITICAL findings per target in this scan
                _target_scores = dict(
                    db.query(
                        _FindingDisp.domain,
                        _sfunc_disp.count(_FindingDisp.id),
                    )
                    .filter(
                        _FindingDisp.scan_job_id == scan_id,
                        _FindingDisp.severity.in_(["critical", "high"]),
                        _FindingDisp.is_false_positive.is_(False),
                    )
                    .group_by(_FindingDisp.domain)
                    .all()
                )

                if _target_scores:
                    # Re-order item_ids: exploitation phases for high-score targets first
                    _EXPLOIT_PHASES = {"P10", "P11", "P12", "P13", "P14", "P17", "P19", "P20"}
                    _items_info = (
                        db.query(_SWIDisp.id, _SWIDisp.target, _SWIDisp.phase_id)
                        .filter(_SWIDisp.id.in_(item_ids))
                        .all()
                    )

                    def _item_priority(info: tuple) -> int:
                        item_id, target, phase_id = info
                        target_score = _target_scores.get(str(target), 0)
                        phase_bonus = 100 if phase_id in _EXPLOIT_PHASES else 0
                        # Higher score = higher priority (sort ascending = lower first so negate)
                        return -(target_score * 10 + phase_bonus)

                    _items_info_sorted = sorted(_items_info, key=_item_priority)
                    item_ids = [info[0] for info in _items_info_sorted]
            except Exception:
                pass  # Priority scoring failure is non-fatal

        for item_id in item_ids:
            execute_scan_work_item.delay(item_id)

        # ── Auto-retry timed-out items that haven't exceeded max_attempts ────────
        # Items with status='timeout' are NOT automatically retried — they stay
        # terminal and block their downstream gate phases indefinitely.
        # Here we re-queue them (resetting lease) if attempts < max_attempts so
        # the dispatch loop picks them up on the next cycle.
        try:
            from app.models.models import ScanWorkItem as _SWI_retry
            from datetime import datetime as _dt_retry
            _retried = 0
            _timeout_items = (
                db.query(_SWI_retry)
                .filter(
                    _SWI_retry.scan_job_id == scan_id,
                    _SWI_retry.status == "timeout",
                    _SWI_retry.attempts < _SWI_retry.max_attempts,
                )
                .limit(200)
                .all()
            )
            for _ti in _timeout_items:
                _ti.status = "queued"
                _ti.lease_until = None
                _ti.last_error = f"[auto-retry after timeout attempt {_ti.attempts}]"
                _ti.updated_at = _dt_retry.utcnow()
                _retried += 1
            if _retried:
                import logging as _retry_log
                _retry_log.getLogger(__name__).info(
                    "auto_retry_timeouts: scan=%d requeued=%d items", scan_id, _retried
                )
        except Exception as _retry_exc:
            import logging as _retry_log2
            _retry_log2.getLogger(__name__).debug("auto_retry_timeouts failed: %s", _retry_exc)

        counts = work_queue_counts(db, scan_id)
        state = dict(job.state_data or {})
        state["work_queue_counts"] = counts
        state["work_queue_last_dispatch"] = {
            "claimed": len(item_ids),
            "limit": limit,
            "engine": "capacity_work_queue",
        }
        job.state_data = state
        db.add(ScanLog(
            scan_job_id=scan_id,
            source="work-queue",
            level="INFO",
            message=f"work_queue_dispatch claimed={len(item_ids)} counts={counts}",
        ))
        db.commit()
        _active_statuses = ("queued", "retry", "dispatched", "running", "submitted")
        # "blocked" items are pending (waiting for their gate to open) — keep polling
        _has_active = item_ids or any(counts.get(st, 0) for st in _active_statuses) or counts.get("blocked", 0) > 0
        if _has_active:
            dispatch_scan_work_items.apply_async(args=[scan_id, limit], countdown=30)
        else:
            # ── Scan completion: all work items reached a terminal state ─────
            # "blocked" is NOT terminal — if we land here, any residual blocked items
            # are orphaned (their gate phase never ran). Treat them as skipped for
            # completion accounting.
            _terminal_statuses = {"completed", "done", "failed", "timeout", "skipped"}
            _total = sum(counts.values())
            _done = sum(counts.get(s, 0) for s in _terminal_statuses)
            if _total > 0 and _done >= _total and job.status == "running":
                import logging as _clog
                _clog.getLogger(__name__).info(
                    "scan_complete: scan_id=%d total_items=%d terminal=%d — marking completed",
                    scan_id, _total, _done,
                )
                _final_state = dict(job.state_data or {})
                _final_state["completion_source"] = "work_queue_dispatcher"
                _final_state["items_total"] = _total
                _final_state["items_terminal"] = _done
                job.state_data = _final_state
                job.status = "completed"
                job.mission_progress = 100
                # Trigger post-scan CVE enrichment pass
                try:
                    from app.services.cve_enrichment_service import enrichment_service as _enrich
                    _enrich.enrich_scan_findings(db, scan_id)
                except Exception:
                    pass
                db.add(ScanLog(
                    scan_job_id=scan_id,
                    source="work-queue",
                    level="INFO",
                    message=(
                        f"SCAN CONCLUÍDO via work_queue_dispatcher — "
                        f"total={_total} terminal={_done} "
                        f"(completed={counts.get('completed',0)} "
                        f"failed={counts.get('failed',0)} "
                        f"timeout={counts.get('timeout',0)} "
                        f"skipped={counts.get('skipped',0)} "
                        f"blocked={counts.get('blocked',0)})"
                    ),
                ))
                db.commit()
        return {"claimed": len(item_ids), "counts": counts}
    finally:
        db.close()
        # Release dispatch lock so the next scheduled dispatch can run immediately
        try:
            if _r_lock is not None:
                _r_lock.delete(_lock_key)
        except Exception:
            pass


@celery.task(name="execute_scan_work_item", queue=SCAN_PARALLEL_QUEUE, ignore_result=True)
def execute_scan_work_item(item_id: int):
    """Submit one tool/profile/target work item through MCP -> Kali and release the worker."""
    from datetime import datetime, timedelta
    import requests
    from app.db.session import SessionLocal
    from app.core.config import settings
    from app.models.models import ScanJob, ScanLog, ScanWorkItem
    from app.services.scan_work_queue import work_queue_counts

    db = SessionLocal()
    try:
        item = db.query(ScanWorkItem).filter(ScanWorkItem.id == item_id).first()
        if not item:
            return {"error": f"work item {item_id} not found"}
        job = db.query(ScanJob).filter(ScanJob.id == item.scan_job_id).first()
        if not job:
            item.status = "failed"
            item.last_error = "scan_not_found"
            item.finished_at = datetime.utcnow()
            db.commit()
            return {"error": "scan_not_found"}
        if item.status not in {"dispatched", "queued", "retry"}:
            return {"status": item.status}

        now = datetime.utcnow()
        item.status = "running"
        item.attempts = int(item.attempts or 0) + 1
        item.started_at = item.started_at or now
        item.lease_until = now + timedelta(seconds=1800)
        item.updated_at = now
        db.add(ScanLog(
            scan_job_id=item.scan_job_id,
            source="work-queue",
            level="INFO",
            message=(
                f"work_item_start id={item.id} phase={item.phase_id} "
                f"target={item.target} tool={item.tool_name} rc={item.resource_class}"
            ),
        ))
        db.commit()

        # ── T4: Batch dispatch — one MCP call for all targets in batch item ──
        _item_meta = dict(item.item_metadata or {})
        _batch_targets: list[str] = list(_item_meta.get("batch_targets") or [])
        _is_batch = item.target == "__batch__" and len(_batch_targets) > 1
        _dispatch_target = _batch_targets[0] if _is_batch else item.target

        execution = {
            "mcp_request_id": f"wi-{item.id}",
            "phase_id": item.phase_id,
            "skill_id": f"work_queue.{item.phase_id}",
            "tool_name": item.tool_name,
            "profile": item.profile or item.tool_name,
            "target": _dispatch_target,
            "arguments": {
                "target": _dispatch_target,
                "scan_id": item.scan_job_id,
                **({"targets": _batch_targets, "batch_count": len(_batch_targets)} if _is_batch else {}),
            },
            "expected_evidence": ["stdout", "raw_tool_output", "parsed_result"],
        }
        if _is_batch:
            execution["targets"] = _batch_targets

        # ── Adaptive timeout: respect per-item override (wapiti/sqlmap port-scaled) ──
        _timeout_override = _item_meta.get("timeout_override")
        if _timeout_override:
            execution["arguments"]["timeout"] = int(_timeout_override)
            execution["timeout_hint"] = int(_timeout_override)

        response = requests.post(
            f"{settings.mcp_server_url.rstrip('/')}/mcp/submit",
            json=execution,
            timeout=30,
        )
        response.raise_for_status()
        result = dict(response.json())
        raw_status = str(result.get("status") or "").lower()
        if raw_status != "submitted":
            # 'skipped' = terminal, non-retryable (e.g. tool/profile genuinely
            # missing). Don't burn retries — mark terminal so the phase completes
            # and its gate fires. Other non-submit statuses retry up to max.
            if raw_status == "skipped":
                item.status = "skipped"
                item.lease_until = None
                item.finished_at = datetime.utcnow()
            else:
                item.status = "retry" if item.attempts < item.max_attempts else (raw_status or "failed")
                item.lease_until = datetime.utcnow() + timedelta(seconds=120) if item.status == "retry" else None
                item.finished_at = datetime.utcnow() if item.status != "retry" else None
            item.last_error = str(result.get("error") or "mcp_submit_failed")[:2000]
        else:
            timeout = int(result.get("timeout") or 300)
            item.status = "submitted"
            # lease = tool_timeout + generous polling buffer (at least 600s / 10 min)
            # This prevents premature expiration when poll tasks are briefly delayed
            # (e.g. during worker pool contention on startup).
            item.lease_until = datetime.utcnow() + timedelta(seconds=max(600, timeout + 300))
            item.last_error = None
            item.result = {
                "status": "submitted",
                "mcp_execution_id": result.get("mcp_execution_id"),
                "mcp_request_id": result.get("mcp_request_id"),
                "kali_job_id": result.get("kali_job_id") or result.get("dispatch_task_id"),
                "dispatch_task_id": result.get("dispatch_task_id"),
                "profile": result.get("profile"),
                "timeout": timeout,
                "execution_path": result.get("execution_path"),
                "submitted_at": datetime.utcnow().isoformat(),
            }
            poll_scan_work_item.apply_async(args=[item.id], countdown=5)
        item.updated_at = datetime.utcnow()

        counts = work_queue_counts(db, item.scan_job_id)
        state = dict(job.state_data or {})
        state["work_queue_counts"] = counts
        job.state_data = state
        db.add(ScanLog(
            scan_job_id=item.scan_job_id,
            source="work-queue",
            level="INFO",
            message=(
                f"work_item_submit id={item.id} phase={item.phase_id} target={item.target} "
                f"tool={item.tool_name} status={item.status} kali_job_id={(item.result or {}).get('kali_job_id')}"
            ),
        ))
        db.commit()
        return {"id": item.id, "status": item.status}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        item = db.query(ScanWorkItem).filter(ScanWorkItem.id == item_id).first()
        if item:
            item.status = "retry" if int(item.attempts or 0) < int(item.max_attempts or 1) else "failed"
            item.last_error = str(exc)[:2000]
            item.lease_until = datetime.utcnow() + timedelta(seconds=120) if item.status == "retry" else None
            item.finished_at = datetime.utcnow() if item.status == "failed" else None
            # ── Camada 0: semaphore leak fix — release slot on exception ──────
            if item.status == "failed":
                try:
                    from app.services.scan_work_queue import kali_inflight_release as _release_exc
                    _release_exc(str(item.resource_class or "light"), 1)
                except Exception:
                    pass
            db.commit()
        return {"id": item_id, "status": "error", "error": str(exc)}
    finally:
        db.close()


@celery.task(name="poll_scan_work_item", queue=SCAN_PARALLEL_QUEUE, ignore_result=True)
def poll_scan_work_item(item_id: int):
    """Poll an async MCP/Kali job and persist the terminal result."""
    from datetime import datetime, timedelta
    import requests
    from app.db.session import SessionLocal
    from app.core.config import settings
    from app.models.models import ExecutedToolRun, ScanJob, ScanLog, ScanWorkItem
    from app.services.scan_work_queue import work_queue_counts

    db = SessionLocal()
    try:
        item = db.query(ScanWorkItem).filter(ScanWorkItem.id == item_id).first()
        if not item:
            return {"error": f"work item {item_id} not found"}
        if item.status != "submitted":
            return {"id": item.id, "status": item.status}
        job = db.query(ScanJob).filter(ScanJob.id == item.scan_job_id).first()
        result_state = dict(item.result or {})
        kali_job_id = str(result_state.get("kali_job_id") or result_state.get("dispatch_task_id") or "")
        if not kali_job_id:
            item.status = "retry" if item.attempts < item.max_attempts else "failed"
            item.last_error = "missing_kali_job_id"
            item.lease_until = datetime.utcnow() + timedelta(seconds=120) if item.status == "retry" else None
            item.finished_at = datetime.utcnow() if item.status == "failed" else None
            db.commit()
            return {"id": item.id, "status": item.status}

        status_response = requests.get(
            f"{settings.mcp_server_url.rstrip('/')}/mcp/jobs/{kali_job_id}",
            timeout=10,
        )
        status_response.raise_for_status()
        status_payload = dict(status_response.json())
        raw_status = str(status_payload.get("status") or "").lower()
        if raw_status not in {"done", "failed", "timeout", "skipped"}:
            item.lease_until = datetime.utcnow() + timedelta(seconds=300)
            result_state["last_poll"] = datetime.utcnow().isoformat()
            result_state["kali_status"] = raw_status or "running"
            item.result = result_state
            item.updated_at = datetime.utcnow()
            db.commit()
            poll_scan_work_item.apply_async(args=[item.id], countdown=15)
            return {"id": item.id, "status": "submitted", "kali_status": raw_status}

        result_response = requests.get(
            f"{settings.mcp_server_url.rstrip('/')}/mcp/jobs/{kali_job_id}/result",
            timeout=75,
        )
        result_response.raise_for_status()
        result = dict(result_response.json())
        exit_code = result.get("return_code", result.get("exit_code"))
        terminal = "completed" if raw_status in {"done", "success"} and exit_code == 0 else raw_status
        if terminal in {"failed", "timeout"} and item.attempts < item.max_attempts:
            terminal = "retry"

        item.status = terminal
        item.finished_at = datetime.utcnow() if terminal != "retry" else None
        item.lease_until = None if terminal != "retry" else datetime.utcnow() + timedelta(seconds=120)
        item.last_error = str(result.get("error") or "")[:2000] or None

        # Libera slot no semáforo Redis global quando tarefa termina (não é retry)
        if terminal != "retry":
            try:
                from app.services.scan_work_queue import kali_inflight_release
                kali_inflight_release(str(item.resource_class or "light"), 1)
            except Exception:
                pass

        # ── L2: Interactsh OOB — poll for callbacks and confirm blind findings ─
        if terminal != "retry" and job:
            try:
                from app.services.interactsh_callback import check_and_confirm_oob_findings
                _oob_confirmed = check_and_confirm_oob_findings(db, job.id)
                if _oob_confirmed > 0:
                    import logging as _ooblog
                    _ooblog.getLogger(__name__).info(
                        "interactsh_oob scan=%d confirmed=%d", job.id, _oob_confirmed
                    )
            except Exception as _ooberr:
                pass  # OOB polling is best-effort

        # Capture full stdout BEFORE truncating for storage — parsers see the whole output
        _full_stdout = str(result.get("stdout") or "")
        _parsed_result = result.get("parsed")
        item.result = {
            **result_state,
            "status": raw_status,
            "exit_code": exit_code,
            "command": result.get("command"),
            "stdout_path": result.get("stdout_path") or result.get("workdir"),
            "stderr_path": result.get("stderr_path"),
            "duration_seconds": result.get("duration_seconds"),
            "error": result.get("error"),
            "stdout_preview": _full_stdout[:3000],       # display only
            "stdout_full": _full_stdout[:200_000],        # parser input (200 KB cap)
            "parsed_result": _parsed_result,
            "finished_at": datetime.utcnow().isoformat(),
        }
        item.updated_at = datetime.utcnow()

        run_status = "success" if item.status == "completed" else ("failed" if item.status in {"failed", "timeout", "skipped"} else "timeout")
        try:
            # Upsert to avoid UniqueViolation when the same tool+target re-runs
            # (happens after worker restarts reset items to queued)
            from sqlalchemy.dialects.postgresql import insert as _pg_insert
            _upsert_stmt = (
                _pg_insert(ExecutedToolRun.__table__)
                .values(
                    scan_job_id=item.scan_job_id,
                    tool_name=item.tool_name[:100],
                    target=item.target[:500],
                    status=run_status,
                    error_message=item.last_error,
                    execution_time_seconds=(
                        float(result.get("duration_seconds"))
                        if result.get("duration_seconds") is not None else None
                    ),
                    created_at=datetime.utcnow(),
                )
                .on_conflict_do_update(
                    constraint="uq_executed_tool_runs_scan_tool_target",
                    set_={
                        "status": run_status,
                        "error_message": item.last_error,
                        "execution_time_seconds": (
                            float(result.get("duration_seconds"))
                            if result.get("duration_seconds") is not None else None
                        ),
                    },
                )
            )
            db.execute(_upsert_stmt)
        except Exception:
            pass  # best-effort; skip run tracking on unexpected error

        # ── Extract and persist findings from completed tool output ──────────
        # Use full_result so parsers receive un-truncated stdout
        findings_created = 0
        if item.status == "completed" and job:
            try:
                from app.services.findings_extractor import persist_findings_from_work_item as _persist_findings
                findings_created = _persist_findings(db, item, job)
            except Exception as _fe:  # noqa: BLE001
                import logging as _log
                _log.getLogger(__name__).warning(
                    "findings_extractor failed for item %s tool=%s: %s", item.id, item.tool_name, _fe
                )

        # ── Camada 2: Phase gate unblocking ──────────────────────────────────────
        # Progressive unlock: when a gate phase reaches terminal state for a target,
        # unblock all dependent phases for that target.
        #   P02 done → unlock P03/P04/P05/P06/P07/P15
        #   P06 done → unlock P08/P09/P16
        #   P09 done → triage + unlock P10-P14/P17/P19/P20 for targets WITH findings
        # Also handles failed/timeout gate items — downstream phases get a chance.
        _GATE_PHASES = {"P02", "P06", "P09"}
        if item.phase_id in _GATE_PHASES and item.status in ("completed", "failed", "timeout", "skipped") and job:
            try:
                from app.services.scan_work_queue import unblock_phase_items as _unblock
                from sqlalchemy import func as _sfunc2

                _imeta_gate = dict(item.item_metadata or {})
                _is_batch_gate = item.target == "__batch__"
                _gate_targets: list[str] = (
                    list(_imeta_gate.get("batch_targets") or []) if _is_batch_gate else [item.target]
                )

                if _gate_targets:
                    # Check if ALL other items for this gate phase (same target scope) are done
                    from app.models.models import ScanWorkItem as _SWI_gate
                    _TERM_GATE = frozenset({"completed", "done", "failed", "timeout", "skipped"})
                    _still_q = (
                        db.query(_sfunc2.count(_SWI_gate.id))
                        .filter(
                            _SWI_gate.scan_job_id == job.id,
                            _SWI_gate.phase_id == item.phase_id,
                            ~_SWI_gate.status.in_(list(_TERM_GATE)),
                            _SWI_gate.id != item.id,  # exclude the just-finished item
                        )
                    )
                    if not _is_batch_gate:
                        # Individual item: only check same target
                        _still_q = _still_q.filter(_SWI_gate.target == item.target)
                    _still_pending_gate = _still_q.scalar() or 0

                    if _still_pending_gate == 0:
                        # All gate items done → unblock dependents
                        _unblock_targets = _gate_targets
                        if item.phase_id == "P09":
                            # P09 special: triage first (cancel P10+ for targets without findings)
                            from app.services.scan_work_queue import triage_post_p09_injection as _triage_p09
                            _triage_result = _triage_p09(db, job.id)
                            if _triage_result.get("cancelled", 0) > 0:
                                import logging as _trilog
                                _trilog.getLogger(__name__).info(
                                    "triage_post_p09 scan=%d cancelled=%d kept=%d twf=%d",
                                    job.id, _triage_result["cancelled"], _triage_result["kept"],
                                    len(_triage_result.get("targets_with_findings", [])),
                                )
                            # Only unblock for targets that survived triage
                            _twf = _triage_result.get("targets_with_findings") or []
                            _unblock_targets = _twf if _twf else _gate_targets

                        _unblocked = _unblock(db, job.id, _unblock_targets, item.phase_id)
                        if _unblocked > 0:
                            import logging as _gatelog
                            _gatelog.getLogger(__name__).info(
                                "phase_gate_unblock scan=%d gate=%s targets=%d unblocked=%d",
                                job.id, item.phase_id, len(_unblock_targets), _unblocked,
                            )
                            db.flush()

                        # ── PoC Batch Scheduler: P09 → P21 ──────────────────────
                        # After P09 (reconnaissance triage) gate unblocks exploitation
                        # phases, bulk-schedule PoC validation items for any HIGH/CRITICAL
                        # candidate findings accumulated during P01-P09.
                        # This catches findings created before poc_validator was wired in,
                        # and ensures ALL reconnaissance findings get a validation chance
                        # before the pentest report is generated.
                        if item.phase_id == "P09":
                            try:
                                from app.services.poc_validator import batch_schedule_poc_validations as _batch_poc
                                _poc_result = _batch_poc(db, job.id, max_findings=30)
                                if _poc_result.get("scheduled", 0) > 0:
                                    import logging as _poclog
                                    _poclog.getLogger(__name__).info(
                                        "poc_batch_scheduler: scan=%d scheduled=%d "
                                        "skipped_confirmed=%d skipped_cap=%d skipped_no_tool=%d",
                                        job.id,
                                        _poc_result.get("scheduled", 0),
                                        _poc_result.get("skipped_confirmed", 0),
                                        _poc_result.get("skipped_cap", 0),
                                        _poc_result.get("skipped_no_tool", 0),
                                    )
                            except Exception as _pocbatch_err:
                                import logging as _pocbatchlog
                                _pocbatchlog.getLogger(__name__).debug(
                                    "poc_batch_scheduler failed scan=%d: %s", job.id, _pocbatch_err
                                )
            except Exception as _gate_err:
                import logging as _gatelog2
                _gatelog2.getLogger(__name__).debug("phase_gate_unblock failed: %s", _gate_err)

        # ── JS endpoint extraction + high-value probe seeding ───────────────
        if item.status == "completed" and job and item.tool_name in (
            "katana", "katana-js", "gospider", "hakrawler",
        ):
            try:
                from app.services.js_endpoint_extractor import process_crawl_result as _crawl_proc
                _crawl_summary = _crawl_proc(db, job.id, item.target, item.tool_name, dict(item.result or {}))
                if _crawl_summary.get("probes_seeded", 0) > 0 or _crawl_summary.get("high_value_found", 0) > 0:
                    import logging as _jlog
                    _jlog.getLogger(__name__).info(
                        "js_endpoint_extractor: target=%s urls=%d api_paths=%d high_value=%d probes=%d",
                        item.target,
                        _crawl_summary.get("urls", 0),
                        _crawl_summary.get("api_paths", 0),
                        _crawl_summary.get("high_value_found", 0),
                        _crawl_summary.get("probes_seeded", 0),
                    )
            except Exception as _je:
                import logging as _jlog2
                _jlog2.getLogger(__name__).debug("js_endpoint_extractor failed: %s", _je)

        # ── Technology → CVE correlation (async Celery task) ─────────────────
        if item.status == "completed" and job and item.tool_name in (
            "httpx", "whatweb", "whatweb-basic", "nmap", "nmap-http", "nmap-ssl", "nmap-vuln",
            "wapiti", "nuclei", "shodan-cli",
        ):
            try:
                correlate_tech_vulns.apply_async(
                    args=[job.id, item.target, item.tool_name, item.id],
                    countdown=5,
                    queue="worker.unit.reconhecimento",
                )
            except Exception:
                pass

        # ── L4: Multi-identity BOLA/BFLA tester ────────────────────────────────
        # Run after web app scanning phases complete for targets with auth endpoints
        if item.status == "completed" and job and item.phase_id in ("P09", "P10", "P12"):
            try:
                from app.services.multi_identity_tester import run_multi_identity_test as _bola_test
                _bola_meta = dict(item.item_metadata or {})
                if not _bola_meta.get("bola_tested"):
                    _bola_result = _bola_test(db, job, item.target)
                    if _bola_result.get("bola_findings", 0) > 0:
                        import logging as _bolog
                        _bolog.getLogger(__name__).info(
                            "bola_test scan=%d target=%s findings=%d",
                            job.id, item.target, _bola_result["bola_findings"],
                        )
            except Exception as _bola_err:
                import logging as _bolog2
                _bolog2.getLogger(__name__).debug("multi_identity_tester failed: %s", _bola_err)

        # ── L3: LLM operator — proposes novel attack chains after key phases ────
        if item.status == "completed" and job and item.phase_id in ("P09", "P10", "P11"):
            try:
                from app.services.llm_operator import run_llm_operator as _llm_op
                _llm_result = _llm_op(db, job)
                if _llm_result.get("items_created", 0) > 0:
                    import logging as _llmlog
                    _llmlog.getLogger(__name__).info(
                        "llm_operator scan=%d chains=%d items=%d",
                        job.id, _llm_result.get("chains_proposed", 0), _llm_result.get("items_created", 0),
                    )
            except Exception as _llme:
                import logging as _llmlog2
                _llmlog2.getLogger(__name__).debug("llm_operator failed: %s", _llme)

        # ── BLA: Business Logic Analyzer — per-target after active phases ────────
        # Runs after P12/P13 (active injection) OR after P09 (nuclei) when
        # no injection tools are queued. Avoids redundant runs via state_data flag.
        if item.status == "completed" and job and item.phase_id in ("P10", "P12", "P13"):
            try:
                _state_bla = dict(job.state_data or {})
                _bla_done_key = f"bla_done_{item.target}"
                if not _state_bla.get(_bla_done_key):
                    from app.services.business_logic_analyzer import run_business_logic_scan as _bla_run
                    _bla_result = _bla_run(db, job.id, target_domains=[item.target], max_domains=1)
                    _state_bla[_bla_done_key] = True
                    job.state_data = _state_bla
                    if _bla_result.get("total_findings", 0) > 0:
                        import logging as _blalog
                        _blalog.getLogger(__name__).info(
                            "business_logic scan=%d target=%s findings=%d",
                            job.id, item.target, _bla_result["total_findings"],
                        )
            except Exception as _bla_err:
                import logging as _blalog2
                _blalog2.getLogger(__name__).debug("business_logic_analyzer failed: %s", _bla_err)

        # ── JSP: JS Prototype Pollution Analyzer — after crawl/nuclei ─────────
        # Triggered after katana (P08) or nuclei (P09) completes. Node.js apps
        # identified by tech stack detection get full pollution test suite.
        if item.status == "completed" and job and item.tool_name in (
            "katana", "katana-js", "httpx", "nuclei", "whatweb",
        ):
            try:
                _state_jsp = dict(job.state_data or {})
                _jsp_done_key = f"jsp_done_{item.target}"
                if not _state_jsp.get(_jsp_done_key):
                    # Only run if target shows Node.js/Express signals
                    _tech_str = str(item.result or "").lower()
                    _is_node_target = any(kw in _tech_str for kw in [
                        "node", "express", "nestjs", "next.js", "nuxt", "fastify",
                        "x-powered-by: express", "x-powered-by: next.js",
                        "vercel", "netlify",
                    ])
                    if _is_node_target:
                        from app.services.js_pollution_analyzer import run_js_pollution_scan as _jsp_run
                        _jsp_result = _jsp_run(db, job.id, target_domains=[item.target], max_domains=1)
                        _state_jsp[_jsp_done_key] = True
                        job.state_data = _state_jsp
                        if _jsp_result.get("findings_created", 0) > 0:
                            import logging as _jsplog
                            _jsplog.getLogger(__name__).info(
                                "js_pollution scan=%d target=%s findings=%d",
                                job.id, item.target, _jsp_result["findings_created"],
                            )
            except Exception as _jsp_err:
                import logging as _jsplog2
                _jsplog2.getLogger(__name__).debug("js_pollution_analyzer failed: %s", _jsp_err)

        # ── ZAP: OWASP ZAP baseline scan — after HTTP fingerprint confirms target ──
        # ZAP runs as a separate container (zap:8090), not via Kali CLI, so it's
        # triggered as a post-processing hook (like js_pollution/multi_identity).
        # After P06 (httpx/whatweb) confirms a target speaks HTTP, run ZAP baseline
        # (passive spider + alerts). Findings go through the same gated path.
        # One ZAP run per target per scan (guarded by state key).
        if item.status == "completed" and job and item.phase_id in ("P06", "P07") and item.target and item.target != "__batch__":
            try:
                _state_zap = dict(job.state_data or {})
                _zap_key = f"zap_done_{item.target}"
                # Cap: ZAP is heavy (1-2 min/target) — limit to first 15 live targets.
                _zap_count = int(_state_zap.get("zap_run_count") or 0)
                if not _state_zap.get(_zap_key) and _zap_count < 15:
                    from app.services.zap_scanner import run_zap_baseline as _zap_baseline, is_zap_available as _zap_avail
                    if _zap_avail():
                        _tgt = item.target
                        _zap_url = _tgt if str(_tgt).startswith("http") else f"https://{_tgt}"
                        # Scan AUTENTICADO: injeta credenciais do scan (auth_config)
                        # nos cabeçalhos do ZAP → alcança endpoints pós-login.
                        _zap_auth = {}
                        try:
                            from app.services.scan_intelligence import auth_headers_from_state
                            _zap_auth = auth_headers_from_state(_state_zap) or {}
                        except Exception:
                            _zap_auth = {}
                        _zap_res = _zap_baseline(_zap_url, auth_headers=_zap_auth or None)
                        _zap_findings = _zap_res.get("findings") or []
                        _state_zap[_zap_key] = True
                        _state_zap["zap_run_count"] = _zap_count + 1
                        job.state_data = _state_zap
                        if _zap_findings:
                            from app.services.findings_extractor import persist_finding_dicts as _persist_zap
                            _zap_created = _persist_zap(
                                db, job, _zap_findings,
                                default_tool="zap-baseline", default_target=_tgt, source_item=None,
                            )
                            import logging as _zaplog
                            _zaplog.getLogger(__name__).info(
                                "zap_baseline scan=%d target=%s alerts=%d findings_created=%d",
                                job.id, _tgt, _zap_res.get("alert_count", 0), _zap_created,
                            )
            except Exception as _zap_err:
                import logging as _zaplog2
                _zaplog2.getLogger(__name__).debug("zap_baseline failed: %s", _zap_err)

        # ── EXC: Attack Graph + Exploit Chain correlation — post-exploitation ────
        # Runs after P12, P13, P17 or P20 items complete (exploitation phases).
        # P17 (Exploit Validation) and P20 (Attack Path Correlation) are the primary
        # triggers — chains have the most evidence at this point.
        # Also triggered on P12/P13 for early partial chain detection.
        _CHAIN_TRIGGER_PHASES = {"P10", "P12", "P13", "P17", "P20"}
        if item.status == "completed" and job and item.phase_id in _CHAIN_TRIGGER_PHASES:
            try:
                _state_exc = dict(job.state_data or {})
                # Re-correlate after each P17/P20 completion (not just once)
                _is_high_value_phase = item.phase_id in ("P17", "P20")
                _already_correlated = bool(_state_exc.get("exploit_chains_correlated"))
                _last_chain_phase = str(_state_exc.get("_last_chain_phase") or "")
                _should_run = _is_high_value_phase or not _already_correlated

                if _should_run:
                    from app.models.models import ScanWorkItem as _SWI_exc
                    # Check no remaining active items in exploitation phases
                    _remaining_exploitation = (
                        db.query(_SWI_exc)
                        .filter(
                            _SWI_exc.scan_job_id == job.id,
                            _SWI_exc.phase_id.in_(list(_CHAIN_TRIGGER_PHASES)),
                            _SWI_exc.status.in_(["queued", "dispatched", "running", "submitted"]),
                        )
                        .count()
                    )
                    # For P17/P20, run even if other phases still active — new evidence
                    if _remaining_exploitation == 0 or _is_high_value_phase:
                        from app.services.exploit_chain import correlate_chains as _corr_chains
                        try:
                            from app.services.attack_graph import build_attack_graph as _build_ag
                            _graph = _build_ag(db, job.id)
                        except Exception:
                            _graph = {}
                        _chains = _corr_chains(db, job.id)
                        _state_exc["exploit_chains_correlated"] = True
                        _state_exc["_last_chain_phase"] = item.phase_id
                        _state_exc["exploit_chains_count"] = len(_chains) if isinstance(_chains, list) else 0
                        _state_exc["attack_graph_nodes"] = _graph.get("node_count", 0) if isinstance(_graph, dict) else 0
                        job.state_data = _state_exc
                        import logging as _exclog
                        _exclog.getLogger(__name__).info(
                            "exploit_chain_correlation scan=%d trigger_phase=%s chains=%d graph_nodes=%d",
                            job.id,
                            item.phase_id,
                            _state_exc["exploit_chains_count"],
                            _state_exc["attack_graph_nodes"],
                        )
            except Exception as _exc_err:
                import logging as _exclog2
                _exclog2.getLogger(__name__).debug("exploit_chain_correlation failed: %s", _exc_err)

        # ── CASCADE FILTER: nmap-vulscan + nmap-vuln findings auto-downgrade ─────
        # nmap-vulscan is pure CVE version-matching (no exploitation). All its
        # findings are downgraded from HIGH→MEDIUM and tagged needs_verification=True
        # so they don't inflate the CRITICAL/HIGH count in the report.
        # This mirrors the pentest principle: port open ≠ CVE confirmed.
        if item.status == "completed" and job and item.tool_name in ("nmap-vulscan", "nmap-vuln"):
            try:
                from app.models.models import Finding as _FindingCF
                _cf_findings = (
                    db.query(_FindingCF)
                    .filter(
                        _FindingCF.scan_job_id == job.id,
                        _FindingCF.tool == item.tool_name,
                        _FindingCF.severity.in_(["critical", "high"]),
                        _FindingCF.verification_status != "confirmed",
                    )
                    .all()
                )
                for _cf in _cf_findings:
                    _cf_details = dict(_cf.details or {})
                    _cf_details["verification_status"] = "hypothesis"
                    _cf_details["needs_verification"] = True
                    _cf_details["cascade_filter"] = (
                        f"Auto-downgraded: {item.tool_name} uses version-matching only — "
                        "no active exploitation. Requires P17 confirmation to restore severity."
                    )
                    _cf_details["original_severity"] = _cf.severity
                    _cf.details = _cf_details
                    _cf.verification_status = "hypothesis"
                    if _cf.severity == "critical":
                        _cf.severity = "high"
                    elif _cf.severity == "high":
                        _cf.severity = "medium"
                    _cf.confidence_score = min(_cf.confidence_score, 20)
                if _cf_findings:
                    import logging as _cfl
                    _cfl.getLogger(__name__).info(
                        "cascade_filter: scan=%d tool=%s downgraded=%d findings",
                        job.id, item.tool_name, len(_cf_findings)
                    )
            except Exception as _cf_err:
                import logging as _cflog2
                _cflog2.getLogger(__name__).debug("cascade_filter failed: %s", _cf_err)

        # ── M1: Crown jewel mid-scan analyzer ────────────────────────────────────
        # After P01 or P02 items complete, identify crown jewel targets and
        # boost their priority across the remaining work queue.
        if item.status == "completed" and job and item.phase_id in ("P01", "P02"):
            try:
                _state = dict(job.state_data or {})
                if not _state.get("crown_jewel_analysis_done"):
                    from app.models.models import ScanWorkItem as _SWI
                    _done_p01p02 = (
                        db.query(_SWI)
                        .filter(
                            _SWI.scan_job_id == job.id,
                            _SWI.phase_id.in_(["P01", "P02"]),
                            _SWI.status.in_(["completed", "done", "failed", "skipped"]),
                        )
                        .count()
                    )
                    if _done_p01p02 >= 3:  # enough recon data to identify crown jewels
                        from app.services.crown_jewel_analyzer import run_crown_jewel_analysis
                        _cj_result = run_crown_jewel_analysis(db, job.id)
                        import logging as _cjlog
                        _cjlog.getLogger(__name__).info(
                            "crown_jewel_analysis scan=%d: %s", job.id, _cj_result
                        )
            except Exception as _cje:
                import logging as _cjlog2
                _cjlog2.getLogger(__name__).debug("crown_jewel_analysis failed: %s", _cje)

        # ── Shared surface memory: propaga credenciais / versões / SANs ────────
        # Ponto #3: descobertas se propagam entre targets do mesmo scan.
        if item.status == "completed" and job:
            try:
                from app.services.cross_target_propagator import (
                    propagate_credential_findings,
                    propagate_certificate_sans,
                )
                _full_result = dict(item.result or {})
                _tool_lower = str(item.tool_name or "").lower()

                # Credenciais: gitleaks/trufflehog → credential stuffing em outros targets
                if _tool_lower in {"gitleaks", "trufflehog", "git-dumper", "h8mail"}:
                    propagate_credential_findings(db, job.id, item.target, item.tool_name, _full_result)

                # Certificado: extrai SANs → novos subdomínios in-scope
                if _tool_lower in {"sslscan", "testssl"}:
                    propagate_certificate_sans(db, job.id, item.target, item.tool_name, _full_result, job)

                # ── Frente E: expansão de superfície (crawl/fuzz → loop) ───────
                # Crawler/spider/fuzzing descobriu páginas → abre, extrai segredos
                # e endpoints, e REINJETA os in-scope como novos alvos de teste.
                if _tool_lower in {
                    "ffuf", "ffuf-content", "ffuf-params", "ffuf-values", "ffuf-post",
                    "feroxbuster", "gobuster", "dirsearch", "katana", "gospider",
                    "hakrawler", "gau", "waybackurls", "linkfinder", "paramspider",
                } and item.target and item.target != "__batch__":
                    from app.services.endpoint_discovery import expand_attack_surface
                    expand_attack_surface(db, job.id, item.target, item.tool_name, _full_result, job)

                # ── Análise estática de JS (endpoints/params/sinks/segredos) ──
                # Após crawl/JS phases. Uma vez por scan. Realimenta endpoints.
                if item.phase_id in ("P03", "P08", "P09") and item.status == "completed":
                    _st_j = dict(job.state_data or {})
                    if not _st_j.get("js_done") and _st_j.get("discovered_endpoints"):
                        from app.services.js_analyzer import run_js_analysis_for_scan
                        _jr = run_js_analysis_for_scan(db, job)
                        _st_j = dict(job.state_data or {})
                        _st_j["js_done"] = True
                        job.state_data = _st_j
                        if _jr.get("findings_created") or _jr.get("endpoints_reseeded"):
                            import logging as _jlog
                            _jlog.getLogger(__name__).info(
                                "js_analyzer scan=%d findings=%s endpoints_reseeded=%s",
                                job.id, _jr.get("findings_created"), _jr.get("endpoints_reseeded"))

                # ── Fase 2: Excessive Data Exposure / Mass Assignment (API) ───
                if item.phase_id in ("P09", "P16") and item.status == "completed":
                    _st_a = dict(job.state_data or {})
                    if not _st_a.get("api_probe_done") and _st_a.get("discovered_endpoints"):
                        from app.services.api_probe import run_api_probe_for_scan
                        _ar = run_api_probe_for_scan(db, job)
                        _st_a = dict(job.state_data or {})
                        _st_a["api_probe_done"] = True
                        job.state_data = _st_a
                        if _ar.get("findings_created"):
                            import logging as _alog
                            _alog.getLogger(__name__).info(
                                "api_probe scan=%d findings=%d", job.id, _ar["findings_created"])

                # ── Fase 2: NoSQL injection (testável sem auth) ───────────────
                # Após descoberta de endpoints com parâmetro. Uma vez por scan.
                if item.phase_id in ("P09", "P16", "P10") and item.status == "completed":
                    _st_n = dict(job.state_data or {})
                    if not _st_n.get("nosql_done") and (_st_n.get("discovered_endpoints")):
                        from app.services.nosql_probe import run_nosql_for_scan
                        _nr = run_nosql_for_scan(db, job)
                        _st_n = dict(job.state_data or {})
                        _st_n["nosql_done"] = True
                        job.state_data = _st_n
                        if _nr.get("findings_created"):
                            import logging as _nlog
                            _nlog.getLogger(__name__).info(
                                "nosql_probe scan=%d confirmados=%d", job.id, _nr["findings_created"])

                # ── Fase 2: BOLA/BFLA autenticado (API #1/#5) ─────────────────
                # Só roda se o scan é AUTENTICADO (auth_config) e após a API/IDOR
                # ter sido mapeada. Uma vez por scan (flag no state).
                if item.phase_id in ("P16", "P19", "P09") and item.status == "completed":
                    _st_b = dict(job.state_data or {})
                    if _st_b.get("auth_config") and not _st_b.get("bola_done"):
                        from app.services.bola_probe import run_bola_for_scan
                        _br = run_bola_for_scan(db, job)
                        _st_b = dict(job.state_data or {})
                        _st_b["bola_done"] = True
                        job.state_data = _st_b
                        if _br.get("findings_created"):
                            import logging as _blog
                            _blog.getLogger(__name__).info(
                                "bola_probe scan=%d confirmados=%d", job.id, _br["findings_created"])
            except Exception as _pe:
                import logging as _plog
                _plog.getLogger(__name__).debug("propagator failed: %s", _pe)

        # ── T1: Evidence gate stage 2 — promote candidate finding to confirmed ──
        # When a verification work item completes, update the original finding.
        if item.status in ("completed", "done", "failed") and job:
            try:
                _meta = dict(item.item_metadata or {})
                _orig_finding_id = _meta.get("verifies_finding_id")
                if _orig_finding_id:
                    from app.models.models import Finding as _Finding
                    _orig = db.query(_Finding).filter(_Finding.id == _orig_finding_id).first()
                    if _orig:
                        if item.status in ("completed", "done"):
                            # Verification succeeded → confirmed
                            _orig.verification_status = "confirmed"
                            _orig_details = dict(_orig.details or {})
                            _orig_details["verification_status"] = "confirmed"
                            _orig_details["verified_by_item_id"] = item.id
                            _orig_details["verified_by_tool"] = item.tool_name
                            _orig_details["needs_verification"] = False
                            # ── Frente B: validação ativa (P21) → PoC reproduzível
                            # + evidência de actions-on-objectives (segura, sem
                            # extração/shell). Mantém status="confirmed".
                            if item.phase_id == "P21":
                                try:
                                    from app.services.exploitation_evidence import (
                                        enrich_confirmed_finding,
                                        propagate_to_vulnerability,
                                    )
                                    _orig.details = _orig_details  # base p/ enrich
                                    _orig_details = enrich_confirmed_finding(_orig, item)
                                    _orig.details = _orig_details
                                    propagate_to_vulnerability(db, _orig, _orig_details)
                                except Exception as _ee:
                                    import logging as _eelog
                                    _eelog.getLogger(__name__).debug(
                                        "exploitation_evidence failed: %s", _ee
                                    )
                            _orig.details = _orig_details
                        else:
                            # Verification tool failed to reproduce → refuted
                            _orig.verification_status = "refuted"
                            _orig_details = dict(_orig.details or {})
                            _orig_details["verification_status"] = "refuted"
                            _orig_details["refuted_by_tool"] = item.tool_name
                            _orig.details = _orig_details
                        db.flush()

                        # ── P21 confirmation → re-correlate exploit chains ────────
                        # A newly-confirmed finding may complete a chain pattern
                        # (e.g., SQLi confirmed + admin panel → full takeover chain).
                        # Re-run correlate_chains() so chains reflect live confirmed state.
                        if item.status in ("completed", "done") and item.phase_id == "P21":
                            try:
                                from app.services.exploit_chain import correlate_chains as _cc_p21
                                _cc_p21(db, job.id)
                            except Exception as _cc_p21_err:
                                import logging as _cc21log
                                _cc21log.getLogger(__name__).debug(
                                    "p21_chain_recorr failed: %s", _cc_p21_err
                                )
                            # ── Frente B: ingere callbacks OOB (interactsh) e
                            # confirma SSRF/RCE/XXE cego via interação out-of-band.
                            try:
                                from app.services.interactsh_callback import (
                                    check_and_confirm_oob_findings as _oob_confirm,
                                )
                                _oob_n = _oob_confirm(db, job.id)
                                if _oob_n:
                                    import logging as _ooblog
                                    _ooblog.getLogger(__name__).info(
                                        "oob: %d finding(s) confirmados por callback OOB (scan=%d)",
                                        _oob_n, job.id,
                                    )
                            except Exception as _oob_err:
                                import logging as _ooblog2
                                _ooblog2.getLogger(__name__).debug(
                                    "oob_confirm failed: %s", _oob_err
                                )
            except Exception as _ve:
                import logging as _vlog
                _vlog.getLogger(__name__).debug("evidence gate stage2 update failed: %s", _ve)

        # ── Target triage: se httpx ou naabu confirma target morto, cancela fila ──
        # ── Target liveness triage — ONLY httpx is authoritative ─────────────────
        # CRITICAL: naabu (SYN port scan) is routinely filtered by Cloudflare/AWS
        # WAF/firewalls. "no ports found" from naabu does NOT mean the target is
        # dead — it usually responds fine on HTTP 443 behind the edge. Killing all
        # HTTP phases (P03-P20, including whatweb/httpx tech detection) based on
        # naabu was skipping live targets en masse. Only httpx (which actually
        # speaks HTTP) can declare a target dead for web-scanning purposes.
        if item.status == "completed" and item.tool_name == "httpx" and job:
            try:
                _result = dict(item.result or {})
                _parsed = _result.get("parsed_result")
                _stdout = str(_result.get("stdout_preview") or "")
                _is_dead = False
                # httpx: parsed_result é lista; vazia OU todos failed=true → morto
                if isinstance(_parsed, list):
                    live = [r for r in _parsed if isinstance(r, dict) and not r.get("failed")]
                    _is_dead = len(live) == 0 and len(_parsed) > 0
                elif not _parsed and not _stdout.strip():
                    _is_dead = True
                if _is_dead:
                    from app.services.scan_work_queue import triage_dead_target as _triage
                    _cancelled = _triage(db, job.id, item.target, reason="httpx_no_http_response")
                    if _cancelled:
                        import logging as _log2
                        _log2.getLogger(__name__).info(
                            "target_triage: cancelled %d items for dead target %s (httpx confirmed no HTTP)",
                            _cancelled, item.target
                        )
            except Exception as _te:
                import logging as _log3
                _log3.getLogger(__name__).debug("triage check failed: %s", _te)

        if job:
            counts = work_queue_counts(db, item.scan_job_id)
            state = dict(job.state_data or {})
            state["work_queue_counts"] = counts

            # ── subdomain_coverage: atualiza a cada 10 items terminados ──────────
            # Para scans work_queue, state_data.subdomain_coverage não é populado
            # pelo workflow LangGraph. Calculamos aqui a cada N completions para que
            # a UI de cobertura mostre progresso real sem overhead por item.
            _cov_update_every = 10
            _cov_last = int(state.get("_cov_last_total") or 0)
            _cov_current = sum(counts.get(s, 0) for s in {"completed", "done", "failed", "timeout", "skipped"})
            if _cov_current - _cov_last >= _cov_update_every or _cov_current == 0:
                try:
                    from sqlalchemy import case as _sa_case, func as _sfunc_cov
                    from app.models.models import ScanWorkItem as _SWI_cov
                    _TERM_COV = {"completed", "done", "failed", "timeout", "skipped"}
                    _ACTIVE_COV = {"dispatched", "running", "submitted", "retry"}
                    # Subdomínios únicos por status (apenas targets individuais)
                    # Using case() instead of func.cast() for boolean→integer conversion
                    _sub_q = (
                        db.query(
                            _SWI_cov.target,
                            _sfunc_cov.sum(
                                _sa_case((_SWI_cov.status.in_(list(_ACTIVE_COV)), 1), else_=0)
                            ).label("active"),
                            _sfunc_cov.sum(
                                _sa_case((_SWI_cov.status == "queued", 1), else_=0)
                            ).label("queued"),
                            _sfunc_cov.sum(
                                _sa_case((_SWI_cov.status.in_(list(_TERM_COV)), 1), else_=0)
                            ).label("terminal"),
                        )
                        .filter(_SWI_cov.scan_job_id == item.scan_job_id, _SWI_cov.target != "__batch__")
                        .group_by(_SWI_cov.target)
                        .all()
                    )
                    _n_scanned = sum(1 for r in _sub_q if int(r.terminal or 0) > 0 and int(r.queued or 0) == 0 and int(r.active or 0) == 0)
                    _n_analyzing = sum(1 for r in _sub_q if int(r.active or 0) > 0)
                    _n_total_wq = len(_sub_q)
                    # active_total usa lista_ativos se disponível (maior cobertura)
                    _lista = list(state.get("lista_ativos") or [])
                    _active_total = max(_n_total_wq, len(_lista))
                    state["subdomain_coverage"] = {
                        "active_total": _active_total,
                        "scanned": _n_scanned,
                        "analyzing": _n_analyzing,
                        "total_work_targets": _n_total_wq,
                    }
                    state["_cov_last_total"] = _cov_current
                except Exception:
                    pass

            job.state_data = state

            # ── mission_progress: baseado em work items reais, não phase_ledger ──
            # Terminal = completed | done | failed | timeout | skipped
            # Não terminais = queued | retry | dispatched | running | submitted
            # Progresso = terminais / total (cap 99% — 100% reservado para "scan completed")
            # Blocked items are NOT done — they are pending (awaiting gate phase).
            # Progress = truly terminal / (total - still-blocked)
            # This prevents progress from appearing 90% done at scan start.
            _total_items = sum(counts.values())
            _blocked_items = counts.get("blocked", 0)
            _effective_total = max(1, _total_items - _blocked_items)
            _terminal_statuses = {"completed", "done", "failed", "timeout", "skipped"}
            _done_items = sum(counts.get(s, 0) for s in _terminal_statuses)
            if _total_items > 0:
                _pct = min(99, int(_done_items / _effective_total * 99))
                _current_pct = int(job.mission_progress or 0)
                # Always apply the real work-queue progress.
                # The old "never regress" rule caused the bug: when the LangGraph
                # engine prematurely set mission_progress=100, it would never
                # be corrected by subsequent WQ completions (WQ pct < 100).
                # Now we always write the real pct unless the scan is already
                # marked completed (where 100% is correct and final).
                if job.status == "running" and abs(_pct - _current_pct) > 1:
                    job.mission_progress = _pct

            db.add(ScanLog(
                scan_job_id=item.scan_job_id,
                source="work-queue",
                level="INFO",
                message=(
                    f"work_item_finish id={item.id} phase={item.phase_id} target={item.target} "
                    f"tool={item.tool_name} status={item.status} kali_status={raw_status}"
                    f" progress={job.mission_progress}%"
                    + (f" findings={findings_created}" if findings_created else "")
                ),
            ))
        db.commit()
        if item.status == "retry":
            dispatch_scan_work_items.delay(item.scan_job_id)
        else:
            dispatch_scan_work_items.apply_async(args=[item.scan_job_id], countdown=1)
        return {"id": item.id, "status": item.status}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        item = db.query(ScanWorkItem).filter(ScanWorkItem.id == item_id).first()
        if item:
            item.last_error = str(exc)[:2000]
            # If max attempts exceeded, mark failed and release semaphore
            _over_limit = int(item.attempts or 0) >= int(item.max_attempts or 2)
            if _over_limit:
                item.status = "failed"
                item.finished_at = datetime.utcnow()
                item.lease_until = None
                # ── Camada 0: semaphore leak fix — release slot on exception ──
                try:
                    from app.services.scan_work_queue import kali_inflight_release as _release_poll
                    _release_poll(str(item.resource_class or "light"), 1)
                except Exception:
                    pass
            else:
                item.lease_until = datetime.utcnow() + timedelta(seconds=120)
            item.updated_at = datetime.utcnow()
            db.commit()
            if not _over_limit:
                poll_scan_work_item.apply_async(args=[item.id], countdown=30)
        return {"id": item_id, "status": "poll_error", "error": str(exc)}
    finally:
        db.close()


@celery.task(bind=True, name="run_scan_job_scheduled", queue=SCAN_SCHEDULED_QUEUE)
def run_scan_job_scheduled(self, scan_id: int):
    """
    Task para scans AGENDADOS (execucao periodica/batch).
    Consumida exclusivamente pelos workers 'worker_scheduled' no docker-compose.
    Prioridade normal | concurrency=2 | cobertura completa.
    """
    return _run_scan_with_retry(self, scan_id, "scheduled")


# Alias retroativo — usado por fallback síncrono quando a fila nao esta disponivel
def run_scan_job(scan_id: int):
    """Compatibilidade retroativa: infere o modo pelo campo 'mode' do ScanJob."""
    db: Session = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        mode: ScanMode = "scheduled" if job and job.mode == "scheduled" else "unit"
    finally:
        db.close()
    return _execute_scan(scan_id, mode)


# ──────────────────────────────────────────────────────────────────────────────
# Scheduler tick — verifica ScheduledScan devidos e dispara ScanJobs
# Executado a cada minuto pelo Celery Beat
# ──────────────────────────────────────────────────────────────────────────────


@celery.task(bind=True, name="create_vulnerability_learning_task", queue="worker.unit.reporting")
def create_vulnerability_learning_task(self, owner_id: int, urls_text: str):
    """Background task to process vulnerability learning from URLs.
    
    This prevents timeouts by running the expensive operations (HTTP fetches, LLM calls)
    in a background worker instead of blocking the API endpoint.
    """
    from app.models.models import User, VulnerabilityLearning
    from app.services.vulnerability_learning_service import (
        create_vulnerability_learning,
        serialize_vulnerability_learning,
    )
    
    db = SessionLocal()
    try:
        owner = db.query(User).filter(User.id == owner_id).first()
        if not owner:
            return {"error": f"User {owner_id} not found"}
        
        rows = create_vulnerability_learning(db, owner, urls_text)
        return {
            "success": True,
            "item": serialize_vulnerability_learning(rows[0]),
            "items": [serialize_vulnerability_learning(r) for r in rows],
            "items_count": len(rows),
        }
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Falha no aprendizado: {exc}"}
    finally:
        db.close()


@celery.task(bind=True, name="create_github_hackerone_learning_task", queue="worker.unit.reporting")
def create_github_hackerone_learning_task(
    self,
    owner_id: int,
    min_per_phase: int = 50,
    min_per_skill: int = 150,
    max_created: int = 10_000,
    purge_source: bool = True,
):
    """Seed accepted operational learnings from public GitHub HackerOne indexes."""
    import importlib.util
    from pathlib import Path
    from app.graph.mission import PENTEST_PHASES

    script_path = Path("/app/scripts/crawl_github_hackerone_learnings.py")
    spec = importlib.util.spec_from_file_location("crawl_github_hackerone_learnings", script_path)
    if spec is None or spec.loader is None:
        return {"error": f"Nao foi possivel carregar {script_path}"}
    crawler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(crawler)

    db = SessionLocal()
    try:
        reports = crawler.crawl_github_hackerone_reports()
        purged = crawler.purge_crawler_learnings(db) if purge_source else 0
        before_phase, before_skill = crawler._counts(db)
        created = crawler.seed(
            db,
            reports,
            min_per_phase=max(0, int(min_per_phase or 0)),
            min_per_skill=max(0, int(min_per_skill or 0)),
            owner_id=owner_id,
            max_created=max(1, int(max_created or 10_000)),
        )
        mcp_ingested = 0
        mcp_url = str(settings.mcp_server_url or "http://mcp_server:3000").rstrip("/")
        mcp_purged = crawler._purge_mcp_source(mcp_url) if purge_source else 0
        mcp_ingested = crawler._ingest_mcp_bulk(created, mcp_url)
        after_phase, after_skill = crawler._counts(db)
        return {
            "success": True,
            "reports_crawled": len(reports),
            "purged": purged,
            "created": len(created),
            "mcp_ingested": mcp_ingested,
            "mcp_purged": mcp_purged,
            "max_created": int(max_created or 10_000),
            "min_per_phase": int(min_per_phase or 0),
            "min_per_skill": int(min_per_skill or 0),
            "phase_counts_before_min": min(before_phase.get(str(p.get("id")), 0) for p in PENTEST_PHASES),
            "phase_counts_after_min": min(after_phase.get(str(p.get("id")), 0) for p in PENTEST_PHASES),
            "skill_counts_before_min": min(before_skill.get(skill_id, 0) for skill_id in crawler._skill_catalog()),
            "skill_counts_after_min": min(after_skill.get(skill_id, 0) for skill_id in crawler._skill_catalog()),
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Falha no crawler GitHub/HackerOne: {exc}"}
    finally:
        db.close()
