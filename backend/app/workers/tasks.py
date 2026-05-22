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
                    # Também atualiza mission_progress em tempo real
                    total = max(1, len(mission_items))
                    job.mission_progress = int(round(min(mi, total) / total * 100))
                
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


@celery.task(bind=True, name="run_scan_target_subset", queue=SCAN_UNIT_QUEUE)
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
