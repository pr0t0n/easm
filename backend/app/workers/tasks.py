import os
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.graph.workflow import build_graph, initial_state
from app.models.models import AppSetting, Finding, ScanJob, ScanLog, WorkerHeartbeat
from app.services.ai_recommendation_service import generate_portuguese_recommendations
from app.services.audit_service import log_audit
from app.services.cve_enrichment_service import enrichment_service
from app.services.tool_adapters import run_tool_execution
from app.workers.celery_app import celery
from app.workers.worker_groups import (
    UNIT_WORKER_GROUPS,
    SCHEDULED_WORKER_GROUPS,
    SCAN_UNIT_QUEUE,
    SCAN_SCHEDULED_QUEUE,
    ScanMode,
    find_group_by_tool,
    group_queue,
)


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

    normalized = {
        "total_steps": total_steps,
        "steps_done": steps_done,
        "steps_success": steps_success,
        "tools_attempted": tools_attempted,
        "tools_success": tools_success,
    }
    return max(0, min(100, progress)), normalized


# ──────────────────────────────────────────────────────────────────────────────
# Helpers de resultado por execucao de ferramenta
# ──────────────────────────────────────────────────────────────────────────────

def _worker_result(group: str, tool: str, target: str, mode: ScanMode, params: dict | None = None):
    execution = run_tool_execution(tool_name=tool, target=target, scan_mode=mode)
    return {
        "ok": execution.get("status") == "executed",
        "group": group,
        "tool": tool,
        "target": target,
        "mode": mode,
        "params": params or {},
        "queue": execution.get("worker", group_queue(group, mode)),
        "status": execution.get("status", "error"),
        "command": execution.get("command", ""),
        "return_code": execution.get("return_code"),
        "stdout": execution.get("stdout", ""),
        "stderr": execution.get("stderr", ""),
        "output": execution.get("output", ""),
        "open_ports": execution.get("open_ports", []),
    }


def _worker_name(scan_mode: ScanMode) -> str:
    # Em container, HOSTNAME reflete o nome unico do worker process.
    return os.getenv("HOSTNAME", f"worker-{scan_mode}")


def _touch_worker_heartbeat(
    db: Session,
    scan_mode: ScanMode,
    status: str,
    scan_id: int | None = None,
    task_name: str | None = None,
):
    name = _worker_name(scan_mode)
    row = db.query(WorkerHeartbeat).filter(WorkerHeartbeat.worker_name == name).first()
    if not row:
        row = WorkerHeartbeat(worker_name=name, mode=scan_mode)
        db.add(row)
    row.mode = scan_mode
    row.status = status
    row.current_scan_id = scan_id
    row.last_task_name = task_name
    row.last_seen_at = datetime.utcnow()


def _get_scan_retry_policy(db: Session, owner_id: int) -> tuple[bool, int, int]:
    rows = (
        db.query(AppSetting)
        .filter(
            AppSetting.owner_id == owner_id,
            AppSetting.key.in_(["scan_retry_enabled", "scan_retry_max_attempts", "scan_retry_delay_seconds"]),
        )
        .all()
    )
    values = {row.key: row.value for row in rows}
    enabled = str(values.get("scan_retry_enabled", "true")).lower() == "true"
    try:
        max_attempts = int(values.get("scan_retry_max_attempts", "3"))
    except (TypeError, ValueError):
        max_attempts = 3
    try:
        delay_seconds = int(values.get("scan_retry_delay_seconds", "45"))
    except (TypeError, ValueError):
        delay_seconds = 45
    return enabled, max(1, min(10, max_attempts)), max(5, min(3600, delay_seconds))


# ──────────────────────────────────────────────────────────────────────────────
# Tasks de ferramentas — UNITARIOS (scan.unit / worker.unit.*)
# ──────────────────────────────────────────────────────────────────────────────

@celery.task(name="worker.unit.recon.execute", queue="worker.unit.recon")
def unit_recon_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("recon", tool, target, "unit", params)


@celery.task(name="worker.unit.fuzzing.execute", queue="worker.unit.fuzzing")
def unit_fuzzing_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("fuzzing", tool, target, "unit", params)


@celery.task(name="worker.unit.vuln.execute", queue="worker.unit.vuln")
def unit_vuln_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("vuln", tool, target, "unit", params)


@celery.task(name="worker.unit.code_js.execute", queue="worker.unit.code_js")
def unit_code_js_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("code_js", tool, target, "unit", params)


@celery.task(name="worker.unit.api.execute", queue="worker.unit.api")
def unit_api_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("api", tool, target, "unit", params)


@celery.task(name="worker.unit.crawler.execute", queue="worker.unit.crawler")
def unit_crawler_execute(tool: str, target: str, params: dict | None = None):
    """httpx (probe vivo), katana (crawling rapido) e uro (URL dedup) — modo unitario."""
    return _worker_result("crawler", tool, target, "unit", params)


@celery.task(name="worker.unit.osint.execute", queue="worker.unit.osint")
def unit_osint_execute(tool: str, target: str, params: dict | None = None):
    """theHarvester, shodan-cli, whatweb, urlscan-cli e subjack — OSINT rapido e exposicao externa."""
    return _worker_result("osint", tool, target, "unit", params)


@celery.task(name="worker.unit.dispatch", queue=SCAN_UNIT_QUEUE)
def unit_dispatch_tool(tool: str, target: str, params: dict | None = None):
    group = find_group_by_tool(tool, mode="unit")
    task_name = f"worker.unit.{group}.execute"
    return celery.send_task(task_name, kwargs={"tool": tool, "target": target, "params": params or {}}).id


# ──────────────────────────────────────────────────────────────────────────────
# Tasks de ferramentas — AGENDADOS (scan.scheduled / worker.scheduled.*)
# ──────────────────────────────────────────────────────────────────────────────

@celery.task(name="worker.scheduled.recon.execute", queue="worker.scheduled.recon")
def scheduled_recon_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("recon", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.fuzzing.execute", queue="worker.scheduled.fuzzing")
def scheduled_fuzzing_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("fuzzing", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.vuln.execute", queue="worker.scheduled.vuln")
def scheduled_vuln_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("vuln", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.code_js.execute", queue="worker.scheduled.code_js")
def scheduled_code_js_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("code_js", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.api.execute", queue="worker.scheduled.api")
def scheduled_api_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("api", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.crawler.execute", queue="worker.scheduled.crawler")
def scheduled_crawler_execute(tool: str, target: str, params: dict | None = None):
    """httpx, katana, waymore, uro e gowitness — probe + crawl + screenshots (modo agendado)."""
    return _worker_result("crawler", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.fingerprint.execute", queue="worker.scheduled.fingerprint")
def scheduled_fingerprint_execute(tool: str, target: str, params: dict | None = None):
    """wappalyzer, whatweb, webanalyze e cmsmap — stack tech fingerprinting (Sn1per + modo agendado)."""
    return _worker_result("fingerprint", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.osint.execute", queue="worker.scheduled.osint")
def scheduled_osint_execute(tool: str, target: str, params: dict | None = None):
    """theHarvester, h8mail, metagoofil, urlscan-cli, subjack, shodan-cli (Sn1per osint.sh)."""
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
    try:
        _touch_worker_heartbeat(db, scan_mode=scan_mode, status="alive")
        db.commit()

        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            return {"ok": False, "error": "scan not found", "retryable": False}

        if job.status == "stopped":
            return {"ok": False, "error": "scan_stopped", "retryable": False}

        if job.compliance_status != "approved":
            job.status = "blocked"
            db.add(ScanLog(
                scan_job_id=scan_id,
                source="compliance",
                level="WARNING",
                message="Execucao bloqueada por gate de compliance",
            ))
            log_audit(
                db,
                event_type="scan.execution_blocked",
                message="Worker interrompeu execucao: compliance nao aprovado",
                scan_job_id=scan_id,
                level="WARNING",
                metadata={"compliance_status": job.compliance_status, "scan_mode": scan_mode},
            )
            _touch_worker_heartbeat(db, scan_mode=scan_mode, status="idle", scan_id=None, task_name=None)
            db.commit()
            return {"ok": False, "error": "compliance_not_approved", "retryable": False}

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
        log_audit(
            db,
            event_type="scan.execution_started",
            message=f"Execucao do scan [{scan_mode}] iniciada",
            scan_job_id=job.id,
            metadata={"scan_mode": scan_mode},
        )
        db.commit()

        app = build_graph(mode=scan_mode)
        known_patterns = [
            row[0]
            for row in db.query(Finding.title).filter(Finding.title.isnot(None)).distinct().limit(500).all()
            if row and row[0]
        ]
        state = initial_state(
            scan_id=job.id,
            target=job.target_query,
            scan_mode=scan_mode,
            known_vulnerability_patterns=known_patterns,
        )
        recursion_limit = max(100, len(state.get("mission_items", [])) * 4)
        final_state = app.invoke(
            state,
            config={
                "configurable": {"thread_id": f"scan-{job.id}"},
                "recursion_limit": recursion_limit,
            },
        )

        db.refresh(job)
        if job.status == "stopped":
            db.add(ScanLog(scan_job_id=job.id, source="worker", level="WARNING", message="Execucao interrompida apos solicitacao de stop"))
            _touch_worker_heartbeat(db, scan_mode=scan_mode, status="idle", scan_id=None, task_name=None)
            db.commit()
            return {"ok": False, "error": "scan_stopped", "retryable": False}

        for line in final_state.get("logs_terminais", []):
            db.add(ScanLog(scan_job_id=job.id, source="graph", level="INFO", message=line))

        seen_findings: set[tuple[str, str, str, str]] = set()
        for vuln in final_state.get("vulnerabilidades_encontradas", []):
            source_worker = vuln.get("source_worker", "vuln")
            details = dict(vuln)

            dedupe_key = (
                str(vuln.get("title") or "").strip().lower(),
                str(vuln.get("severity") or "low").strip().lower(),
                str(source_worker).strip().lower(),
                str((details.get("asset") or details.get("port") or details.get("step") or "")).strip().lower(),
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

            cve_id = enrichment_service.extract_cve(details, title=vuln.get("title"))
            if cve_id:
                details.update(enrichment_service.enrich(cve_id))

            db.add(
                Finding(
                    scan_job_id=job.id,
                    title=vuln.get("title", "Potential issue"),
                    severity=vuln.get("severity", "low"),
                    cve=cve_id,
                    confidence_score=int(vuln.get("confidence_score", 50) or 50),
                    risk_score=vuln.get("risk_score", 1),
                    details={"source_worker": source_worker, "scan_mode": scan_mode, **details},
                )
            )

        progress, progress_ctx = _progress_from_state(final_state)
        final_state["mission_progress_context"] = progress_ctx
        job.state_data = final_state
        job.mission_progress = progress
        job.current_step = "100. Relatorio Final JSON"
        job.status = "completed"
        job.last_error = None
        job.next_retry_at = None
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
            next_retry_at = datetime.utcnow() + timedelta(seconds=delay_seconds)
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
                        f"novo retry em {delay_seconds}s"
                    ),
                )
            )
            db.commit()
            raise task_ctx.retry(exc=Exception(result.get("error", "scan failed")), countdown=delay_seconds)

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

@celery.task(bind=True, name="run_scan_job_unit", queue=SCAN_UNIT_QUEUE)
def run_scan_job_unit(self, scan_id: int):
    """
    Task para scans UNITARIOS (execucao manual/pontual).
    Consumida exclusivamente pelos workers 'worker_unit' no docker-compose.
    Prioridade alta | concurrency=1 | escopo focado.
    """
    return _run_scan_with_retry(self, scan_id, "unit")


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
