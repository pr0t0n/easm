import os
import threading
import time
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.graph.workflow import build_graph, initial_state
from app.models.models import AppSetting, Finding, ScanJob, ScanLog, ScheduledScan, WorkerHeartbeat
from app.services.ai_recommendation_service import generate_portuguese_recommendations
from app.services.audit_service import log_audit
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
        delay_seconds = int(values.get("scan_retry_delay_seconds", "10"))
    except (TypeError, ValueError):
        delay_seconds = 10
    return enabled, max(1, min(10, max_attempts)), max(5, min(3600, delay_seconds))


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
        "2. Analise de Vulnerabilidade", 
        "3. OSINT"
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
        db.add(ScanLog(
            scan_job_id=job.id,
            source="worker",
            level="INFO",
            message="Execucao em andamento: ferramentas como nuclei/nmap podem levar varios minutos por alvo.",
        ))
        db.add(ScanLog(
            scan_job_id=job.id,
            source="worker.plan",
            level="INFO",
            message=(
                "PLANO DE EXECUCAO:\n"
                "  1️⃣  Reconhecimento - Descoberta de hosts, portas, tecnologias e WAF\n"
                "  2️⃣  Analise de Vulnerabilidade - Nuclei, ESM Hunter, Wapiti, Nmap Vulscan\n"
                "  3️⃣  OSINT - Consultas OSINT, Shodan, certificados SSL\n"
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

        stop_pulse = _start_scan_progress_pulse(scan_id=job.id, scan_mode=scan_mode, interval_seconds=20)

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

        seen_findings: set[tuple[str, str, str, str]] = set()
        for vuln in final_state.get("vulnerabilidades_encontradas", []):
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

            db.add(
                Finding(
                    scan_job_id=job.id,
                    title=vuln.get("title", "Potential issue"),
                    severity=vuln.get("severity", "low"),
                    cve=cve_id,
                    confidence_score=int(vuln.get("confidence_score", 50) or 50),
                    risk_score=vuln.get("risk_score", 1),
                    details=flattened_details,
                )
            )

        progress, progress_ctx = _progress_from_state(final_state)
        final_state["mission_progress_context"] = progress_ctx

        # ── EASM: propaga campos dos agentes 4 e 5 para report_v2 ─────────────
        existing_report_v2 = (job.state_data or {}).get("report_v2") or {}
        existing_report_v2.update({
            "easm_rating":        final_state.get("easm_rating") or {},
            "fair_decomposition": final_state.get("fair_decomposition") or {},
            "executive_summary":  final_state.get("executive_summary") or "",
        })
        final_state["report_v2"] = existing_report_v2
        # ───────────────────────────────────────────────────────────────────────

        job.state_data = final_state
        job.mission_progress = progress
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
                f"EXECUCAO EASM CONCLUIDA COM SUCESSO!\n"
                f"\n"
                f"PIPELINE 5 AGENTES:\n"
                f"{mission_summary}\n"
                f"\n"
                f"RESUMO:\n"
                f"  • Vulnerabilidades encontradas: {len(final_state.get('vulnerabilidades_encontradas', []))}\n"
                f"  • Portas descobertas: {len(final_state.get('discovered_ports', []))}\n"
                f"  • Ativos mapeados: {len(final_state.get('lista_ativos', []))}\n"
                f"  • Rating EASM: {easm_rating.get('score', 'N/A')}/100 (Grau {easm_rating.get('grade', 'N/A')})\n"
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


# ──────────────────────────────────────────────────────────────────────────────
# Scheduler tick — verifica ScheduledScan devidos e dispara ScanJobs
# Executado a cada minuto pelo Celery Beat
# ──────────────────────────────────────────────────────────────────────────────

@celery.task(name="scheduler.tick")
def scheduler_tick():
    """
    Roda a cada minuto (via Celery Beat).
    Para cada ScheduledScan enabled=True, verifica se o horário configurado
    bate com o minuto atual (fuso America/Sao_Paulo) e, se ainda não executou
    neste slot (last_run_at), cria um ScanJob e o envia para a fila scheduled.
    """
    from zoneinfo import ZoneInfo

    tz = ZoneInfo("America/Sao_Paulo")
    now = datetime.now(tz)
    current_hhmm = now.strftime("%H:%M")
    current_dow = now.strftime("%A").lower()   # monday, tuesday, …
    current_dom = now.day                      # 1-31

    db: Session = SessionLocal()
    try:
        schedules = db.query(ScheduledScan).filter(ScheduledScan.enabled.is_(True)).all()
        fired = 0
        for sched in schedules:
            if sched.run_time != current_hhmm:
                continue

            # Filtro por dia da semana (frequency=weekly) ou dia do mês (monthly)
            freq = (sched.frequency or "daily").lower()
            if freq == "weekly":
                if (sched.day_of_week or "").lower() != current_dow:
                    continue
            elif freq == "monthly":
                if sched.day_of_month != current_dom:
                    continue
            # daily — sem filtro adicional

            # Idempotência: já disparou neste slot (mesmo minuto)?
            if sched.last_run_at is not None:
                from zoneinfo import ZoneInfo as _ZI
                slot_start = now.replace(second=0, microsecond=0)
                last_run_local = sched.last_run_at.replace(tzinfo=_ZI("UTC")).astimezone(tz)
                if last_run_local >= slot_start:
                    continue

            # Determina o owner (usa o primeiro owner do schedule)
            owner_id = sched.owner_id

            # Cria um ScanJob para cada target (separados por ; ou ,)
            raw_targets = [t.strip() for t in sched.targets_text.replace(",", ";").split(";") if t.strip()]
            if not raw_targets:
                continue

            # Agrupa todos os targets numa única query (compatível com o fluxo existente)
            target_query = "; ".join(raw_targets)

            job = ScanJob(
                owner_id=owner_id,
                access_group_id=sched.access_group_id,
                target_query=target_query,
                status="pending",
                mode="scheduled",
                compliance_status="approved",
                current_step="Aguardando worker",
                state_data={},
            )
            db.add(job)
            db.flush()  # obtém job.id antes do commit

            db.add(ScanLog(
                scan_job_id=job.id,
                source="scheduler",
                level="INFO",
                message=(
                    f"Scan agendado disparado automaticamente | "
                    f"schedule_id={sched.id} | freq={freq} | run_time={sched.run_time}"
                ),
            ))

            # Atualiza last_run_at (UTC) para idempotência
            sched.last_run_at = datetime.utcnow()
            db.add(sched)
            db.commit()

            # Envia para a fila do worker scheduled
            celery.send_task(
                "run_scan_job_scheduled",
                kwargs={"scan_id": job.id},
                queue=SCAN_SCHEDULED_QUEUE,
            )
            fired += 1

        return {"ok": True, "checked": len(schedules), "fired": fired, "slot": current_hhmm}
    except Exception as exc:
        db.rollback()
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()

