from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.graph.workflow import build_graph, initial_state
from app.models.models import Finding, ScanJob, ScanLog
from app.services.ai_recommendation_service import generate_portuguese_recommendations
from app.services.audit_service import log_audit
from app.workers.celery_app import celery
from app.workers.worker_groups import WORKER_GROUPS, find_group_by_tool, group_queue


def _worker_result(group: str, tool: str, target: str, params: dict | None = None):
    return {
        "ok": True,
        "group": group,
        "tool": tool,
        "target": target,
        "params": params or {},
        "queue": group_queue(group),
        "status": "executed",
    }


@celery.task(name="worker.recon.execute", queue="worker.recon")
def recon_worker_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("recon", tool, target, params)


@celery.task(name="worker.fuzzing.execute", queue="worker.fuzzing")
def fuzzing_worker_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("fuzzing", tool, target, params)


@celery.task(name="worker.vuln.execute", queue="worker.vuln")
def vuln_worker_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("vuln", tool, target, params)


@celery.task(name="worker.code_js.execute", queue="worker.code_js")
def code_js_worker_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("code_js", tool, target, params)


@celery.task(name="worker.api.execute", queue="worker.api")
def api_worker_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("api", tool, target, params)


@celery.task(name="worker.dispatch")
def dispatch_tool_execution(tool: str, target: str, params: dict | None = None):
    group = find_group_by_tool(tool)
    task_name = f"worker.{group}.execute"
    return celery.send_task(task_name, kwargs={"tool": tool, "target": target, "params": params or {}}).id


@celery.task(name="worker.groups")
def list_worker_groups():
    return WORKER_GROUPS


@celery.task(name="run_scan_job")
def run_scan_job(scan_id: int):
    db: Session = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            return {"error": "scan not found"}

        if job.compliance_status != "approved":
            job.status = "blocked"
            db.add(ScanLog(scan_job_id=scan_id, source="compliance", level="WARNING", message="Execucao bloqueada por gate de compliance"))
            log_audit(
                db,
                event_type="scan.execution_blocked",
                message="Worker interrompeu execucao: compliance nao aprovado",
                scan_job_id=scan_id,
                level="WARNING",
                metadata={"compliance_status": job.compliance_status},
            )
            db.commit()
            return {"ok": False, "error": "compliance_not_approved"}

        job.status = "running"
        job.current_step = "Iniciando grafo"
        db.add(ScanLog(scan_job_id=job.id, source="worker", level="INFO", message="Execucao iniciada"))
        log_audit(db, event_type="scan.execution_started", message="Execucao do scan iniciada", scan_job_id=job.id)
        db.commit()

        app = build_graph()
        known_patterns = [
            row[0]
            for row in db.query(Finding.title).filter(Finding.title.isnot(None)).distinct().limit(500).all()
            if row and row[0]
        ]
        state = initial_state(scan_id=job.id, target=job.target_query, known_vulnerability_patterns=known_patterns)
        final_state = app.invoke(state, config={"configurable": {"thread_id": f"scan-{job.id}"}})

        for line in final_state.get("logs_terminais", []):
            db.add(ScanLog(scan_job_id=job.id, source="graph", level="INFO", message=line))

        for vuln in final_state.get("vulnerabilidades_encontradas", []):
            source_worker = vuln.get("source_worker", "vuln")
            details = dict(vuln)
            recommendations = generate_portuguese_recommendations(vuln, known_patterns=known_patterns)
            details.update(recommendations)
            db.add(
                Finding(
                    scan_job_id=job.id,
                    title=vuln.get("title", "Potential issue"),
                    severity=vuln.get("severity", "low"),
                    risk_score=vuln.get("risk_score", 1),
                    details={"source_worker": source_worker, **details},
                )
            )

        job.state_data = final_state
        job.mission_progress = min(final_state.get("mission_index", 0), 100)
        job.current_step = "100. Relatorio Final JSON"
        job.status = "completed"
        db.add(ScanLog(scan_job_id=job.id, source="worker", level="INFO", message="Execucao finalizada"))
        log_audit(
            db,
            event_type="scan.execution_completed",
            message="Execucao concluida com sucesso",
            scan_job_id=job.id,
            metadata={
                "discovered_ports": final_state.get("discovered_ports", []),
                "pending_port_tests": final_state.get("pending_port_tests", []),
            },
        )
        db.commit()
        return {"ok": True, "scan_id": scan_id}
    except Exception as exc:
        db.rollback()
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if job:
            job.status = "failed"
            db.add(ScanLog(scan_job_id=job.id, source="worker", level="ERROR", message=str(exc)))
            log_audit(
                db,
                event_type="scan.execution_failed",
                message="Execucao falhou",
                scan_job_id=job.id,
                level="ERROR",
                metadata={"error": str(exc)},
            )
            db.commit()
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()
