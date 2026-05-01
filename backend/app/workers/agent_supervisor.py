"""Agent supervisor: orquestra execução de agentes via Celery.

Coordena:
1. Seleção de fases a executar
2. Dispatch de agentes para fila
3. Monitoramento de progresso
4. Validação de completude
5. Retry automático com backoff
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.agents import create_phase_execution_plan, get_agents_for_execution
from app.db.session import SessionLocal
from app.models.models import ScanJob
from app.workers.agent_dispatcher import (
    submit_agents_for_phase,
    validate_phase_completion,
    get_queue_status,
)
from app.workers.celery_app import celery

logger = logging.getLogger(__name__)


class AgentSupervisor:
    """Supervisiona execução de agentes com orquestração via Celery."""

    def __init__(self, scan_id: int, db: Session | None = None):
        self.scan_id = scan_id
        self.db = db or SessionLocal()
        self.scan: ScanJob | None = None
        self.phase_plan: list[str] = []
        self.phase_results: dict[str, dict[str, Any]] = {}
        self.retry_counts: dict[str, int] = {}
        self.max_retries = 2
        self.started_at = datetime.utcnow().isoformat()

        self._load_scan()

    def _load_scan(self) -> None:
        """Carrega dados do scan."""
        self.scan = self.db.query(ScanJob).filter(ScanJob.id == self.scan_id).first()
        if not self.scan:
            raise ValueError(f"Scan {self.scan_id} not found")

    def create_execution_plan(self) -> list[str]:
        """Cria plano de fases críticas a executar.

        Retorna lista ordenada de fases por prioridade.
        """
        self.phase_plan = create_phase_execution_plan()
        logger.info(f"Created execution plan for scan {self.scan_id}: {len(self.phase_plan)} phases")
        return self.phase_plan

    def submit_phase(self, phase_id: str) -> str:
        """Submete agentes para uma fase.

        Retorna task_id da execução.
        """
        if not self.scan:
            raise RuntimeError("Scan not loaded")

        logger.info(f"Submitting phase {phase_id} for scan {self.scan_id}")

        task_id = submit_agents_for_phase(self.scan_id, phase_id)
        self.phase_results[phase_id] = {
            "task_id": task_id,
            "status": "submitted",
            "submitted_at": datetime.utcnow().isoformat(),
            "retry_count": 0,
        }

        return task_id

    def check_phase_completion(self, phase_id: str) -> dict[str, Any]:
        """Valida se uma fase foi completada.

        Retorna resultado da validação.
        """
        from app.graph.mission import PENTEST_PHASES
        from app.models.models import ExecutedToolRun

        # Query tools executed for this phase
        tool_runs = self.db.query(ExecutedToolRun).filter(
            ExecutedToolRun.scan_job_id == self.scan_id
        ).all()

        executed_tools = {str(run.tool_name).lower() for run in tool_runs if run.status == "success"}

        # Get expected tools for phase
        phase_def = next((p for p in PENTEST_PHASES if p["id"] == phase_id), None)
        if not phase_def:
            return {"error": f"Phase {phase_id} not found"}

        expected_tools = set(str(t).lower() for t in phase_def.get("tools") or [])
        mandatory_count = max(1, int(len(expected_tools) * 0.66))
        mandatory_tools = sorted(list(expected_tools))[:mandatory_count]

        missing = [t for t in mandatory_tools if t not in executed_tools]
        all_done = len(missing) == 0

        result = {
            "phase": phase_id,
            "scan_id": self.scan_id,
            "all_mandatory_executed": all_done,
            "executed_count": len(executed_tools),
            "expected_count": len(expected_tools),
            "mandatory_count": len(mandatory_tools),
            "missing_tools": missing,
            "completion_status": "complete" if all_done else "incomplete",
        }

        self.phase_results[phase_id] = {
            **self.phase_results.get(phase_id, {}),
            "validation": result,
            "status": "complete" if all_done else "incomplete",
            "completed_at": datetime.utcnow().isoformat(),
        }

        return result

    def should_retry_phase(self, phase_id: str) -> bool:
        """Determina se uma fase deve ser retentada.

        Retorna True se:
        - Não foi completada
        - Ainda há retries disponíveis
        """
        result = self.phase_results.get(phase_id, {})
        validation = result.get("validation", {})

        # Se já foi completada, não retenta
        if validation.get("all_mandatory_executed"):
            return False

        # Se atingiu limite de retries, não retenta
        retry_count = self.retry_counts.get(phase_id, 0)
        if retry_count >= self.max_retries:
            logger.warning(f"Phase {phase_id} max retries reached ({self.max_retries})")
            return False

        return True

    def retry_phase(self, phase_id: str) -> str | None:
        """Retenta execução de uma fase.

        Retorna task_id se retentada, None se não pode.
        """
        if not self.should_retry_phase(phase_id):
            return None

        retry_count = self.retry_counts.get(phase_id, 0)
        self.retry_counts[phase_id] = retry_count + 1

        logger.info(f"Retrying phase {phase_id} (attempt {retry_count + 1}/{self.max_retries})")

        task_id = self.submit_phase(phase_id)
        self.phase_results[phase_id]["retry_count"] = retry_count + 1
        return task_id

    def get_execution_summary(self) -> dict[str, Any]:
        """Retorna sumário geral de execução."""
        complete_phases = [
            p
            for p, result in self.phase_results.items()
            if result.get("validation", {}).get("all_mandatory_executed")
        ]

        incomplete_phases = [
            p
            for p, result in self.phase_results.items()
            if not result.get("validation", {}).get("all_mandatory_executed")
        ]

        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "current_time": datetime.utcnow().isoformat(),
            "total_phases_planned": len(self.phase_plan),
            "phases_completed": len(complete_phases),
            "phases_incomplete": len(incomplete_phases),
            "complete_phases": complete_phases,
            "incomplete_phases": incomplete_phases,
            "phase_results": self.phase_results,
            "retry_counts": self.retry_counts,
            "queue_status": get_queue_status(self.scan_id),
        }

    def execute_sequential(self) -> dict[str, Any]:
        """Executa fases sequencialmente com validação.

        Simula execução (em produção seria assíncrono via events).
        """
        if not self.phase_plan:
            self.create_execution_plan()

        logger.info(f"Starting sequential execution for scan {self.scan_id} with {len(self.phase_plan)} phases")

        for phase_id in self.phase_plan:
            logger.info(f"Executing phase {phase_id}")
            self.submit_phase(phase_id)

            # Em produção, esperaria callbacks Celery aqui
            # Por enquanto, simula validação
            self.check_phase_completion(phase_id)

            # Retry se necessário
            if not self.phase_results[phase_id]["validation"]["all_mandatory_executed"]:
                retry_task = self.retry_phase(phase_id)
                if retry_task:
                    logger.info(f"Queued retry for phase {phase_id}: {retry_task}")

        return self.get_execution_summary()


@celery.task(
    name="supervisor.orchestrate_scan",
    bind=True,
    queue="worker.unit.reconhecimento",
    priority=10,  # Highest priority
)
def orchestrate_scan(self, scan_id: int) -> dict[str, Any]:
    """Tarefa Celery: orquestra execução completa de um scan.

    Executa:
    1. Cria plano de fases
    2. Submete agentes para cada fase
    3. Monitora progresso
    4. Retenta fases incompletas
    """
    try:
        db = SessionLocal()
        try:
            supervisor = AgentSupervisor(scan_id, db)
            supervisor.create_execution_plan()

            # Executa sequencialmente (em produção seria com callbacks)
            result = supervisor.execute_sequential()

            logger.info(f"Scan orchestration completed: {result}")
            return result

        finally:
            db.close()

    except Exception as exc:
        logger.exception(f"Error in orchestrate_scan: {exc}")
        raise self.retry(exc=exc, countdown=60)


@celery.task(
    name="supervisor.check_phase_progress",
    bind=True,
    queue="worker.unit.reconhecimento",
)
def check_phase_progress(self, scan_id: int, phase_id: str) -> dict[str, Any]:
    """Monitora progresso de uma fase.

    Valida completude e dispara retry se necessário.
    """
    try:
        db = SessionLocal()
        try:
            supervisor = AgentSupervisor(scan_id, db)
            validation = supervisor.check_phase_completion(phase_id)

            if not validation.get("all_mandatory_executed"):
                retry_task_id = supervisor.retry_phase(phase_id)
                if retry_task_id:
                    logger.info(f"Retrying phase {phase_id}: {retry_task_id}")
                    return {
                        "phase": phase_id,
                        "status": "incomplete_retrying",
                        "retry_task_id": retry_task_id,
                        "validation": validation,
                    }
                else:
                    logger.error(f"Phase {phase_id} incomplete and cannot retry")
                    return {
                        "phase": phase_id,
                        "status": "incomplete_max_retries",
                        "validation": validation,
                    }
            else:
                logger.info(f"Phase {phase_id} completed successfully")
                return {
                    "phase": phase_id,
                    "status": "complete",
                    "validation": validation,
                }

        finally:
            db.close()

    except Exception as exc:
        logger.exception(f"Error checking phase progress: {exc}")
        return {"error": str(exc), "phase": phase_id}


def submit_scan_orchestration(scan_id: int) -> str:
    """Submete orquestração completa de um scan.

    Retorna task_id da tarefa supervisor.
    """
    task = orchestrate_scan.apply_async(
        args=[scan_id],
        queue="worker.unit.reconhecimento",
        priority=10,
    )
    logger.info(f"Submitted scan orchestration: {task.id} for scan={scan_id}")
    return str(task.id)


__all__ = [
    "AgentSupervisor",
    "orchestrate_scan",
    "check_phase_progress",
    "submit_scan_orchestration",
]
