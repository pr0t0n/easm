"""Agent dispatcher: executa agentes via Celery com fila, retry e rastreamento."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.agents import AgentOrchestrator, get_agents_for_phase, validate_phase_completion
from app.db.session import SessionLocal
from app.graph.mission import PENTEST_PHASES
from app.models.models import ExecutedToolRun, ScanJob
from app.workers.celery_app import celery

logger = logging.getLogger(__name__)


class AgentExecutionTask:
    """Rastreia uma tarefa de agente na fila."""

    def __init__(
        self,
        task_id: str,
        agent_id: str,
        scan_id: int,
        phase_id: str,
        tools: list[str],
        priority: int = 5,
    ):
        self.task_id = task_id
        self.agent_id = agent_id
        self.scan_id = scan_id
        self.phase_id = phase_id
        self.tools = tools
        self.priority = priority
        self.status = "pending"  # pending, running, success, failed, skipped
        self.created_at = datetime.utcnow().isoformat()
        self.started_at: str | None = None
        self.completed_at: str | None = None
        self.error_message: str | None = None
        self.execution_time_seconds: float | None = None
        self.tools_executed: dict[str, str] = {}  # tool -> status

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "scan_id": self.scan_id,
            "phase_id": self.phase_id,
            "tools": self.tools,
            "priority": self.priority,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error_message": self.error_message,
            "execution_time_seconds": self.execution_time_seconds,
            "tools_executed": self.tools_executed,
        }


class AgentQueue:
    """Gerencia fila de agentes com prioridades."""

    def __init__(self, db: Session | None = None):
        self.db = db or SessionLocal()
        self.queue: list[AgentExecutionTask] = []
        self.active_tasks: dict[str, AgentExecutionTask] = {}
        self.completed_tasks: dict[str, AgentExecutionTask] = {}

    def enqueue(self, agent_id: str, scan_id: int, phase_id: str, priority: int = 5) -> str:
        """Adiciona agente à fila e retorna task_id."""
        agents = get_agents_for_phase(phase_id)
        agent = next((a for a in agents if a.agent_id == agent_id), None)

        if not agent:
            logger.warning(f"Agent {agent_id} not found for phase {phase_id}")
            return ""

        task_id = f"agent-task-{uuid4().hex[:10]}"
        task = AgentExecutionTask(
            task_id=task_id,
            agent_id=agent_id,
            scan_id=scan_id,
            phase_id=phase_id,
            tools=agent.tools,
            priority=priority,
        )

        self.queue.append(task)
        self.queue.sort(key=lambda t: t.priority, reverse=True)
        return task_id

    def dequeue(self) -> AgentExecutionTask | None:
        """Remove e retorna tarefa de maior prioridade."""
        if not self.queue:
            return None
        task = self.queue.pop(0)
        self.active_tasks[task.task_id] = task
        return task

    def mark_running(self, task_id: str) -> None:
        """Marca tarefa como em execução."""
        if task_id in self.active_tasks:
            self.active_tasks[task_id].status = "running"
            self.active_tasks[task_id].started_at = datetime.utcnow().isoformat()

    def mark_complete(
        self,
        task_id: str,
        status: str = "success",
        error: str | None = None,
        execution_time: float | None = None,
    ) -> None:
        """Marca tarefa como completa."""
        if task_id in self.active_tasks:
            task = self.active_tasks.pop(task_id)
            task.status = status
            task.completed_at = datetime.utcnow().isoformat()
            task.error_message = error
            task.execution_time_seconds = execution_time
            self.completed_tasks[task_id] = task
            logger.info(f"Agent task completed: {task_id} → {status}")

    def get_status_summary(self, scan_id: int) -> dict[str, Any]:
        """Retorna sumário de status das tarefas de um scan."""
        scan_tasks = [
            t
            for t in list(self.active_tasks.values())
            + list(self.completed_tasks.values())
            if t.scan_id == scan_id
        ]

        return {
            "total_tasks": len(scan_tasks),
            "pending": len([t for t in self.queue if t.scan_id == scan_id]),
            "running": len([t for t in self.active_tasks.values() if t.scan_id == scan_id]),
            "completed": len([t for t in self.completed_tasks.values() if t.scan_id == scan_id]),
            "success": len([t for t in self.completed_tasks.values() if t.scan_id == scan_id and t.status == "success"]),
            "failed": len([t for t in self.completed_tasks.values() if t.scan_id == scan_id and t.status == "failed"]),
            "tasks": [t.to_dict() for t in scan_tasks[-20:]],  # últimas 20
        }


# Global queue instance
_agent_queue = AgentQueue()


@celery.task(
    name="agent.execute_phase",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    queue="worker.unit.reconhecimento",
)
def execute_agent_phase(self, scan_id: int, phase_id: str) -> dict[str, Any]:
    """Executa todos os agentes para uma fase.

    Retorna sumário de execução com tool_runs rastreados.
    """
    try:
        db = SessionLocal()
        try:
            scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if not scan:
                return {"error": f"Scan {scan_id} not found", "phase": phase_id}

            logger.info(f"Executing agents for scan={scan_id}, phase={phase_id}")

            orchestrator = AgentOrchestrator(phase_id)
            agents = get_agents_for_phase(phase_id)
            mandatory_agents = orchestrator.get_mandatory_agents()

            execution_results = []
            for agent in agents:
                task_id = _agent_queue.enqueue(
                    agent_id=agent.agent_id,
                    scan_id=scan_id,
                    phase_id=phase_id,
                    priority=agent.priority,
                )
                execution_results.append(
                    {
                        "task_id": task_id,
                        "agent_id": agent.agent_id,
                        "mandatory": agent.agent_id in mandatory_agents,
                    }
                )
                orchestrator.record_execution(agent.agent_id, "queued")

            summary = orchestrator.get_summary()
            return {
                "phase": phase_id,
                "scan_id": scan_id,
                "agents_queued": len(execution_results),
                "mandatory_count": len(mandatory_agents),
                "execution_results": execution_results,
                "summary": summary,
            }

        finally:
            db.close()

    except Exception as exc:
        logger.exception(f"Error in execute_agent_phase: {exc}")
        raise self.retry(exc=exc)


@celery.task(
    name="agent.dispatch_from_queue",
    bind=True,
    queue="worker.unit.reconhecimento",
)
def dispatch_from_queue(self) -> dict[str, Any]:
    """Despacha próxima tarefa da fila para execução."""
    task = _agent_queue.dequeue()
    if not task:
        return {"status": "queue_empty"}

    _agent_queue.mark_running(task.task_id)
    logger.info(f"Dispatching task: {task.task_id} → {task.agent_id}")

    return {
        "task_id": task.task_id,
        "agent_id": task.agent_id,
        "scan_id": task.scan_id,
        "phase_id": task.phase_id,
        "tools": task.tools,
    }


@celery.task(
    name="agent.record_tool_execution",
    bind=True,
    queue="worker.unit.reconhecimento",
)
def record_tool_execution(
    self,
    scan_id: int,
    tool_name: str,
    target: str,
    status: str = "success",
    error_message: str | None = None,
    execution_time_seconds: float | None = None,
) -> dict[str, Any]:
    """Registra execução de uma ferramenta no banco.

    Cria/atualiza ExecutedToolRun e rastreia para idempotência.
    """
    db = SessionLocal()
    try:
        now = datetime.utcnow()

        # Check if already executed (idempotency)
        existing = db.query(ExecutedToolRun).filter(
            ExecutedToolRun.scan_job_id == scan_id,
            ExecutedToolRun.tool_name == tool_name,
            ExecutedToolRun.target == target,
        ).first()

        if existing:
            logger.info(f"Tool execution already recorded: {tool_name}@{target}")
            existing.status = status
            existing.error_message = error_message
            existing.execution_time_seconds = execution_time_seconds
        else:
            run = ExecutedToolRun(
                scan_job_id=scan_id,
                tool_name=tool_name,
                target=target,
                status=status,
                error_message=error_message,
                execution_time_seconds=execution_time_seconds,
                created_at=now,
            )
            db.add(run)

        db.commit()
        return {
            "tool": tool_name,
            "target": target,
            "status": status,
            "recorded": True,
        }

    except Exception as e:
        logger.exception(f"Error recording tool execution: {e}")
        return {"error": str(e), "tool": tool_name}
    finally:
        db.close()


@celery.task(
    name="agent.validate_phase_completion",
    bind=True,
    queue="worker.unit.reconhecimento",
)
def validate_phase_completion(self, scan_id: int, phase_id: str) -> dict[str, Any]:
    """Valida se uma fase foi completada com todas as ferramentas obrigatórias."""
    db = SessionLocal()
    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan:
            return {"error": f"Scan {scan_id} not found"}

        # Busca todas as ferramentas executadas para este scan
        tool_runs = db.query(ExecutedToolRun).filter(
            ExecutedToolRun.scan_job_id == scan_id
        ).all()

        executed_tools = {str(run.tool_name).lower() for run in tool_runs if run.status == "success"}

        # Valida a fase
        from app.agents import validate_phase_completion as validate_tools

        all_done, missing = validate_tools(phase_id, executed_tools)

        return {
            "phase": phase_id,
            "scan_id": scan_id,
            "all_mandatory_executed": all_done,
            "executed_tools_count": len(executed_tools),
            "missing_tools": missing,
            "validation_status": "complete" if all_done else "incomplete",
        }

    finally:
        db.close()


def submit_agents_for_phase(scan_id: int, phase_id: str) -> str:
    """Submete todos os agentes para uma fase.

    Retorna task_id da tarefa principal.
    """
    task = execute_agent_phase.apply_async(
        args=[scan_id, phase_id],
        queue="worker.unit.reconhecimento",
        priority=8,
    )
    logger.info(f"Submitted agent phase execution: {task.id} for scan={scan_id}, phase={phase_id}")
    return str(task.id)


def get_queue_status(scan_id: int) -> dict[str, Any]:
    """Retorna status atual da fila para um scan."""
    return _agent_queue.get_status_summary(scan_id)


__all__ = [
    "AgentExecutionTask",
    "AgentQueue",
    "execute_agent_phase",
    "dispatch_from_queue",
    "record_tool_execution",
    "validate_phase_completion",
    "submit_agents_for_phase",
    "get_queue_status",
]
