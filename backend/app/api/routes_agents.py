"""API routes para monitoramento de execução de agentes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user
from app.models.models import ScanJob, User
from app.workers.agent_supervisor import AgentSupervisor, submit_scan_orchestration
from app.workers.agent_dispatcher import get_queue_status

router = APIRouter(prefix="/api/agents", tags=["agents"])


@router.post("/submit/{scan_id}", response_model=dict[str, Any])
def submit_agents_for_scan(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Submete execução de agentes para um scan.

    Inicia orquestração de fases e retorna task_id de rastreamento.
    """
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.owner_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        task_id = submit_scan_orchestration(scan_id)
        return {
            "status": "submitted",
            "scan_id": scan_id,
            "task_id": task_id,
            "message": f"Agent orchestration submitted for scan {scan_id}",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error submitting agents: {str(e)}")


@router.get("/status/{scan_id}", response_model=dict[str, Any])
def get_agent_execution_status(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retorna status de execução de agentes para um scan.

    Inclui fases completas/incompletas, retry counts, e detalhes da fila.
    """
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.owner_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        supervisor = AgentSupervisor(scan_id, db)
        summary = supervisor.get_execution_summary()
        return {
            "scan_id": scan_id,
            "status": "in_progress" if summary["incomplete_phases"] else "complete",
            "total_phases": summary["total_phases_planned"],
            "phases_completed": summary["phases_completed"],
            "phases_incomplete": summary["phases_incomplete"],
            "complete_phases": summary["complete_phases"],
            "incomplete_phases": summary["incomplete_phases"],
            "retry_counts": summary["retry_counts"],
            "queue_status": summary["queue_status"],
        }
    except Exception as e:
        return {
            "scan_id": scan_id,
            "status": "error",
            "error": str(e),
        }


@router.get("/queue/status/{scan_id}", response_model=dict[str, Any])
def get_queue_status_endpoint(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retorna status atual da fila de agentes.

    Inclui tarefas pendentes, em execução, completas.
    """
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.owner_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return get_queue_status(scan_id)


@router.post("/retry/{scan_id}/{phase_id}", response_model=dict[str, Any])
def retry_phase(
    scan_id: int,
    phase_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retenta execução de uma fase específica.

    Válido apenas se a fase não foi completada e há retries disponíveis.
    """
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.owner_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        supervisor = AgentSupervisor(scan_id, db)
        task_id = supervisor.retry_phase(phase_id)

        if not task_id:
            return {
                "status": "error",
                "message": f"Cannot retry phase {phase_id} (already complete or max retries reached)",
                "phase": phase_id,
            }

        return {
            "status": "retrying",
            "scan_id": scan_id,
            "phase": phase_id,
            "task_id": task_id,
            "message": f"Phase {phase_id} retry submitted",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrying phase: {str(e)}")


@router.get("/phases/plan/{scan_id}", response_model=dict[str, Any])
def get_phase_execution_plan(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retorna plano de execução de fases.

    Mostra ordem e prioridade de execução.
    """
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.owner_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        supervisor = AgentSupervisor(scan_id, db)
        plan = supervisor.create_execution_plan()
        return {
            "scan_id": scan_id,
            "phase_plan": plan,
            "total_phases": len(plan),
            "status": "ready",
        }
    except Exception as e:
        return {
            "scan_id": scan_id,
            "status": "error",
            "error": str(e),
        }


@router.get("/agents/{phase_id}", response_model=dict[str, Any])
def get_agents_for_phase_endpoint(
    phase_id: str,
) -> dict[str, Any]:
    """Retorna lista de agentes para uma fase.

    Público - não requer autenticação.
    """
    from app.agents import get_agents_for_phase

    agents = get_agents_for_phase(phase_id)
    return {
        "phase": phase_id,
        "agents_count": len(agents),
        "agents": [
            {
                "agent_id": a.agent_id,
                "name": a.name,
                "category": a.category,
                "description": a.description,
                "tools": a.tools,
                "priority": a.priority,
            }
            for a in agents
        ],
    }


__all__ = [
    "router",
    "submit_agents_for_scan",
    "get_agent_execution_status",
    "get_queue_status_endpoint",
    "retry_phase",
    "get_phase_execution_plan",
    "get_agents_for_phase_endpoint",
]
