"""Integração de agentes com LangGraph workflow.

Conecta supervisor node do workflow com agent dispatcher/supervisor.
"""
from __future__ import annotations

import logging
from typing import Any

from app.graph.workflow import AgentState
from app.workers.agent_supervisor import submit_scan_orchestration, AgentSupervisor
from app.db.session import SessionLocal

logger = logging.getLogger(__name__)


def dispatch_agents_for_mission(state: AgentState) -> AgentState:
    """Despacha agentes para a missão atual.

    Chamado pelo workflow para orquestrar execução de agentes.
    """
    scan_id = int(state.get("scan_id", 0))
    if not scan_id:
        logger.warning("No scan_id in state, skipping agent dispatch")
        return state

    try:
        # Cria supervisor com contexto da missão atual
        db = SessionLocal()
        try:
            supervisor = AgentSupervisor(scan_id, db)

            # Extrai informações da state
            current_mission_index = int(state.get("mission_index", 0))
            mission_items = list(state.get("mission_items") or [])

            # Cria plano de execução
            phase_plan = supervisor.create_execution_plan()
            logger.info(f"Agent dispatch plan created: {len(phase_plan)} phases")

            # Armazena no state para rastreamento
            state["autonomy_actions"].append({
                "action": "agent_dispatch_initiated",
                "data": {
                    "phase_plan": phase_plan,
                    "mission_index": current_mission_index,
                    "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
                },
            })

            # Submete orquestração (assíncrono via Celery)
            orchestration_task_id = submit_scan_orchestration(scan_id)
            logger.info(f"Submitted orchestration task: {orchestration_task_id}")

            # Atualiza state com referência à tarefa
            execution_control = dict(state.get("execution_control") or {})
            execution_control["orchestration_task_id"] = orchestration_task_id
            execution_control["agents_dispatched_at"] = __import__("datetime").datetime.utcnow().isoformat()
            state["execution_control"] = execution_control

            return state

        finally:
            db.close()

    except Exception as e:
        logger.exception(f"Error in dispatch_agents_for_mission: {e}")
        state["autonomy_errors"].append({
            "source": "agent_dispatch",
            "text": f"Agent dispatch failed: {str(e)}",
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        })
        return state


def check_agent_progress(state: AgentState) -> dict[str, Any]:
    """Verifica progresso da execução de agentes.

    Retorna status e determina próximo passo.
    """
    scan_id = int(state.get("scan_id", 0))
    if not scan_id:
        return {"status": "no_scan_id"}

    try:
        db = SessionLocal()
        try:
            supervisor = AgentSupervisor(scan_id, db)
            summary = supervisor.get_execution_summary()

            return {
                "scan_id": scan_id,
                "total_phases": summary["total_phases_planned"],
                "completed_phases": summary["phases_completed"],
                "incomplete_phases": summary["phases_incomplete"],
                "phase_results": summary["phase_results"],
                "queue_status": summary["queue_status"],
                "all_complete": len(summary["incomplete_phases"]) == 0,
            }

        finally:
            db.close()

    except Exception as e:
        logger.exception(f"Error checking agent progress: {e}")
        return {"error": str(e), "scan_id": scan_id}


def integrate_agents_with_workflow(workflow_graph) -> None:
    """Injeta agent dispatch no workflow.

    Chamado durante build_graph para adicionar nó agent orchestrator.
    """
    from langgraph.graph import END

    def agent_orchestrator_node(state: AgentState) -> AgentState:
        """Nó que orquestra agentes para a fase atual."""
        logger.info(f"Entering agent_orchestrator_node (iter={state.get('loop_iteration')})")

        # Despacha agentes para missão atual
        state = dispatch_agents_for_mission(state)

        # Verifica progresso
        progress = check_agent_progress(state)

        if progress.get("all_complete"):
            logger.info("All agent phases complete, continuing to next node")
            state["routing_next_node"] = state.get("routing_next_node", END)
        else:
            incomplete = progress.get("incomplete_phases", [])
            logger.warning(f"Incomplete phases: {incomplete}")
            state["autonomy_observations"].append({
                "source": "agent_orchestrator",
                "text": f"Phases incomplete: {', '.join(incomplete[:3])}",
                "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
            })

        return state

    # Adiciona nó ao grafo (se workflow_graph for um StateGraph)
    try:
        if hasattr(workflow_graph, "add_node"):
            workflow_graph.add_node("agent_orchestrator", agent_orchestrator_node)
            logger.info("Added agent_orchestrator_node to workflow")
    except Exception as e:
        logger.warning(f"Could not add agent_orchestrator_node: {e}")


__all__ = [
    "dispatch_agents_for_mission",
    "check_agent_progress",
    "integrate_agents_with_workflow",
]
