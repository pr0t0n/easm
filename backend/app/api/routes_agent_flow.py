"""Agent Flow API.

Expõe o ciclo completo supervisor → agente → supervisor para visualização
na UI de Agent Flow.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.models.models import AgentActivityLog, ScanJob, SkillLibrary, SkillToolMapping, User

router = APIRouter(prefix="/api/agent-flow", tags=["agent-flow"])


@router.get("/scans/{scan_id}")
def get_agent_flow(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retorna o ciclo completo supervisor↔agente para um scan.

    Cada entrada representa um ciclo completo:
    supervisor demand → skill lookup → tool selection → execution → agent report → supervisor evaluation.
    """
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not current_user.is_admin and scan.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")

    logs = (
        db.query(AgentActivityLog)
        .filter(AgentActivityLog.scan_job_id == scan_id)
        .order_by(AgentActivityLog.iteration.asc(), AgentActivityLog.created_at.asc())
        .all()
    )

    return {
        "scan_id": scan_id,
        "target": scan.target_query,
        "total_activities": len(logs),
        "activities": [_serialize_log(entry) for entry in logs],
    }


@router.get("/skill-library")
def get_skill_library(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retorna a biblioteca completa de skills com ferramentas e scores."""
    skills = (
        db.query(SkillLibrary)
        .filter(SkillLibrary.is_active.is_(True))
        .order_by(SkillLibrary.skill_category.asc(), SkillLibrary.skill_name.asc())
        .all()
    )

    result = []
    for skill in skills:
        tools = (
            db.query(SkillToolMapping)
            .filter(
                SkillToolMapping.skill_id == skill.id,
                SkillToolMapping.is_active.is_(True),
            )
            .order_by(SkillToolMapping.score.desc())
            .all()
        )
        result.append({
            "id": skill.id,
            "skill_name": skill.skill_name,
            "skill_category": skill.skill_category,
            "activity_types": skill.activity_types or [],
            "kill_chain_phases": skill.kill_chain_phases or [],
            "objective": skill.objective or "",
            "quality_criteria": skill.quality_criteria or "",
            "tools": [
                {
                    "tool_name": t.tool_name,
                    "score": float(t.score or 0),
                    "usage_guide": t.usage_guide or "",
                    "evidence_type": t.evidence_type or "",
                }
                for t in tools
            ],
        })

    return {"total": len(result), "skills": result}


def _serialize_log(entry: AgentActivityLog) -> dict:
    demand = dict(entry.activity_demand or {})
    report = dict(entry.agent_report or {})
    evaluation = dict(entry.supervisor_evaluation or {})
    skill_found = dict(entry.skill_found or {})

    return {
        "id": entry.id,
        "iteration": entry.iteration,
        "status": entry.status,
        "approved": entry.approved,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
        "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,

        # 1. Demanda do supervisor
        "supervisor_demand": {
            "activity_id": demand.get("activity_id", ""),
            "activity_type": demand.get("activity_type", ""),
            "skill_category": demand.get("skill_category", ""),
            "kill_chain_phases": demand.get("kill_chain_phases", []),
            "objective": demand.get("objective", ""),
            "quality_criteria": demand.get("quality_criteria", ""),
            "target": demand.get("target", ""),
            "demanded_at": demand.get("demanded_at", ""),
        },

        # 2. Skill encontrada na biblioteca
        "skill_lookup": {
            "skill_name": skill_found.get("skill_name", ""),
            "skill_category": skill_found.get("skill_category", ""),
            "objective": skill_found.get("objective", ""),
            "source": entry.skill_lookup_source or "library_db",
            "tools_available": len(skill_found.get("tools", [])),
            "top_tools": [
                {"tool_name": t.get("tool_name", ""), "score": t.get("score", 0)}
                for t in (skill_found.get("tools") or [])[:3]
            ],
        },

        # 3. Ferramenta selecionada
        "tool_selection": {
            "tool_name": entry.tool_selected or "",
            "score": float(entry.tool_score or 0),
            "usage_guide": entry.tool_usage_guide or "",
        },

        # 4. Relatório do agente
        "agent_report": {
            "operation_performed": report.get("operation_performed", ""),
            "findings_count": report.get("findings_count", 0),
            "quality_score": report.get("quality_score", 0),
            "question_to_supervisor": report.get("question_to_supervisor", ""),
            "data_collected": report.get("data_collected", [])[:5],
            "reported_at": report.get("reported_at", ""),
        },

        # 5. Avaliação do supervisor
        "supervisor_evaluation": {
            "approved": evaluation.get("approved"),
            "reason": evaluation.get("reason", ""),
            "quality_assessment": evaluation.get("quality_assessment", ""),
            "next_phase": evaluation.get("next_phase", ""),
            "evaluated_at": evaluation.get("evaluated_at", ""),
        },
    }
