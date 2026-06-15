from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


def emit_trace(
    scan_id: int,
    iteration: int,
    event_type: str,
    from_node: str,
    to_node: str,
    skill_id: str | None = None,
    tool_name: str | None = None,
    capability: str | None = None,
    status: str = "success",
    duration_ms: float | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    """Write one trace event to the DB. Never raises — tracing must not break agent flow."""
    try:
        from app.db.session import SessionLocal
        from app.models.models import AgentTraceEvent

        db = SessionLocal()
        try:
            event = AgentTraceEvent(
                scan_id=int(scan_id),
                iteration=int(iteration),
                event_type=str(event_type),
                from_node=str(from_node),
                to_node=str(to_node),
                skill_id=str(skill_id) if skill_id else None,
                tool_name=str(tool_name) if tool_name else None,
                capability=str(capability) if capability else None,
                status=str(status),
                duration_ms=float(duration_ms) if duration_ms is not None else None,
                payload=dict(payload or {}),
                created_at=datetime.now(),
            )
            db.add(event)
            db.commit()
        finally:
            db.close()
    except Exception as exc:
        logger.debug("emit_trace failed (non-critical): %s", exc)


def save_skill_score(
    scan_id: int,
    iteration: int,
    skill_id: str,
    capability: str,
    library_hits: int = 0,
    tool_attempts: int = 0,
    tool_successes: int = 0,
    tool_failures: int = 0,
    findings_raw: int = 0,
    findings_promoted: int = 0,
    duration_ms: float = 0.0,
) -> None:
    """Compute efficiency/productivity scores and persist a SkillScore row."""
    try:
        # Efficiency: success rate penalised by time (long runs score lower)
        time_penalty = min(0.5, duration_ms / 120_000)
        efficiency = round(
            (tool_successes / max(1, tool_attempts)) * 100 * (1 - time_penalty), 1
        )
        # Productivity: ratio of promoted findings + bonus per finding
        productivity = round(
            min(100.0, (findings_promoted / max(1, findings_raw)) * 60 + findings_promoted * 8), 1
        )

        from app.db.session import SessionLocal
        from app.models.models import SkillScore

        db = SessionLocal()
        try:
            # Item 9: UPSERT por (scan_id, skill_id, capability) em vez de sempre
            # inserir — antes o grafo criava linhas duplicadas por skill/fase
            # (ex.: port_service_discovery P02 ×8), poluindo as métricas por-skill.
            score = (
                db.query(SkillScore)
                .filter(
                    SkillScore.scan_id == int(scan_id),
                    SkillScore.skill_id == str(skill_id),
                    SkillScore.capability == str(capability),
                )
                .first()
            )
            if score is None:
                score = SkillScore(
                    scan_id=int(scan_id),
                    iteration=int(iteration),
                    skill_id=str(skill_id),
                    capability=str(capability),
                    created_at=datetime.now(),
                )
                db.add(score)
            score.library_hits = max(int(score.library_hits or 0), int(library_hits))
            score.tool_attempts = max(int(score.tool_attempts or 0), int(tool_attempts))
            score.tool_successes = max(int(score.tool_successes or 0), int(tool_successes))
            score.tool_failures = max(int(score.tool_failures or 0), int(tool_failures))
            score.findings_raw = max(int(score.findings_raw or 0), int(findings_raw))
            score.findings_promoted = max(int(score.findings_promoted or 0), int(findings_promoted))
            score.duration_ms = float(duration_ms)
            score.efficiency_score = max(0.0, min(100.0, efficiency))
            score.productivity_score = max(0.0, min(100.0, productivity))
            db.commit()
        finally:
            db.close()
    except Exception as exc:
        logger.debug("save_skill_score failed (non-critical): %s", exc)
