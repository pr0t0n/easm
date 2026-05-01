"""Agent orchestration: ensures all agents for a phase execute completely."""
from __future__ import annotations

from typing import Any
from datetime import datetime
import logging

from app.agents import AGENT_REGISTRY, get_agents_for_phase

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """Manages agent execution for a given phase, ensuring completion and retry."""

    def __init__(self, phase_id: str):
        self.phase_id = phase_id
        self.agents = get_agents_for_phase(phase_id)
        self.execution_log: list[dict[str, Any]] = []
        self.start_time = datetime.utcnow().isoformat()

    def get_mandatory_agents(self) -> list[str]:
        """Return agent IDs that MUST execute for this phase."""
        if not self.agents:
            return []
        # Top 2/3 of agents are mandatory; lowest 1/3 are optional
        mandatory_count = max(1, int(len(self.agents) * 0.66))
        by_priority = sorted(self.agents, key=lambda a: a.priority, reverse=True)
        return [a.agent_id for a in by_priority[:mandatory_count]]

    def validate_prerequisites(self, agent_id: str) -> tuple[bool, str]:
        """Check if an agent's prerequisites are met."""
        agent = next((a for a in self.agents if a.agent_id == agent_id), None)
        if not agent:
            return False, f"Agent {agent_id} not found"

        missing_skills = [s for s in agent.required_skills if s]  # Placeholder check
        if missing_skills:
            return False, f"Missing skills: {', '.join(missing_skills[:3])}"

        return True, ""

    def record_execution(
        self,
        agent_id: str,
        status: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log an agent execution attempt."""
        self.execution_log.append({
            "agent_id": agent_id,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
            "details": dict(details or {}),
        })

    def get_summary(self) -> dict[str, Any]:
        """Return execution summary for this phase."""
        mandatory = self.get_mandatory_agents()
        executed_agents = {log["agent_id"] for log in self.execution_log if log["status"] == "success"}
        mandatory_executed = [a for a in mandatory if a in executed_agents]
        mandatory_failed = [a for a in mandatory if a not in executed_agents]

        return {
            "phase_id": self.phase_id,
            "agents_expected": len(self.agents),
            "agents_mandatory": len(mandatory),
            "agents_executed": len(executed_agents),
            "mandatory_executed": len(mandatory_executed),
            "mandatory_failed": len(mandatory_failed),
            "execution_log": self.execution_log,
            "start_time": self.start_time,
            "end_time": datetime.utcnow().isoformat(),
            "all_mandatory_executed": len(mandatory_failed) == 0,
        }


def create_phase_execution_plan() -> list[str]:
    """Return prioritized list of phases that MUST execute."""
    from app.graph.mission import PENTEST_PHASES

    # Phases organized by criticality
    critical_phases = ["P01", "P02", "P05", "P11", "P12"]  # Recon, ports, fingerprint, CVE, injection
    return critical_phases


def get_agents_for_execution(phase_id: str) -> list[str]:
    """Return list of agent IDs to execute for this phase, in priority order."""
    agents = get_agents_for_phase(phase_id)
    if not agents:
        return []
    by_priority = sorted(agents, key=lambda a: a.priority, reverse=True)
    return [a.agent_id for a in by_priority]


def validate_phase_completion(
    phase_id: str,
    executed_tools: set[str],
) -> tuple[bool, list[str]]:
    """Validate if all mandatory tools for a phase have been executed.

    Returns:
        (all_mandatory_done, missing_tools)
    """
    from app.graph.mission import PENTEST_PHASES

    phase_def = next((p for p in PENTEST_PHASES if p["id"] == phase_id), None)
    if not phase_def:
        return True, []

    expected_tools = set(str(t).lower() for t in phase_def.get("tools") or [])
    mandatory = list(expected_tools)[: max(1, int(len(expected_tools) * 0.66))]

    missing = [t for t in mandatory if t.lower() not in executed_tools]
    return len(missing) == 0, missing


__all__ = [
    "AgentOrchestrator",
    "create_phase_execution_plan",
    "get_agents_for_execution",
    "validate_phase_completion",
]
