from app.agents.supervisor_prompt import build_supervisor_orchestration_prompt
from app.workers.worker_groups import get_worker_agent_profiles


def test_worker_profiles_require_skill_memory_step() -> None:
    profiles = get_worker_agent_profiles("unit")
    recon = profiles["reconnaissance"]

    assert recon["skill_context"]["retrieval_required"] is True
    assert recon["skill_context"]["execution_path"] == "mcp_to_kali"
    assert "retrieve_skill_memory" in recon["operational_sequence"]
    assert recon["contract"]["tool_execution_path"] == "mcp_to_kali"


def test_supervisor_prompt_embeds_skill_memory() -> None:
    prompt = build_supervisor_orchestration_prompt(
        playbook={"title": "demo"},
        execution_context={"phase": "P11", "target": "example.com", "skill": "vuln-demo"},
        tool_catalog=[{"tool": "nuclei"}],
        skill_memory={"knowledge_items": [{"content": "accepted learning"}]},
    )

    assert "SKILL_MEMORY" in prompt
    assert "accepted learning" in prompt
