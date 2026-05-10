from app.agents.supervisor_prompt import build_supervisor_orchestration_prompt
from app.services.agent_context_service import build_worker_knowledge_context
from app.workers.worker_groups import get_worker_agent_profiles


def test_worker_profiles_require_skill_memory_step() -> None:
    profiles = get_worker_agent_profiles("unit")
    recon = profiles["reconnaissance"]

    assert recon["skill_context"]["retrieval_required"] is True
    assert recon["skill_context"]["runtime_invocation_required"] is True
    assert recon["skill_context"]["execution_path"] == "mcp_to_kali"
    assert "invoke_skill_runtime" in recon["operational_sequence"]
    assert "retrieve_skill_memory" in recon["operational_sequence"]
    assert recon["operational_sequence"].index("invoke_skill_runtime") < recon["operational_sequence"].index("retrieve_skill_memory")
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


def test_worker_knowledge_context_retrieves_accepted_learning_without_group_lock(monkeypatch) -> None:
    accepted_learning_doc = {
        "document_id": "learning-1",
        "content": "juice shop accepted learning",
        "metadata": {"type": "accepted_learning", "skill": "vuln-demo", "phase": "P11"},
        "source": "accepted_learning",
        "score": 0.92,
    }

    monkeypatch.setattr(
        "app.services.agent_context_service.sync_worker_knowledge_to_mcp",
        lambda **kwargs: {"available": True, "playbook": {"title": "accepted playbook", "recommended_tools": ["nuclei"]}},
    )
    monkeypatch.setattr(
        "app.services.agent_context_service.get_worker_agent_profile",
        lambda worker_group, mode="unit": {"mission": f"{worker_group} mission"},
    )

    calls: list[dict] = []

    def _query(**kwargs):
        calls.append(kwargs)
        return [accepted_learning_doc]

    monkeypatch.setattr("app.services.agent_context_service.mcp_client.query_knowledge_sync", _query)

    bundle = build_worker_knowledge_context(
        worker_group="exploitation",
        skill="vuln-demo",
        phase="P11",
        target="http://example.com",
        candidate_tools=["nuclei", "sqlmap"],
    )

    assert bundle["knowledge_items"][0]["source"] == "accepted_learning"
    assert calls[0]["filters"] == {"phase": "P11"}
