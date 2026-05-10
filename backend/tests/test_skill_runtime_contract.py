from app.graph.workflow import _consult_supervisor_orchestration, skill_runtime_node
from app.services.skill_runtime import resolve_skill_invocation


def test_skill_runtime_prefers_learning_skill_over_first_active_skill() -> None:
    playbook = {
        "title": "Accepted vulnerability learning playbook",
        "recommended_tools": ["katana", "curl-headers"],
        "techniques": [
            {
                "name": "Juice Shop hidden route discovery",
                "affected_skills": ["vuln-information-disclosure"],
                "affected_phases": ["P03"],
                "recommended_kali_tools": ["katana", "curl-headers"],
                "evidence_signals": ["score board", "hidden route"],
            }
        ],
    }

    invocation = resolve_skill_invocation(
        worker_group="asset_discovery",
        phase="asset_discovery",
        target="http://localhost:3001/",
        candidate_tools=["httpx", "katana", "curl-headers"],
        active_skills=[
            {"id": "recon-subdomain-enum", "category": "reconnaissance"},
            {"id": "vuln-nuclei-cve", "category": "vulnerabilities"},
        ],
        playbook=playbook,
    )

    assert invocation["called"] is True
    assert invocation["skill_id"] == "vuln-information-disclosure"
    assert invocation["recommended_tools"][0] == "katana"
    assert any(str(item).startswith("learning_skill:") for item in invocation["matched_by"])


def test_supervisor_orchestration_records_skill_invocation_and_falls_back(monkeypatch) -> None:
    playbook = {
        "title": "Accepted vulnerability learning playbook",
        "recommended_tools": ["katana"],
        "evidence_signals": ["score board"],
        "techniques": [
            {
                "name": "Scoreboard discovery from accepted learning",
                "affected_skills": ["vuln-information-disclosure"],
                "affected_phases": ["P03"],
                "recommended_kali_tools": ["katana"],
                "evidence_signals": ["score board"],
            }
        ],
    }

    monkeypatch.setattr(
        "app.services.vulnerability_learning_service.build_runtime_learning_playbook",
        lambda **_kwargs: playbook,
    )
    monkeypatch.setattr(
        "app.services.agent_context_service.build_worker_knowledge_context",
        lambda **_kwargs: {
            "prompt_context": {},
            "knowledge_items": [],
            "recommended_tools": [],
            "sync_status": {"ingested": 0},
        },
    )
    monkeypatch.setattr(
        "app.agents.supervisor_runtime.decide_next_technique",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("LLM unavailable")),
    )

    state = {
        "target": "http://localhost:3001/",
        "current_phase": "asset_discovery",
        "active_skills": [{"id": "recon-subdomain-enum", "category": "reconnaissance"}],
        "logs_terminais": [],
        "scan_mode": "unit",
        "loop_iteration": 0,
        "autonomy_actions": [],
        "orchestration_decisions": [],
    }

    decision = _consult_supervisor_orchestration(
        state,
        "asset_discovery",
        ["httpx", "katana", "curl-headers"],
    )

    assert decision is not None
    assert decision["decision_source"] == "skill_runtime_fallback"
    assert decision["preferred_tools"] == ["katana"]
    assert state["current_skill"] == "vuln-information-disclosure"
    assert state["skill_invocations"][0]["skill_id"] == "vuln-information-disclosure"
    assert state["autonomy_actions"][0]["action"] == "skill_invoked"
    assert state["orchestration_decisions"][0]["decision_source"] == "skill_runtime_fallback"


def test_skill_runtime_node_materializes_workflow_gate(monkeypatch) -> None:
    playbook = {
        "title": "Accepted vulnerability learning playbook",
        "recommended_tools": ["katana"],
        "techniques": [
            {
                "name": "Scoreboard discovery from accepted learning",
                "affected_skills": ["vuln-information-disclosure"],
                "affected_phases": ["P03"],
                "recommended_kali_tools": ["katana"],
                "evidence_signals": ["score board"],
            }
        ],
    }

    monkeypatch.setattr(
        "app.services.vulnerability_learning_service.build_runtime_learning_playbook",
        lambda **_kwargs: playbook,
    )
    monkeypatch.setattr(
        "app.graph.workflow._candidate_tools_for_skill_bootstrap",
        lambda _state, _group: ["httpx", "katana", "curl-headers"],
    )

    state = {
        "target": "http://localhost:3001/",
        "target_type": "site",
        "current_phase": "",
        "routing_next_node": "asset_discovery",
        "active_skills": [],
        "vulnerabilidades_encontradas": [],
        "discovered_ports": [],
        "logs_terminais": [],
        "scan_mode": "unit",
        "loop_iteration": 0,
        "autonomy_actions": [],
        "skill_invocations": [],
        "tool_runtime": {},
        "activity_metrics": [],
        "node_history": [],
        "mission_index": 0,
        "last_completed_node": "",
    }

    skill_runtime_node(state)

    assert state["skill_runtime_ready"] is True
    assert state["skill_runtime_gate"]["skill_id"] == "vuln-information-disclosure"
    assert state["skill_runtime_contract"]["purpose"] == "workflow_gate"
    assert state["skill_invocations"][0]["purpose"] == "workflow_gate"
    assert "skill_runtime" in state["node_history"]
