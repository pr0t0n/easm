from app.graph.workflow import (
    _route_from_supervisor,
    _run_tools_and_collect,
    build_graph,
    skill_planner_node,
    skill_selector_node,
    tool_selector_node,
)
import inspect

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
    assert invocation["worker_rules"]["worker_group"] == "reconnaissance"
    assert any(item["id"] == "recon.web_crawl" for item in invocation["sub_agent_plan"])
    assert any(str(item).startswith("learning_skill:") for item in invocation["matched_by"])


def test_skill_pipeline_turns_learning_into_single_tool_contract(monkeypatch) -> None:
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
        "app.graph.workflow._candidate_tools_for_skill_bootstrap",
        lambda _state, _group: ["httpx", "katana", "curl-headers"],
    )
    monkeypatch.setattr(
        "app.services.agent_context_service.build_worker_knowledge_context",
        lambda **_kwargs: {"knowledge_items": [], "recommended_tools": []},
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

    skill_selector_node(state)
    skill_planner_node(state)
    tool_selector_node(state)

    selection = state["tool_selection_contract"]
    assert selection["decision_source"] == "skill_selector"
    assert selection["selected_tools"][0] == "katana"
    assert "httpx" in selection["selected_tools"]
    assert selection["skill_id"] == "vuln-information-disclosure"
    assert selection["evidence_required"] == ["score board"]
    assert state["current_skill"] == "vuln-information-disclosure"
    assert state["skill_invocations"][0]["skill_id"] == "vuln-information-disclosure"
    assert state["skill_plan_contract"]["worker_rules"]["worker_group"] == "reconnaissance"
    assert any(item["id"] == "recon.web_crawl" for item in state["tool_selection_contract"]["sub_agent_plan"])
    actions = [item["action"] for item in state["autonomy_actions"]]
    assert "skill_invoked" in actions
    assert "skill_planned" in actions
    assert "tool_selected" in actions
    assert actions.index("skill_planned") < actions.index("tool_selected")


def test_skill_selector_node_materializes_skill_contract(monkeypatch) -> None:
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

    skill_selector_node(state)

    assert state["skill_selector_ready"] is True
    assert state["skill_selector_gate"]["skill_id"] == "vuln-information-disclosure"
    assert state["skill_contract"]["purpose"] == "skill_selector"
    assert state["skill_invocations"][0]["purpose"] == "skill_selector"
    assert "skill_selector" in state["node_history"]


def test_supervisor_routes_tool_capabilities_to_skill_selector() -> None:
    state = {"routing_next_node": "risk_assessment"}

    route = _route_from_supervisor(state)

    assert route == "skill_selector"
    assert state["pending_capability_node"] == "risk_assessment"


def test_build_graph_uses_skill_first_pipeline_not_phase_executors() -> None:
    source = inspect.getsource(build_graph)

    assert 'graph.add_node("skill_selector", skill_selector_node)' in source
    assert 'graph.add_node("skill_planner", skill_planner_node)' in source
    assert 'graph.add_node("tool_selector", tool_selector_node)' in source
    assert 'graph.add_node("tool_executor", tool_executor_node)' in source
    assert 'graph.add_node("evidence_gate", evidence_gate_node)' in source
    assert 'graph.add_edge("skill_selector", "skill_planner")' in source
    assert 'graph.add_edge("skill_planner", "tool_selector")' in source
    assert 'graph.add_edge("tool_selector", "tool_executor")' in source
    assert 'graph.add_edge("tool_executor", "evidence_gate")' in source
    assert 'graph.add_node("strategic_planning"' not in source
    assert 'graph.add_node("asset_discovery"' not in source
    assert 'graph.add_node("threat_intel"' not in source
    assert 'graph.add_node("risk_assessment"' not in source
    assert 'graph.add_node("adversarial_hypothesis"' not in source
    assert 'graph.add_node("evidence_adjudication"' not in source



def test_tool_selector_does_not_keep_phase_fan_out(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.agent_context_service.build_worker_knowledge_context",
        lambda **_kwargs: {"knowledge_items": [], "recommended_tools": ["dalfox"]},
    )
    state = {
        "target": "http://localhost:3001/",
        "scan_mode": "unit",
        "skill_plan_contract": {
            "capability": "risk_assessment",
            "phase": "risk_assessment",
            "skill_id": "vuln-injection",
            "skill_invocation_id": "skill-test",
            "skill_contract": {"skill_id": "vuln-injection", "invocation_id": "skill-test"},
            "technique": {"name": "SQLi validation", "recommended_kali_tools": ["sqlmap"]},
            "candidate_tools": ["nuclei", "sqlmap", "dalfox"],
            "recommended_tools": ["sqlmap"],
            "evidence_required": ["sql error"],
            "constraints": ["safe batch mode"],
            "worker_rules": {"worker_group": "exploitation", "rules": ["validate safely"]},
            "sub_agent_plan": [{"id": "exploitation.web_validation"}],
            "playbook_title": "accepted learning",
        },
        "skill_selector_gate": {},
        "skill_invocation": {},
        "skill_contract": {},
        "logs_terminais": [],
        "autonomy_actions": [],
        "activity_metrics": [],
        "node_history": [],
        "mission_index": 0,
        "last_completed_node": "",
    }

    tool_selector_node(state)

    assert state["tool_selection_contract"]["selected_tools"] == ["sqlmap", "dalfox"]
    assert state["tool_selection_contract"]["decision_source"] == "skill_selector"


def test_tool_execution_dispatch_receives_skill_contract(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _dispatch(tool_name: str, target: str, **kwargs):
        captured["tool_name"] = tool_name
        captured["target"] = target
        captured.update(kwargs)
        return {
            "status": "executed",
            "tool": tool_name,
            "target": target,
            "stdout": "",
            "stderr": "",
            "command": "sqlmap --batch",
            "return_code": 0,
        }

    monkeypatch.setattr("app.graph.workflow.execute_tool_with_workers", _dispatch)

    state = {
        "scan_id": None,
        "scan_mode": "unit",
        "executed_tool_runs": [],
        "logs_terminais": [],
        "mission_metrics": {},
        "autonomy_actions": [],
        "autonomy_observations": [],
        "autonomy_errors": [],
        "tool_runtime": {},
    }

    _run_tools_and_collect(
        state,
        ["sqlmap"],
        "http://localhost:3001/",
        "risk_assessment",
        "ToolExecutor:risk_assessment",
        skill_context={
            "skill_id": "vuln-injection",
            "skill_invocation_id": "skill-test",
            "skill_contract": {"skill_id": "vuln-injection"},
            "technique": {"name": "SQLi validation"},
            "evidence_required": ["sql error"],
            "constraints": ["safe batch mode"],
            "worker_rules": {"worker_group": "exploitation", "rules": ["validate safely"]},
            "sub_agent_plan": [{"id": "exploitation.web_validation"}],
            "playbook_title": "accepted learning",
        },
    )

    assert captured["skill_id"] == "vuln-injection"
    assert captured["skill_contract"] == {"skill_id": "vuln-injection"}
    assert captured["technique"] == {"name": "SQLi validation"}
    assert captured["evidence_required"] == ["sql error"]
    assert captured["constraints"] == ["safe batch mode"]
    assert captured["worker_rules"] == {"worker_group": "exploitation", "rules": ["validate safely"]}
    assert captured["sub_agent_plan"] == [{"id": "exploitation.web_validation"}]
