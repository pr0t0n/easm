from __future__ import annotations

from typing import Any

import pytest

from app.services import offensive_operator_core as core


def _skill(skill_id: str, tool_name: str = "curl") -> dict[str, Any]:
    return {
        "skill_id": skill_id,
        "quality_gate_status": "passed",
        "status": "approved",
        "metadata": {
            "skill_id": skill_id,
            "name": skill_id,
            "required_tools": [tool_name],
            "fallback_tools": [],
            "optional_tools": [],
            "evidence_required": ["tool_output", "parsed_result"],
            "exit_criteria": {"evidence_required": True},
            "retry_policy": {},
            "allowed_execution_modes": ["controlled_pentest"],
            "risk_level": "medium",
            "noise_level": "medium",
        },
        "body": "# Objective\nTest skill",
    }


class _Registry:
    def __init__(self, skills: list[dict[str, Any]]) -> None:
        self._skills = skills

    def approved_for_phase(self, _phase_id: str, _execution_mode: str) -> list[dict[str, Any]]:
        return list(self._skills)


class _Rag:
    def __init__(self, skill_ids: list[str]) -> None:
        self.skill_ids = skill_ids

    def retrieve(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "retrieved_skills": [
                {"skill_id": skill_id, "path": f"<test:{skill_id}>", "relevance": 1.0}
                for skill_id in self.skill_ids
            ],
            "retrieved_context": [],
            "recommended_execution_focus": [],
        }


@pytest.fixture()
def multiskill_contract(monkeypatch: pytest.MonkeyPatch) -> str:
    phase_id = "PX"
    contracts = dict(core.PHASE_CONTRACTS)
    contracts[phase_id] = {
        "phase_id": phase_id,
        "name": "Multi Skill Test",
        "description": "test",
        "required_skills": ["skill.one", "skill.two"],
        "optional_skills": [],
        "required_tools": ["curl"],
        "optional_tools": [],
        "minimum_evidence": ["tool_output", "parsed_result"],
        "exit_criteria": {
            "minimum_required_tools_attempted": 1,
            "evidence_required": True,
            "validator_required": True,
            "allow_partial": True,
            "allow_skip": False,
            "minimum_evidence_strength": "medium",
        },
        "retry_policy": {"max_retries": 0, "fallback_allowed": False, "rag_reconsult_allowed": False},
    }
    monkeypatch.setattr(core, "PHASE_CONTRACTS", contracts)
    return phase_id


def test_multiskill_phase_uses_rich_dedup_not_tool_name(multiskill_contract: str) -> None:
    executions: list[dict[str, Any]] = []

    def call_tool(execution: dict[str, Any]) -> dict[str, Any]:
        executions.append(dict(execution))
        return {
            "status": "success",
            "exit_code": 0,
            "stdout": f"ran {execution['skill_id']}",
            "parsed_result": {"parameters": [execution["skill_id"].split(".")[-1]]},
        }

    runtime = core.OffensiveSkillRuntime(
        registry=_Registry([_skill("skill.one"), _skill("skill.two")]),  # type: ignore[arg-type]
        rag=_Rag(["skill.one"]),  # type: ignore[arg-type]
        executor=core.MCPToolExecutor(call_tool=call_tool, available=True),
    )
    scope = core.Scope(scope_id="test", allowed_domains=["example.com"], max_noise_level="high")

    result = runtime.run_phase(multiskill_contract, "example.com", scope, "controlled_pentest")

    assert result["phase_ledger"]["selected_skills"] == ["skill.one", "skill.two"]
    assert result["phase_ledger"]["status"] == "completed"
    assert len(executions) == 2
    assert len({ex["execution_key"] for ex in executions}) == 2
    assert [ex["skill_id"] for ex in executions] == ["skill.one", "skill.two"]
    assert result["phase_ledger"]["skill_coverage"]["skill.one"]["status"] == "completed"
    assert result["phase_ledger"]["skill_coverage"]["skill.two"]["status"] == "completed"


def test_evidence_uses_real_parsed_result(multiskill_contract: str) -> None:
    runtime = core.OffensiveSkillRuntime(
        registry=_Registry([_skill("skill.one")]),  # type: ignore[arg-type]
        rag=_Rag(["skill.one"]),  # type: ignore[arg-type]
        executor=core.MCPToolExecutor(
            call_tool=lambda _execution: {
                "status": "success",
                "exit_code": 0,
                "stdout": "accountId",
                "parsed_result": {"parameters": ["accountId"]},
            },
            available=True,
        ),
    )
    scope = core.Scope(scope_id="test", allowed_domains=["example.com"], max_noise_level="high")

    result = runtime.run_phase(multiskill_contract, "example.com", scope, "controlled_pentest")

    assert result["evidence"][0]["parsed_json"] == {"parameters": ["accountId"]}
    assert "reproducible" not in result["evidence"][0]["parsed_json"]
    assert result["offensive_state"]["open_hypotheses"]


def test_multiskill_required_tool_block_in_one_skill_is_partial(multiskill_contract: str) -> None:
    def call_tool(execution: dict[str, Any]) -> dict[str, Any]:
        if execution["skill_id"] == "skill.two":
            return {"status": "blocked", "error": "scope_fixture_block", "exit_code": None}
        return {
            "status": "success",
            "exit_code": 0,
            "stdout": "ok",
            "parsed_result": {"parameters": ["id"]},
        }

    runtime = core.OffensiveSkillRuntime(
        registry=_Registry([_skill("skill.one"), _skill("skill.two")]),  # type: ignore[arg-type]
        rag=_Rag(["skill.one", "skill.two"]),  # type: ignore[arg-type]
        executor=core.MCPToolExecutor(call_tool=call_tool, available=True),
    )
    scope = core.Scope(scope_id="test", allowed_domains=["example.com"], max_noise_level="high")

    result = runtime.run_phase(multiskill_contract, "example.com", scope, "controlled_pentest")

    assert result["phase_ledger"]["status"] == "partial"
    assert result["validator_decision"]["reason"] == "partial_skill_coverage"
    assert result["phase_ledger"]["skill_coverage"]["skill.one"]["status"] == "completed"
    assert result["phase_ledger"]["skill_coverage"]["skill.two"]["status"] == "blocked"


def test_backend_local_tool_runs_when_mcp_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    phase_id = "PY"
    contracts = dict(core.PHASE_CONTRACTS)
    contracts[phase_id] = {
        "phase_id": phase_id,
        "name": "Backend Local Test",
        "description": "test",
        "required_skills": ["skill.local"],
        "optional_skills": [],
        "required_tools": ["bl-test"],
        "optional_tools": [],
        "minimum_evidence": ["tool_output", "parsed_result"],
        "exit_criteria": {
            "minimum_required_tools_attempted": 1,
            "evidence_required": True,
            "validator_required": True,
            "allow_partial": True,
            "allow_skip": False,
            "minimum_evidence_strength": "medium",
        },
        "retry_policy": {"max_retries": 0, "fallback_allowed": False, "rag_reconsult_allowed": False},
    }
    monkeypatch.setattr(core, "PHASE_CONTRACTS", contracts)
    calls: list[dict[str, Any]] = []

    def call_tool(execution: dict[str, Any]) -> dict[str, Any]:
        calls.append(dict(execution))
        return {
            "status": "success",
            "exit_code": 0,
            "stdout": "business logic done",
            "parsed_result": {"findings": []},
        }

    runtime = core.OffensiveSkillRuntime(
        registry=_Registry([_skill("skill.local", "bl-test")]),  # type: ignore[arg-type]
        rag=_Rag(["skill.local"]),  # type: ignore[arg-type]
        executor=core.MCPToolExecutor(call_tool=call_tool, available=False),
    )
    scope = core.Scope(scope_id="test", allowed_domains=["example.com"], max_noise_level="high")

    result = runtime.run_phase(phase_id, "example.com", scope, "controlled_pentest")

    assert calls
    assert calls[0]["execution_backend"] == "backend_local"
    assert result["phase_ledger"]["status"] == "completed"
    assert result["mcp_results"][0]["status"] == "success"


def test_dependency_light_yaml_parser_preserves_skill_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core, "yaml", None)

    parsed = core.safe_yaml_load(
        """
skill_id: skill.test
phase_ids:
- P02
- P06
required_tools:
- naabu
optional_tools:
  - httpx
  - whatweb
exit_criteria:
  minimum_tools_attempted: 1
  validator_required: true
"""
    )

    assert parsed["phase_ids"] == ["P02", "P06"]
    assert parsed["required_tools"] == ["naabu"]
    assert parsed["optional_tools"] == ["httpx", "whatweb"]
    assert parsed["exit_criteria"]["minimum_tools_attempted"] == 1
    assert parsed["exit_criteria"]["validator_required"] is True


def test_phase_contracts_stay_phase_specific_when_skill_metadata_loads() -> None:
    contracts = core.default_phase_contracts("skills")

    assert contracts["P02"]["required_tools"] == ["naabu"]
    assert contracts["P06"]["required_tools"] == ["httpx"]
    assert contracts["P07"]["required_tools"] == ["whatweb"]
    assert "naabu" not in contracts["P06"]["required_tools"]
    assert "nuclei-headers" not in contracts["P02"]["optional_tools"]


def test_compiler_filters_shared_skill_tools_to_active_phase() -> None:
    contract = {
        "phase_id": "PX",
        "name": "Shared Skill Phase",
        "description": "test",
        "required_skills": ["skill.shared"],
        "optional_skills": [],
        "required_tools": ["curl"],
        "optional_tools": [],
        "minimum_evidence": ["tool_output", "parsed_result"],
        "exit_criteria": {
            "minimum_required_tools_attempted": 1,
            "evidence_required": True,
            "validator_required": True,
            "allow_partial": True,
            "allow_skip": False,
            "minimum_evidence_strength": "medium",
        },
        "retry_policy": {"max_retries": 0, "fallback_allowed": False, "rag_reconsult_allowed": False},
    }
    skill = _skill("skill.shared")
    skill["metadata"]["required_tools"] = ["curl", "ffuf", "httpx"]
    skill["metadata"]["optional_tools"] = ["nuclei-auth"]
    compiler = core.SkillToToolPlanCompiler()
    scope = core.Scope(scope_id="test", allowed_domains=["example.com"], max_noise_level="high")

    plan = compiler.compile(skill, contract, "example.com", scope, "controlled_pentest")

    assert [tool["tool_name"] for tool in plan["tools"]] == ["curl"]


def test_phase_tool_binding_prevents_unbound_skill_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core, "PHASE_TOOL_BINDINGS", {"PX": {"bl-test": ["skill.bound"]}})
    contract = {
        "phase_id": "PX",
        "name": "Bound Tool Phase",
        "description": "test",
        "required_skills": ["skill.bound", "skill.unbound"],
        "optional_skills": [],
        "required_tools": ["bl-test"],
        "optional_tools": ["curl"],
        "minimum_evidence": ["tool_output", "parsed_result"],
        "exit_criteria": {
            "minimum_required_tools_attempted": 1,
            "evidence_required": True,
            "validator_required": True,
            "allow_partial": True,
            "allow_skip": False,
            "minimum_evidence_strength": "medium",
        },
        "retry_policy": {"max_retries": 0, "fallback_allowed": False, "rag_reconsult_allowed": False},
    }
    unbound_skill = _skill("skill.unbound")
    unbound_skill["metadata"]["required_tools"] = ["bl-test", "curl"]
    compiler = core.SkillToToolPlanCompiler()
    scope = core.Scope(scope_id="test", allowed_domains=["example.com"], max_noise_level="high")

    plan = compiler.compile(unbound_skill, contract, "example.com", scope, "controlled_pentest")

    assert [tool["tool_name"] for tool in plan["tools"]] == ["curl"]
    assert all(tool["tool_name"] != "bl-test" for tool in plan["tools"])
