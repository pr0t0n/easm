from __future__ import annotations

from app.models.models import ScanJob
from app.services.offensive_operator_core import ExecutionPolicyEngine
from app.services.offensive_operator_core import MCPToolExecutor
from app.services.offensive_operator_core import OffensiveSkillRuntime
from app.services.offensive_operator_core import PHASE_ORDER
from app.services.offensive_operator_core import create_offensive_state
from app.services.offensive_operator_runner import _parse_targets_from_query
from app.services.offensive_operator_runner import _scope_from_job
from app.services.offensive_operator_runner import _call_mcp_execution
from app.services.offensive_operator_runner import _call_operator_tool


def test_parse_targets_from_query_handles_semicolon_and_comma_separated_values() -> None:
    raw = "valid.com; validecertificadora.com.br, example.org\nlocalhost"
    parsed = _parse_targets_from_query(raw)
    assert parsed == [
        "valid.com",
        "validecertificadora.com.br",
        "example.org",
        "localhost",
    ]


def test_controlled_pentest_default_scope_allows_high_noise_phase_tools() -> None:
    job = ScanJob(id=1, owner_id=1, target_query="valid.com", state_data={})
    scope = _scope_from_job(job, "valid.com", "controlled_pentest")
    decision = ExecutionPolicyEngine().decide(
        {
            "execution_mode": "controlled_pentest",
            "tool_name": "ffuf",
            "target": "valid.com",
            "scope": scope,
            "payload_family": "skill.discovery.endpoint_discovery",
            "noise_level": "high",
            "expected_evidence": ["discovered_paths"],
        }
    )

    assert scope.max_noise_level == "high"
    assert decision["allowed"] is True


def test_safe_validation_default_scope_keeps_high_noise_tools_blocked() -> None:
    job = ScanJob(id=1, owner_id=1, target_query="valid.com", state_data={})
    scope = _scope_from_job(job, "valid.com", "safe_validation")
    decision = ExecutionPolicyEngine().decide(
        {
            "execution_mode": "safe_validation",
            "tool_name": "ffuf",
            "target": "valid.com",
            "scope": scope,
            "payload_family": "skill.discovery.endpoint_discovery",
            "noise_level": "high",
            "expected_evidence": ["discovered_paths"],
        }
    )

    assert scope.max_noise_level == "medium"
    assert decision["allowed"] is False
    assert decision["blocked_reason"] == "noise_level_exceeds_scope"


def test_p01_operator_forwards_scan_authorized_scope(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_call(execution, authorized_scope=None):
        captured["phase_id"] = execution["phase_id"]
        captured["authorized_scope"] = authorized_scope
        return {"status": "success", "exit_code": 0}

    monkeypatch.setattr(
        "app.services.offensive_operator_runner._call_mcp_execution",
        fake_call,
    )
    call_tool = _call_operator_tool(True, ["valid.com"])
    result = call_tool(
        {
            "phase_id": "P01",
            "skill_id": "skill.recon.subdomain_enumeration",
            "tool_name": "subfinder",
            "profile": "subfinder_passive",
            "target": "valid.com",
            "arguments": {"target": "valid.com"},
        }
    )

    assert result["status"] == "success"
    assert captured == {"phase_id": "P01", "authorized_scope": ["valid.com"]}


def test_mcp_payload_contains_authorized_scope(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"status": "failed", "error": "test_terminal_response"}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["payload"] = json
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(
        "app.services.offensive_operator_runner.requests.post",
        fake_post,
    )
    _call_mcp_execution(
        {
            "phase_id": "P01",
            "skill_id": "skill.recon.subdomain_enumeration",
            "tool_name": "subfinder",
            "profile": "subfinder_passive",
            "target": "valid.com",
            "arguments": {"target": "valid.com"},
        },
        authorized_scope=["valid.com"],
    )

    payload = captured["payload"]
    assert payload["arguments"]["authorized_scope"] == ["valid.com"]


def test_all_controlled_pentest_phases_can_advance_with_successful_tool_results() -> None:
    job = ScanJob(id=1, owner_id=1, target_query="valid.com", state_data={})
    scope = _scope_from_job(job, "valid.com", "controlled_pentest")
    runtime = OffensiveSkillRuntime(
        executor=MCPToolExecutor(
            call_tool=lambda _execution: {
                "status": "success",
                "exit_code": 0,
                "stdout_path": "/tmp/tool-output.txt",
            },
            available=True,
        )
    )
    state = create_offensive_state("valid.com", campaign_id="test")

    blocked = []
    for phase_id in PHASE_ORDER:
        result = runtime.run_phase(phase_id, "valid.com", scope, "controlled_pentest", state)
        state = result["offensive_state"]
        if result["phase_ledger"]["status"] == "blocked":
            blocked.append((phase_id, result["phase_ledger"].get("blocking_reason")))

    assert blocked == []
