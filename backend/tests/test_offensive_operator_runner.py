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

    def fake_call(execution, authorized_scope=None, scan_id=None):
        captured["phase_id"] = execution["phase_id"]
        captured["authorized_scope"] = authorized_scope
        captured["scan_id"] = scan_id
        return {"status": "success", "exit_code": 0}

    monkeypatch.setattr(
        "app.services.offensive_operator_runner._call_mcp_execution",
        fake_call,
    )
    call_tool = _call_operator_tool(True, ["valid.com"], 8)
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
    assert captured == {
        "phase_id": "P01",
        "authorized_scope": ["valid.com"],
        "scan_id": 8,
    }


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
        scan_id=8,
    )

    payload = captured["payload"]
    assert payload["arguments"]["authorized_scope"] == ["valid.com"]
    assert payload["arguments"]["scan_id"] == 8


def test_chromium_capture_dispatch_populates_generic_spa_routes(monkeypatch) -> None:
    # Regression: this is the ACTUAL live P08 dispatch path (every real scan
    # goes through _call_mcp_execution -> mcp_server -> kali_runner), unlike
    # browser_capture_service.py's _run_chromium_capture, which only the rare
    # "_lab_fast_path" helper calls. Confirmed live on Juice Shop scans #40-44:
    # chromium-capture only ever saw the ~6 XHRs that fire on "/" because
    # nothing on this path ever populated extra_args (ROUTES was always
    # empty), so the app's real REST surface (basket, profile, search, ...)
    # was never discovered.
    from app.services.browser_capture_service import _GENERIC_SPA_ROUTES

    captured: dict[str, object] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"status": "failed", "error": "test_terminal_response"}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return FakeResponse()

    monkeypatch.setattr(
        "app.services.offensive_operator_runner.requests.post",
        fake_post,
    )
    _call_mcp_execution(
        {
            "phase_id": "P08",
            "skill_id": "skill.discovery.endpoint_discovery",
            "tool_name": "chromium-capture",
            "profile": "chromium_capture",
            "target": "http://juice-shop-local:3000",
            "arguments": {"target": "http://juice-shop-local:3000"},
        },
        authorized_scope=["juice-shop-local"],
        scan_id=44,
    )

    extra_args = captured["payload"]["arguments"]["extra_args"]
    assert len(extra_args) == 4
    assert extra_args[3] == ",".join(_GENERIC_SPA_ROUTES)
    # mcp_server's own extra_args guardrail (_apply_guardrail) drops any
    # element where str(arg).strip() is falsy -- an empty-string placeholder
    # for the unused TOKEN/USER/PASS slots would silently vanish there,
    # shifting ROUTES left into an earlier positional slot. Confirmed live on
    # scan #45: this put the ROUTES csv in cdp_capture.py's TOKEN slot,
    # corrupting localStorage. Every element must be non-empty.
    for arg in extra_args:
        assert str(arg).strip(), f"empty extra_arg would be dropped by mcp_server's guardrail: {extra_args!r}"


def test_chromium_capture_dispatch_always_targets_the_origin_not_the_phase_endpoint(monkeypatch) -> None:
    # chromium-capture's ROUTES navigation is only meaningful relative to the
    # SPA's own root -- the phase loop's "effective target" for this call can
    # be whatever narrow endpoint the current phase iteration is probing for
    # OTHER tools. Confirmed live on scan #46: dispatched against
    # "/redirect?to=https" instead of "/", so hash-route navigation happened
    # on top of a redirect page instead of the app shell.
    captured: dict[str, object] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"status": "failed", "error": "test_terminal_response"}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return FakeResponse()

    monkeypatch.setattr(
        "app.services.offensive_operator_runner.requests.post",
        fake_post,
    )
    _call_mcp_execution(
        {
            "phase_id": "P13",
            "skill_id": "skill.vuln.business_logic",
            "tool_name": "chromium-capture",
            "profile": "chromium_capture",
            "target": "http://juice-shop-local:3000/redirect?to=https",
            "arguments": {"target": "http://juice-shop-local:3000/redirect?to=https"},
        },
        authorized_scope=["juice-shop-local"],
        scan_id=46,
    )

    # kali_runner's {target} substitution reads the request's top-level
    # "target" (its JobRequest model has no nested arguments.target at all)
    # -- that is the field that actually matters for what cdp_capture.py
    # navigates to.
    assert captured["payload"]["target"] == "http://juice-shop-local:3000/"


def test_chromium_capture_dispatch_does_not_override_caller_supplied_extra_args(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"status": "failed", "error": "test_terminal_response"}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return FakeResponse()

    monkeypatch.setattr(
        "app.services.offensive_operator_runner.requests.post",
        fake_post,
    )
    _call_mcp_execution(
        {
            "phase_id": "P08",
            "skill_id": "skill.discovery.endpoint_discovery",
            "tool_name": "chromium-capture",
            "profile": "chromium_capture",
            "target": "http://juice-shop-local:3000",
            "arguments": {"target": "http://juice-shop-local:3000", "extra_args": ["already-set"]},
        },
        authorized_scope=["juice-shop-local"],
        scan_id=44,
    )

    assert captured["payload"]["arguments"]["extra_args"] == ["already-set"]


def test_all_controlled_pentest_phases_can_advance_with_successful_tool_results() -> None:
    # P20/P21/P22 are real evidence-adjudication reviewers now (not Kali
    # placeholders), so they require "strong" evidence (a reproducible
    # request/response pair) rather than a bare successful exit code --
    # simulate that a backend-local reviewer actually found something to
    # correlate/adjudicate/report on, the same shape phase_control_tools.py
    # produces when the scan has real findings to work from.
    _STRONG_EVIDENCE_TOOLS = {"attack-path-correlator", "evidence-adjudicator", "report-snapshot-builder"}

    def _fake_call_tool(execution):
        result = {"status": "success", "exit_code": 0, "stdout_path": "/tmp/tool-output.txt"}
        if execution.get("tool_name") in _STRONG_EVIDENCE_TOOLS:
            result["parsed_result"] = {"reproducible": True, "request_response_pair": True}
        return result

    job = ScanJob(id=1, owner_id=1, target_query="valid.com", state_data={})
    scope = _scope_from_job(job, "valid.com", "controlled_pentest")
    runtime = OffensiveSkillRuntime(
        executor=MCPToolExecutor(
            call_tool=_fake_call_tool,
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
