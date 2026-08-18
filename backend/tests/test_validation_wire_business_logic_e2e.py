from __future__ import annotations

import httpx

from app.services import business_logic_test
from app.services.poc_outcome import classify_poc_work_item
from app.services import worker_dispatcher
from app.services.evidence_contract_service import create_artifact_from_tool_result


def _plan(target: str) -> dict:
    return {
        "policy": "validation-wire-exact-observed-evidence-only",
        "actions": [{
            "endpoint": target,
            "method": "GET",
            "parameters": ["object_id"],
            "required_identities": ["tenant_owner", "tenant_attacker"],
            "validation_wire_id": 91,
            "flows": ["object_ownership"],
            "invariants": ["object_owner_boundary"],
        }],
        "blocked": [],
    }


def _sessions() -> dict:
    return {
        "tenant_owner": {"headers": {"Authorization": "Bearer owner"}, "cookies": {}},
        "tenant_attacker": {"headers": {"Authorization": "Bearer attacker"}, "cookies": {}},
    }


def test_exact_wire_executes_same_object_with_both_bound_identities(monkeypatch):
    target = "https://app.test/api/accounts/object-123"
    seen: list[tuple[str, str]] = []
    original_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers.get("authorization", "")))
        return httpx.Response(200, json={"id": "object-123", "owner": "tenant_owner"})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        business_logic_test.httpx,
        "Client",
        lambda *args, **kwargs: original_client(transport=transport, **kwargs),
    )

    result = business_logic_test.run_as_tool(
        target,
        execution_plan=_plan(target),
        identity_sessions=_sessions(),
        run_business_logic_battery=False,
    )

    assert seen == [(target, "Bearer owner"), (target, "Bearer attacker")]
    assert result["parsed"]["vulnerable"] is True
    assert result["parsed"]["wire_assessments"][0]["validation_wire_id"] == 91
    assert result["parsed"]["wire_assessments"][0]["evidence_status"] == "positive_authorization_bypass"


def test_exact_wire_produces_negative_proof_only_when_owner_succeeds_and_attacker_is_denied(monkeypatch):
    target = "https://app.test/api/accounts/object-123"
    original_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") == "Bearer attacker":
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(200, json={"id": "object-123", "owner": "tenant_owner"})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        business_logic_test.httpx,
        "Client",
        lambda *args, **kwargs: original_client(transport=transport, **kwargs),
    )

    result = business_logic_test.run_as_tool(
        target,
        execution_plan=_plan(target),
        identity_sessions=_sessions(),
        run_business_logic_battery=False,
    )

    assert result["parsed"]["vulnerable"] is False
    assert result["parsed"]["negative_control_passed"] is True
    item = type("Item", (), {"status": "completed", "tool_name": "bl-test", "result": {"parsed_result": result["parsed"]}})()
    assert classify_poc_work_item(item)["result"] == "refuted"


def test_exact_wire_makes_no_request_when_secondary_identity_material_is_missing(monkeypatch):
    target = "https://app.test/api/accounts/object-123"
    requests_made = 0
    original_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests_made
        requests_made += 1
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        business_logic_test.httpx,
        "Client",
        lambda *args, **kwargs: original_client(transport=transport, **kwargs),
    )

    result = business_logic_test.run_as_tool(
        target,
        execution_plan=_plan(target),
        identity_sessions={"tenant_owner": _sessions()["tenant_owner"]},
        run_business_logic_battery=False,
    )

    assert requests_made == 0
    assert result["parsed"]["summary"]["observed"] == 0
    assert result["parsed"]["blocked"][0]["reasons"] == [
        "wire_identity_material_missing:tenant_attacker"
    ]


def test_dispatcher_forwards_the_exact_wire_and_identity_keys(monkeypatch):
    wire = {
        "id": 91,
        "action_id": "compare_two_identities",
        "target_ref": "https://app.test/api/accounts/object-123",
        "parameter_ref": "object_id",
        "identity_key": "tenant_owner",
        "secondary_identity_key": "tenant_attacker",
        "input_bindings": {"finding_id": 44, "object_id": "object-123", "method": "GET"},
    }
    captured: dict = {}

    def fake_plan(scan_id, wire_contract=None):
        captured["scan_id"] = scan_id
        captured["wire_contract"] = wire_contract
        return _plan(wire["target_ref"])

    def fake_identities(scan_id, identity_keys=None):
        captured["identity_keys"] = identity_keys
        return _sessions()

    def fake_run(target, **kwargs):
        captured["target"] = target
        captured["execution_plan"] = kwargs["execution_plan"]
        captured["identity_sessions"] = kwargs["identity_sessions"]
        return {"status": "done", "return_code": 0, "parsed": {"vulnerable": True}, "stdout": "confirmed"}

    monkeypatch.setattr(worker_dispatcher, "_business_logic_execution_plan", fake_plan)
    monkeypatch.setattr(worker_dispatcher, "_resolve_auth_identities", fake_identities)
    monkeypatch.setattr(worker_dispatcher, "_resolve_auth_context", lambda *args, **kwargs: {})
    monkeypatch.setattr(worker_dispatcher, "_persist_result_artifact", lambda *args, **kwargs: None)
    monkeypatch.setattr(business_logic_test, "run_as_tool", fake_run)

    result = worker_dispatcher.execute_tool_with_workers(
        "bl-test",
        wire["target_ref"],
        scan_id=77,
        skill_contract={
            "phase_id": "P21",
            "identity_key": "tenant_owner",
            "secondary_identity_key": "tenant_attacker",
            "validation_wire": wire,
            "input_bindings": wire["input_bindings"],
        },
    )

    assert captured["wire_contract"] == wire
    assert captured["identity_keys"] == ["tenant_owner", "tenant_attacker"]
    assert captured["target"] == wire["target_ref"]
    assert captured["identity_sessions"] == _sessions()
    assert result["validation_wire"] == wire


def test_wire_result_becomes_a_finding_bound_reproduction_pair():
    class Db:
        def __init__(self):
            self.rows = []

        def add(self, row):
            self.rows.append(row)

        def flush(self):
            return None

    wire = {
        "id": 91,
        "target_ref": "https://app.test/api/accounts/object-123",
        "parameter_ref": "object_id",
        "identity_key": "tenant_owner",
        "secondary_identity_key": "tenant_attacker",
        "input_bindings": {"method": "GET", "object_id": "object-123"},
    }
    result = {
        "status": "done",
        "tool": "bl-test",
        "target": wire["target_ref"],
        "validation_wire": wire,
        "input_bindings": wire["input_bindings"],
        "parsed": {
            "vulnerable": True,
            "confirmed": True,
            "observations": [
                {"identity_key": "tenant_owner", "body_fingerprint": "same"},
                {"identity_key": "tenant_attacker", "body_fingerprint": "same"},
            ],
        },
    }

    artifact = create_artifact_from_tool_result(
        Db(), scan_job_id=77, finding_id=44, phase_id="P21", result=result,
    )

    assert artifact.finding_id == 44
    assert artifact.validation_status == "confirmed"
    assert artifact.baseline_response_ref == "validation-wire:91:primary:same"
    assert artifact.exploit_response_ref == "validation-wire:91:attempt:same"
    assert artifact.artifact_metadata["validation_wire_id"] == 91
