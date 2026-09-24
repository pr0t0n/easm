"""_execute_business_logic_actions_once closes the final link in the BOLA
chain found live against Juice Shop: even with real object_authorization
actions computed (two-identity self-registration + object_reference gate
widening + auth_required marking on synthesized endpoints all working),
`worker_dispatcher.py`'s bl-test handler only ever narrows the broad,
already-computed execution plan down to whatever single endpoint a skill's
own static "validation_wire" binding names. A static per-skill binding can
never know in advance which endpoint this specific scan's own evidence-
synthesis discovered, so every actual bl-test invocation kept reporting
"0 ações; pré-condições/contratos pendentes" even though the broad plan had
16 real, ready cross-identity actions -- confirmed live via
`_business_logic_execution_plan(scan_id, wire_contract=None)`. This function
runs that same broad, real "observed-evidence-only" plan directly, bypassing
only the skill/wire narrowing gate (not the evidence gate itself), so
already-computed real actions actually execute. These tests mock
business_logic_test.run_as_tool and the worker_dispatcher helpers, matching
this repo's fake-db unit-test convention.
"""
from types import SimpleNamespace

from app.services import offensive_operator_runner as runner


class _FakeDb:
    def __init__(self):
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def _job():
    return SimpleNamespace(id=12, state_data={})


def test_skips_when_already_attempted():
    job = SimpleNamespace(id=12, state_data={"_business_logic_direct_execution_attempted": True})

    result = runner._execute_business_logic_actions_once(_FakeDb(), job, "http://target.local")

    assert result == {"skipped": True, "reason": "already_attempted"}


def test_no_broad_actions_is_a_clean_noop(monkeypatch):
    import app.services.worker_dispatcher as dispatcher_module

    monkeypatch.setattr(
        dispatcher_module, "_business_logic_execution_plan",
        lambda scan_id, wire_contract=None: {"actions": [], "blocked": []},
    )
    bl_run_calls = []
    import app.services.business_logic_test as bl_module
    monkeypatch.setattr(bl_module, "run_as_tool", lambda *a, **k: bl_run_calls.append((a, k)))

    db = _FakeDb()
    result = runner._execute_business_logic_actions_once(db, _job(), "http://target.local")

    assert result == {"actions": 0}
    assert bl_run_calls == []


def test_real_broad_actions_are_executed_directly_with_both_identities(monkeypatch):
    import app.services.worker_dispatcher as dispatcher_module
    import app.services.business_logic_test as bl_module

    actions = [
        {"endpoint": "http://target.local/api/BasketItems/3", "required_identities": ["user_a", "user_b"]},
        {"endpoint": "http://target.local/api/Feedbacks/1", "required_identities": ["user_a", "user_b"]},
    ]
    plan = {"actions": actions, "blocked": [], "policy": "observed-evidence-only"}
    monkeypatch.setattr(
        dispatcher_module, "_business_logic_execution_plan",
        lambda scan_id, wire_contract=None: plan,
    )
    identities = {"user_a": {"headers": {}}, "user_b": {"headers": {}}}
    monkeypatch.setattr(dispatcher_module, "_resolve_auth_identities", lambda scan_id, identity_keys=None: identities)

    persist_calls = []
    monkeypatch.setattr(
        dispatcher_module, "_persist_result_artifact",
        lambda scan_id, result, skill_contract, auth_context: persist_calls.append((scan_id, result)),
    )

    bl_run_calls = []

    def _fake_run_as_tool(target, **kwargs):
        bl_run_calls.append((target, kwargs))
        return {"status": "completed", "stdout": "business_logic: 2 ações executadas"}

    monkeypatch.setattr(bl_module, "run_as_tool", _fake_run_as_tool)

    db = _FakeDb()
    job = _job()
    result = runner._execute_business_logic_actions_once(db, job, "http://target.local")

    assert result == {"actions": 2, "status": "completed"}
    assert job.state_data["_business_logic_direct_execution_attempted"] is True
    assert len(bl_run_calls) == 1
    target_arg, kwargs = bl_run_calls[0]
    assert target_arg == "http://target.local"
    assert kwargs["execution_plan"] is plan
    assert kwargs["identity_sessions"] == identities
    assert len(persist_calls) == 1
    assert persist_calls[0][0] == job.id


def test_execution_exception_is_caught_and_logged(monkeypatch):
    import app.services.worker_dispatcher as dispatcher_module

    def _boom(scan_id, wire_contract=None):
        raise RuntimeError("db unavailable")

    monkeypatch.setattr(dispatcher_module, "_business_logic_execution_plan", _boom)

    db = _FakeDb()
    result = runner._execute_business_logic_actions_once(db, _job(), "http://target.local")

    assert "error" in result
    assert "db unavailable" in result["error"]
    assert db.rollbacks == 1
    assert any("business_logic_direct_execution_failed" in getattr(row, "message", "") for row in db.added)
