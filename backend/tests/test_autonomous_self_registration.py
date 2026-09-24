"""_ensure_autonomous_self_registration_once gives the platform a path to
TWO authenticated sessions on scans with no operator-supplied auth_config at
all (every purely black-box scan) -- previously AuthSessionManager.ensure_sessions
was a silent no-op in that case, and dozens of authenticated-only
vulnerability classes were untestable. Two independent throwaway accounts
(not just one) are registered because the platform's existing cross-identity
BOLA/IDOR engine (bola_probe.py, business_logic_test.py) only activates once
at least two distinct valid sessions exist -- it picks whichever sessions it
finds, with no requirement on specific role names. These tests mock
execute_via_kali and AuthSessionManager (both imported lazily inside the
function under test), matching this repo's fake-db unit-test convention
rather than hitting a real database or spawning a real kali-runner job.
"""
import json
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
    return SimpleNamespace(id=7, state_data={})


def test_skips_when_already_attempted(monkeypatch):
    calls = []
    monkeypatch.setattr(
        runner, "execute_via_kali", lambda *a, **k: calls.append((a, k)), raising=False,
    )
    job = SimpleNamespace(id=7, state_data={"_self_registration_attempted": True})

    result = runner._ensure_autonomous_self_registration_once(_FakeDb(), job, "http://target.local")

    assert result == {"skipped": True, "reason": "already_attempted"}
    assert calls == []


def test_successful_registration_and_login_persists_two_independent_identities(monkeypatch):
    import app.services.kali_executor as kali_executor_module
    import app.services.auth_session_manager as auth_session_manager_module

    call_count = {"n": 0}

    def _fake_execute(tool, target, **k):
        call_count["n"] += 1
        payload = {
            "registered": True,
            "logged_in": True,
            "email": f"pentest.abc{call_count['n']}@scriptkiddo.test",
            "auth_token": f"eyJhbGciOiJIUzI1NiJ9.fake.sig{call_count['n']}",
            "set_cookie": None,
        }
        return {"stdout": json.dumps(payload)}

    monkeypatch.setattr(kali_executor_module, "execute_via_kali", _fake_execute)

    captured_calls = []

    class _FakeAuthSessionManager:
        def __init__(self, db, scan):
            self.db = db
            self.scan = scan

        def upsert_captured_material(self, **kwargs):
            captured_calls.append(kwargs)

    monkeypatch.setattr(auth_session_manager_module, "AuthSessionManager", _FakeAuthSessionManager)

    db = _FakeDb()
    job = _job()
    result = runner._ensure_autonomous_self_registration_once(db, job, "http://target.local")

    assert result == {
        "self_registered_user_a": {"registered": True, "logged_in": True, "identity_key": "self_registered_user_a"},
        "self_registered_user_b": {"registered": True, "logged_in": True, "identity_key": "self_registered_user_b"},
    }
    assert job.state_data["_self_registration_attempted"] is True
    assert call_count["n"] == 2
    assert len(captured_calls) == 2
    identity_keys = {c["identity_key"] for c in captured_calls}
    assert identity_keys == {"self_registered_user_a", "self_registered_user_b"}
    for call in captured_calls:
        material = call["material"]
        assert material.identity_key == call["identity_key"]
        assert material.role == "customer"
        assert material.auth_type == "bearer_token"
    usernames = {c["username_ref"] for c in captured_calls}
    assert usernames == {"pentest.abc1@scriptkiddo.test", "pentest.abc2@scriptkiddo.test"}


def test_registration_without_extractable_session_does_not_persist_material(monkeypatch):
    import app.services.kali_executor as kali_executor_module
    import app.services.auth_session_manager as auth_session_manager_module

    payload = {"registered": True, "logged_in": False}
    monkeypatch.setattr(
        kali_executor_module, "execute_via_kali",
        lambda tool, target, **k: {"stdout": json.dumps(payload)},
    )
    captured_calls = []
    monkeypatch.setattr(
        auth_session_manager_module, "AuthSessionManager",
        lambda db, scan: SimpleNamespace(
            upsert_captured_material=lambda **kw: captured_calls.append(kw)
        ),
    )

    result = runner._ensure_autonomous_self_registration_once(_FakeDb(), _job(), "http://target.local")

    assert result == {
        "self_registered_user_a": {"registered": True, "logged_in": False},
        "self_registered_user_b": {"registered": True, "logged_in": False},
    }
    assert captured_calls == []


def test_kali_executor_exception_is_caught_and_logged(monkeypatch):
    import app.services.kali_executor as kali_executor_module

    def _boom(tool, target, **k):
        raise RuntimeError("kali-runner unreachable")

    monkeypatch.setattr(kali_executor_module, "execute_via_kali", _boom)

    db = _FakeDb()
    result = runner._ensure_autonomous_self_registration_once(db, _job(), "http://target.local")

    assert "error" in result
    assert "kali-runner unreachable" in result["error"]
    assert db.rollbacks == 1
    assert any("autonomous_self_registration_failed" in getattr(row, "message", "") for row in db.added)
