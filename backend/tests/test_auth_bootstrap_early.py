"""AuthSessionManager.ensure_sessions() -- the only call site that actually
logs in and persists ScanIdentity/ScanAuthSession -- used to run exclusively
from a P21 hypothesis-drain work item, near the end of the pipeline, so
every stateful phase before P21 (P08-P19) dispatched its tools with zero
session material for any scan with auth_config configured.
_ensure_auth_sessions_once fixes the timing (not the mechanism): called once
per scan, idempotent, no-op when auth_config isn't set.
"""
from types import SimpleNamespace

from app.services import offensive_operator_runner as runner


class _FakeDb:
    def __init__(self):
        self.logs = []
        self.committed = 0
        self.rolled_back = 0

    def add(self, row):
        self.logs.append(row)

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1


def test_ensure_auth_sessions_once_calls_ensure_sessions(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.services.auth_session_manager.AuthSessionManager",
        lambda db, job: SimpleNamespace(
            ensure_sessions=lambda: (calls.append(job.id) or {"ready": True, "auth_type": "form_login", "identities": ["user_a"]})
        ),
    )
    job = SimpleNamespace(id=1, state_data={})
    db = _FakeDb()

    result = runner._ensure_auth_sessions_once(db, job)

    assert result["ready"] is True
    assert calls == [1]
    assert job.state_data.get("_auth_sessions_bootstrapped") is True


def test_ensure_auth_sessions_once_is_deduped_per_scan_not_per_target(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.services.auth_session_manager.AuthSessionManager",
        lambda db, job: SimpleNamespace(ensure_sessions=lambda: (calls.append(1) or {"ready": True})),
    )
    job = SimpleNamespace(id=1, state_data={})
    db = _FakeDb()

    first = runner._ensure_auth_sessions_once(db, job)
    second = runner._ensure_auth_sessions_once(db, job)

    assert first["ready"] is True
    assert second == {"skipped": True, "reason": "already_bootstrapped"}
    assert len(calls) == 1


def test_ensure_auth_sessions_once_failure_is_caught_and_rolled_back(monkeypatch):
    monkeypatch.setattr(
        "app.services.auth_session_manager.AuthSessionManager",
        lambda db, job: SimpleNamespace(ensure_sessions=lambda: (_ for _ in ()).throw(RuntimeError("login boom"))),
    )
    job = SimpleNamespace(id=1, state_data={})
    db = _FakeDb()

    result = runner._ensure_auth_sessions_once(db, job)

    assert result["ready"] is False
    assert "login boom" in result["error"]
    assert db.rolled_back == 1


def test_p08_dispatch_bootstraps_auth_before_harvesting():
    import inspect

    source = inspect.getsource(runner.run_offensive_operator_scan)
    p08_block_pos = source.index('if phase_id == "P08":')
    bootstrap_pos = source.index("_ensure_auth_sessions_once(db, job)", p08_block_pos)
    anon_harvest_pos = source.index(
        "_run_browser_request_harvester_once(db, job, _effective_target)", p08_block_pos
    )
    identity_loop_pos = source.index("list_material(limit=4)", p08_block_pos)

    # Auth must be bootstrapped before either harvest pass so identities
    # actually exist when list_material() is queried.
    assert p08_block_pos < bootstrap_pos < anon_harvest_pos < identity_loop_pos
