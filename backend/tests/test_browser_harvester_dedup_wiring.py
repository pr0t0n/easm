"""_run_browser_request_harvester_once must run the new harvester exactly
once per (target, identity) for a scan regardless of scan mode -- unlike
_run_lab_browser_capture_once, which only fires under _is_lab_fast_scan.
Also confirms P08 dispatch calls it unconditionally (not lab-gated) by
inspecting the source around the phase-dispatch loop.
"""
import inspect
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


def test_harvester_runs_once_per_target_and_is_skipped_on_repeat(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.services.browser_request_harvester.harvest_target",
        lambda db, job, target, identity_key="": (calls.append((target, identity_key)) or {"status": "success", "requests_captured": 1, "requests_persisted": 1}),
    )
    job = SimpleNamespace(id=1, state_data={})
    db = _FakeDb()

    first = runner._run_browser_request_harvester_once(db, job, "http://target.local")
    second = runner._run_browser_request_harvester_once(db, job, "http://target.local")

    assert first["status"] == "success"
    assert second == {"skipped": True, "reason": "already_harvested"}
    assert calls == [("http://target.local", "")]


def test_harvester_runs_separately_per_identity(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.services.browser_request_harvester.harvest_target",
        lambda db, job, target, identity_key="": (calls.append((target, identity_key)) or {"status": "success"}),
    )
    job = SimpleNamespace(id=1, state_data={})
    db = _FakeDb()

    runner._run_browser_request_harvester_once(db, job, "http://target.local", identity_key="user_a")
    runner._run_browser_request_harvester_once(db, job, "http://target.local", identity_key="user_b")

    assert calls == [("http://target.local", "user_a"), ("http://target.local", "user_b")]


def test_harvester_failure_is_caught_and_rolled_back(monkeypatch):
    monkeypatch.setattr(
        "app.services.browser_request_harvester.harvest_target",
        lambda db, job, target, identity_key="": (_ for _ in ()).throw(RuntimeError("boom")),
    )
    job = SimpleNamespace(id=1, state_data={})
    db = _FakeDb()

    result = runner._run_browser_request_harvester_once(db, job, "http://target.local")

    assert result["status"] == "error"
    assert db.rolled_back == 1


def test_p08_dispatch_calls_harvester_unconditionally_not_lab_gated():
    source = inspect.getsource(runner.run_offensive_operator_scan)
    lab_block_start = source.index('_is_lab_fast_scan(state, _effective_target)')
    lab_block_continue = source.index("continue", lab_block_start)
    harvester_call_pos = source.index('_run_browser_request_harvester_once(db, job, _effective_target)', lab_block_continue)
    phase_started_pos = source.index('create_operation_event("phase_started"', lab_block_continue)

    # The harvester call sits AFTER the lab-fast-path's own `continue` (i.e.
    # outside/independent of that branch) and BEFORE the normal phase
    # dispatch proceeds -- so it fires for every scan mode, not just lab.
    assert lab_block_continue < harvester_call_pos < phase_started_pos
