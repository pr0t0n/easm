from __future__ import annotations


def test_blocked_execution_is_not_persisted_as_evidence(monkeypatch):
    from app.db import session as session_module
    from app.services import worker_dispatcher

    calls: list[object] = []
    monkeypatch.setattr(session_module, "SessionLocal", lambda: calls.append(object()))

    worker_dispatcher._persist_result_artifact(
        66,
        {"status": "blocked", "tool": "bl-test", "target": "example.test"},
        {"phase_id": "P17"},
        {},
    )

    assert calls == []


def test_error_execution_is_not_persisted_as_evidence(monkeypatch):
    from app.db import session as session_module
    from app.services import worker_dispatcher

    calls: list[object] = []
    monkeypatch.setattr(session_module, "SessionLocal", lambda: calls.append(object()))

    worker_dispatcher._persist_result_artifact(
        66,
        {"status": "error", "tool": "nuclei", "target": "example.test"},
        {"phase_id": "P08"},
        {},
    )

    assert calls == []
