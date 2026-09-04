from __future__ import annotations

from types import SimpleNamespace


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


def test_work_item_persistence_uses_backend_local_extracted_findings(monkeypatch):
    from app.services import findings_extractor

    captured = {}

    def fake_persist(db, job, raw_findings, **kwargs):
        captured["raw_findings"] = raw_findings
        captured["kwargs"] = kwargs
        return len(raw_findings)

    monkeypatch.setattr(findings_extractor, "persist_finding_dicts", fake_persist)
    monkeypatch.setattr(findings_extractor, "_try_ingest_spec_from_findings", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(findings_extractor, "_persist_extractor_meta", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(findings_extractor, "extract_findings_from_work_item", lambda *_args, **_kwargs: [])

    item = SimpleNamespace(
        tool_name="zap-api",
        target="https://api.example.test",
        phase_id="P16",
        item_metadata={},
        result={
            "findings_extracted": [{
                "title": "Strict-Transport-Security Header Not Set",
                "severity": "low",
                "details": {"tool": "zap-api"},
            }],
            "parsed_result": {"imported_url_count": 198},
        },
    )
    job = SimpleNamespace(id=15, target_query="api.example.test")

    created = findings_extractor.persist_findings_from_work_item(object(), item, job)

    assert created == 1
    assert captured["raw_findings"][0]["details"]["tool"] == "zap-api"
    assert captured["raw_findings"][0]["details"]["source_tool"] == "zap-api"
    assert captured["raw_findings"][0]["details"]["api_tested_via"] == "openapi_dast"
    assert captured["kwargs"]["default_tool"] == "zap-api"
