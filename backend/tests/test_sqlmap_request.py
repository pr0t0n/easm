from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.models.models import ObservedRequest, ScanWorkItem
from app.services.sqlmap_request import resolve_sqlmap_request
from app.services import scan_work_queue


def observed_db(rows):
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.all.return_value = rows
    return db


@pytest.mark.parametrize("query", ["id=1", "id=", "id=1&id=2", "q=a%20b"])
def test_get_parameters_do_not_require_post_body(query):
    db = observed_db([])
    result = resolve_sqlmap_request(db, 7, f"https://example.test/items?{query}")
    assert result == {"profile": "sqlmap_basic", "arguments": {}, "reason": ""}
    db.query.assert_not_called()


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
def test_captured_body_preserves_request(method):
    body = '{"id":42,"name":"real value"}'
    db = observed_db([
        SimpleNamespace(request_body={}, method=method),
        SimpleNamespace(request_body={"body": body}, method=method, request_content_type="application/json"),
    ])
    result = resolve_sqlmap_request(db, 7, "https://example.test/items", env={"SCAN_HTTP_METHOD": method})
    assert result == {
        "profile": "sqlmap_body",
        "arguments": {
            "SCAN_HTTP_METHOD": method,
            "SCAN_FUZZ_POST_DATA": body,
            "SCAN_FUZZ_CONTENT_TYPE": "application/json",
        },
        "reason": "",
    }
    clauses = db.query.return_value.filter.call_args.args
    bindings = [clause.compile().params for clause in clauses]
    assert {"scan_job_id_1": 7} in bindings
    assert {"url_1": "https://example.test/items"} in bindings
    assert {"method_1": [method]} in bindings


@pytest.mark.parametrize("env,profile", [({}, "sqlmap_body"), ({"SCAN_HTTP_METHOD": "POST"}, "sqlmap_basic")])
def test_explicit_body_request_cannot_fall_back_to_get(env, profile):
    result = resolve_sqlmap_request(observed_db([]), 7, "https://example.test/items?id=1", profile, env)
    assert result["reason"] == "required_evidence_absent:post_body"


def test_supplied_body_selects_body_profile_with_query_parameters():
    env = {"SCAN_HTTP_METHOD": "PATCH", "SCAN_FUZZ_POST_DATA": '{"id":1}', "SCAN_FUZZ_CONTENT_TYPE": "application/json"}
    db = observed_db([])
    result = resolve_sqlmap_request(db, 7, "https://example.test/items?id=1", env=env)
    assert result["profile"] == "sqlmap_body"
    assert result["arguments"] == env
    db.query.assert_not_called()


def test_database_failure_is_not_reported_as_missing_evidence():
    db = MagicMock()
    db.query.side_effect = RuntimeError("database unavailable")
    with pytest.raises(RuntimeError, match="database unavailable"):
        resolve_sqlmap_request(db, 7, "https://example.test/items")


def test_reconciler_waits_for_actual_body_before_requeue(monkeypatch):
    target = "https://example.test/items"
    item = SimpleNamespace(
        id=42, scan_job_id=7, tool_name="sqlmap", profile="sqlmap_body", target=target,
        status="skipped", attempts=2, item_metadata={},
        last_error="skipped:applicability:required_evidence_absent:post_body",
    )
    job = SimpleNamespace(id=7, status="running", state_data={"known_parameters": [{"url": target, "name": "id"}]})
    rows = []
    db = MagicMock()
    work_query = MagicMock()
    work_query.filter.return_value.all.side_effect = lambda: [item] if item.status == "skipped" else []
    request_query = MagicMock()
    request_query.filter.return_value.order_by.return_value.all.side_effect = lambda: rows
    db.query.side_effect = lambda model: work_query if model is ScanWorkItem else request_query
    monkeypatch.setattr(scan_work_queue, "work_item_applicability_decision", lambda *args, **kwargs: {"applicable": True})
    clear_locks = MagicMock()
    monkeypatch.setattr(scan_work_queue, "clear_work_item_execute_locks", clear_locks)
    for _ in range(3):
        assert scan_work_queue.requeue_evidence_ready_work_items(db, job) == 0
        assert item.status == "skipped"
        assert item.attempts == 2
    clear_locks.assert_not_called()
    rows.append(SimpleNamespace(request_body={"body": "id=42"}, method="POST", request_content_type="application/x-www-form-urlencoded"))
    assert scan_work_queue.requeue_evidence_ready_work_items(db, job) == 1
    assert item.status == "queued"
    assert scan_work_queue.requeue_evidence_ready_work_items(db, job) == 0
    clear_locks.assert_called_once_with([42])


@pytest.mark.parametrize("method,body", [("GET", ""), ("POST", '{"id":42}'), ("PATCH", '{"id":42}'), ("POST", "")])
def test_worker_submits_valid_request_or_blocks_without_reprocessing(monkeypatch, method, body):
    from app.models.models import ScanJob
    from app.workers import tasks

    target = "https://example.test/items?id=1" if method == "GET" else "https://example.test/items"
    item = SimpleNamespace(
        id=42, scan_job_id=7, tool_name="sqlmap", profile="sqlmap_basic", target=target,
        status="queued", attempts=0, max_attempts=2, phase_id="P10", resource_class="light",
        item_metadata={"env": {"SCAN_HTTP_METHOD": method}} if method != "GET" else {},
    )
    job = SimpleNamespace(id=7, owner_id=1, status="running", state_data={})
    db = observed_db([SimpleNamespace(request_body={"body": body}, method=method, request_content_type="application/json")] if body else [])
    observed_query = db.query.return_value

    def query(model):
        if model is ObservedRequest:
            return observed_query
        result = MagicMock()
        result.filter.return_value.first.return_value = item if model is ScanWorkItem else job if model is ScanJob else None
        result.filter.return_value.scalar.return_value = ""
        return result

    db.query.side_effect = query
    monkeypatch.setattr("app.db.session.SessionLocal", lambda: db)
    monkeypatch.setattr(scan_work_queue, "_redis_client", MagicMock())
    monkeypatch.setattr(scan_work_queue, "enforce_work_item_scope", lambda *args: {"in_scope": True})
    monkeypatch.setattr(scan_work_queue, "work_item_applicability_decision", lambda *args, **kwargs: {"applicable": True})
    monkeypatch.setattr("app.services.scan_scope.authorized_scope_for_scan", lambda *args: ["example.test"])
    release = MagicMock()
    monkeypatch.setattr(scan_work_queue, "kali_inflight_release", release)

    class Submitted(BaseException):
        pass

    post = MagicMock(side_effect=Submitted)
    monkeypatch.setattr("requests.post", post)
    if method != "GET" and not body:
        result = tasks.execute_scan_work_item.run(42)
        assert result["status"] == "skipped"
        post.assert_not_called()
        release.assert_called_once_with("light", 1)
    else:
        with pytest.raises(Submitted):
            tasks.execute_scan_work_item.run(42)
        payload = post.call_args.kwargs["json"]
        assert payload["target"] == target
        assert payload["arguments"]["target"] == target
        assert payload["profile"] == ("sqlmap_basic" if method == "GET" else "sqlmap_body")
        if method == "GET":
            assert "SCAN_FUZZ_POST_DATA" not in payload["arguments"]
        else:
            assert payload["arguments"]["SCAN_HTTP_METHOD"] == method
            assert payload["arguments"]["SCAN_FUZZ_POST_DATA"] == body
            assert payload["arguments"]["SCAN_FUZZ_CONTENT_TYPE"] == "application/json"
