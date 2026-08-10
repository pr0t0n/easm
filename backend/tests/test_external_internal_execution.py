from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.models.models import ScanWorkItem
from app.services import (
    app_pentest,
    credential_capture_service,
    crawler_result_normalizer,
    js_analyzer,
    nosql_probe,
    page_analyzer,
    scan_work_queue,
)
from app.services.endpoint_discovery import _internal_endpoint_analysis_matrix
from app.services.execution_context_service import (
    inventory_auth_context,
    normalize_execution_context,
)


def test_execution_context_is_limited_to_g0_and_g1() -> None:
    assert normalize_execution_context("external") == "external"
    assert normalize_execution_context("G0") == "external"
    assert normalize_execution_context("authenticated") == "internal"
    assert normalize_execution_context("G1") == "internal"
    with pytest.raises(ValueError, match="unsupported_execution_context:g2"):
        normalize_execution_context("G2")
    assert inventory_auth_context("external") == "anonymous"
    assert inventory_auth_context("internal") == "authenticated"


def test_internal_endpoint_matrix_includes_code_parameter_api_and_business_analysis() -> None:
    matrix = set(_internal_endpoint_analysis_matrix(
        "https://example.test/api/v1/internal/app.js?account=1",
        {"classification": {"api": True, "sensitive_function": True}},
    ))

    assert ("P08", "linkfinder") in matrix
    assert ("P08", "nuclei-js-analysis") in matrix
    assert ("P04", "arjun") in matrix
    assert ("P04", "ffuf-params") in matrix
    assert ("P16", "nuclei") in matrix
    assert ("P16", "wapiti") in matrix
    assert ("P13", "bl-test") in matrix


def test_g1_clones_crawler_spider_and_fuzzing_without_mutating_g0(monkeypatch) -> None:
    tools = [
        ("P03", "katana"), ("P03", "hakrawler"), ("P03", "gospider"),
        ("P03", "ffuf"), ("P03", "feroxbuster"), ("P03", "dirsearch-api-post"),
        ("P04", "arjun"), ("P04", "ffuf-params"), ("P04", "wfuzz"),
        ("P08", "linkfinder"),
    ]
    sources = [
        SimpleNamespace(
            id=index, scan_job_id=9, execution_context="external",
            phase_id=phase, target="https://example.test", tool_name=tool,
            profile=tool, resource_class="light", priority=50,
            status="running" if index == 1 else "completed", attempts=1,
            max_attempts=2, item_metadata={"original": True}, result={"g0": True},
        )
        for index, (phase, tool) in enumerate(tools, start=1)
    ]

    class Query:
        def __init__(self, rows):
            self.rows = rows

        def filter(self, *args, **kwargs):
            return self

        def order_by(self, *args, **kwargs):
            return self

        def all(self):
            return self.rows

        def first(self):
            return None

    class DB:
        def __init__(self):
            self.query_count = 0
            self.added = []

        def query(self, *args):
            self.query_count += 1
            return Query(sources if self.query_count == 1 else [])

        def add(self, row):
            self.added.append(row)

        def flush(self):
            return None

    import app.services.execution_context_service as contexts
    monkeypatch.setattr(
        contexts,
        "get_context",
        lambda *args, **kwargs: SimpleNamespace(status="running", session_revision=1),
    )
    db = DB()
    created = scan_work_queue.requeue_authenticated_crawl_items(
        db, SimpleNamespace(id=9), "captured-user"
    )
    g1_items = [row for row in db.added if isinstance(row, ScanWorkItem)]

    assert created == len(tools)
    assert {row.tool_name for row in g1_items} == {tool for _, tool in tools}
    assert all(row.execution_context == "internal" for row in g1_items)
    assert all(row.auth_session_revision == 1 for row in g1_items)
    assert all(source.execution_context == "external" and source.result == {"g0": True} for source in sources)


def test_crawler_normalizer_preserves_internal_context(monkeypatch) -> None:
    endpoint_calls: list[dict] = []
    coverage_calls: list[dict] = []
    observations: list[dict] = []

    class Inventory:
        def __init__(self, db, scan):
            pass

        def upsert_endpoint(self, url, **kwargs):
            endpoint_calls.append({"url": url, **kwargs})
            return SimpleNamespace(
                id=len(endpoint_calls), url=url, normalized_url=url,
                method=kwargs.get("method", "GET"), status_code=None,
                content_type=None, source_artifact_id=None,
            )

        def upsert_parameter(self, *args, **kwargs):
            return None

        def upsert_coverage(self, **kwargs):
            coverage_calls.append(kwargs)
            return None

    class Query:
        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return None

    class DB:
        def query(self, *args, **kwargs):
            return Query()

        def add(self, value):
            return None

        def flush(self):
            return None

    monkeypatch.setattr(crawler_result_normalizer, "OffensiveInventoryService", Inventory)
    import app.services.execution_context_service as contexts
    monkeypatch.setattr(contexts, "upsert_endpoint_observation", lambda *args, **kwargs: observations.append(kwargs))

    result = crawler_result_normalizer.normalize_crawler_result(
        DB(),
        SimpleNamespace(id=1, target_query="example.test"),
        target="https://example.test",
        tool_name="katana",
        result={"stdout": "https://example.test/internal\nhttps://example.test/api/private"},
        execution_context="internal",
    )

    assert result["execution_context"] == "internal"
    assert endpoint_calls
    assert all(row["auth_context"] == "authenticated" for row in endpoint_calls)
    assert observations and all(row["execution_context"] == "internal" for row in observations)
    assert coverage_calls and all(row["execution_context"] == "internal" for row in coverage_calls)


class _Response:
    def __init__(self, status: int, body: bytes, location: str = ""):
        self.status_code = status
        self.content = body
        self.text = body.decode()
        self.headers = {"content-type": "text/html", "location": location}


class _Client:
    last_headers: dict[str, str] = {}
    last_cookies: dict[str, str] = {}

    def __init__(self, *args, headers=None, cookies=None, **kwargs):
        type(self).last_headers = dict(headers or {})
        type(self).last_cookies = dict(cookies or {})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, url, headers=None):
        if headers:
            type(self).last_headers = dict(headers)
        return _Response(200, b"fetch('/api/private'); const token='value';")


def test_internal_page_and_javascript_analysis_receive_session_material(monkeypatch) -> None:
    monkeypatch.setattr(js_analyzer.httpx, "Client", _Client)
    js_result = js_analyzer.analyze_js(
        "https://example.test/app.js",
        headers={"Authorization": "Bearer secret"},
        cookies={"sid": "abc"},
    )
    assert js_result["ok"] is True
    assert _Client.last_headers["Authorization"] == "Bearer secret"
    assert _Client.last_cookies == {"sid": "abc"}


def test_app_pentest_uses_captured_session_only_for_internal_context(monkeypatch) -> None:
    captured_calls: list[str] = []
    auth_calls: list[str] = []

    def fake_profile_target(*args, **kwargs):
        captured_calls.append(str(kwargs.get("headers") or {}))
        return {"forms": [], "state_change_forms": [], "param_endpoints": [], "pages_crawled": 1}

    class Manager:
        def __init__(self, *args, **kwargs):
            pass

        def get_material(self):
            return SimpleNamespace(valid=True, headers={"Authorization": "Bearer captured"}, cookies={"sid": "abc"})

    class Client(_Client):
        pass

    monkeypatch.setattr(app_pentest, "profile_target", fake_profile_target)
    monkeypatch.setattr(app_pentest, "authenticate", lambda *args, **kwargs: auth_calls.append("called") or {"authenticated": False})
    monkeypatch.setattr(app_pentest.httpx, "Client", Client)
    monkeypatch.setattr(app_pentest, "_check_business_logic", lambda *args, **kwargs: [])
    monkeypatch.setattr(app_pentest, "_check_sqli", lambda *args, **kwargs: [])
    monkeypatch.setattr(app_pentest, "_check_command_injection", lambda *args, **kwargs: [])
    monkeypatch.setattr(app_pentest, "_check_csrf", lambda *args, **kwargs: [])
    monkeypatch.setattr(app_pentest, "_check_xss", lambda *args, **kwargs: [])
    monkeypatch.setattr(app_pentest, "_check_idor", lambda *args, **kwargs: [])
    monkeypatch.setattr(app_pentest, "_check_info_disclosure", lambda *args, **kwargs: [])
    monkeypatch.setattr("app.services.auth_session_manager.AuthSessionManager", Manager)

    app_pentest.application_pentest("https://example.test", authorized=True, db=object(), job=object(), execution_context="external")
    assert auth_calls == ["called"]

    auth_calls.clear()
    app_pentest.application_pentest("https://example.test", authorized=True, db=object(), job=object(), execution_context="internal")
    assert auth_calls == []
    assert any("Bearer captured" in call for call in captured_calls)
    assert Client.last_headers["Authorization"] == "Bearer captured"


def test_nosql_internal_uses_session_material_and_internal_endpoints(monkeypatch) -> None:
    seen: dict[str, object] = {}

    class Manager:
        def __init__(self, *args, **kwargs):
            pass

        def get_material(self):
            return SimpleNamespace(valid=True, headers={"Authorization": "Bearer captured"}, cookies={"sid": "abc"})

    class Query:
        def filter(self, *args, **kwargs):
            return self

        def limit(self, *args, **kwargs):
            return self

        def all(self):
            return []

    class DB:
        def query(self, *args, **kwargs):
            return Query()

    def fake_verify(urls, auth_headers=None):
        seen["urls"] = urls
        seen["auth_headers"] = dict(auth_headers or {})
        return {"confirmed": False, "findings": []}

    monkeypatch.setattr("app.services.auth_session_manager.AuthSessionManager", Manager)
    monkeypatch.setattr(nosql_probe, "verify_nosql", fake_verify)

    job = SimpleNamespace(
        id=7,
        target_query="https://example.test",
        state_data={
            "discovered_endpoints": ["https://example.test/public?q=1"],
            "internal_discovered_endpoints": ["https://example.test/private?q=1"],
        },
    )
    result = nosql_probe.run_nosql_for_scan(DB(), job, execution_context="internal")

    assert result["findings_created"] == 0
    assert "https://example.test/private?q=1" in seen["urls"]
    assert seen["auth_headers"]["Authorization"] == "Bearer captured"
    assert seen["auth_headers"]["Cookie"] == "sid=abc"

    monkeypatch.setattr(page_analyzer.httpx, "Client", _Client)
    page_result = page_analyzer.fetch_and_extract(
        "https://example.test/internal",
        headers={"Authorization": "Bearer secret"},
        cookies={"sid": "abc"},
    )
    assert page_result["ok"] is True
    assert _Client.last_headers["Authorization"] == "Bearer secret"
    assert _Client.last_cookies == {"sid": "abc"}


class _AsyncClient:
    responses: list[_Response] = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        return type(self).responses.pop(0)


@pytest.mark.asyncio
async def test_login_capture_requires_authenticated_behavior_not_just_a_cookie(monkeypatch) -> None:
    monkeypatch.setattr(credential_capture_service.httpx, "AsyncClient", _AsyncClient)
    capture = SimpleNamespace(
        page=SimpleNamespace(url="https://example.test/dashboard"),
        authorized_scope=["example.test"],
    )

    _AsyncClient.responses = [
        _Response(200, b"private dashboard"),
        _Response(302, b"", "/login"),
    ]
    accepted = await credential_capture_service._validate_captured_login(
        capture, {}, {"sid": "authenticated"}
    )
    assert accepted["valid"] is True

    _AsyncClient.responses = [
        _Response(200, b"same public page"),
        _Response(200, b"same public page"),
    ]
    rejected = await credential_capture_service._validate_captured_login(
        capture, {}, {"consent": "yes"}
    )
    assert rejected["valid"] is False
    assert rejected["reason"] == "no_authenticated_behavior_observed"
