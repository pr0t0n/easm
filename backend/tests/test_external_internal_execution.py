from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.models.models import ScanAuthSession, ScanIdentity, ScanJob, ScanWorkItem
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
    reconcile_execution_plan_state,
)
from app.workers import tasks


def test_execution_context_is_limited_to_g0_and_g1() -> None:
    assert normalize_execution_context("external") == "external"
    assert normalize_execution_context("G0") == "external"
    assert normalize_execution_context("authenticated") == "internal"
    assert normalize_execution_context("G1") == "internal"
    with pytest.raises(ValueError, match="unsupported_execution_context:g2"):
        normalize_execution_context("G2")
    assert inventory_auth_context("external") == "anonymous"
    assert inventory_auth_context("internal") == "authenticated"


def test_execution_plan_reconciler_derives_g1_running_g0_waiting() -> None:
    job = SimpleNamespace(
        id=82,
        state_data={
            "execution_plan": "internal_then_external",
            "external_release_pending": True,
        },
    )
    internal_context = SimpleNamespace(status="pending", finished_at=None)
    external_context = SimpleNamespace(status="running", finished_at=None)

    class Query:
        def __init__(self, db, models):
            self.db = db
            self.models = models

        def filter(self, *args, **kwargs):
            return self

        def group_by(self, *args, **kwargs):
            return self

        def all(self):
            self.db.work_count_queries += 1
            if self.db.work_count_queries == 1:
                return [("completed", 3), ("queued", 2), ("submitted", 1)]
            return []

        def first(self):
            self.db.context_queries += 1
            return internal_context if self.db.context_queries == 1 else external_context

    class DB:
        def __init__(self):
            self.work_count_queries = 0
            self.context_queries = 0
            self.added = []

        def query(self, *models):
            return Query(self, models)

        def add(self, obj):
            self.added.append(obj)

    state = reconcile_execution_plan_state(DB(), job)  # type: ignore[arg-type]

    assert state["current_surface"] == "G1"
    assert state["g1_status"] == "running"
    assert state["g0_status"] == "waiting_for_internal"
    assert state["execution_tracks"]["G1"]["active"] == 3
    assert internal_context.status == "running"
    assert external_context.status == "waiting_for_internal"


def test_execution_plan_reconciler_promotes_g0_when_external_work_is_active() -> None:
    job = SimpleNamespace(
        id=82,
        state_data={
            "execution_plan": "internal_then_external",
            "external_release_pending": True,
            "g1_status": "running",
            "g0_status": "waiting_for_internal",
        },
    )
    internal_context = SimpleNamespace(status="running", finished_at=None)
    external_context = SimpleNamespace(status="waiting_for_internal", finished_at=None)

    class Query:
        def __init__(self, db, models):
            self.db = db
            self.models = models

        def filter(self, *args, **kwargs):
            return self

        def group_by(self, *args, **kwargs):
            return self

        def all(self):
            self.db.work_count_queries += 1
            if self.db.work_count_queries == 1:
                return [("completed", 142), ("skipped", 16)]
            return [("completed", 70), ("queued", 30), ("submitted", 8)]

        def first(self):
            self.db.context_queries += 1
            return internal_context if self.db.context_queries == 1 else external_context

    class DB:
        def __init__(self):
            self.work_count_queries = 0
            self.context_queries = 0
            self.added = []

        def query(self, *models):
            return Query(self, models)

        def add(self, obj):
            self.added.append(obj)

    state = reconcile_execution_plan_state(DB(), job)  # type: ignore[arg-type]

    assert state["current_surface"] == "G0"
    assert state["g1_status"] == "completed"
    assert state["g0_status"] == "running"
    assert state["execution_tracks"]["G0"]["active"] == 38
    assert internal_context.status == "completed"
    assert external_context.status == "running"


def test_inventory_fingerprint_handles_missing_status_codes() -> None:
    import app.services.execution_context_service as contexts

    first = contexts._fingerprint([
        ("https://example.test/a", "GET", None, None),
        ("https://example.test/b", "GET", 200, "abc"),
    ])
    second = contexts._fingerprint([
        ("https://example.test/b", "GET", 200, "abc"),
        ("https://example.test/a", "GET", None, None),
    ])

    assert first == second
    assert len(first) == 64


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


def test_authenticated_deep_tool_selection_covers_p10_p11_p12_p13_after_crawl() -> None:
    state = {
        "discovered_endpoints": ["https://example.test/support/manage"],
        "discovered_parameterized_urls": ["https://example.test/search?q=invoice"],
    }

    assert "wapiti" in scan_work_queue._authenticated_tools_for_phase(
        "P10", "https://example.test/support/manage", state
    )
    assert "sqlmap" in scan_work_queue._authenticated_tools_for_phase(
        "P10", "https://example.test/search?q=invoice", state
    )
    assert "nuclei" in scan_work_queue._authenticated_tools_for_phase(
        "P11", "https://example.test/support/manage", state
    )
    assert "dalfox" in scan_work_queue._authenticated_tools_for_phase(
        "P12", "https://example.test/search?q=invoice", state
    )
    assert "bl-test" in scan_work_queue._authenticated_tools_for_phase(
        "P13", "https://example.test/support/manage", state
    )
    assert "nuclei-auth-bypass" in scan_work_queue._authenticated_tools_for_phase(
        "P14", "https://example.test/api/auth/login", {**state, "login_forms": ["https://example.test/api/auth/login"]}
    )
    assert "nuclei-exposure" in scan_work_queue._authenticated_tools_for_phase(
        "P15", "https://example.test/support/manage", state
    )
    assert "nuclei" in scan_work_queue._authenticated_tools_for_phase(
        "P17", "https://example.test/support/manage", state
    )
    assert "nuclei" in scan_work_queue._authenticated_tools_for_phase(
        "P19", "https://example.test/support/manage", state
    )
    assert "nuclei" in scan_work_queue._authenticated_tools_for_phase(
        "P20", "https://example.test/support/manage", state
    )


def test_authenticated_deep_target_filter_rejects_static_and_mime_artifacts() -> None:
    from app.services.offensive_inventory_service import is_actionable_endpoint_url

    assert scan_work_queue._looks_like_actionable_deep_endpoint("https://example.test/api/users")
    assert scan_work_queue._looks_like_actionable_deep_endpoint("https://example.test/support/manage")
    assert not scan_work_queue._looks_like_actionable_deep_endpoint("https://example.test/assets/app.js")
    assert not scan_work_queue._looks_like_actionable_deep_endpoint("https://example.test/multipart/form-data")
    assert not scan_work_queue._looks_like_actionable_deep_endpoint("https://example.test/image/png")
    assert not scan_work_queue._looks_like_actionable_deep_endpoint(
        "https://example.test/FQAABDgAAAAeT1MvMlYNYwkAAAEgAAAAYGNtYXABDQLUAAACNAAAAUJoZWFk"
    )
    assert is_actionable_endpoint_url("https://example.test/api/users")
    assert not is_actionable_endpoint_url("https://example.test/assets/app.js")
    assert not is_actionable_endpoint_url("https://example.test/text/plain")


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


def test_skill_probe_seed_uses_internal_session_context(monkeypatch) -> None:
    from app.services import skill_execution_engine

    monkeypatch.setattr(
        "app.services.auth_session_manager.has_any_valid_session",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        "app.services.execution_context_service.get_context",
        lambda *args, **kwargs: SimpleNamespace(
            status="running",
            session_revision=7,
            identity_key="vidal",
        ),
    )
    monkeypatch.setattr(
        skill_execution_engine,
        "get_skill_by_id",
        lambda skill_id: {"phase_ids": ["P13"]} if skill_id == "skill.idor_object_authorization" else None,
    )

    class Query:
        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return None

    class DB:
        def __init__(self):
            self.added = []

        def query(self, *_args, **_kwargs):
            return Query()

        def add(self, obj):
            self.added.append(obj)

        def flush(self):
            return None

        def commit(self):
            return None

    db = DB()
    created = skill_execution_engine.seed_skill_probe_items(
        db,
        SimpleNamespace(id=81),
        "P13",
        "https://example.test/support/manage",
    )
    items = [row for row in db.added if isinstance(row, ScanWorkItem)]

    assert created == 1
    assert items[0].execution_context == "internal"
    assert items[0].auth_session_revision == 7
    assert items[0].max_attempts == 2
    assert items[0].item_metadata["identity_key"] == "vidal"


def test_skill_probe_seed_does_not_fallback_to_external_without_g1_context(monkeypatch) -> None:
    from app.services import skill_execution_engine

    monkeypatch.setattr(
        "app.services.auth_session_manager.has_any_valid_session",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        "app.services.execution_context_service.get_context",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        skill_execution_engine,
        "get_skill_by_id",
        lambda skill_id: {"phase_ids": ["P13"]},
    )

    class DB:
        def __init__(self):
            self.added = []

        def add(self, obj):
            self.added.append(obj)

    created = skill_execution_engine.seed_skill_probe_items(
        DB(),
        SimpleNamespace(id=81),
        "P13",
        "https://example.test/support/manage",
    )

    assert created == 0


def test_authenticated_rerun_service_creates_g1_first_scan_from_valid_session(monkeypatch) -> None:
    from app.services.authenticated_scan_starter import start_scan_from_valid_session

    now_source = SimpleNamespace()
    source = ScanJob(
        id=81,
        owner_id=7,
        access_group_id=3,
        target_query="https://example.test",
        authorization_code="AUTH-1",
        authorization_id=11,
        mode="unit",
        state_data={
            "scan_level": "full",
            "parallelize": True,
            "authorization_gate": {
                "approved": True,
                "authorized_scope": ["example.test"],
                "public_targets": ["example.test"],
            },
        },
    )
    identity = ScanIdentity(
        id=10,
        scan_job_id=81,
        identity_key="vidal",
        role="admin",
        username_ref="vidal@example.test",
        auth_type="browser",
        status="valid",
        session_valid=True,
        session_metadata={"validated": True},
    )
    session = ScanAuthSession(
        id=12,
        scan_job_id=81,
        scan_identity_id=10,
        session_key="sess-12",
        auth_type="browser",
        status="valid",
        headers={"Authorization": "Bearer captured"},
        cookies={"sid": "abc"},
        validation_result={"valid": True},
    )

    class Query:
        def __init__(self, db, models):
            self.db = db
            self.models = models

        def join(self, *args, **kwargs):
            return self

        def filter(self, *args, **kwargs):
            return self

        def order_by(self, *args, **kwargs):
            return self

        def first(self):
            if self.models and self.models[0] is ScanJob:
                return source
            if self.models and self.models[0] is ScanAuthSession:
                return (session, identity)
            return None

    class DB:
        def __init__(self):
            self.added = []
            self.next_ids = {ScanJob: 82, ScanIdentity: 20, ScanAuthSession: 21}

        def query(self, *models):
            return Query(self, models)

        def add(self, obj):
            self.added.append(obj)

        def flush(self):
            for obj in self.added:
                for cls, next_id in list(self.next_ids.items()):
                    if isinstance(obj, cls) and getattr(obj, "id", None) is None:
                        obj.id = next_id
                        self.next_ids[cls] = next_id + 1

        def execute(self, *args, **kwargs):
            return now_source

    monkeypatch.setattr(
        "app.services.authenticated_scan_starter.activate_internal_context",
        lambda db, job, auth_session, scan_identity: SimpleNamespace(
            status="running",
            session_revision=1,
            identity_key=scan_identity.identity_key,
            auth_session_id=auth_session.id,
        ),
    )
    external_context = SimpleNamespace(status="running")
    monkeypatch.setattr(
        "app.services.authenticated_scan_starter.get_context",
        lambda db, scan_id, context_type: external_context if context_type == "external" else None,
    )
    monkeypatch.setattr(
        "app.services.authenticated_scan_starter.authorized_scope_for_scan",
        lambda db, scan_id: ["example.test"],
    )
    monkeypatch.setattr(
        "app.services.authenticated_scan_starter.seed_internal_first_work_items",
        lambda db, job, identity_key: 44,
    )
    monkeypatch.setattr(
        "app.services.authenticated_scan_starter.seed_skill_probe_items",
        lambda db, job, phase_id, target: 1,
    )

    db = DB()
    result = start_scan_from_valid_session(db, source_scan_id=81, identity_key="vidal")
    new_job = next(obj for obj in db.added if isinstance(obj, ScanJob) and obj.id == 82)
    copied_session = next(obj for obj in db.added if isinstance(obj, ScanAuthSession) and obj.id == 21)

    assert result["scan_id"] == 82
    assert result["internal_items"] == 44
    assert result["skill_probes"] == 3
    assert external_context.status == "waiting_for_internal"
    assert copied_session.headers == {"Authorization": "Bearer captured"}
    assert copied_session.cookies == {"sid": "abc"}
    assert new_job.state_data["execution_plan"] == "internal_then_external"
    assert new_job.state_data["execution_plan_stage"] == "internal_running"
    assert new_job.state_data["external_release_pending"] is True
    assert new_job.state_data["g1_status"] == "running"
    assert new_job.state_data["g0_status"] == "waiting_for_internal"
    assert new_job.state_data["current_surface"] == "G1"
    assert new_job.state_data["authenticated_scan_source_id"] == 81
    assert new_job.state_data["authenticated_scan_source_auth_session_id"] == 12
    assert new_job.state_data["authenticated_scan_identity_key"] == "vidal"


def test_dispatcher_rehydrates_orphaned_dispatched_work_items(monkeypatch) -> None:
    from datetime import datetime, timedelta

    item = SimpleNamespace(
        id=70001,
        scan_job_id=82,
        phase_id="P13",
        status="dispatched",
        updated_at=datetime.now() - timedelta(minutes=5),
        lease_until=None,
    )
    published: list[dict[str, object]] = []

    class Query:
        def __init__(self, rows=None, scalar_value=None):
            self.rows = rows or []
            self.scalar_value = scalar_value

        def filter(self, *args, **kwargs):
            return self

        def order_by(self, *args, **kwargs):
            return self

        def limit(self, *args, **kwargs):
            return self

        def all(self):
            return self.rows

        def scalar(self):
            return self.scalar_value

    class DB:
        def __init__(self):
            self.added = []

        def query(self, *models):
            if models and models[0] is ScanWorkItem:
                return Query([item])
            return Query(scalar_value="unit")

        def add(self, obj):
            self.added.append(obj)

    monkeypatch.setattr(
        "app.workers.tasks._redis_client",
        lambda: SimpleNamespace(get=lambda key: None),
        raising=False,
    )
    monkeypatch.setattr(
        "app.services.scan_work_queue._redis_client",
        lambda: SimpleNamespace(get=lambda key: None),
    )
    monkeypatch.setattr(
        tasks,
        "phase_queue",
        lambda phase_id, mode="unit": f"queue.{phase_id}.{mode}",
        raising=False,
    )
    monkeypatch.setattr(
        "app.workers.worker_groups.phase_queue",
        lambda phase_id, mode="unit": f"queue.{phase_id}.{mode}",
    )
    monkeypatch.setattr(
        tasks,
        "execute_scan_work_item",
        SimpleNamespace(apply_async=lambda args, queue: published.append({"args": args, "queue": queue})),
    )

    result = tasks._rehydrate_orphaned_dispatched_work_items(DB(), 82, stale_after_seconds=90)

    assert result["scheduled"] == 1
    assert published == [{"args": [70001], "queue": "queue.P13.unit"}]
    assert item.lease_until is not None


def test_worker_transient_error_classifier_covers_db_disconnects() -> None:
    assert tasks._is_transient_worker_error(
        "psycopg2.OperationalError: server closed the connection unexpectedly"
    )
    assert tasks._is_transient_worker_error("PendingRollbackError: transaction has been rolled back")
    assert not tasks._is_transient_worker_error("source_code_required")


def test_runner_timeout_without_detail_is_recoverable() -> None:
    assert tasks._is_recoverable_runner_infra_error("runner_failed_without_detail exit_code=28")
    assert tasks._is_recoverable_runner_infra_error("operation timed out")
    assert not tasks._is_recoverable_runner_infra_error("application returned 403")


def test_poll_work_item_closes_db_transaction_before_runner_poll(monkeypatch) -> None:
    item = SimpleNamespace(
        id=123,
        scan_job_id=81,
        status="submitted",
        result={"kali_job_id": "job-123", "timeout": 300},
        resource_class="light",
        phase_id="P08",
        target="https://example.test/app.js",
        tool_name="linkfinder",
        started_at=None,
        lease_until=None,
        updated_at=None,
        item_metadata={},
    )
    job = SimpleNamespace(id=81, status="running")
    sessions = []

    class Query:
        def __init__(self, model):
            self.model = model

        def filter(self, *args, **kwargs):
            return self

        def first(self):
            if self.model is ScanWorkItem:
                return item
            return job

    class FakeSession:
        def __init__(self):
            self.in_transaction = False
            self.closed = False
            self.added = []
            sessions.append(self)

        def query(self, model):
            self.in_transaction = True
            return Query(model)

        def add(self, row):
            self.in_transaction = True
            self.added.append(row)

        def commit(self):
            self.in_transaction = False

        def rollback(self):
            self.in_transaction = False

        def close(self):
            self.closed = True
            self.in_transaction = False

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "status": "running",
                "heartbeat_at": "2026-08-10T14:00:00",
                "heartbeat_sequence": 7,
                "output_bytes": 10,
            }

    def fake_get(*args, **kwargs):
        assert sessions, "poller should read DB before polling runner"
        assert all(not session.in_transaction for session in sessions)
        return Response()

    import app.db.session as db_session
    import requests

    monkeypatch.setattr(db_session, "SessionLocal", FakeSession)
    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(tasks, "_legacy_delivery_allowed", lambda *args, **kwargs: True)
    monkeypatch.setattr(tasks, "_schedule_work_item_poll", lambda *args, **kwargs: True)
    monkeypatch.setattr(tasks, "_scan_is_terminal", lambda status: False)

    result = tasks.poll_scan_work_item(123)

    assert result["status"] == "submitted"
    assert item.result["kali_status"] == "running"
    assert item.result["poll_count"] == 1


def test_surface_expansion_postprocessor_preserves_internal_context_and_session(monkeypatch) -> None:
    calls: dict[str, object] = {}

    def fake_expand_attack_surface(db, scan_id, source_target, tool_name, result, job, *, execution_context="external"):
        calls["scan_id"] = scan_id
        calls["source_target"] = source_target
        calls["tool_name"] = tool_name
        calls["result"] = result
        calls["execution_context"] = execution_context
        calls["auth_session_id"] = getattr(item, "auth_session_id", None)
        return {"new_endpoints": 2, "reseeded": 1}

    class DB:
        def __init__(self):
            self.commits = 0

        def commit(self):
            self.commits += 1

        def rollback(self):
            raise AssertionError("surface expansion should not rollback")

        def refresh(self, obj):
            calls["refreshed_job"] = obj.id

    import app.services.endpoint_discovery as endpoint_discovery
    import app.services.execution_context_service as contexts

    monkeypatch.setattr(endpoint_discovery, "expand_attack_surface", fake_expand_attack_surface)
    monkeypatch.setattr(contexts, "processor_should_run", lambda *args, **kwargs: (False, None, {}))
    monkeypatch.setattr(contexts, "complete_processor_checkpoint", lambda *args, **kwargs: None)
    monkeypatch.setattr(tasks, "_schedule_pentest_inventory_refresh", lambda *args, **kwargs: calls.setdefault("inventory", True))

    job = SimpleNamespace(id=81, target_query="https://example.test", state_data={}, mode="unit")
    item = SimpleNamespace(
        id=55,
        scan_job_id=81,
        status="completed",
        phase_id="P03",
        target="https://example.test/dashboard",
        tool_name="katana",
        item_metadata={},
        result={"stdout": "https://example.test/api/private"},
        execution_context="internal",
        auth_session_id=10,
    )

    summary = tasks._run_surface_expansion_postprocessor(DB(), job, item)

    assert summary["execution_context"] == "internal"
    assert calls["execution_context"] == "internal"
    assert calls["auth_session_id"] == 10
    assert calls["source_target"] == "https://example.test/dashboard"
    assert summary["surface_expansion"] == {"new_endpoints": 2, "reseeded": 1}
    assert calls["inventory"] is True


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
