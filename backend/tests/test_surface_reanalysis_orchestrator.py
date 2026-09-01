from app.models.models import ScanJob, ScanLog
from contextlib import contextmanager


def test_surface_reanalysis_orchestrator_records_loop_event(monkeypatch) -> None:
    from app.services import endpoint_analysis_pipeline
    from app.services import hypothesis_planner
    from app.services import hypothesis_rules
    from app.services import pentest_coverage_service
    from app.services import surface_reanalysis_orchestrator

    snapshots = iter([
        {"endpoints": 2, "hypotheses": 1, "coverage": 1, "work_items": 3},
        {"endpoints": 5, "hypotheses": 4, "coverage": 6, "work_items": 5},
    ])
    added = []

    class DB:
        def add(self, row):
            added.append(row)

        def flush(self):
            pass

        @contextmanager
        def begin_nested(self):
            yield

    monkeypatch.setattr(surface_reanalysis_orchestrator, "_snapshot", lambda *_args: next(snapshots))
    monkeypatch.setattr(endpoint_analysis_pipeline, "analyze_endpoints_for_scan", lambda *_args, **_kwargs: {"tests_planned": 7})
    from app.services import finding_validation_lifecycle

    monkeypatch.setattr(finding_validation_lifecycle, "enforce_high_risk_lifecycle", lambda *_args, **_kwargs: {"seen": 1, "scheduled": 1})
    monkeypatch.setattr(hypothesis_rules, "generate_hypotheses_for_scan", lambda *_args, **_kwargs: {"hypotheses_created_or_seen": 4})
    monkeypatch.setattr(hypothesis_planner, "plan_hypotheses", lambda *_args, **_kwargs: {"planned": 4, "clusters": 3, "superseded_now": 1})
    monkeypatch.setattr(hypothesis_planner, "ensure_hypothesis_drain_work_item", lambda *_args, **_kwargs: {"scheduled": 1, "remaining": 4})
    monkeypatch.setattr(pentest_coverage_service, "refresh_coverage", lambda *_args, **_kwargs: {"coverage_percent": 62.5, "covered": 5, "total": 8})

    job = ScanJob(id=123, owner_id=1, target_query="https://example.test", state_data={})

    event = surface_reanalysis_orchestrator.run_surface_reanalysis(
        DB(),
        job,
        trigger="surface_expansion:katana",
        execution_context="external",
        source_item_id=55,
        expansion_summary={"new_endpoints": 3, "reseeded": 2},
        validate_findings=True,
    )

    assert event["deltas"] == {"endpoints": 3, "hypotheses": 3, "coverage": 5, "work_items": 2}
    assert event["validation_lifecycle"] == {"seen": 1, "scheduled": 1}
    assert event["drain"]["scheduled"] == 1
    assert job.state_data["surface_reanalysis_latest"]["source_item_id"] == 55
    assert any(isinstance(row, ScanLog) for row in added)


def test_surface_reanalysis_orchestrator_normalizes_g1_and_reopens_internal(monkeypatch) -> None:
    from app.services import endpoint_analysis_pipeline
    from app.services import execution_context_service
    from app.services import hypothesis_planner
    from app.services import hypothesis_rules
    from app.services import pentest_coverage_service
    from app.services import surface_reanalysis_orchestrator

    snapshots = iter([
        {"endpoints": 3, "hypotheses": 2, "coverage": 1, "work_items": 1},
        {"endpoints": 3, "hypotheses": 2, "coverage": 1, "work_items": 2},
    ])
    plan_calls = []

    class DB:
        def add(self, _row):
            pass

        def flush(self):
            pass

        @contextmanager
        def begin_nested(self):
            yield

    monkeypatch.setattr(surface_reanalysis_orchestrator, "_snapshot", lambda *_args: next(snapshots))
    monkeypatch.setattr(endpoint_analysis_pipeline, "analyze_endpoints_for_scan", lambda *_args, **_kwargs: {"tests_planned": 2})
    from app.services import finding_validation_lifecycle

    monkeypatch.setattr(finding_validation_lifecycle, "enforce_high_risk_lifecycle", lambda *_args, **_kwargs: {"seen": 2, "adjudicated": 2})
    monkeypatch.setattr(hypothesis_rules, "generate_hypotheses_for_scan", lambda *_args, **_kwargs: {"hypotheses_created_or_seen": 2})

    def fake_plan(*_args, **_kwargs):
        plan_calls.append(1)
        return {"planned": len(plan_calls), "clusters": 1, "superseded_now": 0}

    monkeypatch.setattr(hypothesis_planner, "plan_hypotheses", fake_plan)
    monkeypatch.setattr(hypothesis_planner, "ensure_hypothesis_drain_work_item", lambda *_args, **_kwargs: {"scheduled": 1})
    monkeypatch.setattr(pentest_coverage_service, "refresh_coverage", lambda *_args, **_kwargs: {"coverage_percent": 50, "covered": 1, "total": 2})
    monkeypatch.setattr(execution_context_service, "reopen_auth_blocked_hypotheses", lambda *_args, **_kwargs: 2)
    monkeypatch.setattr(
        execution_context_service,
        "compute_external_internal_diff",
        lambda *_args, **_kwargs: {
            "external_only": [1],
            "internal_only": [2, 3],
            "shared_changed": [4],
            "shared_equal": [],
        },
    )

    job = ScanJob(id=123, owner_id=1, target_query="https://example.test", state_data={})

    event = surface_reanalysis_orchestrator.run_surface_reanalysis(
        DB(),
        job,
        trigger="inventory_refresh",
        execution_context="G1",
        validate_findings=True,
    )

    assert event["execution_context"] == "internal"
    assert event["reopened_auth_blocked"] == 2
    assert event["diff"] == {"external_only": 1, "internal_only": 2, "shared_changed": 1, "shared_equal": 0}
    assert event["planner"]["planned"] == 2
    assert event["validation_lifecycle"]["adjudicated"] == 2


def test_surface_reanalysis_skips_finding_validation_while_scan_is_active(monkeypatch) -> None:
    from app.services import endpoint_analysis_pipeline
    from app.services import finding_validation_lifecycle
    from app.services import hypothesis_planner
    from app.services import hypothesis_rules
    from app.services import pentest_coverage_service
    from app.services import surface_reanalysis_orchestrator

    snapshots = iter([
        {"endpoints": 1, "hypotheses": 0, "coverage": 0, "work_items": 1},
        {"endpoints": 2, "hypotheses": 1, "coverage": 1, "work_items": 2},
    ])

    class DB:
        def add(self, _row):
            pass

        def flush(self):
            pass

    monkeypatch.setattr(surface_reanalysis_orchestrator, "_snapshot", lambda *_args: next(snapshots))
    monkeypatch.setattr(endpoint_analysis_pipeline, "analyze_endpoints_for_scan", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(hypothesis_rules, "generate_hypotheses_for_scan", lambda *_args, **_kwargs: {"hypotheses_created_or_seen": 1})
    monkeypatch.setattr(hypothesis_planner, "plan_hypotheses", lambda *_args, **_kwargs: {"planned": 1, "clusters": 1, "superseded_now": 0})
    monkeypatch.setattr(hypothesis_planner, "ensure_hypothesis_drain_work_item", lambda *_args, **_kwargs: {"scheduled": 0})
    monkeypatch.setattr(pentest_coverage_service, "refresh_coverage", lambda *_args, **_kwargs: {"coverage_percent": 50, "covered": 1, "total": 2})

    def fail_validation(*_args, **_kwargs):
        raise AssertionError("finding validation should not run while scan is active")

    monkeypatch.setattr(finding_validation_lifecycle, "enforce_high_risk_lifecycle", fail_validation)

    job = ScanJob(id=123, owner_id=1, target_query="https://example.test", status="running", state_data={})

    event = surface_reanalysis_orchestrator.run_surface_reanalysis(
        DB(),
        job,
        trigger="surface_expansion:gau",
        execution_context="external",
    )

    assert event["validation_lifecycle"] == {"skipped": "scan_active"}
