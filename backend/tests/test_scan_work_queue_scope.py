from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from app.services.scan_work_queue import (
    enqueue_scope_safe_redirect_probes,
    enforce_work_item_scope,
    filter_targets_to_authorized_scope,
    is_target_in_authorized_scope,
)
from app.models.models import ScanJob, ScanWorkItem


def test_target_scope_accepts_exact_target_and_children_only() -> None:
    scope = ["www.valid.com"]

    assert is_target_in_authorized_scope("www.valid.com", scope) is True
    assert is_target_in_authorized_scope("https://www.valid.com/quem-somos", scope) is True
    assert is_target_in_authorized_scope("api.www.valid.com", scope) is True
    assert is_target_in_authorized_scope("https://ri.valid.com/", scope) is False
    assert is_target_in_authorized_scope("https://mbbapi.santander.com.br/login", scope) is False
    assert is_target_in_authorized_scope("192.0.2.42", ["192.0.2.0/24"]) is True
    assert is_target_in_authorized_scope("192.0.3.42", ["192.0.2.0/24"]) is False


def test_filter_targets_to_authorized_scope_returns_skipped_targets() -> None:
    clean, skipped = filter_targets_to_authorized_scope(
        [
            "https://www.valid.com/",
            "https://www.valid.com/compliance",
            "https://ri.valid.com/",
            "https://mbbapi.santander.com.br/login",
        ],
        ["www.valid.com"],
    )

    assert clean == ["https://www.valid.com/", "https://www.valid.com/compliance"]
    assert skipped == ["https://ri.valid.com/", "https://mbbapi.santander.com.br/login"]


def test_enforce_work_item_scope_filters_batch_targets() -> None:
    item = SimpleNamespace(
        id=123,
        scan_job_id=10,
        target="__batch__",
        tool_name="nuclei",
        status="queued",
        lease_until=None,
        finished_at=None,
        updated_at=datetime.now(),
        last_error=None,
        result=None,
        item_metadata={
            "batch_targets": [
                "https://www.valid.com/",
                "https://mbbapi.santander.com.br/login",
            ]
        },
    )
    db = SimpleNamespace(add=lambda *_args, **_kwargs: None)

    decision = enforce_work_item_scope(db, item, authorized_scope=["www.valid.com"])  # type: ignore[arg-type]

    assert decision["in_scope"] is True
    assert item.item_metadata["batch_targets"] == ["https://www.valid.com/"]
    assert item.item_metadata["batch_count"] == 1
    assert item.item_metadata["out_of_scope_targets_skipped"] == [
        "https://mbbapi.santander.com.br/login"
    ]


def test_enforce_work_item_scope_skips_external_single_target() -> None:
    item = SimpleNamespace(
        id=124,
        scan_job_id=10,
        target="https://mbbapi.santander.com.br/login",
        tool_name="katana",
        status="queued",
        lease_until=None,
        finished_at=None,
        updated_at=datetime.now(),
        last_error=None,
        result=None,
        item_metadata={},
    )
    db = SimpleNamespace(add=lambda *_args, **_kwargs: None)

    decision = enforce_work_item_scope(db, item, authorized_scope=["www.valid.com"])  # type: ignore[arg-type]

    assert decision["in_scope"] is False
    assert item.status == "skipped"
    assert item.last_error == "skipped:out_of_scope"
    assert item.result["skipped_reason"] == "out_of_scope"


def test_safe_redirect_probe_schedules_only_authorized_destination() -> None:
    job = SimpleNamespace(id=10, target_query="www.valid.com")
    source_item = SimpleNamespace(
        id=124,
        phase_id="P07",
        priority=100,
        item_metadata={"redirect_depth": 0},
    )

    class _Query:
        def __init__(self, model):
            self.model = model

        def filter(self, *_args, **_kwargs):
            return self

        def first(self):
            return job if self.model is ScanJob else None

    class _DB:
        def __init__(self):
            self.added = []

        def query(self, model):
            return _Query(model)

        def add(self, value):
            self.added.append(value)

        def flush(self):
            return None

    db = _DB()
    result = enqueue_scope_safe_redirect_probes(
        db,  # type: ignore[arg-type]
        job,  # type: ignore[arg-type]
        source_item,  # type: ignore[arg-type]
        [
            {"source": "https://www.valid.com/login", "destination": "https://api.www.valid.com/continue"},
            {"source": "https://www.valid.com/login", "destination": "https://ri.valid.com/continue"},
            {"source": "https://www.valid.com/login", "destination": "https://avidabank.dk/continue"},
        ],
    )

    assert result == {"created": 1, "existing": 0, "blocked": 2, "depth_limited": 0}
    created = [value for value in db.added if isinstance(value, ScanWorkItem)]
    assert len(created) == 1
    assert created[0].target == "https://api.www.valid.com/continue"
    assert created[0].item_metadata["source"] == "scope_safe_redirect"
