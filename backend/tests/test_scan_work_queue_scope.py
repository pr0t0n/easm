from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from app.services.scan_work_queue import (
    enforce_work_item_scope,
    filter_targets_to_authorized_scope,
    is_target_in_authorized_scope,
)


def test_target_scope_accepts_exact_target_and_children_only() -> None:
    scope = ["www.valid.com"]

    assert is_target_in_authorized_scope("www.valid.com", scope) is True
    assert is_target_in_authorized_scope("https://www.valid.com/quem-somos", scope) is True
    assert is_target_in_authorized_scope("api.www.valid.com", scope) is True
    assert is_target_in_authorized_scope("https://ri.valid.com/", scope) is False
    assert is_target_in_authorized_scope("https://mbbapi.santander.com.br/login", scope) is False


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
