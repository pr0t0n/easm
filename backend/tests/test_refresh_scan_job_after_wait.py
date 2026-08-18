"""Tests for _refresh_scan_job_after_wait -- must never silently return None
after a failed re-fetch (every call site does `... or job`, which used to
fall back to a stale, session-detached ScanJob object and later blow up with
SQLAlchemy's "Instance '<ScanJob at 0x...>' is not persistent within this
Session", confirmed live on a P21-quality-gate-blocked scan).
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.services.offensive_operator_runner import _refresh_scan_job_after_wait


def test_returns_fresh_job_on_success() -> None:
    fresh_job = SimpleNamespace(id=5)
    db = MagicMock()
    db.get.return_value = fresh_job

    result = _refresh_scan_job_after_wait(db, 5)

    assert result is fresh_job
    db.rollback.assert_called()


def test_accepts_job_object_and_uses_its_id() -> None:
    fresh_job = SimpleNamespace(id=7)
    db = MagicMock()
    db.get.return_value = fresh_job

    result = _refresh_scan_job_after_wait(db, SimpleNamespace(id=7))

    assert result is fresh_job
    db.get.assert_called_with(db.get.call_args.args[0], 7)


def test_retries_once_then_succeeds() -> None:
    fresh_job = SimpleNamespace(id=5)
    db = MagicMock()
    db.get.side_effect = [Exception("transient"), fresh_job]

    result = _refresh_scan_job_after_wait(db, 5)

    assert result is fresh_job
    assert db.get.call_count == 2


def test_raises_instead_of_returning_none_when_refresh_never_succeeds() -> None:
    """The old behavior returned None here, and every caller did
    `job = _refresh_scan_job_after_wait(...) or job` -- silently keeping the
    stale, now-detached job. Must raise instead so the caller's existing
    retryable-task handling sees a real failure."""
    db = MagicMock()
    db.get.side_effect = Exception("db unreachable")

    with pytest.raises(RuntimeError, match="scan_job_refresh_failed_after_external_wait"):
        _refresh_scan_job_after_wait(db, 5)


def test_raises_when_get_returns_none_both_times() -> None:
    db = MagicMock()
    db.get.return_value = None

    with pytest.raises(RuntimeError, match="scan_job_refresh_failed_after_external_wait"):
        _refresh_scan_job_after_wait(db, 5)
