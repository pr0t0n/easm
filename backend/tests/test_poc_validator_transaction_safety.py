"""Regression tests for schedule_poc_validation's transaction handling.

schedule_poc_validation() runs from inside enforce_high_risk_lifecycle's own
`with db.begin_nested():` (see scan_quality.run_scan_quality_gate). A bare
db.rollback()/db.commit() call on the shared session from in here desyncs
SQLAlchemy's transaction-context bookkeeping and makes the NEXT DB call
anywhere in the request raise "Can't operate on closed transaction inside
context manager" -- confirmed live, this recurred on every quality-gate round
for a scan with a colliding finding. The fix replaces those bare calls with
the function's own `with db.begin_nested():` savepoint, so a failure unwinds
only this attempt via the normal context-manager protocol.
"""
from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock


def _fake_session():
    db = MagicMock()
    db.query.return_value.filter.return_value.count.return_value = 0
    db.query.return_value.filter.return_value.first.return_value = None

    @contextmanager
    def fake_begin_nested():
        yield MagicMock()

    db.begin_nested.side_effect = fake_begin_nested

    def fake_add(obj):
        if not getattr(obj, "id", None):
            obj.id = 999

    db.add.side_effect = fake_add
    return db


def _finding():
    return SimpleNamespace(
        id=42,
        severity="high",
        verification_status="candidate",
        tool="nuclei-sqli",
        title="SQL Injection in login form",
        url="https://example.com/login",
        details={},
        domain="example.com",
    )


def test_schedule_poc_validation_never_calls_bare_rollback_on_flush_failure():
    from app.services import poc_validator

    db = _fake_session()
    db.flush.side_effect = Exception("unique constraint violation")
    job = SimpleNamespace(id=7, status="running")

    result = poc_validator.schedule_poc_validation(db, _finding(), job)

    assert result is False
    db.rollback.assert_not_called()
    db.commit.assert_not_called()
    db.begin_nested.assert_called_once()


def test_schedule_poc_validation_never_calls_bare_commit_on_success():
    from app.services import poc_validator

    db = _fake_session()
    job = SimpleNamespace(id=7, status="running")

    result = poc_validator.schedule_poc_validation(db, _finding(), job)

    assert result is True
    db.rollback.assert_not_called()
    db.commit.assert_not_called()
    db.begin_nested.assert_called_once()


def test_schedule_poc_validation_accepts_medium_candidate_with_validator():
    from app.services import poc_validator

    db = _fake_session()
    job = SimpleNamespace(id=7, status="running")
    finding = _finding()
    finding.severity = "medium"

    result = poc_validator.schedule_poc_validation(db, finding, job)

    assert result is True
    db.begin_nested.assert_called_once()


def test_schedule_poc_validation_rejected_for_terminal_scan_never_commits():
    """The scan-not-running early exit also must not touch the shared
    session's transaction directly -- it only queues a ScanLog row."""
    from app.services import poc_validator

    db = _fake_session()
    job = SimpleNamespace(id=7, status="completed")

    result = poc_validator.schedule_poc_validation(db, _finding(), job)

    assert result is False
    db.rollback.assert_not_called()
    db.commit.assert_not_called()
    db.add.assert_called_once()
