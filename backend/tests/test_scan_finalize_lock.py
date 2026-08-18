"""ARCH-003 regression tests.

tasks.py::dispatch_scan_work_items and offensive_operator_runner.py's own
completion path can both independently observe "all work items terminal" and
race to finalize the same ScanJob.status with no row lock (confirmed live:
a 40+ hour stuck scan from exactly this pattern). _try_acquire_scan_finalize_lock
shares dispatch_scan_work_items' own Redis lock key so the two writers
serialize instead of racing.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch


def test_acquire_lock_succeeds_when_key_is_free():
    from app.services.offensive_operator_runner import _try_acquire_scan_finalize_lock

    fake_redis = MagicMock()
    fake_redis.set.return_value = True
    with patch("app.services.scan_work_queue._redis_client", return_value=fake_redis):
        acquired, client = _try_acquire_scan_finalize_lock(42)

    assert acquired is True
    assert client is fake_redis
    fake_redis.set.assert_called_once_with("dispatch_lock:42", "1", nx=True, ex=45)


def test_acquire_lock_fails_when_dispatch_scan_work_items_holds_it():
    """This is the exact scenario ARCH-003 describes: dispatch_scan_work_items
    (tasks.py) already holds dispatch_lock:{scan_id} -- this path must back
    off rather than proceeding to write a conflicting job.status."""
    from app.services.offensive_operator_runner import _try_acquire_scan_finalize_lock

    fake_redis = MagicMock()
    fake_redis.set.return_value = False  # NX failed -- someone else holds it
    with patch("app.services.scan_work_queue._redis_client", return_value=fake_redis):
        acquired, client = _try_acquire_scan_finalize_lock(42)

    assert acquired is False


def test_acquire_lock_fails_open_when_redis_unavailable():
    """A Redis outage must never be able to block scan completion -- matches
    dispatch_scan_work_items' own fail-open precedent."""
    from app.services.offensive_operator_runner import _try_acquire_scan_finalize_lock

    with patch("app.services.scan_work_queue._redis_client", side_effect=RuntimeError("redis down")):
        acquired, client = _try_acquire_scan_finalize_lock(42)

    assert acquired is True
    assert client is None


def test_release_lock_deletes_the_same_key():
    from app.services.offensive_operator_runner import _release_scan_finalize_lock

    fake_redis = MagicMock()
    _release_scan_finalize_lock(42, fake_redis)
    fake_redis.delete.assert_called_once_with("dispatch_lock:42")


def test_release_lock_is_noop_when_no_client_was_acquired():
    from app.services.offensive_operator_runner import _release_scan_finalize_lock

    _release_scan_finalize_lock(42, None)  # must not raise


def test_release_lock_never_raises_on_redis_failure():
    from app.services.offensive_operator_runner import _release_scan_finalize_lock

    fake_redis = MagicMock()
    fake_redis.delete.side_effect = RuntimeError("redis down")
    _release_scan_finalize_lock(42, fake_redis)  # must not raise


def test_lock_key_matches_dispatch_scan_work_items_key_format():
    """The two writers must share the EXACT same key to actually serialize
    against each other -- a mismatched format would silently defeat the fix."""
    import inspect
    from app.workers import tasks

    source = inspect.getsource(tasks.dispatch_scan_work_items)
    assert '_lock_key = f"dispatch_lock:{scan_id}"' in source
