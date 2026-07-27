from __future__ import annotations

from app.services import watchdog


class _Response:
    def __init__(self, items):
        self._items = items

    def raise_for_status(self):
        return None

    def json(self):
        return {"items": self._items}


class _Client:
    def __init__(self, responses):
        self._responses = iter(responses)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get(self, _url, **_kwargs):
        response = next(self._responses)
        if isinstance(response, Exception):
            raise response
        return _Response(response)


def test_watchdog_preserves_scan_with_active_kali_job(monkeypatch):
    client = _Client([[{"scan_id": 12, "status": "running"}]])
    monkeypatch.setattr(watchdog.httpx, "Client", lambda **_kwargs: client)

    assert watchdog._kali_scan_has_active_jobs(12) is True


def test_watchdog_does_not_confuse_another_scan_activity(monkeypatch):
    client = _Client([
        [{"scan_id": 99, "status": "running"}],
        [{"scan_id": 99, "status": "queued"}],
    ])
    monkeypatch.setattr(watchdog.httpx, "Client", lambda **_kwargs: client)

    assert watchdog._kali_scan_has_active_jobs(12) is False


def test_watchdog_reports_unknown_when_runner_cannot_be_inspected(monkeypatch):
    client = _Client([RuntimeError("runner unavailable")])
    monkeypatch.setattr(watchdog.httpx, "Client", lambda **_kwargs: client)

    assert watchdog._kali_scan_has_active_jobs(12) is None


def test_watchdog_default_no_progress_threshold_exceeds_p01_long_job():
    assert watchdog._ORPHAN_NO_PROGRESS_SECONDS > 900


def test_watchdog_has_idle_transaction_reaper_contract():
    source = watchdog.__loader__.get_source(watchdog.__name__)  # type: ignore[union-attr]
    assert "pg_terminate_backend" in source
    assert "idle in transaction" in source
    assert "WATCHDOG_IDLE_TX_REAPER_SECONDS" in source


def test_no_progress_recovery_preserves_scan_with_active_celery_task():
    assert watchdog._no_progress_recovery_blocker(22, False, {22}, True) == "celery_task_active"


def test_no_progress_recovery_preserves_when_celery_inspect_is_unknown():
    assert watchdog._no_progress_recovery_blocker(22, False, set(), False) == "celery_inspect_unknown"


def test_no_progress_recovery_preserves_scan_with_active_runner_job():
    assert watchdog._no_progress_recovery_blocker(22, True, set(), True) == "kali_runner_active"


def test_no_progress_recovery_allows_only_when_runner_and_celery_are_idle():
    assert watchdog._no_progress_recovery_blocker(22, False, {21}, True) is None


def test_deadchain_recovery_consults_kali_runner_before_redrive():
    source = watchdog.__loader__.get_source(watchdog.__name__)  # type: ignore[union-attr]

    deadchain_section = source.split("CADEIA MORTA por AUSÊNCIA DE LOCK", 1)[1].split("PROMOTOR de scans", 1)[0]
    assert "runner_active = _kali_scan_has_active_jobs(sid)" in deadchain_section
    assert '"blocker": "kali_runner_active"' in deadchain_section
    assert '"blocker": "kali_runner_unknown"' in deadchain_section
    assert "truly_orphan.append(sid)" in deadchain_section
