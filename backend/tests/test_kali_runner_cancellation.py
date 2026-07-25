from __future__ import annotations

import pytest

from app.services import kali_executor


class _Response:
    def __init__(self, payload: dict, status_error: Exception | None = None):
        self._payload = payload
        self._status_error = status_error

    def raise_for_status(self):
        if self._status_error:
            raise self._status_error

    def json(self):
        return self._payload


def test_cancel_scan_jobs_calls_runner_scan_cancel(monkeypatch):
    calls: list[dict] = []

    def _post(url, **kwargs):
        calls.append({"url": url, **kwargs})
        return _Response({"requested": 3, "killed_processes": 2, "scan_id": 20})

    monkeypatch.setattr(kali_executor, "_runner_url", lambda: "http://runner.local")
    monkeypatch.setattr(kali_executor.requests, "post", _post)

    result = kali_executor.cancel_scan_jobs_in_kali_runner(20, reason="scan_stopped")

    assert result["ok"] is True
    assert result["requested"] == 3
    assert calls == [
        {
            "url": "http://runner.local/jobs/cancel",
            "params": {"scan_id": 20, "reason": "scan_stopped"},
            "timeout": 15,
        }
    ]


def test_cancel_scan_jobs_reports_runner_failure(monkeypatch):
    def _post(_url, **_kwargs):
        raise RuntimeError("runner unavailable")

    monkeypatch.setattr(kali_executor, "_runner_url", lambda: "http://runner.local")
    monkeypatch.setattr(kali_executor.requests, "post", _post)

    result = kali_executor.cancel_scan_jobs_in_kali_runner(20)

    assert result["ok"] is False
    assert result["scan_id"] == 20
    assert "runner unavailable" in result["error"]
