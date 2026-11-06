"""Fase 4 (LANGGRAPH_BRAIN_PLAN): push de resultado no lugar de poll.

O runner empurra o status terminal (callback → Redis) e o poll loop do
executor short-circuita: 0 requests de polling quando o push chegou.
"""
from __future__ import annotations

import json

import app.services.kali_executor as kex


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, ttl, value):
        self.store[key] = value


def _patch_redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(kex, "_result_push_client", fake)
    monkeypatch.setattr(kex, "_result_push_client_loaded", True)
    return fake


def test_store_and_read_pushed_terminal_status(monkeypatch):
    fake = _patch_redis(monkeypatch)
    assert kex.store_pushed_terminal_status("job-1", "done", scan_id=7) is True
    assert kex.pushed_terminal_status("job-1") == "done"
    stored = json.loads(fake.store["kali:result:job-1"])
    assert stored["scan_id"] == 7
    assert stored["status"] == "done"


def test_non_terminal_push_is_ignored(monkeypatch):
    _patch_redis(monkeypatch)
    kex.store_pushed_terminal_status("job-2", "running")
    assert kex.pushed_terminal_status("job-2") is None


def test_missing_push_returns_none(monkeypatch):
    _patch_redis(monkeypatch)
    assert kex.pushed_terminal_status("nope") is None


def test_callback_endpoint_rejects_bad_token(monkeypatch):
    from fastapi import HTTPException

    from app.api.routes_management import kali_result_callback
    from types import SimpleNamespace

    from app.core.config import settings
    monkeypatch.setattr(settings, "mcp_internal_token", "expected-token")

    request = SimpleNamespace(headers={"X-Internal-Token": "wrong"})
    try:
        kali_result_callback(
            payload=SimpleNamespace(job_id="j", status="done", scan_id=1),
            request=request,
        )
    except HTTPException as exc:
        assert exc.status_code == 401
    else:  # pragma: no cover
        raise AssertionError("deveria ter 401")
