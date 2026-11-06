"""Fase 4 (LANGGRAPH_BRAIN_PLAN): despacho async via MCP (submit+poll).

O caminho sync segurava a chamada HTTP pelo timeout inteiro da ferramenta
(diagnosticado via faulthandler no scan 1/www.example.com: thread presa em
httpcore read dentro de call_tool_sync). O async submete e faz poll com ticks.
"""
from __future__ import annotations

import app.services.mcp_client as mcp_client_mod
from tests.test_mcp_envelope_wiring import FAKE_RESULT


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return dict(self._payload)


def test_execute_kali_tool_async_submit_poll_and_legacy(monkeypatch):
    calls = {"status_checks": 0}

    def fake_post(self, url, **kwargs):
        assert url == "/mcp/submit"
        return _FakeResponse({"status": "submitted", "dispatch_task_id": "job-async-1", "profile": "nuclei_cves"})

    def fake_get(self, url, **kwargs):
        if url == "/mcp/jobs/job-async-1":
            calls["status_checks"] += 1
            return _FakeResponse({"status": "done" if calls["status_checks"] >= 2 else "running"})
        if url == "/mcp/jobs/job-async-1/result":
            result = dict(FAKE_RESULT)
            result["job_id"] = "job-async-1"
            return _FakeResponse(result)
        raise AssertionError(f"url inesperada: {url}")

    monkeypatch.setattr(mcp_client_mod.MCPClient, "call_tool_sync", None)  # sync não deve ser usado
    monkeypatch.setattr("httpx.Client.post", fake_post)
    monkeypatch.setattr("httpx.Client.get", fake_get)

    svc = mcp_client_mod.MCPClient.__new__(mcp_client_mod.MCPClient)
    svc.base_url = "http://mcp_server:3000"
    svc.timeout = 60.0

    ticks = []
    out = svc.execute_kali_tool_async(
        "nuclei", "http://x", scan_id=1, timeout=300, poll_interval=0.01,
        on_tick=lambda elapsed: ticks.append(elapsed),
    )
    assert out.get("execution_path") == "mcp_to_kali_async"
    assert calls["status_checks"] >= 2
    env = out.get("envelope") or {}
    assert env.get("envelope_version") == "result-envelope/v1"
    assert len(env.get("findings_raw") or []) == 1
