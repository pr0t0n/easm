"""SEC-001 regression tests.

kali-runner's own POST /jobs fail-closes (400 "authorized_scope is required")
on any request whose authorized_scope is empty. execute_via_kali (direct
dispatch) and mcp_client.execute_kali_tool_sync (MCP dispatch) previously
never included this field at all, so any live code path routed through
either of them would always be rejected by the runner's guardrail.
"""
from __future__ import annotations


def test_resolve_authorized_scope_returns_empty_for_non_integer_scan_id():
    from app.services.kali_executor import resolve_authorized_scope_for_dispatch

    assert resolve_authorized_scope_for_dispatch(None) == []
    assert resolve_authorized_scope_for_dispatch("mcp_scan") == []


def test_resolve_authorized_scope_derives_from_scan_job(monkeypatch):
    from app.services import kali_executor

    monkeypatch.setattr(
        "app.services.scan_scope.authorized_scope_for_scan",
        lambda db, scan_id: ["example.com", "sub.example.com"],
    )
    result = kali_executor.resolve_authorized_scope_for_dispatch(42)
    assert result == ["example.com", "sub.example.com"]


def test_resolve_authorized_scope_fails_closed_to_empty_on_error(monkeypatch):
    from app.services import kali_executor

    def _boom(db, scan_id):
        raise RuntimeError("db unavailable")

    monkeypatch.setattr("app.services.scan_scope.authorized_scope_for_scan", _boom)
    assert kali_executor.resolve_authorized_scope_for_dispatch(42) == []


def test_execute_via_kali_payload_includes_authorized_scope(monkeypatch):
    from app.services import kali_executor

    captured: dict[str, object] = {}

    def _fake_post(url, json=None, timeout=None):
        captured["payload"] = json
        raise RuntimeError("stop-after-capture")

    monkeypatch.setattr(kali_executor, "_runner_url", lambda: "http://runner.local")
    monkeypatch.setattr(kali_executor, "resolve_authorized_scope_for_dispatch", lambda scan_id: ["example.com"])
    monkeypatch.setattr(kali_executor.requests, "post", _fake_post)

    kali_executor.execute_via_kali("nuclei", "example.com", scan_id=42)

    assert "payload" in captured
    assert captured["payload"]["authorized_scope"] == ["example.com"]


def test_mcp_client_execute_kali_tool_sync_includes_authorized_scope(monkeypatch):
    from app.services import mcp_client as mcp_client_module

    captured: dict[str, object] = {}

    def _fake_call_tool_sync(self, tool_name, parameters, *, timeout=None):
        captured["parameters"] = parameters
        return {"status": "error", "error": "stop-after-capture"}

    monkeypatch.setattr(mcp_client_module.MCPClient, "list_tools_sync", lambda self: [])
    monkeypatch.setattr(mcp_client_module.MCPClient, "call_tool_sync", _fake_call_tool_sync)
    monkeypatch.setattr(
        mcp_client_module, "resolve_authorized_scope_for_dispatch", lambda scan_id: ["example.com"]
    )

    client = mcp_client_module.MCPClient()
    client.execute_kali_tool_sync("nuclei", "example.com", scan_id=42)

    assert "parameters" in captured
    assert captured["parameters"]["authorized_scope"] == ["example.com"]


def test_mcp_client_resolves_empty_scope_for_adhoc_scan_id(monkeypatch):
    from app.services import mcp_client as mcp_client_module

    captured: dict[str, object] = {}

    def _fake_call_tool_sync(self, tool_name, parameters, *, timeout=None):
        captured["parameters"] = parameters
        return {"status": "error", "error": "stop-after-capture"}

    monkeypatch.setattr(mcp_client_module.MCPClient, "list_tools_sync", lambda self: [])
    monkeypatch.setattr(mcp_client_module.MCPClient, "call_tool_sync", _fake_call_tool_sync)

    client = mcp_client_module.MCPClient()
    client.execute_kali_tool_sync("nuclei", "example.com", scan_id=None)

    assert captured["parameters"]["authorized_scope"] == []


# ── MCP-001: audit trail for direct (non-MCP) Kali dispatch ────────────────
#
# browser_capture_service.py, exploit_browser_xss.py and business_logic_test.py
# all call execute_via_kali directly, bypassing MCP's own request audit trail.
# execute_via_kali now writes a durable AuditEvent for every successful direct
# dispatch instead, covering all current (and future) direct callers from one
# choke point.

def test_record_dispatch_audit_event_writes_durable_audit_row(monkeypatch):
    from app.services import kali_executor
    from unittest.mock import MagicMock

    fake_db = MagicMock()
    monkeypatch.setattr("app.db.session.SessionLocal", lambda: fake_db)
    captured = {}

    def _fake_log_audit(db, event_type, message, *, scan_job_id=None, level="INFO", metadata=None):
        captured["db"] = db
        captured["event_type"] = event_type
        captured["scan_job_id"] = scan_job_id
        captured["metadata"] = metadata

    monkeypatch.setattr("app.services.audit_service.log_audit", _fake_log_audit)

    kali_executor._record_dispatch_audit_event(
        tool_name="chromium-capture", profile="chromium_capture", target="example.com",
        scan_id=7, job_id="job-123",
    )

    assert captured["event_type"] == "kali.direct_dispatch"
    assert captured["scan_job_id"] == 7
    assert captured["metadata"]["tool"] == "chromium-capture"
    assert captured["metadata"]["job_id"] == "job-123"
    assert captured["metadata"]["execution_path"] == "direct_kali_bypasses_mcp"
    fake_db.commit.assert_called_once()


def test_record_dispatch_audit_event_never_raises_on_failure(monkeypatch):
    from app.services import kali_executor

    def _boom():
        raise RuntimeError("db unavailable")

    monkeypatch.setattr("app.db.session.SessionLocal", _boom)

    # Must not raise -- audit-write failures can never break the actual dispatch.
    kali_executor._record_dispatch_audit_event(
        tool_name="chromium-capture", profile="chromium_capture", target="example.com",
        scan_id=7, job_id="job-123",
    )


def test_execute_via_kali_records_audit_event_on_successful_enqueue(monkeypatch):
    from app.services import kali_executor

    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"job_id": "job-abc"}

    audit_calls = []

    def _fake_post(url, json=None, timeout=None):
        return _FakeResponse()

    def _fake_get(url, timeout=None):
        class _Poll:
            def raise_for_status(self):
                pass

            def json(self):
                return {
                    "status": "done", "stdout": "", "stderr": "", "return_code": 0,
                    "command": "nuclei", "parsed": [],
                }
        return _Poll()

    monkeypatch.setattr(kali_executor, "_runner_url", lambda: "http://runner.local")
    monkeypatch.setattr(kali_executor.requests, "post", _fake_post)
    monkeypatch.setattr(kali_executor.requests, "get", _fake_get)
    monkeypatch.setattr(kali_executor, "resolve_authorized_scope_for_dispatch", lambda scan_id: ["example.com"])
    monkeypatch.setattr(
        kali_executor, "_record_dispatch_audit_event",
        lambda **kwargs: audit_calls.append(kwargs),
    )

    kali_executor.execute_via_kali("nuclei", "example.com", scan_id=7)

    assert len(audit_calls) == 1
    assert audit_calls[0]["tool_name"] == "nuclei"
    assert audit_calls[0]["scan_id"] == 7
    assert audit_calls[0]["job_id"] == "job-abc"
