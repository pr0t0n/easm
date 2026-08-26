"""Regression test: P14's jwt_tool dispatch must receive a real captured
bearer token as SCAN_JWT_TOKEN, extracted from the auth session material
already threaded through skill_context["auth_context"]["headers"].

Before this fix nothing ever populated SCAN_JWT_TOKEN, so kali-runner's
jwt_tool_audit profile (requires_env: ["SCAN_JWT_TOKEN"]) always skipped.
"""
from app.services import kali_executor


class _FakeResponse:
    def __init__(self, payload=None, raise_exc=None):
        self._payload = payload or {}
        self._raise_exc = raise_exc

    def raise_for_status(self):
        if self._raise_exc:
            raise self._raise_exc

    def json(self):
        return self._payload


def _capture_post(monkeypatch, captured: dict):
    def _fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["payload"] = json
        raise RuntimeError("stop_before_polling")

    monkeypatch.setattr(kali_executor.requests, "post", _fake_post)


def test_jwt_tool_dispatch_injects_bearer_token_from_auth_context(monkeypatch):
    captured: dict = {}
    _capture_post(monkeypatch, captured)
    monkeypatch.setattr(kali_executor, "_runner_url", lambda: "http://kali-runner")
    monkeypatch.setattr(kali_executor, "resolve_authorized_scope_for_dispatch", lambda scan_id: [])

    skill_context = {"auth_context": {"headers": {"Authorization": "Bearer captured.jwt.token"}}}

    result = kali_executor.execute_via_kali(
        "jwt_tool",
        "http://target.local",
        scan_id=1,
        skill_context=skill_context,
    )

    assert result["status"] == "error"  # short-circuited via the injected enqueue failure
    assert captured["payload"]["env_vars"] == {"SCAN_JWT_TOKEN": "captured.jwt.token"}
    assert captured["payload"]["auth_headers"]["Authorization"] == "Bearer captured.jwt.token"


def test_jwt_tool_dispatch_without_captured_token_sends_no_env_var(monkeypatch):
    captured: dict = {}
    _capture_post(monkeypatch, captured)
    monkeypatch.setattr(kali_executor, "_runner_url", lambda: "http://kali-runner")
    monkeypatch.setattr(kali_executor, "resolve_authorized_scope_for_dispatch", lambda scan_id: [])

    result = kali_executor.execute_via_kali(
        "jwt_tool",
        "http://target.local",
        scan_id=1,
        skill_context={},
    )

    assert result["status"] == "error"
    assert "env_vars" not in captured["payload"]


def test_explicit_env_vars_are_not_overridden_by_auto_injection(monkeypatch):
    captured: dict = {}
    _capture_post(monkeypatch, captured)
    monkeypatch.setattr(kali_executor, "_runner_url", lambda: "http://kali-runner")
    monkeypatch.setattr(kali_executor, "resolve_authorized_scope_for_dispatch", lambda scan_id: [])

    skill_context = {"auth_context": {"headers": {"Authorization": "Bearer captured.jwt.token"}}}

    kali_executor.execute_via_kali(
        "jwt_tool",
        "http://target.local",
        scan_id=1,
        skill_context=skill_context,
        env_vars={"SCAN_JWT_TOKEN": "explicit-token"},
    )

    assert captured["payload"]["env_vars"] == {"SCAN_JWT_TOKEN": "explicit-token"}


def test_non_jwt_tool_dispatch_is_unaffected(monkeypatch):
    captured: dict = {}
    _capture_post(monkeypatch, captured)
    monkeypatch.setattr(kali_executor, "_runner_url", lambda: "http://kali-runner")
    monkeypatch.setattr(kali_executor, "resolve_authorized_scope_for_dispatch", lambda scan_id: [])

    skill_context = {"auth_context": {"headers": {"Authorization": "Bearer captured.jwt.token"}}}

    kali_executor.execute_via_kali(
        "sqlmap",
        "http://target.local",
        scan_id=1,
        skill_context=skill_context,
    )

    assert "env_vars" not in captured["payload"]
    assert captured["payload"]["auth_headers"]["Authorization"] == "Bearer captured.jwt.token"
