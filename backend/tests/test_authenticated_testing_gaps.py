"""Unit tests for the 2026-08-07 authenticated-testing gap fixes:
role-aware privilege ranking (IDOR/BFLA directionality), the 2-identity
business-logic executor, and the new file-upload/admin-functionality tests.
"""
from __future__ import annotations

from types import SimpleNamespace

import app.services.business_logic_analyzer as business_logic_analyzer
import app.services.business_logic_test as business_logic_test
from app.services.auth_session_manager import privilege_rank
from app.services.pentest_validators import _extract_identity_marker, _select_idor_pair


# ── privilege_rank ───────────────────────────────────────────────────────────

def test_privilege_rank_classifies_high_low_and_unknown_roles() -> None:
    assert privilege_rank("admin") == 2
    assert privilege_rank("Super_Admin") == 2
    assert privilege_rank("org_a_manager") == 2
    assert privilege_rank("guest") == 0
    assert privilege_rank("low_priv_user") == 0
    assert privilege_rank("") == 1
    assert privilege_rank("qa_tester") == 1


# ── _select_idor_pair ────────────────────────────────────────────────────────

def _identity(id_: int, role: str) -> SimpleNamespace:
    return SimpleNamespace(id=id_, role=role, identity_key=f"identity-{id_}")


def test_select_idor_pair_prefers_two_peer_rank_identities() -> None:
    admin = (_identity(1, "admin"), SimpleNamespace())
    peer_a = (_identity(2, "user"), SimpleNamespace())
    peer_b = (_identity(3, "user"), SimpleNamespace())
    sessions = [admin, peer_a, peer_b]

    user_a, user_b, rank_matched = _select_idor_pair(sessions)

    assert rank_matched is True
    assert {user_a[0].id, user_b[0].id} == {2, 3}


def test_select_idor_pair_falls_back_when_no_rank_has_two_members() -> None:
    admin = (_identity(1, "admin"), SimpleNamespace())
    guest = (_identity(2, "guest"), SimpleNamespace())
    sessions = [admin, guest]

    user_a, user_b, rank_matched = _select_idor_pair(sessions)

    assert rank_matched is False
    # falls back to capture order as given (already rank-sorted by _sessions upstream)
    assert user_a[0].id == 1
    assert user_b[0].id == 2


# ── _extract_identity_marker ─────────────────────────────────────────────────

def test_extract_identity_marker_reads_json_id_field() -> None:
    observation = {
        "ok": True,
        "headers": {"content-type": "application/json"},
        "body_preview": '{"id": 42, "email": "user@example.com"}',
    }
    assert _extract_identity_marker(observation) == "42"


def test_extract_identity_marker_returns_empty_for_html_catch_all() -> None:
    observation = {
        "ok": True,
        "headers": {"content-type": "text/html"},
        "body_preview": "<!doctype html><html>...</html>",
    }
    assert _extract_identity_marker(observation) == ""


def test_extract_identity_marker_returns_empty_when_not_ok() -> None:
    assert _extract_identity_marker({"ok": False}) == ""


# ── run_as_tool: 2-identity execution ────────────────────────────────────────

class _FakeResponse:
    def __init__(self, status_code: int, content: bytes = b""):
        self.status_code = status_code
        self.content = content
        self.headers = {}


class _FakeClient:
    """Stands in for httpx.Client — differentiates identities by the
    X-Identity header each _client_for() call constructs it with."""

    def __init__(self, *, timeout=None, follow_redirects=None, verify=None, headers=None, cookies=None):
        self.headers = dict(headers or {})
        self.cookies = dict(cookies or {})

    def request(self, method: str, url: str) -> _FakeResponse:
        if self.headers.get("X-Identity") == "owner":
            return _FakeResponse(200, b"owner-object-data")
        return _FakeResponse(403, b"forbidden")

    def close(self) -> None:
        pass


def test_run_as_tool_executes_both_identities_for_cross_identity_action(monkeypatch) -> None:
    """Before this fix, run_as_tool only ever accepted ONE auth_headers/
    auth_cookies pair, so an action requiring ["user_a","user_b"] silently
    only ever executed as a single identity."""
    monkeypatch.setattr(business_logic_test.httpx, "Client", _FakeClient)

    execution_plan = {
        "policy": "observed-evidence-only",
        "guardrails": {},
        "actions": [
            {
                "endpoint": "http://target.test/api/resource/1",
                "method": "GET",
                "required_identities": ["user_a", "user_b"],
                "flows": [],
                "invariants": [],
            }
        ],
        "blocked": [],
    }
    identity_sessions = {
        "user_a": {"headers": {"X-Identity": "owner"}, "cookies": {}},
        "user_b": {"headers": {"X-Identity": "attacker"}, "cookies": {}},
    }

    result = business_logic_test.run_as_tool(
        "target.test",
        execution_plan=execution_plan,
        identity_sessions=identity_sessions,
        run_business_logic_battery=False,
    )

    observations = result["parsed"]["observations"]
    assert len(observations) == 2
    by_identity = {obs["identity_key"]: obs for obs in observations}
    assert by_identity["user_a"]["status_code"] == 200
    assert by_identity["user_b"]["status_code"] == 403
    assert by_identity["user_a"]["cross_identity_delta"] is True
    assert by_identity["user_b"]["cross_identity_delta"] is True


def test_run_as_tool_single_identity_action_unaffected_by_identity_sessions(monkeypatch) -> None:
    """An action with no (or one) required identity must keep behaving
    exactly as before — no regression for the existing single-session path."""
    monkeypatch.setattr(business_logic_test.httpx, "Client", _FakeClient)

    execution_plan = {
        "policy": "observed-evidence-only",
        "guardrails": {},
        "actions": [
            {
                "endpoint": "http://target.test/api/public",
                "method": "GET",
                "required_identities": [],
                "flows": [],
                "invariants": [],
            }
        ],
        "blocked": [],
    }

    result = business_logic_test.run_as_tool(
        "target.test",
        execution_plan=execution_plan,
        auth_headers={"X-Identity": "owner"},
        run_business_logic_battery=False,
    )

    observations = result["parsed"]["observations"]
    assert len(observations) == 1
    assert "identity_key" not in observations[0]
    assert observations[0]["status_code"] == 200


# ── business_logic_analyzer: file-upload / admin-functionality tests ────────

class _FakeHttpResponse:
    def __init__(self, status_code: int, text: str = "", cookies: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.cookies = cookies or {}


def test_test_admin_unauthenticated_access_flags_exposed_dashboard(monkeypatch) -> None:
    def fake_get(url, **kwargs):
        if url.endswith("/admin"):
            return _FakeHttpResponse(200, text="<h1>Admin Panel dashboard</h1><a>Logout</a>")
        return _FakeHttpResponse(404)

    monkeypatch.setattr(business_logic_analyzer.requests, "get", fake_get)

    findings = business_logic_analyzer.test_admin_unauthenticated_access("https://valid.com", "valid.com")

    assert len(findings) == 1
    assert findings[0].test_type == "admin_unauthenticated_access"


def test_test_admin_unauthenticated_access_no_finding_when_all_paths_404(monkeypatch) -> None:
    monkeypatch.setattr(business_logic_analyzer.requests, "get", lambda url, **kwargs: _FakeHttpResponse(404))

    findings = business_logic_analyzer.test_admin_unauthenticated_access("https://valid.com", "valid.com")

    assert findings == []


def test_test_file_upload_flags_accepted_dangerous_extension(monkeypatch) -> None:
    def fake_safe_post(url, data=None, json_data=None, **kwargs):
        if url.endswith("/upload"):
            return _FakeHttpResponse(200, text="upload ok")
        return None

    monkeypatch.setattr(business_logic_analyzer, "_safe_post", fake_safe_post)

    findings = business_logic_analyzer.test_file_upload("https://valid.com", "valid.com")

    assert len(findings) >= 1
    assert all(f.test_type == "file_upload" for f in findings)


def test_test_file_upload_no_finding_when_server_rejects(monkeypatch) -> None:
    def fake_safe_post(url, data=None, json_data=None, **kwargs):
        return _FakeHttpResponse(415, text="File type not allowed")

    monkeypatch.setattr(business_logic_analyzer, "_safe_post", fake_safe_post)

    findings = business_logic_analyzer.test_file_upload("https://valid.com", "valid.com")

    assert findings == []


def test_test_admin_default_creds_flags_accepted_weak_credential(monkeypatch) -> None:
    def fake_safe_post(url, data=None, json_data=None, **kwargs):
        password = (data or {}).get("password", "")
        if password == "zzqq_nopass_9913":
            return _FakeHttpResponse(200, text="invalid username or password")
        if password == "password":
            return _FakeHttpResponse(302, text="")
        return _FakeHttpResponse(200, text="invalid username or password")

    monkeypatch.setattr(business_logic_analyzer, "_safe_post", fake_safe_post)

    findings = business_logic_analyzer.test_admin_default_creds("https://valid.com", "valid.com")

    assert len(findings) >= 1
    assert findings[0].test_type == "admin_default_creds"
