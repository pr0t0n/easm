"""Tests for the self_grant_then_revert wiring in skill_execution_engine.py:
the gate must be independent from destructive_payloads_allowed (its own flag
controls it, neither implies the other), and dispatch must correctly split
self-grant actions away from run_as_tool's replay loop.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.services.skill_execution_engine import (
    _run_self_grant_actions,
    _run_weak_secret_actions,
    validate_skill_actions,
)

_ENDPOINTS = [
    {"method": "POST", "url": "https://api.example.com/api/host/organizations/1/members/2/roles"},
]
_SCOPE = ["api.example.com"]


def test_self_grant_template_rejected_when_flag_is_false() -> None:
    raw_actions = [{"endpoint_index": 0, "template": "self_grant_then_revert", "purpose": "escalate"}]
    accepted, rejected = validate_skill_actions(
        raw_actions, _ENDPOINTS, _SCOPE,
        destructive_payloads_allowed=True,  # even with the OTHER flag true...
        self_revert_mutation_allowed=False,  # ...this one still blocks it
    )
    assert accepted == []
    assert rejected[0]["reason"] == "self_grant_template_not_allowed_by_skill_safety_rules"


def test_self_grant_template_accepted_when_flag_is_true_even_if_destructive_false() -> None:
    raw_actions = [{"endpoint_index": 0, "template": "self_grant_then_revert", "purpose": "escalate"}]
    accepted, rejected = validate_skill_actions(
        raw_actions, _ENDPOINTS, _SCOPE,
        destructive_payloads_allowed=False,  # the OTHER, broader flag stays off...
        self_revert_mutation_allowed=True,  # ...but this narrow one is enough
    )
    assert rejected == []
    assert accepted[0]["template"] == "self_grant_then_revert"
    assert accepted[0]["endpoint"] == _ENDPOINTS[0]["url"]


def test_self_grant_template_still_scope_checked() -> None:
    raw_actions = [{"endpoint_index": 0, "template": "self_grant_then_revert", "purpose": "escalate"}]
    accepted, rejected = validate_skill_actions(
        raw_actions, _ENDPOINTS, ["some-other-host.example.com"],
        destructive_payloads_allowed=True, self_revert_mutation_allowed=True,
    )
    assert accepted == []
    assert rejected[0]["reason"] == "endpoint_out_of_scope"


def test_ordinary_mutating_template_unaffected_by_new_flag() -> None:
    """self_revert_mutation_allowed must not accidentally widen the
    unrelated destructive-template gate."""
    accepted, rejected = validate_skill_actions(
        [{"endpoint_index": 0, "template": "baseline_get", "purpose": "x"}],
        [{"method": "GET", "url": "https://api.example.com/x"}], _SCOPE,
        destructive_payloads_allowed=False, self_revert_mutation_allowed=True,
    )
    assert accepted[0]["flows"] == ["baseline_get"]


def test_run_self_grant_actions_skips_without_revert_endpoint() -> None:
    with patch("app.services.skill_execution_engine.authorized_scope_for_scan", return_value=_SCOPE), \
         patch("app.db.session.SessionLocal"), \
         patch("app.services.self_reverting_mutation.find_roles_listing_endpoint", return_value={"method": "GET", "url": "https://api.example.com/roles"}), \
         patch("app.services.self_reverting_mutation.find_revert_endpoint", return_value=None), \
         patch("app.services.self_reverting_mutation.execute_self_grant_then_revert") as mock_execute:
        results = _run_self_grant_actions(
            scan_id=1,
            grant_actions=[{"endpoint": "https://api.example.com/grant", "method": "POST"}],
            endpoints=_ENDPOINTS,
            auth_headers={"Authorization": "Bearer x"},
            auth_cookies={},
        )
    assert results[0]["granted"] is False
    assert results[0]["reason"] == "no_revert_endpoint_discovered"
    mock_execute.assert_not_called()


def test_run_self_grant_actions_skips_without_roles_endpoint() -> None:
    with patch("app.services.skill_execution_engine.authorized_scope_for_scan", return_value=_SCOPE), \
         patch("app.db.session.SessionLocal"), \
         patch("app.services.self_reverting_mutation.find_roles_listing_endpoint", return_value=None), \
         patch("app.services.self_reverting_mutation.find_revert_endpoint", return_value={"method": "DELETE", "url": "https://api.example.com/revert"}), \
         patch("app.services.self_reverting_mutation.execute_self_grant_then_revert") as mock_execute:
        results = _run_self_grant_actions(
            scan_id=1,
            grant_actions=[{"endpoint": "https://api.example.com/grant", "method": "POST"}],
            endpoints=_ENDPOINTS,
            auth_headers={},
            auth_cookies={},
        )
    assert results[0]["reason"] == "no_roles_listing_endpoint"
    mock_execute.assert_not_called()


def test_run_self_grant_actions_rejects_out_of_scope_endpoint() -> None:
    """SEC-002: a defense-in-depth re-check independent of validate_skill_actions."""
    with patch("app.services.skill_execution_engine.authorized_scope_for_scan", return_value=["other-host.example.com"]), \
         patch("app.db.session.SessionLocal"), \
         patch("app.services.self_reverting_mutation.execute_self_grant_then_revert") as mock_execute:
        results = _run_self_grant_actions(
            scan_id=1,
            grant_actions=[{"endpoint": "https://api.example.com/grant", "method": "POST"}],
            endpoints=_ENDPOINTS,
            auth_headers={},
            auth_cookies={},
        )
    assert results[0]["granted"] is False
    assert results[0]["reason"] == "endpoint_out_of_scope"
    mock_execute.assert_not_called()


def test_run_self_grant_actions_dispatches_when_both_endpoints_found() -> None:
    with patch("app.services.skill_execution_engine.authorized_scope_for_scan", return_value=_SCOPE), \
         patch("app.services.self_reverting_mutation.find_roles_listing_endpoint", return_value={"method": "GET", "url": "https://api.example.com/roles"}), \
         patch("app.services.self_reverting_mutation.find_revert_endpoint", return_value={"method": "DELETE", "url": "https://api.example.com/revert"}), \
         patch("app.services.self_reverting_mutation.execute_self_grant_then_revert", return_value={"granted": True, "reverted": True}) as mock_execute, \
         patch("app.db.session.SessionLocal"):
        results = _run_self_grant_actions(
            scan_id=7,
            grant_actions=[{"endpoint": "https://api.example.com/grant", "method": "POST"}],
            endpoints=_ENDPOINTS,
            auth_headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sig"},
            auth_cookies={},
        )
    assert results[0]["granted"] is True
    assert results[0]["grant_endpoint"] == "https://api.example.com/grant"
    mock_execute.assert_called_once()
    assert mock_execute.call_args.kwargs["self_user_id"] == "u1"


# ── weak_secret_guessing gate + dispatch ────────────────────────────────────

def test_weak_secret_template_rejected_when_flag_is_false() -> None:
    raw_actions = [{"endpoint_index": 0, "template": "forge_weak_secret_header", "purpose": "guess"}]
    accepted, rejected = validate_skill_actions(
        raw_actions, _ENDPOINTS, _SCOPE,
        destructive_payloads_allowed=True, self_revert_mutation_allowed=True,
        weak_secret_guessing_allowed=False,
    )
    assert accepted == []
    assert rejected[0]["reason"] == "weak_secret_guessing_not_allowed_by_skill_safety_rules"


def test_weak_secret_template_accepted_when_its_own_flag_is_true() -> None:
    raw_actions = [{"endpoint_index": 0, "template": "forge_weak_secret_header", "purpose": "guess"}]
    accepted, rejected = validate_skill_actions(
        raw_actions, _ENDPOINTS, _SCOPE,
        destructive_payloads_allowed=False, self_revert_mutation_allowed=False,
        weak_secret_guessing_allowed=True,
    )
    assert rejected == []
    assert accepted[0]["template"] == "forge_weak_secret_header"
    assert accepted[0]["method"] == "GET"  # forced GET even though the discovered endpoint was POST


def test_run_weak_secret_actions_skips_without_forgeable_header() -> None:
    results = _run_weak_secret_actions(
        scan_id=1,
        target="https://api.example.com",
        probe_actions=[{"endpoint": "https://api.example.com/whoami"}],
        auth_headers={"Authorization": "Bearer sometoken"},
        auth_cookies={},
    )
    assert results == [{"attempted": False, "reason": "no_forgeable_header_in_captured_session"}]


def test_run_weak_secret_actions_dispatches_when_forgeable_header_present() -> None:
    from app.services.weak_secret_probe import sign_hs256

    token = sign_hs256({}, {"sub": "u1", "roles": ["member"]}, "whatever")
    with patch("app.services.skill_execution_engine.authorized_scope_for_scan", return_value=_SCOPE), \
         patch("app.db.session.SessionLocal"), \
         patch("app.services.weak_secret_probe.probe_weak_secret", return_value={"attempted": True, "confirmed": False}) as mock_probe:
        results = _run_weak_secret_actions(
            scan_id=1,
            target="https://api.example.com",
            probe_actions=[{"endpoint": "https://api.example.com/whoami"}],
            auth_headers={"Authorization": "Bearer x", "X-Impersonate": token},
            auth_cookies={},
        )
    assert results[0]["attempted"] is True
    assert results[0]["confirmed"] is False
    assert results[0]["whoami_url"] == "https://api.example.com/whoami"
    mock_probe.assert_called_once()
    assert mock_probe.call_args.kwargs["header_name"] == "X-Impersonate"
    assert "X-Impersonate" not in mock_probe.call_args.kwargs["other_headers"]


def test_run_weak_secret_actions_rejects_out_of_scope_endpoint() -> None:
    """SEC-002: a defense-in-depth re-check independent of validate_skill_actions."""
    from app.services.weak_secret_probe import sign_hs256

    token = sign_hs256({}, {"sub": "u1", "roles": ["member"]}, "whatever")
    with patch("app.services.skill_execution_engine.authorized_scope_for_scan", return_value=["other-host.example.com"]), \
         patch("app.db.session.SessionLocal"), \
         patch("app.services.weak_secret_probe.probe_weak_secret") as mock_probe:
        results = _run_weak_secret_actions(
            scan_id=1,
            target="https://api.example.com",
            probe_actions=[{"endpoint": "https://api.example.com/whoami"}],
            auth_headers={"Authorization": "Bearer x", "X-Impersonate": token},
            auth_cookies={},
        )
    assert results[0]["reason"] == "endpoint_out_of_scope"
    mock_probe.assert_not_called()


# ── SEC-002: durable audit trail for these direct-HTTP, MCP/Kali-bypassing probes ──

def test_audit_self_grant_attempt_writes_durable_record() -> None:
    from app.services.skill_execution_engine import _audit_self_grant_attempt

    with patch("app.db.session.SessionLocal") as mock_session_local, \
         patch("app.services.audit_service.log_audit") as mock_log_audit:
        fake_db = MagicMock()
        mock_session_local.return_value = fake_db
        _audit_self_grant_attempt(7, {"granted": True, "reverted": True, "grant_endpoint": "https://api.example.com/grant"})

    mock_log_audit.assert_called_once()
    _, kwargs = mock_log_audit.call_args
    assert kwargs["scan_job_id"] == 7
    assert kwargs["event_type"] == "skill_probe.self_grant_then_revert"
    assert kwargs["metadata"]["granted"] is True
    fake_db.commit.assert_called_once()


def test_audit_self_grant_attempt_never_raises_on_failure() -> None:
    from app.services.skill_execution_engine import _audit_self_grant_attempt

    with patch("app.db.session.SessionLocal", side_effect=RuntimeError("db down")):
        _audit_self_grant_attempt(7, {"granted": False})  # must not raise


def test_audit_weak_secret_attempt_writes_durable_record() -> None:
    from app.services.skill_execution_engine import _audit_weak_secret_attempt

    with patch("app.db.session.SessionLocal") as mock_session_local, \
         patch("app.services.audit_service.log_audit") as mock_log_audit:
        fake_db = MagicMock()
        mock_session_local.return_value = fake_db
        _audit_weak_secret_attempt(7, {"attempted": True, "confirmed": True, "whoami_url": "https://api.example.com/whoami"})

    mock_log_audit.assert_called_once()
    _, kwargs = mock_log_audit.call_args
    assert kwargs["scan_job_id"] == 7
    assert kwargs["event_type"] == "skill_probe.weak_secret_guess"
    assert kwargs["metadata"]["confirmed"] is True
    fake_db.commit.assert_called_once()


def test_audit_weak_secret_attempt_never_raises_on_failure() -> None:
    from app.services.skill_execution_engine import _audit_weak_secret_attempt

    with patch("app.db.session.SessionLocal", side_effect=RuntimeError("db down")):
        _audit_weak_secret_attempt(7, {"attempted": False})  # must not raise
