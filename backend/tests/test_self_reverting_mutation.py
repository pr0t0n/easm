"""Tests for the one guarded mutation sequence the platform is allowed to
perform: self-grant an observed role -> confirm -> always revert.

Priorities, in order: (1) never grant without a discovered revert path,
(2) never leave a grant unreverted without screaming about it, (3) never
invent a request body -- only try the fixed, code-defined shape list against
real, already-observed role data.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.services.self_reverting_mutation import (
    _extract_role_objects,
    execute_self_grant_then_revert,
    find_revert_endpoint,
    find_roles_listing_endpoint,
)


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_extract_role_objects_from_data_envelope() -> None:
    payload = {"data": [{"id": "r1", "name": "platform-id.member"}, {"id": "r2", "name": "platform-id.admin"}]}
    roles = _extract_role_objects(payload)
    assert {"id": "r1", "name": "platform-id.member"} in roles
    assert {"id": "r2", "name": "platform-id.admin"} in roles


def test_extract_role_objects_returns_empty_for_unrecognized_shape() -> None:
    assert _extract_role_objects({"unexpected": "shape"}) == []
    assert _extract_role_objects(None) == []
    assert _extract_role_objects("not a dict") == []


def test_find_revert_endpoint_prefers_delete_on_same_path() -> None:
    endpoints = [
        {"method": "GET", "url": "https://api.example.com/api/host/roles"},
        {"method": "DELETE", "url": "https://api.example.com/api/host/organizations/1/members/2/roles"},
    ]
    revert = find_revert_endpoint("https://api.example.com/api/host/organizations/1/members/2/roles", endpoints)
    assert revert is not None
    assert revert["method"] == "DELETE"


def test_find_revert_endpoint_matches_sibling_remove_path() -> None:
    endpoints = [
        {"method": "POST", "url": "https://api.example.com/api/host/permissions/users/2/remove"},
    ]
    revert = find_revert_endpoint("https://api.example.com/api/host/permissions/users/2", endpoints)
    assert revert is not None
    assert "remove" in revert["url"]


def test_find_revert_endpoint_returns_none_when_no_candidate() -> None:
    endpoints = [{"method": "GET", "url": "https://api.example.com/api/host/roles"}]
    assert find_revert_endpoint("https://api.example.com/api/host/organizations/1/members/2/roles", endpoints) is None


def test_find_roles_listing_endpoint_matches_role_path() -> None:
    endpoints = [
        {"method": "POST", "url": "https://api.example.com/api/host/organizations/1/members/2/roles"},
        {"method": "GET", "url": "https://api.example.com/api/host/roles"},
    ]
    found = find_roles_listing_endpoint(endpoints)
    assert found == {"method": "GET", "url": "https://api.example.com/api/host/roles"}


# ── execute_self_grant_then_revert ──────────────────────────────────────────

def _mock_response(status_code=200, json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 300
    resp.json.return_value = json_data or {}
    return resp


def test_grant_then_revert_full_success_confirms_escalation() -> None:
    roles_payload = {"data": [{"id": "r1", "name": "platform-id.member"}, {"id": "r2", "name": "platform-id.admin"}]}
    call_log = []

    def fake_get(url, **kwargs):
        call_log.append(("GET", url))
        return _mock_response(200, roles_payload)

    def fake_request(method, url, **kwargs):
        call_log.append((method, url, kwargs.get("json")))
        if method == "POST" and url == "https://api.example.com/grant":
            return _mock_response(200)
        if method == "DELETE" and url == "https://api.example.com/revert":
            return _mock_response(204)
        return _mock_response(404)

    log_error = MagicMock()

    with patch("app.services.self_reverting_mutation.requests.get", side_effect=fake_get), \
         patch("app.services.self_reverting_mutation.requests.request", side_effect=fake_request):
        result = execute_self_grant_then_revert(
            grant_endpoint="https://api.example.com/grant",
            grant_method="POST",
            roles_endpoint="https://api.example.com/roles",
            revert_endpoint={"method": "DELETE", "url": "https://api.example.com/revert"},
            headers={"Authorization": "Bearer x"},
            cookies={},
            self_user_id="me",
            scan_id=1,
            log_error=log_error,
        )

    assert result["granted"] is True
    assert result["reverted"] is True
    assert result["target_role"]["name"] == "platform-id.admin"
    log_error.assert_not_called()


def test_grant_never_attempted_without_no_elevated_role() -> None:
    """Every observed role ranks as peer/unknown or lower -- nothing to escalate to."""
    roles_payload = {"data": [{"id": "r1", "name": "member"}, {"id": "r2", "name": "viewer"}]}

    def fake_get(url, **kwargs):
        return _mock_response(200, roles_payload)

    log_error = MagicMock()
    with patch("app.services.self_reverting_mutation.requests.get", side_effect=fake_get), \
         patch("app.services.self_reverting_mutation.requests.request") as mock_request:
        result = execute_self_grant_then_revert(
            grant_endpoint="https://api.example.com/grant",
            grant_method="POST",
            roles_endpoint="https://api.example.com/roles",
            revert_endpoint={"method": "DELETE", "url": "https://api.example.com/revert"},
            headers={}, cookies={}, self_user_id="me", scan_id=1, log_error=log_error,
        )

    assert result["granted"] is False
    assert result["reason"] == "no_elevated_role_observed"
    mock_request.assert_not_called()  # never even attempted a write


def test_grant_failure_never_attempts_revert() -> None:
    roles_payload = {"data": [{"id": "r1", "name": "member"}, {"id": "r2", "name": "admin"}]}

    def fake_get(url, **kwargs):
        return _mock_response(200, roles_payload)

    def fake_request(method, url, **kwargs):
        return _mock_response(403)  # every grant attempt rejected

    log_error = MagicMock()
    with patch("app.services.self_reverting_mutation.requests.get", side_effect=fake_get), \
         patch("app.services.self_reverting_mutation.requests.request", side_effect=fake_request) as mock_request:
        result = execute_self_grant_then_revert(
            grant_endpoint="https://api.example.com/grant",
            grant_method="POST",
            roles_endpoint="https://api.example.com/roles",
            revert_endpoint={"method": "DELETE", "url": "https://api.example.com/revert"},
            headers={}, cookies={}, self_user_id="me", scan_id=1, log_error=log_error,
        )

    assert result["granted"] is False
    assert result["reverted"] is None  # revert only tracked when a grant happened
    log_error.assert_not_called()
    # every request call was a grant attempt (one per body shape), never a
    # DELETE to the revert endpoint
    assert all(call.args[0] != "DELETE" for call in mock_request.call_args_list)


def test_revert_failure_screams_via_log_error() -> None:
    roles_payload = {"data": [{"id": "r1", "name": "member"}, {"id": "r2", "name": "admin"}]}

    def fake_get(url, **kwargs):
        return _mock_response(200, roles_payload)

    def fake_request(method, url, **kwargs):
        if method == "POST" and url == "https://api.example.com/grant":
            return _mock_response(200)
        return _mock_response(500)  # revert always fails, regardless of shape tried

    log_error = MagicMock()
    with patch("app.services.self_reverting_mutation.requests.get", side_effect=fake_get), \
         patch("app.services.self_reverting_mutation.requests.request", side_effect=fake_request):
        result = execute_self_grant_then_revert(
            grant_endpoint="https://api.example.com/grant",
            grant_method="POST",
            roles_endpoint="https://api.example.com/roles",
            revert_endpoint={"method": "POST", "url": "https://api.example.com/revert"},
            headers={}, cookies={}, self_user_id="me", scan_id=42, log_error=log_error,
        )

    assert result["granted"] is True
    assert result["reverted"] is False
    log_error.assert_called_once()
    assert "scan=42" in log_error.call_args.args[0]
    assert "MANUAL CLEANUP REQUIRED" in log_error.call_args.args[0]


def test_revert_tries_multiple_body_shapes_when_first_fails() -> None:
    roles_payload = {"data": [{"id": "r1", "name": "member"}, {"id": "r2", "name": "admin"}]}
    revert_attempts = []

    def fake_get(url, **kwargs):
        return _mock_response(200, roles_payload)

    def fake_request(method, url, **kwargs):
        if method == "POST" and url == "https://api.example.com/grant":
            return _mock_response(200)
        if url == "https://api.example.com/revert":
            revert_attempts.append(kwargs.get("json"))
            # only succeed on the 3rd distinct shape tried
            return _mock_response(200) if len(revert_attempts) >= 3 else _mock_response(400)
        return _mock_response(404)

    log_error = MagicMock()
    with patch("app.services.self_reverting_mutation.requests.get", side_effect=fake_get), \
         patch("app.services.self_reverting_mutation.requests.request", side_effect=fake_request):
        result = execute_self_grant_then_revert(
            grant_endpoint="https://api.example.com/grant",
            grant_method="POST",
            roles_endpoint="https://api.example.com/roles",
            revert_endpoint={"method": "POST", "url": "https://api.example.com/revert"},
            headers={}, cookies={}, self_user_id="me", scan_id=1, log_error=log_error,
        )

    assert result["reverted"] is True
    assert len(revert_attempts) == 3
    log_error.assert_not_called()


def test_roles_listing_fetch_failure_never_attempts_write() -> None:
    log_error = MagicMock()
    with patch("app.services.self_reverting_mutation.requests.get", side_effect=ConnectionError("boom")), \
         patch("app.services.self_reverting_mutation.requests.request") as mock_request:
        result = execute_self_grant_then_revert(
            grant_endpoint="https://api.example.com/grant",
            grant_method="POST",
            roles_endpoint="https://api.example.com/roles",
            revert_endpoint={"method": "DELETE", "url": "https://api.example.com/revert"},
            headers={}, cookies={}, self_user_id="me", scan_id=1, log_error=log_error,
        )

    assert result["granted"] is False
    assert "roles_listing_fetch_failed" in result["reason"]
    mock_request.assert_not_called()
