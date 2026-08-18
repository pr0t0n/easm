"""Tests for the multi-owner-listing detector added to validate_auth_matrix
-- completes the "requires_object_level_assertion" gap the validator's own
reason string already named. Reproduces the actual finding shape: a
supposedly caller-scoped "my tickets" listing whose items embed DIFFERENT
organizations' names, visible within a single response, no second identity
needed.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.pentest_validators import (
    _detect_multi_owner_listing,
    _extract_list_items,
    _owner_marker,
    validate_auth_matrix,
)


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_extract_list_items_from_data_envelope() -> None:
    body = json.dumps({"data": [{"id": "1"}, {"id": "2"}]})
    assert _extract_list_items(body) == [{"id": "1"}, {"id": "2"}]


def test_extract_list_items_top_level_array() -> None:
    body = json.dumps([{"id": "1"}, {"id": "2"}])
    assert _extract_list_items(body) == [{"id": "1"}, {"id": "2"}]


def test_extract_list_items_returns_empty_for_unrecognized_shape() -> None:
    assert _extract_list_items(json.dumps({"nope": "shape"})) == []
    assert _extract_list_items("not json") == []


def test_owner_marker_reads_top_level_email() -> None:
    assert _owner_marker({"email": "a@valid.com"}) == "a@valid.com"


def test_owner_marker_reads_nested_organization_name() -> None:
    assert _owner_marker({"organization": {"name": "Valid CS"}}) == "Valid CS"


def test_owner_marker_returns_empty_when_nothing_owner_shaped() -> None:
    assert _owner_marker({"ticketId": "PLAT-0001", "reason": "x"}) == ""


def test_detect_multi_owner_listing_confirms_on_real_finding_shape() -> None:
    """Reproduces the human report's evidence: a support-tickets listing
    returning items from two different organizations in one response."""
    body = json.dumps({
        "data": [
            {"ticketId": "PLAT-0001", "organization": {"name": "Valid CS"}},
            {"ticketId": "PLAT-0002", "organization": {"name": "Voidr"}},
        ]
    })
    evidence = _detect_multi_owner_listing({"body_preview": body})
    assert evidence is not None
    assert evidence["item_count"] == 2
    assert set(evidence["distinct_owners_observed"]) == {"Valid CS", "Voidr"}


def test_detect_multi_owner_listing_none_when_single_owner() -> None:
    body = json.dumps({"data": [
        {"ticketId": "PLAT-0001", "organization": {"name": "Valid CS"}},
        {"ticketId": "PLAT-0002", "organization": {"name": "Valid CS"}},
    ]})
    assert _detect_multi_owner_listing({"body_preview": body}) is None


def test_detect_multi_owner_listing_none_for_single_item() -> None:
    body = json.dumps({"data": [{"ticketId": "PLAT-0001", "organization": {"name": "Valid CS"}}]})
    assert _detect_multi_owner_listing({"body_preview": body}) is None


# ── validate_auth_matrix integration ────────────────────────────────────────

def _fake_session_rows():
    identity_a = SimpleNamespace(identity_key="member_org_a", role="member")
    session_a = SimpleNamespace(headers={"Authorization": "Bearer a"}, cookies={})
    identity_b = SimpleNamespace(identity_key="member_org_b", role="member")
    session_b = SimpleNamespace(headers={"Authorization": "Bearer b"}, cookies={})
    return [(identity_a, session_a), (identity_b, session_b)]


def test_validate_auth_matrix_confirms_multi_owner_leak() -> None:
    endpoint = SimpleNamespace(
        id=1, url="https://api.example.com/support/tickets",
        normalized_url="https://api.example.com/support/tickets", method="GET",
    )
    leaking_body = json.dumps({"data": [
        {"ticketId": "PLAT-0001", "organization": {"name": "Valid CS"}},
        {"ticketId": "PLAT-0002", "organization": {"name": "Voidr"}},
    ]})
    observation = {"ok": True, "status_code": 200, "body_preview": leaking_body, "body_len": 200, "json_keys": ["data"]}

    fake_artifact = SimpleNamespace(id=1)
    with (
        patch("app.services.pentest_validators._endpoint_for_hypothesis", return_value=endpoint),
        patch("app.services.pentest_validators._sessions", return_value=_fake_session_rows()),
        patch("app.services.pentest_validators._safe_request", return_value=observation),
        patch("app.services.pentest_validators.create_request_response_artifact", return_value=fake_artifact) as mock_artifact,
        patch("app.services.pentest_validators.OffensiveInventoryService") as mock_inv_cls,
    ):
        mock_inv = MagicMock()
        mock_inv_cls.return_value = mock_inv
        result = validate_auth_matrix(MagicMock(), MagicMock(), SimpleNamespace(id=1))

    assert result["result"] == "confirmed"
    assert result["reason"] == "listing_response_spans_multiple_owners"
    assert mock_artifact.call_args.kwargs["metadata"]["multi_owner_evidence"] is not None
    assert mock_artifact.call_args.kwargs["confidence_score"] == 88


def test_validate_auth_matrix_unaffected_when_listing_single_owner() -> None:
    endpoint = SimpleNamespace(
        id=1, url="https://api.example.com/support/tickets",
        normalized_url="https://api.example.com/support/tickets", method="GET",
    )
    scoped_body = json.dumps({"data": [
        {"ticketId": "PLAT-0001", "organization": {"name": "Valid CS"}},
        {"ticketId": "PLAT-0002", "organization": {"name": "Valid CS"}},
    ]})
    observation = {"ok": True, "status_code": 200, "body_preview": scoped_body, "body_len": 200, "json_keys": ["data"]}

    fake_artifact = SimpleNamespace(id=1)
    with (
        patch("app.services.pentest_validators._endpoint_for_hypothesis", return_value=endpoint),
        patch("app.services.pentest_validators._sessions", return_value=_fake_session_rows()),
        patch("app.services.pentest_validators._safe_request", return_value=observation),
        patch("app.services.pentest_validators.create_request_response_artifact", return_value=fake_artifact) as mock_artifact,
        patch("app.services.pentest_validators.OffensiveInventoryService") as mock_inv_cls,
    ):
        mock_inv_cls.return_value = MagicMock()
        result = validate_auth_matrix(MagicMock(), MagicMock(), SimpleNamespace(id=1))

    assert result["result"] == "candidate"
    assert result["reason"] == "same_response_across_roles_requires_object_level_assertion"
    assert mock_artifact.call_args.kwargs["metadata"]["multi_owner_evidence"] is None
