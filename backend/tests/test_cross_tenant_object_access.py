"""Tests for the cross-tenant path-parameter substitution capability.

Covers the actual bug shape a human white-box pentest found and the
platform's existing validators missed: a caller's own session accepts a
DIFFERENT, already-observed tenant/org id in a path segment
(".../organizations/{id}/...") -- distinct from validate_idor_bola, which
only ever replays the exact same known-object URL under a second identity.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.endpoint_analysis_pipeline import (
    _tenant_scoped_distinct_values,
    analyze_endpoint_contract,
)
from app.services.pentest_validators import (
    _looks_like_cross_tenant_access,
    _negative_control_value,
    _swap_path_segment,
    validate_cross_tenant_object_access,
)


# ── _tenant_scoped_distinct_values (pure) ───────────────────────────────────

def test_tenant_scoped_distinct_values_finds_two_org_ids() -> None:
    marker, values = _tenant_scoped_distinct_values(
        "/api/host/organizations/019b37cc-42bd-725f-ae2b-6e35f725681a/members",
        [
            "https://api.example.com/api/host/organizations/019b37cc-42bd-725f-ae2b-6e35f725681a/members",
            "https://api.example.com/api/host/organizations/0198f7a1-8a04-72c1-9df2-1e2c9a4b6f10/members",
        ],
    )
    assert marker == "organizations"
    assert len(values) == 2


def test_tenant_scoped_distinct_values_single_value_insufficient() -> None:
    marker, values = _tenant_scoped_distinct_values(
        "/api/host/organizations/019b37cc-42bd-725f-ae2b-6e35f725681a/members",
        ["https://api.example.com/api/host/organizations/019b37cc-42bd-725f-ae2b-6e35f725681a/members"],
    )
    assert marker == "organizations"
    assert len(values) == 1


def test_tenant_scoped_distinct_values_no_marker_for_unrelated_resource() -> None:
    marker, values = _tenant_scoped_distinct_values(
        "/api/products/12345",
        ["https://api.example.com/api/products/12345", "https://api.example.com/api/products/67890"],
    )
    assert marker == ""
    assert values == []


# ── analyze_endpoint_contract wiring ─────────────────────────────────────────

def test_analyze_endpoint_contract_emits_cross_tenant_test_with_two_org_ids() -> None:
    analysis = analyze_endpoint_contract(
        "https://api.example.com/api/host/organizations/019b37cc-42bd-725f-ae2b-6e35f725681a/members",
        method="GET",
        auth_required=True,
        sample_urls=[
            "https://api.example.com/api/host/organizations/019b37cc-42bd-725f-ae2b-6e35f725681a/members",
            "https://api.example.com/api/host/organizations/0198f7a1-8a04-72c1-9df2-1e2c9a4b6f10/members",
        ],
    )
    types_seen = {test["hypothesis_type"] for test in analysis["test_matrix"]}
    assert "cross_tenant_object_access" in types_seen


def test_analyze_endpoint_contract_skips_cross_tenant_test_with_one_org_id() -> None:
    analysis = analyze_endpoint_contract(
        "https://api.example.com/api/host/organizations/019b37cc-42bd-725f-ae2b-6e35f725681a/members",
        method="GET",
        auth_required=True,
        sample_urls=["https://api.example.com/api/host/organizations/019b37cc-42bd-725f-ae2b-6e35f725681a/members"],
    )
    types_seen = {test["hypothesis_type"] for test in analysis["test_matrix"]}
    assert "cross_tenant_object_access" not in types_seen


def test_analyze_endpoint_contract_skips_cross_tenant_test_when_auth_not_observed() -> None:
    analysis = analyze_endpoint_contract(
        "https://api.example.com/api/host/organizations/019b37cc-42bd-725f-ae2b-6e35f725681a/members",
        method="GET",
        auth_required=None,
        sample_urls=[
            "https://api.example.com/api/host/organizations/019b37cc-42bd-725f-ae2b-6e35f725681a/members",
            "https://api.example.com/api/host/organizations/0198f7a1-8a04-72c1-9df2-1e2c9a4b6f10/members",
        ],
    )
    types_seen = {test["hypothesis_type"] for test in analysis["test_matrix"]}
    assert "cross_tenant_object_access" not in types_seen


# ── pure helpers in pentest_validators ──────────────────────────────────────

def test_negative_control_value_matches_uuid_shape() -> None:
    assert _negative_control_value("019b37cc-42bd-725f-ae2b-6e35f725681a") == "00000000-0000-0000-0000-000000000000"


def test_negative_control_value_matches_numeric_shape() -> None:
    assert _negative_control_value("42") == "999999999"


def test_swap_path_segment_replaces_correct_position() -> None:
    url = "https://api.example.com/api/host/organizations/AAA/members"
    swapped = _swap_path_segment(url, 3, "BBB")
    assert swapped == "https://api.example.com/api/host/organizations/BBB/members"


def test_looks_like_cross_tenant_access_confirms_on_substantive_different_body() -> None:
    baseline = {"ok": True, "status_code": 200, "body_preview": '{"id":"A","name":"Org A"}', "body_len": 200, "json_keys": ["id", "name"]}
    attempt = {"ok": True, "status_code": 200, "body_preview": '{"id":"B","name":"Org B"}', "body_len": 200, "json_keys": ["id", "name"]}
    negative = {"ok": True, "status_code": 404, "body_preview": "", "body_len": 0, "json_keys": []}
    assert _looks_like_cross_tenant_access(baseline, attempt, negative) is True


def test_looks_like_cross_tenant_access_rejects_when_negative_also_succeeds() -> None:
    """Endpoint returns 200 for literally any id -- not authorization-specific."""
    baseline = {"ok": True, "status_code": 200, "body_preview": '{"id":"A"}', "body_len": 200, "json_keys": ["id"]}
    attempt = {"ok": True, "status_code": 200, "body_preview": '{"id":"B"}', "body_len": 200, "json_keys": ["id"]}
    negative = {"ok": True, "status_code": 200, "body_preview": '{"id":"nonexistent"}', "body_len": 200, "json_keys": ["id"]}
    assert _looks_like_cross_tenant_access(baseline, attempt, negative) is False


def test_looks_like_cross_tenant_access_rejects_identical_body() -> None:
    baseline = {"ok": True, "status_code": 200, "body_preview": '{"id":"A"}', "body_len": 200, "json_keys": ["id"]}
    attempt = {"ok": True, "status_code": 200, "body_preview": '{"id":"A"}', "body_len": 200, "json_keys": ["id"]}
    negative = {"ok": False, "status_code": 404, "body_preview": "", "body_len": 0, "json_keys": []}
    assert _looks_like_cross_tenant_access(baseline, attempt, negative) is False


# ── validate_cross_tenant_object_access orchestration ───────────────────────

_ORG_A = "019b37cc-42bd-725f-ae2b-6e35f725681a"
_ORG_B = "0198f7a1-8a04-72c1-9df2-1e2c9a4b6f10"


def _fake_endpoint():
    return SimpleNamespace(
        id=1,
        url=f"https://api.example.com/api/host/organizations/{_ORG_A}/members",
        normalized_url="https://api.example.com/api/host/organizations/{id}/members",
        method="GET",
        auth_required=True,
        endpoint_metadata={
            "sample_urls": [
                f"https://api.example.com/api/host/organizations/{_ORG_A}/members",
                f"https://api.example.com/api/host/organizations/{_ORG_B}/members",
            ]
        },
    )


def test_validate_cross_tenant_object_access_confirms_candidate() -> None:
    identity = SimpleNamespace(identity_key="admin_org_a", role="admin")
    session = SimpleNamespace(headers={"Authorization": "Bearer x"}, cookies={})

    responses = {
        f"https://api.example.com/api/host/organizations/{_ORG_A}/members": {"ok": True, "status_code": 200, "body_preview": '{"id":"A","members":["a"]}', "body_len": 200, "json_keys": ["id", "members"]},
        f"https://api.example.com/api/host/organizations/{_ORG_B}/members": {"ok": True, "status_code": 200, "body_preview": '{"id":"B","members":["b"]}', "body_len": 200, "json_keys": ["id", "members"]},
        "https://api.example.com/api/host/organizations/00000000-0000-0000-0000-000000000000/members": {"ok": True, "status_code": 404, "body_preview": "", "body_len": 0, "json_keys": []},
    }

    def _fake_safe_request(url, headers, cookies, **kwargs):
        return responses.get(url, {"ok": False, "status_code": 0, "body_preview": "", "body_len": 0, "json_keys": []})

    fake_artifact = SimpleNamespace(id=99)

    with (
        patch("app.services.pentest_validators._endpoint_for_hypothesis", return_value=_fake_endpoint()),
        patch("app.services.pentest_validators._sessions", return_value=[(identity, session)]),
        patch("app.services.pentest_validators._safe_request", side_effect=_fake_safe_request),
        patch("app.services.pentest_validators.create_request_response_artifact", return_value=fake_artifact) as mock_artifact,
        patch("app.services.pentest_validators.OffensiveInventoryService") as mock_inv_cls,
    ):
        mock_inv = MagicMock()
        mock_inv_cls.return_value = mock_inv
        result = validate_cross_tenant_object_access(MagicMock(), MagicMock(), SimpleNamespace(id=7))

    assert result["result"] == "candidate"
    mock_inv.record_validation.assert_called_once()
    call_kwargs = mock_artifact.call_args.kwargs
    assert call_kwargs["metadata"]["foreign_value"] in {_ORG_A, _ORG_B}
    assert call_kwargs["metadata"]["attribution_uncertain"] is True


def test_validate_cross_tenant_object_access_skips_without_second_value() -> None:
    endpoint = _fake_endpoint()
    endpoint.endpoint_metadata = {"sample_urls": [endpoint.url]}
    identity = SimpleNamespace(identity_key="admin_org_a", role="admin")
    session = SimpleNamespace(headers={}, cookies={})

    with (
        patch("app.services.pentest_validators._endpoint_for_hypothesis", return_value=endpoint),
        patch("app.services.pentest_validators._sessions", return_value=[(identity, session)]),
        patch("app.services.pentest_validators._record_skipped", return_value={"result": "skipped"}) as mock_skip,
    ):
        result = validate_cross_tenant_object_access(MagicMock(), MagicMock(), SimpleNamespace(id=7))

    assert result == {"result": "skipped"}
    mock_skip.assert_called_once()
    assert mock_skip.call_args.args[-1] == "insufficient_distinct_tenant_values_observed"
