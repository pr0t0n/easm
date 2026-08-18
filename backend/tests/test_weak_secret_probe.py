"""Tests for the bounded weak-secret dictionary probe against a forgeable
custom auth-adjacent header (the X-Impersonate class of bug).
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.services.weak_secret_probe import (
    candidate_secrets,
    decode_jwt_unverified,
    escalate_payload_claims,
    find_forgeable_header,
    probe_weak_secret,
    sign_hs256,
)


def test_candidate_secrets_is_short_and_includes_hostname_derived_guesses() -> None:
    candidates = candidate_secrets("platform-id-impersonate.example.com")
    assert len(candidates) < 20
    assert "platform-id-impersonate-secret" in candidates
    assert "secret" in candidates


def test_candidate_secrets_dedupes() -> None:
    candidates = candidate_secrets("secret")  # hostname label collides with a common default
    assert candidates.count("secret") == 1


def test_sign_and_decode_roundtrip() -> None:
    token = sign_hs256({"typ": "JWT"}, {"sub": "u1", "roles": ["member"]}, "my-secret")
    decoded = decode_jwt_unverified(token)
    assert decoded is not None
    header, payload = decoded
    assert payload == {"sub": "u1", "roles": ["member"]}


def test_decode_jwt_unverified_rejects_non_jwt_shape() -> None:
    assert decode_jwt_unverified("not-a-jwt") is None
    assert decode_jwt_unverified("a.b") is None
    assert decode_jwt_unverified("") is None


def test_escalate_payload_claims_only_touches_existing_privilege_keys() -> None:
    payload = {"sub": "u1", "roles": ["member"]}
    escalated = escalate_payload_claims(payload, "admin")
    assert escalated["roles"] == ["admin"]
    assert escalated["sub"] == "u1"  # untouched -- not a privilege-shaped key


def test_escalate_payload_claims_returns_same_object_when_nothing_to_escalate() -> None:
    payload = {"sub": "u1", "email": "a@b.com"}
    result = escalate_payload_claims(payload, "admin")
    assert result is payload  # identity check -- caller detects "nothing to escalate" this way


def test_find_forgeable_header_ignores_standard_authorization() -> None:
    token = sign_hs256({}, {"sub": "u1"}, "s")
    headers = {"Authorization": f"Bearer {token}", "X-Impersonate": token}
    found = find_forgeable_header(headers)
    assert found == ("X-Impersonate", token)


def test_find_forgeable_header_returns_none_when_no_jwt_shaped_custom_header() -> None:
    headers = {"Authorization": "Bearer sometoken", "X-Request-Id": "abc-123"}
    assert find_forgeable_header(headers) is None


# ── probe_weak_secret orchestration ─────────────────────────────────────────

def _mock_resp(status_code=200, text="baseline"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 300
    resp.text = text
    return resp


def test_probe_weak_secret_confirms_on_correct_secret() -> None:
    real_token = sign_hs256({"typ": "JWT"}, {"sub": "u1", "roles": ["member"]}, "app-secret")

    def fake_get(url, headers=None, **kwargs):
        forged_header = (headers or {}).get("X-Impersonate", "")
        decoded = decode_jwt_unverified(forged_header) if forged_header else None
        if decoded and decoded[1].get("roles") == ["admin"]:
            # only the correctly-signed forged token gets treated as valid
            try:
                sign_hs256(decoded[0], decoded[1], "app-secret")
            except Exception:
                pass
            # simulate server verifying signature: only accept if it matches app-secret's signature
            expected = sign_hs256({"typ": "JWT", "alg": "HS256"}, {"sub": "u1", "roles": ["admin"]}, "app-secret")
            if forged_header == expected:
                return _mock_resp(200, "elevated-response")
        return _mock_resp(200, "baseline")

    with patch("app.services.weak_secret_probe.requests.get", side_effect=fake_get):
        result = probe_weak_secret(
            header_name="X-Impersonate",
            header_value=real_token,
            app_hostname="app.example.com",
            whoami_url="https://app.example.com/whoami",
            other_headers={"Authorization": "Bearer x"},
            cookies={},
            elevated_privilege_value="admin",
        )

    assert result["attempted"] is True
    assert result["confirmed"] is True
    assert result["secret_found"] == "app-secret"


def test_probe_weak_secret_no_match_reports_unconfirmed() -> None:
    real_token = sign_hs256({"typ": "JWT"}, {"sub": "u1", "roles": ["member"]}, "genuinely-random-secret-nobody-guesses")

    with patch("app.services.weak_secret_probe.requests.get", return_value=_mock_resp(200, "same-response-always")):
        result = probe_weak_secret(
            header_name="X-Impersonate",
            header_value=real_token,
            app_hostname="app.example.com",
            whoami_url="https://app.example.com/whoami",
            other_headers={},
            cookies={},
            elevated_privilege_value="admin",
        )

    assert result["attempted"] is True
    assert result["confirmed"] is False
    assert len(result["attempts"]) == len(candidate_secrets("app.example.com"))


def test_probe_weak_secret_skips_when_no_privilege_claim() -> None:
    token = sign_hs256({}, {"sub": "u1", "email": "a@b.com"}, "whatever")
    result = probe_weak_secret(
        header_name="X-Impersonate", header_value=token, app_hostname="app.example.com",
        whoami_url="https://app.example.com/whoami", other_headers={}, cookies={},
        elevated_privilege_value="admin",
    )
    assert result["attempted"] is False
    assert result["reason"] == "no_privilege_claim_in_observed_token"


def test_probe_weak_secret_skips_when_header_not_jwt_shaped() -> None:
    result = probe_weak_secret(
        header_name="X-Impersonate", header_value="not-a-jwt", app_hostname="app.example.com",
        whoami_url="https://app.example.com/whoami", other_headers={}, cookies={},
        elevated_privilege_value="admin",
    )
    assert result["attempted"] is False
    assert result["reason"] == "header_not_jwt_shaped"
