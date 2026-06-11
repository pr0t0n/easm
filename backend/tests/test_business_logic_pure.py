"""Unit tests for business logic pure functions (no network, no DB, no Chromium)."""
from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock

from app.services.business_logic_test import (
    BIZ_VALUE_FIELDS,
    _case_variants,
    _collections_from_capture,
    _finding,
    _is_biz_value_field,
    _jwt_self_id,
    _sensitive_storage,
)
from app.services.business_logic_probe import (
    _biz_param_endpoints,
    _fingerprint,
    _looks_like_login,
)
from app.services.business_logic_analyzer import classify_service


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.fakesig"


def _mock_response(status: int, body: bytes) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.content = body
    return r


# ── _is_biz_value_field ───────────────────────────────────────────────────────

def test_biz_value_field_qty_matches() -> None:
    assert _is_biz_value_field("qty") is True


def test_biz_value_field_compound_unitprice_matches() -> None:
    assert _is_biz_value_field("unitPrice") is True


def test_biz_value_field_id_excluded() -> None:
    assert _is_biz_value_field("id") is False


def test_biz_value_field_userid_excluded() -> None:
    assert _is_biz_value_field("userId") is False
    assert _is_biz_value_field("productid") is False


def test_biz_value_field_unrelated_excluded() -> None:
    assert _is_biz_value_field("name") is False
    assert _is_biz_value_field("email") is False


def test_biz_value_field_case_insensitive() -> None:
    assert _is_biz_value_field("PRICE") is True
    assert _is_biz_value_field("Quantity") is True


def test_biz_value_field_all_declared_words_match() -> None:
    for word in BIZ_VALUE_FIELDS:
        assert _is_biz_value_field(word) is True, f"Expected {word!r} to match BIZ_VALUE_FIELDS"


# ── _jwt_self_id ──────────────────────────────────────────────────────────────

def test_jwt_self_id_extracts_id_claim() -> None:
    assert _jwt_self_id(_make_jwt({"id": 42})) == 42


def test_jwt_self_id_extracts_userId_claim() -> None:
    assert _jwt_self_id(_make_jwt({"userId": "user-123"})) == "user-123"


def test_jwt_self_id_extracts_sub_claim() -> None:
    assert _jwt_self_id(_make_jwt({"sub": "user-abc"})) == "user-abc"


def test_jwt_self_id_extracts_juiceshop_data_id() -> None:
    token = _make_jwt({"data": {"id": 7, "email": "test@juice.shop"}})
    assert _jwt_self_id(token) == 7


def test_jwt_self_id_malformed_returns_none() -> None:
    assert _jwt_self_id("notavalidtoken") is None


def test_jwt_self_id_empty_returns_none() -> None:
    assert _jwt_self_id("") is None


def test_jwt_self_id_no_id_claims_returns_none() -> None:
    assert _jwt_self_id(_make_jwt({"email": "x@y.com", "role": "user"})) is None


def test_jwt_self_id_none_value_skipped_falls_to_sub() -> None:
    token = _make_jwt({"id": None, "sub": "real-sub"})
    assert _jwt_self_id(token) == "real-sub"


def test_jwt_self_id_empty_value_skipped_falls_to_userid() -> None:
    token = _make_jwt({"id": "", "userId": "real-id"})
    assert _jwt_self_id(token) == "real-id"


# ── _sensitive_storage ────────────────────────────────────────────────────────

def test_sensitive_storage_detects_jwt_in_localstorage() -> None:
    jwt_val = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MX0.fakesig"
    cap = {"storage": {"localStorage": [["token", jwt_val]]}}
    assert len(_sensitive_storage(cap, "https://target.com")) == 1


def test_sensitive_storage_detects_aws_key() -> None:
    cap = {"storage": {"sessionStorage": [["awsKey", "AKIAIOSFODNN7EXAMPLE"]]}}
    assert len(_sensitive_storage(cap, "https://target.com")) == 1


def test_sensitive_storage_filters_injected_token() -> None:
    injected = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.fakesignaturevalue"
    cap = {"storage": {"localStorage": [["token", injected]]}}
    # My own injected token — must NOT be flagged (circular FP guard)
    assert _sensitive_storage(cap, "https://target.com", injected=injected) == []


def test_sensitive_storage_different_token_still_flagged() -> None:
    injected = "my-injected-token-value-here"
    real_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.fakesignaturevalue"
    cap = {"storage": {"localStorage": [["tok", real_jwt]]}}
    assert len(_sensitive_storage(cap, "https://target.com", injected=injected)) == 1


def test_sensitive_storage_sensitive_key_name_detected() -> None:
    cap = {"storage": {"localStorage": [["auth_token", "short_enough_to_trigger12"]]}}
    assert len(_sensitive_storage(cap, "https://target.com")) == 1


def test_sensitive_storage_short_value_skipped() -> None:
    cap = {"storage": {"localStorage": [["auth_token", "abc"]]}}
    assert _sensitive_storage(cap, "https://target.com") == []


def test_sensitive_storage_both_areas_scanned() -> None:
    jwt_val = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MX0.fakesig"
    cap = {
        "storage": {
            "localStorage": [["a", jwt_val]],
            "sessionStorage": [["b", "AKIAIOSFODNN7EXAMPLE"]],
        }
    }
    assert len(_sensitive_storage(cap, "https://target.com")) == 2


def test_sensitive_storage_finding_is_confirmed() -> None:
    jwt_val = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MX0.fakesig"
    cap = {"storage": {"localStorage": [["tok", jwt_val]]}}
    findings = _sensitive_storage(cap, "https://target.com")
    assert findings[0]["details"]["verification_status"] == "confirmed"


def test_sensitive_storage_empty_returns_nothing() -> None:
    assert _sensitive_storage({}, "https://target.com") == []


# ── _finding ──────────────────────────────────────────────────────────────────

def test_finding_confirmed_scores_9() -> None:
    f = _finding("idor", "confirmada", "high", "/api/orders/2", "diff response")
    assert f["risk_score"] == 9
    assert f["details"]["verification_status"] == "confirmed"


def test_finding_hypothesis_scores_4() -> None:
    f = _finding("idor", "hipotese", "medium", "/api/orders/2", "weak signal")
    assert f["risk_score"] == 4
    assert f["details"]["verification_status"] == "hypothesis"


def test_finding_title_includes_class_and_endpoint() -> None:
    f = _finding("mass_assignment", "confirmada", "critical", "/api/users", "role=admin accepted")
    assert "mass_assignment" in f["title"]
    assert "/api/users" in f["title"]


def test_finding_payload_in_details() -> None:
    f = _finding("bola", "confirmada", "high", "/api/orders/99", "proof", payload={"id": 99})
    assert f["details"]["payload"] == {"id": 99}


# ── _case_variants ────────────────────────────────────────────────────────────

def test_case_variants_no_duplicates() -> None:
    variants = _case_variants("basket")
    assert len(variants) == len(set(variants))


def test_case_variants_includes_lower_upper_capitalized() -> None:
    variants = _case_variants("order")
    assert "order" in variants
    assert "Order" in variants
    assert "ORDER" in variants


def test_case_variants_includes_plural_form() -> None:
    variants = _case_variants("order")
    assert any("orders" in v.lower() for v in variants)


# ── _collections_from_capture ─────────────────────────────────────────────────
# _COLLECTION_RE = r"^/(?:api|rest|v\d)/[A-Za-z][A-Za-z0-9_]+/?$"
# Only matches collection-root paths (no trailing numeric ID).

def test_collections_from_capture_matches_root_path() -> None:
    cap = {"api_requests": [
        {"url": "https://target.com/api/baskets", "method": "GET"},
        {"url": "https://target.com/rest/orders", "method": "GET"},
    ]}
    cols = _collections_from_capture(cap, "https://target.com")
    assert "https://target.com/api/baskets" in cols
    assert "https://target.com/rest/orders" in cols


def test_collections_from_capture_ignores_id_paths() -> None:
    # /api/baskets/1 has a trailing ID — regex doesn't match; this is by design
    cap = {"api_requests": [
        {"url": "https://target.com/api/baskets/1", "method": "GET"},
    ]}
    cols = _collections_from_capture(cap, "https://target.com")
    assert cols == []


def test_collections_from_capture_no_duplicates() -> None:
    cap = {"api_requests": [
        {"url": "https://target.com/api/orders", "method": "GET"},
        {"url": "https://target.com/api/orders", "method": "GET"},
    ]}
    cols = _collections_from_capture(cap, "https://target.com")
    assert len(cols) == 1


def test_collections_from_capture_empty_returns_empty() -> None:
    assert _collections_from_capture({}, "https://target.com") == []


# ── _fingerprint ──────────────────────────────────────────────────────────────

def test_fingerprint_same_body_same_result() -> None:
    assert _fingerprint(_mock_response(200, b"hello")) == _fingerprint(_mock_response(200, b"hello"))


def test_fingerprint_different_body_different_result() -> None:
    assert _fingerprint(_mock_response(200, b"hello")) != _fingerprint(_mock_response(200, b"world"))


def test_fingerprint_different_status_different_result() -> None:
    assert _fingerprint(_mock_response(200, b"body")) != _fingerprint(_mock_response(404, b"body"))


def test_fingerprint_returns_int_and_16char_str() -> None:
    status, digest = _fingerprint(_mock_response(200, b"test"))
    assert isinstance(status, int)
    assert isinstance(digest, str) and len(digest) == 16


def test_fingerprint_spa_catch_all_detection() -> None:
    # If 3 control paths all return identical fingerprint at 200 → catch_all
    fps = [_fingerprint(_mock_response(200, b'{"id":1}')) for _ in range(3)]
    catch_all = all(f == fps[0] for f in fps) and fps[0][0] == 200
    assert catch_all is True


def test_fingerprint_different_bodies_no_catch_all() -> None:
    fps = [
        _fingerprint(_mock_response(200, b"page-a")),
        _fingerprint(_mock_response(200, b"page-b")),
        _fingerprint(_mock_response(200, b"page-c")),
    ]
    catch_all = all(f == fps[0] for f in fps)
    assert catch_all is False


# ── _looks_like_login ─────────────────────────────────────────────────────────

def test_looks_like_login_detects_login_keyword() -> None:
    assert _looks_like_login("<html>Please login to continue</html>") is True


def test_looks_like_login_detects_sign_in() -> None:
    assert _looks_like_login("Sign in to your account") is True


def test_looks_like_login_detects_portuguese_entrar() -> None:
    assert _looks_like_login("Entrar na sua conta") is True


def test_looks_like_login_detects_password_field() -> None:
    assert _looks_like_login('<input type="password">') is True


def test_looks_like_login_api_response_not_login() -> None:
    assert _looks_like_login('{"id":1,"name":"John"}') is False


def test_looks_like_login_only_checks_first_1500_chars() -> None:
    assert _looks_like_login("x" * 1501 + "login") is False


# ── _biz_param_endpoints ──────────────────────────────────────────────────────

def test_biz_param_endpoints_extracts_price_url() -> None:
    urls = ["https://shop.com/checkout?price=100&qty=1"]
    assert _biz_param_endpoints(urls) == urls


def test_biz_param_endpoints_excludes_non_biz_params() -> None:
    urls = ["https://shop.com/page?sort=asc&page=1"]
    assert _biz_param_endpoints(urls) == []


def test_biz_param_endpoints_deduplicates_by_pattern() -> None:
    urls = ["https://shop.com/order?qty=1", "https://shop.com/order?qty=2", "https://shop.com/order?qty=999"]
    assert len(_biz_param_endpoints(urls)) == 1


def test_biz_param_endpoints_keeps_different_params() -> None:
    urls = ["https://shop.com/order?qty=1", "https://shop.com/checkout?price=100"]
    assert len(_biz_param_endpoints(urls)) == 2


def test_biz_param_endpoints_excludes_non_http() -> None:
    urls = ["ftp://shop.com/data?qty=1", "javascript:void(0)?amount=5"]
    assert _biz_param_endpoints(urls) == []


def test_biz_param_endpoints_excludes_no_query_string() -> None:
    assert _biz_param_endpoints(["https://shop.com/checkout"]) == []


def test_biz_param_endpoints_detects_coupon_param() -> None:
    assert len(_biz_param_endpoints(["https://shop.com/apply?coupon=SAVE10"])) == 1


def test_biz_param_endpoints_detects_promo_param() -> None:
    assert len(_biz_param_endpoints(["https://shop.com/cart?promo=SUMMER"])) == 1


# ── classify_service ──────────────────────────────────────────────────────────

def test_classify_service_financial_domain() -> None:
    assert classify_service("payments.bank.com") == "financial_api"


def test_classify_service_docker_portainer() -> None:
    assert classify_service("portainer.internal.com") == "container_management"


def test_classify_service_auth_sso() -> None:
    assert classify_service("sso.company.com") == "auth_service"


def test_classify_service_default_fallback() -> None:
    assert classify_service("random-service.example.com") == "api_gateway"


def test_classify_service_staging_is_development() -> None:
    # "dev-api.company.com" matches api_gateway first (has "api");
    # use a pure staging domain with no other profile keywords
    assert classify_service("staging.company.com") == "development"


def test_classify_service_empty_domain_falls_back() -> None:
    assert classify_service("") == "api_gateway"


def test_classify_service_case_insensitive() -> None:
    assert classify_service("PAYMENT-API.company.com") == "financial_api"


# ── Baseline discipline (rodou != evidência) ──────────────────────────────────

def test_baseline_injected_token_not_flagged() -> None:
    injected = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.fakesignaturevalue"
    cap = {"storage": {"localStorage": [["token", injected]]}}
    assert _sensitive_storage(cap, "https://target.com", injected=injected) == [], \
        "Injected token must not be reported (circular FP guard)"


def test_baseline_confirmed_has_higher_risk_than_hypothesis() -> None:
    confirmed = _finding("bola", "confirmada", "high", "/api/x", "proof")
    hypothesis = _finding("bola", "hipotese", "medium", "/api/x", "weak")
    assert confirmed["risk_score"] > hypothesis["risk_score"]
    assert confirmed["risk_score"] == 9
    assert hypothesis["risk_score"] == 4
