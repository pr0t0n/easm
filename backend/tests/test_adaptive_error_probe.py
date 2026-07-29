from app.services.adaptive_error_probe import (
    SSRF_PARAM_HINTS,
    _candidate_header_sets,
    _candidate_header_value,
    _header_hints_from_body,
    classify_ssrf_candidate_fields,
)
from app.services.evidence_gate import get_verification_status

# Real captured 401 body from a live black-box test (BRZT-2025-380-150),
# used here purely as a fixture for the parsing logic -- the function under
# test has no knowledge of this specific target; it only recognizes header
# TOKEN FORMAT (x-*, Authorization, Bearer, Origin, Cookie, api-key).
REAL_401_BODY = (
    '{"code":"UNAUTHORIZED","message":"Provide x-api-key, or Authorization '
    'Bearer with x-organization-id/x-project-id, or x-organization-id/'
    'x-project-id with Origin"}'
)

REAL_422_BODY = (
    '{"code":"VALIDATION_ERROR","message":"Input validation failed",'
    '"details":[{"field":"url","message":"url is required and must be a string"},'
    '{"field":"contentType","message":"contentType is required and must be a string"},'
    '{"field":"content","message":"content is required"}]}'
)


def test_header_hints_extracted_from_verbose_error_body() -> None:
    hints = _header_hints_from_body(REAL_401_BODY)
    assert set(h.lower() for h in hints) == {
        "x-api-key", "authorization", "bearer", "x-organization-id", "x-project-id", "origin",
    }


def test_header_hints_empty_for_generic_error() -> None:
    assert _header_hints_from_body('{"code":"UNAUTHORIZED","message":"Access denied"}') == []


def test_origin_candidate_value_derives_apex_domain_generically() -> None:
    mapped = _candidate_header_value("Origin", "api-messaging.services-valid.com.br")
    assert mapped == ("Origin", "https://services-valid.com.br")


def test_bearer_token_alone_is_not_double_mapped() -> None:
    # "Bearer" is covered by the "Authorization" mapping; mapping it again
    # standalone would send a bogus "Bearer: <value>" header.
    assert _candidate_header_value("Bearer", "target.com") is None


def test_generic_x_header_gets_placeholder_value() -> None:
    mapped = _candidate_header_value("x-organization-id", "target.com")
    assert mapped is not None
    name, value = mapped
    assert name == "x-organization-id"
    assert value  # any non-empty placeholder is fine, per the real target's own behavior


def test_candidate_header_sets_splits_or_alternatives_before_combining_everything() -> None:
    sets = _candidate_header_sets(REAL_401_BODY, "api-messaging.services-valid.com.br")
    # The 3rd "or"-alternative (x-organization-id/x-project-id with Origin) must
    # appear as an isolated group, not diluted by x-api-key/Authorization from
    # the other alternatives (sending those together causes a real API to
    # reject on the wrong credential type before considering this one).
    assert {"x-organization-id": "1", "x-project-id": "1", "Origin": "https://services-valid.com.br"} in sets
    # the "everything combined" fallback must still exist, just not first
    combined = {"x-api-key": "1", "Authorization": "Bearer 1", "x-organization-id": "1",
                "x-project-id": "1", "Origin": "https://services-valid.com.br"}
    assert combined in sets
    assert sets.index(combined) > 0


def test_field_hints_from_validation_error_classified_for_ssrf() -> None:
    import json
    parsed = json.loads(REAL_422_BODY)
    field_names = [d["field"] for d in parsed["details"]]
    assert field_names == ["url", "contentType", "content"]
    assert classify_ssrf_candidate_fields(field_names) == ["url"]


def test_ssrf_classification_matches_by_substring_not_exact_name() -> None:
    # A real-world field is rarely named exactly "url" -- confirm the generic
    # dictionary catches common compound names too (webhookUrl, callbackUri,
    # targetEndpoint), not just an exact match.
    assert classify_ssrf_candidate_fields(["webhookUrl", "userId", "amount"]) == ["webhookUrl"]
    assert classify_ssrf_candidate_fields(["callbackUri"]) == ["callbackUri"]
    assert classify_ssrf_candidate_fields(["targetEndpoint"]) == ["targetEndpoint"]
    assert classify_ssrf_candidate_fields(["firstName", "lastName"]) == []


def test_ssrf_param_hints_dictionary_is_generic_not_report_specific() -> None:
    # Sanity check the dictionary is a real, broad, industry-standard list --
    # not a single-entry stand-in for "url" copied from one report.
    assert len(SSRF_PARAM_HINTS) >= 15
    assert "url" in SSRF_PARAM_HINTS and "webhook" in SSRF_PARAM_HINTS and "redirect" in SSRF_PARAM_HINTS


# ── evidence_gate wiring: adaptive_probe's two finding types, two certainty levels ──

def test_adaptive_probe_auth_bypass_finding_is_always_confirmed() -> None:
    status = get_verification_status("adaptive_probe", {"details": {"vuln_family": "auth_bypass"}})
    assert status == "confirmed"


def test_adaptive_probe_ssrf_finding_trusts_its_own_precomputed_status() -> None:
    confirmed = get_verification_status(
        "adaptive_probe", {"details": {"vuln_family": "ssrf", "verification_status": "confirmed"}}
    )
    assert confirmed == "confirmed"
    candidate = get_verification_status(
        "adaptive_probe", {"details": {"vuln_family": "ssrf", "verification_status": "candidate"}}
    )
    assert candidate == "candidate"


def test_adaptive_probe_ssrf_finding_defaults_to_candidate_without_a_precomputed_status() -> None:
    status = get_verification_status("adaptive_probe", {"details": {"vuln_family": "ssrf"}})
    assert status == "candidate"
