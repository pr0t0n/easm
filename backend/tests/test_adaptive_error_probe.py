from app.services.adaptive_error_probe import (
    SSRF_PARAM_HINTS,
    _candidate_header_sets,
    _candidate_header_value,
    _header_hints_from_body,
    _matching_oob_callbacks,
    _persist_adaptive_inventory,
    classify_ssrf_candidate_fields,
    probe_auth_bypass,
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

def test_adaptive_probe_auth_boundary_transition_stays_candidate_without_proof_pack() -> None:
    status = get_verification_status("adaptive_probe", {"details": {"vuln_family": "auth_bypass"}})
    assert status == "candidate"


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


# ── candidate endpoint gathering: content-discovery tools feed the probe ─────

def test_candidate_endpoints_reads_from_all_content_discovery_tools() -> None:
    # Reproduced live: dirsearch-api(-post)'s discoveries never reached
    # adaptive_error_probe because this filter's tool allowlist only listed
    # gobuster/dirsearch/feroxbuster/ffuf -- a real endpoint found only by
    # the dedicated REST-convention tools was invisible to the auth-bypass/
    # SSRF probe regardless of what it discovered.
    from unittest.mock import MagicMock

    from app.services.adaptive_error_probe import _candidate_endpoints
    from app.models.models import Finding

    captured: dict[str, tuple] = {}

    def fake_filter(*args, **kwargs):
        captured["args"] = args
        chain = MagicMock()
        chain.order_by.return_value.limit.return_value.all.return_value = []
        return chain

    db = MagicMock()
    db.query.return_value.filter.side_effect = fake_filter
    job = MagicMock(id=1, target_query="api-messaging.services-valid.com.br")

    _candidate_endpoints(db, job, "api-messaging.services-valid.com.br")

    rendered = []
    for arg in captured["args"]:
        try:
            rendered.append(str(arg.compile(compile_kwargs={"literal_binds": True})))
        except Exception:
            rendered.append(str(arg))
    blob = " ".join(rendered)
    for tool in ("gobuster", "dirsearch", "feroxbuster", "ffuf", "dirsearch-api", "dirsearch-api-post"):
        assert tool in blob, f"{tool} missing from _candidate_endpoints tool filter: {blob}"


def test_auth_transition_requires_negative_control_and_stable_repetition() -> None:
    from types import SimpleNamespace

    class Client:
        def request(self, method, url, json=None, headers=None):
            if not headers or headers.get("X-EASM-Negative-Control"):
                return SimpleNamespace(status_code=401, text=REAL_401_BODY)
            return SimpleNamespace(status_code=422, text=REAL_422_BODY)

    result = probe_auth_bypass("https://api.example.test/webhook", client=Client())

    assert result["bypass_detected"] is True
    assert result["stable_transition"] is True
    assert result["negative_control_status"] == 401
    assert result["new_status"] == result["confirmation_status"] == 422


def test_auth_transition_is_rejected_when_negative_control_also_crosses_boundary() -> None:
    from types import SimpleNamespace

    class Client:
        def request(self, method, url, json=None, headers=None):
            if not headers:
                return SimpleNamespace(status_code=401, text=REAL_401_BODY)
            return SimpleNamespace(status_code=422, text=REAL_422_BODY)

    result = probe_auth_bypass("https://api.example.test/webhook", client=Client())

    assert result["bypass_detected"] is False
    assert result["negative_control_status"] == 422


def test_oob_confirmation_requires_callback_for_exact_collector() -> None:
    collector = "http://f7-ssrf-abc123.correlation.oast.fun"
    callbacks = [
        {"unique_id": "f7-ssrf-other"},
        {"unique_id": "dns.f7-ssrf-abc123.correlation"},
    ]

    assert _matching_oob_callbacks(collector, callbacks) == [callbacks[1]]


def test_candidate_endpoints_rejects_batch_and_405_routes() -> None:
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from app.services.adaptive_error_probe import _candidate_endpoints

    db = MagicMock()
    row = SimpleNamespace(details={"discovered_paths": [
        {"path": "/catch-all", "status": "405"},
        {"path": "/protected", "status": "401"},
    ]})
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [row]
    job = SimpleNamespace(id=1, target_query="api.example.test")

    assert _candidate_endpoints(db, job, "__batch__:1") == []
    assert _candidate_endpoints(db, job, "api.example.test") == [
        "https://api.example.test",
        "https://api.example.test/protected",
    ]


def test_adaptive_fields_are_persisted_as_post_body_parameters(monkeypatch) -> None:
    from types import SimpleNamespace

    calls = []
    endpoint = SimpleNamespace(id=9, endpoint_metadata={"analysis": {"version": "old"}})

    class Inventory:
        def __init__(self, db, job):
            pass

        def upsert_endpoint(self, url, **kwargs):
            calls.append(("endpoint", url, kwargs))
            return endpoint

        def upsert_parameter(self, ep, name, **kwargs):
            calls.append(("parameter", name, kwargs))

    class Db:
        def add(self, row):
            pass

        def flush(self):
            pass

    monkeypatch.setattr("app.services.offensive_inventory_service.OffensiveInventoryService", Inventory)

    count = _persist_adaptive_inventory(
        Db(),
        SimpleNamespace(id=1),
        url="https://api.example.test/webhook",
        bypass={
            "baseline_status": 401,
            "negative_control_status": 401,
            "new_status": 422,
            "confirmation_status": 422,
            "stable_transition": True,
            "headers_used": {"x-tenant": "1"},
        },
        field_names=["url", "contentType", "content", "url"],
    )

    assert count == 1
    assert calls[0][2]["method"] == "POST"
    assert calls[0][2]["auth_required"] is True
    assert [call[1] for call in calls if call[0] == "parameter"] == ["url", "contentType", "content"]
    assert all(call[2]["location"] == "body" for call in calls if call[0] == "parameter")
    assert "analysis" not in endpoint.endpoint_metadata
