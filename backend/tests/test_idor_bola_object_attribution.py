"""Marco 4 / P13: validate_idor_bola and bl-test's compare_two_identities used
to both test a single shared OffensiveEndpoint.url -- unconditionally
overwritten on every upsert, so it could belong to any identity/crawl that
ever hit the route, not necessarily the identity the test claims to be
checking. ObservedRequest (browser_request_harvester.py) records the real
per-identity object; these tests cover the new code that prefers it and
marks the result honestly (observed_per_identity vs
unverified_shared_endpoint) when it isn't available.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import app.services.business_logic_test as business_logic_test
from app.services.pentest_validators import (
    _observed_object_for_identity,
    _safe_request,
    validate_idor_bola,
)
from app.services.worker_dispatcher import _attach_observed_endpoints_per_identity


# ── _safe_request body passthrough ──────────────────────────────────────────

def test_safe_request_sends_json_body_for_non_get():
    fake_resp = SimpleNamespace(status_code=200, headers={"content-type": "application/json"}, content=b"{}", text="{}", url="https://x/1")
    with patch("app.services.pentest_validators.requests.request", return_value=fake_resp) as mock_request:
        _safe_request("https://x/1", {}, {}, method="PUT", json_body={"basketId": 5})

    assert mock_request.call_args.args[0] == "PUT"
    assert mock_request.call_args.kwargs["json"] == {"basketId": 5}


def test_safe_request_sends_data_body_for_non_get():
    fake_resp = SimpleNamespace(status_code=200, headers={}, content=b"", text="", url="https://x/1")
    with patch("app.services.pentest_validators.requests.request", return_value=fake_resp) as mock_request:
        _safe_request("https://x/1", {}, {}, method="POST", data_body="a=1&b=2")

    assert mock_request.call_args.kwargs["data"] == "a=1&b=2"


def test_safe_request_get_still_uses_requests_get():
    """GET always goes through requests.get specifically (not
    requests.request("GET", ...)) -- existing tooling monkeypatches
    pentest_validators.requests.get directly, so swapping that call would
    silently bypass it."""
    fake_resp = SimpleNamespace(status_code=200, headers={}, content=b"", text="", url="https://x/1")
    with (
        patch("app.services.pentest_validators.requests.get", return_value=fake_resp) as mock_get,
        patch("app.services.pentest_validators.requests.request") as mock_request,
    ):
        _safe_request("https://x/1", {}, {}, method="GET")

    mock_get.assert_called_once()
    mock_request.assert_not_called()


# ── _observed_object_for_identity ───────────────────────────────────────────

class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *a, **k):
        return self

    def order_by(self, *a, **k):
        return self

    def first(self):
        return self._rows[0] if self._rows else None


class _FakeDb:
    def __init__(self, rows):
        self._rows = rows

    def query(self, model):
        return _FakeQuery(self._rows)


def _fake_endpoint(url="https://x/api/baskets/1", normalized="https://x/api/baskets/{id}"):
    return SimpleNamespace(id=1, url=url, normalized_url=normalized, method="GET", auth_required=True)


def test_observed_object_for_identity_returns_row_when_present():
    row = SimpleNamespace(url="https://x/api/baskets/1", method="GET", is_mutating=False)
    db = _FakeDb([row])

    result = _observed_object_for_identity(db, 1, _fake_endpoint(), "user_a")

    assert result is row


def test_observed_object_for_identity_returns_none_when_absent():
    db = _FakeDb([])

    result = _observed_object_for_identity(db, 1, _fake_endpoint(), "user_a")

    assert result is None


def test_observed_object_for_identity_returns_none_for_blank_identity_key():
    db = _FakeDb([SimpleNamespace(url="https://x/api/baskets/1")])

    result = _observed_object_for_identity(db, 1, _fake_endpoint(), "")

    assert result is None


# ── validate_idor_bola: observed-per-identity path ──────────────────────────

def _identity_session_pair(key, role):
    identity = SimpleNamespace(id=1, identity_key=key, role=role)
    session = SimpleNamespace(headers={"Authorization": f"Bearer {key}"}, cookies={})
    return identity, session


def _idor_response_router(hit_url):
    """baseline/attempt both hit the real object (same non-trivial body);
    the negative control (object id swapped to 999999999) 404s -- the shape
    _looks_like_bola requires to confirm."""
    def _route(url, *a, **k):
        if url == hit_url:
            return {"ok": True, "status_code": 200, "body_preview": "x" * 50, "body_len": 200, "json_keys": ["id"]}
        return {"ok": True, "status_code": 404, "body_preview": "", "body_len": 0, "json_keys": []}
    return _route


def test_validate_idor_bola_uses_real_observed_object_when_available():
    endpoint = _fake_endpoint()
    user_a = _identity_session_pair("user_a", "user")
    user_b = _identity_session_pair("user_b", "user")
    observed_a = SimpleNamespace(
        url="https://x/api/baskets/42", method="GET", is_mutating=False,
        request_body={}, request_content_type=None,
    )
    fake_artifact = SimpleNamespace(id=99)

    with (
        patch("app.services.pentest_validators._endpoint_for_hypothesis", return_value=endpoint),
        patch("app.services.pentest_validators._sessions", return_value=[user_a, user_b]),
        patch("app.services.pentest_validators._select_idor_pair", return_value=(user_a, user_b, True)),
        patch("app.services.pentest_validators._observed_object_for_identity", return_value=observed_a) as mock_observed,
        patch("app.services.pentest_validators._safe_request", side_effect=_idor_response_router("https://x/api/baskets/42")) as mock_safe,
        patch("app.services.pentest_validators.create_request_response_artifact", return_value=fake_artifact) as mock_artifact,
        patch("app.services.pentest_validators.OffensiveInventoryService") as mock_inv_cls,
    ):
        mock_inv = MagicMock()
        mock_inv_cls.return_value = mock_inv
        result = validate_idor_bola(MagicMock(), SimpleNamespace(id=7), SimpleNamespace(id=3))

    mock_observed.assert_called_once()
    # baseline (user_a) and attempt (user_b) both target the REAL observed
    # object, never the shared endpoint.url -- only the negative-control call
    # deliberately swaps the object id.
    called_urls = [call.args[0] for call in mock_safe.call_args_list if call.args]
    assert called_urls[0] == "https://x/api/baskets/42"
    assert called_urls[1] == "https://x/api/baskets/42"
    assert result["result"] == "confirmed"
    metadata = mock_artifact.call_args.kwargs["metadata"]
    assert metadata["object_attribution"] == "observed_per_identity"
    # Peer-matched + confirmed + real attribution -> full confidence, no penalty.
    assert mock_artifact.call_args.kwargs["confidence_score"] == 90


def test_validate_idor_bola_falls_back_to_shared_endpoint_with_unverified_attribution():
    endpoint = _fake_endpoint()
    user_a = _identity_session_pair("user_a", "user")
    user_b = _identity_session_pair("user_b", "user")
    fake_artifact = SimpleNamespace(id=99)

    with (
        patch("app.services.pentest_validators._endpoint_for_hypothesis", return_value=endpoint),
        patch("app.services.pentest_validators._sessions", return_value=[user_a, user_b]),
        patch("app.services.pentest_validators._select_idor_pair", return_value=(user_a, user_b, True)),
        patch("app.services.pentest_validators._observed_object_for_identity", return_value=None),
        patch("app.services.pentest_validators._safe_request", side_effect=_idor_response_router(endpoint.url)) as mock_safe,
        patch("app.services.pentest_validators.create_request_response_artifact", return_value=fake_artifact) as mock_artifact,
        patch("app.services.pentest_validators.OffensiveInventoryService") as mock_inv_cls,
    ):
        mock_inv = MagicMock()
        mock_inv_cls.return_value = mock_inv
        validate_idor_bola(MagicMock(), SimpleNamespace(id=7), SimpleNamespace(id=3))

    called_urls = [call.args[0] for call in mock_safe.call_args_list if call.args]
    assert called_urls[0] == endpoint.url
    assert called_urls[1] == endpoint.url
    metadata = mock_artifact.call_args.kwargs["metadata"]
    assert metadata["object_attribution"] == "unverified_shared_endpoint"
    # Confirmed(90) - 20 penalty = 70.
    assert mock_artifact.call_args.kwargs["confidence_score"] == 70


# ── worker_dispatcher._attach_observed_endpoints_per_identity ──────────────

class _FakeObservedQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *a, **k):
        return self

    def order_by(self, *a, **k):
        return self

    def all(self):
        return self._rows


class _FakeDispatcherDb:
    def __init__(self, rows):
        self._rows = rows

    def query(self, model):
        return _FakeObservedQuery(self._rows)


def test_attach_observed_endpoints_per_identity_enriches_two_identity_actions():
    endpoints = [SimpleNamespace(url="https://x/api/baskets/1", normalized_url="https://x/api/baskets/{id}")]
    observed_rows = [
        SimpleNamespace(normalized_url="https://x/api/baskets/{id}", identity_key="user_a", url="https://x/api/baskets/42"),
        SimpleNamespace(normalized_url="https://x/api/baskets/{id}", identity_key="user_b", url="https://x/api/baskets/7"),
    ]
    actions = [
        {"endpoint": "https://x/api/baskets/1", "required_identities": ["user_a", "user_b"]},
        {"endpoint": "https://x/api/products/1", "required_identities": ["user_a"]},
    ]
    db = _FakeDispatcherDb(observed_rows)

    _attach_observed_endpoints_per_identity(db, 7, actions, endpoints)

    assert actions[0]["endpoint_by_identity"] == {"user_a": "https://x/api/baskets/42", "user_b": "https://x/api/baskets/7"}
    assert "endpoint_by_identity" not in actions[1]


def test_attach_observed_endpoints_per_identity_no_op_when_no_two_identity_actions():
    db = _FakeDispatcherDb([])
    actions = [{"endpoint": "https://x/api/products/1", "required_identities": ["user_a"]}]

    _attach_observed_endpoints_per_identity(db, 7, actions, [])

    assert "endpoint_by_identity" not in actions[0]


def test_attach_observed_endpoints_per_identity_leaves_action_unmarked_when_no_match():
    endpoints = [SimpleNamespace(url="https://x/api/baskets/1", normalized_url="https://x/api/baskets/{id}")]
    actions = [{"endpoint": "https://x/api/baskets/1", "required_identities": ["user_a", "user_b"]}]
    db = _FakeDispatcherDb([])  # harvester never captured anything for this route

    _attach_observed_endpoints_per_identity(db, 7, actions, endpoints)

    assert "endpoint_by_identity" not in actions[0]


# ── business_logic_test.run_as_tool: compare_two_identities attribution ────

class _UrlAwareResponse:
    def __init__(self, status_code: int, content: bytes = b""):
        self.status_code = status_code
        self.content = content
        self.headers = {}


class _UrlAwareClient:
    """Differentiates by the URL actually requested (not the identity) --
    proves whether compare_two_identities sent both identities' requests to
    the SAME url (the real per-identity object, when known) rather than each
    identity's own request potentially hitting a different shared endpoint
    string. Also records what was hit for assertions."""

    calls: list[tuple[str, str]] = []

    def __init__(self, *, timeout=None, follow_redirects=None, verify=None, headers=None, cookies=None):
        self.headers = dict(headers or {})
        self.cookies = dict(cookies or {})

    def request(self, method: str, url: str) -> _UrlAwareResponse:
        type(self).calls.append((self.headers.get("X-Identity", ""), url))
        return _UrlAwareResponse(200, b"basket-42-data")

    def close(self) -> None:
        pass


def test_compare_two_identities_uses_observed_per_identity_object_for_both_requests(monkeypatch) -> None:
    _UrlAwareClient.calls = []
    monkeypatch.setattr(business_logic_test.httpx, "Client", _UrlAwareClient)

    execution_plan = {
        "policy": "observed-evidence-only",
        "guardrails": {},
        "actions": [
            {
                "endpoint": "http://target.test/api/baskets/1",
                "endpoint_by_identity": {"user_a": "http://target.test/api/baskets/42"},
                "method": "GET",
                "required_identities": ["user_a", "user_b"],
                "flows": [],
                "invariants": [],
            }
        ],
        "blocked": [],
    }
    identity_sessions = {
        "user_a": {"headers": {"X-Identity": "user_a"}, "cookies": {}},
        "user_b": {"headers": {"X-Identity": "user_b"}, "cookies": {}},
    }

    result = business_logic_test.run_as_tool(
        "target.test",
        execution_plan=execution_plan,
        identity_sessions=identity_sessions,
        run_business_logic_battery=False,
    )

    # Both identities must have been sent to user_a's REAL observed object,
    # never the shared /api/baskets/1 endpoint string.
    urls_hit = {url for _identity, url in _UrlAwareClient.calls}
    assert urls_hit == {"http://target.test/api/baskets/42"}
    wire_assessment = result["parsed"]["wire_assessments"][0]
    assert wire_assessment["object_attribution"] == "observed_per_identity"


def test_compare_two_identities_falls_back_to_shared_endpoint_with_unverified_attribution(monkeypatch) -> None:
    _UrlAwareClient.calls = []
    monkeypatch.setattr(business_logic_test.httpx, "Client", _UrlAwareClient)

    execution_plan = {
        "policy": "observed-evidence-only",
        "guardrails": {},
        "actions": [
            {
                "endpoint": "http://target.test/api/baskets/1",
                "method": "GET",
                "required_identities": ["user_a", "user_b"],
                "flows": [],
                "invariants": [],
            }
        ],
        "blocked": [],
    }
    identity_sessions = {
        "user_a": {"headers": {"X-Identity": "user_a"}, "cookies": {}},
        "user_b": {"headers": {"X-Identity": "user_b"}, "cookies": {}},
    }

    result = business_logic_test.run_as_tool(
        "target.test",
        execution_plan=execution_plan,
        identity_sessions=identity_sessions,
        run_business_logic_battery=False,
    )

    urls_hit = {url for _identity, url in _UrlAwareClient.calls}
    assert urls_hit == {"http://target.test/api/baskets/1"}
    wire_assessment = result["parsed"]["wire_assessments"][0]
    assert wire_assessment["object_attribution"] == "unverified_shared_endpoint"
