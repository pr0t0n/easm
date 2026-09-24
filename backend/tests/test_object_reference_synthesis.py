"""_synthesize_object_reference_endpoints_once closes a discovery gap found
live against a fresh Juice Shop instance: crawlers and the passive browser
harvester only ever persisted flat collection endpoints (/api/Products,
/api/BasketItems, /api/Feedbacks, ...) with zero numeric/uuid id segments,
so endpoint_analysis_pipeline.py's object_reference classification (fixed
separately to not require an /api/ prefix or a sensitive marker word) had
nothing to classify as True -- the BOLA/business-logic test engine kept
returning "0 ações; pré-condições/contratos pendentes" even with two valid
identities registered. This generic fix fetches each discovered collection
endpoint and, if its JSON response is (or contains) an array of objects each
carrying an id, synthesizes and persists `{collection_url}/{id}` as a new,
testable object-reference endpoint -- true of virtually any REST API, not
specific to Juice Shop. These tests mock urllib.request.urlopen,
AuthSessionManager, and OffensiveInventoryService, matching this repo's
fake-db unit-test convention.
"""
import json
from types import SimpleNamespace

from app.services import offensive_operator_runner as runner


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def all(self):
        return self._rows


class _FakeDb:
    def __init__(self, endpoint_rows=None):
        self._endpoint_rows = endpoint_rows or []
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    def query(self, model):
        return _FakeQuery(self._endpoint_rows)

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def _job():
    return SimpleNamespace(id=9, state_data={})


def _endpoint(url, auth_context="anonymous"):
    return SimpleNamespace(url=url, method="GET", auth_context=auth_context)


class _FakeHTTPResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_skips_when_already_attempted(monkeypatch):
    job = SimpleNamespace(id=9, state_data={"_object_reference_synthesis_attempted": True})

    result = runner._synthesize_object_reference_endpoints_once(_FakeDb(), job, "http://target.local")

    assert result == {"skipped": True, "reason": "already_attempted"}


def test_synthesizes_child_endpoints_from_bare_json_array(monkeypatch):
    import app.services.auth_session_manager as auth_session_manager_module
    import app.services.offensive_inventory_service as inventory_module
    import app.services.endpoint_analysis_pipeline as pipeline_module

    monkeypatch.setattr(
        auth_session_manager_module, "AuthSessionManager",
        lambda db, scan: SimpleNamespace(list_material=lambda limit=4: []),
    )
    upsert_calls = []
    monkeypatch.setattr(
        inventory_module, "OffensiveInventoryService",
        lambda db, scan: SimpleNamespace(
            upsert_endpoint=lambda url, **kw: upsert_calls.append((url, kw))
        ),
    )
    analyze_calls = []
    monkeypatch.setattr(
        pipeline_module, "analyze_endpoints_for_scan",
        lambda db, job, force=False: analyze_calls.append(force),
    )

    body = json.dumps([{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]).encode()
    import urllib.request as _urlreq_mod
    monkeypatch.setattr(_urlreq_mod, "urlopen", lambda req, timeout=8: _FakeHTTPResponse(body))

    db = _FakeDb(endpoint_rows=[_endpoint("http://target.local/api/Products")])
    job = _job()
    result = runner._synthesize_object_reference_endpoints_once(db, job, "http://target.local")

    assert result["checked"] == 1
    assert result["synthesized"] == 2
    urls = {call[0] for call in upsert_calls}
    assert urls == {"http://target.local/api/Products/1", "http://target.local/api/Products/2"}
    assert analyze_calls == [True]
    for _url, kwargs in upsert_calls:
        assert kwargs["auth_required"] is None
        assert kwargs["auth_context"] == "anonymous"


def test_synthesized_endpoints_marked_auth_required_when_fetched_with_a_valid_identity(monkeypatch):
    """A collection fetched using a throwaway authenticated identity's own
    session represents a per-user-owned resource -- exactly the shape BOLA/
    IDOR testing needs. auth_required=True is what flips the generated test
    in endpoint_analysis_pipeline.py from a passive "object_reference_discovery"
    (empty required_identities) into a real two-identity "object_authorization"
    comparison, even when object_reference classification is already True --
    this was the second half of the "0 ações; pré-condições/contratos
    pendentes" gap found live: the first fix (dropping the is_api/is_sensitive
    gate) made object_reference=True, but without this, auth_observed stayed
    falsy and every synthesized endpoint still fell into the discovery-only
    branch."""
    import app.services.auth_session_manager as auth_session_manager_module
    import app.services.offensive_inventory_service as inventory_module
    import app.services.endpoint_analysis_pipeline as pipeline_module

    valid_material = SimpleNamespace(valid=True, headers={"Authorization": "Bearer abc"}, cookies={})
    monkeypatch.setattr(
        auth_session_manager_module, "AuthSessionManager",
        lambda db, scan: SimpleNamespace(list_material=lambda limit=4: [valid_material]),
    )
    upsert_calls = []
    monkeypatch.setattr(
        inventory_module, "OffensiveInventoryService",
        lambda db, scan: SimpleNamespace(
            upsert_endpoint=lambda url, **kw: upsert_calls.append((url, kw))
        ),
    )
    monkeypatch.setattr(pipeline_module, "analyze_endpoints_for_scan", lambda db, job, force=False: None)

    body = json.dumps([{"id": 6}]).encode()
    import urllib.request as _urlreq_mod
    monkeypatch.setattr(_urlreq_mod, "urlopen", lambda req, timeout=8: _FakeHTTPResponse(body))

    db = _FakeDb(endpoint_rows=[_endpoint("http://target.local/api/BasketItems")])
    result = runner._synthesize_object_reference_endpoints_once(db, _job(), "http://target.local")

    assert result["synthesized"] == 1
    _url, kwargs = upsert_calls[0]
    assert kwargs["auth_required"] is True
    assert kwargs["auth_context"] == "authenticated"


def test_skips_endpoints_that_already_have_an_object_id_segment(monkeypatch):
    import app.services.auth_session_manager as auth_session_manager_module

    monkeypatch.setattr(
        auth_session_manager_module, "AuthSessionManager",
        lambda db, scan: SimpleNamespace(list_material=lambda limit=4: []),
    )

    fetch_calls = []

    def _fake_urlopen(req, timeout=8):
        fetch_calls.append(req.full_url if hasattr(req, "full_url") else str(req))
        return _FakeHTTPResponse(b"[]")

    import urllib.request as _urlreq_mod
    monkeypatch.setattr(_urlreq_mod, "urlopen", _fake_urlopen)

    db = _FakeDb(endpoint_rows=[
        _endpoint("http://target.local/api/Products/6"),
        _endpoint("http://target.local/main.js"),
    ])
    result = runner._synthesize_object_reference_endpoints_once(db, _job(), "http://target.local")

    assert result["checked"] == 0
    assert result["synthesized"] == 0
    assert fetch_calls == []


def test_non_json_or_non_array_response_synthesizes_nothing(monkeypatch):
    import app.services.auth_session_manager as auth_session_manager_module

    monkeypatch.setattr(
        auth_session_manager_module, "AuthSessionManager",
        lambda db, scan: SimpleNamespace(list_material=lambda limit=4: []),
    )
    import urllib.request as _urlreq_mod
    monkeypatch.setattr(_urlreq_mod, "urlopen", lambda req, timeout=8: _FakeHTTPResponse(b"<html>not json</html>"))

    db = _FakeDb(endpoint_rows=[_endpoint("http://target.local/api/Whoami")])
    result = runner._synthesize_object_reference_endpoints_once(db, _job(), "http://target.local")

    assert result["checked"] == 1
    assert result["synthesized"] == 0


def test_urlopen_exception_is_caught_and_logged(monkeypatch):
    import app.services.auth_session_manager as auth_session_manager_module

    monkeypatch.setattr(
        auth_session_manager_module, "AuthSessionManager",
        lambda db, scan: SimpleNamespace(list_material=lambda limit=4: []),
    )

    def _boom(*a, **k):
        raise RuntimeError("connection refused")

    import urllib.request as _urlreq_mod
    monkeypatch.setattr(_urlreq_mod, "urlopen", _boom)

    db = _FakeDb(endpoint_rows=[_endpoint("http://target.local/api/Products")])
    result = runner._synthesize_object_reference_endpoints_once(db, _job(), "http://target.local")

    assert result == {"checked": 1, "synthesized": 0}
