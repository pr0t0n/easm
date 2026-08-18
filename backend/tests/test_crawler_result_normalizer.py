from app.services import crawler_result_normalizer as normalizer
from app.services import findings_extractor
from types import SimpleNamespace


def test_crawler_normalizer_upserts_discovered_url_with_detected_method(monkeypatch):
    calls = []

    class _Endpoint:
        id = 1
        url = "https://example.com/api/send?text="
        normalized_url = "https://example.com/api/send?text="
        source_artifact_id = None

    class _Inventory:
        def __init__(self, db, scan):
            pass

        def upsert_endpoint(self, url, **kwargs):
            calls.append({"url": url, **kwargs})
            return _Endpoint()

        def upsert_js_asset(self, *args, **kwargs):
            return None

        def upsert_parameter(self, *args, **kwargs):
            return None

        def upsert_coverage(self, *args, **kwargs):
            return None

    class _DB:
        def add(self, value):
            return None

        def flush(self):
            return None

    monkeypatch.setattr(normalizer, "OffensiveInventoryService", _Inventory)

    normalizer.normalize_crawler_result(
        db=_DB(),
        scan=SimpleNamespace(id=1, target_query="example.com"),
        target="https://example.com",
        tool_name="katana",
        result={"stdout": "fetch('https://example.com/api/send?text=', { method: 'POST' })"},
    )

    assert calls
    assert calls[0]["url"] == "https://example.com/api/send?text="
    assert calls[0]["method"] == "POST"


def test_crawler_normalizer_drops_external_urls_before_inventory(monkeypatch):
    calls = []

    class _Inventory:
        def __init__(self, db, scan):
            pass

        def upsert_endpoint(self, url, **kwargs):
            calls.append(url)
            return SimpleNamespace(id=1, url=url, normalized_url=url, source_artifact_id=None)

        def upsert_parameter(self, *args, **kwargs):
            return None

        def upsert_coverage(self, *args, **kwargs):
            return None

    class _DB:
        def __init__(self):
            self.added = []

        def add(self, value):
            self.added.append(value)

        def flush(self):
            return None

    db = _DB()
    monkeypatch.setattr(normalizer, "OffensiveInventoryService", _Inventory)
    result = normalizer.normalize_crawler_result(
        db=db,
        scan=SimpleNamespace(id=6, target_query="valid.com"),
        target="https://valid.com",
        tool_name="katana",
        result={
            "stdout": (
                "https://valid.com/profile\n"
                "https://api.valid.com/orders/1\n"
                "https://avidabank.dk/login\n"
            )
        },
    )

    assert "https://valid.com/profile" in calls
    assert "https://api.valid.com/orders/1" in calls
    assert not any("avidabank.dk" in value for value in calls)
    assert result["out_of_scope_urls_blocked"] == 1


def test_js_declared_api_base_out_of_scope_is_flagged_high_confidence(monkeypatch):
    """A host the target's own JS names as its API base (baseURL/apiBase/...)
    is a categorically stronger ownership signal than an arbitrary crawled
    link, and must be surfaced as a distinct, actionable finding -- still
    without ever auto-testing it (fail-closed scope is unchanged)."""
    persisted = []

    class _Inventory:
        def __init__(self, db, scan):
            pass

        def upsert_endpoint(self, url, **kwargs):
            return SimpleNamespace(id=1, url=url, normalized_url=url, source_artifact_id=None)

        def upsert_parameter(self, *args, **kwargs):
            return None

        def upsert_coverage(self, *args, **kwargs):
            return None

    class _DB:
        def add(self, value):
            return None

        def flush(self):
            return None

    def _fake_persist(db, scan, raw_findings, **kwargs):
        persisted.extend(raw_findings)

    monkeypatch.setattr(normalizer, "OffensiveInventoryService", _Inventory)
    monkeypatch.setattr(findings_extractor, "persist_finding_dicts", _fake_persist)

    scan = SimpleNamespace(id=7, target_query="https://hml-platform.example.com", state_data={})
    normalizer.normalize_crawler_result(
        db=_DB(),
        scan=scan,
        target="https://hml-platform.example.com",
        tool_name="katana",
        result={
            "stdout": (
                "https://hml-platform.example.com/app.js\n"
                "https://some-cdn-analytics.example.net/track.js\n"
                "const client = axios.create({ baseURL: 'https://hml-api-platform.example.com' });\n"
            ),
        },
    )

    by_host = {f["details"]["related_host_out_of_scope"]: f for f in persisted}
    own_api = by_host["hml-api-platform.example.com"]
    assert own_api["severity"] == "medium"
    assert own_api["details"]["own_api_declared_out_of_scope"] is True
    assert "backend do mesmo produto" in own_api["details"]["discovery_note"]
    assert "hml-api-platform.example.com" in own_api["details"]["discovery_note"]

    generic = by_host["some-cdn-analytics.example.net"]
    assert generic["severity"] == "info"
    assert generic["details"]["own_api_declared_out_of_scope"] is False
