from app.services import crawler_result_normalizer as normalizer
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
