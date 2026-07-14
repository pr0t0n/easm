from app.services import crawler_result_normalizer as normalizer


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
        def flush(self):
            return None

    monkeypatch.setattr(normalizer, "OffensiveInventoryService", _Inventory)

    normalizer.normalize_crawler_result(
        db=_DB(),
        scan=object(),
        target="https://example.com",
        tool_name="katana",
        result={"stdout": "fetch('https://example.com/api/send?text=', { method: 'POST' })"},
    )

    assert calls
    assert calls[0]["url"] == "https://example.com/api/send?text="
    assert calls[0]["method"] == "POST"
