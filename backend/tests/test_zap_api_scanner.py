from app.services import zap_scanner


def test_zap_api_scan_overrides_openapi_server_with_https_target(monkeypatch) -> None:
    calls = []

    monkeypatch.setattr(zap_scanner, "is_zap_available", lambda: True)
    monkeypatch.setattr(zap_scanner, "_apply_auth_headers", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(zap_scanner, "_clear_auth_headers", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(zap_scanner, "_wait_for_active_scan", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(zap_scanner, "_get_alerts", lambda target: [])

    def fake_zap(path, params=None):
        calls.append(("get", path, dict(params or {})))
        if path.endswith("/urls/"):
            return {"urls": ["https://api.example.com/api/ping"]}
        return {"importUrl": []}

    def fake_zap_post(path, data=None):
        calls.append(("post", path, dict(data or {})))
        return {"scan": "9"}

    monkeypatch.setattr(zap_scanner, "_zap", fake_zap)
    monkeypatch.setattr(zap_scanner, "_zap_post", fake_zap_post)

    result = zap_scanner.run_zap_api_scan(
        "api.example.com",
        openapi_url="https://api.example.com/openapi.json",
    )

    assert result["target"] == "https://api.example.com"
    assert result["imported_url_count"] == 1
    assert calls[0] == (
        "get",
        "/JSON/openapi/action/importUrl/",
        {
            "url": "https://api.example.com/openapi.json",
            "hostOverride": "https://api.example.com",
            "maxMessages": "0",
        },
    )
    assert ("post", "/JSON/ascan/action/scan/", {"url": "https://api.example.com", "recurse": "true"}) in calls
