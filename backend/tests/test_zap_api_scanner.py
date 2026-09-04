from app.services import zap_scanner


def test_zap_api_scan_overrides_openapi_server_with_https_target(monkeypatch) -> None:
    calls = []

    monkeypatch.setattr(zap_scanner, "is_zap_available", lambda: True)
    monkeypatch.setattr(zap_scanner, "_apply_auth_headers", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(zap_scanner, "_clear_auth_headers", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(zap_scanner, "_wait_for_active_scan", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(zap_scanner, "_get_alerts", lambda target: [])

    def fake_zap(path, params=None, **kwargs):
        calls.append(("get", path, dict(params or {}), dict(kwargs or {})))
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
    assert (
        "get",
        "/JSON/openapi/action/importUrl/",
        {
            "url": "https://api.example.com/openapi.json",
            "hostOverride": "https://api.example.com",
            "maxMessages": "0",
        },
        {"timeout": 300},
    ) in calls
    assert (
        "post",
        "/JSON/ascan/action/setOptionThreadPerHost/",
        {"Integer": "1"},
    ) in calls
    assert (
        "post",
        "/JSON/ascan/action/scan/",
        {"url": "https://api.example.com", "recurse": "true", "scanPolicyName": "API"},
    ) in calls
    assert result["scan_policy"] == "API"
    assert result["finding_count"] == 0


def test_zap_api_scan_rewrites_openapi_file_when_scan_id_is_available(monkeypatch) -> None:
    calls = []

    monkeypatch.setattr(zap_scanner, "is_zap_available", lambda: True)
    monkeypatch.setattr(zap_scanner, "_apply_auth_headers", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(zap_scanner, "_clear_auth_headers", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(zap_scanner, "_wait_for_active_scan", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(zap_scanner, "_get_alerts", lambda target: [])
    monkeypatch.setattr(
        zap_scanner,
        "_rewritten_openapi_file_for_target",
        lambda *_args, **_kwargs: (
            "/evidence/zap-openapi/scan-15-test.json",
            {"rewritten": True, "paths": 137, "servers": [{"url": "https://api.example.com"}]},
        ),
    )

    def fake_zap(path, params=None, **kwargs):
        calls.append(("get", path, dict(params or {}), dict(kwargs or {})))
        if path.endswith("/urls/"):
            return {"urls": ["https://api.example.com/api/ping"]}
        return {"importFile": []}

    def fake_zap_post(path, data=None):
        calls.append(("post", path, dict(data or {})))
        return {"scan": "9"}

    monkeypatch.setattr(zap_scanner, "_zap", fake_zap)
    monkeypatch.setattr(zap_scanner, "_zap_post", fake_zap_post)

    result = zap_scanner.run_zap_api_scan(
        "api.example.com",
        openapi_url="https://api.example.com/openapi.json",
        scan_id=15,
    )

    assert (
        "get",
        "/JSON/openapi/action/importFile/",
        {
            "file": "/evidence/zap-openapi/scan-15-test.json",
            "target": "https://api.example.com",
            "maxMessages": "0",
        },
        {"timeout": 300},
    ) in calls
    assert not any(call[1] == "/JSON/openapi/action/importUrl/" for call in calls)
    assert result["import_source"] == "rewritten_file"
    assert result["rewritten_spec"]["paths"] == 137
    assert result["imported_url_count"] == 1


def test_zap_api_scan_blocks_active_scan_when_import_has_no_target_urls(monkeypatch) -> None:
    calls = []

    monkeypatch.setattr(zap_scanner, "is_zap_available", lambda: True)
    monkeypatch.setattr(zap_scanner, "_apply_auth_headers", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(zap_scanner, "_clear_auth_headers", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(zap_scanner, "_get_alerts", lambda target: [])
    monkeypatch.setattr(
        zap_scanner,
        "_rewritten_openapi_file_for_target",
        lambda *_args, **_kwargs: ("/evidence/zap-openapi/scan-15-test.json", {"rewritten": True}),
    )

    def fake_zap(path, params=None, **kwargs):
        calls.append(("get", path, dict(params or {}), dict(kwargs or {})))
        if path.endswith("/urls/"):
            return {"urls": []}
        return {"importFile": []}

    def fake_zap_post(path, data=None):
        calls.append(("post", path, dict(data or {})))
        return {"scan": "9"}

    monkeypatch.setattr(zap_scanner, "_zap", fake_zap)
    monkeypatch.setattr(zap_scanner, "_zap_post", fake_zap_post)

    result = zap_scanner.run_zap_api_scan(
        "api.example.com",
        openapi_url="https://api.example.com/openapi.json",
        scan_id=15,
    )

    assert result["active_error"] == "openapi_import_produced_no_target_urls"
    assert result["imported_url_count"] == 0
    assert not any(call[1] == "/JSON/ascan/action/scan/" for call in calls)


def test_zap_api_scan_keeps_snapshot_when_active_scan_is_lost(monkeypatch) -> None:
    url_calls = 0
    alert_calls = 0

    monkeypatch.setattr(zap_scanner, "is_zap_available", lambda: True)
    monkeypatch.setattr(zap_scanner, "_apply_auth_headers", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(zap_scanner, "_clear_auth_headers", lambda *_args, **_kwargs: None)

    def fake_wait(_scan_id, _max_wait=None, on_progress=None, **_kwargs):
        if on_progress:
            on_progress()
        return False

    def fake_zap(path, params=None, **_kwargs):
        nonlocal url_calls
        if path.endswith("/urls/"):
            url_calls += 1
            if url_calls >= 3:
                raise RuntimeError("zap restarted")
            return {"urls": ["https://api.example.com/api/users"]}
        return {"importUrl": []}

    def fake_get_alerts(_target):
        nonlocal alert_calls
        alert_calls += 1
        if alert_calls >= 3:
            return []
        return [{
            "risk": "High",
            "confidence": "2",
            "name": "SQL Injection",
            "url": "https://api.example.com/api/users?id=1",
            "param": "id",
            "evidence": "SQL syntax",
        }]

    monkeypatch.setattr(zap_scanner, "_wait_for_active_scan", fake_wait)
    monkeypatch.setattr(zap_scanner, "_zap", fake_zap)
    monkeypatch.setattr(zap_scanner, "_zap_post", lambda *_args, **_kwargs: {"scan": "9"})
    monkeypatch.setattr(zap_scanner, "_get_alerts", fake_get_alerts)

    result = zap_scanner.run_zap_api_scan(
        "api.example.com",
        openapi_url="https://api.example.com/openapi.json",
    )

    assert result["active_error"] == "zap_active_scan_incomplete_or_lost"
    assert result["scan_policy"] == "API"
    assert result["imported_url_count"] == 1
    assert result["alert_count"] == 1
    assert result["finding_count"] == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "high"
    assert result["findings"][0]["source_tool"] == "zap-api"
    assert result["findings"][0]["details"]["tool"] == "zap-api"
    assert result["findings"][0]["details"]["source_agent_name"] == "Backend ZAP API Scanner"
    assert result["findings"][0]["details"]["imported_url_count"] == 1
