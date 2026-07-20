from app.services.artifact_store import redact
from app.services.endpoint_analysis_pipeline import analyze_endpoint_contract
from app.services.pentest_validators import _safe_request
from app.services.sensitive_file_analyzer import (
    ALL_SENSITIVE_EXTENSIONS,
    analyze_sensitive_file_content,
    classify_sensitive_file_url,
    extension_for_url,
)


def test_catalog_covers_requested_sensitive_extension_families() -> None:
    assert len(ALL_SENSITIVE_EXTENSIONS) >= 100
    for extension in (
        ".js", ".map", ".env", ".json", ".yaml", ".xml", ".config",
        ".properties", ".tfvars", ".tfstate", ".tfstate.backup", ".sql",
        ".bak", ".log", ".har", ".pem", ".key", ".p12", ".jks",
        ".graphql", ".proto", ".tar.gz", ".postman_collection",
    ):
        assert extension in ALL_SENSITIVE_EXTENSIONS


def test_longest_extension_wins_and_critical_file_is_prioritized() -> None:
    assert extension_for_url("https://valid.com/state/prod.tfstate.backup?download=1") == ".tfstate.backup"
    analysis = classify_sensitive_file_url("https://valid.com/state/prod.tfstate.backup")
    assert analysis["matched"] is True
    assert analysis["priority"] == 95
    assert analysis["content_limit_bytes"] == 131072


def test_content_analysis_emits_fingerprints_without_secret_values() -> None:
    content = """API_KEY=super-secret-value
-----BEGIN PRIVATE KEY-----
do-not-store-this
-----END PRIVATE KEY-----
endpoint=https://api.valid.com/orders?id=42&token=secret
"""
    result = analyze_sensitive_file_content(content)

    assert result["indicator_count"] >= 2
    assert result["content_retained"] is False
    assert all("value" not in indicator for indicator in result["indicators"])
    assert result["endpoints"] == ["https://api.valid.com/orders?id=&token="]
    assert "super-secret-value" not in str(result)


def test_content_analysis_limit_is_measured_in_bytes() -> None:
    result = analyze_sensitive_file_content("á" * 100, max_bytes=64)

    assert result["bytes_analyzed"] == 64
    assert result["truncated"] is True


def test_sensitive_static_file_enters_endpoint_test_matrix() -> None:
    analysis = analyze_endpoint_contract("https://valid.com/assets/app.js")
    tests = {row["test_class"]: row for row in analysis["test_matrix"]}

    assert analysis["classification"]["static_asset"] is True
    assert analysis["classification"]["sensitive_file"] is True
    assert "read_only_baseline" in tests
    assert tests["sensitive_file_analysis"]["hypothesis_type"] == "sensitive_file_exposure"


def test_artifact_redaction_removes_private_keys_jwts_and_cloud_keys() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz"
    value = redact(
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"
        + jwt
        + "\nAKIAABCDEFGHIJKLMNOP"
    )
    assert "secret" not in value
    assert jwt not in value
    assert "AKIAABCDEFGHIJKLMNOP" not in value


def test_sensitive_fetch_never_follows_redirects_and_stops_at_byte_limit(monkeypatch) -> None:
    calls = []

    class Response:
        status_code = 200
        headers = {"content-type": "text/plain"}

        def iter_content(self, chunk_size):
            calls.append(("chunk_size", chunk_size))
            yield b"a" * 64
            yield b"b" * 64

        def close(self):
            calls.append(("closed", True))

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr("app.services.pentest_validators.requests.get", fake_get)

    result = _safe_request("https://valid.com/app.js", {}, {}, analysis_bytes=80)

    request_kwargs = calls[0][1]
    assert request_kwargs["allow_redirects"] is False
    assert request_kwargs["stream"] is True
    assert result["body_len"] == 80
    assert result["analysis_text"] == ("a" * 64) + ("b" * 16)
    assert ("closed", True) in calls
