from types import SimpleNamespace

from app.services.artifact_store import redact
from app.services.endpoint_analysis_pipeline import analyze_endpoint_contract
from app.services.hypothesis_planner import _prefetch_read_only_observations
from app.services.pentest_validators import _deduplicate_followup_urls, _safe_request
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


def test_read_only_hypotheses_are_prefetched_without_threaded_db_access(monkeypatch) -> None:
    db = object()
    hypotheses = [
        SimpleNamespace(id=1, hypothesis_type="sensitive_file_exposure"),
        SimpleNamespace(id=2, hypothesis_type="information_disclosure"),
        SimpleNamespace(id=3, hypothesis_type="idor_bola"),
        SimpleNamespace(id=4, hypothesis_type="sensitive_file_exposure"),
    ]
    endpoint_calls = []
    request_calls = []

    def fake_endpoint_for_hypothesis(received_db, hypothesis):
        endpoint_calls.append((received_db, hypothesis.id))
        if hypothesis.id == 4:
            return SimpleNamespace(url="https://external.example/leak.env")
        return SimpleNamespace(url=f"https://valid.com/{hypothesis.id}.txt")

    def fake_safe_request(url, headers, cookies, *, follow_redirects, analysis_bytes):
        request_calls.append((url, follow_redirects, analysis_bytes))
        return {"ok": True, "status_code": 200, "analysis_text": ""}

    monkeypatch.setattr(
        "app.services.pentest_validators._endpoint_for_hypothesis",
        fake_endpoint_for_hypothesis,
    )
    monkeypatch.setattr("app.services.pentest_validators._safe_request", fake_safe_request)

    scan = SimpleNamespace(target_query="valid.com")
    observations = _prefetch_read_only_observations(db, scan, hypotheses)

    assert set(observations) == {1, 2, 4}
    assert observations[4]["error"] == "OutOfScope"
    assert endpoint_calls == [(db, 1), (db, 2), (db, 4)]
    assert sorted(request_calls) == [
        ("https://valid.com/1.txt", False, 131072),
        ("https://valid.com/2.txt", False, 0),
    ]


def test_sensitive_followup_urls_are_deduplicated_across_the_batch() -> None:
    context = {"seen_extracted_urls": set(), "extracted_urls": set()}

    first = _deduplicate_followup_urls(
        ["https://valid.com/a", "https://valid.com/b", "https://valid.com/a"],
        context,
    )
    second = _deduplicate_followup_urls(
        ["https://valid.com/b", "https://valid.com/c"],
        context,
    )

    assert first == ["https://valid.com/a", "https://valid.com/b"]
    assert second == ["https://valid.com/c"]
    assert context["extracted_urls"] == {
        "https://valid.com/a",
        "https://valid.com/b",
        "https://valid.com/c",
    }
