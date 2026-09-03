from app.services.api_scan_contract import (
    api_spec_url_in_scope,
    merge_api_scan_state,
    normalize_api_scan_config,
)


def test_api_scan_without_credentials_runs_anonymous_only() -> None:
    config = normalize_api_scan_config({"enabled": True, "spec_url": "https://api.example.test/openapi.json"}, None)

    assert config["auth_strategy"] == "anonymous_only"
    assert config["execution_contexts"] == ["anonymous"]
    assert config["credential_count"] == 0


def test_api_scan_with_one_credential_runs_anonymous_and_authenticated() -> None:
    config = normalize_api_scan_config({"enabled": True}, {"type": "bearer", "token": "token-a"})

    assert config["auth_strategy"] == "anonymous_authenticated"
    assert config["execution_contexts"] == ["anonymous", "authenticated:user_a"]
    assert config["credential_count"] == 1


def test_api_scan_with_two_credentials_runs_anonymous_and_ab() -> None:
    auth = {
        "type": "bearer",
        "identities": [
            {"id": "user_a", "bearer_token": "token-a"},
            {"id": "user_b", "bearer_token": "token-b"},
        ],
    }

    config = normalize_api_scan_config({"enabled": True}, auth)

    assert config["auth_strategy"] == "anonymous_authenticated_ab"
    assert config["execution_contexts"] == ["anonymous", "authenticated:user_a", "authenticated:user_b"]
    assert config["credential_count"] == 2


def test_api_scan_state_unlocks_openapi_tools_without_storing_inline_payload() -> None:
    config = normalize_api_scan_config(
        {
            "enabled": True,
            "spec_payload": {
                "openapi": "3.0.0",
                "paths": {"/users": {"get": {"parameters": [{"name": "id", "in": "query"}]}}},
            },
        },
        None,
    )

    state = merge_api_scan_state({"scan_level": "full"}, config)

    assert state["api_scan_config"]["inline_spec_provided"] is True
    assert state["openapi_specs"] == ["inline"]
    assert "spec_payload" not in state["api_scan_config"]


def test_api_spec_url_must_match_authorized_scope() -> None:
    assert api_spec_url_in_scope("https://api.example.test/openapi.json", ["example.test"]) is True
    assert api_spec_url_in_scope("https://other.test/openapi.json", ["example.test"]) is False
