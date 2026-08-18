"""SEC-003 regression tests.

Raw operator-supplied credentials (auth_config password/bearer_token/cookies,
llm_risk password/auth_value) must never reach the `scan_jobs.state_data`
column in plaintext (StateDataJSON) and must never be echoed back verbatim in
a ScanResponse/ReportResponse API response (schemas/scan.py redaction).
"""
from __future__ import annotations


def test_state_data_json_encrypts_auth_config_and_llm_risk_at_rest():
    from app.models.encrypted_json import StateDataJSON

    coder = StateDataJSON()
    state = {
        "scan_level": "full",
        "current_surface": "example.com",
        "auth_config": {
            "type": "form_login",
            "username": "admin",
            "password": "hunter2-super-secret",
            "bearer_token": "eyJraldontleak",
        },
        "llm_risk": {
            "enabled": True,
            "target_url": "https://risk.example.com",
            "password": "another-secret",
            "auth_value": "sk-do-not-leak",
        },
    }

    bound = coder.process_bind_param(dict(state), dialect=None)

    # Unrelated keys pass through untouched.
    assert bound["scan_level"] == "full"
    assert bound["current_surface"] == "example.com"

    # Sensitive subtrees are now opaque tokens — nothing in the bound value
    # that would actually be written to Postgres contains the raw secret.
    assert bound["auth_config"] != state["auth_config"]
    assert isinstance(bound["auth_config"], dict) and "__enc__" in bound["auth_config"]
    assert isinstance(bound["llm_risk"], dict) and "__enc__" in bound["llm_risk"]
    serialized = str(bound)
    assert "hunter2-super-secret" not in serialized
    assert "eyJraldontleak" not in serialized
    assert "sk-do-not-leak" not in serialized

    # Round-trips back to the exact original plaintext on read.
    restored = coder.process_result_value(bound, dialect=None)
    assert restored["auth_config"] == state["auth_config"]
    assert restored["llm_risk"] == state["llm_risk"]
    assert restored["scan_level"] == "full"


def test_state_data_json_leaves_legacy_plaintext_rows_untouched_on_read():
    from app.models.encrypted_json import StateDataJSON

    coder = StateDataJSON()
    legacy_row = {"auth_config": {"username": "bob", "password": "plain"}, "scan_level": "asm"}

    # A row written before StateDataJSON existed has no __enc__ marker — must
    # be surfaced as-is rather than crashing (matches EncryptedJSON's
    # existing fail-open-on-legacy-rows convention).
    restored = coder.process_result_value(dict(legacy_row), dialect=None)
    assert restored == legacy_row


def test_state_data_json_does_not_double_encrypt_already_encrypted_value():
    from app.models.encrypted_json import StateDataJSON

    coder = StateDataJSON()
    state = {"auth_config": {"password": "hunter2"}}
    bound_once = coder.process_bind_param(dict(state), dialect=None)
    bound_twice = coder.process_bind_param(dict(bound_once), dialect=None)

    assert bound_once["auth_config"] == bound_twice["auth_config"]
    restored = coder.process_result_value(dict(bound_twice), dialect=None)
    assert restored["auth_config"] == state["auth_config"]


def test_scan_response_redacts_auth_config_and_llm_risk_credentials():
    from app.schemas.scan import ScanResponse
    from datetime import datetime

    resp = ScanResponse(
        id=1,
        target_query="example.com",
        mode="single",
        status="queued",
        compliance_status="approved",
        current_step="1. Amass Subdomain Recon",
        mission_progress=0,
        created_at=datetime.now(),
        state_data={
            "auth_config": {
                "type": "form_login",
                "username": "admin",
                "password": "hunter2-super-secret",
                "bearer_token": "eyJraldontleak",
                "cookies": {"session": "abc123"},
                "headers": {"Authorization": "Bearer abc123"},
            },
            "llm_risk": {
                "enabled": True,
                "password": "another-secret",
                "auth_value": "sk-do-not-leak",
                "target_url": "https://risk.example.com",
            },
            "current_surface": "example.com",
        },
    )

    dumped = resp.model_dump()
    serialized = str(dumped)

    assert "hunter2-super-secret" not in serialized
    assert "eyJraldontleak" not in serialized
    assert "sk-do-not-leak" not in serialized
    assert "abc123" not in serialized

    # Non-secret fields survive so the UI/API consumer keeps useful context.
    assert dumped["state_data"]["auth_config"]["username"] == "admin"
    assert dumped["state_data"]["auth_config"]["type"] == "form_login"
    assert dumped["state_data"]["llm_risk"]["target_url"] == "https://risk.example.com"
    assert dumped["state_data"]["current_surface"] == "example.com"
    assert dumped["state_data"]["auth_config"]["password"] == "[REDACTED]"
    assert dumped["state_data"]["llm_risk"]["auth_value"] == "[REDACTED]"


def test_report_response_redacts_credentials_in_nested_state_data():
    from app.schemas.scan import ReportResponse

    resp = ReportResponse(
        scan_id=1,
        status="completed",
        findings=[],
        state_data={
            "auth_config": {"password": "hunter2", "username": "admin"},
        },
    )
    dumped = resp.model_dump()
    assert dumped["state_data"]["auth_config"]["password"] == "[REDACTED]"
    assert dumped["state_data"]["auth_config"]["username"] == "admin"
