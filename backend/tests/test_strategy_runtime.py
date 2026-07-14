from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

from app.services.strategy_runtime import (
    build_reasoning_feedback,
    build_strategy_timeline,
    evaluate_scan_authorization,
    is_local_test_target,
    parse_scope_targets,
)


class _FakeQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def all(self):
        return list(self.rows)


class _FakeDb:
    def __init__(self, rows):
        self.rows = rows

    def query(self, model):
        return _FakeQuery(self.rows)


def test_parse_scope_targets_normalizes_urls_and_dedupes() -> None:
    assert parse_scope_targets("https://app.example.test/path; app.example.test,api.example.test") == [
        "app.example.test",
        "api.example.test",
    ]


def test_local_test_targets_are_authorization_exempt() -> None:
    assert is_local_test_target("localhost") is True
    assert is_local_test_target("127.0.0.1") is True
    assert is_local_test_target("app.example.test") is True

    decision = evaluate_scan_authorization(
        _FakeDb([]),
        owner_id=1,
        target_query="http://localhost:8080",
        enforce_public_targets=True,
    )

    assert decision["approved"] is True
    assert decision["mode"] == "local_or_policy_exempt"


def test_public_target_without_authorization_is_blocked() -> None:
    decision = evaluate_scan_authorization(
        _FakeDb([]),
        owner_id=1,
        target_query="www.valid.com",
        enforce_public_targets=True,
    )

    assert decision["approved"] is False
    assert decision["mode"] == "blocked_missing_authorization"
    assert decision["public_targets"] == ["www.valid.com"]
    assert decision["authorization_attested"] is False


def test_public_target_with_operator_attestation_is_approved() -> None:
    decision = evaluate_scan_authorization(
        _FakeDb([]),
        owner_id=1,
        target_query="www.valid.com",
        authorization_attested=True,
        enforce_public_targets=True,
    )

    assert decision["approved"] is True
    assert decision["mode"] == "operator_attestation"
    assert decision["authorization_attested"] is True
    assert decision["authorized_scope"] == ["www.valid.com"]


def test_public_target_with_matching_authorization_is_approved() -> None:
    auth = SimpleNamespace(
        id=7,
        authorization_code="abc123",
        target_query="www.valid.com",
        expires_at=datetime.now() + timedelta(days=1),
        created_at=datetime.now(),
        status="approved",
        requester_id=1,
    )

    decision = evaluate_scan_authorization(
        _FakeDb([auth]),
        owner_id=1,
        target_query="https://api.www.valid.com",
        authorization_code="abc123",
        enforce_public_targets=True,
    )

    assert decision["approved"] is True
    assert decision["authorization_id"] == 7
    assert decision["authorized_scope"] == ["www.valid.com"]


def test_reasoning_feedback_and_timeline_are_built_from_runtime_state() -> None:
    state = {"strategy_runtime_timeline": []}
    feedback = build_reasoning_feedback(
        state=state,
        capability="risk_assessment",
        skill_id="api-security",
        selected_tools=["nuclei"],
        execution_results=[{"target": "app.example.test", "findings": 1}],
        findings_added=1,
    )

    scan = SimpleNamespace(
        state_data={
            "operational_strategy": {"events": [{"type": "strategy_initialized", "ts": "2026-07-14T00:00:00"}]},
            "strategy_runtime_timeline": state["strategy_runtime_timeline"],
            "llm_reasoning_feedback": [feedback],
        }
    )

    timeline = build_strategy_timeline(scan)

    assert feedback["status"] == "productive"
    assert any(item["type"] == "reasoning_feedback" for item in timeline)
