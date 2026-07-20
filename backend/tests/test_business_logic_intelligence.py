"""Business-logic contracts and guardrails; no target network is used."""
from __future__ import annotations

from app.services.business_logic_intelligence import (
    build_business_logic_execution_plan,
    build_business_logic_portfolio,
)
from app.services.business_logic_test import (
    _bola_active,
    _bola_single_resource,
    _capture,
    _collections_from_swagger,
    _collections_from_wordlist,
    _coupon_brute,
    _rest_crud_negative,
    _token_reuse_after_logout,
    run_as_tool,
)
from app.services.endpoint_analysis_pipeline import analyze_endpoint_contract


def _analysis(path: str, method: str = "GET") -> dict:
    return analyze_endpoint_contract(f"https://www.valid.com{path}", method=method)


def test_object_contract_requires_two_identities_same_object_and_negative_control() -> None:
    contract = _analysis("/orders/{id}")["business_logic"]

    assert "object_ownership" in contract["flows"]
    assert set(contract["required_identities"]) == {"user_a", "user_b"}
    assert "same_object_owned_by_user_a" in contract["required_fixtures"]
    assert "concrete_object_fixture_required" in contract["blockers"]
    assert {"owner_scope", "list_detail_consistency"} <= {row["id"] for row in contract["invariants"]}
    assert {"owner_baseline", "cross_identity_same_object", "negative_control"} <= set(contract["evidence_requirements"])


def test_transfer_contract_models_value_conservation_replay_and_rollback() -> None:
    contract = _analysis("/transfer", "POST")["business_logic"]

    assert "money_movement" in contract["flows"]
    assert {"positive_amount", "balance_conservation", "single_commit", "authorized_recipient"} <= {
        row["id"] for row in contract["invariants"]
    }
    assert {"sandbox_ledger", "idempotency_key", "read_back", "rollback"} <= set(contract["required_fixtures"])
    assert contract["execution_policy"]["mutation_allowed_by_default"] is False
    assert contract["execution_policy"]["requires_explicit_reversible_plan"] is True


def test_unparameterized_fetch_is_contracted_but_blocked_until_parameter_observed() -> None:
    analysis = _analysis("/proxy")
    contract = analysis["business_logic"]
    plan = build_business_logic_execution_plan([analysis])

    assert "server_side_fetch" in contract["flows"]
    assert "observed_parameter_required" in contract["blockers"]
    assert plan["actions"] == []
    assert plan["blocked"][0]["reasons"] == ["missing_observed_parameter"]


def test_execution_plan_contains_only_observed_read_only_endpoints() -> None:
    observed = [
        _analysis("/search?search=tabletop"),
        _analysis("/orders/{id}"),
        _analysis("/payment", "POST"),
    ]
    plan = build_business_logic_execution_plan(observed, available_identities=["user_a", "user_b"])
    action_urls = {row["endpoint"] for row in plan["actions"]}

    assert action_urls <= {row["business_logic"]["endpoint"] for row in observed}
    assert all(row["method"] in {"GET", "HEAD", "OPTIONS"} for row in plan["actions"])
    assert plan["mutation_authorized"] is False
    assert plan["guardrails"]["guess_routes"] is False
    assert plan["guardrails"]["guess_object_ids"] is False
    assert plan["guardrails"]["brute_force"] is False
    assert plan["guardrails"]["try_sqli_auth"] is False
    assert any("state_change_requires_dedicated_reversible_plan" in row["reasons"] for row in plan["blocked"])


def test_portfolio_exposes_contract_depth_and_missing_preconditions() -> None:
    analyses = [_analysis("/orders/{id}"), _analysis("/payment"), _analysis("/logout")]
    portfolio = build_business_logic_portfolio(analyses)

    assert portfolio["contracted_endpoints"] == portfolio["relevant_endpoints"] == 3
    assert portfolio["invariants"] >= 8
    assert portfolio["high_risk_endpoints"] == 3
    assert portfolio["ready_read_only"] == 0
    assert portfolio["blocked"]["missing_validated_identities"] == 3
    assert portfolio["execution_guardrails"]["mutation_default"] == "blocked"


def test_executor_without_contract_returns_blocked_without_opening_http_client(monkeypatch) -> None:
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("network client must not be constructed without a plan")

    monkeypatch.setattr("app.services.business_logic_test.httpx.Client", fail_if_called)
    result = run_as_tool("https://valid.com")

    assert result["status"] == "blocked_precondition"
    assert result["parsed"]["summary"]["observed"] == 0
    assert result["findings_extracted"] == []


def test_legacy_speculative_probes_are_hard_disabled() -> None:
    class FailClient:
        def get(self, *_args, **_kwargs):
            raise AssertionError("legacy probe attempted network access")

        def request(self, *_args, **_kwargs):
            raise AssertionError("legacy probe attempted network access")

    client = FailClient()
    assert _collections_from_wordlist(client, "https://valid.com") == []
    assert _collections_from_swagger(client, "https://valid.com") == []
    assert _bola_active(client, ["https://valid.com/api/orders"], "token") == []
    assert _bola_single_resource(client, {}, "https://valid.com", "token") == []
    assert _coupon_brute(client, {}, "https://valid.com") == []
    assert _rest_crud_negative(client, ["https://valid.com/api/orders"]) == []
    assert _token_reuse_after_logout("https://valid.com", "token", {}) == []
    assert _capture("https://valid.com")["login_status"] == "blocked_observed_endpoint_plan_required"


def test_executor_rejects_out_of_scope_action_before_request(monkeypatch) -> None:
    class NoRequestClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def request(self, *_args, **_kwargs):
            raise AssertionError("out-of-scope endpoint must never be requested")

    monkeypatch.setattr("app.services.business_logic_test.httpx.Client", NoRequestClient)
    result = run_as_tool("https://valid.com", execution_plan={
        "policy": "observed-evidence-only",
        "actions": [{"endpoint": "https://attacker.invalid/search?q=x", "method": "GET"}],
        "blocked": [],
    })

    assert result["parsed"]["observations"] == []
    assert result["parsed"]["blocked"][0]["reasons"] == ["outside_target_scope"]
