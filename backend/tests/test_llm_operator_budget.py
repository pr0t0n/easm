from __future__ import annotations

from types import SimpleNamespace

from app.core.config import settings
from app.services.llm_operator import (
    MAX_LLM_OPERATOR_CALLS_PER_SCAN,
    MAX_LLM_OPERATOR_ITEMS_PER_SCAN,
    _build_operator_prompt,
    _normalize_tech_stack,
    run_llm_operator,
)


def _job(state: dict) -> SimpleNamespace:
    return SimpleNamespace(id=1, state_data=dict(state), tech_stack=[])


def test_call_budget_blocks_before_touching_db(monkeypatch) -> None:
    monkeypatch.setattr(settings, "llm_operator_enabled", True)
    job = _job({"llm_operator_call_count": MAX_LLM_OPERATOR_CALLS_PER_SCAN})

    result = run_llm_operator(db=None, job=job)  # db=None proves the budget check runs first

    assert result == {"skipped": "call_budget_exhausted", "call_count": MAX_LLM_OPERATOR_CALLS_PER_SCAN}


def test_item_budget_blocks_before_touching_db(monkeypatch) -> None:
    monkeypatch.setattr(settings, "llm_operator_enabled", True)
    job = _job({"llm_operator_items_total": MAX_LLM_OPERATOR_ITEMS_PER_SCAN})

    result = run_llm_operator(db=None, job=job)

    assert result == {"skipped": "item_budget_exhausted", "items_total": MAX_LLM_OPERATOR_ITEMS_PER_SCAN}


def test_under_budget_falls_through_to_rate_limit_check(monkeypatch) -> None:
    monkeypatch.setattr(settings, "llm_operator_enabled", True)
    job = _job({
        "llm_operator_call_count": 1,
        "llm_operator_items_total": 2,
        "llm_operator_last_run": 9_999_999_999,  # far future -> still "rate limited"
    })

    result = run_llm_operator(db=None, job=job)

    # Proves it passed the budget gates and reached the next check (not budget-blocked)
    assert result["skipped"] == "rate_limited"


def test_dict_tech_stack_is_normalized_for_prompt_builder() -> None:
    raw = {
        "cms": ["drupal", "shopify"],
        "waf": ["akamai"],
        "detected": ["wordpress"],
    }

    tech_stack = _normalize_tech_stack(raw)
    prompt = _build_operator_prompt(
        targets=["validcertificadora.com.br"],
        findings=[],
        tech_stack=tech_stack,
        phases_done=["P01", "P06"],
    )

    assert {"category": "waf", "tech": "akamai"} in tech_stack
    assert "akamai" in prompt
    assert "drupal" in prompt
