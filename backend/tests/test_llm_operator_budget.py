from __future__ import annotations

from types import SimpleNamespace

from app.core.config import settings
from app.services.llm_operator import (
    MAX_LLM_OPERATOR_CALLS_PER_SCAN,
    MAX_LLM_OPERATOR_ITEMS_PER_SCAN,
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
