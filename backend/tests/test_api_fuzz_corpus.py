from app.services.api_fuzz_corpus import (
    CORPUS_VERSION,
    build_openapi_variable_corpus,
    corpus_catalog,
    select_corpus_values,
)
from app.services.api_fuzz_generator import fuzz_values_for_param


def test_openapi_corpus_has_10000_deterministic_synthetic_entries() -> None:
    first = build_openapi_variable_corpus()
    second = build_openapi_variable_corpus()

    assert len(first) == 10_000
    assert first == second
    assert len({entry["id"] for entry in first}) == 10_000
    assert {entry["source"] for entry in first} == {CORPUS_VERSION}
    assert len({entry["category"] for entry in first}) >= 50


def test_corpus_selection_is_parameter_aware_and_bounded() -> None:
    request_id = select_corpus_values(
        {"name": "requestId", "location": "path", "type_hint": "string", "format": "uuid"},
        budget=12,
    )
    sql_query = select_corpus_values(
        {"name": "query", "location": "query", "type_hint": "string"},
        budget=12,
    )

    assert len(request_id) == 12
    assert len(sql_query) == 12
    assert any("uuid" in label or "identifier" in label for _value, label in request_id)
    assert any("sql" in label or "search" in label or "filter" in label for _value, label in sql_query)
    assert request_id == select_corpus_values(
        {"name": "requestId", "location": "path", "type_hint": "string", "format": "uuid"},
        budget=12,
    )


def test_generator_can_add_library_values_without_changing_safe_default() -> None:
    param = {"name": "requestId", "type_hint": "string", "format": "uuid"}
    safe = fuzz_values_for_param(param, cap=12)
    deep = fuzz_values_for_param(param, cap=12, library_budget=8)

    assert len(deep) > len(safe)
    assert any(label.startswith("library:") for _value, label in deep)
    assert not any(label.startswith("library:") for _value, label in safe)


def test_catalog_reports_full_library_and_synthetic_provenance() -> None:
    catalog = corpus_catalog()

    assert catalog["size"] == 10_000
    assert catalog["synthetic"] is True
    assert catalog["version"] == CORPUS_VERSION
    assert sum(int(item["count"]) for item in catalog["categories"]) == 10_000
