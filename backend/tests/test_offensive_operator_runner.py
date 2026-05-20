from __future__ import annotations

from app.services.offensive_operator_runner import _parse_targets_from_query


def test_parse_targets_from_query_handles_semicolon_and_comma_separated_values() -> None:
    raw = "valid.com; validecertificadora.com.br, example.org\nlocalhost"
    parsed = _parse_targets_from_query(raw)
    assert parsed == [
        "valid.com",
        "validecertificadora.com.br",
        "example.org",
        "localhost",
    ]
