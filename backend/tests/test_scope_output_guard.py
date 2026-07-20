from __future__ import annotations

import json
from app.services.scan_scope import (
    filter_httpx_output_to_authorized_scope,
    out_of_scope_hosts_for_finding,
)


def test_httpx_output_drops_certificate_san_fanout() -> None:
    rows = [
        {"input": "api.valid.com", "url": "https://api.valid.com", "status_code": 200},
        {"input": "avidabank.dk", "url": "https://avidabank.dk", "status_code": 200},
        {"input": "graddo.es", "url": "https://graddo.es", "status_code": 200},
    ]
    stdout = "\n".join(json.dumps(row) for row in rows)

    parsed, clean_stdout, audit = filter_httpx_output_to_authorized_scope(
        rows, stdout, ["valid.com"]
    )

    assert parsed == [rows[0]]
    assert "api.valid.com" in clean_stdout
    assert "avidabank.dk" not in clean_stdout
    assert audit["rejected_count"] == 2
    assert audit["rejected_hosts"] == ["avidabank.dk", "graddo.es"]


def test_redirect_is_followed_only_after_scope_evaluation() -> None:
    rows = [
        {
            "input": "valid.com",
            "url": "https://valid.com/login",
            "status_code": 302,
            "location": "/continue",
        },
        {
            "input": "valid.com",
            "url": "https://valid.com/callback",
            "status_code": 302,
            "location": "https://avidabank.dk/session",
        },
    ]

    parsed, _, audit = filter_httpx_output_to_authorized_scope(rows, "", ["valid.com"])

    # Both source responses remain valid evidence, but only the in-scope
    # destination is eligible for a separately authorized follow-up request.
    assert parsed == rows
    assert audit["allowed_redirects"] == [
        {"source": "https://valid.com/login", "destination": "https://valid.com/continue"}
    ]
    assert audit["blocked_redirects"] == [
        {"source": "https://valid.com/callback", "destination": "https://avidabank.dk/session"}
    ]


def test_finding_gate_rejects_external_primary_locations() -> None:
    assert out_of_scope_hosts_for_finding(
        {"asset": "avidabank.dk", "network": {"url": "https://avidabank.dk"}},
        "avidabank.dk",
        "https://avidabank.dk",
        ["valid.com"],
    ) == ["avidabank.dk"]
    assert out_of_scope_hosts_for_finding(
        {"asset": "api.valid.com", "url": "/orders/1"},
        "api.valid.com",
        "https://api.valid.com/orders/1",
        ["valid.com"],
    ) == []


