from __future__ import annotations

from app.services.offensive_operator_core import tool_execution_signature


def test_tool_execution_signature_dedupes_aliases_with_same_profile() -> None:
    base = {
        "profile": "amass_brute",
        "arguments": {"target": "Tarcisio.blog", "timeout": 300},
        "execution_backend": "mcp",
    }

    assert tool_execution_signature("P01", {**base, "tool_name": "amass"}) == tool_execution_signature(
        "P01",
        {**base, "tool_name": "amass-brute"},
    )
