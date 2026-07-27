from __future__ import annotations

from pathlib import Path


ROOT_CANDIDATES = [
    Path(__file__).resolve().parents[1],
    Path(__file__).resolve().parents[2],
]


def test_p01_requires_public_index_fallback_not_only_subfinder() -> None:
    path = next(
        candidate / "skills" / "reconnaissance" / "subdomain_enumeration.md"
        for candidate in ROOT_CANDIDATES
        if (candidate / "skills" / "reconnaissance" / "subdomain_enumeration.md").exists()
    )
    source = path.read_text(encoding="utf-8")

    required = source.split("required_tools:", 1)[1].split("optional_tools:", 1)[0]
    fallback = source.split("fallback_tools:", 1)[1].split("evidence_required:", 1)[0]

    assert "- subfinder" in required
    assert "- ghdb-public-indexes" in required
    assert "- ghdb-public-indexes" in fallback
    assert "minimum_tools_attempted: 2" in source
