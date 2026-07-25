from __future__ import annotations

from pathlib import Path


def test_runtime_does_not_import_legacy_phase_validator() -> None:
    """Production phase advancement must keep a single judge.

    ``app.services.phase_validator`` is retained for legacy unit tests/helpers,
    but runtime code advances phases through ``app.graph.workflow``. Importing
    both in production recreated the historical "two judges" drift.
    """

    app_root = Path(__file__).resolve().parents[1] / "app"
    offenders: list[str] = []
    for path in app_root.rglob("*.py"):
        rel = str(path.relative_to(app_root))
        if rel == "services/phase_validator.py":
            continue
        text = path.read_text(encoding="utf-8")
        if "app.services.phase_validator" in text:
            offenders.append(rel)

    assert offenders == []
