from __future__ import annotations

import re
from pathlib import Path


def test_limited_all_queries_have_explicit_order_by() -> None:
    app_root = Path(__file__).resolve().parents[1] / "app"
    offenders: list[str] = []
    for path in app_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"\.limit\([^\n]+\)\s*\n\s*\.all\(\)", text):
            window_start = max(0, text.rfind("\n", 0, match.start() - 700))
            block = text[window_start:match.end()]
            if ".order_by(" not in block:
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{path.relative_to(app_root)}:{line}")

    assert offenders == []
