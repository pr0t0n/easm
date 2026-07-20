from datetime import datetime, timedelta
from time import perf_counter
from types import SimpleNamespace

from app.services.scan_execution_metrics import summarize_work_items


def test_ten_thousand_work_items_are_summarized_within_budget():
    started = datetime(2026, 1, 1)
    rows = [
        SimpleNamespace(
            status="completed" if index % 4 else "failed",
            phase_id=f"P{(index % 22) + 1:02d}",
            tool_name=f"tool-{index % 60}",
            target=f"host-{index % 300}.example",
            resource_class=("light", "medium", "heavy")[index % 3],
            created_at=started,
            started_at=started + timedelta(seconds=index % 30),
            finished_at=started + timedelta(seconds=(index % 30) + 5),
        )
        for index in range(10_000)
    ]
    before = perf_counter()
    metrics = summarize_work_items(rows)
    elapsed = perf_counter() - before
    assert metrics["total"] == 10_000
    assert elapsed < 1.5
