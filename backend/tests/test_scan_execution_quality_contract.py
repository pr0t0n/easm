from datetime import datetime, timedelta
from types import SimpleNamespace

from app.services.scan_execution_metrics import summarize_work_items
from app.services.scan_quality import quality_gate_decision


def _item(status: str, *, phase: str = "P01", tool: str = "httpx"):
    start = datetime(2026, 1, 1, 10, 0, 0)
    return SimpleNamespace(
        status=status,
        phase_id=phase,
        tool_name=tool,
        target="example.test",
        resource_class="light",
        created_at=start,
        started_at=start,
        finished_at=start + timedelta(seconds=10) if status in {"completed", "failed", "skipped"} else None,
    )


def test_execution_metrics_use_one_work_item_denominator():
    metrics = summarize_work_items([
        _item("completed"),
        _item("failed", tool="nmap"),
        _item("skipped", phase="P02"),
        _item("queued", phase="P03"),
    ])
    assert metrics["source"] == "scan_work_items"
    assert metrics["total"] == 4
    assert metrics["attempted"] == 3
    assert metrics["succeeded"] == 1
    assert metrics["success_pct"] == 33.3
    assert metrics["progress_pct"] == 75.0


def test_no_more_remediation_does_not_mean_quality_passed():
    decision = quality_gate_decision({"score": 48, "gaps": []}, [])
    assert decision["completion_allowed"] is True
    assert decision["passed"] is False
    assert decision["completion_status"] == "completed_with_gaps"


def test_high_gap_blocks_even_when_numeric_score_is_high():
    decision = quality_gate_decision({
        "score": 92,
        "gaps": [{"severity": "high", "title": "high finding without proof"}],
    })
    assert decision["passed"] is False
    assert len(decision["blockers"]) == 1
