from types import SimpleNamespace

from app.models.models import ScanLog, ScanWorkItem
from app.services.scan_quality import _schedule_fallback_quality_items


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def all(self):
        return list(self.rows)

    def first(self):
        return self.rows[0] if self.rows else None


class _FakeDb:
    def __init__(self, work_items):
        self.rows = {
            ScanWorkItem: list(work_items),
            ScanLog: [],
        }

    def query(self, model):
        if model is ScanWorkItem:
            return _Query(self.rows[ScanWorkItem])
        return _Query([])

    def add(self, row):
        bucket = self.rows.setdefault(type(row), [])
        if row not in bucket:
            bucket.append(row)


def test_quality_gate_schedules_alternate_tool_after_retry():
    original = ScanWorkItem(
        id=10,
        scan_job_id=7,
        phase_id="P12",
        target="https://app.example.test/search?q=1",
        tool_name="sqlmap",
        profile="sqlmap",
        resource_class="heavy",
        priority=60,
        status="failed",
        attempts=1,
        max_attempts=1,
        last_error="timeout",
        item_metadata={"quality_gate_retries": 1},
    )
    db = _FakeDb([original])

    result = _schedule_fallback_quality_items(
        db,
        SimpleNamespace(id=7),
        {"P12"},
    )

    created = [item for item in db.rows[ScanWorkItem] if item is not original]
    assert result["scheduled"] == 1
    assert len(created) == 1
    assert created[0].tool_name == "nuclei-sqli"
    assert created[0].status == "queued"
    assert created[0].max_attempts == 1
    assert created[0].item_metadata["quality_gate_fallback"] is True
    assert created[0].item_metadata["quality_gate_fallback_for_item_id"] == 10
    assert created[0].item_metadata["quality_gate_original_tool"] == "sqlmap"
