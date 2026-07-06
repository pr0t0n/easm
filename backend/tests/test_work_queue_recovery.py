from __future__ import annotations

from types import SimpleNamespace


def test_recover_orphaned_capacity_work_queue_resumes_dispatcher(monkeypatch) -> None:
    from app.models.models import ScanJob
    from app.workers import tasks

    job = SimpleNamespace(
        id=5,
        status="running",
        state_data={"parallel_engine": "capacity_work_queue"},
        current_step="stale",
        next_retry_at="later",
    )
    delayed: list[int] = []

    class FakeQuery:
        def __init__(self, first_value=None, count_value=0):
            self.first_value = first_value
            self.count_value = count_value

        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return self.first_value

        def count(self):
            return self.count_value

    class FakeSession:
        def query(self, model):
            if model is ScanJob:
                return FakeQuery(first_value=job)
            return FakeQuery(count_value=3)

        def add(self, obj):
            return None

        def commit(self):
            return None

        def close(self):
            return None

    class FakeDispatcher:
        @staticmethod
        def delay(scan_id: int):
            delayed.append(scan_id)

    monkeypatch.setattr(tasks, "SessionLocal", lambda: FakeSession())
    monkeypatch.setattr(tasks, "_chain_lock_alive", lambda scan_id: False)
    monkeypatch.setattr(tasks, "dispatch_scan_work_items", FakeDispatcher)

    result = tasks.recover_scan_if_orphaned(5, source="test")

    assert result["action"] == "work_queue_resumed"
    assert result["work_items"] == 3
    assert delayed == [5]
    assert job.status == "running"
    assert job.current_step == "Recuperacao automatica: retomando fila persistida"


def test_terminal_scan_finishes_late_work_item_without_requeue() -> None:
    from app.workers.tasks import _finish_work_item_for_terminal_scan

    item = SimpleNamespace(
        status="submitted",
        lease_until="soon",
        finished_at=None,
        updated_at=None,
        last_error=None,
        result={"kali_job_id": "abc"},
    )

    _finish_work_item_for_terminal_scan(item, "completed", "before_poll")

    assert item.status == "skipped"
    assert item.lease_until is None
    assert item.finished_at is not None
    assert item.last_error == "skipped:scan_completed:before_poll"
    assert item.result["status"] == "skipped"
