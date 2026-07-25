from types import SimpleNamespace

from app.services.offensive_operator_runner import _scan_halt_reason, _scan_halted
from app.services import scan_work_queue
from app.workers.tasks import _patch_scan_state


def _job(status: str = "running", epoch: int = 0):
    return SimpleNamespace(status=status, state_data={"execution_epoch": epoch})


def test_execution_epoch_fences_writer_that_survived_pause_resume():
    job = _job(epoch=3)

    assert _scan_halt_reason(job, expected_execution_epoch=2) == "execution_epoch_changed"
    assert _scan_halted(job, expected_execution_epoch=2) is True


def test_current_execution_epoch_remains_runnable():
    job = _job(epoch=3)

    assert _scan_halt_reason(job, expected_execution_epoch=3) is None
    assert _scan_halted(job, expected_execution_epoch=3) is False


def test_explicit_pause_still_takes_precedence_over_epoch():
    job = _job(status="paused", epoch=3)

    assert _scan_halt_reason(job, expected_execution_epoch=3) == "paused"
    assert _scan_halted(job, expected_execution_epoch=3) is True


def test_requeued_work_item_locks_are_deleted_by_exact_id(monkeypatch):
    deleted = []

    class FakeRedis:
        def delete(self, *keys):
            deleted.extend(keys)
            return len(keys)

    monkeypatch.setattr(scan_work_queue, "_redis_client", lambda: FakeRedis())

    assert scan_work_queue.clear_work_item_execute_locks([9, 12]) == 2
    assert deleted == ["work_item_execute_lock:9", "work_item_execute_lock:12"]


def test_state_patch_preserves_concurrent_qualification_keys():
    job = SimpleNamespace(
        state_data={
            "preflight": {"targets": {"api.example": {"p02_complete": True}}},
            "execution_epoch": 7,
        }
    )

    class FakeQuery:
        def filter(self, *_args):
            return self

        def populate_existing(self):
            return self

        def with_for_update(self):
            return self

        def first(self):
            return job

    class FakeDB:
        def query(self, *_args):
            return FakeQuery()

        def flush(self):
            return None

    _patch_scan_state(FakeDB(), 12, {"js_done": True})

    assert job.state_data["js_done"] is True
    assert job.state_data["execution_epoch"] == 7
    assert job.state_data["preflight"]["targets"]["api.example"]["p02_complete"] is True
