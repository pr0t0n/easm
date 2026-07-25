from __future__ import annotations

from types import SimpleNamespace


def test_recover_orphaned_capacity_work_queue_resumes_dispatcher(monkeypatch) -> None:
    from app.models.models import ScanJob
    from app.services import scan_work_queue
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

    monkeypatch.setattr(tasks, "SessionLocal", lambda: FakeSession())
    monkeypatch.setattr(tasks, "_chain_lock_alive", lambda scan_id: False)
    monkeypatch.setattr(tasks, "_kali_scan_has_active_jobs", lambda scan_id: False)
    monkeypatch.setattr(tasks, "_schedule_scan_work_dispatch", lambda scan_id: delayed.append(scan_id))
    monkeypatch.setattr(scan_work_queue, "has_pending_work", lambda db, scan_id: True)

    result = tasks.recover_scan_if_orphaned(5, source="test")

    assert result["action"] == "work_queue_resumed"
    assert result["work_items"] == 3
    assert delayed == [5]
    assert job.status == "running"
    assert job.current_step == "Recuperacao automatica: retomando fila persistida"


def test_completed_postprocessor_ledger_ignores_stale_redis_key(monkeypatch) -> None:
    from app.workers import tasks

    class FakeRedis:
        def scan_iter(self, match, count=10):
            yield b"scan_postprocessor_pending:14:zap:example.test"

    monkeypatch.setattr(
        "app.services.scan_work_queue._redis_client",
        lambda: FakeRedis(),
    )

    state = {
        "postprocessor_ledger": {
            "zap:example.test": {
                "kind": "zap",
                "target": "example.test",
                "status": "completed",
                "updated_at": "2026-07-24T15:17:01",
            }
        }
    }

    assert tasks._scan_postprocessors_pending(14, state) is False


def test_running_postprocessor_ledger_blocks_completion() -> None:
    from datetime import datetime
    from app.workers import tasks

    state = {
        "postprocessor_ledger": {
            "zap:example.test": {
                "kind": "zap",
                "target": "example.test",
                "status": "running",
                "updated_at": datetime.now().isoformat(),
            }
        }
    }

    assert tasks._scan_postprocessors_pending(14, state) is True


def test_postprocessor_skipped_result_stays_skipped() -> None:
    from app.workers import tasks

    assert tasks._postprocessor_outcome_from_result({"skipped": "llm_unavailable"}) == (
        "skipped",
        "llm_unavailable",
    )
    assert tasks._postprocessor_outcome_from_result({"status": "not_applicable"}) == (
        "skipped",
        "not_applicable",
    )
    assert tasks._postprocessor_outcome_from_result({"chains": []}) == ("completed", "")


def test_runtime_state_merge_does_not_resurrect_running_postprocessor() -> None:
    from app.workers import tasks

    stale_snapshot = {
        "postprocessor_ledger": {
            "llm_operator:api.example.test": {
                "kind": "llm_operator",
                "target": "api.example.test",
                "item_id": 10,
                "status": "running",
                "updated_at": "2026-07-24T15:00:00",
            }
        }
    }
    durable_state = {
        "postprocessor_done:llm_operator:api.example.test": True,
        "postprocessor_ledger": {
            "llm_operator:api.example.test": {
                "kind": "llm_operator",
                "target": "api.example.test",
                "item_id": 10,
                "status": "failed",
                "error": "llm_unavailable",
                "updated_at": "2026-07-24T15:01:00",
            }
        },
    }

    merged = tasks._merge_runtime_scan_state(stale_snapshot, durable_state)

    assert merged["postprocessor_ledger"]["llm_operator:api.example.test"]["status"] == "failed"
    assert merged["postprocessor_done:llm_operator:api.example.test"] is True


def test_recover_terminal_capacity_queue_requests_finalization_only(monkeypatch) -> None:
    from app.models.models import ScanJob
    from app.services import scan_work_queue
    from app.workers import tasks

    job = SimpleNamespace(
        id=8,
        status="running",
        state_data={"parallel_engine": "capacity_work_queue", "current_pentest_phase_id": "P21"},
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
            return FakeQuery(count_value=4358)

        def add(self, obj):
            return None

        def commit(self):
            return None

        def close(self):
            return None

    monkeypatch.setattr(tasks, "SessionLocal", lambda: FakeSession())
    monkeypatch.setattr(tasks, "_chain_lock_alive", lambda scan_id: False)
    monkeypatch.setattr(tasks, "_kali_scan_has_active_jobs", lambda scan_id: False)
    monkeypatch.setattr(tasks, "_schedule_scan_work_dispatch", lambda scan_id: delayed.append(scan_id))
    monkeypatch.setattr(scan_work_queue, "has_pending_work", lambda db, scan_id: False)

    result = tasks.recover_scan_if_orphaned(8, source="test")

    assert result == {
        "scan_id": 8,
        "action": "work_queue_finalization_queued",
        "work_items": 4358,
    }
    assert delayed == [8]
    assert job.status == "running"
    assert job.current_step == "P21 · Finalizacao automatica: fila terminal enviada ao Quality Gate"
    assert "work_queue_finalization_requested_at" in job.state_data["recovery"]


def test_recover_does_not_interfere_with_valid_leased_work_item(monkeypatch) -> None:
    from app.models.models import ScanJob, ScanWorkItem
    from app.workers import tasks

    job = SimpleNamespace(
        id=8,
        status="running",
        state_data={"parallel_engine": "capacity_work_queue"},
        current_step="P21 · validando hipoteses",
        next_retry_at=None,
    )
    delayed: list[int] = []

    class FakeQuery:
        def __init__(self, *, first_value=None, count_value=0):
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
            if model is ScanWorkItem.id:
                return FakeQuery(first_value=(22499,), count_value=4358)
            raise AssertionError(model)

        def close(self):
            return None

    monkeypatch.setattr(tasks, "SessionLocal", lambda: FakeSession())
    monkeypatch.setattr(tasks, "_chain_lock_alive", lambda scan_id: False)
    monkeypatch.setattr(tasks, "_kali_scan_has_active_jobs", lambda scan_id: False)
    monkeypatch.setattr(tasks, "_schedule_scan_work_dispatch", lambda scan_id: delayed.append(scan_id))

    result = tasks.recover_scan_if_orphaned(8, source="test")

    assert result == {
        "scan_id": 8,
        "action": "work_queue_active",
        "work_items": 4358,
        "active_work_item_id": 22499,
    }
    assert delayed == []
    assert job.current_step == "P21 · validando hipoteses"


def test_recover_does_not_redrive_active_phase_queue_task(monkeypatch) -> None:
    from app.models.models import ScanJob
    from app.workers import tasks

    job = SimpleNamespace(
        id=7,
        status="running",
        state_data={
            "_operator_phase_queue_started": True,
            "current_pentest_phase_id": "P03",
            "current_pentest_target": "www.valid.com",
            "recovery": {"redrive_count": 2},
        },
        current_step="P03 Endpoint Discovery (www.valid.com)",
        next_retry_at=None,
    )
    commits: list[bool] = []

    class FakeQuery:
        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return job

    class FakeSession:
        def query(self, model):
            assert model is ScanJob
            return FakeQuery()

        def commit(self):
            commits.append(True)

        def close(self):
            return None

    monkeypatch.setattr(tasks, "SessionLocal", lambda: FakeSession())
    monkeypatch.setattr(tasks, "_chain_lock_alive", lambda scan_id: False)
    monkeypatch.setattr(tasks, "_kali_scan_has_active_jobs", lambda scan_id: False)
    monkeypatch.setattr(tasks, "active_scan_task_ids", lambda: ({7}, True))

    result = tasks.recover_scan_if_orphaned(7, source="test")

    assert result == {
        "scan_id": 7,
        "action": "task_active",
        "reason": "active_without_chain_lock",
    }
    assert job.state_data["recovery"]["redrive_count"] == 0
    assert commits == [True]


def test_recover_preserves_chain_when_kali_runner_has_active_job(monkeypatch) -> None:
    from app.models.models import ScanJob
    from app.workers import tasks

    job = SimpleNamespace(
        id=12,
        status="running",
        state_data={"recovery": {"redrive_count": 2}},
    )
    commits: list[bool] = []

    class FakeQuery:
        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return job

    class FakeSession:
        def query(self, model):
            assert model is ScanJob
            return FakeQuery()

        def commit(self):
            commits.append(True)

        def close(self):
            return None

    monkeypatch.setattr(tasks, "SessionLocal", lambda: FakeSession())
    monkeypatch.setattr(tasks, "active_scan_task_ids", lambda: (set(), True))
    monkeypatch.setattr(tasks, "_kali_scan_has_active_jobs", lambda scan_id: True)

    result = tasks.recover_scan_if_orphaned(12, source="test")

    assert result == {
        "scan_id": 12,
        "action": "runner_active",
        "reason": "kali_job_active_without_celery_inspect_visibility",
    }
    assert job.state_data["recovery"]["redrive_count"] == 0
    assert commits == [True]


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


def test_retry_policy_only_treats_required_phase_tools_as_required() -> None:
    from app.workers.tasks import _work_item_tool_is_required

    assert _work_item_tool_is_required(SimpleNamespace(phase_id="P17", tool_name="nuclei")) is True
    assert _work_item_tool_is_required(SimpleNamespace(phase_id="P17", tool_name="sqlmap")) is False
