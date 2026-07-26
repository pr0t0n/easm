import base64
import json
import zlib


def _compressed_celery_message(task: str, args: list | None = None, kwargs: dict | None = None) -> str:
    body = json.dumps([args or [], kwargs or {}, None]).encode("utf-8")
    return json.dumps(
        {
            "headers": {"task": task, "compression": "application/x-gzip"},
            "body": base64.b64encode(zlib.compress(body)).decode("ascii"),
        }
    )


def test_scan_driver_pending_in_broker_detects_compressed_scan_driver(monkeypatch):
    from app.workers import tasks

    class FakeBroker:
        def lrange(self, queue, start, end):
            assert queue == tasks.SCAN_UNIT_QUEUE
            return [
                _compressed_celery_message("worker.heartbeat"),
                _compressed_celery_message("run_scan_job_unit", [31]),
            ]

    import redis

    monkeypatch.setattr(redis, "from_url", lambda *args, **kwargs: FakeBroker())

    assert tasks._scan_driver_pending_in_broker(31, mode="unit") is True
    assert tasks._scan_driver_pending_in_broker(32, mode="unit") is False


def test_control_beat_tasks_expire_instead_of_backlogging():
    from app.workers.celery_app import celery
    from app.workers.worker_groups import PLATFORM_CONTROL_QUEUE

    schedule = celery.conf.beat_schedule

    assert schedule["scheduler-tick"]["options"]["expires"] > 0
    assert schedule["watchdog-tick"]["options"]["expires"] > 0
    assert schedule["tool-health-refresh"]["options"]["expires"] > 0
    assert schedule["scheduler-tick"]["options"]["queue"] == PLATFORM_CONTROL_QUEUE
    assert schedule["watchdog-tick"]["options"]["queue"] == PLATFORM_CONTROL_QUEUE
    assert schedule["tool-health-refresh"]["options"]["queue"] == PLATFORM_CONTROL_QUEUE

    heartbeat_entries = [
        entry for name, entry in schedule.items()
        if name.startswith("worker-heartbeat-")
    ]
    assert heartbeat_entries
    assert all(entry["options"].get("expires") for entry in heartbeat_entries)
