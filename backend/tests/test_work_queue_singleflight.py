from __future__ import annotations


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.expirations: dict[str, int] = {}

    def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def get(self, key: str):
        return self.values.get(key)

    def delete(self, key: str):
        return int(self.values.pop(key, None) is not None)

    def expire(self, key: str, ttl: int):
        if key not in self.values:
            return False
        self.expirations[key] = ttl
        return True


class FakeTask:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    def apply_async(self, *, args, kwargs, countdown):
        self.messages.append({"args": args, "kwargs": kwargs, "countdown": countdown})


class FakeRoutedTask(FakeTask):
    def apply_async(self, *, args, kwargs, countdown, queue):
        self.messages.append({
            "args": args,
            "kwargs": kwargs,
            "countdown": countdown,
            "queue": queue,
        })


def test_dispatch_schedule_has_only_one_pending_message(monkeypatch) -> None:
    from app.services import scan_work_queue
    from app.workers import tasks

    redis = FakeRedis()
    task = FakeTask()
    monkeypatch.setattr(scan_work_queue, "_redis_client", lambda: redis)
    monkeypatch.setattr(tasks, "dispatch_scan_work_items", task)

    assert tasks._schedule_scan_work_dispatch(12, countdown=30) is True
    assert tasks._schedule_scan_work_dispatch(12, countdown=30) is False
    assert len(task.messages) == 1

    token = task.messages[0]["kwargs"]["_dispatch_token"]
    assert tasks._singleflight_claim("dispatch_pending:12", token) is True
    assert tasks._schedule_scan_work_dispatch(12, countdown=30) is True
    assert len(task.messages) == 2


def test_poll_schedule_is_unique_per_work_item(monkeypatch) -> None:
    from app.services import scan_work_queue
    from app.workers import tasks

    redis = FakeRedis()
    task = FakeRoutedTask()
    monkeypatch.setattr(scan_work_queue, "_redis_client", lambda: redis)
    monkeypatch.setattr(tasks, "poll_scan_work_item", task)

    assert tasks._schedule_work_item_poll(45227, countdown=15) is True
    assert tasks._schedule_work_item_poll(45227, countdown=1) is False
    assert tasks._schedule_work_item_poll(45368, countdown=1) is True
    assert len(task.messages) == 2
    assert all(message["queue"] == "scan.poll" for message in task.messages)


def test_stale_token_cannot_claim_newer_message(monkeypatch) -> None:
    from app.services import scan_work_queue
    from app.workers import tasks

    redis = FakeRedis()
    redis.values["poll_pending:9"] = "new-token"
    monkeypatch.setattr(scan_work_queue, "_redis_client", lambda: redis)

    assert tasks._singleflight_claim("poll_pending:9", "old-token") is False
    assert redis.get("poll_pending:9") == "new-token"


def test_singleflight_claim_accepts_redis_bytes_token(monkeypatch) -> None:
    from app.services import scan_work_queue
    from app.workers import tasks

    redis = FakeRedis()
    redis.values["poll_pending:9"] = b"token-9"
    monkeypatch.setattr(scan_work_queue, "_redis_client", lambda: redis)

    assert tasks._singleflight_claim("poll_pending:9", "token-9") is True
    assert redis.get("poll_pending:9") is None


def test_missing_singleflight_key_is_guarded_not_unbounded(monkeypatch) -> None:
    from app.services import scan_work_queue
    from app.workers import tasks

    redis = FakeRedis()
    monkeypatch.setattr(scan_work_queue, "_redis_client", lambda: redis)

    assert tasks._singleflight_claim("poll_pending:9", "expired-token") is True
    assert tasks._singleflight_claim("poll_pending:9", "expired-token") is False


def test_scan_chain_lock_release_accepts_redis_bytes_token() -> None:
    from app.workers import tasks

    redis = FakeRedis()
    redis.values["scan_chain_lock:20"] = b"chain-token"

    tasks._release_scan_chain_lock(redis, 20, "chain-token")

    assert redis.get("scan_chain_lock:20") is None


def test_scan_chain_lock_release_preserves_newer_token() -> None:
    from app.workers import tasks

    redis = FakeRedis()
    redis.values["scan_chain_lock:20"] = b"newer-token"

    tasks._release_scan_chain_lock(redis, 20, "old-token")

    assert redis.get("scan_chain_lock:20") == b"newer-token"


def test_inventory_refresh_is_coalesced_and_routed_off_poll_queue(monkeypatch) -> None:
    from app.services import scan_work_queue
    from app.workers import tasks

    redis = FakeRedis()
    task = FakeRoutedTask()
    monkeypatch.setattr(scan_work_queue, "_redis_client", lambda: redis)
    monkeypatch.setattr(tasks, "refresh_pentest_inventory", task)

    assert tasks._schedule_pentest_inventory_refresh(12, countdown=2) is True
    assert tasks._schedule_pentest_inventory_refresh(12, countdown=2) is False
    assert len(task.messages) == 1
    assert task.messages[0]["queue"] != "scan.parallel"
    assert task.messages[0]["kwargs"]["_inventory_token"]

    redis.delete("pentest_inventory_pending:12")
    redis.values["pentest_inventory_cooldown:12"] = "active"
    assert tasks._schedule_pentest_inventory_refresh(12, countdown=2) is False
    assert len(task.messages) == 1


def test_business_logic_analysis_is_unique_per_target_and_off_poll_queue(monkeypatch) -> None:
    from app.services import scan_work_queue
    from app.workers import tasks

    redis = FakeRedis()
    task = FakeRoutedTask()
    monkeypatch.setattr(scan_work_queue, "_redis_client", lambda: redis)
    monkeypatch.setattr(tasks, "run_business_logic_analysis_postprocess", task)

    assert tasks._schedule_business_logic_analysis(12, 77, "app.example.test") is True
    assert tasks._schedule_business_logic_analysis(12, 78, "app.example.test") is False
    assert tasks._schedule_business_logic_analysis(12, 79, "api.example.test") is True
    assert len(task.messages) == 2
    assert all(message["queue"] != "scan.parallel" for message in task.messages)


def test_legacy_delivery_guard_collapses_duplicate_messages(monkeypatch) -> None:
    from app.services import scan_work_queue
    from app.workers import tasks

    redis = FakeRedis()
    monkeypatch.setattr(scan_work_queue, "_redis_client", lambda: redis)

    assert tasks._legacy_delivery_allowed("poll_legacy_guard:7", ttl=10) is True
    assert tasks._legacy_delivery_allowed("poll_legacy_guard:7", ttl=10) is False
