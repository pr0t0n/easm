import inspect


def test_run_scan_preflight_happens_before_chain_lock() -> None:
    from app.workers import tasks

    source = inspect.getsource(tasks._run_scan_with_retry)

    preflight_pos = source.index("_scan_execution_preflight(scan_id)")
    lock_pos = source.index("_acquire_scan_chain_lock(scan_id")
    contention_preflight_pos = source.index("_scan_execution_preflight(scan_id)", lock_pos)
    contention_log_pos = source.index("chain_lock_contended", lock_pos)

    assert preflight_pos < lock_pos
    assert lock_pos < contention_preflight_pos < contention_log_pos


def test_terminal_preflight_source_contract() -> None:
    from app.workers import tasks

    source = inspect.getsource(tasks._scan_execution_preflight)

    assert "HALTED_SCAN_STATUSES" in source
    assert "TERMINAL_SCAN_STATUSES" in source
    assert "scan_not_found" in source
    assert "scan_{status}" in source


def test_scan_work_item_insert_guard_rejects_terminal_scan() -> None:
    """The guard no longer raises here (it used to, and the exception fired
    mid-flush -- before_insert -- poisoning the caller's SQLAlchemy session:
    "This Session's transaction has been rolled back...". Confirmed live:
    this cascaded into 3 failed retries of an unfixable condition and
    clobbered an already-`completed` scan's status back to `failed`.
    Converting the item to a terminal "skipped" row on insert gives the same
    "closed scans never receive new active work" guarantee without ever
    raising mid-flush."""
    from app.models.models import ScanWorkItem, _guard_scan_work_item_insert

    class Result:
        def scalar_one_or_none(self):
            return "completed_with_gaps"

    class Connection:
        def execute(self, *_args, **_kwargs):
            return Result()

    item = ScanWorkItem(
        scan_job_id=58,
        phase_id="P21",
        target="https://example.test/api/v1/webhook",
        tool_name="nuclei-ssrf",
        status="queued",
    )

    _guard_scan_work_item_insert(None, Connection(), item)

    assert item.status == "skipped"
    assert item.item_metadata["rejected_for_terminal_scan"]["scan_status"] == "completed_with_gaps"


def test_scan_work_item_insert_guard_allows_terminal_item_status() -> None:
    from app.models.models import ScanWorkItem, _guard_scan_work_item_insert

    class Connection:
        def execute(self, *_args, **_kwargs):
            raise AssertionError("terminal item statuses should not query scan state")

    item = ScanWorkItem(
        scan_job_id=58,
        phase_id="P21",
        target="https://example.test/api/v1/webhook",
        tool_name="nuclei-ssrf",
        status="skipped",
    )

    _guard_scan_work_item_insert(None, Connection(), item)


def test_scan_work_item_insert_guard_allows_fully_bound_post_scan_wire() -> None:
    from app.models.models import ScanWorkItem, _guard_scan_work_item_insert

    class Result:
        def scalar_one_or_none(self):
            return "cancelled"

    class Connection:
        def execute(self, *_args, **_kwargs):
            return Result()

    item = ScanWorkItem(
        scan_job_id=58,
        phase_id="P21",
        target="https://example.test/api/v1/webhook",
        tool_name="nuclei-ssrf",
        status="queued",
        item_metadata={
            "post_scan_revalidation": True,
            "validation_wire_id": 9,
            "verifies_finding_id": 71,
            "adjudication_id": 12,
        },
    )

    _guard_scan_work_item_insert(None, Connection(), item)

    assert item.status == "queued"
    assert "rejected_for_terminal_scan" not in item.item_metadata


def test_scan_work_item_insert_guard_rejects_unbound_post_scan_flag() -> None:
    from app.models.models import ScanWorkItem, _guard_scan_work_item_insert

    class Result:
        def scalar_one_or_none(self):
            return "completed"

    class Connection:
        def execute(self, *_args, **_kwargs):
            return Result()

    item = ScanWorkItem(
        scan_job_id=58,
        phase_id="P21",
        target="https://example.test/",
        tool_name="nuclei",
        status="queued",
        item_metadata={"post_scan_revalidation": True, "validation_wire_id": 9},
    )

    _guard_scan_work_item_insert(None, Connection(), item)

    assert item.status == "skipped"
    assert item.item_metadata["rejected_for_terminal_scan"]["scan_status"] == "completed"
