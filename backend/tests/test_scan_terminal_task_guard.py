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
