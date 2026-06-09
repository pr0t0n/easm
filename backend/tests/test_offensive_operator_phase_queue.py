from __future__ import annotations

from pathlib import Path

from app.services.offensive_operator_runner import _next_pending_phase_target
from app.workers.worker_groups import group_for_phase, phase_queue


def test_phase_queue_routes_operator_phases_to_kill_chain_workers() -> None:
    assert group_for_phase("P01") == "reconnaissance"
    assert phase_queue("P01", mode="unit") == "worker.unit.reconnaissance"
    assert group_for_phase("P13") == "exploitation"
    assert phase_queue("P13", mode="unit") == "worker.unit.exploitation"
    assert group_for_phase("P14") == "installation"
    assert phase_queue("P22", mode="scheduled") == "worker.scheduled.reporting"


def test_next_pending_phase_target_preserves_kill_chain_order() -> None:
    targets = ["example.com", "app.example.com"]

    assert _next_pending_phase_target(targets, set(), 1, None) == ("P01", "example.com")
    assert _next_pending_phase_target(targets, {"P01:example.com"}, 1, None) == ("P02", "example.com")


def test_next_pending_phase_target_skips_p01_for_discovered_subdomains() -> None:
    targets = ["example.com", "app.example.com"]
    completed = {f"P{i:02d}:example.com" for i in range(1, 23)}

    assert _next_pending_phase_target(targets, completed, 1, None) == ("P02", "app.example.com")
    assert _next_pending_phase_target(targets, completed, 1, None, {"app.example.com"}) is None


def test_work_queue_dispatches_items_to_phase_queues() -> None:
    backend_root = Path(__file__).resolve().parents[1]
    source = (backend_root / "app/workers/tasks.py").read_text(encoding="utf-8")

    assert "phase_queue(_phase_id" in source
    assert "execute_scan_work_item.apply_async" in source
    assert "execute_scan_work_item.delay(item_id)" not in source
