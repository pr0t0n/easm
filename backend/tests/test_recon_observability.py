from types import SimpleNamespace

from app.services.recon_observability import (
    _gate_snapshot,
    _profile_summary,
    _scan_assessment,
)


def _item(
    *,
    phase_id: str,
    tool_name: str,
    status: str,
    target: str = "__batch__",
    result: dict | None = None,
):
    return SimpleNamespace(
        phase_id=phase_id,
        tool_name=tool_name,
        status=status,
        target=target,
        result=result or {},
    )


def test_profile_summary_counts_qualification_per_target() -> None:
    state = {
        "preflight": {
            "targets": {
                "a.example": {
                    "dns_resolves": True,
                    "p02_input_covered": True,
                    "p02_complete": True,
                    "open_ports": [80, 443],
                    "p06_input_covered": True,
                    "p06_complete": True,
                    "p06_http_live": True,
                },
                "b.example": {
                    "status": "dns_inconclusive",
                    "p02_input_covered": True,
                    "p02_complete": True,
                    "open_ports": [],
                    "p06_input_covered": True,
                    "p06_complete": True,
                    "p06_http_live": False,
                },
            }
        }
    }

    summary = _profile_summary(state)

    assert summary["profiles_total"] == 2
    assert summary["dns_resolved"] == 1
    assert summary["dns_inconclusive"] == 1
    assert summary["p02_input_covered"] == 2
    assert summary["targets_with_open_ports"] == 1
    assert summary["open_ports_observed"] == 2
    assert summary["p06_input_covered"] == 2
    assert summary["http_live"] == 1
    assert summary["no_http_response"] == 1


def test_gate_snapshot_exposes_normal_running_wait_and_manifest_coverage() -> None:
    item = _item(
        phase_id="P02",
        tool_name="naabu",
        status="running",
        result={
            "batch_targets": ["a.example", "b.example"],
            "batch_target_file_sha256": "abc123",
        },
    )

    snapshot = _gate_snapshot(
        "P02",
        [item],
        {"p02_complete": 0, "p02_input_covered": 0},
        downstream_blocked=20,
        contract_version=3,
        scan_status="running",
    )

    assert snapshot["state"] == "running"
    assert snapshot["normal_wait"] is True
    assert snapshot["active_items"] == 1
    assert snapshot["manifested_batches"] == 1
    assert snapshot["manifest_targets"] == 2
    assert snapshot["downstream_blocked"] == 20


def test_gate_snapshot_marks_active_gate_after_completion_inconsistent() -> None:
    item = _item(phase_id="P06", tool_name="httpx", status="submitted")

    snapshot = _gate_snapshot(
        "P06",
        [item],
        {"http_live": 0, "p06_input_covered": 0},
        downstream_blocked=100,
        contract_version=3,
        scan_status="completed_with_gaps",
    )

    assert snapshot["state"] == "terminal_inconsistent"
    assert snapshot["normal_wait"] is False
    assert "terminal" in snapshot["reason"].lower()


def test_scan_assessment_distinguishes_platform_failure_from_clean_execution() -> None:
    platform_failure = _scan_assessment(
        {
            "status": "completed_with_gaps",
            "qualification_contract_version": 2,
            "successful_items": 3,
            "failed_items": 2,
            "blocked_items": 2846,
            "active_items": 311,
            "skills_attributed": 11,
            "skills_executed": 2,
            "phases_with_success": 2,
        }
    )
    executed = _scan_assessment(
        {
            "status": "completed_with_gaps",
            "qualification_contract_version": 3,
            "successful_items": 3070,
            "failed_items": 352,
            "blocked_items": 0,
            "active_items": 0,
            "skills_attributed": 12,
            "skills_executed": 12,
            "phases_with_success": 17,
        }
    )

    assert platform_failure["category"] == "platform_orchestration_failure"
    assert platform_failure["reliable_negative"] is False
    assert executed["category"] == "executed"
    assert executed["reliable_negative"] is True
