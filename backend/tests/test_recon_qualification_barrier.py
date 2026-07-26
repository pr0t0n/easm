from __future__ import annotations

import inspect
from datetime import datetime
from types import SimpleNamespace


def _item(
    *,
    phase_id: str,
    tool_name: str,
    status: str,
    targets: list[str],
    stdout: str = "",
    stdout_full: str = "",
    parsed_result=None,
    batch_targets: list[str] | None = None,
):
    return SimpleNamespace(
        id=101,
        phase_id=phase_id,
        tool_name=tool_name,
        target="__batch__" if len(targets) > 1 else targets[0],
        status=status,
        item_metadata={"batch_targets": targets} if len(targets) > 1 else {},
        result={
            "stdout_preview": stdout,
            "stdout_full": stdout_full,
            "parsed_result": parsed_result,
            "batch_targets": batch_targets or [],
            "batch_target_count": len(batch_targets or []),
        },
        finished_at=datetime(2026, 7, 23, 12, 0, 0),
        updated_at=datetime(2026, 7, 23, 12, 0, 0),
    )


def test_dns_outage_preserves_targets_as_inconclusive_instead_of_dead(monkeypatch) -> None:
    from app.services import scan_intelligence

    monkeypatch.setattr(scan_intelligence, "_resolve_hosts_via_kali_dnsx", lambda *args, **kwargs: {})
    monkeypatch.setattr(scan_intelligence, "_resolve_host", lambda host: None)

    result = scan_intelligence.refine_target_set(
        "valid.com",
        ["api.valid.com", "login.valid.com"],
    )

    assert result["resolution_complete"] is False
    assert result["dead_targets"] == []
    assert result["live_targets"] == [
        "valid.com",
        "api.valid.com",
        "login.valid.com",
    ]
    assert result["inconclusive_targets"] == result["live_targets"]


def test_p02_batch_records_ports_per_target_without_inventing_ports() -> None:
    from app.services.scan_work_queue import (
        qualified_targets_for_gate,
        record_recon_work_item_evidence,
    )

    targets = ["api.valid.com", "login.valid.com"]
    job = SimpleNamespace(state_data={"qualification_contract_version": 2})
    item = _item(
        phase_id="P02",
        tool_name="naabu",
        status="completed",
        targets=targets,
        stdout="api.valid.com:443\n",
        parsed_result=["api.valid.com:443"],
    )

    record_recon_work_item_evidence(job, item)

    profiles = job.state_data["preflight"]["targets"]
    assert profiles["api.valid.com"]["open_ports"] == [443]
    assert profiles["login.valid.com"]["open_ports"] == []
    assert profiles["api.valid.com"]["status"] == "tcp_live"
    assert profiles["login.valid.com"]["status"] == "tcp_scanned_no_open_ports"
    assert qualified_targets_for_gate(job.state_data, "P02", targets) == targets


def test_failed_p02_does_not_qualify_or_unlock_target() -> None:
    from app.services.scan_work_queue import (
        qualified_targets_for_gate,
        record_recon_work_item_evidence,
    )

    job = SimpleNamespace(state_data={"qualification_contract_version": 2})
    item = _item(
        phase_id="P02",
        tool_name="naabu",
        status="failed",
        targets=["api.valid.com"],
    )

    record_recon_work_item_evidence(job, item)

    profile = job.state_data["preflight"]["targets"]["api.valid.com"]
    assert profile["p02_complete"] is False
    assert profile["status"] == "p02_inconclusive"
    assert qualified_targets_for_gate(job.state_data, "P02", ["api.valid.com"]) == []


def test_missing_qualification_contract_fails_closed() -> None:
    from app.services.scan_work_queue import qualified_targets_for_gate

    assert qualified_targets_for_gate({}, "P06", ["api.valid.com"]) == []


def test_runtime_state_merge_preserves_p02_p06_qualification() -> None:
    from app.workers.tasks import _merge_runtime_scan_state

    stale_snapshot = {
        "qualification_contract_version": 2,
        "preflight": {
            "targets": {
                "api.valid.com": {
                    "status": "dns_live",
                    "p02_complete": False,
                    "p06_complete": False,
                    "open_ports": [],
                    "http": [],
                }
            }
        },
        "tcp_live_targets": [],
        "http_live_targets": [],
        "qualified_target_set": [],
    }
    durable_state = {
        "qualification_contract_version": 3,
        "preflight": {
            "targets": {
                "api.valid.com": {
                    "status": "http_live",
                    "p02_complete": True,
                    "p06_complete": True,
                    "p06_http_live": True,
                    "open_ports": [443],
                    "http": [{"url": "https://api.valid.com", "status_code": 200}],
                }
            }
        },
        "tcp_live_targets": ["api.valid.com"],
        "http_live_targets": ["api.valid.com"],
        "qualified_target_set": ["api.valid.com"],
    }

    merged = _merge_runtime_scan_state(stale_snapshot, durable_state)

    profile = merged["preflight"]["targets"]["api.valid.com"]
    assert merged["qualification_contract_version"] == 3
    assert profile["status"] == "http_live"
    assert profile["p02_complete"] is True
    assert profile["p06_complete"] is True
    assert profile["p06_http_live"] is True
    assert profile["open_ports"] == [443]
    assert merged["http_live_targets"] == ["api.valid.com"]
    assert merged["qualified_target_set"] == ["api.valid.com"]


def test_partial_p02_accepts_positive_ports_without_treating_silence_as_negative() -> None:
    from app.services.scan_work_queue import (
        qualified_targets_for_gate,
        record_recon_work_item_evidence,
    )

    targets = ["api.valid.com", "login.valid.com"]
    job = SimpleNamespace(state_data={"qualification_contract_version": 3})
    item = _item(
        phase_id="P02",
        tool_name="naabu",
        status="timeout",
        targets=targets,
        stdout="api.valid.com:443\n",
        batch_targets=targets,
    )

    record_recon_work_item_evidence(job, item)

    profiles = job.state_data["preflight"]["targets"]
    assert profiles["api.valid.com"]["p02_complete"] is True
    assert profiles["api.valid.com"]["open_ports"] == [443]
    assert profiles["api.valid.com"]["status"] == "tcp_live"
    assert profiles["login.valid.com"]["p02_complete"] is False
    assert profiles["login.valid.com"]["status"] == "p02_inconclusive"
    assert qualified_targets_for_gate(job.state_data, "P02", targets) == ["api.valid.com"]


def test_partial_p06_accepts_positive_http_without_treating_silence_as_negative() -> None:
    from app.services.scan_work_queue import (
        qualified_targets_for_gate,
        record_recon_work_item_evidence,
    )

    targets = ["api.valid.com", "login.valid.com"]
    job = SimpleNamespace(state_data={"qualification_contract_version": 3})
    item = _item(
        phase_id="P06",
        tool_name="httpx",
        status="timeout",
        targets=targets,
        parsed_result=[{"input": "api.valid.com", "url": "https://api.valid.com"}],
        batch_targets=targets,
    )

    record_recon_work_item_evidence(job, item)

    profiles = job.state_data["preflight"]["targets"]
    assert profiles["api.valid.com"]["p06_complete"] is True
    assert profiles["api.valid.com"]["p06_http_live"] is True
    assert profiles["api.valid.com"]["status"] == "http_live"
    assert profiles["login.valid.com"]["p06_complete"] is False
    assert profiles["login.valid.com"]["status"] == "p06_inconclusive"
    assert qualified_targets_for_gate(job.state_data, "P06", targets) == ["api.valid.com"]


def test_v3_batch_requires_runner_input_coverage_manifest() -> None:
    from app.services.scan_work_queue import (
        qualified_targets_for_gate,
        record_recon_work_item_evidence,
    )

    targets = ["api.valid.com", "login.valid.com"]
    job = SimpleNamespace(state_data={"qualification_contract_version": 3})
    item = _item(
        phase_id="P02",
        tool_name="naabu",
        status="completed",
        targets=targets,
    )

    record_recon_work_item_evidence(job, item)

    profiles = job.state_data["preflight"]["targets"]
    assert profiles["api.valid.com"]["p02_complete"] is False
    assert profiles["login.valid.com"]["p02_complete"] is False
    assert qualified_targets_for_gate(job.state_data, "P02", targets) == []


def test_v3_empty_p02_output_is_conclusive_only_with_exact_input_manifest() -> None:
    from app.services.scan_work_queue import (
        qualified_targets_for_gate,
        record_recon_work_item_evidence,
    )

    targets = ["api.valid.com", "login.valid.com"]
    job = SimpleNamespace(state_data={"qualification_contract_version": 3})
    item = _item(
        phase_id="P02",
        tool_name="naabu",
        status="completed",
        targets=targets,
        batch_targets=targets,
    )

    record_recon_work_item_evidence(job, item)

    profiles = job.state_data["preflight"]["targets"]
    assert profiles["api.valid.com"]["open_ports"] == []
    assert profiles["login.valid.com"]["open_ports"] == []
    assert profiles["api.valid.com"]["p02_input_covered"] is True
    assert profiles["login.valid.com"]["p02_input_covered"] is True
    assert qualified_targets_for_gate(job.state_data, "P02", targets) == targets


def test_p02_parser_uses_full_output_not_only_compressed_preview() -> None:
    from app.services.scan_work_queue import record_recon_work_item_evidence

    targets = ["api.valid.com", "login.valid.com"]
    job = SimpleNamespace(state_data={"qualification_contract_version": 2})
    item = _item(
        phase_id="P02",
        tool_name="naabu",
        status="completed",
        targets=targets,
        stdout="api.valid.com:443\n",
        stdout_full="api.valid.com:443\nlogin.valid.com:8080\n",
    )

    record_recon_work_item_evidence(job, item)

    profiles = job.state_data["preflight"]["targets"]
    assert profiles["api.valid.com"]["open_ports"] == [443]
    assert profiles["login.valid.com"]["open_ports"] == [8080]


def test_p06_only_qualifies_targets_with_actual_http_response() -> None:
    from app.services.scan_work_queue import (
        qualified_targets_for_gate,
        record_recon_work_item_evidence,
    )

    targets = ["api.valid.com", "login.valid.com"]
    job = SimpleNamespace(state_data={"qualification_contract_version": 2})
    item = _item(
        phase_id="P06",
        tool_name="httpx",
        status="completed",
        targets=targets,
        parsed_result=[
            {"input": "api.valid.com", "url": "https://api.valid.com", "status_code": 200},
        ],
    )

    record_recon_work_item_evidence(job, item)

    profiles = job.state_data["preflight"]["targets"]
    assert profiles["api.valid.com"]["status"] == "http_live"
    assert profiles["api.valid.com"]["open_ports"] == [443]
    assert profiles["api.valid.com"]["http_observed_ports"] == [443]
    assert profiles["api.valid.com"]["http"][0]["url"] == "https://api.valid.com"
    assert profiles["api.valid.com"]["http"][0]["status_code"] == 200
    assert profiles["login.valid.com"]["status"] == "no_http_response"
    assert qualified_targets_for_gate(job.state_data, "P06", targets) == ["api.valid.com"]


def test_p09_cannot_reopen_web_work_for_target_rejected_by_p06() -> None:
    from app.services.scan_work_queue import qualified_targets_for_gate

    targets = ["api.valid.com", "login.valid.com"]
    state = {
        "qualification_contract_version": 3,
        "preflight": {
            "targets": {
                "api.valid.com": {"p06_http_live": True},
                "login.valid.com": {"p06_http_live": False},
            }
        },
    }

    assert qualified_targets_for_gate(state, "P09", targets) == ["api.valid.com"]


def test_p09_requires_p06_http_live_on_contract_v2_too() -> None:
    from app.services.scan_work_queue import qualified_targets_for_gate

    targets = ["api.valid.com", "login.valid.com"]
    state = {
        "qualification_contract_version": 2,
        "preflight": {
            "targets": {
                "api.valid.com": {"p06_http_live": True},
                "login.valid.com": {"p06_http_live": False},
            }
        },
    }

    assert qualified_targets_for_gate(state, "P09", targets) == ["api.valid.com"]


def test_p02_open_ports_seed_explicit_nonstandard_http_origins() -> None:
    from app.models.models import ScanWorkItem
    from app.services.scan_work_queue import enqueue_p06_discovered_port_origins

    target = "api.valid.com"
    job = SimpleNamespace(
        id=77,
        state_data={
            "preflight": {
                "targets": {
                    target: {
                        "target": target,
                        "host": target,
                        "status": "tcp_live",
                        "p02_complete": True,
                        "p02_input_covered": True,
                        "open_ports": [80, 443, 8080, 8443],
                    }
                }
            }
        },
    )

    class Query:
        def filter(self, *_args, **_kwargs):
            return self

        def first(self):
            return None

    class Db:
        def __init__(self):
            self.added = []

        def query(self, *_args, **_kwargs):
            return Query()

        def add(self, row):
            self.added.append(row)

        def flush(self):
            return None

    db = Db()
    result = enqueue_p06_discovered_port_origins(db, job, [target])  # type: ignore[arg-type]

    assert result["created"] == 2
    assert {row.target for row in db.added if isinstance(row, ScanWorkItem)} == {
        "http://api.valid.com:8080",
        "https://api.valid.com:8443",
    }
    origin_profile = job.state_data["preflight"]["targets"]["https://api.valid.com:8443"]
    assert origin_profile["p02_complete"] is True
    assert origin_profile["open_ports"] == [8443]


def test_known_empty_port_set_blocks_port_specific_tool() -> None:
    from app.services.scan_work_queue import validate_skill_applicability

    state = {
        "preflight": {
            "targets": {
                "api.valid.com": {
                    "status": "tcp_scanned_no_open_ports",
                    "open_ports": [],
                    "p02_complete": True,
                }
            }
        }
    }

    decision = validate_skill_applicability(
        "P06",
        "skill.recon.port_service_discovery",
        "sslscan",
        "api.valid.com",
        state,
        at="dispatch",
    )

    assert decision["applicable"] is False
    assert decision["reason"] == "required_port_absent:443,8443,9443,10443"


def test_web_phases_depend_on_p06_not_only_p02() -> None:
    from app.services.scan_work_queue import PHASE_GATE, PHASE_PRIORITY

    assert PHASE_PRIORITY["P08"] == 40
    assert PHASE_GATE["P06"] == "P02"
    assert PHASE_GATE["P15"] == "P06"
    for phase_id in ("P03", "P04", "P05", "P07", "P08", "P09", "P15", "P16"):
        assert PHASE_GATE[phase_id] == "P06"


def test_no_http_response_still_schedules_inconclusive_p02() -> None:
    from app.services.scan_work_queue import _eligible_phases_for_target

    state = {
        "preflight": {
            "targets": {
                "api.valid.com": {
                    "status": "no_http_response",
                    "p02_complete": False,
                    "p06_complete": True,
                    "p06_http_live": False,
                }
            }
        }
    }

    phases = _eligible_phases_for_target("api.valid.com", state)

    assert phases == ["P02"]


def test_no_http_response_does_not_schedule_p15_deep_file_testing() -> None:
    from app.services.scan_work_queue import _eligible_phases_for_target

    state = {
        "preflight": {
            "targets": {
                "api.valid.com": {
                    "status": "no_http_response",
                    "p02_complete": True,
                    "p06_complete": True,
                    "p02_positive_evidence": False,
                    "p06_positive_evidence": False,
                    "p06_http_live": False,
                }
            }
        }
    }

    assert _eligible_phases_for_target("api.valid.com", state) == []


def test_no_http_response_preserves_p18_for_primary_scan_target() -> None:
    from app.services.scan_work_queue import _eligible_phases_for_target

    state = {
        "target_query": "valid.com",
        "preflight": {
            "targets": {
                "valid.com": {
                    "status": "no_http_response",
                    "p02_complete": True,
                    "p06_complete": True,
                    "p02_positive_evidence": False,
                    "p06_positive_evidence": False,
                    "p06_http_live": False,
                    "http": [],
                }
            }
        },
    }

    assert _eligible_phases_for_target("valid.com", state) == ["P18"]


def test_p18_does_not_bypass_proven_dead_target() -> None:
    from app.services.scan_work_queue import _eligible_phases_for_target, validate_skill_applicability

    state = {
        "target_query": "valid.com",
        "preflight": {"targets": {"dead.valid.com": {"status": "dns_dead"}}},
    }

    assert _eligible_phases_for_target("dead.valid.com", state) == []

    decision = validate_skill_applicability(
        "P18",
        "skill.chain.exposed_git_to_credential_leak",
        "theharvester",
        "dead.valid.com",
        state,
        at="dispatch",
    )

    assert decision["applicable"] is False
    assert decision["reason"] == "target_not_reachable:dns_dead"


def test_phase_queue_continuations_do_not_bypass_scan_chain_lock() -> None:
    from app.workers import tasks

    source = inspect.getsource(tasks._run_scan_with_retry)
    assert "_acquire_scan_chain_lock(scan_id, _lock_token)" in source
    assert "None if phase_queue_task" not in source


def test_force_release_chain_lock_uses_compare_delete() -> None:
    from app.workers import tasks

    source = inspect.getsource(tasks._force_release_chain_lock)

    assert "redis.call('get', KEYS[1]) == ARGV[1]" in source
    assert "redis.call('del', KEYS[1])" in source


def test_orphan_recovery_locks_scan_row_before_redrive_budget_update() -> None:
    from app.workers import tasks

    source = inspect.getsource(tasks.recover_scan_if_orphaned)

    assert ".with_for_update()" in source
    assert "redrive_count" in source


def test_completion_barrier_requires_explicit_producer_seal() -> None:
    from app.workers.tasks import _scan_work_producers_sealed

    assert _scan_work_producers_sealed({"work_producers_sealed": False}) is False
    assert _scan_work_producers_sealed({"work_producers_sealed": True}) is True
    # Rolling-deploy compatibility for scans created before the marker existed.
    assert _scan_work_producers_sealed({"_operator_phase_queue_started": True}) is True


def test_runtime_state_merge_preserves_sealed_producer_checkpoint() -> None:
    from app.workers.tasks import _merge_runtime_scan_state

    stale_dispatcher_snapshot = {
        "work_producers_sealed": False,
        "work_producer_stage": "P01_discovery",
        "target_set": [],
        "parallel_delegated_targets": [],
    }
    durable_p01_checkpoint = {
        "work_producers_sealed": True,
        "work_producer_stage": "sealed",
        "target_set": ["validcertificadora.com.br"],
        "parallel_delegated_targets": ["validcertificadora.com.br"],
        "parallel_engine": "capacity_work_queue",
        "parallel_batch_size": 1,
    }

    merged = _merge_runtime_scan_state(stale_dispatcher_snapshot, durable_p01_checkpoint)

    assert merged["work_producers_sealed"] is True
    assert merged["work_producer_stage"] == "sealed"
    assert merged["target_set"] == ["validcertificadora.com.br"]
    assert merged["parallel_delegated_targets"] == ["validcertificadora.com.br"]
    assert merged["parallel_engine"] == "capacity_work_queue"
    assert merged["parallel_batch_size"] == 1


def test_p01_persists_producer_checkpoint_before_dispatcher_wakeup() -> None:
    from app.services import offensive_operator_runner

    source = inspect.getsource(offensive_operator_runner.run_offensive_operator_scan)
    checkpoint = "Persist the producer checkpoint before waking the"
    checkpoint_pos = source.index(checkpoint)
    assign_pos = source.index("job.state_data = _cp_state", checkpoint_pos)
    commit_pos = source.index("db.commit()", assign_pos)
    dispatch_pos = source.index("_dispatch_wq(job.id)", commit_pos)

    assert checkpoint_pos < assign_pos < commit_pos < dispatch_pos


def test_claim_fairness_discovers_phases_before_limiting_items() -> None:
    from app.services import scan_work_queue

    source = inspect.getsource(scan_work_queue.claim_work_items)
    assert "group_by(ScanWorkItem.phase_id)" in source
    assert ".limit(max(to_claim * 6, 60))" not in source
