"""bas_scheduler.py: due-time evaluation (mirrors scheduler_tick's idempotency
logic) and the shadow-ScanJob target_query fix (kali_runner rejects any
dispatch with an empty authorized_scope -- resolve_authorized_scope_for_
dispatch derives that scope from the ScanJob's target_query, so it must be
the schedule's real target_hint, never a synthetic label)."""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.models.models import BasAgent, BasJob, ScanJob
from app.services.bas_scheduler import (
    _create_shadow_scan_job,
    _derive_severity,
    _extract_key_findings,
    _finding_from_job_result,
    _is_due,
    _port_scan_chunks,
    _port_scan_max_wait,
    _split_targets,
    execute_schedule_run,
    fire_schedule,
    resume_schedule_run,
)
from app.services.bas_technique_catalog import get_technique


def _schedule(**overrides):
    base = dict(
        frequency="daily", run_time="03:00", day_of_week=None, day_of_month=None,
        last_run_at=None, owner_id=1, access_group_id=None, target_hint="10.10.10.5", id=1,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_daily_schedule_is_due_at_its_run_time_and_not_yet_run_today():
    now = datetime(2026, 8, 18, 3, 0)
    assert _is_due(_schedule(frequency="daily", run_time="03:00"), now) is True


def test_daily_schedule_not_due_outside_its_run_time():
    now = datetime(2026, 8, 18, 3, 1)
    assert _is_due(_schedule(frequency="daily", run_time="03:00"), now) is False


def test_daily_schedule_not_due_twice_in_the_same_day():
    now = datetime(2026, 8, 18, 3, 0)
    already_ran_today = _schedule(frequency="daily", run_time="03:00", last_run_at=datetime(2026, 8, 18, 3, 0))
    assert _is_due(already_ran_today, now) is False


def test_weekly_schedule_checks_day_of_week():
    now = datetime(2026, 8, 18, 3, 0)  # a Tuesday
    assert _is_due(_schedule(frequency="weekly", run_time="03:00", day_of_week="tuesday"), now) is True
    assert _is_due(_schedule(frequency="weekly", run_time="03:00", day_of_week="monday"), now) is False


def test_monthly_schedule_checks_day_of_month():
    now = datetime(2026, 8, 18, 3, 0)
    assert _is_due(_schedule(frequency="monthly", run_time="03:00", day_of_month=18), now) is True
    assert _is_due(_schedule(frequency="monthly", run_time="03:00", day_of_month=1), now) is False


def test_interval_frequency_due_when_never_run():
    now = datetime(2026, 8, 18, 3, 0)
    assert _is_due(_schedule(frequency="every_3_hours", last_run_at=None), now) is True


def test_interval_frequency_not_due_before_interval_elapses():
    now = datetime(2026, 8, 18, 3, 0)
    last_run = datetime(2026, 8, 18, 1, 30)  # only 90 min ago, interval is 180
    assert _is_due(_schedule(frequency="every_3_hours", last_run_at=last_run), now) is False


def test_interval_frequency_due_once_interval_elapses():
    now = datetime(2026, 8, 18, 5, 0)
    last_run = datetime(2026, 8, 18, 1, 30)  # 210 min ago, interval is 180
    assert _is_due(_schedule(frequency="every_3_hours", last_run_at=last_run), now) is True


def _agent(**overrides):
    base = dict(id=13, kind="real", hostname="mac.local", tunnel_host="", tunnel_port=None, local_network_cidr=None)
    base.update(overrides)
    return SimpleNamespace(**base)


def _wire_db_for_agent(db, agent):
    """Wires a MagicMock DB session for fire_schedule/execute_schedule_run
    tests that don't care about resume: BasAgent/ScanJob lookups resolve to
    `agent` (harmless aliasing -- none of these tests assert on shadow/agent
    identity), while both idempotency checks -- the mandatory port_service_
    scan pre-req's "did it already run for this target" (db.query(BasJob)...)
    and the regular per-technique resume check (db.query(BasJob.id)...) --
    always report "nothing dispatched yet", matching a fresh, non-resumed
    run, so both the pre-req and every selected technique still dispatch
    like before either check existed."""
    def fake_query(*entities):
        m = MagicMock()
        if entities and entities[0] is BasJob.id:
            m.filter.return_value.first.return_value = None
        elif entities and entities[0] is BasJob:
            m.filter.return_value.order_by.return_value.first.return_value = None
        else:
            m.filter.return_value.first.return_value = agent
        return m
    db.query.side_effect = fake_query


def test_shadow_scan_job_target_query_is_the_real_target_hint_not_a_synthetic_label():
    """Regression: a synthetic label like 'bas:schedule#1' parses to no valid
    scope root at all, so kali_runner's authorized_scope-required check
    would fail-closed on every single dispatch through this shadow job."""
    db = MagicMock()
    schedule = _schedule(target_hint="10.10.10.5")

    shadow = _create_shadow_scan_job(db, schedule, _agent())

    assert shadow.target_query == "10.10.10.5"
    assert shadow.mode == "bas"
    db.add.assert_called_once_with(shadow)
    db.flush.assert_called_once()


def test_shadow_scan_job_uses_the_agents_own_network_when_target_hint_is_blank():
    db = MagicMock()
    schedule = _schedule(target_hint="")

    shadow = _create_shadow_scan_job(db, schedule, _agent(local_network_cidr="10.10.10.5/24"))

    assert shadow.target_query == "10.10.10.5/24"


def test_shadow_scan_job_falls_back_to_a_placeholder_when_target_hint_and_agent_network_are_both_blank():
    db = MagicMock()
    schedule = _schedule(target_hint="")

    shadow = _create_shadow_scan_job(db, schedule, _agent(local_network_cidr=None))

    assert shadow.target_query  # never empty -- an empty target_query also fails scope resolution
    assert "1" in shadow.target_query


def _job(**overrides):
    base = dict(id=1, scan_job_id=1, target="10.10.10.5", result={"command": "smbmap -H 127.0.0.1", "status": "executed"})
    base.update(overrides)
    return SimpleNamespace(**base)


def test_finding_from_job_result_never_creates_a_finding_for_a_stub_agent_dispatch():
    """A stub's key_findings is always [] by construction (it never gets to
    claim a real observation) -- since 2026-08-28, empty key_findings means
    no Finding is created at all, so every stub dispatch is now a no-op
    here. The BasJob row is still the execution record; it just never
    becomes a fake "(simulado)" placeholder Finding anymore."""
    db = MagicMock()
    agent = SimpleNamespace(id=1, kind="stub")
    technique = get_technique("network_share_discovery")

    finding = _finding_from_job_result(db, _job(), _schedule(), technique, agent)

    assert finding is None


def test_finding_from_job_result_skips_a_real_dispatch_with_no_observed_signal():
    """No stdout content at all -- key_findings comes back empty, so this
    must not create a noise Finding just because a real agent ran a tool."""
    db = MagicMock()
    agent = SimpleNamespace(id=9, kind="real")
    technique = get_technique("network_share_discovery")

    finding = _finding_from_job_result(db, _job(), _schedule(), technique, agent)

    assert finding is None


def test_finding_from_job_result_marks_real_agent_dispatch_as_not_simulated():
    db = MagicMock()
    agent = SimpleNamespace(id=9, kind="real")
    technique = get_technique("network_share_discovery")
    job = _job(result={
        "command": "smbmap -H 127.0.0.1",
        "stdout": "Disk1    open share    ADMIN$\n",
        "status": "executed",
    })

    finding = _finding_from_job_result(db, job, _schedule(), technique, agent)

    assert finding.details["simulated"] is False
    assert finding.details["counts_towards_score"] is True
    assert finding.details["counts_towards_attack_path"] is True
    assert finding.details["proof"]["status"] == "validated"
    assert finding.verification_status == "confirmed"
    assert "(simulado)" not in finding.title
    assert finding.details["bas_agent_id"] == 9
    assert finding.details["bas_agent_kind"] == "real"


def test_split_targets_splits_on_comma_semicolon_and_newline():
    assert _split_targets("10.0.0.5, app-db.internal", "fallback") == ["10.0.0.5", "app-db.internal"]
    assert _split_targets("10.0.0.5;app-db.internal", "fallback") == ["10.0.0.5", "app-db.internal"]
    assert _split_targets("10.0.0.5\napp-db.internal", "fallback") == ["10.0.0.5", "app-db.internal"]


def test_split_targets_single_value_returns_one_element_list():
    assert _split_targets("10.0.0.5", "fallback") == ["10.0.0.5"]


def test_split_targets_falls_back_when_blank():
    assert _split_targets("", "fallback") == ["fallback"]
    assert _split_targets("   ", "fallback") == ["fallback"]


def test_port_scan_max_wait_floors_at_the_fast_prereq_timeout_for_a_single_host():
    assert _port_scan_max_wait("10.10.10.5") == 60
    assert _port_scan_max_wait("10.10.10.0/30") == 60


def test_port_scan_max_wait_scales_up_for_a_large_network():
    assert _port_scan_max_wait("10.10.10.0/26") == 64 * 4


def test_port_scan_max_wait_caps_at_a_sane_ceiling_for_a_huge_network():
    assert _port_scan_max_wait("10.0.0.0/8") == 300


def test_port_scan_max_wait_falls_back_to_the_fast_prereq_timeout_for_a_non_cidr_target():
    assert _port_scan_max_wait("not-a-valid-target") == 60


def test_port_scan_chunks_leaves_a_small_range_alone():
    assert _port_scan_chunks("10.10.10.5") == ["10.10.10.5"]
    assert _port_scan_chunks("10.10.10.0/28") == ["10.10.10.0/28"]


def test_port_scan_chunks_splits_a_large_network_into_28_bit_blocks():
    """Explicit user decision (2026-08-28): a monolithic port scan of an
    entire large network left progress/CMDB empty for 30+ minutes with
    nothing to show -- chunking gives incremental feedback instead."""
    chunks = _port_scan_chunks("10.10.128.0/20")
    assert len(chunks) == 256
    assert chunks[0] == "10.10.128.0/28"
    assert chunks[-1] == "10.10.143.240/28"


def test_port_scan_chunks_falls_back_to_the_whole_target_for_a_non_cidr_value():
    assert _port_scan_chunks("not-a-valid-target") == ["not-a-valid-target"]


def test_fire_schedule_defaults_to_the_agents_own_network_when_target_hint_is_blank():
    db = MagicMock()
    agent = _agent(local_network_cidr="10.10.10.5/24")
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["port_service_scan"]

    with patch(
        "app.services.bas_scheduler.dispatch_bas_technique",
        return_value={"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"},
    ) as mock_dispatch:
        result = fire_schedule(db, schedule)

    assert mock_dispatch.call_count == 16
    assert mock_dispatch.call_args_list[0].kwargs["target_hint"] == "10.10.10.0/28"
    assert mock_dispatch.call_args_list[-1].kwargs["target_hint"] == "10.10.10.240/28"
    assert len(result["job_ids"]) == 16


def test_fire_schedule_expands_agent_network_for_host_based_techniques():
    """port_service_scan always runs first now (mandatory CMDB pre-req,
    against the whole CIDR) -- network_share_discovery (SMB, port 445) then
    only fans out to hosts the pre-req actually found port 445 open on."""
    db = MagicMock()
    agent = _agent(local_network_cidr="10.10.10.0/30")
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["network_share_discovery"]

    with patch(
        "app.services.bas_scheduler.dispatch_bas_technique",
        return_value={
            "dispatched": True,
            "result": {
                "status": "executed",
                "open_ports": [
                    {"host": "10.10.10.1", "port": 445, "protocol": "tcp", "service": "microsoft-ds"},
                    {"host": "10.10.10.2", "port": 445, "protocol": "tcp", "service": "microsoft-ds"},
                ],
            },
            "agent_kind": "real",
        },
    ) as mock_dispatch:
        result = fire_schedule(db, schedule)

    assert [call.kwargs["target_hint"] for call in mock_dispatch.call_args_list] == [
        "10.10.10.0/30", "10.10.10.1", "10.10.10.2",
    ]
    assert len(result["job_ids"]) == 3  # port scan + 2 network_share_discovery dispatches


def test_fire_schedule_expands_host_fanout_with_no_upper_bound():
    """No cap on how large a network a host-based technique fans out over --
    explicit user decision (2026-08-28): a prior session added a 256-host
    fanout ceiling nobody asked for, silently skipping techniques against
    larger agent networks. Removed entirely, not replaced with a bigger cap.
    Uses an ungated technique (no required_ports) so the port-scan CMDB
    gate added later the same day doesn't interfere with this assertion."""
    db = MagicMock()
    agent = _agent(local_network_cidr="10.10.0.0/23")  # 510 usable hosts, well past the old 256-host ceiling
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["owasp_web_app_scan"]  # safe tier, ungated, host-based

    with patch(
        "app.services.bas_scheduler.dispatch_bas_technique",
        return_value={"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"},
    ) as mock_dispatch:
        result = fire_schedule(db, schedule)

    assert mock_dispatch.call_count == 542  # mandatory port scan (32 /28 chunks for a /23) + 510 hosts
    assert result["skipped"] == []
    assert len(result["job_ids"]) == 542


def test_fire_schedule_skips_everything_with_a_clear_reason_when_agent_network_is_unknown():
    """The agent binary predates local_network_cidr, or hasn't sent a
    heartbeat yet -- never guess a target, never fall back to a meaningless
    placeholder that would just 400 at kali_runner with no clear signal why."""
    db = MagicMock()
    agent = _agent(local_network_cidr=None)
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="", agent_id=13)
    schedule.technique_keys = ["port_service_scan", "smb_enum_cme"]

    with patch("app.services.bas_scheduler.dispatch_bas_technique") as mock_dispatch:
        result = fire_schedule(db, schedule)

    mock_dispatch.assert_not_called()
    assert result["job_ids"] == []
    assert len(result["skipped"]) == 2
    assert all(s["reason"] == "agent_network_unknown_send_a_heartbeat_first" for s in result["skipped"])


def test_fire_schedule_dispatches_one_job_per_technique_per_target():
    """A mandatory port_service_scan pre-req now runs before each target's
    technique chain -- its (shared, mocked) result reports both SMB/445 and
    LDAP/389 open so neither of the two gated techniques below gets
    filtered out."""
    db = MagicMock()
    agent = SimpleNamespace(id=13, kind="real", hostname="mac.local", tunnel_host="", tunnel_port=None)
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="10.0.0.5, 10.0.0.6", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["network_share_discovery", "ad_scouting_ldap"]

    def open_ports_for(host):
        return {
            "dispatched": True,
            "result": {
                "status": "executed",
                "open_ports": [
                    {"host": host, "port": 445, "protocol": "tcp", "service": "microsoft-ds"},
                    {"host": host, "port": 389, "protocol": "tcp", "service": "ldap"},
                ],
            },
            "agent_kind": "real",
        }

    with patch(
        "app.services.bas_scheduler.dispatch_bas_technique",
        side_effect=lambda *, target_hint, **_kw: open_ports_for(target_hint),
    ) as mock_dispatch:
        result = fire_schedule(db, schedule)

    assert mock_dispatch.call_count == 6  # 2 targets x (1 port scan + 2 techniques)
    dispatched_targets = [call.kwargs["target_hint"] for call in mock_dispatch.call_args_list]
    assert dispatched_targets == [
        "10.0.0.5", "10.0.0.5", "10.0.0.5", "10.0.0.6", "10.0.0.6", "10.0.0.6",
    ]
    assert len(result["job_ids"]) == 6


def test_fire_schedule_stop_on_failure_only_stops_the_failing_targets_own_chain():
    """A chain failing for one target must not skip the SAME techniques for
    a different target in the same schedule -- each target runs its own
    independent chain attempt."""
    db = MagicMock()
    agent = SimpleNamespace(id=13, kind="real", hostname="mac.local", tunnel_host="", tunnel_port=None)
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="10.0.0.5, 10.0.0.6", agent_id=13)
    schedule.stop_on_failure = True
    schedule.technique_keys = ["network_share_discovery", "ad_scouting_ldap"]

    open_ports_result = {"status": "executed", "open_ports": [
        {"host": "10.0.0.5", "port": 445, "protocol": "tcp", "service": "microsoft-ds"},
        {"host": "10.0.0.5", "port": 389, "protocol": "tcp", "service": "ldap"},
        {"host": "10.0.0.6", "port": 445, "protocol": "tcp", "service": "microsoft-ds"},
        {"host": "10.0.0.6", "port": 389, "protocol": "tcp", "service": "ldap"},
    ]}
    outcomes = [
        {"dispatched": True, "result": open_ports_result, "agent_kind": "real"},  # target 1: mandatory port scan
        {"dispatched": True, "result": {"status": "error"}, "agent_kind": "real"},  # target 1, step 1: fails
        # target 1, step 2 skipped (chain_stopped_after_failure)
        {"dispatched": True, "result": open_ports_result, "agent_kind": "real"},  # target 2: mandatory port scan
        {"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"},  # target 2, step 1
        {"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"},  # target 2, step 2
    ]
    with patch("app.services.bas_scheduler.dispatch_bas_technique", side_effect=outcomes) as mock_dispatch:
        result = fire_schedule(db, schedule)

    assert mock_dispatch.call_count == 5  # 2 port scans + target 1's 1 attempt + target 2's 2 attempts
    assert {"technique_key": "ad_scouting_ldap", "target": "10.0.0.5", "reason": "chain_stopped_after_failure"} in result["skipped"]
    assert len(result["job_ids"]) == 5  # 2 port scan jobs + target 1's failed job + target 2's two successful jobs


def test_fire_schedule_stops_after_a_failure_when_stop_on_failure_is_set():
    """A chain schedule (stop_on_failure=True) must not keep firing later
    steps once an earlier one genuinely fails -- those steps' premise (the
    earlier one succeeding) no longer holds, so running them produces noise
    instead of signal. port_service_scan is no longer listed explicitly --
    it's a mandatory pre-req now, dispatched before the chain regardless."""
    db = MagicMock()
    agent = SimpleNamespace(id=13, kind="real", hostname="mac.local", tunnel_host="", tunnel_port=None)
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="192.168.1.65", agent_id=13)
    schedule.stop_on_failure = True
    schedule.technique_keys = ["network_share_discovery", "ad_scouting_ldap"]

    outcomes = [
        {"dispatched": True, "result": {"status": "executed", "open_ports": [
            {"host": "192.168.1.65", "port": 445, "protocol": "tcp", "service": "microsoft-ds"},
            {"host": "192.168.1.65", "port": 389, "protocol": "tcp", "service": "ldap"},
        ]}, "agent_kind": "real"},  # mandatory port scan
        {"dispatched": True, "result": {"status": "error"}, "agent_kind": "real"},  # network_share_discovery fails
    ]
    with patch("app.services.bas_scheduler.dispatch_bas_technique", side_effect=outcomes) as mock_dispatch:
        result = fire_schedule(db, schedule)

    assert mock_dispatch.call_count == 2  # port scan + network_share_discovery; ad_scouting_ldap never dispatched
    assert {"technique_key": "ad_scouting_ldap", "target": "192.168.1.65", "reason": "chain_stopped_after_failure"} in result["skipped"]


def test_fire_schedule_does_not_stop_early_when_stop_on_failure_is_false():
    db = MagicMock()
    agent = SimpleNamespace(id=13, kind="real", hostname="mac.local", tunnel_host="", tunnel_port=None)
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="192.168.1.65", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["network_share_discovery", "ad_scouting_ldap"]

    outcomes = [
        {"dispatched": True, "result": {"status": "executed", "open_ports": [
            {"host": "192.168.1.65", "port": 445, "protocol": "tcp", "service": "microsoft-ds"},
            {"host": "192.168.1.65", "port": 389, "protocol": "tcp", "service": "ldap"},
        ]}, "agent_kind": "real"},  # mandatory port scan
        {"dispatched": True, "result": {"status": "error"}, "agent_kind": "real"},
        {"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"},
    ]
    with patch("app.services.bas_scheduler.dispatch_bas_technique", side_effect=outcomes) as mock_dispatch:
        result = fire_schedule(db, schedule)

    assert mock_dispatch.call_count == 3  # port scan + 2 techniques
    assert result["skipped"] == []


def test_execute_schedule_run_stops_cooperatively_when_scan_job_is_marked_stopped():
    """The stop endpoint (routes_bas.py) sets the shadow ScanJob's status to
    "stopped" from a different request/session -- execute_schedule_run must
    notice on its very next check (a raw scalar read, not the cached ORM
    object) and exit without dispatching anything further or overwriting
    that status back to "completed"."""
    db = MagicMock()
    agent = _agent(local_network_cidr="10.10.10.0/30")  # expands to 2 hosts
    shadow = SimpleNamespace(id=99, status="running", current_step="", mission_progress=0)

    def fake_query(*entities):
        m = MagicMock()
        if entities and entities[0] is BasAgent:
            m.filter.return_value.first.return_value = agent
        elif entities and entities[0] is ScanJob:
            m.filter.return_value.first.return_value = shadow
        elif entities and entities[0] is BasJob.id:
            m.filter.return_value.first.return_value = None  # nothing dispatched yet
        return m
    db.query.side_effect = fake_query

    # First cooperative check (before the very first technique) reports
    # still running; every check after that reports stopped -- simulates
    # the stop endpoint's UPDATE landing right after the run started.
    calls = {"n": 0}
    def fake_execute(*args, **kwargs):
        calls["n"] += 1
        row = MagicMock()
        row.first.return_value = ("running",) if calls["n"] <= 1 else ("stopped",)
        return row
    db.execute.side_effect = fake_execute

    schedule = _schedule(target_hint="", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["network_share_discovery", "port_service_scan"]

    with patch(
        "app.services.bas_scheduler.dispatch_bas_technique",
        return_value={"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"},
    ) as mock_dispatch:
        result = execute_schedule_run(db, schedule, 99, ["10.10.10.0/30"], True, [])

    assert result["cancelled"] is True
    assert mock_dispatch.call_count <= 1  # at most the one dispatch already in flight when stop landed
    assert shadow.status == "running"  # never overwritten to "completed" once cancelled
    assert shadow.current_step == "Interrompido pelo usuário"


def test_mandatory_port_scan_dispatches_first_even_when_absent_from_technique_keys():
    """explicit user decision (2026-08-28): port_service_scan is a
    prerequisite of every BAS run now, not an optional pick -- it must
    dispatch before anything else even when a schedule's technique_keys
    never mentions it at all."""
    db = MagicMock()
    agent = _agent(local_network_cidr="10.10.10.5/32")
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["ad_scouting_ldap"]

    with patch(
        "app.services.bas_scheduler.dispatch_bas_technique",
        return_value={
            "dispatched": True,
            "result": {"status": "executed", "open_ports": [
                {"host": "10.10.10.5", "port": 389, "protocol": "tcp", "service": "ldap"},
            ]},
            "agent_kind": "real",
        },
    ) as mock_dispatch:
        fire_schedule(db, schedule)

    assert mock_dispatch.call_args_list[0].kwargs["technique_key"] == "port_service_scan"
    assert mock_dispatch.call_count == 2  # port scan + ad_scouting_ldap


def test_port_scan_gate_only_dispatches_hosts_with_the_required_port_open():
    """A host-based technique with required_ports set (ad_scouting_ldap ->
    LDAP 389/636) must only be dispatched against hosts the mandatory port
    scan actually found that port open on -- not blindly against every host
    in the network mask."""
    db = MagicMock()
    agent = _agent(local_network_cidr="10.10.10.0/30")  # hosts .1 and .2
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["ad_scouting_ldap"]

    def dispatch_side_effect(*, technique_key, target_hint, **_kw):
        if technique_key == "port_service_scan":
            return {"dispatched": True, "result": {"status": "executed", "open_ports": [
                {"host": "10.10.10.1", "port": 389, "protocol": "tcp", "service": "ldap"},
                # .2 has nothing open -- absent from open_ports entirely.
            ]}, "agent_kind": "real"}
        return {"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"}

    with patch("app.services.bas_scheduler.dispatch_bas_technique", side_effect=dispatch_side_effect) as mock_dispatch:
        result = fire_schedule(db, schedule)

    dispatched = [call.kwargs["target_hint"] for call in mock_dispatch.call_args_list]
    assert dispatched == ["10.10.10.0/30", "10.10.10.1"]  # port scan, then only .1 (has LDAP open)
    assert {"technique_key": "ad_scouting_ldap", "target": "10.10.10.2", "reason": "port_not_open_per_port_scan:[389, 636]"} in result["skipped"]


def test_port_scan_failure_falls_back_to_testing_every_host():
    """A failed/errored port scan means the CMDB signal is unknown -- not
    "nothing is open". Gated techniques must fall back to testing every
    host rather than silently skipping real testing because the one
    prerequisite that was supposed to enable it never got an answer."""
    db = MagicMock()
    agent = _agent(local_network_cidr="10.10.10.0/30")  # hosts .1 and .2
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["ad_scouting_ldap"]

    def dispatch_side_effect(*, technique_key, target_hint, **_kw):
        if technique_key == "port_service_scan":
            return {"dispatched": False, "reason": "agent_offline"}
        return {"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"}

    with patch("app.services.bas_scheduler.dispatch_bas_technique", side_effect=dispatch_side_effect) as mock_dispatch:
        result = fire_schedule(db, schedule)

    dispatched = [call.kwargs["target_hint"] for call in mock_dispatch.call_args_list]
    assert dispatched == ["10.10.10.0/30", "10.10.10.1", "10.10.10.2"]  # both hosts still tested
    assert not any(s["reason"].startswith("port_not_open_per_port_scan") for s in result["skipped"])


def test_port_scan_gate_falls_back_per_host_for_a_chunk_that_failed_while_others_succeeded():
    """A /23 network scan splits into thirty-two /28 chunks. One completes (and
    gates its own hosts normally); the other fails -- its hosts must still
    be tested (unknown, not confirmed closed), while the completed chunk's
    hosts without the required port stay correctly gated out."""
    db = MagicMock()
    agent = _agent(local_network_cidr="10.10.0.0/23")
    _wire_db_for_agent(db, agent)

    schedule = _schedule(target_hint="", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["ad_scouting_ldap"]

    def dispatch_side_effect(*, technique_key, target_hint, **_kw):
        if technique_key == "port_service_scan":
            if target_hint == "10.10.0.0/28":
                return {"dispatched": True, "result": {"status": "executed", "open_ports": [
                    {"host": "10.10.0.5", "port": 389, "protocol": "tcp", "service": "ldap"},
                ]}, "agent_kind": "real"}
            return {"dispatched": False, "reason": "agent_offline"}
        return {"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"}

    with patch("app.services.bas_scheduler.dispatch_bas_technique", side_effect=dispatch_side_effect) as mock_dispatch:
        result = fire_schedule(db, schedule)

    ldap_dispatches = [
        call.kwargs["target_hint"] for call in mock_dispatch.call_args_list
        if call.kwargs["technique_key"] == "ad_scouting_ldap"
    ]
    assert "10.10.0.5" in ldap_dispatches
    assert len(ldap_dispatches) == 1 + 495
    gated_out = [s for s in result["skipped"] if s["reason"].startswith("port_not_open_per_port_scan")]
    assert len(gated_out) == 14
    assert all(s["target"].startswith("10.10.0.") for s in gated_out)


def test_resume_schedule_run_reactivates_a_stopped_shadow_job():
    db = MagicMock()
    agent = _agent(local_network_cidr="10.10.10.0/30")
    shadow = SimpleNamespace(id=99, status="stopped", current_step="Interrompido pelo usuário", mission_progress=17)

    def fake_query(*entities):
        m = MagicMock()
        if entities and entities[0] is BasAgent:
            m.filter.return_value.first.return_value = agent
        elif entities and entities[0] is ScanJob:
            m.filter.return_value.first.return_value = shadow
        return m
    db.query.side_effect = fake_query

    schedule = _schedule(target_hint="", agent_id=13)
    schedule.technique_keys = ["network_share_discovery"]

    result = resume_schedule_run(db, schedule, 99)

    assert result["queued"] is True
    assert result["scan_job_id"] == 99
    assert result["targets"] == ["10.10.10.0/30"]
    assert shadow.status == "running"


def test_resume_schedule_run_refuses_a_job_that_isnt_actually_stopped():
    """Only a genuinely stopped run can be resumed -- resuming a completed
    or still-running one would double-dispatch or race the live loop."""
    db = MagicMock()
    agent = _agent(local_network_cidr="10.10.10.0/30")
    shadow = SimpleNamespace(id=99, status="completed", current_step="Concluído", mission_progress=100)

    def fake_query(*entities):
        m = MagicMock()
        if entities and entities[0] is BasAgent:
            m.filter.return_value.first.return_value = agent
        elif entities and entities[0] is ScanJob:
            m.filter.return_value.first.return_value = shadow
        return m
    db.query.side_effect = fake_query

    result = resume_schedule_run(db, _schedule(target_hint="", agent_id=13), 99)

    assert result["error"] == "not_stopped"


def test_resumed_run_skips_a_target_already_dispatched_before_the_stop():
    """The whole point of resume: a (technique, target) pair that already
    has a terminal BasJob on this exact scan_job_id must not be dispatched
    again -- only what was never reached the first time actually runs. The
    mandatory port_service_scan pre-req already completed before the stop
    too (with SMB/445 open on the one host), so it must be reused, not
    redispatched, and it's what lets network_share_discovery's host through
    the CMDB gate."""
    db = MagicMock()
    agent = _agent(local_network_cidr="10.10.10.5/32")  # a single host: 10.10.10.5
    shadow = SimpleNamespace(id=99, status="stopped", current_step="", mission_progress=50)
    completed_port_scan = SimpleNamespace(
        status="completed",
        result={"open_ports": [{"host": "10.10.10.5", "port": 445, "protocol": "tcp", "service": "microsoft-ds"}]},
    )

    def fake_query(*entities):
        m = MagicMock()
        if entities and entities[0] is BasAgent:
            m.filter.return_value.first.return_value = agent
        elif entities and entities[0] is ScanJob:
            m.filter.return_value.first.return_value = shadow
        elif entities and entities[0] is BasJob:
            m.filter.return_value.order_by.return_value.first.return_value = completed_port_scan
        elif entities and entities[0] is BasJob.id:
            m.filter.return_value.first.return_value = None  # network_share_discovery not yet done
        return m
    db.query.side_effect = fake_query
    db.execute.return_value.first.return_value = ("running",)  # never stopped again mid-resume

    schedule = _schedule(target_hint="", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["network_share_discovery"]

    resumed = resume_schedule_run(db, schedule, 99)
    assert resumed["queued"] is True

    with patch(
        "app.services.bas_scheduler.dispatch_bas_technique",
        return_value={"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"},
    ) as mock_dispatch:
        result = execute_schedule_run(
            db, schedule, resumed["scan_job_id"], resumed["targets"],
            resumed["target_was_defaulted"], resumed["skipped"],
        )

    assert mock_dispatch.call_count == 1  # only network_share_discovery -- port scan reused, not redone
    assert shadow.status == "completed"  # a resumed run still reaches its normal terminal state


def test_extract_key_findings_pulls_nikto_numbered_lines():
    stdout = (
        "- Nikto v2.6.0\n"
        "+ Target IP: 192.168.1.65\n"
        "+ [007352] /: The X-Content-Type-Options header is not set.\n"
        "+ [999986] /: Retrieved access-control-allow-origin header: *.\n"
        "+ 4016 requests: 0 errors and 8 items reported\n"
    )
    findings = _extract_key_findings("owasp_web_app_scan", "web", {"stdout": stdout})
    assert len(findings) == 2
    assert all(ln.startswith("+ [") for ln in findings)


def test_extract_key_findings_pulls_open_ports_from_nmap():
    stdout = "PORT     STATE SERVICE\n3000/tcp open  http\nNot shown: 98 closed tcp ports\n"
    findings = _extract_key_findings("port_service_scan", "network", {"stdout": stdout})
    assert findings == ["3000/tcp open  http"]


def test_smb_cme_findings_and_severity_reflect_signing_and_smbv1():
    stdout = "\n".join([
        "SMB                      10.125.133.225  445    BR-SEN1-PC0214   [*] Windows 11 / Server 2025 Build 26100 x64 (name:BR-SEN1-PC0214) (domain:falconcorp.net) (signing:False) (SMBv1:False)",
        "SMB                      10.125.135.102  445    NBK-DANIEL       [*] Windows 10 Home Single Language 26200 x64 (name:NBK-DANIEL) (domain:NBK-DANIEL) (signing:False) (SMBv1:True)",
    ])

    findings = _extract_key_findings("smb_enum_cme", "smb", {"stdout": stdout})

    assert len(findings) == 2
    assert _derive_severity("smb_enum_cme", findings) == "high"


def test_extract_key_findings_pulls_secret_grep_hits_and_excludes_exit_code_line():
    stdout = "api_key\nsecret\nEXIT_CODE:0\n"
    findings = _extract_key_findings("pipeline_secrets_harvesting", "cicd", {"stdout": stdout})
    assert findings == ["api_key", "secret"]


def test_extract_key_findings_empty_when_secret_scan_found_nothing():
    stdout = "EXIT_CODE:0\n"
    findings = _extract_key_findings("pipeline_secrets_harvesting", "cicd", {"stdout": stdout})
    assert findings == []


def test_extract_key_findings_returns_empty_for_blank_stdout():
    assert _extract_key_findings("port_service_scan", "network", {"stdout": ""}) == []
    assert _extract_key_findings("port_service_scan", "network", {}) == []


def test_derive_severity_is_info_when_nothing_was_found():
    assert _derive_severity("owasp_web_app_scan", []) == "info"


def test_derive_severity_escalates_per_technique_when_something_was_found():
    assert _derive_severity("netlogon_zerologon_check", ["VULNERABLE"]) == "critical"
    assert _derive_severity("source_code_secrets_scan", ["AKIA..."]) == "high"
    assert _derive_severity("owasp_web_app_scan", ["+ [1] header missing"]) == "medium"
    assert _derive_severity("port_service_scan", ["3000/tcp open"]) == "low"


def test_finding_from_job_result_never_escalates_severity_for_a_stub_dispatch():
    """A stub's canned content could say anything -- it must never be
    allowed to claim a real vulnerability was observed. Its key_findings is
    forced to [] regardless of stdout, which (since 2026-08-28) also means
    no Finding is created at all -- verified separately by
    test_finding_from_job_result_never_creates_a_finding_for_a_stub_agent_dispatch."""
    db = MagicMock()
    agent = SimpleNamespace(id=1, kind="stub")
    technique = get_technique("owasp_web_app_scan")
    job = _job(result={"stdout": "+ [007352] /: fake header issue\n", "status": "executed"})

    finding = _finding_from_job_result(db, job, _schedule(), technique, agent)

    assert finding is None


def test_finding_from_job_result_escalates_severity_for_a_real_dispatch_with_real_signal():
    db = MagicMock()
    agent = SimpleNamespace(id=13, kind="real")
    technique = get_technique("owasp_web_app_scan")
    job = _job(result={
        "command": "nikto -h 10.10.10.5",
        "stdout": "+ [007352] /: The X-Content-Type-Options header is not set.\n",
        "status": "executed",
    })

    finding = _finding_from_job_result(db, job, _schedule(), technique, agent)

    assert finding.severity == "medium"
    assert finding.details["key_findings"] == ["+ [007352] /: The X-Content-Type-Options header is not set."]
    assert finding.details["recommendation"] == technique["recommendation"]
    assert finding.details["mitre_refs"] == technique["mitre_refs"]
    assert finding.details["proof"]["valid"] is True
    assert finding.details["counts_towards_score"] is True
    assert finding.verification_status == "confirmed"
    assert finding.confidence_score == 90
    assert job.result["bas_proof"]["valid"] is True


def test_extract_key_findings_supports_internal_pentest_techniques():
    stdout = "Nmap scan report for 10.10.10.5\n445/tcp open microsoft-ds\n"
    assert _extract_key_findings("lateral_movement_simulation_safe", "lateral_movement", {"stdout": stdout}) == [
        "10.10.10.5: 445/tcp open microsoft-ds"
    ]
    assert _derive_severity("safe_credential_checks", ["SMB 10.10.10.5 445 HOST (signing:False)"]) == "medium"
    assert _derive_severity("controlled_exploit_validation", ["+ [1] missing security header"]) == "medium"


def test_extract_key_findings_supports_cloud_identity_discovery():
    stdout = '{"NameSpaceType":"Managed","FederationBrandName":"Example","cloud":"m365"}\nEXIT_CODE:0\n'
    assert _extract_key_findings("azure_entra_id_discovery", "cloud_identity", {"stdout": stdout}) == [
        '{"NameSpaceType":"Managed","FederationBrandName":"Example","cloud":"m365"}'
    ]
    assert _derive_severity("m365_tenant_exposure_check", ["tenant discovered"]) == "info"


def test_extract_key_findings_ignores_enum4linux_unreachable_host_banner():
    """Regression (live 2026-08-28): every unreachable host in a /23 sweep
    got a "confirmed" Finding out of this exact banner -- enum4linux-ng's
    own "nothing here" message, not an observation about the target."""
    stdout = (
        "| NetBIOS Names and Workgroup/Domain for 192.168.16.82 |\n"
        "============================================================\n"
        "\x1b[91m[-] Could not get NetBIOS names information via 'nmblookup': timed out\x1b[0m\n"
        "\x1b[93m[!] Aborting remainder of tests since neither SMB nor LDAP are accessible\x1b[0m\n"
        "Completed after 22.28 seconds\n"
    )
    assert _extract_key_findings("smb_enum_enum4linux", "smb", {"stdout": stdout}) == []


def test_extract_key_findings_pulls_real_enum4linux_success_markers():
    stdout = (
        "\x1b[92m[+] Found domain: CORP\x1b[0m\n"
        "\x1b[91m[-] Could not enumerate password policy\x1b[0m\n"
        "\x1b[92m[+] Enumerated shares: ADMIN$, C$, NETLOGON\x1b[0m\n"
    )
    assert _extract_key_findings("smb_enum_enum4linux", "smb", {"stdout": stdout}) == [
        "[+] Found domain: CORP",
        "[+] Enumerated shares: ADMIN$, C$, NETLOGON",
    ]
    assert _derive_severity("smb_enum_enum4linux", ["[+] Found domain: CORP"]) == "medium"


def test_extract_key_findings_generic_fallback_ignores_timeout_only_output():
    """Same failure-only guard as the enum4linux case, applied to the
    generic fallback path so any OTHER technique without a dedicated
    extractor gets the same protection -- not just this one instance."""
    stdout = "Connection timed out\nNo route to host\n"
    assert _extract_key_findings("some_future_technique_with_no_extractor", "misc", {"stdout": stdout}) == []


def test_extract_key_findings_generic_fallback_still_surfaces_real_output():
    stdout = "Discovered internal hostname: db01.corp.internal\n"
    assert _extract_key_findings("some_future_technique_with_no_extractor", "misc", {"stdout": stdout}) == [
        "Discovered internal hostname: db01.corp.internal"
    ]
