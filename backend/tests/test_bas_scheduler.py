"""bas_scheduler.py: due-time evaluation (mirrors scheduler_tick's idempotency
logic) and the shadow-ScanJob target_query fix (kali_runner rejects any
dispatch with an empty authorized_scope -- resolve_authorized_scope_for_
dispatch derives that scope from the ScanJob's target_query, so it must be
the schedule's real target_hint, never a synthetic label)."""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.services.bas_scheduler import _create_shadow_scan_job, _finding_from_job_result, _is_due
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


def test_shadow_scan_job_target_query_is_the_real_target_hint_not_a_synthetic_label():
    """Regression: a synthetic label like 'bas:schedule#1' parses to no valid
    scope root at all, so kali_runner's authorized_scope-required check
    would fail-closed on every single dispatch through this shadow job."""
    db = MagicMock()
    schedule = _schedule(target_hint="10.10.10.5")

    shadow = _create_shadow_scan_job(db, schedule)

    assert shadow.target_query == "10.10.10.5"
    assert shadow.mode == "bas"
    db.add.assert_called_once_with(shadow)
    db.flush.assert_called_once()


def test_shadow_scan_job_falls_back_to_a_placeholder_when_target_hint_is_blank():
    db = MagicMock()
    schedule = _schedule(target_hint="")

    shadow = _create_shadow_scan_job(db, schedule)

    assert shadow.target_query  # never empty -- an empty target_query also fails scope resolution
    assert "1" in shadow.target_query


def _job(**overrides):
    base = dict(id=1, scan_job_id=1, result={"command": "smbmap -H 127.0.0.1", "status": "executed"})
    base.update(overrides)
    return SimpleNamespace(**base)


def test_finding_from_job_result_marks_stub_agent_dispatch_as_simulated():
    db = MagicMock()
    agent = SimpleNamespace(id=1, kind="stub")
    technique = get_technique("network_share_discovery")

    finding = _finding_from_job_result(db, _job(), _schedule(), technique, agent)

    assert finding.details["simulated"] is True
    assert finding.details["counts_towards_score"] is False
    assert finding.details["counts_towards_attack_path"] is False
    assert "(simulado)" in finding.title


def test_finding_from_job_result_marks_real_agent_dispatch_as_not_simulated():
    """A real (mTLS-certified) agent's dispatch is a genuine result -- it
    must count like any other Finding, and never carry the "(simulado)"
    title suffix."""
    db = MagicMock()
    agent = SimpleNamespace(id=9, kind="real")
    technique = get_technique("network_share_discovery")

    finding = _finding_from_job_result(db, _job(), _schedule(), technique, agent)

    assert finding.details["simulated"] is False
    assert finding.details["counts_towards_score"] is True
    assert finding.details["counts_towards_attack_path"] is True
    assert "(simulado)" not in finding.title
    assert finding.details["bas_agent_id"] == 9
    assert finding.details["bas_agent_kind"] == "real"
