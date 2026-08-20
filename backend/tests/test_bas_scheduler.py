"""bas_scheduler.py: due-time evaluation (mirrors scheduler_tick's idempotency
logic) and the shadow-ScanJob target_query fix (kali_runner rejects any
dispatch with an empty authorized_scope -- resolve_authorized_scope_for_
dispatch derives that scope from the ScanJob's target_query, so it must be
the schedule's real target_hint, never a synthetic label)."""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.bas_scheduler import (
    _create_shadow_scan_job,
    _derive_severity,
    _extract_key_findings,
    _finding_from_job_result,
    _is_due,
    fire_schedule,
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


def test_fire_schedule_stops_after_a_failure_when_stop_on_failure_is_set():
    """A chain schedule (stop_on_failure=True) must not keep firing later
    steps once an earlier one genuinely fails -- those steps' premise (the
    earlier one succeeding) no longer holds, so running them produces noise
    instead of signal."""
    db = MagicMock()
    agent = SimpleNamespace(id=13, kind="real", hostname="mac.local", tunnel_host="", tunnel_port=None)
    db.query.return_value.filter.return_value.first.return_value = agent

    schedule = _schedule(target_hint="192.168.1.65", agent_id=13)
    schedule.stop_on_failure = True
    schedule.technique_keys = ["network_share_discovery", "ad_scouting_ldap", "port_service_scan"]

    outcomes = [
        {"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"},
        {"dispatched": True, "result": {"status": "error"}, "agent_kind": "real"},
    ]
    with patch("app.services.bas_scheduler.dispatch_bas_technique", side_effect=outcomes) as mock_dispatch:
        result = fire_schedule(db, schedule)

    assert mock_dispatch.call_count == 2  # third step never dispatched
    assert {"technique_key": "port_service_scan", "reason": "chain_stopped_after_failure"} in result["skipped"]


def test_fire_schedule_does_not_stop_early_when_stop_on_failure_is_false():
    db = MagicMock()
    agent = SimpleNamespace(id=13, kind="real", hostname="mac.local", tunnel_host="", tunnel_port=None)
    db.query.return_value.filter.return_value.first.return_value = agent

    schedule = _schedule(target_hint="192.168.1.65", agent_id=13)
    schedule.stop_on_failure = False
    schedule.technique_keys = ["network_share_discovery", "ad_scouting_ldap", "port_service_scan"]

    outcomes = [
        {"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"},
        {"dispatched": True, "result": {"status": "error"}, "agent_kind": "real"},
        {"dispatched": True, "result": {"status": "executed"}, "agent_kind": "real"},
    ]
    with patch("app.services.bas_scheduler.dispatch_bas_technique", side_effect=outcomes) as mock_dispatch:
        result = fire_schedule(db, schedule)

    assert mock_dispatch.call_count == 3
    assert result["skipped"] == []


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
    allowed to claim a real vulnerability was observed."""
    db = MagicMock()
    agent = SimpleNamespace(id=1, kind="stub")
    technique = get_technique("owasp_web_app_scan")
    job = _job(result={"stdout": "+ [007352] /: fake header issue\n", "status": "executed"})

    finding = _finding_from_job_result(db, job, _schedule(), technique, agent)

    assert finding.severity == "info"
    assert finding.details["key_findings"] == []


def test_finding_from_job_result_escalates_severity_for_a_real_dispatch_with_real_signal():
    db = MagicMock()
    agent = SimpleNamespace(id=13, kind="real")
    technique = get_technique("owasp_web_app_scan")
    job = _job(result={"stdout": "+ [007352] /: The X-Content-Type-Options header is not set.\n", "status": "executed"})

    finding = _finding_from_job_result(db, job, _schedule(), technique, agent)

    assert finding.severity == "medium"
    assert finding.details["key_findings"] == ["+ [007352] /: The X-Content-Type-Options header is not set."]
    assert finding.details["recommendation"] == technique["recommendation"]
    assert finding.details["mitre_refs"] == technique["mitre_refs"]
