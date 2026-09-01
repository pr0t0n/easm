from types import SimpleNamespace

from app.models.models import ScanLog


def test_bas_reanalysis_records_missing_techniques_and_next_actions() -> None:
    from app.services.bas_reanalysis_orchestrator import run_bas_reanalysis

    added = []

    class Query:
        def filter(self, *_args, **_kwargs):
            return self

        def order_by(self, *_args, **_kwargs):
            return self

        def all(self):
            return [
                SimpleNamespace(
                    id=10,
                    scan_job_id=77,
                    technique_key="port_service_scan",
                    target="10.0.0.0/28",
                    status="completed",
                    result={"bas_proof": {"status": "validated"}},
                    finding_id=44,
                    last_error=None,
                )
            ]

    class DB:
        def query(self, *_args, **_kwargs):
            return Query()

        def add(self, row):
            added.append(row)

        def flush(self):
            pass

    schedule = SimpleNamespace(
        id=5,
        agent_id=9,
        technique_keys=["port_service_scan", "smb_enum_cme", "network_share_discovery"],
    )
    shadow = SimpleNamespace(id=77, state_data={})

    event = run_bas_reanalysis(
        DB(),
        schedule,
        shadow,
        trigger="bas_job_completed:port_service_scan",
        source_job_id=10,
        skipped=[{"technique_key": "smb_enum_cme", "target": "10.0.0.5", "reason": "port_gate_no_required_ports"}],
    )

    assert event["coverage_percent"] == 33.3
    assert event["tested_techniques"] == ["port_service_scan"]
    assert event["missing_techniques"] == ["smb_enum_cme", "network_share_discovery"]
    assert event["jobs"]["statuses"] == {"completed": 1}
    assert event["findings"]["linked"] == 1
    assert event["next_actions"][0]["type"] == "dispatch_missing_techniques"
    assert shadow.state_data["bas_reanalysis_latest"]["source_job_id"] == 10
    assert any(isinstance(row, ScanLog) for row in added)


def test_bas_reanalysis_marks_completed_run_ready_for_reporting() -> None:
    from app.services.bas_reanalysis_orchestrator import run_bas_reanalysis

    class Query:
        def filter(self, *_args, **_kwargs):
            return self

        def order_by(self, *_args, **_kwargs):
            return self

        def all(self):
            return [
                SimpleNamespace(
                    id=10,
                    scan_job_id=77,
                    technique_key="port_service_scan",
                    target="10.0.0.0/28",
                    status="completed",
                    result={"bas_proof": {"status": "validated"}},
                    finding_id=None,
                    last_error=None,
                ),
                SimpleNamespace(
                    id=11,
                    scan_job_id=77,
                    technique_key="smb_enum_cme",
                    target="10.0.0.5",
                    status="completed",
                    result={"bas_control_status": "detected"},
                    finding_id=45,
                    last_error=None,
                ),
            ]

    class DB:
        def query(self, *_args, **_kwargs):
            return Query()

        def add(self, _row):
            pass

        def flush(self):
            pass

    schedule = SimpleNamespace(id=5, agent_id=9, technique_keys=["smb_enum_cme"])
    shadow = SimpleNamespace(id=77, state_data={})

    event = run_bas_reanalysis(DB(), schedule, shadow, trigger="bas_run_completed")

    assert event["coverage_percent"] == 100.0
    assert event["missing_techniques"] == []
    assert event["control_outcomes"]["validated"] == 1
    assert event["control_outcomes"]["detected"] == 1
    assert event["next_actions"] == [{"type": "ready_for_control_reporting"}]
