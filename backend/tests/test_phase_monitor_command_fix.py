from datetime import UTC, datetime
from types import SimpleNamespace

from app.models.models import ExecutedToolRun, Finding
from app.services.phase_monitor import build_phase_monitor


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self._rows)


class _FakeDB:
    def __init__(self, runs, findings):
        self._runs = runs
        self._findings = findings

    def query(self, model):
        if model is ExecutedToolRun:
            return _FakeQuery(self._runs)
        if model is Finding:
            return _FakeQuery(self._findings)
        return _FakeQuery([])


def test_installed_tool_failure_requires_command_fix_instead_of_tool_failure(monkeypatch) -> None:
    command = "amass enum -passive -d example.com"
    run = SimpleNamespace(
        tool_name="amass",
        target="example.com",
        status="failed",
        error_message=f"command={command}\n\nreturn_code=1\n\nstderr:\nunknown flag",
        execution_time_seconds=0.4,
        created_at=datetime.now(UTC),
    )
    scan = SimpleNamespace(
        id=77,
        status="completed",
        current_step="",
        mission_progress=100,
        state_data={
            "executed_tool_runs": ["P01|example.com|amass"],
            "tool_runtime": {"amass": {"attempts": 1, "failures": 1}},
            "mission_metrics": {},
        },
    )

    monkeypatch.setattr("app.services.tool_catalog.is_tool_installed", lambda tool: tool == "amass")
    monkeypatch.setattr(
        "app.services.tool_catalog.installation_report",
        lambda: {"total": 1, "installed": ["amass"], "missing": [], "coverage_ratio": 1.0},
    )

    monitor = build_phase_monitor(_FakeDB([run], []), scan)

    assert monitor["command_fix_required"] == [
        {
            "tool": "amass",
            "attempts": 1,
            "last_status": "failed",
            "last_command": command,
            "last_error": "command=amass enum -passive -d example.com\n\nreturn_code=1\n\nstderr:\nunknown flag",
        }
    ]
    critical_text = "\n".join(monitor["validation_summary"]["critical"])
    assert "COMMAND FIX REQUIRED" in critical_text
    assert f"amass command=`{command}`" in critical_text
    assert "A ferramenta existe no Kali" in critical_text
    assert "TOOL FAILURES" not in critical_text


def test_phase_monitor_suppresses_tool_sweep_failures_until_execution_exists(monkeypatch) -> None:
    scan = SimpleNamespace(
        id=78,
        status="completed",
        current_step="",
        mission_progress=0,
        state_data={"mission_metrics": {}, "executed_tool_runs": []},
    )
    monkeypatch.setattr("app.services.tool_catalog.is_tool_installed", lambda _tool: True)
    monkeypatch.setattr(
        "app.services.tool_catalog.installation_report",
        lambda: {"total": 66, "installed": ["amass"], "missing": [], "coverage_ratio": 1.0},
    )

    monitor = build_phase_monitor(_FakeDB([], []), scan)
    critical_text = "\n".join(monitor["validation_summary"]["critical"])
    info_text = "\n".join(monitor["validation_summary"]["info"])

    assert "NO KALI TOOL EXECUTION RECORDED" in critical_text
    assert "KALI TOOLS NOT EXECUTED" not in critical_text
    assert "Coverage of Kali-ready tools low" not in critical_text
    assert "INCOMPLETE CAPABILITIES" not in critical_text
    assert "CRITICAL NODES NOT VISITED" not in critical_text
    assert "KALI TOOL EXECUTION PENDING" in info_text
    assert "Coverage pending" in info_text


def test_incomplete_capabilities_report_required_runtime_evidence(monkeypatch) -> None:
    run = SimpleNamespace(
        tool_name="amass",
        target="example.com",
        status="success",
        error_message=None,
        execution_time_seconds=0.2,
        created_at=datetime.now(UTC),
    )
    scan = SimpleNamespace(
        id=79,
        status="completed",
        current_step="",
        mission_progress=100,
        state_data={
            "executed_tool_runs": ["P01|example.com|amass"],
            "mission_metrics": {},
        },
    )
    monkeypatch.setattr("app.services.tool_catalog.is_tool_installed", lambda tool: tool == "amass")
    monkeypatch.setattr(
        "app.services.tool_catalog.installation_report",
        lambda: {"total": 1, "installed": ["amass"], "missing": [], "coverage_ratio": 1.0},
    )

    monitor = build_phase_monitor(_FakeDB([run], []), scan)
    critical_text = "\n".join(monitor["validation_summary"]["critical"])

    assert "INCOMPLETE CAPABILITIES" in critical_text
    assert "Graph traversal did not produce the required capability evidence" in critical_text
    assert "strategic_planning requires" in critical_text
    assert monitor["capability_gaps"]
    assert monitor["capability_gaps"][0]["required_evidence"]


def test_capability_ledger_satisfies_capability_completion(monkeypatch) -> None:
    run = SimpleNamespace(
        tool_name="amass",
        target="example.com",
        status="success",
        error_message=None,
        execution_time_seconds=0.2,
        created_at=datetime.now(UTC),
    )
    ledger = {
        cap: {
            "id": cap,
            "visited": True,
            "completed": True,
            "last_source": "unit-test",
            "last_evidence": {"ok": True},
        }
        for cap in [
            "strategic_planning",
            "asset_discovery",
            "threat_intel",
            "adversarial_hypothesis",
            "risk_assessment",
            "evidence_adjudication",
            "governance",
            "executive_analyst",
        ]
    }
    scan = SimpleNamespace(
        id=80,
        status="completed",
        current_step="",
        mission_progress=100,
        state_data={
            "executed_tool_runs": ["P01|example.com|amass"],
            "capability_ledger": ledger,
            "completed_capabilities": list(ledger),
            "mission_metrics": {},
        },
    )
    monkeypatch.setattr("app.services.tool_catalog.is_tool_installed", lambda tool: tool == "amass")
    monkeypatch.setattr(
        "app.services.tool_catalog.installation_report",
        lambda: {"total": 1, "installed": ["amass"], "missing": [], "coverage_ratio": 1.0},
    )

    monitor = build_phase_monitor(_FakeDB([run], []), scan)
    critical_text = "\n".join(monitor["validation_summary"]["critical"])

    assert "INCOMPLETE CAPABILITIES" not in critical_text
    assert monitor["capability_gaps"] == []
