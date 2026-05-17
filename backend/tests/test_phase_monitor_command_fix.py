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
