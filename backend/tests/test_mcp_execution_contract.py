from types import SimpleNamespace

from app.services.mcp_client import MCPClient
from app.services.vulnerability_learning_service import build_runtime_learning_playbook


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return dict(self.payload)


class _FakeSyncClient:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def get(self, _path: str) -> _FakeResponse:
        return _FakeResponse(self.payload)


def test_mcp_rag_health_is_not_enough_for_kali_tool_execution(monkeypatch) -> None:
    client = MCPClient(base_url="http://mcp.test")
    monkeypatch.setattr(
        client,
        "_sync_client",
        lambda: _FakeSyncClient({"status": "healthy", "kali_connected": False, "kali_profiles_loaded": 0}),
    )

    assert client.health_check_sync() is True
    assert client.kali_tools_available_sync() is False


def test_mcp_kali_tool_execution_requires_loaded_profiles(monkeypatch) -> None:
    client = MCPClient(base_url="http://mcp.test")
    monkeypatch.setattr(
        client,
        "_sync_client",
        lambda: _FakeSyncClient({"status": "healthy", "kali_connected": True, "kali_profiles_loaded": 12}),
    )

    assert client.kali_tools_available_sync() is True


def test_mcp_execution_normalizes_localhost_and_legacy_status(monkeypatch) -> None:
    client = MCPClient(base_url="http://mcp.test")
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        client,
        "list_tools_sync",
        lambda: [{"name": "sqlmap_basic"}],
    )

    def _call(tool_name: str, parameters: dict[str, object], *, timeout: float | None = None) -> dict[str, object]:
        captured["tool_name"] = tool_name
        captured["parameters"] = dict(parameters)
        captured["timeout"] = timeout
        return {
            "status": "done",
            "profile": "sqlmap_basic",
            "job_id": "job-123",
            "command": "sqlmap -u http://host.docker.internal:3001/",
            "return_code": 0,
            "stdout": "ok",
            "stderr": "",
        }

    monkeypatch.setattr(client, "call_tool_sync", _call)

    result = client.execute_kali_tool_sync(
        tool_name="sqlmap",
        target="http://localhost:3001/",
        scan_id=27,
        extra_args=["--dbms=mssql", "--batch"],
    )

    assert captured["tool_name"] == "sqlmap_basic"
    assert captured["parameters"]["target"] == "http://host.docker.internal:3001/"
    assert captured["parameters"]["original_target"] == "http://localhost:3001/"
    assert captured["parameters"]["timeout"] == 600
    assert captured["parameters"]["extra_args"] == ["--dbms=mssql", "--batch"]
    assert captured["timeout"] == 615.0
    assert result["status"] == "executed"
    assert result["target"] == "http://host.docker.internal:3001/"
    assert result["original_target"] == "http://localhost:3001/"
    assert result["dispatch_task_name"] == "kali:sqlmap_basic"


def test_learning_playbook_keeps_technique_when_candidate_matches_technique_tools(monkeypatch) -> None:
    row = SimpleNamespace(
        id=99,
        title="Juice Shop SQLi",
        vulnerability_type="SQL Injection",
        learned_mission="Validate SQLi",
        summary="Use sqlmap on injectable endpoint",
        learned_prompt="Focus on SQLi",
        recommended_tools=["ffuf"],
        affected_phases=["P11"],
        affected_skills=["sqli"],
        raw_extraction={"risk_score_hint": "high"},
        accepted_at=None,
        created_at=None,
    )

    class _Query:
        def filter(self, *_args, **_kwargs):
            return self

        def order_by(self, *_args, **_kwargs):
            return self

        def limit(self, *_args, **_kwargs):
            return self

        def all(self):
            return [row]

    class _DB:
        def query(self, *_args, **_kwargs):
            return _Query()

        def close(self):
            return None

    monkeypatch.setattr("app.services.vulnerability_learning_service.SessionLocal", lambda: _DB())
    monkeypatch.setattr(
        "app.services.vulnerability_learning_service._learning_runtime_techniques",
        lambda _row: [
            {
                "name": "SQLi via walkthrough",
                "recommended_kali_tools": ["sqlmap"],
                "affected_phases": ["P11"],
                "evidence_signals": ["database error"],
                "safe_validation_steps": ["Run sqlmap conservatively"],
            }
        ],
    )

    playbook = build_runtime_learning_playbook(
        candidate_tools=["sqlmap"],
        phase="P11",
        limit=8,
    )

    assert playbook is not None
    assert playbook["techniques"][0]["name"] == "SQLi via walkthrough"
    assert "sqlmap" in playbook["techniques"][0]["recommended_kali_tools"]


def test_learning_playbook_understands_graph_phase_aliases(monkeypatch) -> None:
    row = SimpleNamespace(
        id=100,
        title="Juice Shop Recon",
        vulnerability_type="Information Disclosure",
        learned_mission="Discover hidden routes",
        summary="Use crawl output to identify hidden routes",
        learned_prompt="Focus on crawl findings",
        recommended_tools=["hakrawler"],
        affected_phases=["P03"],
        affected_skills=["recon-web-crawl"],
        raw_extraction={"risk_score_hint": "medium"},
        accepted_at=None,
        created_at=None,
    )

    class _Query:
        def filter(self, *_args, **_kwargs):
            return self

        def order_by(self, *_args, **_kwargs):
            return self

        def limit(self, *_args, **_kwargs):
            return self

        def all(self):
            return [row]

    class _DB:
        def query(self, *_args, **_kwargs):
            return _Query()

        def close(self):
            return None

    monkeypatch.setattr("app.services.vulnerability_learning_service.SessionLocal", lambda: _DB())
    monkeypatch.setattr(
        "app.services.vulnerability_learning_service._learning_runtime_techniques",
        lambda _row: [
            {
                "name": "Recon via walkthrough",
                "recommended_kali_tools": ["katana"],
                "affected_phases": ["P03"],
                "evidence_signals": ["hidden route"],
                "safe_validation_steps": ["Crawl the application safely"],
            }
        ],
    )

    playbook = build_runtime_learning_playbook(
        candidate_tools=["katana"],
        phase="asset_discovery",
        limit=8,
    )

    assert playbook is not None
    assert playbook["techniques"][0]["name"] == "Recon via walkthrough"
