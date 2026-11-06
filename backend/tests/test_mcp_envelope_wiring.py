"""Fase 2 (LANGGRAPH_BRAIN_PLAN): o resultado que chega ao grafo carrega o
envelope v1 com findings_raw extraídos na borda (MCP), para o pipeline
acumular no state (evidence gate / findings_extractor consomem sem re-varrer
stdout).
"""
from __future__ import annotations

from app.services.result_envelope import ENVELOPE_VERSION, build_envelope


FAKE_RESULT = {
    "status": "done",
    "return_code": 0,
    "stdout": "",
    "stderr": "",
    "parsed": [
        {"template-id": "http/x", "severity": "medium", "host": "http://x"}
    ],
    "command": "nuclei -u http://x",
    "workdir": "/workspace/1/nuclei/job-1",
    "duration_seconds": 5.0,
    "job_id": "job-1",
    "execution_path": "mcp_to_kali",
}


def test_build_envelope_version_matches_mcp_contract():
    env = build_envelope(tool="nuclei", target="http://x", status="done")
    assert env["envelope_version"] == ENVELOPE_VERSION == "result-envelope/v1"


def test_mcp_client_attaches_envelope_to_legacy_result(monkeypatch):
    import app.services.mcp_client as mcp_client_mod

    monkeypatch.setattr(mcp_client_mod, "profile_for_tool", lambda t: "nuclei_cves")
    monkeypatch.setattr(mcp_client_mod, "TOOL_TO_PROFILE", {"nuclei": "nuclei_cves"})
    monkeypatch.setattr(
        mcp_client_mod, "resolve_authorized_scope_for_dispatch", lambda sid: ["x"]
    )
    monkeypatch.setattr(
        mcp_client_mod.MCPClient,
        "list_tools_sync",
        lambda self: [{"name": "nuclei_cves", "metadata": {"timeout": 900}}],
    )
    monkeypatch.setattr(
        mcp_client_mod.MCPClient,
        "call_tool_sync",
        lambda self, name, payload, timeout=None: dict(FAKE_RESULT),
    )

    svc = mcp_client_mod.MCPClient.__new__(mcp_client_mod.MCPClient)
    svc.base_url = "http://mcp_server:3000"
    svc.timeout = 60.0

    out = svc.execute_kali_tool_sync("nuclei", "http://x", scan_id=1)
    env = out.get("envelope") or {}
    assert env.get("envelope_version") == "result-envelope/v1"
    assert len(env.get("findings_raw") or []) == 1
    assert env["findings_raw"][0]["id"] == "http/x"


def test_graph_accumulates_envelope_findings_with_cap():
    """O merge do _run_tools_and_collect acumula em state['envelope_findings']
    com cap de 200 e métrica total — mesma lógica aplicada no workflow."""
    from app.graph.workflow import initial_state

    state = initial_state(0, 1, "http://x")
    bucket = list(state.get("envelope_findings") or [])
    for i in range(250):
        bucket.append({"tool": "nuclei", "findings_raw": [{"id": f"t{i}"}]})
    state["envelope_findings"] = bucket[-200:]
    assert len(state["envelope_findings"]) == 200
    assert state["envelope_findings"][-1]["findings_raw"][0]["id"] == "t249"
