"""Fase 1 (LANGGRAPH_BRAIN_PLAN): state slim — caps de telemetria no checkpoint.

ScanJob.state_data é a persistência durável do scan (o checkpointer do
LangGraph é em memória). Listas append-only de telemetria cresciam sem limite;
o StateDataJSON agora aplica caps no bind. Listas de decisão (executed_tool_
runs, vulnerabilidades_encontradas, logs_terminais) NUNCA são cortadas.
"""
from __future__ import annotations

from app.models.encrypted_json import StateDataJSON


def _bind(state: dict) -> dict:
    return StateDataJSON().process_bind_param(state, dialect=None)


def test_telemetry_lists_are_capped_on_bind():
    state = {
        "activity_metrics": [{"n": i} for i in range(800)],
        "autonomy_notes": [{"i": i} for i in range(500)],
        "envelope_findings": [{"i": i} for i in range(400)],
    }
    out = _bind(state)
    assert len(out["activity_metrics"]) == 500
    assert out["activity_metrics"][-1] == {"n": 799}, "cap preserva os mais recentes"
    assert len(out["autonomy_notes"]) == 300
    assert len(out["envelope_findings"]) == 200


def test_decision_lists_are_never_capped():
    state = {
        "executed_tool_runs": [f"p01|t|tool{i}" for i in range(1500)],
        "vulnerabilidades_encontradas": [{"id": i} for i in range(600)],
        "logs_terminais": [f"log {i}" for i in range(5000)],
    }
    out = _bind(state)
    assert len(out["executed_tool_runs"]) == 1500
    assert len(out["vulnerabilidades_encontradas"]) == 600
    assert len(out["logs_terminais"]) == 5000


def test_non_dict_and_small_lists_pass_through():
    assert StateDataJSON().process_bind_param(None, None) is None
    small = {"activity_metrics": [{"n": 1}], "auth_config": None}
    out = _bind(small)
    assert out["activity_metrics"] == [{"n": 1}]


def test_sensitive_subtrees_still_encrypted_with_caps():
    state = {
        "auth_config": {"password": "secret"},
        "activity_metrics": [{"n": i} for i in range(600)],
    }
    out = _bind(state)
    enc = out["auth_config"]
    assert isinstance(enc, dict) and "__enc__" in enc
    assert "secret" not in str(enc)
    assert len(out["activity_metrics"]) == 500
