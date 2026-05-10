from app.agents.supervisor_runtime import (
    _candidate_ollama_models,
    _coerce_orchestration_payload,
)


def test_candidate_ollama_models_resolve_installed_aliases(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.agents.supervisor_runtime._fetch_ollama_models",
        lambda: ["qwen2.5:7b-instruct", "codellama:13b-instruct"],
    )
    monkeypatch.setattr("app.agents.supervisor_runtime.settings.llm_primary_model", "qwen2.5:7b")
    monkeypatch.setattr("app.agents.supervisor_runtime.settings.ollama_qwen_model", "qwen2.5:7b")
    monkeypatch.setattr("app.agents.supervisor_runtime.settings.ollama_model", "llama3")
    monkeypatch.setattr("app.agents.supervisor_runtime.settings.ollama_cloudcode_model", "llama3.1:8b")

    models = _candidate_ollama_models()

    assert models[0] == "qwen2.5:7b-instruct"


def test_coerce_orchestration_payload_repairs_partial_llm_output() -> None:
    playbook = {
        "title": "Accepted vulnerability learning playbook",
        "techniques": [
            {
                "name": "juice shop sqli validation",
                "objective": "Confirm SQL injection safely",
                "recommended_kali_tools": ["sqlmap", "nuclei"],
                "evidence_signals": ["sql error", "time delay"],
                "affected_phases": ["P11"],
            }
        ],
        "evidence_signals": ["sql error"],
    }
    execution_context = {
        "target": "http://localhost:3001",
        "phase": "P11",
        "skill": "sqli",
        "authorized_scope": True,
        "auth_available": False,
        "max_risk_allowed": "medium",
    }

    repaired = _coerce_orchestration_payload(
        parsed={"selected_tool": "sqlmap", "reason": "query parameter looks injectable"},
        playbook=playbook,
        execution_context=execution_context,
        skill_memory={"recommended_tools": ["sqlmap"]},
    )

    assert repaired is not None
    assert repaired["execution_decision"] == "proceed"
    assert repaired["selected_technique"]["name"] == "juice shop sqli validation"
    assert repaired["execution_context"]["phase"] == "P11"
    assert "sql error" in repaired["signals_to_validate"]
