from __future__ import annotations

from pathlib import Path

from app.services.llm_determinism import (
    DEFAULT_LLM_DETERMINISTIC_SEED,
    deterministic_llm_options,
    ollama_generate_payload,
)


def test_deterministic_llm_options_force_sampling_contract(monkeypatch) -> None:
    monkeypatch.setattr("app.services.llm_determinism.settings.llm_deterministic_seed", 123)

    options = deterministic_llm_options({"temperature": 0.9, "top_p": 0.5, "num_predict": 2048})

    assert options["temperature"] == 0
    assert options["top_p"] == 1
    assert options["seed"] == 123
    assert options["num_predict"] == 2048


def test_ollama_generate_payload_includes_seed_when_setting_is_empty(monkeypatch) -> None:
    monkeypatch.setattr("app.services.llm_determinism.settings.llm_deterministic_seed", 0)

    payload = ollama_generate_payload("llama3", "prompt", system="system", format="json")

    assert payload["model"] == "llama3"
    assert payload["prompt"] == "prompt"
    assert payload["system"] == "system"
    assert payload["format"] == "json"
    assert payload["options"]["temperature"] == 0
    assert payload["options"]["top_p"] == 1
    assert payload["options"]["seed"] == DEFAULT_LLM_DETERMINISTIC_SEED


def test_all_ollama_runtime_calls_use_determinism_helpers() -> None:
    app_root = Path(__file__).resolve().parents[1] / "app"
    offenders: list[str] = []
    for path in app_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "/api/generate" in text and path.name != "llm_determinism.py" and "ollama_generate_payload" not in text:
            offenders.append(str(path.relative_to(app_root)))
        if "/api/chat" in text and path.name != "llm_determinism.py" and "ollama_chat_payload" not in text:
            offenders.append(str(path.relative_to(app_root)))

    assert offenders == []
