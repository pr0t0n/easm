"""P21 — Testes de segurança do grafo / supervisor.

Propriedade crítica de uma plataforma AUTÔNOMA: o LLM (Ollama em CPU) pode
estar fora do ar, lento ou devolver lixo. Quando isso acontece, o supervisor
NÃO pode travar nem explodir — tem que cair num fallback determinístico e
seguir. Estes testes travam esse contrato.

(Os outros sub-itens do P21 — terminação/max_iterations e bloqueio de pivot
fora de escopo — dependem do harness de grafo/Attack Path, P14/P11/P15.)
"""
from __future__ import annotations

import pytest

from app.agents import supervisor_runtime as sr


_PLAYBOOK = {
    "techniques": [
        {"name": "httpx_probe", "affected_phases": ["RECONNAISSANCE"], "objective": "probe"},
    ],
    "evidence_signals": ["http_response"],
}
_CTX = {"phase": "RECONNAISSANCE", "target": "http://example.com"}


def test_supervisor_falls_back_when_llm_offline(monkeypatch):
    """LLM inalcançável → decisão determinística usável, sem exceção."""
    def _boom(*_a, **_k):
        raise RuntimeError("llm offline")

    monkeypatch.setattr(sr, "_ollama_chat", _boom)
    decision = sr.decide_next_technique(_PLAYBOOK, _CTX, [], None, timeout=1)

    assert isinstance(decision, dict)
    assert decision.get("execution_decision") == "proceed"
    assert decision.get("selected_technique")
    assert "fallback" in str(decision.get("notes", "")).lower()


def test_supervisor_falls_back_on_malformed_llm_output(monkeypatch):
    """LLM devolve texto não-JSON → ainda assim retorna decisão usável."""
    monkeypatch.setattr(sr, "_ollama_chat", lambda *_a, **_k: "isto não é json {{{")
    decision = sr.decide_next_technique(_PLAYBOOK, _CTX, [], None, timeout=1)

    assert isinstance(decision, dict)
    assert decision.get("execution_decision") in {"proceed", "block"}
    assert decision.get("selected_technique") or decision.get("notes")


def test_decide_next_technique_never_raises_for_empty_playbook(monkeypatch):
    """Playbook vazio + LLM offline não pode estourar exceção não tratada."""
    monkeypatch.setattr(sr, "_ollama_chat", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("x")))
    try:
        decision = sr.decide_next_technique({"techniques": []}, _CTX, [], None, timeout=1)
    except sr.BlockedDecision:
        return  # bloquear explicitamente é um resultado aceitável
    assert isinstance(decision, dict)
