"""Supervisor de Orquestracao — prompt deterministico para selecao de tecnica.

This is the system prompt the supervisor uses to translate a learned playbook
into a single, unambiguous execution decision. The supervisor itself does NOT
execute tools — it prepares the execution context for the Tool Selection
Engine, which then dispatches to the Kali runner.

Inputs the supervisor receives at runtime (substituted into the prompt):
  - PLAYBOOK_APRENDIDO   = serialized seed/learning entry (JSON)
  - EXECUTION_CONTEXT    = current scan state (phase, target, signals)
  - SKILL_MEMORY         = RAG context for the worker/skill (tests + learnings)
  - TOOL_CATALOG         = list of available tools with descriptions

Output (strict JSON, no prose) drives:
  - which technique gets attempted next
  - which phase / skill / target the execution belongs to
  - whether to block, proceed, or escalate to human review

Each capability node calls `build_supervisor_orchestration_prompt(...)` to
materialize the instance prompt, then asks the LLM (Ollama qwen2.5 by default)
for a JSON decision, then routes the decision through the Kali runner.
"""
from __future__ import annotations

import json
from typing import Any


# ── Static system prompt (the user-provided contract) ────────────────────────
SUPERVISOR_ORCHESTRATION_SYSTEM_PROMPT = """Você é o Supervisor de Orquestração de uma plataforma de segurança ofensiva controlada.

Sua função é transformar um playbook de vulnerabilidade estruturado em uma decisão de execução clara e determinística para seleção de ferramenta.

Você NÃO executa testes.
Você NÃO escolhe ferramenta diretamente.
Você PREPARA o contexto para o Tool Selection Engine.

ENTRADA:

1. PLAYBOOK_APRENDIDO (JSON estruturado)
2. EXECUTION_CONTEXT (estado atual do scan)
3. SKILL_MEMORY (aprendizado recuperado por skill, incluindo testes e historico)
4. TOOL_CATALOG (lista de ferramentas disponíveis)

OBJETIVO:

Selecionar UMA técnica do playbook e preparar o contexto completo para execução segura.

---

REGRAS:

1. Seleção de técnica:
- Escolher a técnica mais relevante para a fase atual
- Priorizar técnicas com maior evidência potencial
- Evitar técnicas de alto risco se não necessário

2. Determinar:
- phase atual
- skill necessária
- objetivo da execução
- quais sinais do aprendizado recuperado realmente sustentam a decisao

3. NÃO ambíguo:
- Nunca retornar múltiplas técnicas
- Nunca deixar fase/skill indefinida

4. Segurança:
- Se não houver escopo autorizado → bloquear execução
- Se risco > permitido → ajustar ou bloquear

---

SAÍDA OBRIGATÓRIA (JSON):

{
  "execution_decision": "proceed | block | needs_review",

  "selected_technique": {
    "name": "string",
    "objective": "string",
    "reason": "string"
  },

  "execution_context": {
    "target": "string",
    "phase": "string",
    "skill": "string",
    "authorized_scope": true,
    "auth_available": true,
    "max_risk_allowed": "low | medium | high"
  },

  "signals_to_validate": ["string"],

  "constraints": [
    "string"
  ],

  "notes": "string",

  "confidence": 0.0
}

---

REGRAS FINAIS:
- JSON puro
- Sem texto fora do JSON
- Não inventar técnica
- Não deixar campos vazios
"""


def build_supervisor_orchestration_prompt(
    playbook: dict[str, Any],
    execution_context: dict[str, Any],
    tool_catalog: list[dict[str, Any]] | str,
    skill_memory: dict[str, Any] | None = None,
) -> str:
    """Materializes the supervisor instance prompt with concrete inputs.

    Returns a single string that goes as the user message after the system
    prompt above. The LLM should reply with strict JSON matching the schema
    documented in SUPERVISOR_ORCHESTRATION_SYSTEM_PROMPT.
    """
    if isinstance(tool_catalog, str):
        catalog_block = tool_catalog
    else:
        catalog_block = json.dumps(tool_catalog, ensure_ascii=False, indent=2)

    return (
        "PLAYBOOK_APRENDIDO:\n"
        + json.dumps(playbook or {}, ensure_ascii=False, indent=2)
        + "\n\nEXECUTION_CONTEXT:\n"
        + json.dumps(execution_context or {}, ensure_ascii=False, indent=2)
        + "\n\nSKILL_MEMORY:\n"
        + json.dumps(skill_memory or {}, ensure_ascii=False, indent=2)
        + "\n\nTOOL_CATALOG:\n"
        + catalog_block
        + "\n\nResponda APENAS com o JSON da SAÍDA OBRIGATÓRIA."
    )


# ── Output validation ────────────────────────────────────────────────────────
REQUIRED_TOP_LEVEL = {
    "execution_decision",
    "selected_technique",
    "execution_context",
    "signals_to_validate",
    "constraints",
    "notes",
    "confidence",
}
ALLOWED_DECISIONS = {"proceed", "block", "needs_review"}
ALLOWED_RISKS = {"low", "medium", "high"}


def validate_orchestration_decision(raw: Any) -> dict[str, Any]:
    """Strict shape check + safe defaults. Returns a normalized dict.

    Raises ValueError if the LLM produced something outside the contract —
    callers should fall back to the deterministic technique-selector when
    that happens.
    """
    if not isinstance(raw, dict):
        raise ValueError("orchestration output is not a JSON object")

    missing = REQUIRED_TOP_LEVEL - set(raw.keys())
    if missing:
        raise ValueError(f"orchestration output missing keys: {sorted(missing)}")

    decision = str(raw.get("execution_decision") or "").strip().lower()
    if decision not in ALLOWED_DECISIONS:
        raise ValueError(f"execution_decision must be one of {ALLOWED_DECISIONS}")

    technique = raw.get("selected_technique") or {}
    if not isinstance(technique, dict):
        raise ValueError("selected_technique must be an object")
    for key in ("name", "objective", "reason"):
        if not str(technique.get(key) or "").strip():
            raise ValueError(f"selected_technique.{key} is empty")

    context = raw.get("execution_context") or {}
    if not isinstance(context, dict):
        raise ValueError("execution_context must be an object")
    for key in ("target", "phase", "skill"):
        if not str(context.get(key) or "").strip():
            raise ValueError(f"execution_context.{key} is empty")
    risk = str(context.get("max_risk_allowed") or "").strip().lower()
    if risk not in ALLOWED_RISKS:
        raise ValueError(f"max_risk_allowed must be one of {ALLOWED_RISKS}")

    signals = raw.get("signals_to_validate") or []
    if not isinstance(signals, list):
        raise ValueError("signals_to_validate must be a list")

    constraints = raw.get("constraints") or []
    if not isinstance(constraints, list):
        raise ValueError("constraints must be a list")

    confidence = raw.get("confidence")
    try:
        confidence = float(confidence)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"confidence must be numeric: {exc}") from exc
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")

    return {
        "execution_decision": decision,
        "selected_technique": {
            "name": str(technique["name"]).strip(),
            "objective": str(technique["objective"]).strip(),
            "reason": str(technique["reason"]).strip(),
        },
        "execution_context": {
            "target": str(context["target"]).strip(),
            "phase": str(context["phase"]).strip(),
            "skill": str(context["skill"]).strip(),
            "authorized_scope": bool(context.get("authorized_scope", False)),
            "auth_available": bool(context.get("auth_available", False)),
            "max_risk_allowed": risk,
        },
        "signals_to_validate": [str(s).strip() for s in signals if str(s).strip()],
        "constraints": [str(c).strip() for c in constraints if str(c).strip()],
        "notes": str(raw.get("notes") or "").strip(),
        "confidence": round(confidence, 3),
    }


__all__ = [
    "SUPERVISOR_ORCHESTRATION_SYSTEM_PROMPT",
    "build_supervisor_orchestration_prompt",
    "validate_orchestration_decision",
    "ALLOWED_DECISIONS",
    "ALLOWED_RISKS",
]
