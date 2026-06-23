"""Supervisor runtime — calls the LLM with the orchestration prompt.

Glue between `agents/supervisor_prompt.py` and the actual LLM (Ollama by
default). Each capability node calls `decide_next_technique(...)` to get a
structured execution decision before dispatching to the Kali runner.

Failure modes:
  - LLM unavailable      → fall back to deterministic "first compatible"
                           technique from the playbook.
  - LLM returns garbage  → fall back + log to scan_logs.
  - LLM blocks (decision="block") → raises BlockedDecision so the caller
    can mark the phase as skipped_with_reason.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any

import httpx

from app.core.config import settings
from app.agents.supervisor_prompt import (
    REQUIRED_TOP_LEVEL,
    SUPERVISOR_ORCHESTRATION_SYSTEM_PROMPT,
    build_supervisor_orchestration_prompt,
    validate_orchestration_decision,
)

logger = logging.getLogger(__name__)
_OLLAMA_MODELS_CACHE: dict[str, Any] = {"expires_at": 0.0, "models": []}


class BlockedDecision(Exception):
    """Raised when the supervisor decides `execution_decision="block"`."""

    def __init__(self, reason: str, raw: dict[str, Any]):
        super().__init__(reason)
        self.raw = raw


def _extract_first_json_object(text: str) -> dict[str, Any] | None:
    """Best-effort: pull the first balanced {...} object out of LLM output."""
    if not text:
        return None
    text = text.strip()
    # Strip common code-fence wrappers
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    # Find balanced braces
    depth = 0
    start = -1
    for idx, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = idx
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                blob = text[start : idx + 1]
                try:
                    return json.loads(blob)
                except json.JSONDecodeError:
                    return None
    return None


def _ollama_chat(system: str, user: str, *, timeout: int = 60) -> str:
    """Calls the local Ollama /api/chat endpoint and returns the text reply."""
    url = f"{settings.ollama_base_url.rstrip('/')}/api/chat"
    models = _candidate_ollama_models()

    # P4 — opções base. num_predict cap a saída; temperature baixa p/ decisão.
    _options: dict[str, Any] = {"temperature": 0.1, "num_predict": 1024}
    # num_ctx (janela de contexto) é configurável por env. Por padrão fica
    # AUSENTE = comportamento atual do Ollama (default ~2048). Setar OLLAMA_NUM_CTX
    # > 0 amplia a janela p/ não truncar o prompt do supervisor — mas custa RAM
    # (KV-cache), então é lever explícito, medido com os logs abaixo, não default.
    _num_ctx = int(os.getenv("OLLAMA_NUM_CTX", "0") or 0)
    if _num_ctx > 0:
        _options["num_ctx"] = _num_ctx

    # P4 — instrumentação ("medir primeiro"): tamanho aproximado do prompt em
    # tokens (~chars/4) e latência por chamada, p/ ver se está truncando em
    # num_ctx e quanto cada decisão custa no LLM em CPU.
    _approx_tokens = (len(system) + len(user)) // 4

    last_error: Exception | None = None
    for model_name in models:
        payload = {
            "model": model_name,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "options": _options,
        }
        try:
            _t0 = time.perf_counter()
            r = httpx.post(url, json=payload, timeout=timeout)
            if r.status_code == 404 and len(models) > 1:
                last_error = httpx.HTTPStatusError(
                    f"model not found: {model_name}",
                    request=r.request,
                    response=r,
                )
                continue
            r.raise_for_status()
            data = r.json()
            _elapsed_ms = int((time.perf_counter() - _t0) * 1000)
            logger.info(
                "ollama_chat model=%s approx_prompt_tokens=%d num_ctx=%s latency_ms=%d",
                model_name, _approx_tokens, _num_ctx or "default", _elapsed_ms,
            )
            return str(data.get("message", {}).get("content") or "").strip()
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue

    if last_error:
        raise last_error
    raise RuntimeError("no Ollama model configured")


def _fetch_ollama_models() -> list[str]:
    now = time.time()
    cached = list(_OLLAMA_MODELS_CACHE.get("models") or [])
    if cached and float(_OLLAMA_MODELS_CACHE.get("expires_at") or 0.0) > now:
        return cached

    try:
        response = httpx.get(
            f"{settings.ollama_base_url.rstrip('/')}/api/tags",
            timeout=10,
        )
        response.raise_for_status()
        models = [
            str(item.get("name") or "").strip()
            for item in (response.json().get("models") or [])
            if str(item.get("name") or "").strip()
        ]
    except Exception as exc:  # noqa: BLE001
        logger.warning("failed to fetch Ollama tags: %s", exc)
        models = cached

    _OLLAMA_MODELS_CACHE["models"] = models
    _OLLAMA_MODELS_CACHE["expires_at"] = now + 60
    return models


def _resolve_ollama_model(preferred: str, available_models: list[str]) -> str | None:
    preferred = str(preferred or "").strip()
    if not preferred:
        return None
    if preferred in available_models:
        return preferred

    preferred_lower = preferred.lower()
    available_lower = {model.lower(): model for model in available_models}
    if preferred_lower in available_lower:
        return available_lower[preferred_lower]

    for model in available_models:
        lowered = model.lower()
        if lowered.startswith(preferred_lower):
            return model
        if preferred_lower.startswith(lowered):
            return model
        if preferred_lower in lowered:
            return model
    return None


def _candidate_ollama_models() -> list[str]:
    configured = [
        str(settings.llm_primary_model or "").strip(),
        str(settings.ollama_qwen_model or "").strip(),
        str(settings.ollama_model or "").strip(),
        str(settings.ollama_cloudcode_model or "").strip(),
    ]
    available = _fetch_ollama_models()
    ordered: list[str] = []
    for preferred in configured:
        resolved = _resolve_ollama_model(preferred, available)
        candidate = resolved or preferred
        if candidate and candidate not in ordered:
            ordered.append(candidate)
    for model in available:
        if model and model not in ordered:
            ordered.append(model)
    return ordered


def _deterministic_fallback(
    playbook: dict[str, Any],
    execution_context: dict[str, Any],
) -> dict[str, Any]:
    """When LLM is unreachable, pick the first technique listed in the
    playbook that matches the current phase. Honest about confidence."""
    phase = str(execution_context.get("phase") or "").strip()
    techniques = playbook.get("techniques") or playbook.get("safe_validation_steps") or []
    if not techniques:
        techniques = [{"name": playbook.get("title") or "first-pass", "objective": "explore phase"}]

    # Improved fallback: try to match phase if possible
    matched_techniques = []
    for tech in techniques:
        if isinstance(tech, dict):
            affected_phases = tech.get("affected_phases", [])
            if phase and any(phase.lower() in str(ph).lower() or str(ph).lower() in phase.lower() for ph in affected_phases):
                matched_techniques.append(tech)
        elif isinstance(tech, str):
            # If technique is just a string, include it
            matched_techniques.append({"name": tech, "objective": "fallback step"})

    # Use matched techniques if available, otherwise all
    chosen_pool = matched_techniques if matched_techniques else techniques
    chosen = chosen_pool[0] if chosen_pool else techniques[0]

    if isinstance(chosen, str):
        chosen = {"name": chosen, "objective": "fallback first-step", "reason": "deterministic"}

    return {
        "execution_decision": "proceed",
        "selected_technique": {
            "name": str(chosen.get("name") or "first-pass"),
            "objective": str(chosen.get("objective") or "explore"),
            "reason": "fallback: LLM indisponível, primeira técnica compatível do playbook",
        },
        "execution_context": {
            "target": str(execution_context.get("target") or ""),
            "phase": phase or "RECONNAISSANCE",
            "skill": str(execution_context.get("skill") or playbook.get("vulnerability_type") or "generic"),
            "authorized_scope": bool(execution_context.get("authorized_scope", True)),
            "auth_available": bool(execution_context.get("auth_available", False)),
            "max_risk_allowed": str(execution_context.get("max_risk_allowed") or "low"),
        },
        "signals_to_validate": list(playbook.get("evidence_signals") or [])[:5],
        "constraints": ["read-only", "no-destructive-payload"],
        "notes": "deterministic fallback (LLM unreachable or invalid output)",
        "confidence": 0.4,
    }


def _pick_playbook_technique(
    playbook: dict[str, Any],
    execution_context: dict[str, Any],
    hint: str = "",
) -> dict[str, Any]:
    phase = str(execution_context.get("phase") or "").strip().lower()
    hint_blob = str(hint or "").strip().lower()
    techniques = list(playbook.get("techniques") or [])
    if not techniques:
        return {
            "name": str(playbook.get("title") or "first-pass"),
            "objective": "explore phase",
            "reason": "playbook fallback",
        }

    for technique in techniques:
        if not isinstance(technique, dict):
            continue
        technique_blob = json.dumps(technique, ensure_ascii=False).lower()
        if hint_blob and hint_blob in technique_blob:
            return technique
        affected_phases = [str(item or "").strip().lower() for item in (technique.get("affected_phases") or [])]
        if phase and any(phase in item or item in phase for item in affected_phases if item):
            return technique

    first = techniques[0]
    return first if isinstance(first, dict) else {"name": str(first), "objective": "explore phase"}


def _coerce_orchestration_payload(
    parsed: dict[str, Any] | None,
    playbook: dict[str, Any],
    execution_context: dict[str, Any],
    skill_memory: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(parsed, dict):
        return None

    candidate = dict(parsed)
    for wrapper_key in ("result", "decision", "output", "response", "data"):
        wrapped = candidate.get(wrapper_key)
        if isinstance(wrapped, dict):
            candidate = dict(wrapped)
            break

    if REQUIRED_TOP_LEVEL.issubset(candidate.keys()):
        return candidate

    fallback = _deterministic_fallback(playbook, execution_context)
    selected = candidate.get("selected_technique")
    if not isinstance(selected, dict):
        hint = candidate.get("selected_technique") or candidate.get("technique") or candidate.get("selected_tool") or candidate.get("notes")
        selected = _pick_playbook_technique(playbook, execution_context, hint=str(hint or ""))
    if not str(selected.get("name") or "").strip():
        selected = _pick_playbook_technique(playbook, execution_context, hint=json.dumps(candidate, ensure_ascii=False))

    context = candidate.get("execution_context")
    if not isinstance(context, dict):
        context = {}

    signals = candidate.get("signals_to_validate")
    if not isinstance(signals, list) or not signals:
        signals = list(selected.get("evidence_signals") or playbook.get("evidence_signals") or fallback.get("signals_to_validate") or [])

    constraints = candidate.get("constraints")
    if not isinstance(constraints, list) or not constraints:
        constraints = ["read-only", "no-destructive-payload"]

    try:
        confidence = float(candidate.get("confidence"))
    except (TypeError, ValueError):
        confidence = float(fallback["confidence"])

    notes = str(candidate.get("notes") or candidate.get("reason") or "").strip() or "coerced supervisor payload"
    coerced = {
        "execution_decision": str(candidate.get("execution_decision") or "proceed").strip().lower(),
        "selected_technique": {
            "name": str(selected.get("name") or fallback["selected_technique"]["name"]).strip(),
            "objective": str(selected.get("objective") or fallback["selected_technique"]["objective"]).strip(),
            "reason": str(selected.get("reason") or notes or fallback["selected_technique"]["reason"]).strip(),
        },
        "execution_context": {
            "target": str(context.get("target") or execution_context.get("target") or fallback["execution_context"]["target"]).strip(),
            "phase": str(context.get("phase") or execution_context.get("phase") or fallback["execution_context"]["phase"]).strip(),
            "skill": str(context.get("skill") or execution_context.get("skill") or fallback["execution_context"]["skill"]).strip(),
            "authorized_scope": bool(context.get("authorized_scope", execution_context.get("authorized_scope", True))),
            "auth_available": bool(context.get("auth_available", execution_context.get("auth_available", False))),
            "max_risk_allowed": str(context.get("max_risk_allowed") or execution_context.get("max_risk_allowed") or "medium").strip().lower(),
        },
        "signals_to_validate": [str(item).strip() for item in signals if str(item).strip()][:8],
        "constraints": [str(item).strip() for item in constraints if str(item).strip()][:8],
        "notes": notes,
        "confidence": max(0.0, min(confidence, 1.0)),
    }
    if skill_memory:
        coerced["memory_context"] = {
            "knowledge_items": list(skill_memory.get("knowledge_items") or [])[:5],
            "recommended_tools": list(skill_memory.get("recommended_tools") or [])[:10],
            "retrieval_query": skill_memory.get("retrieval_query"),
        }
    return coerced


def decide_next_technique(
    playbook: dict[str, Any],
    execution_context: dict[str, Any],
    tool_catalog: list[dict[str, Any]] | str,
    skill_memory: dict[str, Any] | None = None,
    *,
    timeout: int = 60,
) -> dict[str, Any]:
    """Returns a validated orchestration decision (dict). Raises BlockedDecision
    if the supervisor decided to block.

    Always returns a usable dict — falls back to deterministic selection if
    the LLM is unreachable or returns malformed output. The returned dict
    matches the schema in `agents/supervisor_prompt.py`.
    """
    user_prompt = build_supervisor_orchestration_prompt(
        playbook=playbook,
        execution_context=execution_context,
        tool_catalog=tool_catalog,
        skill_memory=skill_memory,
    )

    raw_text: str | None = None
    parsed: dict[str, Any] | None = None
    try:
        raw_text = _ollama_chat(
            SUPERVISOR_ORCHESTRATION_SYSTEM_PROMPT,
            user_prompt,
            timeout=timeout,
        )
        parsed = _extract_first_json_object(raw_text) or json.loads(raw_text)
    except Exception as exc:  # noqa: BLE001
        logger.warning("supervisor LLM call failed: %s", exc)
        parsed = None

    if parsed is None:
        decision = _deterministic_fallback(playbook, execution_context)
    else:
        try:
            normalized = _coerce_orchestration_payload(parsed, playbook, execution_context, skill_memory)
            decision = validate_orchestration_decision(normalized or parsed)
        except ValueError as exc:
            logger.warning("supervisor LLM produced invalid output: %s", exc)
            decision = _deterministic_fallback(playbook, execution_context)
            decision["notes"] = (
                decision["notes"] + f" | LLM output validation error: {exc}"
            ).strip()

    if decision["execution_decision"] == "block":
        raise BlockedDecision(reason=decision.get("notes") or "blocked by supervisor", raw=decision)

    if skill_memory:
        decision.setdefault("memory_context", {
            "knowledge_items": list(skill_memory.get("knowledge_items") or [])[:5],
            "recommended_tools": list(skill_memory.get("recommended_tools") or [])[:10],
            "retrieval_query": skill_memory.get("retrieval_query"),
        })

    return decision


__all__ = ["decide_next_technique", "BlockedDecision"]
