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
import re
from typing import Any

import httpx

from app.core.config import settings
from app.agents.supervisor_prompt import (
    SUPERVISOR_ORCHESTRATION_SYSTEM_PROMPT,
    build_supervisor_orchestration_prompt,
    validate_orchestration_decision,
)

logger = logging.getLogger(__name__)


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
    payload = {
        "model": settings.llm_primary_model,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "options": {"temperature": 0.1, "num_predict": 1024},
    }
    r = httpx.post(url, json=payload, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    return str(data.get("message", {}).get("content") or "").strip()


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

    chosen = techniques[0]
    if isinstance(chosen, str):
        chosen = {"name": chosen, "objective": "fallback first-step", "reason": "deterministic"}

    return {
        "execution_decision": "proceed",
        "selected_technique": {
            "name": str(chosen.get("name") or "first-pass"),
            "objective": str(chosen.get("objective") or "explore"),
            "reason": "fallback: LLM indisponível, primeiro técnica do playbook",
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


def decide_next_technique(
    playbook: dict[str, Any],
    execution_context: dict[str, Any],
    tool_catalog: list[dict[str, Any]] | str,
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
            decision = validate_orchestration_decision(parsed)
        except ValueError as exc:
            logger.warning("supervisor LLM produced invalid output: %s", exc)
            decision = _deterministic_fallback(playbook, execution_context)
            decision["notes"] = (
                decision["notes"] + f" | LLM output validation error: {exc}"
            ).strip()

    if decision["execution_decision"] == "block":
        raise BlockedDecision(reason=decision.get("notes") or "blocked by supervisor", raw=decision)

    return decision


__all__ = ["decide_next_technique", "BlockedDecision"]
