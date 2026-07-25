from __future__ import annotations

from typing import Any

from app.core.config import settings


DEFAULT_LLM_DETERMINISTIC_SEED = 424242


def _deterministic_seed() -> int:
    return int(
        getattr(settings, "llm_deterministic_seed", DEFAULT_LLM_DETERMINISTIC_SEED)
        or DEFAULT_LLM_DETERMINISTIC_SEED
    )


def deterministic_llm_options(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the single deterministic sampling contract for local LLM calls.

    Operational scan decisions, ranking, validation grading and report synthesis
    must not depend on per-file sampling defaults. Call-sites can still add
    non-sampling controls such as num_predict/num_ctx through ``extra``.
    """

    options: dict[str, Any] = {
        "temperature": 0,
        "top_p": 1,
        "seed": _deterministic_seed(),
    }
    if extra:
        options.update(extra)
        # Never allow a caller to silently reintroduce stochastic sampling for
        # scan/runtime logic. If creative prose is needed, it should use a
        # different explicit helper outside the scan stability path.
        options["temperature"] = 0
        options["top_p"] = 1
        options["seed"] = _deterministic_seed()
    return options


def ollama_generate_payload(
    model: str,
    prompt: str,
    *,
    stream: bool = False,
    system: str | None = None,
    format: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": stream,
        "options": deterministic_llm_options(options),
    }
    if system is not None:
        payload["system"] = system
    if format is not None:
        payload["format"] = format
    return payload


def ollama_chat_payload(
    model: str,
    messages: list[dict[str, str]],
    *,
    stream: bool = False,
    format: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model,
        "stream": stream,
        "messages": messages,
        "options": deterministic_llm_options(options),
    }
    if format is not None:
        payload["format"] = format
    return payload
