import json
import time

import httpx

from app.core.config import settings
from app.services.resilience import SimpleCircuitBreaker, guarded_call


_MODEL_CACHE: dict[str, object] = {
    "models": tuple(),
    "expires_at": 0.0,
}

_GENERATION_CACHE: dict[str, object] = {
    "cooldown_until": 0.0,
}

_OLLAMA_BREAKER = SimpleCircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30)

MODEL_CACHE_TTL_SECONDS = 60.0
EMPTY_MODEL_CACHE_TTL_SECONDS = 10.0
GENERATION_ERROR_COOLDOWN_SECONDS = 120.0


def _generation_in_cooldown() -> bool:
    now = time.time()
    cooldown_until = float(_GENERATION_CACHE.get("cooldown_until", 0.0) or 0.0)
    return now < cooldown_until


def _set_generation_cooldown() -> None:
    _GENERATION_CACHE["cooldown_until"] = time.time() + GENERATION_ERROR_COOLDOWN_SECONDS


def _ollama_available_models() -> tuple[str, ...]:
    now = time.time()
    cached_models = _MODEL_CACHE.get("models")
    cached_expires_at = float(_MODEL_CACHE.get("expires_at", 0.0) or 0.0)
    if isinstance(cached_models, tuple) and now < cached_expires_at:
        return cached_models

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{settings.ollama_base_url}/api/tags")
        if resp.status_code != 200:
            _MODEL_CACHE["models"] = tuple()
            _MODEL_CACHE["expires_at"] = now + EMPTY_MODEL_CACHE_TTL_SECONDS
            return tuple()
        payload = resp.json()
        models = []
        for item in payload.get("models", []):
            name = str(item.get("name") or "").strip()
            if name:
                models.append(name)
        resolved = tuple(models)
        _MODEL_CACHE["models"] = resolved
        _MODEL_CACHE["expires_at"] = now + (MODEL_CACHE_TTL_SECONDS if resolved else EMPTY_MODEL_CACHE_TTL_SECONDS)
        return resolved
    except Exception:
        _MODEL_CACHE["models"] = tuple()
        _MODEL_CACHE["expires_at"] = now + EMPTY_MODEL_CACHE_TTL_SECONDS
        return tuple()


def _resolve_model(requested_model: str) -> str:
    available = _ollama_available_models()
    if not available:
        return ""

    requested = (requested_model or "").strip()
    if requested and requested in available:
        return requested

    preferred = (settings.ollama_model or "").strip()
    if preferred and preferred in available:
        return preferred

    return available[0]


def _call_ollama(model: str, prompt: str) -> str:
    if not settings.ai_recommendations_use_ollama:
        return ""

    if _generation_in_cooldown():
        return ""

    resolved_model = _resolve_model(model)
    if not resolved_model:
        return ""

    try:
        timeout_seconds = float(settings.ai_recommendations_timeout_seconds)
        if timeout_seconds <= 0:
            timeout_seconds = 20.0
        with httpx.Client(timeout=timeout_seconds) as client:
            resp = guarded_call(
                _OLLAMA_BREAKER,
                lambda: client.post(
                    f"{settings.ollama_base_url}/api/generate",
                    json={
                        "model": resolved_model,
                        "prompt": prompt,
                        "stream": False,
                    },
                ),
                on_open_error=RuntimeError("circuit_open: ollama indisponivel temporariamente"),
            )
        if resp.status_code != 200:
            if resp.status_code >= 500:
                _set_generation_cooldown()
            return ""
        payload = resp.json()
        return (payload.get("response") or "").strip()
    except Exception:
        _set_generation_cooldown()
        return ""


def generate_portuguese_recommendations(finding: dict, known_patterns: list[str] | None = None) -> dict:
    title = str(finding.get("title", "Achado de seguranca"))
    severity = str(finding.get("severity", "medium"))
    details = finding.get("details") if isinstance(finding.get("details"), dict) else finding
    known_list = known_patterns or []

    base_prompt = (
        "Voce e um analista senior de ciberseguranca. "
        "Responda SOMENTE em portugues do Brasil e em JSON valido. "
        "Objetivo: recomendar mitigacoes praticas para vulnerabilidades encontradas no EASM. "
        "Formato JSON obrigatorio: "
        '{"resumo":"...","impacto":"...","mitigacoes":["..."],"prioridade":"baixa|media|alta|critica","validacoes":["..."]}. '
        "Contexto do achado: "
        f"titulo={title}; severidade={severity}; detalhes={json.dumps(details, ensure_ascii=True)}. "
        f"Padroes conhecidos no banco para autoaprendizado: {json.dumps(known_list[:25], ensure_ascii=True)}."
    )

    qwen_text = _call_ollama(settings.ollama_qwen_model, base_prompt)
    cloudcode_text = _call_ollama(settings.ollama_cloudcode_model, base_prompt)

    if not qwen_text:
        qwen_text = json.dumps(
            {
                "resumo": f"Risco identificado: {title}",
                "impacto": "Possivel exposicao de superficie externa e aumento do risco operacional.",
                "mitigacoes": [
                    "Aplicar correcao de configuracao ou patch no servico afetado.",
                    "Restringir exposicao externa via firewall/WAF e segmentacao.",
                    "Monitorar eventos correlatos no SIEM com alerta priorizado.",
                ],
                "prioridade": "media",
                "validacoes": [
                    "Executar reteste apos mitigacao.",
                    "Confirmar ausencia de regressao em scan subsequente.",
                ],
            },
            ensure_ascii=True,
        )

    if not cloudcode_text:
        cloudcode_text = qwen_text

    return {
        "qwen_recomendacao_pt": qwen_text,
        "cloudcode_recomendacao_pt": cloudcode_text,
    }
