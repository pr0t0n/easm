"""jev-local — motor de decisão tipada local (Jev-compatible).

Implementa localmente o contrato HTTP do Jev (System One) descrito em
docs/ANALISE_JEV_FLUXO_DECISAO_2026-11-05.md: recebe `state` + perguntas
fechadas e devolve respostas TIPADAS com probabilidade — nunca texto livre.

Primitivos:
  - noul   → sim/não com P(sim)
  - choice → uma entre opções declaradas, com P por opção
  - score  → nível inteiro 1..scale_max, com P(confiança)

Backend semântico: Ollama local com payload determinístico (temperature 0,
top_p 1, seed fixa — mesmo contrato de backend/app/services/llm_determinism.py).

Fallback: Ollama fora / resposta inválida / opção fora do enum → resposta
determinística por regra lexical (source="rule"). O serviço NUNCA bloqueia o
chamador: toda falha degrada para rule, nunca para 5xx.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

JEV_PORT = int(os.getenv("JEV_PORT", "8097"))
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434").rstrip("/")
JEV_MODEL = os.getenv("JEV_MODEL", "llama3.2:3b")
OLLAMA_TIMEOUT_SECONDS = float(os.getenv("JEV_OLLAMA_TIMEOUT_SECONDS", "20"))
STATE_MAX_CHARS = int(os.getenv("JEV_STATE_MAX_CHARS", "12000"))

# Mesmo seed do backend (llm_determinism.py) — decisões de scan não podem
# depender de amostragem por arquivo.
DETERMINISTIC_SEED = 424242

app = FastAPI(title="jev-local", version="0.1.0")


# ─────────────────────────────────────────────────────────────
# Contrato
# ─────────────────────────────────────────────────────────────

class Question(BaseModel):
    id: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern="^(noul|choice|score)$")
    question: str = Field(min_length=1, max_length=4000)
    # choice: enum fechado declarado pelo chamador
    options: list[str] = Field(default_factory=list)
    # score: escala inteira 1..scale_max
    scale_max: int = 5
    # critério explícito (em inglês, melhor desempenho do backend semântico)
    criteria: str | None = Field(default=None, max_length=2000)

    @field_validator("options")
    @classmethod
    def _options_valid(cls, v: list[str]) -> list[str]:
        cleaned = [str(o).strip() for o in v if str(o).strip()]
        if len(cleaned) > 24:
            raise ValueError("choice supports at most 24 options")
        if len(cleaned) != len(set(cleaned)):
            raise ValueError("choice options must be unique")
        return cleaned

    @field_validator("scale_max")
    @classmethod
    def _scale_valid(cls, v: int) -> int:
        if not (2 <= int(v) <= 10):
            raise ValueError("scale_max must be between 2 and 10")
        return int(v)


class SystemOneRequest(BaseModel):
    model: str | None = Field(default=None, max_length=200)
    state: str | dict[str, Any] = ""
    questions: list[Question] = Field(min_length=1, max_length=32)

    @field_validator("questions")
    @classmethod
    def _question_semantics(cls, v: list[Question]) -> list[Question]:
        for q in v:
            if q.kind == "choice" and len(q.options) < 2:
                raise ValueError(f"choice question '{q.id}' requires >=2 options")
        ids = [q.id for q in v]
        if len(ids) != len(set(ids)):
            raise ValueError("question ids must be unique within a request")
        return v


class Answer(BaseModel):
    id: str
    kind: str
    value: bool | str | int
    probability: float = Field(ge=0.0, le=1.0)
    # choice: distribuição completa por opção (quando o backend a devolve)
    probabilities: dict[str, float] = Field(default_factory=dict)
    source: str  # "jev" | "rule"
    fallback_reason: str | None = None
    latency_ms: float


class SystemOneResponse(BaseModel):
    engine: str
    model: str
    latency_ms: float
    answers: list[Answer]


# ─────────────────────────────────────────────────────────────
# Backend semântico (Ollama, determinístico)
# ─────────────────────────────────────────────────────────────

def _state_text(state: str | dict[str, Any]) -> str:
    if isinstance(state, dict):
        text = json.dumps(state, ensure_ascii=False, default=str)
    else:
        text = str(state or "")
    return text[:STATE_MAX_CHARS]


def _prompt_for(question: Question, state_text: str) -> str:
    criteria = f"\nCRITERIA: {question.criteria}" if question.criteria else ""
    if question.kind == "noul":
        schema = '{"value": true|false, "probability": <0.0-1.0 confidence in the value>}'
    elif question.kind == "choice":
        opts = json.dumps(question.options)
        schema = (
            '{"value": <exactly one of the options>, '
            '"probabilities": {<option>: <0.0-1.0>, ...}}'
        )
        criteria += f"\nOPTIONS: {opts}\nThe value must be exactly one of the OPTIONS, copied verbatim."
    else:
        schema = (
            '{"value": <integer 1..%d>, "probability": <0.0-1.0 confidence in the value>}'
            % question.scale_max
        )
    return (
        "You are a deterministic decision engine. Answer the QUESTION using only "
        "the STATE below. Reply with ONE JSON object and nothing else.\n"
        f"QUESTION: {question.question}{criteria}\n"
        f"REQUIRED JSON SCHEMA: {schema}\n"
        f"STATE:\n{state_text}"
    )


def _ollama_generate(prompt: str, model: str) -> str:
    """Chamada Ollama com sampling determinístico. Levanta exceção em qualquer falha."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0,
            "top_p": 1,
            "seed": DETERMINISTIC_SEED,
            "num_predict": 256,
        },
    }
    with httpx.Client(timeout=OLLAMA_TIMEOUT_SECONDS) as client:
        resp = client.post(f"{OLLAMA_URL}/api/generate", json=payload)
        resp.raise_for_status()
        return str((resp.json() or {}).get("response") or "")


def _extract_json(raw: str) -> dict[str, Any]:
    text = str(raw or "").strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return {}
    try:
        value = json.loads(text[start : end + 1])
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _clamp_probability(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.5


def _answer_with_ollama(question: Question, state_text: str, model: str) -> Answer:
    """Faz a pergunta ao backend semântico e valida fail-closed.

    Qualquer desvio do contrato (JSON inválido, choice fora do enum, score
    fora da escala) levanta ValueError → o caller cai no fallback rule.
    """
    started = time.monotonic()
    raw = _ollama_generate(_prompt_for(question, state_text), model)
    data = _extract_json(raw)
    if not data:
        raise ValueError("empty_or_invalid_json")

    if question.kind == "noul":
        value = data.get("value")
        if not isinstance(value, bool):
            raise ValueError("noul_value_not_boolean")
        return Answer(
            id=question.id, kind="noul", value=value,
            probability=_clamp_probability(data.get("probability")),
            source="jev", latency_ms=round((time.monotonic() - started) * 1000, 2),
        )

    if question.kind == "choice":
        value = str(data.get("value") or "").strip()
        if value not in question.options:
            raise ValueError("choice_value_not_in_options")
        probabilities: dict[str, float] = {}
        raw_probs = data.get("probabilities")
        if isinstance(raw_probs, dict):
            for opt in question.options:
                if opt in raw_probs:
                    probabilities[opt] = _clamp_probability(raw_probs[opt])
        return Answer(
            id=question.id, kind="choice", value=value,
            probability=probabilities.get(value, _clamp_probability(data.get("probability"))),
            probabilities=probabilities,
            source="jev", latency_ms=round((time.monotonic() - started) * 1000, 2),
        )

    # score
    try:
        value = int(data.get("value"))
    except (TypeError, ValueError):
        raise ValueError("score_value_not_int")
    if not (1 <= value <= question.scale_max):
        raise ValueError("score_value_out_of_scale")
    return Answer(
        id=question.id, kind="score", value=value,
        probability=_clamp_probability(data.get("probability")),
        source="jev", latency_ms=round((time.monotonic() - started) * 1000, 2),
    )


# ─────────────────────────────────────────────────────────────
# Fallback determinístico (rule) — lexical overlap, nunca bloqueia
# ─────────────────────────────────────────────────────────────

def _rule_answer(question: Question, state_text: str, reason: str) -> Answer:
    started = time.monotonic()
    blob = f"{question.question} {question.criteria or ''} {state_text}".lower()

    if question.kind == "noul":
        # Sem julgamento semântico disponível: não assume verdadeiro.
        # O chamador decide por limiar; 0.5 abaixo de qualquer threshold útil.
        value, probability = False, 0.5
    elif question.kind == "choice":
        best, best_hits = question.options[0], -1
        for opt in question.options:
            hits = sum(1 for token in opt.lower().split() if len(token) > 3 and token in blob)
            if hits > best_hits:
                best, best_hits = opt, hits
        value = best
        probability = round(1.0 / len(question.options), 4)
    else:
        value = max(1, question.scale_max // 2)
        probability = 0.5

    return Answer(
        id=question.id, kind=question.kind, value=value,
        probability=probability, source="rule", fallback_reason=reason,
        latency_ms=round((time.monotonic() - started) * 1000, 2),
    )


# ─────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict[str, Any]:
    started = time.monotonic()
    ollama_ok = False
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"{OLLAMA_URL}/api/tags")
            ollama_ok = resp.status_code == 200
    except Exception:
        ollama_ok = False
    return {
        "status": "ok" if ollama_ok else "degraded",
        "engine": "jev-local",
        "model": JEV_MODEL,
        "ollama_url": OLLAMA_URL,
        "ollama_ok": ollama_ok,
        "latency_ms": round((time.monotonic() - started) * 1000, 2),
    }


@app.post("/v1/systemone", response_model=SystemOneResponse)
def systemone(request: SystemOneRequest) -> SystemOneResponse:
    model = (request.model or JEV_MODEL).strip() or JEV_MODEL
    state_text = _state_text(request.state)
    started = time.monotonic()
    answers: list[Answer] = []

    for question in request.questions:
        try:
            answers.append(_answer_with_ollama(question, state_text, model))
        except Exception as exc:  # noqa: BLE001 — degradação é o contrato
            reason = f"{type(exc).__name__}:{str(exc)[:120]}"
            logger.warning("jev question=%s kind=%s fallback=rule reason=%s",
                           question.id, question.kind, reason)
            answers.append(_rule_answer(question, state_text, reason))

    summary = ", ".join(
        f"{a.id}={a.value!r}({a.source},p={a.probability:.2f})" for a in answers
    )
    logger.info("systemone questions=%d model=%s %s", len(answers), model, summary)

    return SystemOneResponse(
        engine="jev-local/0.1.0",
        model=model,
        latency_ms=round((time.monotonic() - started) * 1000, 2),
        answers=answers,
    )


@app.get("/v1/questions")
def question_kinds() -> dict[str, Any]:
    """Documenta os primitivos suportados (introspecção para o decision_port)."""
    return {
        "kinds": {
            "noul": {"value": "boolean", "probability": "P(yes), 0-1"},
            "choice": {"value": "one of declared options", "probabilities": "per option"},
            "score": {"value": "integer 1..scale_max", "probability": "confidence"},
        },
        "deterministic_seed": DETERMINISTIC_SEED,
        "fallback": "rule (source=rule, fallback_reason set) — never 5xx",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=JEV_PORT)
