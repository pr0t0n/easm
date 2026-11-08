"""decision_port — porta única de decisão tipada (noul/choice/score).

Fase 3 do PLANO_CANDIDATE_VALIDATION: o JEV (jev-local) decide dentro de um
espaço fechado proposto pelo código; o código mantém guardrails duros
(allowlist, budget, escopo). Toda decisão é persistida em `jev_decisions`.

Backends:
  - "rule" (default): fallback determinístico local, sempre disponível.
  - "jev": HTTP para o jev-local (POST /v1/systemone). Abaixo do limiar, ou
    JEV indisponível, ou resposta fora do contrato → cai no rule. JEV NUNCA
    bloqueia o fluxo.
  - shadow (flag): usa rule, mas grava a resposta JEV paralela em `shadow`
    para calibração.

Contrato do jev-local (jev-local/app.py): POST /v1/systemone com
{model?, state, questions:[{id, kind, question, options?, scale_max?}]} →
{answers:[{id, kind, value, probability, source, ...}]}.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)

JEV_BASE_URL = (os.getenv("JEV_BASE_URL") or "http://jev_local:8097").rstrip("/")
JEV_TIMEOUT_SECONDS = float(os.getenv("JEV_DECISION_TIMEOUT_SECONDS", "8"))


def _backend() -> str:
    return str(getattr(settings, "jev_decision_backend", "rule") or "rule").strip().lower()


def _threshold(question_id: str, override: float | None) -> float:
    if override is not None:
        return float(override)
    defaults = dict(getattr(settings, "jev_decision_thresholds", None) or {})
    return float(defaults.get(question_id) or getattr(settings, "jev_decision_threshold", 0.6) or 0.6)


def _rule_answer(kind: str, question: str, state: Any, options: list[str] | None, scale_max: int) -> dict[str, Any]:
    """Fallback determinístico — nunca falha."""
    if kind == "noul":
        return {"value": False, "probability": 0.5}
    if kind == "choice":
        opts = [str(o) for o in (options or []) if str(o).strip()] or ["unknown"]
        return {"value": opts[0], "probability": round(1.0 / len(opts), 4)}
    return {"value": max(1, int(scale_max) // 2), "probability": 0.5}


def _call_jev(
    *,
    question_id: str,
    kind: str,
    question: str,
    state: Any,
    options: list[str] | None,
    scale_max: int,
) -> dict[str, Any] | None:
    """Uma pergunta ao jev-local. None em qualquer falha (contrato: nunca 5xx)."""
    import httpx

    q: dict[str, Any] = {"id": question_id, "kind": kind, "question": question[:3500]}
    if kind == "choice":
        q["options"] = [str(o) for o in (options or [])][:24]
        if len(q["options"]) < 2:
            return None
    if kind == "score":
        q["scale_max"] = max(2, min(10, int(scale_max)))
    payload = {"state": state if state not in (None, "") else {}, "questions": [q]}
    try:
        with httpx.Client(timeout=JEV_TIMEOUT_SECONDS) as client:
            resp = client.post(f"{JEV_BASE_URL}/v1/systemone", json=payload)
            resp.raise_for_status()
            body = resp.json() or {}
        answers = body.get("answers") or []
        if not answers:
            return None
        ans = answers[0]
        value = ans.get("value")
        if kind == "noul" and not isinstance(value, bool):
            return None
        if kind == "choice" and str(value) not in set(q["options"]):
            return None
        if kind == "score":
            try:
                ivalue = int(value)
            except (TypeError, ValueError):
                return None
            if not (1 <= ivalue <= q["scale_max"]):
                return None
            value = ivalue
        try:
            probability = max(0.0, min(1.0, float(ans.get("probability"))))
        except (TypeError, ValueError):
            probability = 0.5
        return {"value": value, "probability": probability, "jev_source": ans.get("source")}
    except Exception as exc:  # noqa: BLE001 — JEV nunca bloqueia
        logger.debug("jev decision failed question=%s: %s", question_id, exc)
        return None


def _persist(
    *,
    scan_id: int | None,
    question_id: str,
    kind: str,
    question: str,
    answer: dict[str, Any],
    threshold: float,
    source: str,
    shadow: dict[str, Any],
    context: dict[str, Any],
) -> None:
    try:
        from app.db.session import SessionLocal
        from app.models.models import JevDecision

        db = SessionLocal()
        try:
            db.add(JevDecision(
                scan_job_id=int(scan_id) if scan_id else None,
                question_id=question_id[:120],
                kind=kind,
                question=str(question or "")[:4000],
                answer=dict(answer),
                probability=float(answer.get("probability") or 0.0),
                threshold=float(threshold),
                source=source,
                shadow=dict(shadow),
                context=dict(context),
            ))
            db.commit()
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001 — auditoria não derruba decisão
        logger.debug("jev decision persist failed: %s", exc)


def decide(
    *,
    question_id: str,
    kind: str,  # noul | choice | score
    question: str,
    state: Any = None,
    options: list[str] | None = None,
    scale_max: int = 5,
    threshold: float | None = None,
    scan_id: int | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Decide uma pergunta fechada e persiste o registro.

    Retorna {value, probability, source, below_threshold}. Em qualquer falha
    do JEV, cai no rule determinístico (source="rule").
    """
    kind = str(kind or "").strip().lower()
    if kind not in {"noul", "choice", "score"}:
        raise ValueError(f"unknown decision kind: {kind}")
    thr = _threshold(question_id, threshold)
    want_jev = _backend() == "jev"
    shadow_mode = bool(getattr(settings, "jev_shadow_mode", False))

    rule = _rule_answer(kind, question, state, options, scale_max)
    rule.update({"source": "rule"})

    jev_answer: dict[str, Any] | None = None
    if want_jev or shadow_mode:
        jev_answer = _call_jev(
            question_id=question_id, kind=kind, question=question,
            state=state, options=options, scale_max=scale_max,
        )

    if want_jev and not shadow_mode and jev_answer is not None:
        below = jev_answer["probability"] < thr
        chosen = rule if below else {**jev_answer, "source": "jev"}
    else:
        chosen = rule
        below = False

    shadow_payload = {
        "jev": jev_answer,
        "rule": rule,
        "backend_requested": _backend(),
        "shadow_mode": shadow_mode,
    }
    _persist(
        scan_id=scan_id, question_id=question_id, kind=kind, question=question,
        answer={"value": chosen["value"], "probability": chosen["probability"]},
        threshold=thr, source=str(chosen["source"]),
        shadow=shadow_payload, context=dict(context or {}),
    )
    return {
        "value": chosen["value"],
        "probability": float(chosen["probability"]),
        "source": str(chosen["source"]),
        "below_threshold": bool(below),
        "threshold": thr,
    }
