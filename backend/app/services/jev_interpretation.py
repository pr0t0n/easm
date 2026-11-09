"""Interpretação ternária do JEV (Estágio 6 do fluxo).

`Choice` {concluir, investigar, encerrar} sobre o dossiê — o slot advisory que
o `review_with_llm` ocupava, mas com decisão tipada e limiar alto (0.85).

Regras duras:
- Veredito final continua 100% determinístico — o JEV propõe, o código decide.
- "concluir" só promove quando o gate determinístico JÁ concluiu (confirmed).
- "investigar" = caminho atual (wire de validação).
- "encerrar" só vira not_applicable quando o dossiê tem contradições (FP
  provável) — caso contrário cai no veredito determinístico.
- Abaixo do limiar 0.85 ou JEV indisponível → comportamento atual (None).
"""
from __future__ import annotations

from typing import Any

_INTERPRET_THRESHOLD = 0.85
_OPTIONS = ["concluir", "investigar", "encerrar"]


def interpret_with_jev(
    dossier: dict[str, Any],
    decision: dict[str, Any],
    *,
    scan_id: int | None = None,
    finding_id: int | None = None,
) -> dict[str, Any] | None:
    """Proposta ternária do JEV. None = seguir o caminho determinístico atual."""
    try:
        from app.services.decision_port import decide

        finding = dict(dossier.get("finding") or {})
        quality = dict(dossier.get("quality") or {})
        contradictions = list(quality.get("contradictions") or [])
        missing = list(quality.get("missing_artifacts") or [])
        blob = {
            "title": str(finding.get("title") or "")[:200],
            "severity": str(finding.get("severity_claimed") or ""),
            "deterministic_verdict": str(decision.get("verdict") or ""),
            "reason_code": str(decision.get("reason_code") or ""),
            "missing_artifacts": missing[:10],
            "contradictions": contradictions[:5],
            "evidence_count": len(list(dossier.get("evidence") or [])),
            "confidence": float(decision.get("confidence") or 0),
        }
        result = decide(
            question_id="finding_interpretation",
            kind="choice",
            question=(
                "Given this adjudication dossier, what should happen to the finding? "
                "'concluir' only if the deterministic gate already confirmed it; "
                "'investigar' if more validation evidence is needed; "
                "'encerrar' only if the dossier shows contradictions indicating a false positive."
            ),
            options=list(_OPTIONS),
            state=blob,
            scan_id=scan_id,
            context={"finding_id": int(finding_id or 0) or None, "stage": "interpretation"},
            threshold=_INTERPRET_THRESHOLD,
        )
        if result.get("source") != "jev" or result.get("below_threshold"):
            return None
        value = str(result.get("value") or "")
        if value not in set(_OPTIONS):
            return None
        return {
            "proposal": value,
            "probability": float(result.get("probability") or 0.0),
            "threshold": _INTERPRET_THRESHOLD,
        }
    except Exception:  # noqa: BLE001 — advisory nunca bloqueia o gate
        return None


def merge_interpretation(
    proposal: dict[str, Any] | None,
    decision: dict[str, Any],
    dossier: dict[str, Any],
) -> dict[str, Any]:
    """Aplica a proposta sobre o veredito determinístico, fail-closed."""
    if not proposal:
        return {}
    verdict = str(decision.get("verdict") or "")
    contradictions = list((dict(dossier.get("quality") or {}).get("contradictions") or []))
    action = str(proposal.get("proposal") or "")

    if action == "concluir" and verdict == "confirmed":
        # Gate já concluiu — a proposta só reforça (sem mudança de estado).
        return {"interpretation": action, "applied": False, "note": "deterministic_gate_already_confirmed"}
    if action == "encerrar" and contradictions and verdict in {"inconclusive", "blocked"}:
        return {
            "interpretation": action,
            "applied": True,
            "final_verdict": "not_applicable",
            "reason_code": "jev_interpretation_false_positive_contradictions",
        }
    # "investigar" e demais casos: caminho atual (wire/gate) permanece.
    return {"interpretation": action, "applied": False, "note": "deterministic_path_preserved"}
