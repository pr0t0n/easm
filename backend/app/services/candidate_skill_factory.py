"""Skill Factory — JEV tria reports H1 e propõe aprendizados (Estágio 7).

Quatro decisões tipadas por report, sempre via decision_port (JEV acima do
limiar, rule no fallback):

  Choice  "h1_family"         → qual família (catálogo FAMILY_LABELS, 24 opções)
  Noul    "h1_novel"          → duplica learning aceito existente?
  Noul    "h1_safe_autoaccept"→ conteúdo utilizável e seguro para aceite automático?
  Score   "h1_quality"        → qualidade 1-5 (ranqueia a fila humana)

REGRA DURA: o JEV nunca escreve arquivo de skill. Auto-aceite aqui significa
status='accepted' no banco (alimenta RAG/learnings); a escrita no catálogo
(`skills/`) continua exclusiva do aceite humano via
`_promote_learning_candidate_to_skill`.

Calibrável: a coluna `shadow` das decisões guarda jev vs rule para análise
de concordância contra rótulos reais do corpus aceito.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# 23 famílias de maior valor + "outros" = 24 (cap do jev-local para Choice).
FAMILY_OPTIONS: list[str] = [
    "sqli", "xss", "ssrf", "rce", "idor", "bola_bfla", "broken_access_control",
    "auth_bypass", "jwt_oauth", "csrf", "cors", "open_redirect", "path_traversal",
    "lfri", "ssti", "deserialization", "file_upload", "business_logic",
    "race_condition", "secrets", "security_headers", "info_exposure",
    "subdomain_takeover", "outros",
]

_QUALITY_ACCEPT_FLOOR = 4


def _learning_text(learning: Any) -> str:
    parts = [
        str(getattr(learning, "title", "") or ""),
        str(getattr(learning, "summary", "") or "")[:1200],
        str(getattr(learning, "steps_to_reproduce", "") or "")[:800],
    ]
    return "\n".join(p for p in parts if p.strip())


def _existing_titles(db: Any, limit: int = 30) -> list[str]:
    """Amostra de títulos aceitos para o JEV julgar novidade (estado enxuto)."""
    from app.models.models import VulnerabilityLearning
    rows = (
        db.query(VulnerabilityLearning.title)
        .filter(VulnerabilityLearning.status == "accepted", VulnerabilityLearning.title.isnot(None))
        .order_by(VulnerabilityLearning.accepted_at.desc().nullslast())
        .limit(limit)
        .all()
    )
    return [str(r[0] or "")[:160] for r in rows if str(r[0] or "").strip()]


def triage_learning(db: Any, learning: Any, *, scan_id: int | None = None) -> dict[str, Any]:
    """Triage de UM learning via JEV. Retorna vereditos + decisão final."""
    from app.services.decision_port import decide

    text = _learning_text(learning)
    if not text.strip():
        return {"learning_id": int(learning.id), "skipped": "empty_content"}

    state = {
        "report": text[:3000],
        "existing_accepted_titles": _existing_titles(db),
        "has_steps": bool(str(getattr(learning, "steps_to_reproduce", "") or "").strip()),
        "has_mission_or_prompt": bool(
            str(getattr(learning, "learned_mission", "") or "").strip()
            or str(getattr(learning, "learned_prompt", "") or "").strip()
        ),
        "technique_count": int(getattr(learning, "technique_count", 0) or 0),
    }

    fam = decide(
        question_id="h1_family", kind="choice",
        question="Which vulnerability family does this security report belong to? Choose exactly one option.",
        state={"report": state["report"]}, options=list(FAMILY_OPTIONS),
        scan_id=scan_id, context={"learning_id": int(learning.id), "factory": "h1"},
    )
    novelty = decide(
        question_id="h1_novel", kind="noul",
        question="Is this report a DUPLICATE of one of the existing accepted learnings (same vulnerability, same technique, same target class)? Answer yes only if clearly a duplicate.",
        state={"report": state["report"], "existing_accepted_titles": state["existing_accepted_titles"][:12]},
        scan_id=scan_id, context={"learning_id": int(learning.id), "factory": "h1"},
    )
    safe = decide(
        question_id="h1_safe_autoaccept", kind="noul",
        question=(
            "Is this learning safe to auto-accept? Criteria: it carries usable content "
            "(steps/mission/prompt), describes a defensive-reproducible technique, and does "
            "not contain destructive payloads, credential reuse instructions or out-of-scope actions."
        ),
        state={k: state[k] for k in ("has_steps", "has_mission_or_prompt", "technique_count", "report")},
        scan_id=scan_id, context={"learning_id": int(learning.id), "factory": "h1"},
    )
    quality = decide(
        question_id="h1_quality", kind="score",
        question="Rate the quality of this security report as a learning source: 1=trivial/noise, 3=usable technique, 5=detailed reproduction with clear impact and remediation.",
        state={"report": state["report"]}, scale_max=5,
        scan_id=scan_id, context={"learning_id": int(learning.id), "factory": "h1"},
    )

    is_duplicate = bool(novelty["value"]) and novelty["source"] == "jev"
    quality_value = int(quality["value"]) if quality["source"] == "jev" else 0
    auto_accept = (
        not is_duplicate
        and safe["value"] is True and safe["source"] == "jev"
        and quality["source"] == "jev"
        and quality_value >= _QUALITY_ACCEPT_FLOOR
    )

    return {
        "learning_id": int(learning.id),
        "family": str(fam["value"]) if fam["source"] == "jev" else None,
        "family_source": fam["source"],
        "duplicate": is_duplicate,
        "novel_source": novelty["source"],
        "safe": bool(safe["value"]) if safe["source"] == "jev" else False,
        "safe_source": safe["source"],
        "quality": quality_value,
        "quality_source": quality["source"],
        "auto_accept": auto_accept,
    }


def apply_triage(db: Any, learning: Any, verdict: dict[str, Any]) -> str:
    """Aplica o veredito: rejeita duplicata, auto-aceita os seguros+úteis,
    ranqueia o restante na fila humana (score em raw_extraction.factory)."""
    from datetime import datetime

    raw = dict(getattr(learning, "raw_extraction", None) or {})
    raw["factory"] = {
        **dict(raw.get("factory") or {}),
        **verdict,
        "triaged_at": datetime.now().isoformat(),
    }
    learning.raw_extraction = raw

    if verdict.get("skipped"):
        return "skipped"
    if verdict.get("duplicate"):
        learning.status = "rejected"
        learning.rejected_at = datetime.now()
        learning.review_notes = "skill_factory: duplicata de learning aceito (JEV)"
        return "rejected_duplicate"
    if verdict.get("auto_accept"):
        learning.status = "accepted"
        learning.accepted_at = datetime.now()
        learning.vulnerability_type = str(verdict.get("family") or learning.vulnerability_type or "")[:120] or None
        learning.review_notes = (
            f"skill_factory: auto-accept (safe p/jev, quality {verdict.get('quality')}/5, "
            f"family {verdict.get('family')})"
        )
        return "auto_accepted"
    # Fila humana ranqueada: score visível para triagem manual.
    learning.review_notes = (
        f"skill_factory: quality {verdict.get('quality')}/5 "
        f"(src={verdict.get('quality_source')}), family {verdict.get('family')} — aguardando revisão humana"
    )
    return "queued_ranked"


def calibrate_against_corpus(db: Any, sample_size: int = 200) -> dict[str, Any]:
    """Calibração shadow: JEV classifica learnings ACEITOS e compara com os
    rótulos reais (vulnerability_type). Mede concordância por question_id."""
    from app.models.models import VulnerabilityLearning

    rows = (
        db.query(VulnerabilityLearning)
        .filter(
            VulnerabilityLearning.status == "accepted",
            VulnerabilityLearning.vulnerability_type.isnot(None),
            VulnerabilityLearning.summary.isnot(None),
        )
        .order_by(VulnerabilityLearning.accepted_at.desc().nullslast())
        .limit(int(sample_size))
        .all()
    )
    fam_hits = fam_total = 0
    qual_sum = qual_n = 0

    def _norm_truth(raw: str) -> str:
        t = str(raw or "").strip().lower()
        for fam in FAMILY_OPTIONS:
            if fam != "outros" and (fam in t or t in fam):
                return fam
        aliases = {
            "sql injection": "sqli", "cross-site scripting": "xss", "xss": "xss",
            "idor": "idor", "access control": "broken_access_control", "rce": "rce",
            "ssrf": "ssrf", "csrf": "csrf", "cors": "cors", "redirect": "open_redirect",
            "traversal": "path_traversal", "lfi": "lfri", "rfi": "lfri",
            "template injection": "ssti", "deserial": "deserialization",
            "upload": "file_upload", "race": "race_condition", "secret": "secrets",
            "header": "security_headers", "takeover": "subdomain_takeover",
            "jwt": "jwt_oauth", "oauth": "jwt_oauth", "auth": "auth_bypass",
            "information disclosure": "info_exposure", "info exposure": "info_exposure",
            "logic": "business_logic", "bfla": "bola_bfla", "bola": "bola_bfla",
            "nosql": "nosql_injection", "graphql": "graphql_api", "xxe": "xxe",
        }
        for key, fam in aliases.items():
            if key in t:
                return fam
        return "outros"

    for row in rows:
        try:
            verdict = triage_learning(db, row)
        except Exception as exc:  # noqa: BLE001
            logger.debug("calibration learning=%s failed: %s", row.id, exc)
            continue
        truth = _norm_truth(str(row.vulnerability_type or ""))
        if verdict.get("family") and truth:
            fam_total += 1
            if verdict["family"] == truth:
                fam_hits += 1
        if verdict.get("quality"):
            qual_sum += int(verdict["quality"]); qual_n += 1
    return {
        "sample": fam_total,
        "family_accuracy": round(fam_hits / fam_total, 3) if fam_total else 0.0,
        "quality_avg": round(qual_sum / qual_n, 2) if qual_n else 0.0,
        "family_hits": fam_hits,
    }
