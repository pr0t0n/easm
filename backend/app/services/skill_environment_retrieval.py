"""Recuperação semântica de skills por ambiente (Estágio 2 do fluxo).

Wrapper fino sobre o que já existe: skills indexadas em rag_knowledge_store
(skill_rag_indexer + pgvector) consultadas pelas características do alvo
(tech stack, fase, superfície). O resultado alimenta o JEV no Estágio 3 e a
seleção determinística (fallback quando o índice está indisponível).
"""
from __future__ import annotations

from typing import Any


def retrieve_skills_for_environment(
    *,
    tech_stack: list[str] | None = None,
    phase_id: str | None = None,
    surface: str | None = None,
    findings: list[dict[str, Any]] | None = None,
    top_k: int = 8,
    db: Any = None,
) -> list[dict[str, Any]]:
    """Retorna skills ranqueadas semanticamente para o ambiente fingerprintado.

    Cada entrada: {skill_id, score, category, phase_ids, name}. Lista vazia =
    índice indisponível → caller cai na seleção heurística atual.
    """
    tech = [str(t).strip() for t in (tech_stack or []) if str(t).strip()][:10]
    finding_terms = []
    for f in list(findings or [])[:6]:
        title = str((f or {}).get("title") or "").strip()
        if title:
            finding_terms.append(title[:60])
    query_text = (
        f"security testing skills for {' '.join(tech) or 'web application'} "
        f"phase {phase_id or ''} surface {surface or 'web'} "
        f"{' '.join(finding_terms)}"
    ).strip()
    if len(query_text) < 12:
        return []

    try:
        from app.services.rag_repository import query as rag_query

        rows = rag_query(query_text, top_k=max(1, min(int(top_k) * 2, 20)), db=db)
    except Exception:  # noqa: BLE001 — índice indisponível = fallback do caller
        return []

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        meta = dict(row.get("metadata") or {})
        skill_id = str(meta.get("skill_id") or "").strip()
        if not skill_id or skill_id in seen:
            continue
        seen.add(skill_id)
        raw_phases = meta.get("phase_ids") or []
        if isinstance(raw_phases, str):
            phase_ids = [p for p in raw_phases.replace(",", " ").split() if p.strip()]
        else:
            phase_ids = [str(p) for p in list(raw_phases)]
        score = float(row.get("score") or 0.0)
        # Boost determinístico por fase alinhada (o JEV recebe o ranking já
        # puxado para a fase corrente; sem isso o vetor de fase errada domina).
        if phase_id and str(phase_id) in phase_ids:
            score = round(score + 0.15, 4)
        out.append({
            "skill_id": skill_id,
            "name": str(meta.get("name") or skill_id),
            "category": str(meta.get("category") or ""),
            "phase_ids": phase_ids,
            "score": min(1.0, score),
        })
    out.sort(key=lambda item: -item["score"])
    return out[: max(1, min(int(top_k), 12))]
