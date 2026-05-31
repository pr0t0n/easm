"""Índice semântico dos aprendizados HackerOne (Frente A — inteligência viva).

Em vez de escolher classes de vulnerabilidade por CONTAGEM GLOBAL (cego ao
alvo), embedamos o contexto do alvo (tech-stack + endpoints/parâmetros
descobertos) e recuperamos os aprendizados mais SIMILARES — dirigindo o
pentest para o que realmente importa naquele alvo, com proveniência do report.
"""

from __future__ import annotations

import json
import logging

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.embedding_service import (
    EMBED_MODEL,
    embed_text,
    embed_texts,
    vector_literal,
)

logger = logging.getLogger("learning_semantic")


# vulnerability_type (texto livre dos reports) → família canônica do seeder.
# Substring case-insensitive; primeira correspondência vence.
_VTYPE_TO_FAMILY: list[tuple[str, str]] = [
    ("cross-site scripting", "xss"),
    ("xss", "xss"),
    ("sql injection", "sqli"),
    ("sqli", "sqli"),
    ("server-side request forgery", "ssrf"),
    ("ssrf", "ssrf"),
    ("insecure direct object", "idor"),
    ("idor", "idor"),
    ("improper access control", "broken_access_control"),
    ("privilege escalation", "broken_access_control"),
    ("authorization", "broken_access_control"),
    ("improper authentication", "auth_bypass"),
    ("authentication", "auth_bypass"),
    ("path traversal", "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("local file inclusion", "lfri"),
    ("file inclusion", "lfri"),
    ("cross-site request forgery", "csrf"),
    ("csrf", "csrf"),
    ("open redirect", "open_redirect"),
    ("xml external entit", "xxe"),
    ("xxe", "xxe"),
    ("remote code execution", "rce"),
    ("command injection", "rce"),
    ("code execution", "rce"),
    ("deserialization", "deserialization"),
    ("cors", "cors"),
    ("file upload", "file_upload"),
    ("crlf", "header_injection"),
    ("header injection", "header_injection"),
    ("response splitting", "header_injection"),
    ("subdomain takeover", "subdomain_takeover"),
    ("graphql", "graphql_api"),
    ("jwt", "jwt_oauth"),
    ("oauth", "jwt_oauth"),
    ("business logic", "business_logic"),
    ("information disclosure", "info_exposure"),
    ("information exposure", "info_exposure"),
    ("sensitive data", "info_exposure"),
    ("security headers", "security_headers"),
    ("clickjacking", "security_headers"),
]


def family_for_vuln_type(vuln_type: str | None, title: str | None = None) -> str | None:
    """Classifica o vulnerability_type de um learning em família canônica."""
    hay = f"{vuln_type or ''} {title or ''}".lower()
    for needle, fam in _VTYPE_TO_FAMILY:
        if needle in hay:
            return fam
    return None


def _learning_doc(vtype: str, title: str, summary: str, steps: str) -> str:
    """Texto canônico de um learning para embedar."""
    parts = [p for p in (vtype, title, summary, steps) if p]
    return " \n ".join(parts)[:6000]


def backfill_learning_embeddings(db: Session, limit: int | None = None, batch: int = 64) -> dict:
    """Gera embeddings para learnings que ainda não têm. Idempotente.

    Retorna {embedded, skipped, total_missing, available}.
    """
    if not embed_text("ping"):
        return {"embedded": 0, "skipped": 0, "total_missing": 0, "available": False}

    where = "embedding IS NULL"
    count_row = db.execute(text(f"SELECT count(*) FROM vulnerability_learnings WHERE {where}")).first()
    total_missing = int(count_row[0]) if count_row else 0
    if total_missing == 0:
        return {"embedded": 0, "skipped": 0, "total_missing": 0, "available": True}

    sql_sel = (
        "SELECT id, COALESCE(vulnerability_type,''), COALESCE(title,''), "
        "COALESCE(summary,''), COALESCE(steps_to_reproduce,'') "
        f"FROM vulnerability_learnings WHERE {where} ORDER BY id LIMIT :lim"
    )
    embedded = 0
    skipped = 0
    remaining = limit if limit else total_missing
    while remaining > 0:
        take = min(batch, remaining)
        rows = db.execute(text(sql_sel), {"lim": take}).fetchall()
        if not rows:
            break
        docs = [_learning_doc(r[1], r[2], r[3], r[4]) for r in rows]
        vecs = embed_texts(docs)
        for r, vec in zip(rows, vecs):
            if vec is None:
                skipped += 1
                continue
            db.execute(
                text(
                    "UPDATE vulnerability_learnings SET embedding = CAST(:v AS vector), "
                    "embedding_model = :m WHERE id = :id"
                ),
                {"v": vector_literal(vec), "m": EMBED_MODEL, "id": int(r[0])},
            )
            embedded += 1
        db.commit()
        remaining -= len(rows)
        if len(rows) < take:
            break
    logger.info("backfill_learning_embeddings: embedded=%d skipped=%d", embedded, skipped)
    return {"embedded": embedded, "skipped": skipped, "total_missing": total_missing, "available": True}


def semantic_search_learnings(
    db: Session, query_text: str, top_k: int = 20
) -> list[dict]:
    """Recupera os learnings mais similares ao contexto do alvo.

    Retorna lista de dicts: id, vulnerability_type, family, title, similarity,
    source_report_id, recommended_tools, learned_tool.
    """
    qvec = embed_text(query_text)
    if qvec is None:
        return []
    sql = text(
        """
        SELECT id, COALESCE(vulnerability_type,''), COALESCE(title,''),
               COALESCE(recommended_tools,'[]'::jsonb), COALESCE(learned_techniques,'[]'::jsonb),
               (embedding <=> CAST(:qvec AS vector)) AS distance
        FROM vulnerability_learnings
        WHERE embedding IS NOT NULL
        ORDER BY embedding <=> CAST(:qvec AS vector)
        LIMIT :k
        """
    )
    rows = db.execute(sql, {"qvec": vector_literal(qvec), "k": int(top_k)}).fetchall()
    out: list[dict] = []
    for r in rows:
        lid, vtype, title, rec_tools, techniques, distance = r
        if isinstance(rec_tools, str):
            try:
                rec_tools = json.loads(rec_tools)
            except Exception:
                rec_tools = []
        if isinstance(techniques, str):
            try:
                techniques = json.loads(techniques)
            except Exception:
                techniques = []
        learned_tool = None
        if isinstance(techniques, list) and techniques and isinstance(techniques[0], dict):
            learned_tool = techniques[0].get("tool")
        out.append({
            "id": int(lid),
            "vulnerability_type": vtype,
            "family": family_for_vuln_type(vtype, title),
            "title": title,
            "similarity": round(1.0 - float(distance), 4),
            "recommended_tools": rec_tools if isinstance(rec_tools, list) else [],
            "learned_tool": learned_tool,
            "source_report_id": (techniques[0].get("source_report_id")
                                 if isinstance(techniques, list) and techniques
                                 and isinstance(techniques[0], dict) else None),
        })
    return out


def build_target_query(target: str, tech_stack: list[str], endpoints: list[str] | None = None,
                       params: list[str] | None = None) -> str:
    """Monta o texto de consulta a partir do contexto descoberto do alvo."""
    parts = [f"Target {target}"]
    if tech_stack:
        parts.append("Tech stack: " + ", ".join(tech_stack[:12]))
    if endpoints:
        parts.append("Endpoints: " + ", ".join(endpoints[:20]))
    if params:
        parts.append("Parameters: " + ", ".join(params[:30]))
    return " . ".join(parts)
