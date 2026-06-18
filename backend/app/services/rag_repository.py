"""RAG Repository — armazenamento e busca de conhecimento via pgvector.

Substitui o knowledge_store.json do mcp_server por uma tabela PostgreSQL com:
- Busca semântica: cosine similarity via pgvector (vector 384-dim bge-small)
- Busca lexical: tokens JSONB (mesma heurística do mcp_server original)
- Busca híbrida: semântica ranqueia candidatos, lexical refina o score final

Interface pública compatível com MCPClient.query_knowledge_sync/ingest_document_sync.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import SessionLocal

logger = logging.getLogger(__name__)

# Mesma regex do mcp_server original para compatibilidade de tokens.
_TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-]{3,}")


def _tokenize(value: str) -> list[str]:
    return list({t for t in _TOKEN_RE.findall(str(value or "").lower()) if t})


def _score_lexical(query_tokens: set[str], doc_tokens: set[str]) -> float:
    if not query_tokens or not doc_tokens:
        return 0.0
    overlap = query_tokens & doc_tokens
    if not overlap:
        return 0.0
    coverage = len(overlap) / max(1, len(query_tokens))
    precision = len(overlap) / max(1, len(doc_tokens))
    return round(coverage * 0.7 + precision * 0.3, 4)


# ── Ingest ────────────────────────────────────────────────────────────────────

def _chunk_text(content: str, chunk_size: int = 900) -> list[str]:
    normalized = str(content or "").strip()
    if not normalized:
        return []
    parts = [p.strip() for p in re.split(r"\n\s*\n", normalized) if p.strip()]
    if not parts:
        parts = [normalized]
    chunks: list[str] = []
    current = ""
    for part in parts:
        if len(current) + len(part) + 2 <= chunk_size:
            current = f"{current}\n\n{part}".strip()
        else:
            if current:
                chunks.append(current)
            if len(part) <= chunk_size:
                current = part
            else:
                for idx in range(0, len(part), chunk_size):
                    chunks.append(part[idx: idx + chunk_size])
                current = ""
    if current:
        chunks.append(current)
    return chunks


def _get_embedding(text: str) -> list[float] | None:
    try:
        from app.services.embedding_service import embed_text
        return embed_text(text)
    except Exception:
        return None


def _embedding_literal(vec: list[float]) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in vec) + "]"


def ingest_document(
    content: str,
    metadata: dict[str, Any] | None = None,
    source: str = "unknown",
    document_id: str | None = None,
    *,
    db: Session | None = None,
) -> list[str]:
    meta = dict(metadata or {})
    meta.setdefault("source", source)
    source_kind = str(meta.get("source_kind") or meta.get("type") or "").strip() or None
    doc_id = document_id or f"{source}:{abs(hash(content))}"
    chunks = _chunk_text(content) or [content]

    own_session = db is None
    if own_session:
        db = SessionLocal()

    ids: list[str] = []
    try:
        for idx, chunk in enumerate(chunks):
            chunk_id = f"{doc_id}:{idx}"
            tokens = _tokenize(chunk + " " + json.dumps(meta, ensure_ascii=False))
            chunk_meta = dict(meta)
            chunk_meta["chunk_index"] = idx
            chunk_meta["chunk_total"] = len(chunks)
            vec = _get_embedding(chunk)
            # Use CAST() instead of ::type to avoid SQLAlchemy parameter parser
            # treating ::jsonb/::vector as extra named params.
            if vec:
                embed_sql = "CAST(:embed AS vector)"
                extra_params = {"embed": _embedding_literal(vec)}
            else:
                embed_sql = "NULL"
                extra_params = {}
            db.execute(
                text(
                    f"""
                    INSERT INTO rag_knowledge_store
                        (chunk_id, source, source_kind, content, metadata, tokens, embedding)
                    VALUES
                        (:chunk_id, :source, :source_kind, :content,
                         CAST(:metadata AS jsonb), CAST(:tokens AS jsonb), {embed_sql})
                    ON CONFLICT (chunk_id) DO UPDATE SET
                        source      = EXCLUDED.source,
                        source_kind = EXCLUDED.source_kind,
                        content     = EXCLUDED.content,
                        metadata    = EXCLUDED.metadata,
                        tokens      = EXCLUDED.tokens,
                        embedding   = EXCLUDED.embedding
                    """
                ),
                {
                    "chunk_id": chunk_id,
                    "source": source,
                    "source_kind": source_kind,
                    "content": chunk,
                    "metadata": json.dumps(chunk_meta, ensure_ascii=False),
                    "tokens": json.dumps(tokens, ensure_ascii=False),
                    **extra_params,
                },
            )
            ids.append(chunk_id)
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("rag_repository.ingest_document failed: %s", exc)
    finally:
        if own_session:
            db.close()
    return ids


def ingest_documents_bulk(
    documents: list[dict[str, Any]],
    *,
    db: Session | None = None,
) -> dict[str, Any]:
    own_session = db is None
    if own_session:
        db = SessionLocal()
    total_chunks = 0
    errors = 0
    try:
        for doc in documents:
            try:
                ids = ingest_document(
                    content=str(doc.get("content") or ""),
                    metadata=dict(doc.get("metadata") or {}),
                    source=str(doc.get("source") or "unknown"),
                    document_id=doc.get("document_id"),
                    db=db,
                )
                total_chunks += len(ids)
            except Exception as exc:
                logger.error("rag_repository.bulk item failed: %s", exc)
                errors += 1
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("rag_repository.ingest_bulk commit failed: %s", exc)
    finally:
        if own_session:
            db.close()
    return {
        "documents_ingested": len(documents) - errors,
        "chunks_ingested": total_chunks,
        "errors": errors,
    }


def delete_source(
    source: str | None = None,
    source_kind: str | None = None,
    *,
    db: Session | None = None,
) -> int:
    if not source and not source_kind:
        return 0
    own_session = db is None
    if own_session:
        db = SessionLocal()
    removed = 0
    try:
        if source and source_kind:
            result = db.execute(
                text("DELETE FROM rag_knowledge_store WHERE source = :s OR source_kind = :sk"),
                {"s": source, "sk": source_kind},
            )
        elif source:
            result = db.execute(
                text("DELETE FROM rag_knowledge_store WHERE source = :s"),
                {"s": source},
            )
        else:
            result = db.execute(
                text("DELETE FROM rag_knowledge_store WHERE source_kind = :sk"),
                {"sk": source_kind},
            )
        removed = result.rowcount
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("rag_repository.delete_source failed: %s", exc)
    finally:
        if own_session:
            db.close()
    return removed


# ── Query ─────────────────────────────────────────────────────────────────────

def _build_filter_clause(
    filters: dict[str, Any] | None,
    skill: str | None,
) -> tuple[str, dict[str, Any]]:
    """Build WHERE clause fragments for metadata filters."""
    parts: list[str] = []
    params: dict[str, Any] = {}
    combined = dict(filters or {})
    if skill:
        combined["skill"] = skill
    for i, (key, val) in enumerate(combined.items()):
        if val in (None, "", []):
            continue
        param_key = f"fk_{i}"
        param_val = f"fv_{i}"
        parts.append(f"metadata->>{param_key!r} = :{param_val}")
        params[param_key[3:]] = key
        params[param_val[3:]] = str(val)
    if not parts:
        return "", {}
    return " AND ".join(parts), params


def query(
    query_text: str,
    top_k: int = 5,
    filters: dict[str, Any] | None = None,
    skill: str | None = None,
    *,
    db: Session | None = None,
) -> list[dict[str, Any]]:
    """Busca híbrida: semântica (pgvector cosine) + lexical (token overlap).

    Se o modelo de embedding não estiver disponível, faz busca puramente lexical
    varrendo a tabela. Com embedding disponível, usa ANN no pgvector para
    pré-filtrar os melhores candidatos e re-ranqueia com lexical.
    """
    query_text = str(query_text or "").strip()
    if not query_text:
        return []

    query_tokens = set(_tokenize(query_text))
    top_k = max(1, min(int(top_k), 20))
    fetch_k = top_k * 4  # over-fetch para re-ranking

    own_session = db is None
    if own_session:
        db = SessionLocal()

    results: list[dict[str, Any]] = []
    try:
        vec = _get_embedding(query_text)
        if vec:
            # Semântica: ANN via pgvector, over-fetch e re-rank via lexical
            embed_lit = _embedding_literal(vec)
            sql = f"""
                SELECT chunk_id, source, content, metadata, tokens,
                       1 - (embedding <=> '{embed_lit}'::vector) AS cosine_score
                FROM rag_knowledge_store
                WHERE embedding IS NOT NULL
                ORDER BY embedding <=> '{embed_lit}'::vector
                LIMIT :fetch_k
            """
            rows = db.execute(text(sql), {"fetch_k": fetch_k}).mappings().all()
            scored: list[tuple[float, dict[str, Any]]] = []
            for row in rows:
                meta = dict(row["metadata"] or {})
                if not _matches_filters(meta, filters, skill):
                    continue
                doc_tokens = set(list(row["tokens"] or []))
                lex_score = _score_lexical(query_tokens, doc_tokens)
                cosine = float(row["cosine_score"] or 0.0)
                final_score = round(cosine * 0.6 + lex_score * 0.4, 4)
                scored.append((final_score, {
                    "content": row["content"] or "",
                    "metadata": meta,
                    "score": final_score,
                    "source": row["source"] or meta.get("source", "unknown"),
                    "skill": meta.get("skill"),
                    "document_id": row["chunk_id"],
                }))
            scored.sort(key=lambda x: x[0], reverse=True)
            results = [r for _, r in scored[:top_k]]
        else:
            # Lexical puro: varredura com scoring em Python
            rows = db.execute(
                text("SELECT chunk_id, source, content, metadata, tokens FROM rag_knowledge_store LIMIT 5000")
            ).mappings().all()
            scored_lex: list[tuple[float, dict[str, Any]]] = []
            for row in rows:
                meta = dict(row["metadata"] or {})
                if not _matches_filters(meta, filters, skill):
                    continue
                doc_tokens = set(list(row["tokens"] or []))
                score = _score_lexical(query_tokens, doc_tokens)
                if score <= 0:
                    continue
                scored_lex.append((score, {
                    "content": row["content"] or "",
                    "metadata": meta,
                    "score": score,
                    "source": row["source"] or meta.get("source", "unknown"),
                    "skill": meta.get("skill"),
                    "document_id": row["chunk_id"],
                }))
            scored_lex.sort(key=lambda x: x[0], reverse=True)
            results = [r for _, r in scored_lex[:top_k]]
    except Exception as exc:
        logger.error("rag_repository.query failed: %s", exc)
    finally:
        if own_session:
            db.close()
    return results


def _matches_filters(
    metadata: dict[str, Any],
    filters: dict[str, Any] | None,
    skill: str | None,
) -> bool:
    combined = dict(filters or {})
    if skill:
        combined["skill"] = skill
    for key, expected in combined.items():
        if expected in (None, "", []):
            continue
        current = metadata.get(key)
        if isinstance(current, list):
            if str(expected) not in {str(i) for i in current}:
                return False
        elif str(current) != str(expected):
            return False
    return True


def document_count(*, db: Session | None = None) -> int:
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        row = db.execute(text("SELECT COUNT(*) FROM rag_knowledge_store")).scalar()
        return int(row or 0)
    except Exception:
        return 0
    finally:
        if own_session:
            db.close()


def rebuild_embedding_index(*, db: Session | None = None) -> None:
    """Recria o IVFFlat com lists = max(1, sqrt(N)).

    IVFFlat precisa de dados para construir centróides. Chame após bulk ingest
    ou quando o dataset crescer significativamente.
    """
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        n = db.execute(text("SELECT COUNT(*) FROM rag_knowledge_store WHERE embedding IS NOT NULL")).scalar() or 0
        lists = max(1, int(n ** 0.5))
        db.execute(text("DROP INDEX IF EXISTS idx_rag_ks_embedding"))
        db.execute(
            text(
                f"CREATE INDEX idx_rag_ks_embedding ON rag_knowledge_store "
                f"USING ivfflat (embedding vector_cosine_ops) WITH (lists = {lists})"
            )
        )
        db.commit()
        logger.info("rag_repository: rebuilt IVFFlat index (n=%d, lists=%d)", n, lists)
    except Exception as exc:
        db.rollback()
        logger.error("rag_repository.rebuild_embedding_index failed: %s", exc)
    finally:
        if own_session:
            db.close()
