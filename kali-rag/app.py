"""kali_rag — sidecar de retrieve-and-operate (Fase 3 do LANGGRAPH_BRAIN_PLAN).

Roda ao lado do kali_runner (mesma rede do compose), NÃO dentro da imagem de
~55 GB. Antes de executar um job, o runner consulta este serviço e injeta o
contexto operacional (skill steps + learnings H1 aceitos relevantes) no job.

Duas vias de consulta:
  - Estrutural/lexical (sem embedding): filtra por fase/ferramenta/família e
    ranqueia por sobreposição de termos do tech_stack — caminho quente <100ms.
  - Vetorial (opcional): se o chamador passar query_embedding, faz busca por
    similaridade no pgvector sobre o corpus aceito.

Fallback: indisponível → o runner segue sem contexto (nunca bloqueia execução).
"""
from __future__ import annotations

import os
import re
import time
from typing import Any

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


def re_escape(value: str) -> str:
    return re.escape(str(value))

RAG_PORT = int(os.getenv("RAG_PORT", "8099"))
DATABASE_URL = os.getenv("DATABASE_URL", "")
RETRIEVE_BUDGET_MS = float(os.getenv("RAG_RETRIEVE_BUDGET_MS", "100"))

app = FastAPI(title="kali_rag", version="0.3.0")


def _db():
    if not DATABASE_URL:
        raise HTTPException(status_code=503, detail="DATABASE_URL not configured")
    return psycopg2.connect(DATABASE_URL, connect_timeout=3)


class RetrieveRequest(BaseModel):
    phase_id: str | None = None
    skill_id: str | None = None
    tool: str | None = None
    tech_stack: list[str] = Field(default_factory=list)
    target: str | None = None
    limit: int = 5
    query_embedding: list[float] | None = None


def _terms(tech_stack: list[str]) -> list[str]:
    return [str(t).strip().lower() for t in (tech_stack or []) if str(t).strip()]


def _lexical_learnings(cur, phase_id: str | None, tool: str | None, terms: list[str], limit: int) -> list[dict[str, Any]]:
    """Learnings aceitos filtrados por fase/ferramenta, ranqueados por termos."""
    # Corpus aceito: o gate de síntese (raw_llm_response) é saída da Fase 3,
    # não pré-condição — as 10k linhas aceitas têm steps/mission reais.
    where = ["status = 'accepted'",
             "(steps_to_reproduce IS NOT NULL OR learned_mission IS NOT NULL OR summary IS NOT NULL)"]
    params: list[Any] = []
    if phase_id:
        where.append("affected_phases ? %s")
        params.append(phase_id)
    if tool:
        params.append(tool)
        where.append("EXISTS (SELECT 1 FROM jsonb_array_elements_text(recommended_tools) t(v) WHERE lower(t.v) = lower(%s))")
    sql = f"""
        SELECT id, title, vulnerability_type, affected_phases, recommended_tools,
               learned_mission, steps_to_reproduce
        FROM vulnerability_learnings
        WHERE {' AND '.join(where)}
        ORDER BY accepted_at DESC NULLS LAST
        LIMIT %s
    """
    params.append(max(1, min(limit * 4, 40)))
    cur.execute(sql, params)
    rows = cur.fetchall()
    scored = []
    for row in rows:
        haystack = " ".join(str(x or "").lower() for x in row[1:7])
        score = sum(1 for t in terms if t and t in haystack)
        scored.append((score, {
            "id": row[0], "title": row[1], "vulnerability_type": row[2],
            "phases": row[3], "tools": row[4],
            "mission": (row[5] or "")[:400],
            "steps": (row[6] or "")[:600],
        }))
    scored.sort(key=lambda item: -item[0])
    return [item for _, item in scored[:limit]]


def _semantic_learnings(cur, query_embedding: list[float], limit: int) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT id, title, vulnerability_type, affected_phases, recommended_tools,
               1 - (embedding <=> CAST(%s AS vector)) AS similarity
        FROM vulnerability_learnings
        WHERE embedding IS NOT NULL
          AND (steps_to_reproduce IS NOT NULL OR learned_mission IS NOT NULL OR summary IS NOT NULL)
        ORDER BY embedding <=> CAST(%s AS vector)
        LIMIT %s
        """,
        (query_embedding, query_embedding, max(1, min(limit, 20))),
    )
    return [
        {
            "id": row[0], "title": row[1], "vulnerability_type": row[2],
            "phases": row[3], "tools": row[4], "similarity": round(float(row[5]), 4),
        }
        for row in cur.fetchall()
    ]


def _skill_docs(cur, phase_id: str | None, tool: str | None, terms: list[str], limit: int) -> list[dict[str, Any]]:
    where = ["1=1"]
    params: list[Any] = []
    if phase_id:
        where.append("metadata->>'phase_ids' ~ %s")
        params.append(f"(^|[ ]){re_escape(phase_id)}([ ]|$)")
    sql = f"""
        SELECT source, chunk_id, content, metadata
        FROM rag_knowledge_store
        WHERE {' AND '.join(where)}
        ORDER BY source_kind = 'skill' DESC
        LIMIT %s
    """
    params.append(max(1, min(limit * 4, 40)))
    cur.execute(sql, params)
    rows = cur.fetchall()
    scored = []
    for source, chunk_id, content, metadata in rows:
        haystack = f"{chunk_id} {content}".lower()
        score = sum(1 for t in terms if t and t in haystack)
        if tool and tool.lower() in haystack:
            score += 2
        scored.append((score, {
            "source": source, "title": chunk_id,
            "excerpt": (content or "")[:500],
            "metadata": metadata or {},
        }))
    scored.sort(key=lambda item: -item[0])
    return [item for _, item in scored[:limit]]


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    started = time.monotonic()
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False
    return {"status": "ok" if db_ok else "degraded", "db": db_ok,
            "budget_ms": RETRIEVE_BUDGET_MS,
            "latency_ms": round((time.monotonic() - started) * 1000, 2)}


@app.post("/retrieve")
def retrieve(request: RetrieveRequest) -> dict[str, Any]:
    started = time.monotonic()
    terms = _terms(request.tech_stack)
    try:
        conn = _db()
        with conn.cursor() as cur:
            learnings = (
                _semantic_learnings(cur, request.query_embedding, request.limit)
                if request.query_embedding
                else _lexical_learnings(cur, request.phase_id, request.tool, terms, request.limit)
            )
            skills = _skill_docs(cur, request.phase_id, request.tool, terms, request.limit)
        conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"retrieve_failed:{type(exc).__name__}") from exc

    latency_ms = round((time.monotonic() - started) * 1000, 2)
    return {
        "retrieve_version": "kali-rag/v1",
        "mode": "semantic" if request.query_embedding else "lexical",
        "latency_ms": latency_ms,
        "within_budget": latency_ms <= RETRIEVE_BUDGET_MS,
        "operational_context": {
            "skill_docs": skills,
            "learnings": learnings,
            "terms": terms,
            "phase_id": request.phase_id,
            "tool": request.tool,
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=RAG_PORT)
