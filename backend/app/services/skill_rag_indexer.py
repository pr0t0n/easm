"""Skill RAG indexer — indexes skills/*.md into pgvector (rag_knowledge_store).

Substitui a escrita em knowledge_store.json por inserção direta no PostgreSQL
via rag_repository. Cada skill vira um documento RAG com embedding semântico
(bge-small 384-dim) + tokens lexicais para busca híbrida.
"""
from __future__ import annotations

import logging
import threading
from typing import Any

from app.services.skill_runtime import load_all_md_skills

logger = logging.getLogger(__name__)
_INDEX_LOCK = threading.Lock()


def _build_rag_document(skill: dict[str, Any]) -> dict[str, Any]:
    skill_id = skill["skill_id"]
    phase_ids = skill.get("phase_ids") or []
    category = skill.get("category") or ""
    required_tools = skill.get("required_tools") or []
    optional_tools = skill.get("optional_tools") or []
    evidence_required = skill.get("evidence_required") or []
    attack_chain_opportunities = skill.get("attack_chain_opportunities") or []

    text_parts = [
        f"skill: {skill_id}",
        f"name: {skill.get('name') or skill_id}",
        f"category: {category}",
        f"phases: {' '.join(phase_ids)}",
        f"tools: {' '.join(required_tools + optional_tools)}",
        f"evidence: {' '.join(evidence_required)}",
        f"chains: {' '.join(attack_chain_opportunities)}",
        f"risk: {skill.get('risk_level') or 'medium'}",
    ]
    source_file = str(skill.get("source_file") or "")
    if source_file:
        try:
            from pathlib import Path

            # Index the actual operational methodology, not only its labels.
            # RAG retrieval can therefore reason about preconditions, evidence,
            # safety rules, negative controls and exit criteria.
            text_parts.append(Path(source_file).read_text(encoding="utf-8"))
        except OSError:
            logger.warning("skill_rag_indexer: cannot read source_file=%s", source_file)

    return {
        "id": f"skill:{skill_id}",
        "type": "skill",
        "skill_id": skill_id,
        "name": skill.get("name") or skill_id,
        "version": skill.get("version") or "1.0.0",
        "category": category,
        "phase_ids": phase_ids,
        "required_tools": required_tools,
        "optional_tools": optional_tools,
        "fallback_tools": skill.get("fallback_tools") or [],
        "evidence_required": evidence_required,
        "exit_criteria": skill.get("exit_criteria") or {},
        "retry_policy": skill.get("retry_policy") or {},
        "attack_chain_opportunities": attack_chain_opportunities,
        "risk_level": skill.get("risk_level") or "medium",
        "noise_level": skill.get("noise_level") or "medium",
        "requires_authorization": skill.get("requires_authorization", True),
        "source_file": skill.get("source_file") or "",
        "text": " ".join(text_parts),
        "tags": phase_ids + [category] + required_tools + attack_chain_opportunities,
    }


def index_skills_to_knowledge_store() -> dict[str, Any]:
    """Load all skills from .md files and upsert them into rag_knowledge_store."""
    skills = load_all_md_skills()
    if not skills:
        logger.warning("skill_rag_indexer: no skills found in skills/ directory")
        return {"indexed": 0, "errors": 0, "total_in_store": 0}

    from app.services import rag_repository

    # Limpar entradas de skill antigas antes de re-indexar
    try:
        removed = rag_repository.delete_source(source_kind="skill")
        if removed:
            logger.debug("skill_rag_indexer: removed %d old skill chunks", removed)
    except Exception as exc:
        logger.warning("skill_rag_indexer: failed to clear old skills: %s", exc)

    indexed = 0
    errors = 0
    for skill_id, skill in skills.items():
        try:
            doc = _build_rag_document(skill)
            content = doc.pop("text", "") or str(doc)
            metadata = {k: v for k, v in doc.items() if not isinstance(v, (dict, list))}
            metadata["skill"] = skill_id
            metadata["skill_id"] = skill_id
            metadata["category"] = doc.get("category") or ""
            metadata["type"] = "skill"
            metadata["source_kind"] = "skill"
            # Serializar listas como string para filtros simples
            for list_field in ("phase_ids", "required_tools", "optional_tools", "tags"):
                val = doc.get(list_field)
                if isinstance(val, list):
                    metadata[list_field] = " ".join(str(v) for v in val)
            ids = rag_repository.ingest_document(
                content=content,
                metadata=metadata,
                source=f"skill:{skill_id}",
                document_id=f"skill:{skill_id}",
            )
            if ids:
                indexed += 1
            else:
                errors += 1
        except Exception as exc:
            logger.error("skill_rag_indexer: failed to index skill %s: %s", skill_id, exc)
            errors += 1

    try:
        total = rag_repository.document_count()
    except Exception:
        total = indexed

    # IVFFlat precisa ser reconstruído após ingest para que os centróides
    # reflitam os dados reais. Sem isso, queries semânticas retornam 0 resultados.
    try:
        rag_repository.rebuild_embedding_index()
    except Exception as exc:
        logger.warning("skill_rag_indexer: rebuild_embedding_index failed: %s", exc)

    logger.info("skill_rag_indexer: indexed %d skills (errors=%d)", indexed, errors)
    return {
        "indexed": indexed,
        "errors": errors,
        "total_in_store": total,
        "skill_ids": list(skills.keys()),
    }


def ensure_skill_index_ready(*, force: bool = False) -> dict[str, Any]:
    """Idempotently make the approved Skill corpus available to RAG.

    Called both at API startup and immediately before methodology planning.
    The second call closes the race where a scan is submitted while the
    background startup index is still warming up.
    """
    with _INDEX_LOCK:
        from app.db.session import SessionLocal
        from sqlalchemy import text

        db = SessionLocal()
        try:
            current = int(db.execute(text(
                "SELECT COUNT(DISTINCT source) FROM rag_knowledge_store WHERE source_kind = 'skill'"
            )).scalar() or 0)
        except Exception:
            current = 0
        finally:
            db.close()
        expected = len(load_all_md_skills())
        if not force and expected > 0 and current >= expected:
            return {"indexed": 0, "errors": 0, "already_ready": True, "skill_documents": current}
        return index_skills_to_knowledge_store()


def warm_skill_rag(*, force: bool = False, backfill: bool = True, backfill_limit: int = 500) -> dict[str, Any]:
    from app.services import rag_repository

    index_result = ensure_skill_index_ready(force=force)
    backfill_result = (
        rag_repository.backfill_missing_embeddings(limit=backfill_limit)
        if backfill
        else {"available": None, "pending": 0, "updated": 0, "errors": 0, "skipped": True}
    )
    health = rag_repository.knowledge_health()
    ok = bool(health.get("ok")) and int(index_result.get("errors") or 0) == 0 and int(backfill_result.get("errors") or 0) == 0
    return {
        "ok": ok,
        "index": index_result,
        "embedding_backfill": backfill_result,
        "health": health,
    }


def start_skill_index_background() -> None:
    """Start non-blocking RAG warm-up during API boot."""
    def _run() -> None:
        try:
            result = warm_skill_rag()
            logger.info("automatic Skill RAG initialization complete: %s", result)
        except Exception:
            logger.exception("automatic Skill RAG initialization failed")

    threading.Thread(target=_run, name="skill-rag-indexer", daemon=True).start()


def query_skills_by_phase(phase_id: str) -> list[dict[str, Any]]:
    from app.services.skill_runtime import resolve_skill_for_phase
    return [_build_rag_document(s) for s in resolve_skill_for_phase(phase_id)]


def query_skills_by_tool(tool_name: str) -> list[dict[str, Any]]:
    skills = load_all_md_skills()
    tool_lower = tool_name.lower()
    return [
        _build_rag_document(skill)
        for skill in skills.values()
        if tool_lower in [t.lower() for t in (skill.get("required_tools") or []) + (skill.get("optional_tools") or [])]
    ]
