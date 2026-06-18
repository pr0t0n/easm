"""Skill RAG indexer — indexes skills/*.md into pgvector (rag_knowledge_store).

Substitui a escrita em knowledge_store.json por inserção direta no PostgreSQL
via rag_repository. Cada skill vira um documento RAG com embedding semântico
(bge-small 384-dim) + tokens lexicais para busca híbrida.
"""
from __future__ import annotations

import logging
from typing import Any

from app.services.skill_runtime import load_all_md_skills

logger = logging.getLogger(__name__)


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
