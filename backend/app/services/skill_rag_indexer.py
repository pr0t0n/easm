"""Skill RAG indexer — pushes skills/*.md into the MCP knowledge store.

Converts each skill's frontmatter + body into a structured RAG document
so the MCP server can return skill objects (not just text) when queried
by phase_id, category, or vulnerability class.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from app.services.skill_runtime import load_all_md_skills

logger = logging.getLogger(__name__)

_KNOWLEDGE_STORE_PATH = (
    Path(__file__).parent.parent.parent.parent / "mcp-server" / "knowledge_store.json"
)


def _build_rag_document(skill: dict[str, Any]) -> dict[str, Any]:
    """Convert a loaded skill dict into a RAG document chunk."""
    skill_id = skill["skill_id"]
    phase_ids = skill.get("phase_ids") or []
    category = skill.get("category") or ""
    required_tools = skill.get("required_tools") or []
    optional_tools = skill.get("optional_tools") or []
    evidence_required = skill.get("evidence_required") or []
    attack_chain_opportunities = skill.get("attack_chain_opportunities") or []

    # Build a searchable text blob combining key fields
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
        # Text blob for lexical matching in mcp_server.py
        "text": " ".join(text_parts),
        # Metadata tags for structured filter queries
        "tags": phase_ids + [category] + required_tools + attack_chain_opportunities,
    }


def index_skills_to_knowledge_store() -> dict[str, Any]:
    """Load all skills from .md files and write them to the MCP knowledge store.

    Merges with existing knowledge_store.json content, replacing skill entries
    and preserving non-skill entries.
    Returns a summary dict with counts.
    """
    skills = load_all_md_skills()
    if not skills:
        logger.warning("skill_rag_indexer: no skills found in skills/ directory")
        return {"indexed": 0, "errors": 0, "total_in_store": 0}

    # Load existing knowledge store
    existing: dict[str, Any] = {}
    if _KNOWLEDGE_STORE_PATH.exists():
        try:
            existing = json.loads(_KNOWLEDGE_STORE_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("skill_rag_indexer: failed to read existing knowledge store: %s", exc)
            existing = {}

    # knowledge_store.json is expected to be a dict with a "documents" list
    if not isinstance(existing, dict):
        existing = {}
    documents: list[dict[str, Any]] = list(existing.get("documents") or [])

    # Remove existing skill entries (will be replaced)
    documents = [doc for doc in documents if not str(doc.get("id") or "").startswith("skill:")]

    indexed = 0
    errors = 0
    for skill_id, skill in skills.items():
        try:
            doc = _build_rag_document(skill)
            documents.append(doc)
            indexed += 1
        except Exception as exc:
            logger.error("skill_rag_indexer: failed to index skill %s: %s", skill_id, exc)
            errors += 1

    existing["documents"] = documents

    try:
        _KNOWLEDGE_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _KNOWLEDGE_STORE_PATH.write_text(
            json.dumps(existing, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(
            "skill_rag_indexer: indexed %d skills to %s", indexed, _KNOWLEDGE_STORE_PATH
        )
    except OSError as exc:
        logger.error("skill_rag_indexer: failed to write knowledge store: %s", exc)
        errors += 1

    return {
        "indexed": indexed,
        "errors": errors,
        "total_in_store": len(documents),
        "skill_ids": list(skills.keys()),
    }


def query_skills_by_phase(phase_id: str) -> list[dict[str, Any]]:
    """Return all RAG documents for skills that cover a given phase_id."""
    from app.services.skill_runtime import resolve_skill_for_phase
    return [_build_rag_document(s) for s in resolve_skill_for_phase(phase_id)]


def query_skills_by_tool(tool_name: str) -> list[dict[str, Any]]:
    """Return all skill RAG documents that require or optionally use a given tool."""
    skills = load_all_md_skills()
    tool_lower = tool_name.lower()
    return [
        _build_rag_document(skill)
        for skill in skills.values()
        if tool_lower in [t.lower() for t in (skill.get("required_tools") or []) + (skill.get("optional_tools") or [])]
    ]
