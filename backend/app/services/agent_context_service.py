from __future__ import annotations

import json
import logging
from app.core.config import settings
from app.services.mcp_client import mcp_client
from app.services.vulnerability_learning_service import build_runtime_learning_playbook
from app.workers.worker_groups import get_worker_agent_profile


logger = logging.getLogger(__name__)


def _learning_documents(
    *,
    skill: str,
    worker_group: str,
    phase: str,
    candidate_tools: list[str],
    limit: int = 6,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    playbook = build_runtime_learning_playbook(
        candidate_tools=candidate_tools,
        phase=phase or None,
        limit=max(4, limit),
    )
    if not playbook:
        return [], None

    docs: list[dict[str, Any]] = []
    for idx, technique in enumerate(playbook.get("techniques") or [], start=1):
        content = {
            "technique": technique.get("name"),
            "objective": technique.get("objective"),
            "when_to_use": technique.get("when_to_use"),
            "evidence_signals": technique.get("evidence_signals"),
            "safe_validation_steps": technique.get("safe_validation_steps"),
            "recommended_kali_tools": technique.get("recommended_kali_tools"),
            "prompt_instruction": technique.get("prompt_instruction"),
        }
        serialized = json.dumps(content, ensure_ascii=False)
        docs.append(
            {
                "document_id": f"learning-{technique.get('source_learning_id', 'na')}-{idx}",
                "content": serialized,
                "metadata": {
                    "type": "accepted_learning",
                    "skill": skill,
                    "phase": phase,
                    "worker_group": worker_group,
                    "knowledge_scope": "accepted_learning",
                    "recommended_tools": technique.get("recommended_kali_tools") or [],
                },
                "source": "accepted_learning",
            }
        )
        if len(docs) >= limit:
            break
    return docs, playbook


def sync_worker_knowledge_to_mcp(
    *,
    skill: str,
    worker_group: str,
    phase: str,
    candidate_tools: list[str],
) -> dict[str, Any]:
    if not settings.mcp_rag_enabled:
        return {"enabled": False, "ingested": 0, "available": False}

    docs, playbook = _learning_documents(
        skill=skill,
        worker_group=worker_group,
        phase=phase,
        candidate_tools=candidate_tools,
        limit=8,
    )
    if not docs:
        return {"enabled": True, "ingested": 0, "available": mcp_client.health_check_sync(), "playbook": playbook}

    ingested = 0
    available = mcp_client.health_check_sync()
    if available:
        for doc in docs:
            if mcp_client.ingest_document_sync(
                content=doc["content"],
                metadata=doc["metadata"],
                source=doc["source"],
                document_id=doc["document_id"],
            ):
                ingested += 1

    return {
        "enabled": True,
        "available": available,
        "ingested": ingested,
        "documents": len(docs),
        "playbook": playbook,
    }


def build_worker_knowledge_context(
    *,
    worker_group: str,
    skill: str,
    phase: str,
    target: str,
    candidate_tools: list[str],
    mode: str = "unit",
    top_k: int | None = None,
) -> dict[str, Any]:
    profile = get_worker_agent_profile(worker_group, mode=mode)
    sync_status = sync_worker_knowledge_to_mcp(
        skill=skill,
        worker_group=worker_group,
        phase=phase,
        candidate_tools=candidate_tools,
    )
    query = " ".join(
        part for part in [
            worker_group,
            skill,
            phase,
            target,
            " ".join(candidate_tools[:5]),
            "accepted learning tests kali tool execution",
        ]
        if str(part or "").strip()
    )
    results = mcp_client.query_knowledge_sync(
        query=query,
        top_k=top_k or settings.mcp_default_top_k,
        filters={"phase": phase} if phase else None,
        skill=skill or None,
    ) if sync_status.get("available") else []
    if not results and sync_status.get("available"):
        results = mcp_client.query_knowledge_sync(
            query=query,
            top_k=top_k or settings.mcp_default_top_k,
            filters=None,
            skill=skill or None,
        )

    playbook = sync_status.get("playbook")
    recommended_tools = list(dict.fromkeys(
        [*list(candidate_tools or []), *list((playbook or {}).get("recommended_tools") or [])]
    ))[:16]
    knowledge_items = [
        {
            "source": item.get("source") or item.get("metadata", {}).get("source") or "mcp",
            "score": item.get("score"),
            "content": str(item.get("content") or "")[:500],
            "metadata": item.get("metadata") or {},
        }
        for item in results[: max(1, settings.mcp_default_top_k)]
    ]
    prompt_context = {
        "worker_group": worker_group,
        "skill": skill,
        "phase": phase,
        "target": target,
        "execution_path": "mcp_to_kali" if settings.mcp_execute_tools_via_mcp else "direct_kali",
        "retrieval_query": query,
        "retrieval_required": True,
        "recommended_tools": recommended_tools,
        "playbook_title": (playbook or {}).get("title"),
        "knowledge_items": knowledge_items,
        "worker_mission": profile.get("mission"),
        "worker_rules": dict(profile.get("worker_rules") or {}),
        "sub_agent_rules": list(profile.get("sub_agent_rules") or []),
    }
    return {
        "sync_status": sync_status,
        "query": query,
        "knowledge_items": knowledge_items,
        "recommended_tools": recommended_tools,
        "worker_rules": dict(profile.get("worker_rules") or {}),
        "sub_agent_rules": list(profile.get("sub_agent_rules") or []),
        "prompt_context": prompt_context,
        "playbook": playbook,
    }
