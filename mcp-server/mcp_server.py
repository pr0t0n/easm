#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

STORE_PATH = Path(os.getenv("MCP_STORE_PATH", "/app/chroma_db/knowledge_store.json"))
KALI_RUNNER_URL = os.getenv("KALI_RUNNER_URL", "http://kali_runner:8088").rstrip("/")
MCP_PORT = int(os.getenv("MCP_PORT", "3000"))
TERMINAL_STATES = {"done", "failed", "timeout", "skipped"}

kali_client: httpx.AsyncClient | None = None
kali_profiles: dict[str, dict[str, Any]] = {}
tool_aliases: dict[str, str] = {}
knowledge_store: dict[str, dict[str, Any]] = {}


class Document(BaseModel):
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    source: str = "unknown"
    document_id: str | None = None


class QueryRequest(BaseModel):
    query: str
    top_k: int = 5
    filters: dict[str, Any] | None = None
    skill: str | None = None


def _ensure_store_dir() -> None:
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)


def _load_store() -> dict[str, dict[str, Any]]:
    _ensure_store_dir()
    if not STORE_PATH.exists():
        return {}
    try:
        data = json.loads(STORE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load MCP store: %s", exc)
        return {}


def _persist_store() -> None:
    _ensure_store_dir()
    STORE_PATH.write_text(json.dumps(knowledge_store, ensure_ascii=False, indent=2), encoding="utf-8")


def _tokenize(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-zA-Z0-9_\\-]{3,}", str(value or "").lower())
        if token
    }


def _chunk_text(content: str, chunk_size: int = 900) -> list[str]:
    normalized = str(content or "").strip()
    if not normalized:
        return []
    parts = [part.strip() for part in re.split(r"\n\s*\n", normalized) if part.strip()]
    if not parts:
        parts = [normalized]
    chunks: list[str] = []
    current = ""
    for part in parts:
        if len(current) + len(part) + 2 <= chunk_size:
            current = f"{current}\n\n{part}".strip()
            continue
        if current:
            chunks.append(current)
        if len(part) <= chunk_size:
            current = part
            continue
        for idx in range(0, len(part), chunk_size):
            chunks.append(part[idx : idx + chunk_size])
        current = ""
    if current:
        chunks.append(current)
    return chunks


def _matches_filters(metadata: dict[str, Any], filters: dict[str, Any] | None, skill: str | None) -> bool:
    combined = dict(filters or {})
    if skill:
        combined["skill"] = skill
    for key, expected in combined.items():
        if expected in (None, "", []):
            continue
        current = metadata.get(key)
        if isinstance(current, list):
            if str(expected) not in {str(item) for item in current}:
                return False
            continue
        if str(current) != str(expected):
            return False
    return True


def _score_document(query_tokens: set[str], record: dict[str, Any]) -> float:
    doc_tokens = set(record.get("tokens") or [])
    if not query_tokens or not doc_tokens:
        return 0.0
    overlap = query_tokens.intersection(doc_tokens)
    if not overlap:
        return 0.0
    coverage = len(overlap) / max(1, len(query_tokens))
    precision = len(overlap) / max(1, len(doc_tokens))
    return round((coverage * 0.7) + (precision * 0.3), 4)


async def _refresh_kali_catalog() -> None:
    global kali_profiles, tool_aliases
    if kali_client is None:
        return
    try:
        response = await kali_client.get("/profiles")
        response.raise_for_status()
        profiles = dict((response.json() or {}).get("profiles") or {})
        kali_profiles = profiles
        aliases: dict[str, str] = {}
        for profile_name, spec in profiles.items():
            aliases[profile_name] = profile_name
            tool_name = str(spec.get("tool") or "").strip()
            if tool_name:
                aliases[tool_name] = profile_name
            command = list(spec.get("command") or [])
            if command:
                aliases[str(command[0])] = profile_name
        tool_aliases = aliases
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load Kali profiles: %s", exc)
        kali_profiles = {}
        tool_aliases = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global kali_client, knowledge_store
    knowledge_store = _load_store()
    kali_client = httpx.AsyncClient(base_url=KALI_RUNNER_URL, timeout=30.0)
    await _refresh_kali_catalog()
    yield
    if kali_client is not None:
        await kali_client.aclose()


app = FastAPI(
    title="EASM MCP Server",
    description="Lexical MCP memory + Kali execution bridge",
    version="3.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, Any]:
    kali_healthy = False
    if kali_client is not None:
        try:
            response = await kali_client.get("/healthz")
            kali_healthy = response.status_code == 200
        except Exception:  # noqa: BLE001
            kali_healthy = False
    return {
        "status": "healthy",
        "rag_enabled": True,
        "kali_connected": kali_healthy,
        "kali_profiles_loaded": len(kali_profiles),
        "knowledge_documents": len(knowledge_store),
    }


@app.post("/rag/ingest")
async def ingest_document(doc: Document) -> dict[str, Any]:
    doc_id = doc.document_id or f"{doc.source}:{abs(hash(doc.content))}"
    chunks = _chunk_text(doc.content) or [doc.content]
    for index, chunk in enumerate(chunks):
        chunk_id = f"{doc_id}:{index}"
        metadata = dict(doc.metadata)
        metadata["source"] = doc.source
        metadata["chunk_index"] = index
        metadata["chunk_total"] = len(chunks)
        knowledge_store[chunk_id] = {
            "content": chunk,
            "metadata": metadata,
            "tokens": sorted(_tokenize(chunk + " " + json.dumps(metadata, ensure_ascii=False))),
        }
    _persist_store()
    return {"status": "success", "chunks_ingested": len(chunks), "ids": [f"{doc_id}:{i}" for i in range(len(chunks))]}


@app.post("/rag/query")
async def query_knowledge(request: QueryRequest) -> dict[str, Any]:
    query_tokens = _tokenize(request.query)
    scored: list[tuple[float, str, dict[str, Any]]] = []
    for record_id, record in knowledge_store.items():
        metadata = dict(record.get("metadata") or {})
        if not _matches_filters(metadata, request.filters, request.skill):
            continue
        score = _score_document(query_tokens, record)
        if score <= 0:
            continue
        scored.append((score, record_id, record))
    scored.sort(key=lambda item: item[0], reverse=True)
    results = [
        {
            "content": record.get("content") or "",
            "metadata": record.get("metadata") or {},
            "score": score,
            "source": (record.get("metadata") or {}).get("source", "unknown"),
            "skill": (record.get("metadata") or {}).get("skill"),
            "document_id": record_id,
        }
        for score, record_id, record in scored[: max(1, min(request.top_k, 20))]
    ]
    return {"results": results, "total_found": len(results)}


@app.get("/mcp/tools")
async def list_mcp_tools() -> dict[str, Any]:
    if not kali_profiles and kali_client is not None:
        await _refresh_kali_catalog()
    return {
        "tools": [
            {
                "name": profile_name,
                "description": spec.get("description") or f"Kali profile {profile_name}",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "scan_id": {"type": "string"},
                        "timeout": {"type": "integer"},
                    },
                    "required": ["target"],
                },
                "metadata": {
                    "tool": spec.get("tool") or profile_name,
                    "category": spec.get("category"),
                    "phase": spec.get("phase"),
                    "execution_path": "mcp_to_kali",
                },
            }
            for profile_name, spec in sorted(kali_profiles.items())
        ]
    }


async def _run_kali_profile(profile_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
    if kali_client is None:
        raise HTTPException(status_code=503, detail="Kali runner not available")

    # Ensure scan_id is int or None
    scan_id = parameters.get("scan_id")
    if scan_id is not None:
        try:
            scan_id = int(str(scan_id))
        except (ValueError, TypeError):
            scan_id = None

    response = await kali_client.post(
        "/jobs",
        json={
            "profile": profile_name,
            "target": parameters["target"],
            "scan_id": scan_id,
            "tool": (kali_profiles.get(profile_name) or {}).get("tool") or profile_name,
        },
    )
    response.raise_for_status()
    job_id = response.json()["job_id"]
    timeout = int(parameters.get("timeout") or (kali_profiles.get(profile_name) or {}).get("timeout") or 300)
    start = asyncio.get_running_loop().time()
    while True:
        if asyncio.get_running_loop().time() - start > timeout:
            raise HTTPException(status_code=504, detail=f"MCP timed out waiting for job {job_id}")
        status_response = await kali_client.get(f"/jobs/{job_id}")
        status_response.raise_for_status()
        payload = status_response.json()
        if payload.get("status") in TERMINAL_STATES:
            break
        await asyncio.sleep(2)
    result_response = await kali_client.get(f"/jobs/{job_id}/result")
    result_response.raise_for_status()
    result = dict(result_response.json())
    result.setdefault("dispatch_task_id", job_id)
    result.setdefault("execution_path", "mcp_to_kali")
    return result


@app.post("/mcp/tools/{tool_name}/call")
async def call_mcp_tool(tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
    if tool_name == "security_knowledge_search":
        payload = await query_knowledge(
            QueryRequest(
                query=str(parameters.get("query") or ""),
                top_k=int(parameters.get("limit") or 5),
                filters={"category": parameters.get("category")} if parameters.get("category") else None,
            )
        )
        return {"result": payload.get("results") or [], "total": payload.get("total_found", 0)}
    if not parameters.get("target"):
        raise HTTPException(status_code=400, detail="target is required")
    profile_name = tool_aliases.get(tool_name, tool_name)
    if profile_name not in kali_profiles:
        await _refresh_kali_catalog()
        profile_name = tool_aliases.get(tool_name, tool_name)
    if profile_name not in kali_profiles:
        raise HTTPException(status_code=404, detail=f"Tool or profile {tool_name} not found")
    return await _run_kali_profile(profile_name, parameters)


@app.get("/mcp/resources")
async def list_resources() -> dict[str, Any]:
    return {
        "resources": [
            {
                "uri": "easm://knowledge/worker-memory",
                "name": "Worker Skill Memory",
                "description": "Accepted learnings, tests and ingested worker knowledge",
                "mime_type": "application/json",
            },
            {
                "uri": "easm://execution/kali-profiles",
                "name": "Kali Profiles",
                "description": "Profiles exposed by the Kali runner through MCP",
                "mime_type": "application/json",
            },
        ]
    }


@app.get("/mcp/resources/{resource_uri:path}")
async def read_resource(resource_uri: str) -> dict[str, Any]:
    if resource_uri == "easm://execution/kali-profiles":
        return {"profiles": kali_profiles, "aliases": tool_aliases}
    if resource_uri == "easm://knowledge/worker-memory":
        return {"document_count": len(knowledge_store), "ids": list(knowledge_store.keys())[:100]}
    raise HTTPException(status_code=404, detail=f"Resource {resource_uri} not found")


if __name__ == "__main__":
    uvicorn.run("mcp_server:app", host="0.0.0.0", port=MCP_PORT, reload=False, log_level="info")
