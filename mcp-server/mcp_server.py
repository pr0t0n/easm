#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

import chromadb
import httpx
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_community.vectorstores import Chroma
from pydantic import BaseModel, Field


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

CHROMA_PATH = os.getenv("MCP_CHROMA_PATH", "./chroma_db")
KALI_RUNNER_URL = os.getenv("KALI_RUNNER_URL", "http://kali_runner:8088").rstrip("/")
MCP_PORT = int(os.getenv("MCP_PORT", "3000"))
TERMINAL_STATES = {"done", "failed", "timeout", "skipped"}

vector_store: Chroma | None = None
chroma_client: chromadb.PersistentClient | None = None
kali_client: httpx.AsyncClient | None = None
kali_profiles: dict[str, dict[str, Any]] = {}
tool_aliases: dict[str, str] = {}


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


def _result_score(distance: Any) -> float:
    try:
        numeric = float(distance)
    except (TypeError, ValueError):
        return 0.0
    return round(1.0 / (1.0 + max(0.0, numeric)), 4)


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
        logger.info("Loaded %s Kali profiles into MCP", len(kali_profiles))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load Kali profiles: %s", exc)
        kali_profiles = {}
        tool_aliases = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global vector_store, chroma_client, kali_client
    try:
        embeddings = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
        chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
        chroma_client.get_or_create_collection(
            name="easm_knowledge_base",
            metadata={"description": "EASM worker skill memory and learnings"},
        )
        vector_store = Chroma(
            client=chroma_client,
            collection_name="easm_knowledge_base",
            embedding_function=embeddings,
        )
        logger.info("MCP vector store ready at %s", CHROMA_PATH)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to initialize vector store: %s", exc)
        vector_store = None

    kali_client = httpx.AsyncClient(base_url=KALI_RUNNER_URL, timeout=30.0)
    await _refresh_kali_catalog()
    yield
    if kali_client is not None:
        await kali_client.aclose()


app = FastAPI(
    title="EASM MCP Server",
    description="RAG + MCP gateway for worker skill memory and Kali execution",
    version="2.0.0",
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
        "rag_enabled": vector_store is not None,
        "kali_connected": kali_healthy,
        "kali_profiles_loaded": len(kali_profiles),
    }


@app.post("/rag/ingest")
async def ingest_document(doc: Document) -> dict[str, Any]:
    if vector_store is None:
        raise HTTPException(status_code=503, detail="RAG system not available")
    splitter = RecursiveCharacterTextSplitter(chunk_size=900, chunk_overlap=120)
    chunks = splitter.split_text(doc.content)
    if not chunks:
        chunks = [doc.content]

    ids = []
    for index, chunk in enumerate(chunks):
        doc_id = doc.document_id or f"{doc.source}:{abs(hash(doc.content))}"
        chunk_id = f"{doc_id}:{index}"
        metadata = dict(doc.metadata)
        metadata["source"] = doc.source
        metadata["chunk_index"] = index
        metadata["chunk_total"] = len(chunks)
        vector_store._collection.upsert(  # type: ignore[attr-defined]
            ids=[chunk_id],
            documents=[chunk],
            metadatas=[metadata],
        )
        ids.append(chunk_id)
    return {"status": "success", "chunks_ingested": len(ids), "ids": ids}


@app.post("/rag/query")
async def query_knowledge(request: QueryRequest) -> dict[str, Any]:
    if vector_store is None:
        raise HTTPException(status_code=503, detail="RAG system not available")
    search_filter = dict(request.filters or {})
    if request.skill:
        search_filter["skill"] = request.skill
    docs = vector_store.similarity_search_with_score(
        query=request.query,
        k=max(1, min(request.top_k, 12)),
        filter=search_filter or None,
    )
    if not docs and request.skill:
        search_filter.pop("skill", None)
        docs = vector_store.similarity_search_with_score(
            query=request.query,
            k=max(1, min(request.top_k, 12)),
            filter=search_filter or None,
        )
    results = [
        {
            "content": doc.page_content,
            "metadata": doc.metadata,
            "score": _result_score(score),
            "source": doc.metadata.get("source", "unknown"),
            "skill": doc.metadata.get("skill"),
        }
        for doc, score in docs
    ]
    return {"results": results, "total_found": len(results)}


@app.get("/mcp/tools")
async def list_mcp_tools() -> dict[str, Any]:
    if not kali_profiles and kali_client is not None:
        await _refresh_kali_catalog()
    tools = []
    for profile_name, spec in sorted(kali_profiles.items()):
        tools.append(
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
        )
    return {"tools": tools}


async def _run_kali_profile(profile_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
    if kali_client is None:
        raise HTTPException(status_code=503, detail="Kali runner not available")
    job_payload = {
        "profile": profile_name,
        "target": parameters["target"],
        "scan_id": parameters.get("scan_id"),
        "tool": (kali_profiles.get(profile_name) or {}).get("tool") or profile_name,
    }
    response = await kali_client.post("/jobs", json=job_payload)
    response.raise_for_status()
    job_id = response.json()["job_id"]
    timeout = int(parameters.get("timeout") or (kali_profiles.get(profile_name) or {}).get("timeout") or 300)
    start = asyncio.get_running_loop().time()
    while True:
        if asyncio.get_running_loop().time() - start > timeout:
            raise HTTPException(status_code=504, detail=f"MCP timed out waiting for job {job_id}")
        status_response = await kali_client.get(f"/jobs/{job_id}")
        status_response.raise_for_status()
        status_payload = status_response.json()
        if status_payload.get("status") in TERMINAL_STATES:
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
        if vector_store is None:
            return {"documents": []}
        collection = vector_store.get()
        return {
            "document_count": len(collection.get("ids") or []),
            "ids": list(collection.get("ids") or [])[:100],
        }
    raise HTTPException(status_code=404, detail=f"Resource {resource_uri} not found")


if __name__ == "__main__":
    uvicorn.run("mcp_server:app", host="0.0.0.0", port=MCP_PORT, reload=False, log_level="info")
