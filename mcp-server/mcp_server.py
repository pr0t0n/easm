#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
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

# Per-request timeout overrides for the kali_runner calls (Tier 4-A).
# Status poll: just a JSON status dict — must respond in <5s or the runner is stuck.
# Result fetch: includes full stdout blob — allow up to 60s.
_KALI_POLL_TIMEOUT = httpx.Timeout(connect=5.0, read=5.0, write=5.0, pool=5.0)
_KALI_RESULT_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=5.0, pool=5.0)

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


class MCPExecutionRequest(BaseModel):
    mcp_request_id: str | None = None
    phase_id: str
    skill_id: str
    tool_name: str
    profile: str
    target: str
    # Tier 3: optional batch target list — when provided the kali runner
    # materialises a targets.txt file and the profile uses {target_file}.
    targets: list[str] = Field(default_factory=list)
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected_evidence: list[str] = Field(default_factory=list)


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


def _ingest_document_record(doc: Document, *, persist: bool = True) -> list[str]:
    doc_id = doc.document_id or f"{doc.source}:{abs(hash(doc.content))}"
    chunks = _chunk_text(doc.content) or [doc.content]
    ids: list[str] = []
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
        ids.append(chunk_id)
    if persist:
        _persist_store()
    return ids


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


def _profile_context_hints(profile_name: str, spec: dict[str, Any]) -> dict[str, Any]:
    tool = str(spec.get("tool") or profile_name).strip()
    category = str(spec.get("category") or "").strip().lower()
    phase = str(spec.get("phase") or "").strip()
    description = str(spec.get("description") or "")
    command = [str(item) for item in list(spec.get("command") or spec.get("cmd") or [])]
    text = " ".join([tool, category, phase, description, " ".join(command)]).lower()

    capabilities: list[str] = []
    if any(token in text for token in ["subdomain", "dns", "port", "crawl", "fingerprint", "http", "tls", "waf", "recon"]):
        capabilities.append("asset_discovery")
    if any(token in text for token in ["osint", "shodan", "harvester", "breach", "leak", "secret", "git"]):
        capabilities.append("threat_intel")
    if any(token in text for token in ["vuln", "cve", "xss", "sqli", "sql", "ssrf", "nikto", "nuclei", "scan"]):
        capabilities.append("risk_assessment")
    if not capabilities:
        capabilities.append("risk_assessment" if category in {"vuln", "exploit"} else "asset_discovery")

    target_types: list[str] = []
    if "{url}" in command or " url" in text or "http" in text:
        target_types.append("url")
    if "{host}" in command or "{host_ip}" in command or "domain" in text or "subdomain" in text:
        target_types.append("host_or_domain")
    if "filesystem" in text or "git" in text or category == "code":
        target_types.append("code_or_filesystem")
    if not target_types:
        target_types.append("host_or_domain")

    evidence_outputs: list[str] = []
    if any(token in text for token in ["json", "jsonl"]):
        evidence_outputs.append("structured_json")
    if any(token in text for token in ["cve", "vuln", "finding", "xss", "sqli"]):
        evidence_outputs.append("security_findings")
    if any(token in text for token in ["subdomain", "url", "endpoint", "port", "service"]):
        evidence_outputs.append("surface_inventory")
    if not evidence_outputs:
        evidence_outputs.append("raw_tool_output")

    return {
        "capabilities": list(dict.fromkeys(capabilities)),
        "target_types": list(dict.fromkeys(target_types)),
        "evidence_outputs": list(dict.fromkeys(evidence_outputs)),
        "requires_scheme": list(spec.get("requires_scheme") or []),
        "requires_env": list(spec.get("requires_env") or []),
        "parser": spec.get("parser"),
        "safe_execution": {
            "destructive_actions_allowed": False,
            "data_extraction_allowed": False,
            "operator_approval_required": bool(category in {"exploit"} or tool in {"hydra", "medusa", "crackmapexec"}),
        },
    }


def _mcp_tool_descriptor(profile_name: str, spec: dict[str, Any]) -> dict[str, Any]:
    context = _profile_context_hints(profile_name, spec)
    tool = spec.get("tool") or profile_name
    return {
        "name": profile_name,
        "description": spec.get("description") or f"Kali profile {profile_name}",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "scan_id": {"type": "string"},
                "timeout": {"type": "integer"},
                "extra_args": {"type": "array", "items": {"type": "string"}},
                "skill_context": {"type": "object"},
            },
            "required": ["target"],
        },
        "metadata": {
            "tool": tool,
            "category": spec.get("category"),
            "phase": spec.get("phase"),
            "timeout": spec.get("timeout"),
            "execution_path": "mcp_to_kali",
            "context": context,
            "capabilities": context["capabilities"],
            "target_types": context["target_types"],
            "evidence_outputs": context["evidence_outputs"],
        },
    }


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

        # ── Contract-name → closest existing profile (vuln tags sem profile próprio) ──
        # Os contratos de fase referenciam nomes que não têm profile 1:1 no Kali.
        # Mapear para a capability existente mais próxima evita skip de
        # tool_or_profile_not_found e mantém a cobertura de detecção.
        _CONTRACT_ALIASES = {
            "nuclei-auth-bypass": "nuclei_auth",
            "nuclei-auth": "nuclei_auth",
            "nuclei-js-secrets": "nuclei_exposure",
            "nuclei-js-analysis": "nuclei_exposure",
            "nuclei-default-credentials": "nuclei_auth",
            "nuclei-oauth": "nuclei_auth",
            "nuclei-jwt": "nuclei_jwt",
            "nuclei-misconfiguration": "nuclei_exposure",
            "nuclei-file-upload": "nuclei_exposure",
            "nuclei-swagger": "nuclei_exposure",
            "nuclei-redirect": "nuclei_open_redirect",
        }
        for _cname, _target in _CONTRACT_ALIASES.items():
            if _cname not in aliases and _target in profiles:
                aliases[_cname] = _target
        tool_aliases = aliases
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load Kali profiles: %s", exc)
        kali_profiles = {}
        tool_aliases = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global kali_client, knowledge_store
    knowledge_store = _load_store()
    # Tier 2-A / 4-A: separate timeouts per call type.
    # The client default covers POST /jobs (submit).  Status polls and result
    # fetches override read= per-request so a hung kali_runner doesn't block
    # the MCP event loop for 30s per poll iteration.
    kali_client = httpx.AsyncClient(
        base_url=KALI_RUNNER_URL,
        timeout=httpx.Timeout(connect=5.0, read=30.0, write=15.0, pool=5.0),
        limits=httpx.Limits(
            max_connections=50,
            max_keepalive_connections=20,
            keepalive_expiry=30.0,
        ),
    )
    # Per-request timeout overrides used in _run_kali_profile:
    #   _POLL_TIMEOUT   — GET /jobs/{id}       — just a status JSON, must be fast
    #   _RESULT_TIMEOUT — GET /jobs/{id}/result — includes stdout, allow more time
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
    ids = _ingest_document_record(doc)
    return {"status": "success", "chunks_ingested": len(ids), "ids": ids}


@app.post("/rag/ingest-bulk")
async def ingest_documents_bulk(payload: dict[str, Any]) -> dict[str, Any]:
    raw_documents = payload.get("documents") or []
    if not isinstance(raw_documents, list) or not raw_documents:
        raise HTTPException(status_code=400, detail="Informe documents como lista.")
    ids: list[str] = []
    for raw in raw_documents:
        ids.extend(_ingest_document_record(Document(**dict(raw or {})), persist=False))
    _persist_store()
    return {"status": "success", "documents_ingested": len(raw_documents), "chunks_ingested": len(ids)}


@app.post("/rag/delete-source")
async def delete_source(payload: dict[str, Any]) -> dict[str, Any]:
    source = str(payload.get("source") or "").strip()
    source_kind = str(payload.get("source_kind") or source).strip()
    if not source and not source_kind:
        raise HTTPException(status_code=400, detail="Informe source ou source_kind.")
    removed = 0
    for record_id, record in list(knowledge_store.items()):
        metadata = dict(record.get("metadata") or {})
        if (
            (source and str(metadata.get("source") or "") == source)
            or (source_kind and str(metadata.get("source_kind") or "") == source_kind)
        ):
            knowledge_store.pop(record_id, None)
            removed += 1
    if removed:
        _persist_store()
    return {"status": "success", "removed": removed}


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
            _mcp_tool_descriptor(profile_name, spec)
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

    timeout = int(parameters.get("timeout") or (kali_profiles.get(profile_name) or {}).get("timeout") or 300)
    batch_targets = [str(t).strip() for t in (parameters.get("targets") or []) if str(t).strip()]
    response = await kali_client.post(
        "/jobs",
        json={
            "profile": profile_name,
            "target": parameters["target"],
            "targets": batch_targets,   # Tier 3: populated for batch profiles
            "scan_id": scan_id,
            "tool": (kali_profiles.get(profile_name) or {}).get("tool") or profile_name,
            "timeout": timeout,
            "auth_headers": parameters.get("auth_headers") or {},
            "extra_args": [
                str(arg)
                for arg in list(parameters.get("extra_args") or [])
                if str(arg).strip()
            ],
        },
    )
    response.raise_for_status()
    job_id = response.json()["job_id"]
    start = asyncio.get_running_loop().time()
    while True:
        elapsed = asyncio.get_running_loop().time() - start
        if elapsed > timeout:
            raise HTTPException(status_code=504, detail=f"MCP timed out waiting for job {job_id}")
        # Tier 4-A: short 5s read timeout for status polls — the runner just
        # reads an in-memory dict; anything slower means it is stuck.
        status_response = await kali_client.get(f"/jobs/{job_id}", timeout=_KALI_POLL_TIMEOUT)
        status_response.raise_for_status()
        payload = status_response.json()
        if payload.get("status") in TERMINAL_STATES:
            break
        # Adaptive backoff: 2s for the first 30s, then grows 1s per 30s elapsed,
        # capped at 15s.  Reduces polls from 450→~90 for a 900s nuclei scan.
        _sleep = min(2 + int(elapsed // 30), 15)
        await asyncio.sleep(_sleep)
    # Tier 4-A: 60s read timeout for result fetch — stdout can be up to 500KB.
    # Full stdout is needed here: offensive_operator_runner parses raw stdout for
    # subdomain/port discovery.  Tier 2-C (_trim_mcp_stdout) handles truncation
    # before the data reaches Postgres state_data.
    result_response = await kali_client.get(f"/jobs/{job_id}/result", timeout=_KALI_RESULT_TIMEOUT)
    result_response.raise_for_status()
    result = dict(result_response.json())
    result.setdefault("dispatch_task_id", job_id)
    result.setdefault("execution_path", "mcp_to_kali")
    return result


def _base_contract(request: MCPExecutionRequest, mcp_request_id: str | None = None) -> dict[str, Any]:
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "mcp_execution_id": f"mexec_{uuid.uuid4().hex[:12]}",
        "mcp_request_id": mcp_request_id or request.mcp_request_id or f"mcp_{uuid.uuid4().hex[:12]}",
        "phase_id": request.phase_id,
        "skill_id": request.skill_id,
        "tool_name": request.tool_name,
        "profile": request.profile,
        "target": request.target,
        "status": "blocked",
        "exit_code": None,
        "stdout_path": "",
        "stderr_path": "",
        "artifact_paths": [],
        "started_at": started_at,
        "finished_at": "",
        "duration_ms": 0,
        "evidence_ids": [],
        "error": None,
    }


def _candidate_profile_names(request: MCPExecutionRequest) -> list[str]:
    """Ordered candidate profile names to try against kali_profiles.

    The phase contracts use hyphenated tool names (nuclei-rce, nuclei-headers)
    while the Kali profiles are keyed with underscores (nuclei_rce). This
    bridges the two naming conventions and provides sane fallbacks so a missing
    exact match doesn't stall the whole phase/gate.
    """
    raw_profile = str(request.profile or "").strip()
    raw_tool = str(request.tool_name or "").strip()
    cands: list[str] = []

    def _add(name: str) -> None:
        n = str(name or "").strip()
        if n and n not in cands:
            cands.append(n)

    # 1. Exact as-given
    _add(raw_profile)
    _add(raw_tool)
    # 2. Alias table
    _add(tool_aliases.get(raw_tool, ""))
    _add(tool_aliases.get(raw_profile, ""))
    # 3. Hyphen→underscore normalization (nuclei-rce → nuclei_rce)
    _add(raw_profile.replace("-", "_"))
    _add(raw_tool.replace("-", "_"))
    # 4. Underscore→hyphen (defensive, opposite convention)
    _add(raw_profile.replace("_", "-"))
    _add(raw_tool.replace("_", "-"))
    # 5. Base "nuclei" (no specific template) → the broad CVE template set
    for base in (raw_profile, raw_tool):
        if base in ("nuclei", "nuclei-base"):
            _add("nuclei_cves")
    return cands


async def _resolve_profile_name(request: MCPExecutionRequest) -> str | None:
    for name in _candidate_profile_names(request):
        if name in kali_profiles:
            return name
    # Catalog may be stale — refresh once and retry the candidates.
    await _refresh_kali_catalog()
    for name in _candidate_profile_names(request):
        if name in kali_profiles:
            return name
    return None


async def _submit_kali_profile(profile_name: str, request: MCPExecutionRequest) -> dict[str, Any]:
    if kali_client is None:
        raise HTTPException(status_code=503, detail="Kali runner not available")
    scan_id = request.arguments.get("scan_id")
    if scan_id is not None:
        try:
            scan_id = int(str(scan_id))
        except (ValueError, TypeError):
            scan_id = None
    timeout = int(request.arguments.get("timeout") or (kali_profiles.get(profile_name) or {}).get("timeout") or 300)
    batch_targets = [str(t).strip() for t in (request.targets or []) if str(t).strip()]
    response = await kali_client.post(
        "/jobs",
        json={
            "profile": profile_name,
            "target": request.target,
            "targets": batch_targets,
            "scan_id": scan_id,
            "tool": (kali_profiles.get(profile_name) or {}).get("tool") or profile_name,
            "timeout": timeout,
            "auth_headers": request.arguments.get("auth_headers") or {},
            "extra_args": [
                str(arg)
                for arg in list(request.arguments.get("extra_args") or [])
                if str(arg).strip()
            ],
        },
    )
    response.raise_for_status()
    payload = dict(response.json())
    payload["timeout"] = timeout
    payload["profile"] = profile_name
    return payload


@app.post("/mcp/submit")
async def submit_mcp_contract(request: MCPExecutionRequest) -> dict[str, Any]:
    """Submit a Kali job and return immediately; callers poll status/result."""
    started = time.monotonic()
    contract = _base_contract(request)
    try:
        if not request.expected_evidence:
            contract.update(status="blocked", error="expected_evidence_required")
            return contract
        if kali_client is None:
            contract.update(status="blocked", error="kali_runner_not_available")
            return contract
        profile_name = await _resolve_profile_name(request)
        if not profile_name:
            # Profile genuinely doesn't exist in Kali (e.g. a tool that was never
            # installed). Return 'skipped' — a TERMINAL status — NOT 'blocked'.
            # 'blocked' is non-terminal and would stall the phase forever (the
            # gate waits for all phase items to be terminal), freezing every
            # downstream phase. 'skipped' lets the phase complete and the gate fire.
            contract.update(status="skipped", error=f"tool_or_profile_not_found:{request.tool_name}")
            return contract
        raw = await _submit_kali_profile(profile_name, request)
        contract.update(
            status="submitted",
            profile=profile_name,
            dispatch_task_id=raw.get("job_id"),
            kali_job_id=raw.get("job_id"),
            timeout=raw.get("timeout"),
            execution_path="mcp_to_kali_async",
        )
        return contract
    except HTTPException as exc:
        contract.update(status="failed", error=str(exc.detail))
        return contract
    except Exception as exc:  # noqa: BLE001
        contract.update(status="failed", error=str(exc))
        return contract
    finally:
        contract["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        contract["duration_ms"] = int((time.monotonic() - started) * 1000)


@app.get("/mcp/jobs/{job_id}")
async def mcp_job_status(job_id: str) -> dict[str, Any]:
    if kali_client is None:
        raise HTTPException(status_code=503, detail="Kali runner not available")
    response = await kali_client.get(f"/jobs/{job_id}", timeout=_KALI_POLL_TIMEOUT)
    response.raise_for_status()
    payload = dict(response.json())
    payload.setdefault("kali_job_id", job_id)
    payload["mcp_status"] = "terminal" if payload.get("status") in TERMINAL_STATES else "running"
    return payload


@app.get("/mcp/jobs/{job_id}/result")
async def mcp_job_result(job_id: str) -> dict[str, Any]:
    if kali_client is None:
        raise HTTPException(status_code=503, detail="Kali runner not available")
    result_response = await kali_client.get(f"/jobs/{job_id}/result", timeout=_KALI_RESULT_TIMEOUT)
    result_response.raise_for_status()
    result = dict(result_response.json())
    result.setdefault("dispatch_task_id", job_id)
    result.setdefault("kali_job_id", job_id)
    result.setdefault("execution_path", "mcp_to_kali_async")
    return result


@app.post("/mcp/execute")
async def execute_mcp_contract(request: MCPExecutionRequest) -> dict[str, Any]:
    """Execute a traceable MCP contract and always return explicit status."""
    mcp_request_id = request.mcp_request_id or f"mcp_{uuid.uuid4().hex[:12]}"
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    started = time.monotonic()
    contract = {
        "mcp_execution_id": f"mexec_{uuid.uuid4().hex[:12]}",
        "mcp_request_id": mcp_request_id,
        "phase_id": request.phase_id,
        "skill_id": request.skill_id,
        "tool_name": request.tool_name,
        "profile": request.profile,
        "target": request.target,
        "status": "blocked",
        "exit_code": None,
        "stdout_path": "",
        "stderr_path": "",
        "artifact_paths": [],
        "started_at": started_at,
        "finished_at": "",
        "duration_ms": 0,
        "evidence_ids": [],
        "error": None,
    }
    try:
        if not request.expected_evidence:
            contract.update(status="blocked", error="expected_evidence_required")
            return contract
        if kali_client is None:
            contract.update(status="blocked", error="kali_runner_not_available")
            return contract
        profile_name = request.profile if request.profile in kali_profiles else tool_aliases.get(request.tool_name, request.profile)
        if profile_name not in kali_profiles:
            await _refresh_kali_catalog()
            profile_name = request.profile if request.profile in kali_profiles else tool_aliases.get(request.tool_name, request.profile)
        if profile_name not in kali_profiles:
            contract.update(status="blocked", error=f"tool_or_profile_not_found:{request.tool_name}")
            return contract
        raw = await _run_kali_profile(
            profile_name,
            {
                "target": request.target,
                "targets": list(request.targets or []),          # Tier 3 batch
                "scan_id": request.arguments.get("scan_id"),
                "timeout": request.arguments.get("timeout"),
                # Propagate scanner authentication so kali runner injects
                # the right -H flags into supported tool commands.
                "auth_headers": request.arguments.get("auth_headers") or {},
            },
        )
        exit_code = raw.get("return_code", raw.get("exit_code"))
        raw_status = raw.get("status")
        stdout_raw = str(raw.get("stdout") or "")
        contract.update(
            status="success" if raw_status in {"done", "success"} and exit_code == 0 else "failed",
            exit_code=exit_code,
            stdout_path=raw.get("stdout_path") or raw.get("workdir") or "",
            stderr_path=raw.get("stderr_path") or "",
            artifact_paths=raw.get("artifact_paths") or [],
            error=raw.get("error"),
            # Pass actual output so the runner can extract evidence without a second HTTP call.
            stdout=stdout_raw[:10_000],
            parsed_result=raw.get("parsed"),
            command=raw.get("command") or "",
            duration_seconds=raw.get("duration_seconds"),
        )
        return contract
    except HTTPException as exc:
        contract.update(status="timeout" if exc.status_code == 504 else "failed", error=str(exc.detail))
        return contract
    except Exception as exc:  # noqa: BLE001
        contract.update(status="failed", error=str(exc))
        return contract
    finally:
        contract["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        contract["duration_ms"] = int((time.monotonic() - started) * 1000)


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
                "description": "Accepted learnings, Skill memory and ingested worker knowledge",
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
