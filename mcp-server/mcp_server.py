#!/usr/bin/env python3
"""EASM MCP Server — Kali Runner execution bridge.

Responsabilidade única: receber contratos de execução de ferramentas ofensivas
e despachar para o kali_runner via HTTP. O RAG (busca de conhecimento) foi
migrado para o backend via rag_repository + pgvector; este serviço não armazena
nem responde mais a queries de conhecimento.

Endpoints mantidos:
  GET  /health
  GET  /mcp/tools
  POST /mcp/submit          — submete job async ao kali_runner
  GET  /mcp/jobs/{job_id}   — status do job
  GET  /mcp/jobs/{job_id}/result
  POST /mcp/execute         — executa e aguarda (sync)
  POST /mcp/tools/{name}/call
  GET  /mcp/resources
  GET  /mcp/resources/{uri}
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

KALI_RUNNER_URL = os.getenv("KALI_RUNNER_URL", "http://kali_runner:8088").rstrip("/")
MCP_PORT = int(os.getenv("MCP_PORT", "3000"))
TERMINAL_STATES = {"done", "failed", "timeout", "skipped"}

_KALI_POLL_TIMEOUT = httpx.Timeout(connect=5.0, read=5.0, write=5.0, pool=5.0)
_KALI_RESULT_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=5.0, pool=5.0)

kali_client: httpx.AsyncClient | None = None
kali_profiles: dict[str, dict[str, Any]] = {}
tool_aliases: dict[str, str] = {}


# ---------------------------------------------------------------------------
# GUARDRAIL — deny-list espelhada de backend/app/services/guardrail_policy.py.
# ---------------------------------------------------------------------------
import re as _re

_GUARDRAIL_BY_TOOL: dict[str, list[str]] = {
    "sqlmap": [
        r"^--dump(?:-all)?$", r"^--passwords$", r"^--sql-query.*$", r"^--sql-shell$",
        r"^--os-shell$", r"^--os-pwn$", r"^--os-cmd.*$", r"^--os-smbrelay$",
        r"^--file-read.*$", r"^--file-write.*$", r"^--file-dest.*$",
        r"^--reg-read$", r"^--reg-add$", r"^--reg-del$", r"^--eval.*$", r"^--priv-esc$",
    ],
    "ghauri": [
        r"^--dump(?:-all)?$", r"^--os-shell$", r"^--sql-shell$",
        r"^--file-read.*$", r"^--file-write.*$",
    ],
}
_GUARDRAIL_GLOBAL = [
    r"(?i)^--dump(?:-all)?$", r"(?i)^--os-shell$", r"(?i)^--file-write.*$", r"(?i)^--exfil.*$",
]
_GUARDRAIL_NUCLEI_TAGS = {"dos", "fuzzing-dos", "intrusive"}
_GUARDRAIL_THREAD_CAPS = {"hydra": 8, "medusa": 8}

_GUARDRAIL_COMPILED = {t: [_re.compile(p) for p in ps] for t, ps in _GUARDRAIL_BY_TOOL.items()}
_GUARDRAIL_COMPILED_GLOBAL = [_re.compile(p) for p in _GUARDRAIL_GLOBAL]


def _apply_guardrail(tool: str, args: list[str]) -> list[str]:
    if not args:
        return []
    tool_l = str(tool or "").strip().lower()
    pats = _GUARDRAIL_COMPILED.get(tool_l, []) + _GUARDRAIL_COMPILED_GLOBAL
    clean: list[str] = []
    removed: list[str] = []
    skip_next = False
    for i, raw in enumerate(args):
        if skip_next:
            skip_next = False
            removed.append(str(raw))
            continue
        a = str(raw)
        if tool_l == "nuclei" and _re.match(r"(?i)^-?-?tags?(=.*)?$", a):
            val = a.split("=", 1)[1] if "=" in a else (str(args[i + 1]) if i + 1 < len(args) else "")
            if any(t in val.lower() for t in _GUARDRAIL_NUCLEI_TAGS):
                removed.append(a)
                if "=" not in a:
                    skip_next = True
                continue
        if any(p.match(a) for p in pats):
            removed.append(a)
            continue
        clean.append(a)
    cap = _GUARDRAIL_THREAD_CAPS.get(tool_l)
    if cap:
        clean = _guardrail_cap_threads(clean, cap)
    if removed:
        try:
            print(f"[guardrail] tool={tool_l} blocked={removed}", flush=True)
        except Exception:
            pass
    return clean


def _guardrail_cap_threads(args: list[str], cap: int) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        m = _re.match(r"^(-t|-T|--threads?)(=)?(\d+)?$", a)
        if m and m.group(3) and int(m.group(3)) > cap:
            out.append(f"{m.group(1)}{'=' if m.group(2) else ''}{cap}")
            i += 1
            continue
        if m and not m.group(3) and i + 1 < len(args) and str(args[i + 1]).isdigit() and int(args[i + 1]) > cap:
            out.append(a)
            out.append(str(cap))
            i += 2
            continue
        out.append(a)
        i += 1
    return out


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class MCPExecutionRequest(BaseModel):
    mcp_request_id: str | None = None
    phase_id: str
    skill_id: str
    tool_name: str
    profile: str
    target: str
    targets: list[str] = Field(default_factory=list)
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected_evidence: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Kali catalog
# ---------------------------------------------------------------------------

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
    global kali_client
    kali_client = httpx.AsyncClient(
        base_url=KALI_RUNNER_URL,
        timeout=httpx.Timeout(connect=5.0, read=30.0, write=15.0, pool=5.0),
        limits=httpx.Limits(
            max_connections=50,
            max_keepalive_connections=20,
            keepalive_expiry=30.0,
        ),
    )
    await _refresh_kali_catalog()
    yield
    if kali_client is not None:
        await kali_client.aclose()


app = FastAPI(
    title="EASM MCP Server",
    description="Kali execution bridge (RAG migrado para backend/pgvector)",
    version="4.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

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
        "rag_enabled": False,
        "rag_backend": "pgvector",
        "kali_connected": kali_healthy,
        "kali_profiles_loaded": len(kali_profiles),
    }


# ---------------------------------------------------------------------------
# Kali tools catalog
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Kali execution helpers
# ---------------------------------------------------------------------------

async def _run_kali_profile(profile_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
    if kali_client is None:
        raise HTTPException(status_code=503, detail="Kali runner not available")

    scan_id = parameters.get("scan_id")
    if scan_id is not None:
        try:
            scan_id = int(str(scan_id))
        except (ValueError, TypeError):
            scan_id = None

    timeout = int(parameters.get("timeout") or 1800)
    batch_targets = [str(t).strip() for t in (parameters.get("targets") or []) if str(t).strip()]
    response = await kali_client.post(
        "/jobs",
        json={
            "profile": profile_name,
            "target": parameters["target"],
            "targets": batch_targets,
            "scan_id": scan_id,
            "tool": (kali_profiles.get(profile_name) or {}).get("tool") or profile_name,
            "auth_headers": parameters.get("auth_headers") or {},
            "extra_args": _apply_guardrail(
                (kali_profiles.get(profile_name) or {}).get("tool") or profile_name,
                [str(arg) for arg in list(parameters.get("extra_args") or []) if str(arg).strip()],
            ),
        },
    )
    response.raise_for_status()
    job_id = response.json()["job_id"]
    start = asyncio.get_running_loop().time()
    while True:
        elapsed = asyncio.get_running_loop().time() - start
        if elapsed > timeout:
            raise HTTPException(status_code=504, detail=f"MCP timed out waiting for job {job_id}")
        status_response = await kali_client.get(f"/jobs/{job_id}", timeout=_KALI_POLL_TIMEOUT)
        status_response.raise_for_status()
        payload = status_response.json()
        if payload.get("status") in TERMINAL_STATES:
            break
        _sleep = min(2 + int(elapsed // 30), 15)
        await asyncio.sleep(_sleep)
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
    raw_profile = str(request.profile or "").strip()
    raw_tool = str(request.tool_name or "").strip()
    cands: list[str] = []

    def _add(name: str) -> None:
        n = str(name or "").strip()
        if n and n not in cands:
            cands.append(n)

    _add(raw_profile)
    _add(raw_tool)
    _add(tool_aliases.get(raw_tool, ""))
    _add(tool_aliases.get(raw_profile, ""))
    _add(raw_profile.replace("-", "_"))
    _add(raw_tool.replace("-", "_"))
    _add(raw_profile.replace("_", "-"))
    _add(raw_tool.replace("_", "-"))
    for base in (raw_profile, raw_tool):
        if base in ("nuclei", "nuclei-base"):
            _add("nuclei_cves")
    return cands


async def _resolve_profile_name(request: MCPExecutionRequest) -> str | None:
    for name in _candidate_profile_names(request):
        if name in kali_profiles:
            return name
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
    batch_targets = [str(t).strip() for t in (request.targets or []) if str(t).strip()]
    _forwarded_env: dict[str, str] = {}
    _env_forward_keys = ("SHODAN_API_KEY", "HIBP_API_KEY", "GITHUB_TOKEN")
    for _ek in _env_forward_keys:
        _val = str(request.arguments.get(_ek) or request.arguments.get(_ek.lower()) or "").strip()
        if _val:
            _forwarded_env[_ek] = _val
    _extra_env = request.arguments.get("env_vars") or {}
    if isinstance(_extra_env, dict):
        _forwarded_env.update({str(k): str(v) for k, v in _extra_env.items() if str(v).strip()})

    response = await kali_client.post(
        "/jobs",
        json={
            "profile": profile_name,
            "target": request.target,
            "targets": batch_targets,
            "scan_id": scan_id,
            "tool": (kali_profiles.get(profile_name) or {}).get("tool") or profile_name,
            "auth_headers": request.arguments.get("auth_headers") or {},
            "env_vars": _forwarded_env,
            "extra_args": _apply_guardrail(
                (kali_profiles.get(profile_name) or {}).get("tool") or profile_name,
                [str(arg) for arg in list(request.arguments.get("extra_args") or []) if str(arg).strip()],
            ),
        },
    )
    response.raise_for_status()
    payload = dict(response.json())
    payload["profile"] = profile_name
    return payload


# ---------------------------------------------------------------------------
# Kali execution endpoints
# ---------------------------------------------------------------------------

@app.post("/mcp/submit")
async def submit_mcp_contract(request: MCPExecutionRequest) -> dict[str, Any]:
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
                "targets": list(request.targets or []),
                "scan_id": request.arguments.get("scan_id"),
                "timeout": request.arguments.get("timeout"),
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
    raise HTTPException(status_code=404, detail=f"Resource {resource_uri} not found")


if __name__ == "__main__":
    uvicorn.run("mcp_server:app", host="0.0.0.0", port=MCP_PORT, reload=False, log_level="info")
