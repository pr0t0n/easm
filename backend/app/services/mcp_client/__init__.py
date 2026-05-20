from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.services.kali_executor import TOOL_TO_PROFILE, normalize_kali_result, normalize_target_for_kali


logger = logging.getLogger(__name__)


_PROFILE_TIMEOUT_HINTS: dict[str, int] = {
    # Long-running web validation profiles. The previous default was
    # max(MCP_TIMEOUT*6, 120), which cut nikto/sqlmap/nuclei while the Kali
    # runner kept working in the background. Keep the MCP wait aligned with
    # the runner profile so the backend receives the real result.
    "nuclei_cves": 900,
    "nikto_basic": 900,
    "sqlmap_basic": 600,
    "dalfox_xss": 600,
    "wapiti_scan": 1200,
    "wpscan_basic": 900,
    "nmap_vuln_scripts": 900,
    "nmap_http_enum": 900,
    "nmap_ssl_vuln": 600,
    "nmap_smb_vuln": 600,
    "ffuf_dirs": 600,
    "ffuf_files": 600,
    "ffuf_param_names": 600,
    "wfuzz_param_names": 600,
}


class MCPClient:
    """HTTP client for the local MCP server.

    The backend uses MCP for two things:
    1. RAG retrieval over accepted learnings + Skill memory
    2. Mandatory offensive tool execution proxy to the Kali runner
    """

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = str(base_url or settings.mcp_server_url).rstrip("/")
        self.timeout = float(settings.mcp_request_timeout_seconds)

    def _sync_client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base_url, timeout=self.timeout)

    def _async_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)

    def _sync_timeout(self, timeout: float | None = None) -> httpx.Timeout | float:
        value = float(timeout if timeout is not None else self.timeout)
        return httpx.Timeout(connect=min(value, 10.0), read=value, write=value, pool=value)

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=4))
    async def health_check(self) -> bool:
        try:
            async with self._async_client() as client:
                response = await client.get("/health")
                response.raise_for_status()
                return str(response.json().get("status") or "").lower() == "healthy"
        except Exception as exc:  # noqa: BLE001
            logger.warning("MCP async health check failed: %s", exc)
            return False

    def health_check_sync(self) -> bool:
        try:
            with self._sync_client() as client:
                response = client.get("/health")
                response.raise_for_status()
                return str(response.json().get("status") or "").lower() == "healthy"
        except Exception as exc:  # noqa: BLE001
            logger.warning("MCP sync health check failed: %s", exc)
            return False

    def kali_tools_available_sync(self) -> bool:
        """True only when MCP can actually proxy tool execution to Kali.

        RAG can be healthy without Kali being connected, so execution callers
        must not rely on the generic MCP health status.
        """
        try:
            with self._sync_client() as client:
                response = client.get("/health")
                response.raise_for_status()
                payload = response.json()
                if not bool(payload.get("kali_connected")):
                    return False
                if int(payload.get("kali_profiles_loaded") or 0) <= 0:
                    return False
                return str(payload.get("status") or "").lower() == "healthy"
        except Exception as exc:  # noqa: BLE001
            logger.warning("MCP Kali tool availability check failed: %s", exc)
            return False

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=4))
    async def query_knowledge(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, Any] | None = None,
        skill: str | None = None,
    ) -> list[dict[str, Any]]:
        try:
            async with self._async_client() as client:
                response = await client.post(
                    "/rag/query",
                    json={
                        "query": query,
                        "top_k": top_k,
                        "filters": filters or None,
                        "skill": skill,
                    },
                )
                response.raise_for_status()
                return list(response.json().get("results") or [])
        except Exception as exc:  # noqa: BLE001
            logger.error("MCP async query failed: %s", exc)
            return []

    def query_knowledge_sync(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, Any] | None = None,
        skill: str | None = None,
    ) -> list[dict[str, Any]]:
        try:
            with self._sync_client() as client:
                response = client.post(
                    "/rag/query",
                    json={
                        "query": query,
                        "top_k": top_k,
                        "filters": filters or None,
                        "skill": skill,
                    },
                )
                response.raise_for_status()
                return list(response.json().get("results") or [])
        except Exception as exc:  # noqa: BLE001
            logger.error("MCP sync query failed: %s", exc)
            return []

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=4))
    async def ingest_document(
        self,
        content: str,
        metadata: dict[str, Any] | None = None,
        source: str = "easm_backend",
        document_id: str | None = None,
    ) -> bool:
        try:
            async with self._async_client() as client:
                response = await client.post(
                    "/rag/ingest",
                    json={
                        "content": content,
                        "metadata": metadata or {},
                        "source": source,
                        "document_id": document_id,
                    },
                )
                response.raise_for_status()
                return True
        except Exception as exc:  # noqa: BLE001
            logger.error("MCP async ingest failed: %s", exc)
            return False

    def ingest_document_sync(
        self,
        content: str,
        metadata: dict[str, Any] | None = None,
        source: str = "easm_backend",
        document_id: str | None = None,
    ) -> bool:
        try:
            with self._sync_client() as client:
                response = client.post(
                    "/rag/ingest",
                    json={
                        "content": content,
                        "metadata": metadata or {},
                        "source": source,
                        "document_id": document_id,
                    },
                )
                response.raise_for_status()
                return True
        except Exception as exc:  # noqa: BLE001
            logger.error("MCP sync ingest failed: %s", exc)
            return False

    def list_tools_sync(self) -> list[dict[str, Any]]:
        try:
            with self._sync_client() as client:
                response = client.get("/mcp/tools")
                response.raise_for_status()
                payload = response.json()
                return list(payload.get("tools") if isinstance(payload, dict) else payload)
        except Exception as exc:  # noqa: BLE001
            logger.error("MCP list tools failed: %s", exc)
            return []

    def call_tool_sync(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        try:
            with httpx.Client(base_url=self.base_url, timeout=self._sync_timeout(timeout)) as client:
                response = client.post(f"/mcp/tools/{tool_name}/call", json=parameters)
                response.raise_for_status()
                return dict(response.json())
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
            logger.error("MCP tool call failed: %s", error)
            return {"status": "error", "error": error, "tool": tool_name}

    def execute_kali_tool_sync(
        self,
        tool_name: str,
        target: str,
        *,
        scan_id: int | str | None = None,
        timeout: int | None = None,
        skill_context: dict[str, Any] | None = None,
        extra_args: list[str] | None = None,
    ) -> dict[str, Any]:
        requested = str(tool_name or "").strip()
        if not requested:
            return {"status": "error", "error": "empty_tool_name", "tool": requested}

        original_target = str(target or "").strip()
        normalized_target = normalize_target_for_kali(original_target)
        mcp_tools = self.list_tools_sync()
        tool_names = {str(item.get("name") or "") for item in mcp_tools}
        profile_name = TOOL_TO_PROFILE.get(requested.lower(), requested)
        selected_name = requested if requested in tool_names else profile_name

        metadata_timeout = 0
        for item in mcp_tools:
            if str(item.get("name") or "") != selected_name:
                continue
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            try:
                metadata_timeout = int(metadata.get("timeout") or 0)
            except (TypeError, ValueError):
                metadata_timeout = 0
            break

        profile_timeout = metadata_timeout or _PROFILE_TIMEOUT_HINTS.get(profile_name, 0)
        runner_timeout = int(timeout or profile_timeout or max(self.timeout * 6, 120))
        client_timeout = max(float(runner_timeout) + 15.0, self.timeout)
        payload: dict[str, Any] = {
            "target": normalized_target,
            "scan_id": scan_id or "mcp_scan",
            "timeout": runner_timeout,
            "extra_args": [str(arg) for arg in (extra_args or []) if str(arg).strip()],
        }
        if skill_context:
            payload["skill_context"] = dict(skill_context)
        if normalized_target != original_target:
            payload["original_target"] = original_target
        result = self.call_tool_sync(selected_name, payload, timeout=client_timeout)
        if str(result.get("status") or "").lower() == "error":
            result.setdefault("tool", requested)
            result.setdefault("profile", profile_name)
            result.setdefault("execution_path", "mcp_to_kali")
            result.setdefault("target", normalized_target)
            return result

        legacy = normalize_kali_result(
            tool_name=requested,
            target=normalized_target,
            scan_mode="unit",
            result=result,
        )
        legacy["execution_path"] = "mcp_to_kali"
        legacy["profile"] = result.get("profile") or profile_name
        legacy["raw_mcp_status"] = result.get("status")
        if skill_context:
            legacy["skill_context"] = dict(skill_context)
            if skill_context.get("skill_id"):
                legacy["skill_id"] = skill_context.get("skill_id")
        if normalized_target != original_target:
            legacy["original_target"] = original_target
        return legacy


class RAGService:
    def __init__(self) -> None:
        self.mcp_client = MCPClient()

    async def is_available(self) -> bool:
        if not settings.mcp_rag_enabled:
            return False
        return await self.mcp_client.health_check()

    async def enrich_prompt_with_context(
        self,
        base_prompt: str,
        context_type: str,
        target_info: dict[str, Any],
    ) -> str:
        if not await self.is_available():
            return base_prompt

        query = " ".join(
            part for part in [
                context_type,
                target_info.get("target"),
                target_info.get("skill"),
                target_info.get("phase"),
                target_info.get("tool"),
            ]
            if str(part or "").strip()
        )
        results = await self.mcp_client.query_knowledge(
            query=query,
            top_k=min(5, settings.mcp_default_top_k),
            skill=str(target_info.get("skill") or "") or None,
        )
        if not results:
            return base_prompt

        context_block = "\n".join(
            f"- {str(item.get('content') or '')[:200]}"
            for item in results[:3]
            if str(item.get("content") or "").strip()
        )
        if not context_block:
            return base_prompt
        return f"{base_prompt}\n\nRelevant Skill Memory:\n{context_block}"


mcp_client = MCPClient()
rag_service = RAGService()


async def get_rag_service() -> RAGService:
    return rag_service


def run_async(coro: Any) -> Any:
    return asyncio.run(coro)
