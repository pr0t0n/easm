"""MCP Client for EASM - Model Context Protocol Integration.

Provides RAG (Retrieval-Augmented Generation) capabilities by connecting
to the MCP server for enhanced LLM context and knowledge retrieval.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import settings

logger = logging.getLogger(__name__)


class MCPClient:
    """Client for interacting with the MCP server."""

    def __init__(self, base_url: str = None):
        self.base_url = base_url or getattr(settings, 'mcp_server_url', 'http://mcp_server:3000')
        self.client = httpx.AsyncClient(timeout=30.0)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def health_check(self) -> bool:
        """Check if MCP server is healthy."""
        try:
            response = await self.client.get(f"{self.base_url}/health")
            response.raise_for_status()
            data = response.json()
            return data.get("status") == "healthy"
        except Exception as e:
            logger.warning(f"MCP server health check failed: {e}")
            return False

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def query_knowledge(
        self,
        query: str,
        top_k: int = 5,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Query the RAG knowledge base."""
        try:
            payload = {
                "query": query,
                "top_k": top_k,
                "filters": filters
            }

            response = await self.client.post(
                f"{self.base_url}/rag/query",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()

            data = response.json()
            return data.get("results", [])

        except Exception as e:
            logger.error(f"MCP knowledge query failed: {e}")
            return []

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def ingest_document(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        source: str = "easm_backend"
    ) -> bool:
        """Ingest a document into the knowledge base."""
        try:
            payload = {
                "content": content,
                "metadata": metadata or {},
                "source": source
            }

            response = await self.client.post(
                f"{self.base_url}/rag/ingest",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()

            return True

        except Exception as e:
            logger.error(f"MCP document ingestion failed: {e}")
            return False

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def call_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Call an MCP tool."""
        try:
            response = await self.client.post(
                f"{self.base_url}/mcp/tools/{tool_name}/call",
                json=parameters,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()

            return response.json()

        except Exception as e:
            logger.error(f"MCP tool call failed: {e}")
            return {"error": str(e)}

    async def search_security_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Search security knowledge base."""
        return await self.call_tool("security_knowledge_search", {
            "query": query,
            "category": category,
            "limit": limit
        })

    async def find_vulnerability_patterns(
        self,
        target_description: str,
        vulnerability_type: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Find vulnerability patterns matching criteria."""
        return await self.call_tool("vulnerability_pattern_match", {
            "target_description": target_description,
            "vulnerability_type": vulnerability_type,
            "severity": severity
        })


class RAGService:
    """RAG service that integrates MCP client for enhanced LLM context."""

    def __init__(self):
        self.mcp_client = MCPClient()
        self.enabled = True

    async def is_available(self) -> bool:
        """Check if RAG service is available."""
        if not self.enabled:
            return False
        return await self.mcp_client.health_check()

    async def enrich_prompt_with_context(
        self,
        base_prompt: str,
        context_type: str,
        target_info: Dict[str, Any]
    ) -> str:
        """Enrich a prompt with relevant context from RAG."""
        if not await self.is_available():
            logger.info("RAG service not available, using base prompt")
            return base_prompt

        try:
            # Build context query based on type
            if context_type == "vulnerability_analysis":
                query = f"vulnerability analysis for {target_info.get('target', '')}"
                category = "vulnerability"
            elif context_type == "reconnaissance":
                query = f"reconnaissance techniques for {target_info.get('target', '')}"
                category = "reconnaissance"
            elif context_type == "tool_usage":
                query = f"how to use {target_info.get('tool', '')} for security testing"
                category = "technique"
            else:
                query = f"security knowledge for {target_info.get('target', '')}"
                category = None

            # Query knowledge base
            knowledge_results = await self.mcp_client.query_knowledge(
                query=query,
                top_k=3,
                filters={"category": category} if category else None
            )

            if not knowledge_results:
                return base_prompt

            # Build enriched context
            context_parts = []
            for result in knowledge_results[:3]:  # Limit to top 3
                content = result.get("content", "")
                score = result.get("score", 0)
                if score > 0.7:  # Only include highly relevant results
                    context_parts.append(f"- {content[:200]}...")

            if context_parts:
                enriched_context = "\n".join(context_parts)
                enriched_prompt = f"{base_prompt}\n\nRelevant Security Context:\n{enriched_context}\n\nUse this context to inform your analysis and recommendations."
                logger.info(f"Enriched prompt with {len(context_parts)} context items")
                return enriched_prompt

        except Exception as e:
            logger.error(f"Failed to enrich prompt with RAG context: {e}")

        return base_prompt

    async def store_learning_insight(
        self,
        insight: str,
        metadata: Dict[str, Any],
        source: str = "easm_workflow"
    ) -> bool:
        """Store a learning insight in the knowledge base."""
        if not await self.is_available():
            return False

        try:
            return await self.mcp_client.ingest_document(
                content=insight,
                metadata=metadata,
                source=source
            )
        except Exception as e:
            logger.error(f"Failed to store learning insight: {e}")
            return False

    async def get_relevant_patterns(
        self,
        target_description: str,
        vulnerability_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get relevant vulnerability patterns for a target."""
        if not await self.is_available():
            return []

        try:
            return await self.mcp_client.find_vulnerability_patterns(
                target_description=target_description,
                vulnerability_type=vulnerability_type
            )
        except Exception as e:
            logger.error(f"Failed to get relevant patterns: {e}")
            return []


# Global RAG service instance
rag_service = RAGService()


async def get_rag_service() -> RAGService:
    """Get the global RAG service instance."""
    return rag_service