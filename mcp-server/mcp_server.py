#!/usr/bin/env python3
"""
MCP Server for EASM - Model Context Protocol Implementation

Provides RAG (Retrieval-Augmented Generation) capabilities for the EASM platform,
enabling LLMs to access and retrieve relevant security knowledge, vulnerability
patterns, and contextual information during analysis.
"""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import chromadb
import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import SentenceTransformerEmbeddings
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables for RAG system
vector_store = None
embeddings = None
chroma_client = None

class Document(BaseModel):
    """Document model for RAG ingestion."""
    content: str
    metadata: Dict[str, Any] = {}
    source: str = "unknown"

class QueryRequest(BaseModel):
    """Query request for RAG retrieval."""
    query: str
    top_k: int = 5
    filters: Optional[Dict[str, Any]] = None

class QueryResponse(BaseModel):
    """Response from RAG query."""
    results: List[Dict[str, Any]]
    total_found: int

class MCPTool(BaseModel):
    """MCP Tool definition."""
    name: str
    description: str
    input_schema: Dict[str, Any]

class MCPResource(BaseModel):
    """MCP Resource definition."""
    uri: str
    name: str
    description: str
    mime_type: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global vector_store, embeddings, chroma_client

    # Initialize RAG system
    try:
        # Initialize embeddings
        embeddings = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")

        # Initialize ChromaDB
        chroma_client = chromadb.PersistentClient(path="./chroma_db")

        # Create or get collection
        collection = chroma_client.get_or_create_collection(
            name="easm_knowledge_base",
            metadata={"description": "EASM security knowledge base"}
        )

        # Initialize vector store
        vector_store = Chroma(
            client=chroma_client,
            collection_name="easm_knowledge_base",
            embedding_function=embeddings
        )

        logger.info("RAG system initialized successfully")

        # Load initial knowledge base
        await load_initial_knowledge()

    except Exception as e:
        logger.error(f"Failed to initialize RAG system: {e}")
        # Continue without RAG if initialization fails

    yield

    # Cleanup
    if chroma_client:
        chroma_client.clear_system_cache()

app = FastAPI(
    title="EASM MCP Server",
    description="Model Context Protocol Server with RAG capabilities for EASM",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def load_initial_knowledge():
    """Load initial security knowledge into the vector store."""
    global vector_store

    if not vector_store:
        return

    # Sample security knowledge documents
    initial_docs = [
        Document(
            content="SQL Injection vulnerabilities occur when user input is not properly sanitized before being used in SQL queries. Common patterns include using prepared statements, input validation, and parameterized queries.",
            metadata={"type": "vulnerability", "category": "injection", "severity": "high"},
            source="security_knowledge_base"
        ),
        Document(
            content="Cross-Site Scripting (XSS) vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users. Types include reflected, stored, and DOM-based XSS.",
            metadata={"type": "vulnerability", "category": "injection", "severity": "high"},
            source="security_knowledge_base"
        ),
        Document(
            content="Subdomain enumeration is a reconnaissance technique used to discover hidden subdomains of a target domain. Tools like subfinder, amass, and assetfinder are commonly used.",
            metadata={"type": "technique", "category": "reconnaissance", "phase": "RECONNAISSANCE"},
            source="security_knowledge_base"
        ),
        Document(
            content="Port scanning helps identify open ports and services running on target systems. Nmap is the most comprehensive tool for this purpose, supporting various scan types.",
            metadata={"type": "technique", "category": "reconnaissance", "phase": "RECONNAISSANCE"},
            source="security_knowledge_base"
        ),
        Document(
            content="Web application vulnerability scanning involves automated testing for common security issues. Tools like nuclei, nikto, and wapiti are used for comprehensive scanning.",
            metadata={"type": "technique", "category": "vulnerability_scanning", "phase": "WEAPONIZATION"},
            source="security_knowledge_base"
        )
    ]

    # Add documents to vector store
    for doc in initial_docs:
        try:
            vector_store.add_texts(
                texts=[doc.content],
                metadatas=[doc.metadata],
                ids=[f"{doc.source}_{hash(doc.content)}"]
            )
        except Exception as e:
            logger.warning(f"Failed to add document: {e}")

    logger.info(f"Loaded {len(initial_docs)} initial knowledge documents")

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "rag_enabled": vector_store is not None,
        "chroma_connected": chroma_client is not None
    }

@app.post("/rag/ingest")
async def ingest_document(doc: Document):
    """Ingest a document into the RAG knowledge base."""
    global vector_store

    if not vector_store:
        raise HTTPException(status_code=503, detail="RAG system not available")

    try:
        # Split document into chunks if too large
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200
        )

        chunks = text_splitter.split_text(doc.content)

        # Add chunks to vector store
        for i, chunk in enumerate(chunks):
            chunk_metadata = doc.metadata.copy()
            chunk_metadata["chunk_id"] = i
            chunk_metadata["total_chunks"] = len(chunks)

            vector_store.add_texts(
                texts=[chunk],
                metadatas=[chunk_metadata],
                ids=[f"{doc.source}_{hash(doc.content)}_{i}"]
            )

        return {"status": "success", "chunks_ingested": len(chunks)}

    except Exception as e:
        logger.error(f"Failed to ingest document: {e}")
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")

@app.post("/rag/query")
async def query_knowledge(request: QueryRequest) -> QueryResponse:
    """Query the RAG knowledge base."""
    global vector_store

    if not vector_store:
        raise HTTPException(status_code=503, detail="RAG system not available")

    try:
        # Perform similarity search
        docs = vector_store.similarity_search_with_score(
            query=request.query,
            k=request.top_k,
            filter=request.filters
        )

        # Format results
        results = []
        for doc, score in docs:
            results.append({
                "content": doc.page_content,
                "metadata": doc.metadata,
                "score": float(score),
                "source": doc.metadata.get("source", "unknown")
            })

        return QueryResponse(
            results=results,
            total_found=len(results)
        )

    except Exception as e:
        logger.error(f"Failed to query knowledge base: {e}")
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")

@app.get("/mcp/tools")
async def list_tools() -> List[MCPTool]:
    """List available MCP tools."""
    return [
        MCPTool(
            name="security_knowledge_search",
            description="Search security knowledge base for relevant information",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "category": {"type": "string", "description": "Filter by category"},
                    "limit": {"type": "integer", "description": "Maximum results"}
                },
                "required": ["query"]
            }
        ),
        MCPTool(
            name="vulnerability_pattern_match",
            description="Find vulnerability patterns matching given criteria",
            input_schema={
                "type": "object",
                "properties": {
                    "target_description": {"type": "string", "description": "Description of target"},
                    "vulnerability_type": {"type": "string", "description": "Type of vulnerability"},
                    "severity": {"type": "string", "description": "Severity level"}
                },
                "required": ["target_description"]
            }
        )
    ]

@app.get("/mcp/resources")
async def list_resources() -> List[MCPResource]:
    """List available MCP resources."""
    return [
        MCPResource(
            uri="easm://knowledge/security",
            name="Security Knowledge Base",
            description="Comprehensive security knowledge and vulnerability patterns",
            mime_type="application/json"
        ),
        MCPResource(
            uri="easm://knowledge/vulnerabilities",
            name="Vulnerability Database",
            description="Known vulnerability patterns and exploitation techniques",
            mime_type="application/json"
        ),
        MCPResource(
            uri="easm://knowledge/tools",
            name="Security Tools Reference",
            description="Reference information for security testing tools",
            mime_type="application/json"
        )
    ]

@app.post("/mcp/tools/{tool_name}/call")
async def call_tool(tool_name: str, parameters: Dict[str, Any]):
    """Execute an MCP tool."""
    try:
        if tool_name == "security_knowledge_search":
            query = parameters.get("query", "")
            category = parameters.get("category")
            limit = parameters.get("limit", 5)

            filters = {}
            if category:
                filters["category"] = category

            response = await query_knowledge(QueryRequest(
                query=query,
                top_k=limit,
                filters=filters if filters else None
            ))

            return {
                "result": response.results,
                "total": response.total_found
            }

        elif tool_name == "vulnerability_pattern_match":
            target_desc = parameters.get("target_description", "")
            vuln_type = parameters.get("vulnerability_type")
            severity = parameters.get("severity")

            filters = {}
            if vuln_type:
                filters["type"] = "vulnerability"
                filters["category"] = vuln_type
            if severity:
                filters["severity"] = severity

            response = await query_knowledge(QueryRequest(
                query=f"vulnerability patterns for {target_desc}",
                top_k=10,
                filters=filters if filters else None
            ))

            return {
                "patterns": response.results,
                "matched": len(response.results)
            }

        else:
            raise HTTPException(status_code=404, detail=f"Tool {tool_name} not found")

    except Exception as e:
        logger.error(f"Tool execution failed: {e}")
        raise HTTPException(status_code=500, detail=f"Tool execution failed: {str(e)}")

@app.get("/mcp/resources/{resource_uri}")
async def read_resource(resource_uri: str):
    """Read an MCP resource."""
    try:
        if resource_uri == "easm://knowledge/security":
            # Return security knowledge summary
            return {
                "type": "knowledge_base",
                "categories": ["vulnerabilities", "techniques", "tools"],
                "total_documents": await get_document_count(),
                "last_updated": "2024-01-01T00:00:00Z"
            }

        elif resource_uri == "easm://knowledge/vulnerabilities":
            # Return vulnerability patterns
            response = await query_knowledge(QueryRequest(
                query="vulnerability patterns",
                top_k=20,
                filters={"type": "vulnerability"}
            ))
            return {"vulnerabilities": response.results}

        elif resource_uri == "easm://knowledge/tools":
            # Return tool information
            response = await query_knowledge(QueryRequest(
                query="security tools",
                top_k=20,
                filters={"type": "technique"}
            ))
            return {"tools": response.results}

        else:
            raise HTTPException(status_code=404, detail=f"Resource {resource_uri} not found")

    except Exception as e:
        logger.error(f"Resource read failed: {e}")
        raise HTTPException(status_code=500, detail=f"Resource read failed: {str(e)}")

async def get_document_count() -> int:
    """Get total number of documents in knowledge base."""
    global vector_store
    if not vector_store:
        return 0
    try:
        return len(vector_store.get()["ids"])
    except:
        return 0

if __name__ == "__main__":
    port = int(os.getenv("MCP_PORT", "3000"))
    uvicorn.run(
        "mcp_server:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info"
    )