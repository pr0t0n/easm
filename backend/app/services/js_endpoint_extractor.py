"""
js_endpoint_extractor.py — Extração de endpoints a partir de crawl e JS bundles.

Pipeline:
  1. Pega o stdout do katana/gospider (URLs descobertas)
  2. Identifica JS bundles (.js, chunk.js, main.*.js)
  3. Para cada bundle, extrai padrões de endpoint:
       - fetch('/api/v1/users')
       - axios.get('/auth/token')
       - '/graphql'
       - baseURL: 'https://api.example.com'
       - /openapi.json, /swagger.json, /api-docs
  4. Identifica probes de alto valor:
       - GraphQL → seed probe de introspection
       - OpenAPI → seed ffuf com o schema descoberto
       - Admin paths → seed nuclei-exposure
  5. Cria ScanWorkItems para cada endpoint de alto valor encontrado

Chamado por poll_scan_work_item após katana/gospider completar.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ── Padrões para extração de endpoints em JS ────────────────────────────────

# API path literals em código JS
_API_PATH_PATTERNS = [
    # fetch/axios/xhr calls
    re.compile(r"""(?:fetch|get|post|put|delete|patch|request)\s*\(\s*['"](\/[\w\/\-\.]+)['"]""", re.IGNORECASE),
    # template literals: `${base}/api/users`
    re.compile(r"""`\$\{[^}]+\}(\/[\w\/\-\.]+)`"""),
    # string literals that look like API paths
    re.compile(r"""['"](\/(?:api|v\d|graphql|auth|admin|internal|rpc|rest)\/[\w\/\-\.?=&%]+)['"]""", re.IGNORECASE),
    # baseURL / basePath declarations
    re.compile(r"""(?:baseURL|basePath|apiBase|API_URL)\s*[:=]\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    # endpoint object keys: { login: '/api/auth/login' }
    re.compile(r""":\s*['"](\/(api|v\d|auth|admin|graphql|internal)[^\s'"]{3,60})['"]""", re.IGNORECASE),
]

# Caminhos especiais que merecem probes imediatas
_HIGH_VALUE_PATHS = {
    # OpenAPI / Swagger
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/api/swagger.json", "/api/docs", "/api/openapi.json",
    "/openapi.json", "/openapi.yaml", "/openapi/v3/api-docs",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/api-docs", "/api-docs.json", "/docs.json",
    # GraphQL
    "/graphql", "/api/graphql", "/gql", "/query",
    "/graphiql", "/playground",
    # Admin / management
    "/admin", "/admin/", "/administrator", "/manager",
    "/wp-admin", "/wp-login.php",
    "/console", "/management", "/actuator",
    "/actuator/health", "/actuator/info", "/actuator/env",
    # Debug / dev artifacts
    "/.env", "/.env.local", "/.env.production",
    "/config.json", "/settings.json", "/app.config.js",
    "/robots.txt", "/sitemap.xml",
    # Common sensitive endpoints
    "/login", "/signin", "/auth/login", "/api/login", "/api/auth",
    "/register", "/signup", "/forgot-password",
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/health", "/healthz", "/status", "/ping",
}

# Extensões de arquivo que provavelmente contêm endpoints
_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

# Regex para extrair URLs/paths de saída do katana/gospider
_URL_LINE_PATTERN = re.compile(r"https?://\S+|(/[\w/\-\.?=&%#]+)", re.IGNORECASE)

# Paths administrativos/sensíveis para alertar
_SENSITIVE_PATH_PATTERNS = re.compile(
    r"/(admin|administrator|manager|console|management|portal|"
    r"dashboard|internal|private|secret|backup|config|settings|"
    r"env|\.git|\.svn|wp-admin|phpmyadmin|adminer|actuator|"
    r"swagger|api-docs|openapi|graphql|graphiql)",
    re.IGNORECASE,
)


def extract_endpoints_from_crawl(
    stdout: str,
    target: str,
    tool_name: str = "katana",
) -> dict[str, Any]:
    """
    Analisa saída do katana/gospider e retorna:
      - urls: todas as URLs descobertas
      - api_paths: endpoints de API extraídos
      - high_value: paths de alto valor (swagger, graphql, admin)
      - js_files: arquivos JS descobertos para análise adicional
      - sensitive_paths: caminhos potencialmente sensíveis
    """
    urls: list[str] = []
    api_paths: set[str] = set()
    js_files: list[str] = []
    high_value: list[str] = []
    sensitive_paths: list[str] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # gospider prefixes: [url] http://... or [javascript] ...
        # katana output: raw URLs
        # Strip log prefixes
        line = re.sub(r"^\[[\w\-]+\]\s*", "", line)

        if not (line.startswith("http://") or line.startswith("https://")):
            continue

        urls.append(line)

        # Check for JS files
        path = line.split("?")[0]
        if any(path.endswith(ext) for ext in _JS_EXTENSIONS):
            js_files.append(line)

        # Extract path component
        try:
            from urllib.parse import urlparse
            parsed = urlparse(line)
            path = parsed.path
        except Exception:
            path = "/" + "/".join(line.split("/")[3:])

        # High-value path detection
        path_lower = path.lower().rstrip("/") or "/"
        canonical_path = path_lower if path_lower in _HIGH_VALUE_PATHS else None
        if canonical_path:
            high_value.append(line)
        elif _SENSITIVE_PATH_PATTERNS.search(path):
            sensitive_paths.append(line)

    # Also check for API patterns in the raw output (inline JS in HTML)
    for pat in _API_PATH_PATTERNS:
        for m in pat.finditer(stdout):
            candidate = m.group(1)
            if candidate and len(candidate) > 3 and len(candidate) < 200:
                api_paths.add(candidate)

    return {
        "urls": urls[:500],
        "url_count": len(urls),
        "api_paths": sorted(api_paths)[:100],
        "js_files": js_files[:50],
        "high_value": high_value[:30],
        "sensitive_paths": sensitive_paths[:50],
    }


def _extract_js_endpoints(js_content: str) -> list[str]:
    """Extrai endpoints de API de conteúdo de arquivo JS."""
    endpoints: set[str] = set()
    for pat in _API_PATH_PATTERNS:
        for m in pat.finditer(js_content):
            ep = m.group(1)
            if ep and len(ep) > 3 and len(ep) < 300:
                endpoints.add(ep)
    return sorted(endpoints)


def seed_high_value_probes(
    db: Session,
    scan_id: int,
    target: str,
    crawl_result: dict[str, Any],
    *,
    phase_id: str = "P09",
) -> int:
    """
    Para cada high-value path encontrado, cria work items:
      - GraphQL → nuclei-graphql + nuclei-exposure
      - OpenAPI/Swagger → ffuf com schema como wordlist
      - Admin paths → nuclei-exposure
      - Actuator → nuclei-exposure (Spring Boot info leak)

    Retorna quantidade de items criados.
    """
    from app.models.models import ScanWorkItem
    from app.services.scan_work_queue import resource_class_for_tool, PHASE_PRIORITY

    created = 0
    high_value_urls = list(crawl_result.get("high_value") or [])
    sensitive_urls = list(crawl_result.get("sensitive_paths") or [])
    api_paths = list(crawl_result.get("api_paths") or [])

    # Determine which tools to seed based on discovered paths
    tools_to_seed: list[tuple[str, str]] = []  # (tool_name, reason)

    all_discovered = high_value_urls + sensitive_urls
    combined_text = " ".join(all_discovered + api_paths).lower()

    if any("graphql" in u.lower() or "/gql" in u.lower() for u in all_discovered):
        tools_to_seed.append(("nuclei-graphql", "graphql endpoint discovered"))

    if any(x in combined_text for x in ("/swagger", "/openapi", "/api-docs", "/api/docs")):
        tools_to_seed.append(("nuclei-exposure", "swagger/openapi endpoint discovered"))

    if any(x in combined_text for x in ("/admin", "/administrator", "/wp-admin", "/console")):
        tools_to_seed.append(("nuclei-exposure", "admin path discovered"))

    if any("/actuator" in u.lower() for u in all_discovered):
        tools_to_seed.append(("nuclei-exposure", "spring actuator discovered"))

    if api_paths:
        # There are API paths — seed parameter fuzzing
        tools_to_seed.append(("arjun", f"{len(api_paths)} api paths discovered"))

    if any(u.endswith(".js") or "chunk" in u.lower() for u in (crawl_result.get("js_files") or [])):
        tools_to_seed.append(("gitleaks", "js bundles discovered — check for secrets"))

    for tool_name, reason in tools_to_seed:
        already = (
            db.query(ScanWorkItem.id)
            .filter(
                ScanWorkItem.scan_job_id == scan_id,
                ScanWorkItem.phase_id == phase_id,
                ScanWorkItem.tool_name == tool_name,
                ScanWorkItem.target == target[:500],
            )
            .first()
        )
        if already:
            continue

        from app.services.scan_work_queue import apply_phase_tool_metadata

        rc = resource_class_for_tool(tool_name)
        base_pri = PHASE_PRIORITY.get(phase_id, 50)
        item = ScanWorkItem(
            scan_job_id=scan_id,
            phase_id=phase_id,
            target=target[:500],
            tool_name=tool_name,
            profile=tool_name,
            resource_class=rc,
            priority=max(1, base_pri - 10),  # high priority — context-driven
            status="queued",
            max_attempts=2,
            item_metadata=apply_phase_tool_metadata({
                "source": "js_endpoint_extractor",
                "reason": reason,
                "discovered_paths": (high_value_urls + sensitive_urls)[:10],
                "api_path_count": len(api_paths),
            }, phase_id, tool_name, source="js_endpoint_extractor"),
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        db.add(item)
        try:
            db.flush()
            created += 1
            logger.info(
                "js_endpoint_extractor: seeded %s for %s (%s)", tool_name, target, reason
            )
        except Exception as exc:
            db.rollback()
            logger.debug("seed probe flush error: %s", exc)

    if created:
        db.commit()
    return created


def process_crawl_result(
    db: Session,
    scan_id: int,
    target: str,
    tool_name: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    """
    Entry point chamado por poll_scan_work_item após katana/gospider/hakrawler completar.
    Analisa o crawl, semeia probes de alto valor e retorna resumo.
    """
    stdout = str(result.get("stdout_full") or result.get("stdout_preview") or "")
    if not stdout.strip():
        return {"urls": 0, "probes_seeded": 0}

    crawl_result = extract_endpoints_from_crawl(stdout, target, tool_name)
    probes = seed_high_value_probes(db, scan_id, target, crawl_result)

    return {
        "urls": crawl_result["url_count"],
        "api_paths": len(crawl_result["api_paths"]),
        "js_files": len(crawl_result["js_files"]),
        "high_value_found": len(crawl_result["high_value"]),
        "sensitive_paths": len(crawl_result["sensitive_paths"]),
        "probes_seeded": probes,
    }
