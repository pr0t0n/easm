"""Ingestão de OpenAPI, GraphQL, Postman e HAR para o inventário ofensivo."""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin

import requests
from sqlalchemy.orm import Session

from app.models.models import ScanJob
from app.services.hypothesis_rules import generate_hypotheses_for_scan
from app.services.offensive_inventory_service import OffensiveInventoryService


def ingest_api_spec(
    db: Session,
    scan: ScanJob,
    *,
    spec_url: str = "",
    spec_payload: dict[str, Any] | None = None,
    spec_type: str = "openapi",
    execution_context: str = "external",
    auth_headers: dict[str, str] | None = None,
    auth_cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    from app.services.execution_context_service import inventory_auth_context, normalize_execution_context

    execution_context = normalize_execution_context(execution_context)
    auth_context = inventory_auth_context(execution_context)
    inv = OffensiveInventoryService(db, scan)
    payload = spec_payload or _fetch_json(spec_url, headers=auth_headers, cookies=auth_cookies)
    if not isinstance(payload, dict):
        inv.upsert_api_spec(spec_url or "inline", spec_type=spec_type, parsed_status="failed", metadata={"error": "invalid_json"})
        db.flush()
        return {"ok": False, "error": "invalid_json", "endpoints": 0}

    if spec_type == "har" or "log" in payload:
        count = _ingest_har(inv, payload, auth_context=auth_context)
    elif spec_type == "postman" or "item" in payload and "info" in payload:
        count = _ingest_postman(inv, payload, auth_context=auth_context)
    elif spec_type == "graphql":
        count = _ingest_graphql(inv, payload, spec_url, auth_context=auth_context)
    else:
        count = _ingest_openapi(inv, payload, spec_url, auth_context=auth_context)

    try:
        from app.models.models import OffensiveEndpoint
        from app.services.execution_context_service import upsert_endpoint_observation

        for endpoint in db.query(OffensiveEndpoint).filter(
            OffensiveEndpoint.scan_job_id == scan.id,
            OffensiveEndpoint.auth_context == auth_context,
            OffensiveEndpoint.source_tool.in_(["api-spec", "graphql-spec", "postman", "har"]),
        ).all():
            upsert_endpoint_observation(
                db, scan, endpoint, execution_context=execution_context,
                source_tool=str(endpoint.source_tool or "api-spec"),
                metadata={"source": "api_spec_ingestion", "spec_url": spec_url},
            )
    except Exception:
        pass

    inv.upsert_api_spec(
        spec_url or "inline",
        spec_type=spec_type,
        version=str(payload.get("openapi") or payload.get("swagger") or payload.get("info", {}).get("schema") or ""),
        parsed_status="parsed",
        endpoint_count=count,
        metadata={"title": (payload.get("info") or {}).get("title"), "source": "api_spec_ingestion"},
    )
    generate_hypotheses_for_scan(db, scan)
    db.flush()
    return {"ok": True, "spec_type": spec_type, "endpoints": count}


def _fetch_json(url: str, *, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None) -> dict[str, Any] | None:
    try:
        resp = requests.get(url, timeout=20, verify=False, headers=dict(headers or {}), cookies=dict(cookies or {}))
        return resp.json()
    except Exception:
        return None


def _base_url(spec: dict[str, Any], source_url: str) -> str:
    """Real-world OpenAPI specs commonly declare `servers[0].url` with
    unresolved template variables for multi-environment deploys (e.g.
    "https://{env}-platform.example.com"), and the variable's declared
    `default` frequently points at a different environment than the one we
    actually fetched the spec from (confirmed live: a spec fetched from a
    "hml-api-*" host had servers[0].url templated with `default: "dev-api"`).
    Trusting servers[0] literally, or resolving it to its declared default,
    both produce a host that is out of scope for the scan that found this
    spec. The one thing we know for certain is in-scope is source_url itself
    (the scan already fetched it successfully) — prefer deriving the base
    from that whenever the declared server URL still has an unresolved
    `{...}` placeholder.
    """
    servers = spec.get("servers") or []
    server_url = ""
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        server_url = str(servers[0]["url"])
    if server_url and "{" not in server_url:
        return server_url
    if source_url.startswith("http"):
        return source_url.rsplit("/", 1)[0] + "/"
    return server_url


def _ingest_openapi(inv: OffensiveInventoryService, spec: dict[str, Any], source_url: str, *, auth_context: str = "anonymous") -> int:
    base = _base_url(spec, source_url)
    count = 0
    for path, methods in dict(spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                continue
            url = urljoin(base, path.lstrip("/")) if base else path
            ep = inv.upsert_endpoint(url, method=method.upper(), source_tool="api-spec", auth_context=auth_context, tags=["api"], metadata={"operation_id": (operation or {}).get("operationId") if isinstance(operation, dict) else ""})
            for param in (operation or {}).get("parameters", []) if isinstance(operation, dict) else []:
                if isinstance(param, dict) and param.get("name"):
                    inv.upsert_parameter(ep, str(param["name"]), location=str(param.get("in") or "query"), type_hint=str((param.get("schema") or {}).get("type") or ""), source_tool="api-spec")
            request_body = (operation or {}).get("requestBody") if isinstance(operation, dict) else {}
            for name in _schema_property_names(request_body):
                inv.upsert_parameter(ep, name, location="json", source_tool="api-spec")
            count += 1
    return count


def _ingest_graphql(inv: OffensiveInventoryService, spec: dict[str, Any], source_url: str, *, auth_context: str = "anonymous") -> int:
    endpoint = source_url or "/graphql"
    ep = inv.upsert_endpoint(endpoint, method="POST", source_tool="graphql-spec", auth_context=auth_context, tags=["graphql", "api"])
    count = 1
    schema = spec.get("data", {}).get("__schema") or spec.get("__schema") or {}
    for typ in schema.get("types") or []:
        if not isinstance(typ, dict):
            continue
        if typ.get("name") in {"Query", "Mutation"}:
            for field in typ.get("fields") or []:
                if isinstance(field, dict) and field.get("name"):
                    inv.upsert_parameter(ep, str(field["name"]), location="graphql", type_hint=str(typ.get("name")), source_tool="graphql-spec")
    return count


def _ingest_postman(inv: OffensiveInventoryService, payload: dict[str, Any], *, auth_context: str = "anonymous") -> int:
    count = 0
    for item in _walk_postman_items(payload.get("item") or []):
        request = item.get("request") or {}
        method = str(request.get("method") or "GET")
        url = request.get("url")
        raw = url.get("raw") if isinstance(url, dict) else url
        if not raw:
            continue
        ep = inv.upsert_endpoint(str(raw), method=method, source_tool="postman", auth_context=auth_context, tags=["api"])
        if isinstance(url, dict):
            for q in url.get("query") or []:
                if isinstance(q, dict) and q.get("key"):
                    inv.upsert_parameter(ep, str(q["key"]), location="query", sample_value=str(q.get("value") or ""), source_tool="postman")
        count += 1
    return count


def _ingest_har(inv: OffensiveInventoryService, payload: dict[str, Any], *, auth_context: str = "anonymous") -> int:
    count = 0
    for entry in ((payload.get("log") or {}).get("entries") or []):
        req = entry.get("request") or {}
        url = req.get("url")
        if not url:
            continue
        ep = inv.upsert_endpoint(str(url), method=str(req.get("method") or "GET"), status_code=(entry.get("response") or {}).get("status"), source_tool="har", auth_context=auth_context, tags=["browser"])
        for q in req.get("queryString") or []:
            if isinstance(q, dict) and q.get("name"):
                inv.upsert_parameter(ep, str(q["name"]), location="query", sample_value=str(q.get("value") or ""), source_tool="har")
        count += 1
    return count


def _walk_postman_items(items: list[Any]) -> list[dict[str, Any]]:
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("request"):
            out.append(item)
        out.extend(_walk_postman_items(item.get("item") or []))
    return out


def _schema_property_names(node: Any) -> list[str]:
    if not isinstance(node, dict):
        return []
    names = []
    content = node.get("content") or {}
    for media in content.values():
        schema = media.get("schema") if isinstance(media, dict) else {}
        props = (schema or {}).get("properties") or {}
        names.extend(str(k) for k in props.keys())
    return names
