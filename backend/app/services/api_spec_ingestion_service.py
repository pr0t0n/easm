"""Ingestão de OpenAPI, GraphQL, Postman e HAR para o inventário ofensivo."""
from __future__ import annotations

import json
import os
import uuid
from typing import Any
from urllib.parse import urljoin, urlparse

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
    # Base for resolving relative OpenAPI paths when the spec is inline / has no
    # usable `servers` URL: the scan's own authorized target host.
    _tq = str(scan.target_query or "").strip()
    _parsed_tq = urlparse(_tq if "://" in _tq else f"https://{_tq}")
    fallback_base = f"{_parsed_tq.scheme}://{_parsed_tq.netloc}/" if _parsed_tq.netloc else ""
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
        count = _ingest_openapi(inv, payload, spec_url, auth_context=auth_context, fallback_base=fallback_base)

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
    # Inline OpenAPI (no public spec URL): materialize it to the ZAP shared
    # volume so the active API DAST can importFile the operator's endpoints.
    inline_spec_file = ""
    if spec_payload and not spec_url and spec_type == "openapi" and count > 0 and fallback_base:
        inline_spec_file = _materialize_inline_openapi(payload, fallback_base, int(scan.id))
    return {"ok": True, "spec_type": spec_type, "endpoints": count, "inline_spec_file": inline_spec_file}


def _materialize_inline_openapi(spec: dict[str, Any], base_url: str, scan_id: int) -> str:
    """Write an inline OpenAPI spec to the ZAP shared volume so the API DAST can
    importFile it. Without this, an inline spec (no public /openapi.json URL)
    reaches the inventory but never the ZAP OpenAPI scan, which can only import
    from a URL/file — the operator-supplied endpoints would go untested by the
    active API scan. Servers are rewritten to the in-scope target host."""
    try:
        base_dir = os.getenv("ZAP_OPENAPI_SHARED_DIR", "/evidence/zap-openapi")
        os.makedirs(base_dir, exist_ok=True)
        doc = dict(spec)
        parsed = urlparse(base_url)
        if str(doc.get("openapi") or "").startswith("3"):
            doc["servers"] = [{"url": base_url.rstrip("/")}]
        elif doc.get("swagger"):
            doc["schemes"] = [parsed.scheme or "https"]
            doc["host"] = parsed.netloc
            doc["basePath"] = str(doc.get("basePath") or "/")
        path = os.path.join(base_dir, f"scan-{scan_id}-inline-{uuid.uuid4().hex[:12]}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, ensure_ascii=False)
        return path
    except Exception:
        return ""


def _fetch_json(url: str, *, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None) -> dict[str, Any] | None:
    try:
        resp = requests.get(url, timeout=20, verify=False, headers=dict(headers or {}), cookies=dict(cookies or {}))
        return resp.json()
    except Exception:
        return None


def _base_url(spec: dict[str, Any], source_url: str, fallback_base: str = "") -> str:
    """Pick the base URL to resolve relative OpenAPI paths against, scope-aware.

    Real specs are messy about `servers`:
      - `servers[0]` is often a RELATIVE proxy path ("/onboarding") or a
        TEMPLATED multi-env URL ("https://{env}-api.example.com") — neither has
        a usable host, so blindly trusting servers[0] yields hostless endpoints
        that fail the inventory scope gate and abort the whole ingestion.
      - the array usually also lists several absolute environment URLs (prod,
        hml, dev, sandbox, localhost); only the one matching the authorized
        scan target is in scope — the others must NOT be scanned.

    Preference order: an absolute server whose host == the authorized target
    host → the scan's own target (fallback_base) → source_url → first absolute
    server → "". Relative and templated server URLs are ignored.
    """
    servers = spec.get("servers") or []
    absolute: list[str] = []
    for entry in servers:
        if not (isinstance(entry, dict) and entry.get("url")):
            continue
        url = str(entry["url"])
        if "{" in url:
            continue
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            absolute.append(url)

    fallback_host = urlparse(fallback_base).netloc.lower() if fallback_base else ""
    if fallback_host:
        for url in absolute:
            if urlparse(url).netloc.lower() == fallback_host:
                return _ensure_base_slash(url)
    # Prefer the authorized target over any out-of-scope absolute server
    # (hml/dev/sandbox/localhost environments declared in the same spec).
    if fallback_base:
        return _ensure_base_slash(fallback_base)
    if source_url.startswith("http"):
        return source_url.rsplit("/", 1)[0] + "/"
    if absolute:
        return _ensure_base_slash(absolute[0])
    return ""


def _ensure_base_slash(url: str) -> str:
    # urljoin needs the base to end in "/" so a relative path appends instead
    # of replacing the last path segment.
    return url if url.endswith("/") else url + "/"


def _ingest_openapi(inv: OffensiveInventoryService, spec: dict[str, Any], source_url: str, *, auth_context: str = "anonymous", fallback_base: str = "") -> int:
    base = _base_url(spec, source_url, fallback_base)
    count = 0
    for path, methods in dict(spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                continue
            url = urljoin(base, path.lstrip("/")) if base else path
            # One out-of-scope (or hostless) path must not abort ingestion of
            # the rest of the spec: skip it and keep the in-scope endpoints.
            try:
                ep = inv.upsert_endpoint(url, method=method.upper(), source_tool="api-spec", auth_context=auth_context, tags=["api"], metadata={"operation_id": (operation or {}).get("operationId") if isinstance(operation, dict) else ""})
            except ValueError:
                continue
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
