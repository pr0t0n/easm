"""Normalização genérica de crawlers/fuzzers para o inventário ofensivo."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from sqlalchemy.orm import Session

from app.models.models import ScanJob
from app.services.offensive_inventory_service import OffensiveInventoryService


_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+")
_PATH_RE = re.compile(r"(?m)^\s*(/[^\s\"']{1,240})(?:\s|$)")
_JS_RE = re.compile(r"\.(?:js|mjs|cjs)(?:\?|$)", re.I)
_API_RE = re.compile(r"(?i)(/api/[^\"'\s<>)]{0,180}|/rest/[^\"'\s<>)]{0,180}|/graphql\b|/swagger(?:-ui)?/?|/openapi\.json|/api-docs)")
_FORM_RE = re.compile(r"(?is)<form\b[^>]*?(?:action=[\"']([^\"']+)[\"'])?[^>]*>(.*?)</form>")
_INPUT_RE = re.compile(r"(?is)<(?:input|textarea|select)\b[^>]*?name=[\"']([^\"']+)[\"']")
_METHOD_RE = re.compile(r"(?i)\b(GET|POST|PUT|PATCH|DELETE|OPTIONS)\b")


def normalize_crawler_result(
    db: Session,
    scan: ScanJob,
    *,
    target: str,
    tool_name: str,
    result: dict[str, Any] | None,
    source_artifact_id: int | None = None,
    auth_context: str = "anonymous",
) -> dict[str, Any]:
    inv = OffensiveInventoryService(db, scan)
    payload = result if isinstance(result, dict) else {}
    raw = _raw_text(payload)
    urls = _urls_from_payload(payload, raw, target)
    forms = _forms_from_html(raw, target)
    api_candidates = _api_candidates(raw, target)
    scripts = [u for u in urls if _JS_RE.search(u)]

    endpoints = []
    for url in sorted(set(urls + api_candidates)):
        method = _method_for_url(raw, url)
        ep = inv.ingest_url(
            url,
            source_tool=tool_name,
            discovered_from=target,
            auth_context=auth_context,
            metadata={"source": "crawler_result_normalizer", "source_artifact_id": source_artifact_id},
        )
        if source_artifact_id:
            ep.source_artifact_id = source_artifact_id
        if method != "GET":
            ep.method = method
        endpoints.append(ep)

    form_params = 0
    for form in forms:
        ep = inv.upsert_endpoint(
            form["action"],
            method=form["method"],
            source_tool=tool_name,
            discovered_from=target,
            auth_context=auth_context,
            source_artifact_id=source_artifact_id,
            tags=["form"],
            metadata={"source": "crawler_form", "raw_fields": form["fields"][:50]},
        )
        for name in form["fields"]:
            inv.upsert_parameter(ep, name, location="body" if form["method"] != "GET" else "query", source_tool=tool_name)
            form_params += 1

    # Marca coverage inicial. Testes específicos mudam esse estado depois.
    for ep in endpoints:
        inv.upsert_coverage(
            coverage_type="endpoint",
            target_ref=ep.normalized_url,
            test_class="discovery",
            status="tested_no_issue",
            endpoint_id=ep.id,
            metadata={"source_tool": tool_name},
        )
        if "?" in ep.url:
            inv.upsert_coverage(
                coverage_type="endpoint",
                target_ref=ep.normalized_url,
                test_class="parameter_discovery",
                status="candidate",
                endpoint_id=ep.id,
                metadata={"source_tool": tool_name},
            )

    db.flush()
    return {
        "urls": len(set(urls)),
        "scripts": len(set(scripts)),
        "api_candidates": len(set(api_candidates)),
        "forms": len(forms),
        "form_params": form_params,
        "endpoints_upserted": len(endpoints),
    }


def _raw_text(payload: dict[str, Any]) -> str:
    chunks: list[str] = []
    for key in ("stdout_full", "stdout_preview", "stdout", "body", "html", "raw", "output"):
        value = payload.get(key)
        if value:
            chunks.append(str(value))
    parsed = payload.get("parsed_result") or payload.get("parsed") or {}
    if isinstance(parsed, dict):
        chunks.append(str(parsed))
    return "\n".join(chunks)


def _urls_from_payload(payload: dict[str, Any], raw: str, target: str) -> list[str]:
    urls: list[str] = []
    parsed = payload.get("parsed_result") or payload.get("parsed") or {}
    if isinstance(parsed, dict):
        for key in ("discovered_urls", "urls", "endpoints", "results"):
            for item in parsed.get(key) or []:
                value = item.get("url") if isinstance(item, dict) else item
                if isinstance(value, str):
                    urls.append(_absolute(value, target))
        for key in ("discovered_paths", "paths"):
            for item in parsed.get(key) or []:
                value = item.get("url") if isinstance(item, dict) else item
                if isinstance(value, str):
                    urls.append(_absolute(value, target))
    urls.extend(m.group(0).split("#", 1)[0] for m in _URL_RE.finditer(raw or ""))
    urls.extend(_absolute(m.group(1), target) for m in _PATH_RE.finditer(raw or ""))
    return [u for u in urls if str(u).startswith("http")]


def _api_candidates(raw: str, target: str) -> list[str]:
    return [_absolute(m.group(1), target) for m in _API_RE.finditer(raw or "")]


def _forms_from_html(raw: str, target: str) -> list[dict[str, Any]]:
    forms = []
    for form_match in _FORM_RE.finditer(raw or ""):
        action = form_match.group(1) or target
        body = form_match.group(2) or ""
        method_match = re.search(r"(?i)\bmethod=[\"']([^\"']+)[\"']", form_match.group(0))
        fields = sorted(set(_INPUT_RE.findall(body)))
        forms.append({"action": _absolute(action, target), "method": str(method_match.group(1) if method_match else "GET").upper(), "fields": fields})
    return forms


def _method_for_url(raw: str, url: str) -> str:
    idx = (raw or "").find(url)
    if idx < 0:
        return "GET"
    window = raw[max(0, idx - 80): idx + len(url) + 80]
    method = _METHOD_RE.search(window)
    return method.group(1).upper() if method else "GET"


def _absolute(value: str, target: str) -> str:
    raw = str(value or "").strip().strip("'\"")
    if raw.startswith("http"):
        return raw.split("#", 1)[0]
    if raw.startswith("//"):
        scheme = urlparse(target).scheme or "https"
        return f"{scheme}:{raw}".split("#", 1)[0]
    if raw.startswith("/"):
        return urljoin(target if str(target).startswith("http") else f"https://{target}", raw).split("#", 1)[0]
    return raw.split("#", 1)[0]
