"""Normalização genérica de crawlers/fuzzers para o inventário ofensivo."""
from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse

from sqlalchemy.orm import Session

from app.models.models import ScanJob, ScanLog
from app.services.offensive_inventory_service import OffensiveInventoryService
from app.services.scan_scope import (
    authorized_scope_from_target_query,
    host_from_scope_reference,
    is_host_in_scope,
)

logger = logging.getLogger(__name__)


_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+")
_PATH_RE = re.compile(r"(?m)^\s*(/[^\s\"']{1,240})(?:\s|$)")
_JS_RE = re.compile(r"\.(?:js|mjs|cjs)(?:\?|$)", re.I)
_API_RE = re.compile(r"(?i)(/api/[^\"'\s<>)]{0,180}|/rest/[^\"'\s<>)]{0,180}|/graphql\b|/swagger(?:-ui)?/?|/openapi\.json|/api-docs)")
# Narrower than _API_RE: only the paths that are themselves a machine-readable
# spec document (not just "an API-shaped URL") — these are worth structurally
# parsing via api_spec_ingestion_service, not merely recording as an endpoint.
_SPEC_URL_RE = re.compile(r"(?i)(/swagger(?:-ui)?/?(?:\.json)?$|/openapi\.json$|/api-docs/?$|/v\d+/api-docs$)")
_FORM_RE = re.compile(r"(?is)<form\b[^>]*?(?:action=[\"']([^\"']+)[\"'])?[^>]*>(.*?)</form>")
_INPUT_RE = re.compile(r"(?is)<(?:input|textarea|select)\b[^>]*?name=[\"']([^\"']+)[\"']")
_METHOD_RE = re.compile(r"(?i)\b(GET|POST|PUT|PATCH|DELETE|OPTIONS)\b")


def _try_ingest_exposed_spec(db: Session, scan: ScanJob, spec_url: str) -> None:
    """Auto-parse a discovered OpenAPI/Swagger spec into the offensive endpoint
    inventory. This is the shared path for ZAP, browser capture, endpoint_discovery
    and the offensive operator runner — unlike the katana/gospider/hakrawler-only
    hook in js_endpoint_extractor.py, this one covers whichever tool actually
    surfaces the spec URL first."""
    try:
        from app.services.api_spec_ingestion_service import ingest_api_spec

        result = ingest_api_spec(db, scan, spec_url=spec_url, spec_type="openapi")
        if result.get("ok"):
            logger.info(
                "crawler_result_normalizer: auto-ingested exposed spec %s (%d endpoints)",
                spec_url, result.get("endpoints") or 0,
            )
        else:
            logger.debug(
                "crawler_result_normalizer: exposed spec %s did not parse as OpenAPI: %s",
                spec_url, result.get("error"),
            )
    except Exception:
        logger.debug("crawler_result_normalizer: failed to auto-ingest exposed spec %s", spec_url, exc_info=True)


def _flag_related_out_of_scope_hosts(
    db: Session,
    scan: ScanJob,
    in_scope_target: str,
    blocked_hosts: list[str],
    blocked_urls: list[str],
) -> None:
    """Surface hosts referenced by the target but outside its authorized scope
    as a visible, persisted signal — today this only ever produced a ScanLog
    WARNING line, invisible unless an operator had the live log drawer open at
    the right moment. Never auto-expands scope; only flags it for the operator
    to decide. Deduplicated per scan via state_data so the same host doesn't
    re-fire a finding on every crawl result."""
    state = dict(scan.state_data or {})
    already_flagged = set(state.get("related_hosts_flagged") or [])
    new_hosts = [h for h in blocked_hosts if h and h not in already_flagged]
    if not new_hosts:
        return

    raw_findings = []
    for host in new_hosts:
        example_urls = [u for u in blocked_urls if host_from_scope_reference(u) == host][:5]
        raw_findings.append({
            "title": f"Host relacionado fora do escopo detectado: {host}",
            "severity": "info",
            "risk_score": 1,
            "details": {
                # Deliberately NOT one of asset/domain/host/hostname/target/url/
                # matched_at/final_url/network.* — those are exactly the keys
                # scan_scope.out_of_scope_hosts_for_finding scans, which would
                # reject this very finding for referencing an out-of-scope host.
                "related_host_out_of_scope": host,
                "example_references": example_urls,
                "discovery_note": (
                    f"Referenciado a partir de {in_scope_target}, mas '{host}' nao esta "
                    "no escopo autorizado deste scan. Nenhum teste ativo foi executado "
                    "contra este host. Adicione-o ao escopo explicitamente se ele deve "
                    "ser testado."
                ),
            },
        })

    try:
        from app.services.findings_extractor import persist_finding_dicts

        persist_finding_dicts(
            db, scan, raw_findings,
            default_tool="scope-guard",
            default_target=in_scope_target,
            source_item=None,
        )
    except Exception:
        logger.debug("crawler_result_normalizer: failed to persist related-host-out-of-scope finding", exc_info=True)
        return

    state["related_hosts_flagged"] = sorted(already_flagged | set(new_hosts))[:200]
    scan.state_data = state


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
    browser_requests = _browser_requests_from_payload(payload, raw, target)
    urls = _urls_from_payload(payload, raw, target)
    forms = _forms_from_html(raw, target)
    api_candidates = _api_candidates(raw, target)
    authorized_scope = authorized_scope_from_target_query(str(scan.target_query or ""))

    def _allowed(value: str) -> bool:
        return bool(
            authorized_scope
            and is_host_in_scope(host_from_scope_reference(value), authorized_scope)
        )

    raw_candidates = (
        list(urls)
        + list(api_candidates)
        + [str(req.get("url") or "") for req in browser_requests]
        + [str(form.get("action") or "") for form in forms]
    )
    blocked_urls = sorted({value for value in raw_candidates if value and not _allowed(value)})
    urls = [value for value in urls if _allowed(value)]
    api_candidates = [value for value in api_candidates if _allowed(value)]
    browser_requests = [req for req in browser_requests if _allowed(str(req.get("url") or ""))]
    forms = [form for form in forms if _allowed(str(form.get("action") or ""))]
    browser_urls = {req["url"] for req in browser_requests}
    scripts = [u for u in urls if _JS_RE.search(u)]

    spec_urls = [u for u in (urls + api_candidates) if _SPEC_URL_RE.search(u)]
    if spec_urls:
        _try_ingest_exposed_spec(db, scan, spec_urls[0])
    if blocked_urls:
        blocked_hosts = sorted({host_from_scope_reference(url) for url in blocked_urls if host_from_scope_reference(url)})
        db.add(ScanLog(
            scan_job_id=scan.id,
            source="scope-guard",
            level="WARNING",
            message=(
                f"crawler_inventory_scope_blocked tool={tool_name} "
                f"count={len(blocked_urls)} hosts={blocked_hosts}"
            )[:4000],
        ))
        _flag_related_out_of_scope_hosts(db, scan, target, blocked_hosts, blocked_urls)

    endpoints = []
    for url in sorted(set(urls + api_candidates)):
        if url in browser_urls:
            continue
        method = _method_for_url(raw, url)
        ep = inv.upsert_endpoint(
            url,
            method=method,
            source_tool=tool_name,
            discovered_from=target,
            auth_context=auth_context,
            tags=[],
            metadata={"source": "crawler_result_normalizer", "source_artifact_id": source_artifact_id},
        )
        if source_artifact_id:
            ep.source_artifact_id = source_artifact_id
        endpoints.append(ep)

    captured_params = 0
    for req in browser_requests:
        method = str(req.get("method") or "GET").upper()
        url = str(req.get("url") or "")
        if not url:
            continue
        ep = inv.upsert_endpoint(
            url,
            method=method,
            source_tool=tool_name,
            discovered_from=target,
            auth_context=auth_context,
            source_artifact_id=source_artifact_id,
            tags=["browser-captured", "api"],
            metadata={
                "source": "browser_capture",
                "source_artifact_id": source_artifact_id,
                "has_post_data": bool(req.get("postData")),
            },
        )
        endpoints.append(ep)
        for name in req.get("query_parameters") or []:
            inv.upsert_parameter(
                ep,
                name,
                location="query",
                source_tool=tool_name,
                metadata={"source": "browser_capture_query"},
            )
            captured_params += 1
        body_location = "json" if _looks_json(str(req.get("postData") or "")) else "body"
        for name in req.get("body_parameters") or []:
            inv.upsert_parameter(
                ep,
                name,
                location=body_location,
                source_tool=tool_name,
                metadata={"source": "browser_capture_body"},
            )
            captured_params += 1

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

    # Discovery proves that an endpoint exists; it does not prove that any
    # vulnerability class was tested.  Keep the initial state explicitly
    # non-tested so coverage cannot be inflated by crawling alone.
    for ep in endpoints:
        inv.upsert_coverage(
            coverage_type="endpoint",
            target_ref=ep.normalized_url,
            test_class="discovery",
            status="discovered",
            endpoint_id=ep.id,
            metadata={"source_tool": tool_name},
        )
        if "?" in ep.url:
            inv.upsert_coverage(
                coverage_type="endpoint",
                target_ref=ep.normalized_url,
                test_class="parameter_discovery",
                status="planned",
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
        "browser_requests": len(browser_requests),
        "captured_params": captured_params,
        "endpoints_upserted": len(endpoints),
        "out_of_scope_urls_blocked": len(blocked_urls),
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


def _browser_requests_from_payload(payload: dict[str, Any], raw: str, target: str) -> list[dict[str, Any]]:
    requests_seen: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add_req(item: Any) -> None:
        if not isinstance(item, dict):
            return
        url = _absolute(str(item.get("url") or ""), target)
        if not url.startswith("http"):
            return
        method = str(item.get("method") or "GET").upper()
        post_data = str(item.get("postData") or item.get("post_data") or item.get("body") or "")
        key = (method, url.split("#", 1)[0], post_data[:500])
        if key in seen:
            return
        seen.add(key)
        requests_seen.append({
            "method": method,
            "url": url.split("#", 1)[0],
            "postData": post_data,
            "query_parameters": _query_param_names(url),
            "body_parameters": _body_param_names(post_data),
        })

    for parsed in _parsed_dicts(payload, raw):
        for item in parsed.get("api_requests") or parsed.get("requests") or []:
            add_req(item)
    return requests_seen[:200]


def _parsed_dicts(payload: dict[str, Any], raw: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    parsed = payload.get("parsed_result") or payload.get("parsed")
    if isinstance(parsed, dict):
        out.append(parsed)
    for key in ("stdout_full", "stdout_preview", "stdout", "body", "raw", "output"):
        value = payload.get(key)
        if not value:
            continue
        text = str(value).strip()
        candidates = [text]
        if "{" in text and "}" in text:
            candidates.append(text[text.find("{"): text.rfind("}") + 1])
        for candidate in candidates:
            try:
                decoded = json.loads(candidate)
            except Exception:
                continue
            if isinstance(decoded, dict):
                out.append(decoded)
                break
    return out


def _query_param_names(url: str) -> list[str]:
    return _unique_names(name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True))


def _body_param_names(post_data: str) -> list[str]:
    raw = str(post_data or "").strip()
    if not raw:
        return []
    names: list[str] = []
    try:
        decoded = json.loads(raw)
    except Exception:
        decoded = None
    if decoded is not None:
        _collect_json_keys(decoded, names)
        return _unique_names(names)
    form_names = [name for name, _ in parse_qsl(raw, keep_blank_values=True)]
    if form_names:
        return _unique_names(form_names)
    multipart_names = re.findall(r'name=["\']([^"\']+)["\']', raw)
    return _unique_names(multipart_names)


def _collect_json_keys(value: Any, names: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                names.append(key)
            _collect_json_keys(child, names)
    elif isinstance(value, list):
        for child in value[:20]:
            _collect_json_keys(child, names)


def _unique_names(values: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        name = str(value or "").strip()
        if not name or len(name) > 160:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
    return out[:100]


def _looks_json(value: str) -> bool:
    return str(value or "").lstrip().startswith(("{", "["))


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
