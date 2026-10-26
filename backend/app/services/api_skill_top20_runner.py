from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
import yaml

from app.models.models import Finding, ObservedRequest, OffensiveEndpoint, OffensiveParameter, ScanJob
from app.services.offensive_inventory_service import normalize_url
from app.services.scan_scope import authorized_scope_for_scan, is_host_in_scope


DEFAULT_TIMEOUT_SECONDS = 10
MAX_BODY_CHARS = 160_000
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
STATIC_RE = re.compile(r"\.(?:js|css|png|jpe?g|gif|svg|woff2?|ico|map|webp|pdf)(?:\?|$)", re.I)
API_RE = re.compile(r"(/api/|/rest/|/v\d+/|/graphql|/gql|swagger|openapi)", re.I)
SQL_ERROR_RE = re.compile(r"(sql syntax|mysql|postgres|ora-\d+|sqlite|odbc|jdbc|unterminated quoted|string literal)", re.I)
NOSQL_ERROR_RE = re.compile(r"(MongoError|BSONError|CastError|MongooseError|\$where|E11000|querySelector)", re.I)
SHELL_ERROR_RE = re.compile(r"(sh:|bash:|cmd\.exe|PowerShell|syntax error near unexpected token|command not found)", re.I)
# Generic server-side error / stack-trace signatures for the schema-fuzzing
# oracle (property-based testing idea from Schemathesis: malformed input that
# yields a 5xx or a stack trace signals missing input validation).
STACKTRACE_RE = re.compile(r"(traceback \(most recent call last\)|\bat [\w.$]+\([\w.]+\.(?:java|kt):|werkzeug|django\.|org\.springframework|NullPointerException|undefined (?:index|variable)|Fatal error:|Warning: |Notice: |panic:|goroutine \d+|System\.\w+Exception|unhandled exception)", re.I)
SENSITIVE_RE = re.compile(
    r"(password|passwd|pwd|hash|secret|token|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|"
    r"private[_-]?key|ssn|cpf|cnpj|credit[_-]?card|card[_-]?number|cvv|stacktrace|exception|traceback)",
    re.I,
)
RATE_LIMIT_HEADERS = {
    "ratelimit-limit", "x-ratelimit-limit", "x-rate-limit-limit",
    "ratelimit-remaining", "x-ratelimit-remaining", "retry-after",
}
SENSITIVE_PATH_TOKENS = {
    "admin", "internal", "manage", "management", "role", "roles", "permission", "permissions",
    "approval", "approve", "backoffice", "operator", "root", "account", "accounts", "user",
    "users", "profile", "customer", "customers", "order", "orders", "invoice", "invoices",
    "document", "documents", "exam", "certificate", "payment", "checkout", "cart", "coupon",
    "transaction", "transfer", "otp", "resend", "verify", "settings", "price", "status",
    "token", "session", "auth", "login", "upload", "file", "attachment", "media", "xml",
    "soap", "import", "report", "config", "debug", "error",
}
ANONYMOUS_ACCESS_STATUSES = set(range(200, 300))
ANONYMOUS_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
STRONG_ANONYMOUS_EXPOSURE_TOKENS = {
    "cpf", "cnpj", "ssn", "certificate", "document", "invoice", "payment", "transfer",
    "token", "session", "password", "secret", "user-cpf", "candidatecpf",
}
WEAK_OPERATIONAL_TOKENS = {
    "health", "status", "ping", "version", "time", "server-hour", "server_hour", "clock",
}


@dataclass
class Endpoint:
    method: str
    url: str
    normalized_url: str
    parameters: list[dict[str, str]]
    tags: list[str]
    source_tool: str
    documented: bool
    metadata: dict[str, Any]


@dataclass
class Identity:
    key: str
    role: str
    headers: dict[str, str]
    cookies: dict[str, str]


def _catalog_path() -> Path:
    configured = str(os.getenv("API_TOP20_SKILL_CATALOG") or "").strip()
    if configured:
        return Path(configured)
    here = Path(__file__).resolve()
    roots = [Path("/app/skills")]
    roots.extend(parent / "skills" for parent in here.parents)
    for root in roots:
        candidate = root / "api_testing" / "top20_api_security_skills.yaml"
        if candidate.exists():
            return candidate
    return Path("/app/skills/api_testing/top20_api_security_skills.yaml")


def load_api_top20_skills() -> dict[str, Any]:
    path = _catalog_path()
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    skills = [dict(item) for item in list(data.get("skills") or []) if isinstance(item, dict)]
    data["skills"] = sorted(skills, key=lambda item: int(item.get("priority") or 999))
    data["catalog_path"] = str(path)
    return data


def _host_allowed(url: str, scope: list[str]) -> bool:
    if not scope:
        return False
    try:
        host = str(urlparse(url if "://" in url else f"https://{url}").hostname or "").lower()
    except Exception:
        host = ""
    return bool(host and is_host_in_scope(host, scope))


def _base_url(job: ScanJob, state: dict[str, Any]) -> str:
    api_config = dict(state.get("api_scan_config") or {})
    for raw in (api_config.get("spec_url"), getattr(job, "target_query", ""), *(state.get("openapi_urls") or [])):
        value = str(raw or "").strip()
        if not value:
            continue
        parsed = urlparse(value if "://" in value else f"https://{value}")
        if parsed.hostname:
            return urlunparse((parsed.scheme or "https", parsed.netloc, "", "", "", ""))
    return ""


def _params_from_url(url: str) -> list[dict[str, str]]:
    parsed = urlparse(url)
    return [{"name": str(k), "location": "query", "sample_value": str(v)} for k, v in parse_qsl(parsed.query, keep_blank_values=True)]


def _canonical_endpoint_url(url: str, target_base: str) -> str:
    if not target_base:
        return url
    parsed = urlparse(url)
    base = urlparse(target_base)
    if parsed.hostname and base.hostname and parsed.hostname.lower() == base.hostname.lower():
        return urlunparse((base.scheme or parsed.scheme, base.netloc or parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    return url


def _params_by_endpoint(db: Any, endpoint_ids: list[int]) -> dict[int, list[dict[str, str]]]:
    if not endpoint_ids:
        return {}
    param_rows = (
        db.query(OffensiveParameter)
        .filter(OffensiveParameter.endpoint_id.in_(endpoint_ids))
        .all()
    )
    by_endpoint: dict[int, list[dict[str, str]]] = {}
    for param in param_rows:
        by_endpoint.setdefault(int(param.endpoint_id), []).append({
            "name": str(param.name or ""),
            "location": str(param.location or "query"),
            "sample_value": str(param.sample_value or ""),
            "type_hint": str(param.type_hint or ""),
            "risk_hint": str(param.risk_hint or ""),
        })
    return by_endpoint


# ─── Path-variable value generation ──────────────────────────────────────────
# Templated URIs like /api/v1/admin/dead-letters/{id}/replay must be probed with
# CONCRETE values, not the literal "{id}", or no object is ever reached. Values
# come from (1) the Swagger schema (example/enum/format, persisted as
# sample_value at ingestion) and (2) numeric enumeration — so BOLA/IDOR and the
# other skills can actually enumerate objects and surface codes/data.
_SAMPLE_UUID = "05be75cc-8f8a-414a-891f-434aa9b4e7a5"
_NUMERIC_ENUM = ["1", "2", "3", "10", "100", "9001"]
_PATH_PLACEHOLDER_RE = re.compile(r"\{([^/{}]+)\}|:([^/{}]+)")


def _path_placeholder_names(path: str) -> list[str]:
    """Placeholder names from a path in both {param} and :param styles."""
    return [a or b for (a, b) in _PATH_PLACEHOLDER_RE.findall(path or "")]


def _fill_path_placeholder(url: str, name: str, value: str) -> str:
    """Substitute a path placeholder written as {name} or :name with value."""
    return url.replace("{" + name + "}", value).replace(":" + name, value)
_MAX_ENUM_VARIANTS = 8
_UUID_SEG_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _path_template_key(path: str) -> str:
    """Normalize a URL path to a template key so that a concrete/observed path and
    its documented spec template collapse to the same key:
    /api/v1/admin/dead-letters/{id}/replay and /api/v1/admin/dead-letters/42/replay
    both -> /api/v1/admin/dead-letters/{}/replay. Segments that are placeholders,
    pure digits or UUIDs become {}. Used to avoid flagging as 'shadow' a path that
    matches a template already in the submitted spec."""
    segs: list[str] = []
    for s in str(path or "").strip("/").split("/"):
        if not s:
            continue
        if ("{" in s and "}" in s) or s.startswith(":") or s.isdigit() or _UUID_SEG_RE.match(s):
            segs.append("{}")
        else:
            segs.append(s.lower())
    return "/" + "/".join(segs)


def _looks_numeric(type_hint: str, name: str) -> bool:
    if str(type_hint or "").lower() in {"integer", "number", "int", "long"}:
        return True
    n = str(name or "").lower()
    if "uuid" in n:
        return False
    return any(tok in n for tok in ("id", "num", "count", "page", "limit", "order", "index", "seq"))


def _looks_uuid(name: str, sample: str, type_hint: str) -> bool:
    n = str(name or "").lower()
    if "uuid" in n or "requestid" in n or "projectid" in n:
        return True
    s = str(sample or "")
    return s.count("-") >= 4 and len(s) >= 32


def _path_param_candidates(param: dict[str, Any]) -> list[str]:
    """Values to try for a path variable. Delegates to the schema-driven fuzz
    generator (format-valid samples + IDOR/BOLA enumeration) instead of the old
    ~6 hand-rolled values; capped for path expansion to bound request volume."""
    try:
        from app.services.api_fuzz_generator import fuzz_values_for_param
        res: list[str] = []
        seen: set[str] = set()
        # Keep only the useful classes for a path id (valid + id-enumeration).
        for value, label in fuzz_values_for_param(param, cap=12):
            if not (label.startswith("valid") or label.startswith("idor")):
                continue
            v = str(value)
            if v and "{" not in v and v not in seen:
                seen.add(v)
                res.append(v)
        if res:
            return res[:12]
    except Exception:
        pass
    # Fallback (generator unavailable): minimal legacy probes.
    name = str(param.get("name") or "")
    type_hint = str(param.get("type_hint") or "")
    sample = str(param.get("sample_value") or "").strip()
    out: list[str] = []
    if sample and "{" not in sample:
        out.append(sample)
    if _looks_uuid(name, sample, type_hint):
        out.append(_SAMPLE_UUID)
    if _looks_numeric(type_hint, name):
        out.extend(_NUMERIC_ENUM)
    if not out:
        out.extend(["1", "test"])
    seen2: set[str] = set()
    res2: list[str] = []
    for v in out:
        v = str(v)
        if v and v not in seen2:
            seen2.add(v)
            res2.append(v)
    return res2[:6]


def _expand_templated_endpoints(endpoints: list[Endpoint], test_variables: dict[str, Any] | None = None) -> list[Endpoint]:
    """Expand each endpoint with {path-vars} into the template PLUS concrete
    variants (enumerated/sample values) so skills probe real object URLs. A
    value supplied in test_variables (ex.: um requestId válido) é usado primeiro,
    permitindo testes como optIn contra uma transação real."""
    test_variables = test_variables or {}
    expanded: list[Endpoint] = []
    seen_urls: set[str] = set()
    for ep in endpoints:
        expanded.append(ep)
        seen_urls.add(ep.url)
        placeholders = _path_placeholder_names(urlparse(ep.url).path)
        if not placeholders:
            continue
        params_by_name = {str(p.get("name")): p for p in ep.parameters if str(p.get("location")) == "path"}
        candidates = {}
        for ph in placeholders:
            cands = _path_param_candidates(params_by_name.get(ph, {"name": ph}))
            if ph in test_variables and str(test_variables[ph]):
                v = str(test_variables[ph])
                cands = [v] + [c for c in cands if c != v]
            candidates[ph] = cands
        # Enumerate the first placeholder (the object id); fix the rest to their
        # first candidate, to keep the request count bounded.
        primary = placeholders[0]
        base_fill = {ph: (candidates[ph][0] if candidates[ph] else "1") for ph in placeholders}
        for val in candidates[primary][:_MAX_ENUM_VARIANTS]:
            fill = {**base_fill, primary: val}
            url = ep.url
            for ph, v in fill.items():
                url = _fill_path_placeholder(url, ph, str(v))
            if url in seen_urls:
                continue
            seen_urls.add(url)
            expanded.append(Endpoint(
                method=ep.method,
                url=url,
                normalized_url=normalize_url(url),
                parameters=ep.parameters,
                tags=ep.tags,
                source_tool=ep.source_tool,
                documented=ep.documented,
                metadata={**ep.metadata, "concretized_from": ep.url, "path_values": fill, "enumeration_candidate": str(val)},
            ))
    return expanded


def _add_offensive_endpoint(rows: dict[tuple[str, str], Endpoint], ep: OffensiveEndpoint, scope: list[str], by_endpoint: dict[int, list[dict[str, str]]], metadata_extra: dict[str, Any] | None = None, target_base: str = "") -> None:
    url = _canonical_endpoint_url(str(ep.url or ""), target_base)
    if not url.startswith(("http://", "https://")) or STATIC_RE.search(url) or not _host_allowed(url, scope):
        return
    method = str(ep.method or "GET").upper()
    key = (method, normalize_url(url))
    documented = str(ep.source_tool or "").lower() in {"api-spec", "openapi", "swagger", "graphql-spec"}
    metadata = dict(ep.endpoint_metadata or {})
    metadata.update(metadata_extra or {})
    rows.setdefault(key, Endpoint(
        method=method,
        url=url,
        normalized_url=key[1],
        parameters=by_endpoint.get(int(ep.id), []) + _params_from_url(url),
        tags=[str(tag).lower() for tag in list(ep.tags or [])],
        source_tool=str(ep.source_tool or ""),
        documented=documented,
        metadata=metadata,
    ))


def _collect_endpoints(db: Any, job: ScanJob, scope: list[str]) -> list[Endpoint]:
    rows: dict[tuple[str, str], Endpoint] = {}
    state = dict(job.state_data or {})
    target_base = _base_url(job, state)
    offensive_rows = (
        db.query(OffensiveEndpoint)
        .filter(OffensiveEndpoint.scan_job_id == job.id)
        .order_by(OffensiveEndpoint.id.asc())
        .all()
    )
    by_endpoint = _params_by_endpoint(db, [int(ep.id) for ep in offensive_rows])
    for ep in offensive_rows:
        _add_offensive_endpoint(rows, ep, scope, by_endpoint, target_base=target_base)
    if len(rows) < 5:
        previous_ids = [
            int(row[0]) for row in (
                db.query(ScanJob.id)
                .filter(ScanJob.id != job.id)
                .filter(ScanJob.target_query == job.target_query)
                .filter(ScanJob.access_group_id == job.access_group_id)
                .order_by(ScanJob.id.desc())
                .limit(5)
                .all()
            )
        ]
        if previous_ids:
            previous_rows = (
                db.query(OffensiveEndpoint)
                .filter(OffensiveEndpoint.scan_job_id.in_(previous_ids))
                .filter(OffensiveEndpoint.source_tool.in_(["api-spec", "openapi", "swagger", "graphql-spec"]))
                .order_by(OffensiveEndpoint.id.asc())
                .all()
            )
            previous_params = _params_by_endpoint(db, [int(ep.id) for ep in previous_rows])
            for ep in previous_rows:
                _add_offensive_endpoint(rows, ep, scope, previous_params, {"reused_from_scan_id": ep.scan_job_id}, target_base=target_base)
    for req in (
        db.query(ObservedRequest)
        .filter(ObservedRequest.scan_job_id == job.id)
        .order_by(ObservedRequest.id.asc())
        .all()
    ):
        url = str(req.url or "")
        if not url.startswith(("http://", "https://")) or STATIC_RE.search(url) or not _host_allowed(url, scope):
            continue
        method = str(req.method or "GET").upper()
        key = (method, normalize_url(url))
        rows.setdefault(key, Endpoint(
            method=method,
            url=url,
            normalized_url=key[1],
            parameters=_params_from_url(url),
            tags=["api", "observed"],
            source_tool=str(req.source or "observed_request"),
            documented=False,
            metadata={"observed_request_id": req.id, "identity_key": req.identity_key},
        ))
    for raw in list(state.get("discovered_endpoints") or []) + list(state.get("internal_discovered_endpoints") or []):
        url = _canonical_endpoint_url(str(raw or ""), target_base)
        if not url.startswith(("http://", "https://")) or STATIC_RE.search(url) or not _host_allowed(url, scope):
            continue
        key = ("GET", normalize_url(url))
        rows.setdefault(key, Endpoint(
            method="GET",
            url=url,
            normalized_url=key[1],
            parameters=_params_from_url(url),
            tags=["api"] if API_RE.search(url) else [],
            source_tool="state_discovery",
            documented=False,
            metadata={},
        ))
    return list(rows.values())


def _collect_identities(db: Any, job: ScanJob) -> list[Identity]:
    identities = [Identity(key="anonymous", role="", headers={}, cookies={})]
    try:
        from app.services.auth_session_manager import AuthSessionManager

        for material in AuthSessionManager(db, job).list_material(limit=2):
            identities.append(Identity(
                key=str(material.identity_key or f"identity_{len(identities)}"),
                role=str(material.role or ""),
                headers={str(k): str(v) for k, v in dict(material.headers or {}).items()},
                cookies={str(k): str(v) for k, v in dict(material.cookies or {}).items()},
            ))
    except Exception:
        pass
    return identities


def _select_endpoints(skill: dict[str, Any], endpoints: list[Endpoint], limit: int) -> list[Endpoint]:
    selectors = dict(skill.get("selectors") or {})
    path_keywords = [str(item).lower() for item in list(selectors.get("path_keywords") or [])]
    param_keywords = [str(item).lower() for item in list(selectors.get("parameter_keywords") or [])]
    safe_methods = {str(item).upper() for item in list(skill.get("safe_methods") or [])}
    selected: list[Endpoint] = []
    for ep in endpoints:
        if safe_methods and ep.method.upper() not in safe_methods and not safe_methods.intersection({"HEAD", "OPTIONS"}):
            continue
        text = " ".join([
            urlparse(ep.url).path.lower(),
            " ".join(ep.tags),
            " ".join(str(p.get("name") or "").lower() for p in ep.parameters),
        ])
        if not path_keywords and not param_keywords:
            matched = True
        else:
            matched = any(k and k in text for k in path_keywords) or any(k and k in text for k in param_keywords)
        if matched:
            selected.append(ep)
        if limit > 0 and len(selected) >= limit:
            break
    if selected:
        return selected
    fallback = [
        ep for ep in endpoints
        if API_RE.search(ep.url)
        and (not safe_methods or ep.method.upper() in safe_methods or safe_methods.intersection({"HEAD", "OPTIONS"}))
    ]
    return fallback[:limit] if limit > 0 else fallback


def _fingerprint(response: requests.Response) -> dict[str, Any]:
    body = response.text or ""
    return {
        "status_code": int(response.status_code),
        "content_type": response.headers.get("content-type", ""),
        "body_sha256": hashlib.sha256(body[:MAX_BODY_CHARS].encode("utf-8", errors="ignore")).hexdigest(),
        "body_length": len(body),
    }


_EVIDENCE_BODY_MAX = 2000
_REDACT_HEADER_KEYS = {"authorization", "cookie", "x-api-key", "proxy-authorization", "x-auth-token"}


def _build_curl(method: str, url: str, headers: dict[str, str], cookies: dict[str, str], json_body: Any, identity_key: str = "") -> str:
    """Reproducible cURL for the executed request. Credential header/cookie
    VALUES are masked (the identity is named instead) so evidence is
    reproducible without leaking secrets into the report."""
    parts = [f"curl -i -s -X {method.upper()} {shlex.quote(url)}"]
    for k, v in (headers or {}).items():
        val = f"<identity:{identity_key or 'auth'}>" if str(k).lower() in _REDACT_HEADER_KEYS else str(v)
        parts.append("-H " + shlex.quote(f"{k}: {val}"))
    if cookies:
        parts.append("-H " + shlex.quote("Cookie: " + "; ".join(f"{k}=<identity:{identity_key or 'auth'}>" for k in cookies)))
    if json_body is not None:
        parts.append("-H " + shlex.quote("Content-Type: application/json"))
        parts.append("-d " + shlex.quote(json.dumps(json_body, ensure_ascii=False)))
    return " ".join(parts)


# Optional Caido traffic/replay transport. Set per-scan in run_api_top20_for_scan
# when the scan opted in (use_caido) and a headless Caido is reachable. When set,
# every probe is replayed through Caido (captured in the project); on any failure
# we fall back to direct requests, so Caido is never a hard dependency.
_CAIDO_CLIENT: Any = None
# Burst size for the rate-limit control validation (0 => use skill default).
_RATE_LIMIT_BURST: int = 0

# Request headers that carry multi-tenant context (swapped by tenant_isolation).
_TENANT_HEADER_KEYS = {"x-organization-id", "x-project-id", "x-tenant-id", "organizationid", "projectid", "x-platform-id", "platformid"}

# Generic scoping/ownership tokens: ANY variable (header/path/query/body, any API)
# whose name implies it scopes data to an owner/tenant/account is a cross-tenant
# surface. Pattern-based so the platform works for any API, not a fixed list.
_SCOPING_TOKENS = (
    "org", "organization", "tenant", "project", "account", "owner", "company",
    "workspace", "group", "customer", "client", "realm", "site", "team", "member",
    "partner", "merchant", "store", "shop", "user", "subscriber", "platform",
)


def _is_scoping_var(name: str) -> bool:
    """Heuristic: does this variable name scope data to a tenant/owner? Matches
    any API's scoping variable (x-organization-id, projectId, accountId, ownerId,
    companyUuid, tenant, workspaceKey, ...) without hardcoding a specific API."""
    n = str(name or "").lower().replace("_", "").replace("-", "")
    if not n:
        return False
    if n in {t.replace("-", "") for t in _TENANT_HEADER_KEYS}:
        return True
    for tok in _SCOPING_TOKENS:
        if tok in n and (n.endswith("id") or n.endswith("uuid") or n.endswith("key") or n.endswith("code") or n == tok or n.startswith("x" + tok) or n.startswith(tok)):
            return True
    return False


def _body_similarity(a: str, b: str) -> float:
    """Rough similarity (0..1) between two response bodies, to tell whether a
    tenant-swapped response returned *equivalent* data (cross-tenant leak) vs a
    different/denied one. Bounded for cost."""
    import difflib
    a = (a or "")[:4000]
    b = (b or "")[:4000]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _request(session: requests.Session, method: str, url: str, identity: Identity, *, headers: dict[str, str] | None = None, json_body: Any = None, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    req_headers = {"User-Agent": "ValidCyber-API-SkillTop20/1.0", "Accept": "application/json, text/plain, */*"}
    req_headers.update(identity.headers or {})
    req_headers.update(headers or {})
    curl = _build_curl(method, url, req_headers, identity.cookies or {}, json_body, identity.key)
    request_body = json.dumps(json_body, ensure_ascii=False) if json_body is not None else ""
    if _CAIDO_CLIENT is not None:
        try:
            via = _CAIDO_CLIENT.send(method, url, identity_headers={**(identity.headers or {}), **(headers or {})},
                                     cookies=identity.cookies or {}, json_body=json_body, curl=curl, timeout=timeout)
            if via.get("ok"):
                return via
        except Exception:
            pass  # fall back to direct requests below
    try:
        response = session.request(method.upper(), url, headers=req_headers, cookies=identity.cookies or {}, json=json_body, timeout=timeout, allow_redirects=False, verify=False)
        body = response.text or ""
        return {
            "ok": True,
            "response": response,
            "fingerprint": _fingerprint(response),
            "curl": curl,
            "request_body": request_body[:_EVIDENCE_BODY_MAX],
            "response_status": int(response.status_code),
            "response_headers": {k: v for k, v in list(response.headers.items())[:25]},
            "response_body": body[:_EVIDENCE_BODY_MAX],
            "response_truncated": len(body) > _EVIDENCE_BODY_MAX,
        }
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:300], "curl": curl, "request_body": request_body[:_EVIDENCE_BODY_MAX]}


def _probe_method(skill: dict[str, Any], endpoint: Endpoint) -> str:
    safe_methods = {str(item).upper() for item in list(skill.get("safe_methods") or [])}
    method = endpoint.method.upper()
    if method in READ_METHODS and (not safe_methods or method in safe_methods):
        return method
    if "HEAD" in safe_methods:
        return "HEAD"
    if "OPTIONS" in safe_methods:
        return "OPTIONS"
    return "GET"


def _endpoint_signal_text(endpoint: Endpoint) -> str:
    return " ".join([
        urlparse(endpoint.url).path.lower(),
        " ".join(endpoint.tags).lower(),
        " ".join(str(param.get("name") or "").lower() for param in endpoint.parameters),
    ])


def _sensitive_endpoint_reasons(skill: dict[str, Any], endpoint: Endpoint) -> list[str]:
    selectors = dict(skill.get("selectors") or {})
    keywords = {
        str(item).lower().strip()
        for item in list(selectors.get("path_keywords") or []) + list(selectors.get("parameter_keywords") or [])
        if str(item).strip()
    }
    keywords.update(SENSITIVE_PATH_TOKENS)
    text = _endpoint_signal_text(endpoint)
    matched = sorted(keyword for keyword in keywords if keyword and keyword in text)
    return matched[:12]


def _anonymous_exposure_profile(skill: dict[str, Any], endpoint: Endpoint, reasons: list[str], status_code: int) -> dict[str, Any]:
    text = _endpoint_signal_text(endpoint)
    strong = sorted(token for token in STRONG_ANONYMOUS_EXPOSURE_TOKENS if token in text or token in reasons)
    weak = sorted(token for token in WEAK_OPERATIONAL_TOKENS if token in text)
    skill_id = str(skill.get("id") or "")
    if weak and not strong:
        return {"severity": "medium", "confidence": 35, "confidence_score": 35, "risk_score": 5, "signal_strength": "weak_operational_endpoint", "strong_reasons": strong, "weak_reasons": weak}
    if strong:
        severity = "high" if status_code in ANONYMOUS_ACCESS_STATUSES else "medium"
        confidence = 72 if skill_id in {"skill.api.bola_idor", "skill.api.bopla"} else 65
        return {"severity": severity, "confidence": confidence, "confidence_score": confidence, "risk_score": 8 if severity == "high" else 5, "signal_strength": "strong_sensitive_endpoint", "strong_reasons": strong, "weak_reasons": weak}
    return {"severity": "medium", "confidence": 50, "confidence_score": 50, "risk_score": 5, "signal_strength": "generic_sensitive_endpoint", "strong_reasons": strong, "weak_reasons": weak}


def _response_observation(skill: dict[str, Any], endpoint: Endpoint, identity: Identity, method: str, result: dict[str, Any]) -> dict[str, Any]:
    observation = {
        "skill_id": skill.get("id"),
        "endpoint": endpoint.url,
        "method": method,
        "identity_key": identity.key,
        "ok": bool(result.get("ok")),
    }
    fingerprint = dict(result.get("fingerprint") or {})
    if fingerprint:
        observation.update({
            "http_status": fingerprint.get("status_code"),
            "content_type": fingerprint.get("content_type"),
            "body_sha256": fingerprint.get("body_sha256"),
            "body_length": fingerprint.get("body_length"),
        })
    if not result.get("ok"):
        observation.update({"error": result.get("error"), "detail": result.get("detail")})
    # Evidence for the per-endpoint drill-down: executed cURL, request body and
    # the response body/status, so clicking an endpoint shows exactly what ran.
    observation.update({
        "curl": result.get("curl"),
        "request_body": result.get("request_body") or "",
        "response_status": result.get("response_status"),
        "response_body": result.get("response_body") or "",
        "response_truncated": bool(result.get("response_truncated")),
    })
    return observation


def _response_evidence(result: dict[str, Any], method: str) -> dict[str, Any]:
    fingerprint = dict(result.get("fingerprint") or {})
    return {
        "method": method,
        "http_status": fingerprint.get("status_code"),
        "response_fingerprint": fingerprint,
    }


def _anonymous_exposure_finding(skill: dict[str, Any], endpoint: Endpoint, result: dict[str, Any], method: str) -> dict[str, Any] | None:
    response = result.get("response")
    if response is None:
        return None
    status_code = int(response.status_code)
    if status_code not in ANONYMOUS_ACCESS_STATUSES and status_code not in ANONYMOUS_REDIRECT_STATUSES:
        return None
    reasons = _sensitive_endpoint_reasons(skill, endpoint)
    if not reasons:
        return None
    profile = _anonymous_exposure_profile(skill, endpoint, reasons, status_code)
    severity = str(profile.get("severity") or "medium")
    evidence = f"Endpoint sensível acessível sem autenticação retornou HTTP {status_code}; requer reteste com identidade/fixture para confirmação."
    extra = _response_evidence(result, method)
    extra.update({
        "anonymous_access": True,
        "sensitive_reasons": reasons,
        "confirmation_gap": "identity_or_fixture_required",
        "api_skill_signal_strength": profile.get("signal_strength"),
        "api_skill_confidence_score": profile.get("confidence"),
        "api_skill_risk_score": profile.get("risk_score"),
        "strong_reasons": profile.get("strong_reasons"),
        "weak_reasons": profile.get("weak_reasons"),
    })
    finding = _finding(skill, endpoint.url, evidence, "anonymous", severity=severity, verification_status="candidate", evidence_extra=extra)
    finding["risk_score"] = int(profile.get("risk_score") or finding.get("risk_score") or 5)
    return finding


def _replace_first_query_value(url: str, payload: str, operator_suffix: str = "") -> str | None:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not pairs:
        return None
    key, _ = pairs[0]
    pairs[0] = (f"{key}{operator_suffix}", payload)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(pairs), parsed.fragment))


def _extract_json_field_names(value: Any, depth: int = 0) -> set[str]:
    if depth > 5:
        return set()
    out: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            out.add(str(key))
            out.update(_extract_json_field_names(child, depth + 1))
    elif isinstance(value, list):
        for child in value[:10]:
            out.update(_extract_json_field_names(child, depth + 1))
    return out


def _decoded_jwt_findings(skill: dict[str, Any], identities: list[Identity], target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for identity in identities:
        auth = next((v for k, v in identity.headers.items() if str(k).lower() == "authorization"), "")
        token = str(auth or "").removeprefix("Bearer ").strip()
        if token.count(".") != 2:
            continue
        try:
            header_raw, payload_raw, _sig = token.split(".")
            header_raw += "=" * (-len(header_raw) % 4)
            payload_raw += "=" * (-len(payload_raw) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_raw.encode()))
            payload = json.loads(base64.urlsafe_b64decode(payload_raw.encode()))
        except Exception:
            continue
        gaps = []
        if str(header.get("alg") or "").lower() in {"none", ""}:
            gaps.append("alg ausente ou none")
        if header.get("kid") and any(token in str(header.get("kid")) for token in ("..", "://", "\\", "/")):
            gaps.append("kid contém path/URL")
        for claim in ("exp", "iss", "aud"):
            if claim not in payload:
                gaps.append(f"claim {claim} ausente")
        if gaps:
            findings.append(_finding(skill, target, "; ".join(gaps), identity.key, evidence_extra={"decoded_header": _redact(header), "decoded_claims": _redact(payload)}))
    return findings


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if SENSITIVE_RE.search(str(k)) else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value[:20]]
    text = str(value)
    if len(text) > 160:
        return text[:80] + "...[truncated]"
    return value


def _finding(skill: dict[str, Any], endpoint: str, evidence: str, identity_key: str = "anonymous", *, severity: str | None = None, verification_status: str = "candidate", evidence_extra: dict[str, Any] | None = None) -> dict[str, Any]:
    spec = dict(skill.get("finding") or {})
    title = f"{skill.get('name')}: {str(endpoint)[:120]}"
    sev = str(severity or spec.get("severity") or skill.get("typical_criticality") or "medium").lower()
    if sev == "critical" and verification_status != "confirmed":
        sev = "high"
    details = {
        "tool": "api-skill-top20",
        "source_tool": "api-skill-top20",
        "api_tested_via": "api_skill_top20",
        "api_skill_id": skill.get("id"),
        "api_skill_name": skill.get("name"),
        "api_skill_priority": skill.get("priority"),
        "finding_class": spec.get("finding_class"),
        "vuln_family": spec.get("vuln_family"),
        "owasp_category": skill.get("owasp"),
        "url": endpoint,
        "matched_at": endpoint,
        "asset": endpoint,
        "identity_key": identity_key,
        "verification_status": verification_status,
        "evidence": evidence,
        "description": evidence,
        "discovery_method": "requests_safe_api_probe sobre inventário OpenAPI/observado",
        "reproduction": {
            "url": endpoint,
            "identity_key": identity_key,
            "expected_result": "A API deve negar, rejeitar ou validar a entrada de acordo com o controle testado.",
            "observed_result": evidence,
        },
    }
    details.update(evidence_extra or {})
    return {
        "title": title,
        "severity": sev,
        "risk_score": {"critical": 9, "high": 8, "medium": 5, "low": 3, "info": 1}.get(sev, 5),
        "url": endpoint,
        "source_tool": "api-skill-top20",
        "details": details,
    }


_FUZZ_QUERY_PAYLOADS = ["A" * 5000, "-1", "2147483648", "null", "' OR '1'='1", "../../../../etc/passwd", "{{7*7}}"]
# Flags que costumam pular validação/etapas (o incidente foi optIn:true aceitando
# submissão sem imagem). Enviar como true + corpo mínimo para testar bypass.
_BYPASS_FLAGS = ["optIn", "optin", "skip", "skipValidation", "skipLiveness", "skipFraud",
                 "bypass", "force", "override", "docless", "mock", "test", "debug",
                 "verified", "approved", "isValid", "validated"]


def _fuzz_cases(ep: Endpoint, allow_mutations: bool, test_variables: dict[str, Any] | None = None) -> list[tuple[str, str, Any, str]]:
    """Property/schema fuzzing probes: malformed/boundary/injection values for
    EVERY declared query param and request-body field, from the schema-driven
    generator. Returns (method, url, json_body, label). Body fuzzing (mutating)
    is gated behind allow_mutations."""
    cases: list[tuple[str, str, Any, str]] = []
    try:
        from app.services.api_fuzz_generator import fuzz_values_for_param
    except Exception:
        fuzz_values_for_param = None  # type: ignore[assignment]

    def attack_values(param: dict[str, Any], n: int) -> list[tuple[Any, str]]:
        if fuzz_values_for_param is None:
            return [(p, f"query:{param.get('name')}") for p in _FUZZ_QUERY_PAYLOADS[:n]]
        vals = [(v, lb) for (v, lb) in fuzz_values_for_param(param, cap=12) if not lb.startswith(("valid", "idor"))]
        return vals[:n]

    # Query fuzzing: every declared query parameter (spec keeps params in
    # ep.parameters, not the URL) plus any existing URL query key.
    query_params = [p for p in ep.parameters if str(p.get("location")) == "query" and p.get("name")]
    existing = parse_qsl(urlparse(ep.url).query, keep_blank_values=True)
    if not query_params and existing:
        query_params = [{"name": existing[0][0]}]
    if query_params and ep.method.upper() in {"GET", "HEAD"}:
        parsed = urlparse(ep.url)
        per = 6 if allow_mutations else 4
        for qp in query_params[:6]:
            qn = str(qp.get("name"))
            for value, label in attack_values(qp, per):
                base_pairs = dict(existing)
                base_pairs[qn] = str(value)
                furl = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(base_pairs), parsed.fragment))
                cases.append(("GET", furl, None, f"query:{qn}:{label}"))
    json_fields = [str(p.get("name")) for p in ep.parameters if str(p.get("location")) == "json" and p.get("name")]
    json_params = [p for p in ep.parameters if str(p.get("location")) == "json" and p.get("name")]
    if json_params and ep.method.upper() in {"POST", "PUT", "PATCH"} and allow_mutations:
        # Per-field injection: each body field gets a few malformed/injection values.
        base_body = {f: "x" for f in json_fields}
        for jp in json_params[:8]:
            fn = str(jp.get("name"))
            for value, label in attack_values(jp, 3):
                cases.append((ep.method.upper(), ep.url, {**base_body, fn: value}, f"body:{fn}:{label}"))
    if json_fields and ep.method.upper() in {"POST", "PUT", "PATCH"} and allow_mutations:
        cases.append((ep.method.upper(), ep.url, {f: "A" * 2000 for f in json_fields}, "body:oversized"))
        cases.append((ep.method.upper(), ep.url, {f: [] for f in json_fields}, "body:type-confusion"))
        cases.append((ep.method.upper(), ep.url, {**{f: "x" for f in json_fields}, "isAdmin": True, "role": "admin"}, "body:mass-assignment"))
        # Validation-bypass by flag (incidente optIn: fraude aceitou submissão SEM
        # imagem com optIn:true). Injeta flags de bypass e envia corpo MÍNIMO —
        # se a API aceitar (2xx) em vez de rejeitar, é bypass de regra de negócio.
        cases.append((ep.method.upper(), ep.url, {**{f: "x" for f in json_fields}, **{k: True for k in _BYPASS_FLAGS}}, "body:bypass-flags"))
        cases.append((ep.method.upper(), ep.url, {k: True for k in _BYPASS_FLAGS}, "body:only-flags-no-required"))
        # Caso optIn com variáveis REAIS (requestId/cpf/...) — reproduz o incidente:
        # corpo válido pelos campos fornecidos + optIn:true, SEM imagem/documento.
        tv = test_variables or {}
        if tv:
            body = {f: tv.get(f, "x") for f in json_fields}
            body.update({k: tv[k] for k in tv if k not in ("requestId", "x-api-key", "x-organization-id", "x-project-id")})
            body["optIn"] = True
            cases.append((ep.method.upper(), ep.url, body, "body:optin-with-vars"))
    # Bound per-endpoint request volume (higher ceiling now that every variable
    # is fuzzed, but still capped to avoid hammering the target).
    return cases[: (60 if allow_mutations else 30)]


# Curated API route segments for active shadow-route discovery (kiterunner idea):
# find UNDOCUMENTED endpoints that are not in the submitted spec/crawl.
_API_ROUTE_WORDLIST = [
    "users", "user", "accounts", "account", "admin", "internal", "private", "debug",
    "status", "health", "config", "settings", "transactions", "transaction", "orders",
    "order", "documents", "document", "files", "file", "upload", "download", "results",
    "result", "callback", "callbacks", "webhook", "webhooks", "values", "value", "submit",
    "data", "process", "processes", "steps", "step", "sign", "signer", "signature",
    "export", "import", "reports", "report", "metrics", "audit", "logs", "notifications",
    "search", "me", "profile", "session", "token", "refresh", "verify", "validate",
    "approve", "reject", "replay", "discard", "reprocess", "retry", "cancel", "v1", "v2", "v3",
]


def _discover_shadow_routes(session: requests.Session, endpoints: list[Endpoint], identities: list[Identity], scope: list[str], *, limit: int = 180, timeout: int = 8) -> list[Endpoint]:
    """Active route discovery: probe candidate API routes derived from the spec's
    own path prefixes/resource names + a curated wordlist, to surface endpoints
    NOT present in the submitted spec/crawl. A non-404/<500 response means the
    route exists (even if auth-gated)."""
    bases: set[str] = set()
    resource_names: set[str] = set()
    for ep in endpoints:
        if not ep.documented:
            continue
        p = urlparse(ep.url)
        segs = [s for s in p.path.split("/") if s and "{" not in s]
        for i in range(1, len(segs) + 1):
            bases.add(f"{p.scheme}://{p.netloc}/" + "/".join(segs[:i]) + "/")
        for s in segs:
            if not s.isdigit():
                resource_names.add(s.lower())
    words = list(dict.fromkeys(list(resource_names) + _API_ROUTE_WORDLIST))
    identity = identities[0] if identities else Identity("anonymous", "", {}, {})
    known = {normalize_url(ep.url) for ep in endpoints}
    discovered: list[Endpoint] = []
    seen: set[str] = set()
    probes = 0
    for base in sorted(bases, key=len):
        for w in words:
            if probes >= limit:
                return discovered
            url = urljoin(base, w)
            if not url.startswith(("http://", "https://")) or not _host_allowed(url, scope):
                continue
            key = normalize_url(url)
            if key in seen or key in known:
                continue
            seen.add(key)
            probes += 1
            r = _request(session, "GET", url, identity, timeout=timeout)
            resp = r.get("response")
            if resp is None:
                continue
            sc = int(resp.status_code)
            if sc != 404 and sc != 400 and sc < 500:
                discovered.append(Endpoint("GET", url, key, [], ["shadow"], "route-brute", False, {"discovered_via": "route_brute", "probe_status": sc}))
    return discovered


def _object_id_params(ep: Endpoint) -> list[str]:
    """Path variables that identify an object/transaction (id, requestId,
    externalId, uuid, *_id). These are the BOLA access-control surface."""
    out: list[str] = []
    for name in _path_placeholder_names(urlparse(ep.url).path):
        nl = name.lower()
        if any(tok in nl for tok in ("id", "uuid", "request", "external", "order")):
            out.append(name)
    return out


def _guessable_identifier(id_params: list[str]) -> bool:
    # Client-assigned / sequential identifiers (externalId "order-12345") are
    # enumerable — the worst case for object-id-only access control.
    return any(g in p.lower() for p in id_params for g in ("external", "order"))


def _run_endpoint_skill(skill: dict[str, Any], endpoints: list[Endpoint], identities: list[Identity], limits: dict[str, Any], allow_mutations: bool, test_variables: dict[str, Any] | None = None) -> dict[str, Any]:
    max_endpoints = 0
    timeout = int(limits.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
    all_matching = _select_endpoints(skill, endpoints, 0)
    selected = _select_endpoints(skill, endpoints, max_endpoints)
    selected_count = len(selected)
    matched_count = len(all_matching)
    if skill.get("local_analysis"):
        findings = _decoded_jwt_findings(skill, identities, selected[0].url if selected else "")
        return {
            "status": "completed",
            "selected": selected_count,
            "selected_endpoint_count": selected_count,
            "matched_endpoint_count": matched_count,
            "skipped_endpoint_count": max(0, matched_count - selected_count),
            "coverage_complete": selected_count >= matched_count,
            "coverage_gap_reason": None if selected_count >= matched_count else "endpoint_limit_reached",
            "attempts": 0,
            "request_limit": None,
            "findings": findings,
            "observations": [],
        }

    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    attempts = 0
    blocked_reasons: set[str] = set()
    if skill.get("mutating_confirmation_requires_fixture") and not allow_mutations:
        blocked_reasons.add("mutation_fixture_or_allow_mutations_required")
    if skill.get("requires_two_identities_for_confirmation") and len(identities) < 3:
        blocked_reasons.add("second_identity_required_for_confirmation")
    with requests.Session() as session:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        for ep in selected:
            skill_id = str(skill.get("id") or "")
            active_identities = identities if skill.get("requires_authorization") else identities[:1]
            for identity in active_identities:
                if skill_id == "skill.api.cors_misconfiguration":
                    attempts += 1
                    result = _request(session, "OPTIONS" if ep.method != "GET" else "GET", ep.url, identity, headers={"Origin": "https://attacker.example"}, timeout=timeout)
                    observations.append(_response_observation(skill, ep, identity, "OPTIONS" if ep.method != "GET" else "GET", result))
                    response = result.get("response")
                    if response is not None:
                        acao = response.headers.get("access-control-allow-origin", "")
                        acac = response.headers.get("access-control-allow-credentials", "")
                        if acao == "*" and str(acac).lower() == "true" or acao == "https://attacker.example":
                            extra = _response_evidence(result, "OPTIONS" if ep.method != "GET" else "GET")
                            extra.update({"access_control_allow_origin": acao, "access_control_allow_credentials": acac})
                            findings.append(_finding(skill, ep.url, f"CORS permissivo: ACAO={acao!r}, ACAC={acac!r}.", identity.key, evidence_extra=extra))
                    continue
                if skill_id == "skill.api.graphql_security":
                    attempts += 1
                    result = _request(session, "POST", ep.url, identity, json_body={"query": "query{__schema{queryType{name}}}"}, timeout=timeout)
                    observations.append(_response_observation(skill, ep, identity, "POST", result))
                    response = result.get("response")
                    if response is not None and response.status_code == 200 and "__schema" in (response.text or "")[:8000]:
                        findings.append(_finding(skill, ep.url, "Introspection GraphQL habilitada e retornando schema.", identity.key, verification_status="confirmed", evidence_extra=_response_evidence(result, "POST")))
                    continue
                if skill_id == "skill.api.rate_limit_resource_consumption":
                    # Rate-limit CONTROL validation: burst N requests and detect
                    # whether throttling engages (429), rate-limit headers are
                    # present, or when the control trips. Burst is configurable via
                    # api_scan_config.rate_limit_burst (default 30) so it's enough
                    # to actually exercise the control, not just 3 probes.
                    burst = _RATE_LIMIT_BURST or int(skill.get("max_repeated_requests") or 3)
                    codes: list[int] = []
                    header_names: set[str] = set()
                    first_429_at = 0
                    retry_after = ""
                    method = _probe_method(skill, ep)
                    for i in range(burst):
                        attempts += 1
                        result = _request(session, method, ep.url, identity, timeout=timeout)
                        if i < 4 or (result.get("response") is not None and int(getattr(result.get("response"), "status_code", 0)) == 429):
                            observations.append(_response_observation(skill, ep, identity, method, result))
                        response = result.get("response")
                        if response is None:
                            continue
                        sc = int(response.status_code)
                        codes.append(sc)
                        hdrs = {k.lower(): v for k, v in response.headers.items()}
                        header_names.update(hdrs.keys())
                        if sc == 429 and not first_429_at:
                            first_429_at = i + 1
                            retry_after = str(hdrs.get("retry-after") or "")
                            break  # control engaged — enough evidence
                    rl_headers = sorted(header_names.intersection(RATE_LIMIT_HEADERS))
                    total = len(codes)
                    if first_429_at:
                        findings.append(_finding(
                            skill, ep.url,
                            f"Rate-limit SATISFATÓRIO: HTTP 429 após {first_429_at} requisições (Retry-After={retry_after or 'ausente'}; headers={rl_headers or 'nenhum'}).",
                            identity.key, severity="info", verification_status="confirmed",
                            evidence_extra={"rate_limit": "enforced", "trips_at": first_429_at, "retry_after": retry_after, "headers": rl_headers, "burst": burst}))
                    elif rl_headers:
                        findings.append(_finding(
                            skill, ep.url,
                            f"Rate-limit sinalizado por headers ({rl_headers}) em {total} requisições, mas SEM 429 no burst — verificar limiar.",
                            identity.key, severity="low", verification_status="confirmed",
                            evidence_extra={"rate_limit": "headers_only", "headers": rl_headers, "burst": burst, "codes_sample": codes[:8]}))
                    elif total >= min(burst, 10):
                        findings.append(_finding(
                            skill, ep.url,
                            f"Rate-limit NÃO SATISFATÓRIO: {total} requisições sem 429 e sem headers de rate-limit (status repetido {codes[:1]}). Controle ausente/ineficaz nesta rota.",
                            identity.key, severity="medium", verification_status="confirmed",
                            evidence_extra={"rate_limit": "absent", "burst": burst, "status_seen": sorted(set(codes))}))
                    continue
                if skill_id == "skill.api.tenant_isolation":
                    # GENERIC multi-tenant isolation (any API): find every scoping
                    # variable present on the request — header, path or query whose
                    # name implies tenancy/ownership (_is_scoping_var) — establish a
                    # baseline, then SWAP each scoping var for other values and check
                    # whether the API still serves equivalent data. Hard rule:
                    # positive requires baseline 2xx AND swapped 2xx with similar
                    # body; 401/403 on swap => control OK; no 2xx baseline => advisory.
                    method = _probe_method(skill, ep)
                    scope_hdrs = [k for k in (identity.headers or {}) if _is_scoping_var(k)]
                    scope_path = [ph for ph in _path_placeholder_names(urlparse(ep.url).path) if _is_scoping_var(ph)]
                    scope_query = [str(p.get("name")) for p in ep.parameters if str(p.get("location")) == "query" and _is_scoping_var(str(p.get("name")))]
                    q_existing = dict(parse_qsl(urlparse(ep.url).query, keep_blank_values=True))
                    scope_query += [k for k in q_existing if _is_scoping_var(k) and k not in scope_query]
                    if not (scope_hdrs or scope_path or scope_query):
                        continue  # no scoping variable on this endpoint
                    attempts += 1
                    base = _request(session, method, ep.url, identity, timeout=timeout)
                    observations.append(_response_observation(skill, ep, identity, method, base))
                    bresp = base.get("response")
                    bsc = int(getattr(bresp, "status_code", 0) or 0) if bresp is not None else 0
                    bbody = base.get("response_body") or (getattr(bresp, "text", "") if bresp is not None else "")
                    others = ["00000000-0000-0000-0000-000000000000", "1", "2", "99999", _SAMPLE_UUID]
                    # (variable, location, swap-builder) across all scoping surfaces
                    swaps: list[tuple[str, str]] = [(h, "header") for h in scope_hdrs] + [(p, "path") for p in scope_path] + [(q, "query") for q in scope_query]
                    reported = False
                    for var, loc in swaps[:4]:
                        if reported:
                            break
                        for other in others[:3]:
                            attempts += 1
                            if loc == "header":
                                sw = _request(session, method, ep.url, identity, headers={var: other}, timeout=timeout)
                            elif loc == "path":
                                sw = _request(session, method, _fill_path_placeholder(ep.url, var, other), identity, timeout=timeout)
                            else:  # query
                                pr = urlparse(ep.url); qd = dict(q_existing); qd[var] = other
                                swurl = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(qd), pr.fragment))
                                sw = _request(session, method, swurl, identity, timeout=timeout)
                            observations.append(_response_observation(skill, ep, identity, method, sw))
                            sresp = sw.get("response")
                            ssc = int(getattr(sresp, "status_code", 0) or 0) if sresp is not None else 0
                            sbody = sw.get("response_body") or (getattr(sresp, "text", "") if sresp is not None else "")
                            if 200 <= bsc < 300 and 200 <= ssc < 300 and _body_similarity(bbody, sbody) >= 0.6:
                                extra = _response_evidence(sw, method)
                                extra.update({"scoping_var": var, "location": loc, "swapped_to": other, "baseline_status": bsc, "cross_tenant": True})
                                findings.append(_finding(skill, ep.url, f"Isolamento FALHOU: trocar {loc} '{var}' por {other} ainda retornou {ssc} com dados equivalentes — acesso cross-tenant (OWASP API5/API1).", identity.key, severity="critical", verification_status="confirmed", evidence_extra=extra))
                                reported = True
                                break
                        if not (200 <= bsc < 300):
                            findings.append(_finding(skill, ep.url, f"Isolamento: sem baseline autenticado (HTTP {bsc}) — não confirmável sem credencial; variáveis de escopo detectadas: {[v for v,_ in swaps]}.", identity.key, severity="info", verification_status="advisory"))
                            reported = True
                    continue
                if skill_id == "skill.api.schema_fuzzing":
                    for (fmethod, furl, fbody, label) in _fuzz_cases(ep, allow_mutations, test_variables):
                        attempts += 1
                        result = _request(session, fmethod, furl, identity, json_body=fbody, timeout=timeout)
                        obs = _response_observation(skill, ep, identity, fmethod, result)
                        obs["fuzz_case"] = label
                        observations.append(obs)
                        resp = result.get("response")
                        if resp is None:
                            continue
                        sc = int(resp.status_code)
                        rbody = (resp.text or "")[:8000]
                        if label.startswith("body:bypass") or label.startswith("body:only-flags") or label.startswith("body:optin"):
                            if 200 <= sc < 300:
                                extra = _response_evidence(result, fmethod)
                                extra.update({"fuzz_case": label, "http_status": sc})
                                findings.append(_finding(skill, ep.url, f"Entrada incompleta com flag de bypass ({label}) foi ACEITA (HTTP {sc}) — possível bypass de validação/regra de negócio (ex.: optIn:true sem imagem; OWASP API6/API3).", identity.key, severity="high", verification_status="confirmed", evidence_extra=extra))
                            continue
                        if sc >= 500:
                            extra = _response_evidence(result, fmethod)
                            extra.update({"fuzz_case": label, "http_status": sc})
                            findings.append(_finding(skill, ep.url, f"Entrada malformada ({label}) resultou em HTTP {sc} — validação de input ausente/fraca.", identity.key, severity="medium", verification_status="confirmed", evidence_extra=extra))
                        elif SQL_ERROR_RE.search(rbody) or NOSQL_ERROR_RE.search(rbody) or SHELL_ERROR_RE.search(rbody) or STACKTRACE_RE.search(rbody):
                            extra = _response_evidence(result, fmethod)
                            extra.update({"fuzz_case": label})
                            findings.append(_finding(skill, ep.url, f"Fuzz ({label}) disparou erro/stack trace na resposta.", identity.key, severity="high", verification_status="confirmed", evidence_extra=extra))
                    # Header fuzzing (analisar TUDO: path/query/body JÁ cobertos acima;
                    # aqui os headers declarados recebem valores malformados/injeção).
                    try:
                        from app.services.api_fuzz_generator import fuzz_values_for_param as _fv
                    except Exception:
                        _fv = None
                    header_params = [p for p in ep.parameters if str(p.get("location")) == "header" and p.get("name")]
                    for hp in header_params[:6]:
                        hn = str(hp.get("name"))
                        vals = (_fv(hp, cap=8) if _fv else [(p, "hdr") for p in _FUZZ_QUERY_PAYLOADS])
                        for value, label in [(v, l) for (v, l) in vals if not str(l).startswith(("valid", "idor"))][:4]:
                            method = _probe_method(skill, ep)
                            attempts += 1
                            result = _request(session, method, ep.url, identity, headers={hn: str(value)}, timeout=timeout)
                            obs = _response_observation(skill, ep, identity, method, result)
                            obs["fuzz_case"] = f"header:{hn}:{label}"
                            observations.append(obs)
                            resp = result.get("response")
                            if resp is None:
                                continue
                            sc = int(resp.status_code)
                            rbody = (resp.text or "")[:8000]
                            if sc >= 500 or SQL_ERROR_RE.search(rbody) or NOSQL_ERROR_RE.search(rbody) or SHELL_ERROR_RE.search(rbody) or STACKTRACE_RE.search(rbody):
                                extra = _response_evidence(result, method)
                                extra.update({"fuzz_case": f"header:{hn}:{label}", "http_status": sc})
                                findings.append(_finding(skill, ep.url, f"Header '{hn}' com valor malformado ({label}) causou HTTP {sc}/erro — validação de header ausente.", identity.key, severity="medium", verification_status="confirmed", evidence_extra=extra))
                    continue
                if skill_id == "skill.api.bola_idor" and ep.documented and _object_id_params(ep):
                    id_params = _object_id_params(ep)
                    guessable = _guessable_identifier(id_params)
                    is_template = "{" in ep.url
                    method = _probe_method(skill, ep)
                    attempts += 1
                    result = _request(session, method, ep.url, identity, timeout=timeout)
                    observations.append(_response_observation(skill, ep, identity, method, result))
                    resp = result.get("response")
                    sc = int(resp.status_code) if resp is not None else 0
                    if is_template:
                        # Advisory on the access-control model (one per logical
                        # endpoint): object reached only by its identifier, no
                        # owner check — the pattern the DevOps team flagged.
                        note = (
                            f"Acesso ao objeto depende apenas do identificador de path ({', '.join(id_params)}) — "
                            "sem verificação de dono (BOLA / OWASP API1). "
                            + ("O identificador é atribuído pelo cliente e tende a ser sequencial/adivinhável "
                               "(ex.: 'order-12345'), permitindo enumeração por um atacante."
                               if guessable else
                               "Se o identificador da transação vazar ou for previsível, outro chamador "
                               "lê/submete dados do processo que não lhe pertence.")
                        )
                        extra = _response_evidence(result, method)
                        extra.update({
                            "object_id_params": id_params,
                            "guessable_identifier": guessable,
                            "access_control_model": "identifier_only",
                            "advisory": True,
                            "confirmation": "NÃO confirma acesso indevido — é um risco de design (modelo de acesso por ID). Para confirmar BOLA é preciso um ID válido de outro dono retornar 200 com dados.",
                        })
                        # Advisory de design, NÃO um achado positivo: severidade
                        # informativa e verification_status=advisory (o relatório
                        # separa de achados confirmados; não conta como "achado BAC").
                        findings.append(_finding(skill, ep.url, "Modelo de acesso por identificador (revisar BOLA): " + note, identity.key, severity="info", verification_status="advisory", evidence_extra=extra))
                    elif resp is not None and sc not in (0, 401, 403, 404):
                        # Concrete enumerated identifier returned data without an
                        # owner check -> active BOLA confirmation.
                        extra = _response_evidence(result, method)
                        extra.update({"enumerated_value": ep.metadata.get("enumeration_candidate"), "http_status": sc})
                        findings.append(_finding(skill, ep.url, f"Objeto acessível por identificador enumerado (HTTP {sc}) sem autorização de dono — BOLA confirmado por enumeração.", identity.key, severity=("high" if guessable else "medium"), verification_status=("confirmed" if sc == 200 else "candidate"), evidence_extra=extra))
                    continue
                method = _probe_method(skill, ep)
                attempts += 1
                baseline = _request(session, method, ep.url, identity, timeout=timeout)
                observations.append(_response_observation(skill, ep, identity, method, baseline))
                response = baseline.get("response")
                body = response.text if response is not None else ""
                status_code = int(response.status_code) if response is not None else 0
                if identity.key == "anonymous" and skill.get("requires_authorization"):
                    exposure = _anonymous_exposure_finding(skill, ep, baseline, method)
                    if exposure:
                        findings.append(exposure)
                    continue
                if skill_id == "skill.api.broken_authentication" and response is not None and status_code == 200 and any(token in ep.url.lower() for token in ("/me", "profile", "account", "userinfo")):
                    findings.append(_finding(skill, ep.url, "Endpoint sensível retornou 200 sem autenticação.", identity.key, evidence_extra=_response_evidence(baseline, method)))
                elif skill_id in {"skill.api.sensitive_data_exposure", "skill.api.bopla"} and response is not None and status_code == 200:
                    fields: set[str] = set()
                    try:
                        fields = _extract_json_field_names(response.json())
                    except Exception:
                        fields = set()
                    sensitive_fields = sorted(field for field in fields if SENSITIVE_RE.search(field))
                    if sensitive_fields:
                        extra = _response_evidence(baseline, method)
                        extra.update({"sensitive_fields": sensitive_fields[:30]})
                        findings.append(_finding(skill, ep.url, f"Resposta expõe campos sensíveis: {', '.join(sensitive_fields[:12])}.", identity.key, verification_status="confirmed", evidence_extra=extra))
                    elif SENSITIVE_RE.search(body[:8000]):
                        findings.append(_finding(skill, ep.url, "Resposta contém padrão sensível ou stack trace.", identity.key, verification_status="candidate", evidence_extra=_response_evidence(baseline, method)))
                elif skill_id in {"skill.api.sql_injection", "skill.api.command_injection", "skill.api.ssrf"} and response is not None and ep.parameters:
                    payload = str((skill.get("payloads") or ["'"])[0])
                    mutated = _replace_first_query_value(ep.url, payload)
                    if mutated:
                        attempts += 1
                        probe = _request(session, "GET", mutated, identity, timeout=timeout)
                        observations.append(_response_observation(skill, ep, identity, "GET", probe))
                        probe_response = probe.get("response")
                        probe_body = probe_response.text if probe_response is not None else ""
                        if skill_id == "skill.api.sql_injection" and SQL_ERROR_RE.search(probe_body[:8000]):
                            extra = _response_evidence(probe, "GET")
                            extra.update({"payload": payload})
                            findings.append(_finding(skill, ep.url, "Payload SQL benigno disparou erro de banco na resposta.", identity.key, verification_status="confirmed", evidence_extra=extra))
                        elif skill_id == "skill.api.command_injection" and SHELL_ERROR_RE.search(probe_body[:8000]):
                            extra = _response_evidence(probe, "GET")
                            extra.update({"payload": payload})
                            findings.append(_finding(skill, ep.url, "Separador de comando gerou erro de shell/comando.", identity.key, verification_status="confirmed", evidence_extra=extra))
                        elif skill_id == "skill.api.ssrf" and probe_response is not None and probe_response.status_code < 400 and any(token in probe_body.lower() for token in ("fetch", "connect", "resolve", "callback", "webhook")):
                            extra = _response_evidence(probe, "GET")
                            extra.update({"payload": payload})
                            findings.append(_finding(skill, ep.url, "Parâmetro de URL aceitou payload externo sem rejeição explícita.", identity.key, evidence_extra=extra))
                elif skill_id == "skill.api.nosql_injection" and response is not None and ep.parameters:
                    mutated = _replace_first_query_value(ep.url, "1", str((skill.get("payloads") or ["[$ne]"])[0]))
                    if mutated:
                        attempts += 1
                        probe = _request(session, "GET", mutated, identity, timeout=timeout)
                        observations.append(_response_observation(skill, ep, identity, "GET", probe))
                        probe_response = probe.get("response")
                        probe_body = probe_response.text if probe_response is not None else ""
                        if NOSQL_ERROR_RE.search(probe_body[:8000]):
                            extra = _response_evidence(probe, "GET")
                            extra.update({"payload": mutated})
                            findings.append(_finding(skill, ep.url, "Operador NoSQL benigno disparou erro de parser/query.", identity.key, verification_status="confirmed", evidence_extra=extra))
                elif skill_id in {"skill.api.bfla_privilege_escalation", "skill.api.file_upload_content_handling", "skill.api.xxe_xml_parser", "skill.api.mass_assignment", "skill.api.business_logic_abuse", "skill.api.replay_idempotency"} and response is not None:
                    if status_code in {200, 204} and any(token in ep.url.lower() for token in ("admin", "internal", "upload", "xml", "soap", "approve", "payment", "role")):
                        findings.append(_finding(skill, ep.url, f"Superfície sensível respondeu HTTP {status_code}; requer fixture/identidade para confirmação.", identity.key, verification_status="candidate", evidence_extra=_response_evidence(baseline, method)))
                elif skill_id == "skill.api.oauth_oidc_security" and response is not None:
                    text = body[:12000].lower()
                    if status_code == 200 and ("openid" in text or "issuer" in text or "jwks_uri" in text) and ("pkce" not in text and "code_challenge" not in text):
                        findings.append(_finding(skill, ep.url, "Metadado OAuth/OIDC não evidencia PKCE/code_challenge.", identity.key, evidence_extra=_response_evidence(baseline, method)))
    return {
        "status": "completed",
        "selected": selected_count,
        "selected_endpoint_count": selected_count,
        "matched_endpoint_count": matched_count,
        "skipped_endpoint_count": max(0, matched_count - selected_count),
        "coverage_complete": selected_count >= matched_count,
        "coverage_gap_reason": None if selected_count >= matched_count else "endpoint_limit_reached",
        "attempts": attempts,
        "request_limit": None,
        "blocked_reason": ",".join(sorted(blocked_reasons)) or None,
        "findings": findings,
        "observations": observations,
    }


def _shadow_api_findings(skill: dict[str, Any], endpoints: list[Endpoint]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    # Templates que JÁ estão no contrato (spec/collection). Um path só é "shadow"
    # se NÃO casar com nenhum template documentado — ex.: /dead-letters/{id}/replay
    # é documentado, então /dead-letters/42/replay (concreto) não é shadow.
    documented_templates = {
        _path_template_key(urlparse(ep.url).path)
        for ep in endpoints
        if ep.documented
    }
    seen_templates: set[str] = set()
    for ep in endpoints:
        if ep.documented:
            continue
        path = urlparse(ep.url).path
        tkey = _path_template_key(path)
        if tkey in documented_templates:
            continue  # casa com um template do próprio spec → não é shadow
        if tkey in seen_templates:
            continue  # evita duplicar o mesmo template concretizado em várias variantes
        plow = path.lower()
        if any(token in plow for token in ("/v0", "/v1", "/old", "/legacy", "/beta", "/internal", "/private", "/debug", "/admin")):
            seen_templates.add(tkey)
            findings.append(_finding(skill, ep.url, f"Endpoint de API observado fora do contrato documentado: {path}.", "anonymous", severity=str((skill.get("finding") or {}).get("severity") or "medium")))
    return findings


def run_api_top20_for_scan(scan_id: int, target: str, *, api_skill_id: str | None = None) -> dict[str, Any]:
    from app.db.session import SessionLocal

    db = SessionLocal()
    started = time.time()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == int(scan_id)).first()
        if not job:
            return {"status": "error", "error": "scan_not_found", "exit_code": 1}
        state = dict(job.state_data or {})
        api_config = dict(state.get("api_scan_config") or {})
        catalog = load_api_top20_skills()
        skills = [dict(item) for item in list(catalog.get("skills") or [])]
        if api_skill_id:
            skills = [skill for skill in skills if str(skill.get("id") or "") == str(api_skill_id)]
        scope = authorized_scope_for_scan(db, job.id)
        test_headers = {str(k): str(v) for k, v in (api_config.get("test_headers") or {}).items()}
        test_variables = {str(k): v for k, v in (api_config.get("test_variables") or {}).items()}
        endpoints = _expand_templated_endpoints(_collect_endpoints(db, job, scope), test_variables)
        identities = _collect_identities(db, job)
        # Header variables (x-api-key, x-organization-id, x-project-id, ...) are
        # applied to EVERY request of EVERY identity — passam o gate de auth.
        if test_headers:
            for _idn in identities:
                _idn.headers = {**(_idn.headers or {}), **test_headers}
        reused_inventory_scan_ids = sorted({
            int(ep.metadata.get("reused_from_scan_id"))
            for ep in endpoints
            if ep.metadata.get("reused_from_scan_id")
        })
        ingestion = dict(api_config.get("ingestion") or {})
        inventory_source = "reused_api_spec_snapshot" if reused_inventory_scan_ids else "current_scan_inventory"
        spec_fallback_reason = ""
        if reused_inventory_scan_ids and ingestion.get("ok") is False:
            spec_fallback_reason = "api_spec_unavailable_using_previous_inventory"
        limits = dict(catalog.get("default_limits") or {})
        allow_mutations = bool(api_config.get("allow_mutations"))
        # Route all probes through a headless Caido (traffic/replay engine) when
        # the scan opted in and Caido is reachable; otherwise direct requests.
        global _CAIDO_CLIENT, _RATE_LIMIT_BURST
        _CAIDO_CLIENT = None
        _RATE_LIMIT_BURST = int(api_config.get("rate_limit_burst") or 30)
        caido_status = {"enabled": False, "detail": "not_configured"}
        try:
            from app.services.caido_client import get_caido_client_for_config
            _client = get_caido_client_for_config(api_config)
            if _client is not None:
                _CAIDO_CLIENT = _client
                caido_status = {"enabled": True, "detail": "caido_replay", "instance": _client.base_url}
        except Exception as _cexc:  # noqa: BLE001
            caido_status = {"enabled": False, "detail": f"caido_init_failed: {type(_cexc).__name__}"}
        all_findings: list[dict[str, Any]] = []
        all_observations: list[dict[str, Any]] = []
        skill_results: list[dict[str, Any]] = []
        if not endpoints:
            return {
                "status": "blocked",
                "exit_code": 0,
                "error": "api_endpoint_inventory_empty",
                "parsed": {"skills_total": len(skills), "endpoint_count": 0, "blocked_precondition": "api_endpoint_inventory_empty"},
                "findings_extracted": [],
            }
        for skill in skills:
            if str(skill.get("id")) == "skill.api.business_flow_fraud_bypass":
                continue  # handled by the dedicated stateful flow runner below
            if str(skill.get("id")) == "skill.api.inventory_shadow_api":
                # Descoberta ATIVA de rotas (kiterunner): acha endpoints fora da
                # spec/collection enviada. O BOLA do DevOps é um shadow endpoint.
                discovered: list[Endpoint] = []
                try:
                    with requests.Session() as _ds:
                        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
                        discovered = _discover_shadow_routes(_ds, endpoints, identities, scope)
                except Exception:
                    discovered = []
                if discovered:
                    try:
                        from app.services.offensive_inventory_service import OffensiveInventoryService
                        inv = OffensiveInventoryService(db, job)
                        for sep in discovered:
                            try:
                                inv.upsert_endpoint(sep.url, method="GET", source_tool="route-brute", tags=["api", "shadow"], metadata=dict(sep.metadata))
                            except Exception:
                                continue
                        db.flush()
                    except Exception:
                        pass
                findings = _shadow_api_findings(skill, endpoints + discovered)
                for sep in discovered:
                    findings.append(_finding(
                        skill, sep.url,
                        f"Rota de API NÃO documentada descoberta por brute de rotas (HTTP {sep.metadata.get('probe_status')}): {urlparse(sep.url).path}. "
                        "Está fora da spec/collection enviada — superfície shadow; revisar autorização/BOLA.",
                        "anonymous", severity="medium", verification_status="confirmed",
                        evidence_extra={"discovered_via": "route_brute", "probe_status": sep.metadata.get("probe_status"), "shadow_api": True},
                    ))
                result = {"status": "completed", "selected": len(endpoints) + len(discovered), "attempts": len(discovered), "findings": findings}
            else:
                result = _run_endpoint_skill(skill, endpoints, identities, limits, allow_mutations, test_variables)
            all_findings.extend(result.get("findings") or [])
            all_observations.extend(result.get("observations") or [])
            skill_results.append({
                "skill_id": skill.get("id"),
                "name": skill.get("name"),
                "priority": skill.get("priority"),
                "status": result.get("status"),
                "selected_endpoints": result.get("selected", 0),
                "matched_endpoint_count": result.get("matched_endpoint_count", result.get("selected", 0)),
                "skipped_endpoint_count": result.get("skipped_endpoint_count", 0),
                "coverage_complete": bool(result.get("coverage_complete", True)),
                "coverage_gap_reason": result.get("coverage_gap_reason"),
                "attempts": result.get("attempts", 0),
                "request_limit": result.get("request_limit"),
                "findings": len(result.get("findings") or []),
                "blocked_reason": result.get("blocked_reason"),
            })

        # Stateful business-logic flow (onboarding incident): create -> harvest
        # requestId -> fraud optIn-without-image (API6) -> result BOLA cross-identity
        # (API1). Runs when the skill is in the catalog and mutations are allowed.
        flow_lineage: list[dict[str, Any]] = []
        flow_dynamic = False
        flow_steps: list[dict[str, Any]] = []
        _bf_skill = next((s for s in skills if str(s.get("id")) == "skill.api.business_flow_fraud_bypass"), None)
        if _bf_skill is not None:
            try:
                from app.services.api_flow_runner import VariableStore, run_business_flow
                with requests.Session() as _bfsess:
                    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

                    def _bf_request(method, url, identity, *, headers=None, json_body=None, timeout=DEFAULT_TIMEOUT_SECONDS):
                        return _request(_bfsess, method, url, identity, headers=headers, json_body=json_body, timeout=timeout)

                    _store = VariableStore(seed=test_variables)
                    _bf = run_business_flow(endpoints, identities, _bf_request, _store,
                                            allow_mutations=allow_mutations, skill=_bf_skill, make_finding=_finding)
                all_findings.extend(_bf.get("findings") or [])
                flow_lineage = _bf.get("variables") or []
                flow_dynamic = bool(_bf.get("dynamic_executed"))
                flow_steps = _bf.get("steps") or []
                skill_results.append({
                    "skill_id": _bf_skill.get("id"), "name": _bf_skill.get("name"),
                    "priority": _bf_skill.get("priority"),
                    "status": "completed" if flow_dynamic else "blocked",
                    "selected_endpoints": len(flow_steps), "attempts": len(flow_steps),
                    "coverage_complete": True, "coverage_gap_reason": None,
                    "findings": len(_bf.get("findings") or []),
                    "blocked_reason": _bf.get("skipped"),
                })
            except Exception as _bfexc:  # noqa: BLE001
                skill_results.append({"skill_id": "skill.api.business_flow_fraud_bypass", "status": "error",
                                      "blocked_reason": type(_bfexc).__name__, "findings": 0,
                                      "coverage_complete": True})
        parsed = {
            "scan_type": "api_skill_top20",
            "target": target,
            "catalog_id": catalog.get("catalog_id"),
            "catalog_version": catalog.get("version"),
            "catalog_path": catalog.get("catalog_path"),
            "skills_total": len(skills),
            "endpoint_count": len(endpoints),
            "identity_count": len(identities),
            "execution_contexts": [identity.key for identity in identities],
            "allow_mutations": allow_mutations,
            "api_spec_ingestion": ingestion,
            "inventory_source": inventory_source,
            "reused_inventory_scan_ids": reused_inventory_scan_ids,
            "spec_fallback_reason": spec_fallback_reason,
            "skill_results": skill_results,
            "endpoint_coverage_complete": all(bool(item.get("coverage_complete", True)) for item in skill_results),
            "endpoint_coverage_gaps": [
                {
                    "skill_id": item.get("skill_id"),
                    "matched_endpoint_count": item.get("matched_endpoint_count"),
                    "selected_endpoints": item.get("selected_endpoints"),
                    "skipped_endpoint_count": item.get("skipped_endpoint_count"),
                    "coverage_gap_reason": item.get("coverage_gap_reason"),
                }
                for item in skill_results
                if not bool(item.get("coverage_complete", True))
            ],
            "finding_count": len(all_findings),
            "response_observation_count": len(all_observations),
            "response_observations": all_observations[:300],
            "anonymous_exposure_candidates": len([
                finding for finding in all_findings
                if dict(finding.get("details") or {}).get("anonymous_access") is True
            ]),
            "duration_seconds": round(time.time() - started, 3),
        }
        # Flow/Caido metadata. The static flow graph + attack-paths are recomputed
        # (cleanly, from the deduped DB inventory) by build_api_endpoint_report;
        # here we carry Caido transport status and a placeholder for dynamic
        # variable lineage (filled once the stateful flow runner executes).
        try:
            from app.services.api_flow_graph import build_flow_graph
            _fg = build_flow_graph([
                {"method": ep.method, "url": ep.url, "parameters": ep.parameters,
                 "tags": ep.tags, "documented": ep.documented, "metadata": ep.metadata}
                for ep in endpoints
            ])
            _flow_stats = _fg.get("stats", {})
            _external_vars = _fg.get("external_variables", [])
        except Exception:
            _flow_stats, _external_vars = {}, []
        parsed["api_flow"] = {
            "caido": caido_status,
            "caido_project": caido_status.get("instance", ""),
            "dynamic_executed": flow_dynamic,
            "variables": flow_lineage,
            "flow_steps": flow_steps,
            "external_variables": _external_vars,
            "graph_stats": _flow_stats,
        }
        return {
            "status": "success",
            "exit_code": 0,
            "tool": "api-skill-top20",
            "target": target,
            "stdout": json.dumps(parsed, ensure_ascii=False, sort_keys=True),
            "parsed": parsed,
            "findings_extracted": all_findings,
            "findings": all_findings,
        }
    finally:
        db.close()
