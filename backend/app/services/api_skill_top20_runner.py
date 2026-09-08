from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
import yaml

from app.models.models import Finding, ObservedRequest, OffensiveEndpoint, OffensiveParameter, ScanJob
from app.services.offensive_inventory_service import normalize_url
from app.services.scan_scope import authorized_scope_for_scan, is_host_in_scope


DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_REQUESTS_HARD_CAP = 5000
MAX_BODY_CHARS = 160_000
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
STATIC_RE = re.compile(r"\.(?:js|css|png|jpe?g|gif|svg|woff2?|ico|map|webp|pdf)(?:\?|$)", re.I)
API_RE = re.compile(r"(/api/|/rest/|/v\d+/|/graphql|/gql|swagger|openapi)", re.I)
SQL_ERROR_RE = re.compile(r"(sql syntax|mysql|postgres|ora-\d+|sqlite|odbc|jdbc|unterminated quoted|string literal)", re.I)
NOSQL_ERROR_RE = re.compile(r"(MongoError|BSONError|CastError|MongooseError|\$where|E11000|querySelector)", re.I)
SHELL_ERROR_RE = re.compile(r"(sh:|bash:|cmd\.exe|PowerShell|syntax error near unexpected token|command not found)", re.I)
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


def _request(session: requests.Session, method: str, url: str, identity: Identity, *, headers: dict[str, str] | None = None, json_body: Any = None, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    req_headers = {"User-Agent": "ValidCyber-API-SkillTop20/1.0", "Accept": "application/json, text/plain, */*"}
    req_headers.update(identity.headers or {})
    req_headers.update(headers or {})
    try:
        response = session.request(method.upper(), url, headers=req_headers, cookies=identity.cookies or {}, json=json_body, timeout=timeout, allow_redirects=False, verify=False)
        return {"ok": True, "response": response, "fingerprint": _fingerprint(response)}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:300]}


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


def _run_endpoint_skill(skill: dict[str, Any], endpoints: list[Endpoint], identities: list[Identity], limits: dict[str, Any], allow_mutations: bool) -> dict[str, Any]:
    configured_max_endpoints = int(limits.get("max_endpoints_per_skill") or 0)
    configured_max_requests = int(limits.get("max_requests_per_skill") or 0)
    hard_cap = int(limits.get("max_requests_hard_cap") or DEFAULT_MAX_REQUESTS_HARD_CAP)
    max_endpoints = configured_max_endpoints
    max_requests = configured_max_requests if configured_max_requests > 0 else hard_cap
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
            "request_limit": max_requests,
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
            if attempts >= max_requests:
                blocked_reasons.add("request_limit_reached")
                break
            skill_id = str(skill.get("id") or "")
            active_identities = identities if skill.get("requires_authorization") else identities[:1]
            for identity in active_identities:
                if attempts >= max_requests:
                    blocked_reasons.add("request_limit_reached")
                    break
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
                    codes = []
                    header_names: set[str] = set()
                    for _ in range(int(skill.get("max_repeated_requests") or 3)):
                        if attempts >= max_requests:
                            blocked_reasons.add("request_limit_reached")
                            break
                        method = _probe_method(skill, ep)
                        attempts += 1
                        result = _request(session, method, ep.url, identity, timeout=timeout)
                        observations.append(_response_observation(skill, ep, identity, method, result))
                        response = result.get("response")
                        if response is not None:
                            codes.append(response.status_code)
                            header_names.update(k.lower() for k in response.headers)
                    if len(codes) >= 3 and all(code < 400 for code in codes) and not header_names.intersection(RATE_LIMIT_HEADERS):
                        findings.append(_finding(skill, ep.url, f"{len(codes)} requisições repetidas sem headers de rate limit; códigos={codes}.", identity.key, severity="medium"))
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
                    if mutated and attempts < max_requests:
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
                    if mutated and attempts < max_requests:
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
        "coverage_complete": selected_count >= matched_count and "request_limit_reached" not in blocked_reasons,
        "coverage_gap_reason": "request_limit_reached" if "request_limit_reached" in blocked_reasons else (None if selected_count >= matched_count else "endpoint_limit_reached"),
        "attempts": attempts,
        "request_limit": max_requests,
        "blocked_reason": ",".join(sorted(blocked_reasons)) or None,
        "findings": findings,
        "observations": observations,
    }


def _shadow_api_findings(skill: dict[str, Any], endpoints: list[Endpoint]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for ep in endpoints:
        path = urlparse(ep.url).path.lower()
        if ep.documented:
            continue
        if any(token in path for token in ("/v0", "/v1", "/old", "/legacy", "/beta", "/internal", "/private", "/debug", "/admin")):
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
        endpoints = _collect_endpoints(db, job, scope)
        identities = _collect_identities(db, job)
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
            if str(skill.get("id")) == "skill.api.inventory_shadow_api":
                findings = _shadow_api_findings(skill, endpoints)
                result = {"status": "completed", "selected": len(endpoints), "attempts": 0, "findings": findings}
            else:
                result = _run_endpoint_skill(skill, endpoints, identities, limits, allow_mutations)
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
