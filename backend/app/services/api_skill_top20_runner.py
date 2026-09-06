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


def _collect_endpoints(db: Any, job: ScanJob, scope: list[str]) -> list[Endpoint]:
    rows: dict[tuple[str, str], Endpoint] = {}
    param_rows = (
        db.query(OffensiveParameter)
        .filter(OffensiveParameter.scan_job_id == job.id)
        .limit(5000)
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
    for ep in (
        db.query(OffensiveEndpoint)
        .filter(OffensiveEndpoint.scan_job_id == job.id)
        .order_by(OffensiveEndpoint.id.asc())
        .limit(2000)
        .all()
    ):
        url = str(ep.url or "")
        if not url.startswith(("http://", "https://")) or STATIC_RE.search(url) or not _host_allowed(url, scope):
            continue
        method = str(ep.method or "GET").upper()
        key = (method, normalize_url(url))
        documented = str(ep.source_tool or "").lower() in {"api-spec", "openapi", "swagger", "graphql-spec"}
        rows[key] = Endpoint(
            method=method,
            url=url,
            normalized_url=key[1],
            parameters=by_endpoint.get(int(ep.id), []) + _params_from_url(url),
            tags=[str(tag).lower() for tag in list(ep.tags or [])],
            source_tool=str(ep.source_tool or ""),
            documented=documented,
            metadata=dict(ep.endpoint_metadata or {}),
        )
    for req in (
        db.query(ObservedRequest)
        .filter(ObservedRequest.scan_job_id == job.id)
        .order_by(ObservedRequest.id.asc())
        .limit(2000)
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
    state = dict(job.state_data or {})
    for raw in list(state.get("discovered_endpoints") or []) + list(state.get("internal_discovered_endpoints") or []):
        url = str(raw or "")
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
        if safe_methods and ep.method.upper() not in safe_methods:
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
        if len(selected) >= limit:
            break
    if selected:
        return selected
    fallback = [ep for ep in endpoints if API_RE.search(ep.url) and (not safe_methods or ep.method.upper() in safe_methods)]
    return fallback[:limit]


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
    max_endpoints = int(limits.get("max_endpoints_per_skill") or 30)
    max_requests = int(limits.get("max_requests_per_skill") or 60)
    timeout = int(limits.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
    selected = _select_endpoints(skill, endpoints, max_endpoints)
    if skill.get("local_analysis"):
        findings = _decoded_jwt_findings(skill, identities, selected[0].url if selected else "")
        return {"status": "completed", "selected": len(selected), "attempts": 0, "findings": findings}
    if skill.get("mutating_confirmation_requires_fixture") and not allow_mutations:
        return {"status": "skipped", "selected": len(selected), "attempts": 0, "blocked_reason": "mutation_fixture_or_allow_mutations_required", "findings": []}

    findings: list[dict[str, Any]] = []
    attempts = 0
    with requests.Session() as session:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        for ep in selected:
            if attempts >= max_requests:
                break
            skill_id = str(skill.get("id") or "")
            active_identities = identities if skill.get("requires_authorization") else identities[:1]
            if skill.get("requires_two_identities_for_confirmation") and len(identities) < 3:
                return {"status": "skipped", "selected": len(selected), "attempts": attempts, "blocked_reason": "second_identity_required", "findings": []}
            for identity in active_identities:
                if identity.key == "anonymous" and skill.get("requires_authorization"):
                    continue
                if attempts >= max_requests:
                    break
                if skill_id == "skill.api.cors_misconfiguration":
                    attempts += 1
                    result = _request(session, "OPTIONS" if ep.method != "GET" else "GET", ep.url, identity, headers={"Origin": "https://attacker.example"}, timeout=timeout)
                    response = result.get("response")
                    if response is not None:
                        acao = response.headers.get("access-control-allow-origin", "")
                        acac = response.headers.get("access-control-allow-credentials", "")
                        if acao == "*" and str(acac).lower() == "true" or acao == "https://attacker.example":
                            findings.append(_finding(skill, ep.url, f"CORS permissivo: ACAO={acao!r}, ACAC={acac!r}.", identity.key, evidence_extra={"method": ep.method, "http_status": response.status_code}))
                    continue
                if skill_id == "skill.api.graphql_security":
                    attempts += 1
                    result = _request(session, "POST", ep.url, identity, json_body={"query": "query{__schema{queryType{name}}}"}, timeout=timeout)
                    response = result.get("response")
                    if response is not None and response.status_code == 200 and "__schema" in (response.text or "")[:8000]:
                        findings.append(_finding(skill, ep.url, "Introspection GraphQL habilitada e retornando schema.", identity.key, verification_status="confirmed", evidence_extra={"method": "POST", "http_status": 200}))
                    continue
                if skill_id == "skill.api.rate_limit_resource_consumption":
                    codes = []
                    header_names: set[str] = set()
                    for _ in range(int(skill.get("max_repeated_requests") or 3)):
                        attempts += 1
                        result = _request(session, ep.method if ep.method in READ_METHODS else "GET", ep.url, identity, timeout=timeout)
                        response = result.get("response")
                        if response is not None:
                            codes.append(response.status_code)
                            header_names.update(k.lower() for k in response.headers)
                    if len(codes) >= 3 and all(code < 400 for code in codes) and not header_names.intersection(RATE_LIMIT_HEADERS):
                        findings.append(_finding(skill, ep.url, f"{len(codes)} requisições repetidas sem headers de rate limit; códigos={codes}.", identity.key, severity="medium"))
                    continue
                attempts += 1
                baseline = _request(session, ep.method if ep.method in READ_METHODS else "GET", ep.url, identity, timeout=timeout)
                response = baseline.get("response")
                body = response.text if response is not None else ""
                status_code = int(response.status_code) if response is not None else 0
                if skill_id == "skill.api.broken_authentication" and response is not None and status_code == 200 and any(token in ep.url.lower() for token in ("/me", "profile", "account", "userinfo")):
                    findings.append(_finding(skill, ep.url, "Endpoint sensível retornou 200 sem autenticação.", identity.key, evidence_extra={"method": ep.method, "http_status": status_code}))
                elif skill_id in {"skill.api.sensitive_data_exposure", "skill.api.bopla"} and response is not None and status_code == 200:
                    fields: set[str] = set()
                    try:
                        fields = _extract_json_field_names(response.json())
                    except Exception:
                        fields = set()
                    sensitive_fields = sorted(field for field in fields if SENSITIVE_RE.search(field))
                    if sensitive_fields:
                        findings.append(_finding(skill, ep.url, f"Resposta expõe campos sensíveis: {', '.join(sensitive_fields[:12])}.", identity.key, verification_status="confirmed", evidence_extra={"method": ep.method, "http_status": status_code, "sensitive_fields": sensitive_fields[:30]}))
                    elif SENSITIVE_RE.search(body[:8000]):
                        findings.append(_finding(skill, ep.url, "Resposta contém padrão sensível ou stack trace.", identity.key, verification_status="candidate", evidence_extra={"method": ep.method, "http_status": status_code}))
                elif skill_id in {"skill.api.sql_injection", "skill.api.command_injection", "skill.api.ssrf"} and response is not None and ep.parameters:
                    payload = str((skill.get("payloads") or ["'"])[0])
                    mutated = _replace_first_query_value(ep.url, payload)
                    if mutated:
                        attempts += 1
                        probe = _request(session, "GET", mutated, identity, timeout=timeout)
                        probe_response = probe.get("response")
                        probe_body = probe_response.text if probe_response is not None else ""
                        if skill_id == "skill.api.sql_injection" and SQL_ERROR_RE.search(probe_body[:8000]):
                            findings.append(_finding(skill, ep.url, "Payload SQL benigno disparou erro de banco na resposta.", identity.key, verification_status="confirmed", evidence_extra={"method": "GET", "payload": payload}))
                        elif skill_id == "skill.api.command_injection" and SHELL_ERROR_RE.search(probe_body[:8000]):
                            findings.append(_finding(skill, ep.url, "Separador de comando gerou erro de shell/comando.", identity.key, verification_status="confirmed", evidence_extra={"method": "GET", "payload": payload}))
                        elif skill_id == "skill.api.ssrf" and probe_response is not None and probe_response.status_code < 400 and any(token in probe_body.lower() for token in ("fetch", "connect", "resolve", "callback", "webhook")):
                            findings.append(_finding(skill, ep.url, "Parâmetro de URL aceitou payload externo sem rejeição explícita.", identity.key, evidence_extra={"method": "GET", "payload": payload}))
                elif skill_id == "skill.api.nosql_injection" and response is not None and ep.parameters:
                    mutated = _replace_first_query_value(ep.url, "1", str((skill.get("payloads") or ["[$ne]"])[0]))
                    if mutated:
                        attempts += 1
                        probe = _request(session, "GET", mutated, identity, timeout=timeout)
                        probe_response = probe.get("response")
                        probe_body = probe_response.text if probe_response is not None else ""
                        if NOSQL_ERROR_RE.search(probe_body[:8000]):
                            findings.append(_finding(skill, ep.url, "Operador NoSQL benigno disparou erro de parser/query.", identity.key, verification_status="confirmed", evidence_extra={"method": "GET", "payload": mutated}))
                elif skill_id in {"skill.api.bfla_privilege_escalation", "skill.api.file_upload_content_handling", "skill.api.xxe_xml_parser", "skill.api.mass_assignment", "skill.api.business_logic_abuse", "skill.api.replay_idempotency"} and response is not None:
                    if status_code in {200, 204} and any(token in ep.url.lower() for token in ("admin", "internal", "upload", "xml", "soap", "approve", "payment", "role")):
                        findings.append(_finding(skill, ep.url, f"Superfície sensível respondeu HTTP {status_code}; requer fixture/identidade para confirmação.", identity.key, verification_status="candidate", evidence_extra={"method": ep.method, "http_status": status_code}))
                elif skill_id == "skill.api.oauth_oidc_security" and response is not None:
                    text = body[:12000].lower()
                    if status_code == 200 and ("openid" in text or "issuer" in text or "jwks_uri" in text) and ("pkce" not in text and "code_challenge" not in text):
                        findings.append(_finding(skill, ep.url, "Metadado OAuth/OIDC não evidencia PKCE/code_challenge.", identity.key, evidence_extra={"method": ep.method, "http_status": status_code}))
    return {"status": "completed", "selected": len(selected), "attempts": attempts, "findings": findings}


def _shadow_api_findings(skill: dict[str, Any], endpoints: list[Endpoint]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for ep in endpoints[:200]:
        path = urlparse(ep.url).path.lower()
        if ep.documented:
            continue
        if any(token in path for token in ("/v0", "/v1", "/old", "/legacy", "/beta", "/internal", "/private", "/debug", "/admin")):
            findings.append(_finding(skill, ep.url, f"Endpoint de API observado fora do contrato documentado: {path}.", "anonymous", severity=str((skill.get("finding") or {}).get("severity") or "medium")))
    return findings[:20]


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
        limits = dict(catalog.get("default_limits") or {})
        allow_mutations = bool(api_config.get("allow_mutations"))
        all_findings: list[dict[str, Any]] = []
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
            skill_results.append({
                "skill_id": skill.get("id"),
                "name": skill.get("name"),
                "priority": skill.get("priority"),
                "status": result.get("status"),
                "selected_endpoints": result.get("selected", 0),
                "attempts": result.get("attempts", 0),
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
            "skill_results": skill_results,
            "finding_count": len(all_findings),
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
