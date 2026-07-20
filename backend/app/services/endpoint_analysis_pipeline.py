"""Canonical endpoint intelligence between discovery and test execution."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, urlparse

from sqlalchemy.orm import Session

from app.models.models import OffensiveEndpoint, OffensiveParameter, ScanJob
from app.services.offensive_inventory_service import OffensiveInventoryService, parameter_risk_hint


ANALYSIS_VERSION = "endpoint-intelligence-v4"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
STATIC_EXTENSIONS = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map"}
SENSITIVE_MARKERS = {
    "admin", "internal", "manage", "console", "account", "profile", "user",
    "billing", "payment", "order", "invoice", "document", "transaction",
    "download", "export", "file", "view", "template", "log", "backup",
    "message", "transfer", "upload", "import", "email", "password",
    "accounts", "profiles", "users", "payments", "orders", "invoices",
    "documents", "transactions", "messages", "transfers", "files", "logs",
}
AUTH_MARKERS = {
    "login", "signin", "auth", "oauth", "sso", "session", "token", "logout",
    "register", "password", "otp", "mfa", "refresh", "saml",
}
API_MARKERS = {"api", "graphql", "gql", "swagger", "openapi", "api-docs"}
UPLOAD_MARKERS = {"upload", "import", "attachment", "file"}
REDIRECT_SURFACE_MARKERS = {"redirect", "callback", "return", "continue"}
SERVER_FETCH_SURFACE_MARKERS = {"proxy", "fetch", "preview", "webhook", "relay", "integrations", "image"}
FILE_DELIVERY_MARKERS = {
    "download", "export", "file", "view", "template", "image", "log", "logs",
    "backup", "invoice", "document", "documents", "report", "reports",
}
SESSION_TERMINATION_MARKERS = {"logout", "signout", "logoff"}
INPUT_SURFACE_MARKERS = {"search", "comments", "feedback", "support", "messages", "test"}
STRUCTURED_INPUT_MARKERS = {"xml", "soap", "import"}
STATE_CHANGE_CANDIDATE_MARKERS = {"update", "change", "create", "payment", "transfer", "register", "reset"}
TOKEN_LIFECYCLE_MARKERS = {"token", "refresh", "otp", "mfa"}
_OBJECT_SEGMENT = re.compile(r"/(?:\d{1,12}|[0-9a-f]{8}-[0-9a-f-]{27,}|\{id\})(?:/|$)", re.I)


def analyze_endpoint_contract(
    url: str,
    *,
    method: str = "GET",
    tags: list[str] | None = None,
    parameters: list[dict[str, Any]] | None = None,
    content_type: str = "",
) -> dict[str, Any]:
    parsed = urlparse(str(url or ""))
    path = parsed.path or "/"
    path_tokens = {token.lower() for token in re.findall(r"[A-Za-z0-9_-]+", path)}
    normalized_tags = {str(tag).strip().lower() for tag in tags or []}
    lower = f"{path} {parsed.query} {' '.join(tags or [])} {content_type}".lower()
    suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    is_static = suffix in STATIC_EXTENSIONS
    is_api = bool((path_tokens | normalized_tags) & API_MARKERS) or "json" in content_type.lower()
    is_auth = bool((path_tokens | normalized_tags) & AUTH_MARKERS)
    is_sensitive = bool((path_tokens | normalized_tags) & SENSITIVE_MARKERS)
    is_upload = bool((path_tokens | normalized_tags) & UPLOAD_MARKERS)
    is_redirect_surface = bool(path_tokens & REDIRECT_SURFACE_MARKERS)
    is_server_fetch_surface = bool(path_tokens & SERVER_FETCH_SURFACE_MARKERS)
    is_file_delivery = bool(path_tokens & FILE_DELIVERY_MARKERS)
    is_session_termination = bool(path_tokens & SESSION_TERMINATION_MARKERS)
    is_input_surface = bool(path_tokens & INPUT_SURFACE_MARKERS)
    is_structured_input = bool(path_tokens & STRUCTURED_INPUT_MARKERS)
    is_state_change_candidate = bool(path_tokens & STATE_CHANGE_CANDIDATE_MARKERS)
    is_token_lifecycle = bool(path_tokens & TOKEN_LIFECYCLE_MARKERS)
    method_state_changing = str(method or "GET").upper() not in SAFE_METHODS
    state_changing = method_state_changing or is_session_termination
    object_reference = bool(_OBJECT_SEGMENT.search(path))

    raw_parameters = list(parameters or [])
    if not raw_parameters:
        raw_parameters = [
            {"name": name, "location": "query", "sample_value": value}
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
    parameter_rows = []
    for parameter in raw_parameters:
        name = str(parameter.get("name") or "").strip()
        if not name:
            continue
        hint = str(parameter.get("risk_hint") or parameter_risk_hint(name, url) or "")
        parameter_rows.append({
            "name": name,
            "location": str(parameter.get("location") or "query"),
            "type_hint": str(parameter.get("type_hint") or _infer_type(parameter.get("sample_value"))),
            "risk_hint": hint,
            "sample_present": parameter.get("sample_value") not in {None, ""},
        })

    tests: list[dict[str, Any]] = []
    if not is_static:
        tests.append(_test("read_only_baseline", "", 40, ["read-only-validator"], [], ["request_response_pair"], "endpoint:baseline"))
    if is_auth or is_sensitive or is_api:
        test_class = "file_delivery_authorization" if is_file_delivery else "auth_requirement"
        tests.append(_test(test_class, "bfla_authz" if is_sensitive else "api_security", 72 if is_file_delivery else (68 if is_sensitive else 55), ["auth-matrix"], ["user_a", "user_b"] if is_sensitive else [], ["anonymous_vs_authenticated", "cross_identity_response"] if is_file_delivery else ["anonymous_vs_authenticated"], "endpoint:auth_boundary"))
    if object_reference:
        tests.append(_test("object_authorization", "object_reference", 82, ["idor-validator"], ["user_a", "user_b"], ["baseline_vs_exploit", "negative_control"], "path:object_reference"))
    if "graphql" in lower or "/gql" in lower:
        tests.append(_test("graphql_contract", "api_graphql", 70, ["read-only-validator", "auth-matrix"], [], ["schema_or_introspection", "auth_matrix"], "path:graphql"))
    if any(marker in lower for marker in ("swagger", "openapi", "api-docs")):
        tests.append(_test("api_spec", "api_spec_exposure", 72, ["read-only-validator", "api-spec-ingestor"], [], ["spec_parse", "endpoint_inventory"], "path:api_spec"))
    if is_upload and method_state_changing:
        tests.append(_test("upload_boundary", "business_logic_mass_assignment", 65, ["mass-assignment-validator"], ["user_a"], ["safe_precondition", "read_back"], "path:upload"))
    elif is_upload:
        tests.append(_test("upload_contract_discovery", "", 55, ["chromium-capture"], [], ["accepted_methods", "accepted_content_types"], "path:upload_surface"))
    if method_state_changing:
        tests.append(_test("state_change_authorization", "business_logic_mass_assignment", 75, ["mass-assignment-validator", "auth-matrix"], ["user_a", "user_b"], ["baseline", "read_back", "negative_control"], f"method:{str(method).upper()}"))
    if is_session_termination:
        tests.append(_test("session_termination_boundary", "", 70, ["session-invalidation-validator"], ["user_a"], ["session_before", "logout_request", "session_after"], "path:session_termination"))
    if (is_redirect_surface or is_server_fetch_surface or is_input_surface) and not parameter_rows:
        surface = "server_fetch" if is_server_fetch_surface else ("redirect" if is_redirect_surface else "input")
        validators = ["arjun", "chromium-capture"] if is_input_surface else ["arjun"]
        tests.append(_test("surface_parameter_discovery", "", 55, validators, [], ["parameter_inventory"], f"path:{surface}_surface"))
    if is_structured_input:
        tests.append(_test("structured_input_contract_discovery", "", 60, ["api-spec-ingestor", "chromium-capture"], [], ["accepted_methods", "accepted_content_types"], "path:structured_input"))
    if is_state_change_candidate and not method_state_changing:
        identities = ["user_a"] if is_sensitive else []
        tests.append(_test("state_change_method_discovery", "", 62, ["chromium-capture"], identities, ["observed_method", "csrf_token_behavior"], "path:state_change_candidate"))
    if is_token_lifecycle:
        tests.append(_test("token_lifecycle_boundary", "", 65, ["auth-matrix"], ["user_a"], ["token_before", "token_after", "replay_control"], "path:token_lifecycle"))
    for parameter in parameter_rows:
        hint = parameter["risk_hint"]
        if not hint:
            continue
        rule = _parameter_test(hint, parameter["name"], parameter["location"])
        if rule:
            tests.append(rule)

    tests = _dedupe_tests(tests)
    risk = min(100, 15 + (20 if is_api else 0) + (20 if is_sensitive else 0) + (12 if is_auth else 0) + (15 if state_changing else 0) + min(25, len([row for row in tests if row["hypothesis_type"] not in {"information_disclosure", "api_security"}]) * 5))
    return {
        "version": ANALYSIS_VERSION,
        "route_template": _route_template(path),
        "method": str(method or "GET").upper(),
        "classification": {
            "static_asset": is_static,
            "api": is_api,
            "authentication_surface": is_auth,
            "sensitive_function": is_sensitive,
            "state_changing": state_changing,
            "object_reference": object_reference,
            "upload_surface": is_upload,
            "redirect_surface": is_redirect_surface,
            "server_side_fetch_surface": is_server_fetch_surface,
            "file_delivery_surface": is_file_delivery,
            "session_termination_surface": is_session_termination,
            "input_surface": is_input_surface,
            "structured_input_surface": is_structured_input,
            "state_change_candidate_surface": is_state_change_candidate,
            "token_lifecycle_surface": is_token_lifecycle,
        },
        "risk_score": risk,
        "parameters": parameter_rows,
        "test_matrix": tests,
        "recommended_tools": sorted({tool for test in tests for tool in test["validators"]}),
        "analyzed_at": datetime.now().isoformat(),
    }


def analyze_endpoints_for_scan(db: Session, job: ScanJob, *, limit: int = 10000, force: bool = False) -> dict[str, Any]:
    endpoints = (
        db.query(OffensiveEndpoint)
        .filter(OffensiveEndpoint.scan_job_id == job.id)
        .order_by(OffensiveEndpoint.id.asc())
        .limit(max(1, int(limit)))
        .all()
    )
    inv = OffensiveInventoryService(db, job)
    analyzed = 0
    tests_planned = 0
    tests_current = 0
    skipped_current = 0
    for endpoint in endpoints:
        metadata = dict(endpoint.endpoint_metadata or {})
        if not force and (metadata.get("analysis") or {}).get("version") == ANALYSIS_VERSION:
            skipped_current += 1
            tests_current += len(list((metadata.get("analysis") or {}).get("test_matrix") or []))
            continue
        parameters = (
            db.query(OffensiveParameter)
            .filter(OffensiveParameter.endpoint_id == endpoint.id)
            .order_by(OffensiveParameter.id.asc())
            .all()
        )
        analysis = analyze_endpoint_contract(
            endpoint.url,
            method=endpoint.method,
            tags=list(endpoint.tags or []),
            parameters=[{
                "name": parameter.name,
                "location": parameter.location,
                "type_hint": parameter.type_hint,
                "risk_hint": parameter.risk_hint,
                "sample_value": parameter.sample_value,
            } for parameter in parameters],
            content_type=str(endpoint.content_type or ""),
        )
        metadata["analysis"] = analysis
        endpoint.endpoint_metadata = metadata
        endpoint.tags = sorted(set(list(endpoint.tags or []) + _analysis_tags(analysis)))
        endpoint.confidence = max(int(endpoint.confidence or 0), 70)
        endpoint.last_seen = datetime.now()
        db.add(endpoint)
        for parameter_row in analysis["parameters"]:
            inv.upsert_parameter(
                endpoint,
                parameter_row["name"],
                location=parameter_row["location"],
                type_hint=parameter_row["type_hint"],
                risk_hint=parameter_row["risk_hint"],
                source_tool=endpoint.source_tool or "endpoint-analysis",
                metadata={"analysis_version": ANALYSIS_VERSION},
            )
        for test in analysis["test_matrix"]:
            inv.upsert_coverage(
                coverage_type="endpoint_test_plan",
                target_ref=endpoint.normalized_url,
                test_class=test["test_class"],
                status="planned",
                endpoint_id=endpoint.id,
                metadata={"analysis_version": ANALYSIS_VERSION, "hypothesis_type": test["hypothesis_type"], "validators": test["validators"], "preconditions": test["preconditions"]},
            )
            tests_planned += 1
            tests_current += 1
        analyzed += 1
    state = dict(job.state_data or {})
    state["endpoint_intelligence"] = {
        "version": ANALYSIS_VERSION,
        "endpoints_seen": len(endpoints),
        "endpoints_analyzed": analyzed + skipped_current,
        "endpoints_analyzed_now": analyzed,
        "already_current": skipped_current,
        "tests_planned": tests_current,
        "tests_planned_now": tests_planned,
        "updated_at": datetime.now().isoformat(),
    }
    job.state_data = state
    db.add(job)
    db.flush()
    return state["endpoint_intelligence"]


def recommended_execution_tools(analysis: dict[str, Any]) -> list[str]:
    """Return only discovery-safe tools; active validators run via hypotheses."""
    classifications = dict(analysis.get("classification") or {})
    tools: list[str] = []
    if classifications.get("api") or classifications.get("sensitive_function"):
        tools.append("nuclei")
    if any(test.get("test_class") == "api_spec" for test in analysis.get("test_matrix") or []):
        tools.append("nuclei-exposure")
    return list(dict.fromkeys(tools))


def _test(test_class: str, hypothesis_type: str, confidence: int, validators: list[str], identities: list[str], evidence: list[str], source_signal: str) -> dict[str, Any]:
    return {
        "test_class": test_class,
        "hypothesis_type": hypothesis_type,
        "confidence": confidence,
        "validators": validators,
        "required_identities": identities,
        "evidence_requirements": evidence,
        "preconditions": _preconditions(identities, test_class),
        "source_signal": source_signal,
        "safe_mode": True,
    }


def _parameter_test(hint: str, name: str, location: str) -> dict[str, Any] | None:
    config = {
        "idor_bola": (86, ["idor-validator"], ["user_a", "user_b"], ["baseline_vs_exploit", "negative_control"]),
        "business_logic_mass_assignment": (78, ["mass-assignment-validator", "auth-matrix"], ["user_a", "user_b"], ["baseline", "read_back", "negative_control"]),
        "ssrf_open_redirect": (72, ["open-redirect-validator"], [], ["baseline_vs_exploit", "negative_control"]),
        "lfi_ssti_path_traversal": (70, ["lfi_ssti_path_traversal-validator"], [], ["baseline_vs_exploit", "negative_control"]),
        "xss_sqli": (66, ["xss_sqli-validator"], [], ["baseline_vs_payload", "negative_control"]),
        "rce": (88, ["nuclei-rce"], [], ["operator_authorization", "safe_oob_callback"]),
        "object_reference": (82, ["idor-validator"], ["user_a", "user_b"], ["baseline_vs_exploit", "negative_control"]),
    }
    row = config.get(hint)
    if not row:
        return None
    confidence, validators, identities, evidence = row
    return _test(f"parameter:{location}:{name}:{hint}", hint, confidence, validators, identities, evidence, f"param:{location}:{name}")


def _preconditions(identities: list[str], test_class: str) -> list[str]:
    values = ["authorized_scope", "endpoint_reachable"]
    if identities:
        values.append("valid_identities:" + ",".join(identities))
    if "state_change" in test_class or "upload" in test_class:
        values.extend(["safe_write_fixture", "read_back_available"])
    return values


def _infer_type(value: Any) -> str:
    text = str(value or "")
    if text.isdigit():
        return "integer"
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f-]{27,}", text, re.I):
        return "uuid"
    if text.lower() in {"true", "false"}:
        return "boolean"
    return "string"


def _route_template(path: str) -> str:
    return re.sub(r"(?<=/)(?:\d{1,12}|[0-9a-f]{8}-[0-9a-f-]{27,})(?=/|$)", "{id}", path or "/", flags=re.I)


def _dedupe_tests(tests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for test in tests:
        key = (test["test_class"], test["source_signal"])
        if key not in seen:
            seen.add(key)
            result.append(test)
    return result


def _analysis_tags(analysis: dict[str, Any]) -> list[str]:
    return [key for key, enabled in dict(analysis.get("classification") or {}).items() if enabled]
