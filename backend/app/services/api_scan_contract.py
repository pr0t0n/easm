from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


API_SCAN_ACTIVITIES = [
    "api_discovery",
    "api_spec_ingestion",
    "api_contract_validation",
    "api_dast",
    "api_parameter_testing",
    "api_authorization_matrix",
    "api_json_body_analysis",
    "graphql_testing",
    "swagger_openapi_review",
    "api_session_auth_testing",
    "api_guardrail_enforcement",
    "api_coverage_reporting",
]


def credential_count(auth_config: dict[str, Any] | None) -> int:
    if not isinstance(auth_config, dict) or not auth_config:
        return 0
    identities = auth_config.get("identities")
    if isinstance(identities, list):
        usable = [
            identity for identity in identities
            if isinstance(identity, dict) and _identity_has_material(identity)
        ]
        return min(2, len(usable))
    return 1 if _identity_has_material(auth_config) else 0


def api_execution_contexts(auth_config: dict[str, Any] | None) -> list[str]:
    count = credential_count(auth_config)
    if count <= 0:
        return ["anonymous"]
    if count == 1:
        return ["anonymous", "authenticated:user_a"]
    return ["anonymous", "authenticated:user_a", "authenticated:user_b"]


def normalize_api_scan_config(
    config: dict[str, Any] | None,
    auth_config: dict[str, Any] | None,
) -> dict[str, Any]:
    source = dict(config or {})
    spec_url = str(source.get("spec_url") or source.get("url") or "").strip()
    spec_type = str(source.get("spec_type") or source.get("type") or "openapi").strip().lower()
    if spec_type in {"swagger", "openapi3", "openapi2"}:
        spec_type = "openapi"
    if spec_type not in {"openapi", "graphql", "postman", "har"}:
        spec_type = "openapi"
    spec_payload = source.get("spec_payload") if isinstance(source.get("spec_payload"), dict) else None
    enabled = bool(source.get("enabled") or spec_url or spec_payload)
    contexts = api_execution_contexts(auth_config)
    return {
        "enabled": enabled,
        "version": "api-scan-complete-v1",
        "activities": list(API_SCAN_ACTIVITIES) if enabled else [],
        "spec_url": spec_url,
        "spec_type": spec_type,
        "inline_spec_provided": bool(spec_payload),
        "auth_strategy": _auth_strategy(contexts),
        "execution_contexts": contexts,
        "credential_count": credential_count(auth_config),
        "anonymous_always_on": True,
        "allow_mutations": bool(source.get("allow_mutations", False)),
        "active_level": str(source.get("active_level") or "safe").strip().lower() or "safe",
    }


def api_spec_payload(config: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(config, dict):
        return None
    payload = config.get("spec_payload")
    return payload if isinstance(payload, dict) else None


def merge_api_scan_state(state: dict[str, Any], api_config: dict[str, Any]) -> dict[str, Any]:
    if not api_config.get("enabled"):
        return state
    merged = dict(state)
    merged["api_scan_config"] = dict(api_config)
    spec_url = str(api_config.get("spec_url") or "").strip()
    spec_type = str(api_config.get("spec_type") or "openapi").strip().lower()
    if spec_url:
        key = "graphql_schema_urls" if spec_type == "graphql" else "openapi_urls"
        merged[key] = list(dict.fromkeys(list(merged.get(key) or []) + [spec_url]))
        if spec_type == "openapi":
            merged["swagger_urls"] = list(dict.fromkeys(list(merged.get("swagger_urls") or []) + [spec_url]))
    if api_config.get("inline_spec_provided"):
        key = "api_specs" if spec_type != "openapi" else "openapi_specs"
        merged[key] = list(dict.fromkeys(list(merged.get(key) or []) + ["inline"]))
    merged["api_scan_activities"] = list(api_config.get("activities") or [])
    merged["api_execution_contexts"] = list(api_config.get("execution_contexts") or ["anonymous"])
    return merged


def api_spec_url_in_scope(spec_url: str, authorized_scope: list[str]) -> bool:
    raw = str(spec_url or "").strip()
    if not raw:
        return True
    try:
        host = str(urlparse(raw if "://" in raw else f"https://{raw}").hostname or "").strip().lower()
    except Exception:
        return False
    if not host:
        return False
    if not authorized_scope:
        return True
    from app.services.scan_scope import is_host_in_scope

    return is_host_in_scope(host, authorized_scope)


def _identity_has_material(identity: dict[str, Any]) -> bool:
    if identity.get("bearer_token") or identity.get("token"):
        return True
    if identity.get("username") or identity.get("password"):
        return True
    if any(str(value or "").strip() for value in dict(identity.get("cookies") or {}).values()):
        return True
    if any(str(value or "").strip() for value in dict(identity.get("headers") or {}).values()):
        return True
    if str(identity.get("cookie") or "").strip():
        return True
    return False


def _auth_strategy(contexts: list[str]) -> str:
    if len(contexts) >= 3:
        return "anonymous_authenticated_ab"
    if len(contexts) == 2:
        return "anonymous_authenticated"
    return "anonymous_only"
