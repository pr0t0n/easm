"""Regras que transformam inventário em hipóteses testáveis."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models.models import OffensiveEndpoint, OffensiveParameter, ScanJob
from app.services.offensive_inventory_service import OffensiveInventoryService, parameter_risk_hint


RULES: dict[str, dict[str, Any]] = {
    "idor_bola": {
        "title": "Possível IDOR/BOLA por referência a objeto/usuário",
        "tools": ["idor-validator", "bola-validator", "curl-headers"],
        "identities": ["user_a", "user_b"],
        "evidence": ["baseline_vs_exploit", "negative_control", "authenticated_identity"],
    },
    "business_logic_mass_assignment": {
        "title": "Possível mass assignment ou abuso de lógica de negócio",
        "tools": ["mass-assignment-validator", "business-logic-validator"],
        "identities": ["user_a"],
        "evidence": ["baseline_vs_exploit", "read_back", "negative_control"],
    },
    "ssrf_open_redirect": {
        "title": "Possível SSRF ou open redirect por parâmetro URL-like",
        "tools": ["ssrf-validator", "open-redirect-validator", "interactsh-client"],
        "identities": [],
        "evidence": ["request_response_pair", "location_or_oob_callback", "negative_control"],
    },
    "lfi_ssti_path_traversal": {
        "title": "Possível LFI/path traversal/SSTI por parâmetro de caminho/template",
        "tools": ["path-traversal-validator", "ssti-validator"],
        "identities": [],
        "evidence": ["request_response_pair", "safe_payload", "negative_control"],
    },
    "xss_sqli": {
        "title": "Possível XSS/SQLi por parâmetro de busca/entrada textual",
        "tools": ["dalfox", "sqlmap", "xss-validator", "sqli-validator"],
        "identities": [],
        "evidence": ["baseline_vs_payload", "response_delta", "negative_control"],
    },
    "rce": {
        "title": "Possível RCE por parâmetro de comando",
        "tools": ["nuclei-rce", "interactsh-client"],
        "identities": [],
        "evidence": ["safe_payload", "oob_callback", "operator_authorization"],
    },
    "object_reference": {
        "title": "Endpoint contém referência a objeto sensível",
        "tools": ["idor-validator", "bola-validator"],
        "identities": ["user_a", "user_b"],
        "evidence": ["baseline_vs_exploit", "authenticated_identity"],
    },
}


HIGH_VALUE_PATHS = {
    "graphql": ("api_graphql", "Endpoint GraphQL descoberto", ["graphql-validator", "zap-api"], ["schema_or_introspection", "auth_matrix"]),
    "swagger": ("api_spec_exposure", "Swagger/OpenAPI exposto", ["zap-api", "api-spec-ingestor"], ["spec_parse", "endpoint_inventory"]),
    "openapi": ("api_spec_exposure", "OpenAPI exposto", ["zap-api", "api-spec-ingestor"], ["spec_parse", "endpoint_inventory"]),
    "admin": ("bfla_authz", "Endpoint administrativo descoberto", ["bfla-validator", "auth-matrix"], ["multi_identity_delta"]),
    "internal": ("bfla_authz", "Endpoint interno descoberto", ["bfla-validator", "auth-matrix"], ["multi_identity_delta"]),
    "debug": ("information_disclosure", "Endpoint debug descoberto", ["nuclei", "curl-headers"], ["request_response_pair"]),
}


def generate_hypotheses_for_scan(db: Session, scan: ScanJob) -> dict[str, int]:
    inv = OffensiveInventoryService(db, scan)
    created_or_seen = 0
    endpoints = db.query(OffensiveEndpoint).filter(OffensiveEndpoint.scan_job_id == scan.id).limit(10000).all()
    for endpoint in endpoints:
        lower = str(endpoint.url or "").lower()
        for marker, (h_type, title, tools, evidence) in HIGH_VALUE_PATHS.items():
            if marker in lower:
                inv.upsert_hypothesis(
                    hypothesis_type=h_type,
                    title=title,
                    target_ref=endpoint.normalized_url,
                    source_signal=f"path:{marker}",
                    confidence=70,
                    recommended_tools=tools,
                    required_identities=["user_a", "admin"] if h_type == "bfla_authz" else [],
                    evidence_requirements=evidence,
                    metadata={"endpoint_id": endpoint.id, "url": endpoint.url},
                )
                created_or_seen += 1
        if any(tag in (endpoint.tags or []) for tag in ("api", "auth", "token", "upload")):
            inv.upsert_hypothesis(
                hypothesis_type="api_security",
                title="Endpoint de API sensível descoberto",
                target_ref=endpoint.normalized_url,
                source_signal="endpoint_tag:" + ",".join(endpoint.tags or []),
                confidence=60,
                recommended_tools=["api-probe", "auth-matrix", "zap-api"],
                evidence_requirements=["request_response_pair", "auth_matrix"],
                metadata={"endpoint_id": endpoint.id, "url": endpoint.url},
            )
            created_or_seen += 1

    params = db.query(OffensiveParameter).filter(OffensiveParameter.scan_job_id == scan.id).limit(20000).all()
    for param in params:
        endpoint = param.endpoint
        if not endpoint:
            continue
        hint = param.risk_hint or parameter_risk_hint(param.name, endpoint.url)
        rule = RULES.get(hint)
        if not rule:
            continue
        inv.upsert_hypothesis(
            hypothesis_type=hint,
            title=f"{rule['title']}: {param.name}",
            target_ref=endpoint.normalized_url,
            source_signal=f"param:{param.location}:{param.name}",
            confidence=75 if hint in {"idor_bola", "business_logic_mass_assignment"} else 65,
            recommended_tools=rule["tools"],
            required_identities=rule["identities"],
            evidence_requirements=rule["evidence"],
            metadata={"endpoint_id": endpoint.id, "parameter_id": param.id, "url": endpoint.url, "parameter": param.name},
        )
        created_or_seen += 1

    db.flush()
    return {"hypotheses_created_or_seen": created_or_seen}
