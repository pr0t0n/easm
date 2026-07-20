"""Pure business-logic contracts derived exclusively from observed endpoints.

This module does not send requests and does not infer undiscovered routes or
object identifiers.  It turns endpoint evidence into explicit invariants and
an execution-readiness decision that other layers can audit.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any
from urllib.parse import urlparse


CONTRACT_VERSION = "business-logic-v1"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

_FLOW_TOKENS: dict[str, set[str]] = {
    "object_ownership": {"users", "accounts", "orders", "invoices", "documents", "transactions"},
    "money_movement": {"payment", "payments", "transfer", "transfers", "transaction", "transactions"},
    "file_and_export": {"download", "export", "file", "view", "template", "logs", "backup", "invoice", "image"},
    "authentication": {"login", "logout", "register", "reset", "otp", "mfa", "token", "refresh", "saml"},
    "account_change": {"profile", "password", "email", "users", "create"},
    "server_side_fetch": {"fetch", "proxy", "preview", "webhook", "integrations", "callback", "image"},
    "redirect_navigation": {"redirect", "continue", "callback"},
    "structured_ingestion": {"xml", "soap", "import", "upload"},
    "user_content": {"search", "comments", "feedback", "support", "messages"},
}

_FLOW_PRIORITY = {
    "money_movement": 95,
    "object_ownership": 88,
    "account_change": 85,
    "authentication": 82,
    "file_and_export": 80,
    "server_side_fetch": 78,
    "structured_ingestion": 76,
    "redirect_navigation": 62,
    "user_content": 58,
    "state_transition": 75,
}

_INVARIANTS: dict[str, list[dict[str, Any]]] = {
    "object_ownership": [
        {"id": "owner_scope", "statement": "O mesmo objeto só pode ser lido pela identidade proprietária ou por papel explicitamente autorizado.", "evidence": ["owner_baseline", "cross_identity_same_object", "negative_control"]},
        {"id": "list_detail_consistency", "statement": "O escopo da listagem e do detalhe deve aplicar a mesma regra de autorização.", "evidence": ["scoped_list", "detail_response"]},
    ],
    "money_movement": [
        {"id": "positive_amount", "statement": "Valor e quantidade devem respeitar limites server-side e nunca aceitar valor inválido/negativo.", "evidence": ["valid_baseline", "invalid_value_response", "read_back"]},
        {"id": "balance_conservation", "statement": "Débito, crédito, taxas e saldo final devem conservar o valor esperado da operação.", "evidence": ["balance_before", "ledger_entry", "balance_after"]},
        {"id": "single_commit", "statement": "Reenvio, retry e concorrência não podem duplicar a operação; idempotência deve ser verificável.", "evidence": ["operation_key", "first_result", "replay_result", "ledger_count"]},
        {"id": "authorized_recipient", "statement": "Origem, destino e instrumento de pagamento devem pertencer a identidades autorizadas.", "evidence": ["identity_context", "ownership_baseline", "cross_identity_control"]},
    ],
    "file_and_export": [
        {"id": "authorized_file_scope", "statement": "Download, exportação e visualização devem respeitar o mesmo escopo de dados da aplicação.", "evidence": ["owner_file", "cross_identity_same_file", "content_fingerprint"]},
        {"id": "server_selected_path", "statement": "O cliente não pode selecionar caminho arbitrário fora do recurso autorizado.", "evidence": ["accepted_parameter", "path_boundary_response"]},
    ],
    "authentication": [
        {"id": "auth_state_transition", "statement": "Cada transição anônimo/autenticado/MFA deve ocorrer somente após a pré-condição correta.", "evidence": ["session_before", "transition_request", "session_after"]},
        {"id": "server_side_invalidation", "statement": "Logout, reset e revogação devem invalidar a sessão/token no servidor.", "evidence": ["authenticated_baseline", "invalidation_response", "same_token_replay"]},
        {"id": "token_rotation", "statement": "Refresh e mudança de credencial devem rotacionar tokens e negar replay do artefato antigo.", "evidence": ["token_before", "token_after", "old_token_replay"]},
        {"id": "mfa_not_skippable", "statement": "OTP/MFA não pode ser omitido, reordenado ou reutilizado para concluir autenticação.", "evidence": ["challenge_state", "invalid_or_replayed_otp", "final_session_state"]},
    ],
    "account_change": [
        {"id": "reauthentication", "statement": "Mudanças sensíveis exigem credencial atual, MFA ou reautenticação proporcional ao risco.", "evidence": ["session_context", "reauth_challenge", "change_result"]},
        {"id": "server_owned_fields", "statement": "Papel, dono, status, saldo e campos privilegiados não podem ser definidos pelo cliente.", "evidence": ["accepted_schema", "privileged_field_control", "read_back"]},
        {"id": "post_change_session", "statement": "Mudança de senha/e-mail deve rotacionar ou invalidar sessões conforme a política.", "evidence": ["sessions_before", "change_response", "sessions_after"]},
    ],
    "server_side_fetch": [
        {"id": "destination_policy", "statement": "O servidor só pode buscar destinos, esquemas e portas permitidos pela política.", "evidence": ["accepted_parameter", "allowed_destination_control", "blocked_destination_control"]},
        {"id": "network_boundary", "statement": "Destinos privados, loopback, link-local e metadados de nuvem devem permanecer inacessíveis.", "evidence": ["safe_oob_observation", "private_range_denial"]},
    ],
    "redirect_navigation": [
        {"id": "redirect_allowlist", "statement": "Redirecionamentos devem permanecer em destinos permitidos e preservar o contexto de confiança.", "evidence": ["accepted_parameter", "same_origin_control", "external_origin_control"]},
    ],
    "structured_ingestion": [
        {"id": "parser_boundary", "statement": "Parser deve impor tipo, tamanho e schema, com entidades externas e resolução remota desabilitadas.", "evidence": ["accepted_content_type", "valid_document_control", "safe_invalid_document"]},
        {"id": "import_atomicity", "statement": "Importações inválidas não podem deixar estado parcial ou duplicado.", "evidence": ["state_before", "import_result", "state_after"]},
    ],
    "user_content": [
        {"id": "content_ownership", "statement": "Conteúdo privado deve respeitar autoria, destinatário e visibilidade configurada.", "evidence": ["author_baseline", "cross_identity_control"]},
        {"id": "output_context", "statement": "Entrada deve ser validada e codificada no contexto de saída onde reaparece.", "evidence": ["input_location", "rendered_context", "negative_control"]},
        {"id": "abuse_boundary", "statement": "Busca, feedback, suporte e mensagens devem aplicar limites contra abuso sem quebrar o fluxo legítimo.", "evidence": ["normal_rate_baseline", "limit_signal"]},
    ],
    "state_transition": [
        {"id": "transition_preconditions", "statement": "A operação só pode avançar do estado anterior permitido e na ordem definida.", "evidence": ["state_before", "transition_request", "state_after"]},
        {"id": "replay_safe", "statement": "Replay e concorrência não podem repetir efeitos de uma única intenção do usuário.", "evidence": ["request_identity", "first_effect", "replay_effect"]},
        {"id": "rollback_verified", "statement": "Teste de escrita deve usar fixture descartável, read-back e rollback comprovado.", "evidence": ["fixture_id", "read_back", "rollback_result"]},
    ],
}


def build_business_logic_contract(
    url: str,
    *,
    method: str,
    classification: dict[str, Any],
    parameters: list[dict[str, Any]] | None = None,
    test_matrix: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build an auditable contract without inventing endpoints or test data."""
    path = urlparse(str(url or "")).path or "/"
    tokens = {part.lower() for part in path.replace("-", "/").replace("_", "/").split("/") if part}
    flows = [name for name, markers in _FLOW_TOKENS.items() if tokens & markers]
    if classification.get("object_reference") and "object_ownership" not in flows:
        flows.append("object_ownership")
    if classification.get("state_changing") and "state_transition" not in flows:
        flows.append("state_transition")
    flows = sorted(set(flows), key=lambda name: (-_FLOW_PRIORITY.get(name, 0), name))

    invariants: list[dict[str, Any]] = []
    for flow in flows:
        for invariant in _INVARIANTS.get(flow, []):
            if invariant["id"] not in {row["id"] for row in invariants}:
                invariants.append({**invariant, "flow": flow})

    identities: set[str] = set()
    if any(flow in flows for flow in ("object_ownership", "file_and_export", "money_movement", "user_content")):
        identities.update({"user_a", "user_b"})
    elif any(flow in flows for flow in ("authentication", "account_change", "state_transition")):
        identities.add("user_a")
    for test in test_matrix or []:
        identities.update(str(item) for item in test.get("required_identities") or [] if item)

    verb = str(method or "GET").upper()
    mutation_candidate = verb not in SAFE_METHODS or any(flow in flows for flow in ("money_movement", "account_change", "structured_ingestion", "state_transition"))
    observed_parameters = [str(row.get("name") or "") for row in parameters or [] if row.get("name")]
    parameter_required = any(flow in flows for flow in ("server_side_fetch", "redirect_navigation"))
    fixtures: list[str] = []
    if "object_ownership" in flows or "file_and_export" in flows:
        fixtures.append("same_object_owned_by_user_a")
    if mutation_candidate:
        fixtures.extend(["disposable_entity", "read_back", "rollback"])
    if "money_movement" in flows:
        fixtures.extend(["sandbox_ledger", "idempotency_key"])

    blockers: list[str] = []
    if parameter_required and not observed_parameters:
        blockers.append("observed_parameter_required")
    if classification.get("object_reference") and ("{" in path or "}" in path):
        blockers.append("concrete_object_fixture_required")
    if identities:
        blockers.append("validated_identity_context_required")
    if mutation_candidate:
        blockers.extend(["explicit_mutation_authorization_required", "reversible_fixture_required"])

    return {
        "version": CONTRACT_VERSION,
        "relevant": bool(flows),
        "endpoint": url,
        "method": verb,
        "flows": flows,
        "priority": max((_FLOW_PRIORITY.get(flow, 0) for flow in flows), default=0),
        "invariants": invariants,
        "required_identities": sorted(identities),
        "required_fixtures": list(dict.fromkeys(fixtures)),
        "observed_parameters": observed_parameters,
        "evidence_requirements": sorted({item for invariant in invariants for item in invariant["evidence"]}),
        "execution_policy": {
            "observed_endpoint_only": True,
            "guess_routes": False,
            "guess_object_ids": False,
            "credential_injection": False,
            "brute_force": False,
            "read_only_allowed": bool(flows) and not mutation_candidate and not (parameter_required and not observed_parameters),
            "mutation_allowed_by_default": False,
            "mutation_candidate": mutation_candidate,
            "requires_explicit_reversible_plan": mutation_candidate,
        },
        "blockers": list(dict.fromkeys(blockers)),
        "status": "contracted" if flows else "not_applicable",
    }


def build_business_logic_portfolio(
    analyses: list[dict[str, Any]],
    *,
    available_identities: list[str] | None = None,
    mutation_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregate contracts and expose actual readiness, not optimistic coverage."""
    identities = {str(item) for item in available_identities or []}
    contracts = [dict(row.get("business_logic") or {}) for row in analyses]
    relevant = [row for row in contracts if row.get("relevant")]
    flow_counts = Counter(flow for row in relevant for flow in row.get("flows") or [])
    invariant_count = sum(len(row.get("invariants") or []) for row in relevant)
    ready_read_only = 0
    ready_mutation = 0
    blocked = Counter()
    for row in relevant:
        missing_ids = set(row.get("required_identities") or []) - identities
        if missing_ids:
            blocked["missing_validated_identities"] += 1
        if "observed_parameter_required" in (row.get("blockers") or []):
            blocked["missing_observed_parameter"] += 1
        if "concrete_object_fixture_required" in (row.get("blockers") or []):
            blocked["missing_concrete_object_fixture"] += 1
        contract_blocked = bool(
            {"observed_parameter_required", "concrete_object_fixture_required"}
            & set(row.get("blockers") or [])
        )
        if row.get("execution_policy", {}).get("read_only_allowed") and not missing_ids and not contract_blocked:
            ready_read_only += 1
        if row.get("execution_policy", {}).get("mutation_candidate"):
            if mutation_plan and not missing_ids and all(mutation_plan.get(key) for key in ("endpoint", "fixture_id", "rollback")):
                ready_mutation += 1
            else:
                blocked["mutation_plan_or_fixture_missing"] += 1
    return {
        "version": CONTRACT_VERSION,
        "endpoints_evaluated": len(analyses),
        "relevant_endpoints": len(relevant),
        "contracted_endpoints": len([row for row in relevant if row.get("status") == "contracted"]),
        "flows": dict(sorted(flow_counts.items())),
        "flow_count": len(flow_counts),
        "invariants": invariant_count,
        "high_risk_endpoints": len([row for row in relevant if int(row.get("priority") or 0) >= 80]),
        "ready_read_only": ready_read_only,
        "ready_mutation": ready_mutation,
        "blocked": dict(sorted(blocked.items())),
        "blocked_endpoints": len(relevant) - ready_read_only,
        "execution_guardrails": {
            "observed_endpoints_only": True,
            "route_guessing": False,
            "object_id_guessing": False,
            "brute_force": False,
            "mutation_default": "blocked",
        },
        "updated_at": datetime.now().isoformat(),
    }


def build_business_logic_execution_plan(
    analyses: list[dict[str, Any]],
    *,
    available_identities: list[str] | None = None,
    mutation_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return only evidence-backed actions that the executor may consume."""
    identities = {str(item) for item in available_identities or []}
    actions: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for analysis in analyses:
        contract = dict(analysis.get("business_logic") or {})
        if not contract.get("relevant"):
            continue
        missing = sorted(set(contract.get("required_identities") or []) - identities)
        reasons = []
        if missing:
            reasons.append("missing_validated_identities:" + ",".join(missing))
        if "observed_parameter_required" in (contract.get("blockers") or []):
            reasons.append("missing_observed_parameter")
        if "concrete_object_fixture_required" in (contract.get("blockers") or []):
            reasons.append("missing_concrete_object_fixture")
        if contract.get("execution_policy", {}).get("mutation_candidate"):
            reasons.append("state_change_requires_dedicated_reversible_plan")
        if reasons:
            blocked.append({"endpoint": contract.get("endpoint"), "method": contract.get("method"), "reasons": reasons})
            continue
        actions.append({
            "endpoint": contract.get("endpoint"),
            "method": contract.get("method"),
            "mode": "read_only_baseline",
            "flows": contract.get("flows") or [],
            "invariants": [row.get("id") for row in contract.get("invariants") or []],
            "parameters": contract.get("observed_parameters") or [],
            "required_identities": contract.get("required_identities") or [],
        })
    mutation_authorized = bool(mutation_plan and all(mutation_plan.get(key) for key in ("endpoint", "fixture_id", "rollback")))
    return {
        "version": CONTRACT_VERSION,
        "policy": "observed-evidence-only",
        "actions": actions,
        "blocked": blocked,
        "mutation_authorized": mutation_authorized,
        "mutation_plan": mutation_plan if mutation_authorized else None,
        "guardrails": {
            "guess_routes": False,
            "guess_object_ids": False,
            "brute_force": False,
            "try_sqli_auth": False,
            "mutation_requires_fixture_and_rollback": True,
        },
    }
