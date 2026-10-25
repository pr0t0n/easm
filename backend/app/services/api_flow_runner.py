"""Stateful flow runner for the API module.

Executes endpoints as a *sequence* instead of in isolation: it creates an object,
harvests the identifier the API returns (requestId/id/fileId/token/...), and
reuses it in later requests — so business-logic and BOLA flaws that only appear
mid-flow become testable. Every value and where it is reused is tracked as
*lineage*, which the report renders.

The actual HTTP goes through the caller-provided ``request_fn`` (the runner's
``_request``, which already routes via Caido or direct requests), so this module
stays network-free and unit-testable: pass a stub ``request_fn`` in tests.

Primary sequence implemented: the onboarding incident — create a flow, then
submit the fraud step with ``optIn:true`` and NO image (business-logic bypass,
OWASP API6/API3), then read the result with a second identity (BOLA, API1).
"""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import urlparse

# Response fields that commonly carry an object identifier to reuse downstream.
_ID_FIELDS = ("requestid", "request_id", "id", "externalid", "external_id",
              "fileid", "file_id", "token", "transactionid", "transaction_id",
              "protocol", "uuid", "sessionid", "session_id")
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}|\{([a-zA-Z0-9_]+)\}")
# Flags that attempt to skip a validation step (the optIn bypass family).
_BYPASS_FLAGS = {"optIn": True, "skipValidation": True, "bypass": True, "force": True}


def _mask(value: Any) -> str:
    s = str(value)
    if len(s) <= 8:
        return s[:2] + "…" if len(s) > 2 else s
    return s[:4] + "…" + s[-4:]


class VariableStore:
    """Named values harvested during a flow, with provenance + reuse tracking."""

    def __init__(self, seed: dict[str, Any] | None = None):
        self._values: dict[str, Any] = {}
        self._lineage: dict[str, dict[str, Any]] = {}
        for k, v in (seed or {}).items():
            if v is None or str(v) == "":
                continue
            self._values[str(k)] = v
            self._lineage[str(k)] = {
                "name": str(k), "value_masked": _mask(v),
                "source_endpoint": "(seed/test_variables)", "source_field": str(k),
                "reused_in": [],
            }

    def put(self, name: str, value: Any, source_endpoint: str, source_field: str) -> None:
        if value is None or str(value) == "":
            return
        name = str(name)
        # Do not overwrite a user-seeded value with a harvested one.
        if name in self._values and self._lineage.get(name, {}).get("source_endpoint") == "(seed/test_variables)":
            return
        self._values[name] = value
        self._lineage.setdefault(name, {
            "name": name, "value_masked": _mask(value),
            "source_endpoint": source_endpoint, "source_field": source_field, "reused_in": [],
        })

    def get(self, name: str) -> Any:
        return self._values.get(str(name))

    def has(self, name: str) -> bool:
        return str(name) in self._values

    def mark_reuse(self, name: str, endpoint: str) -> None:
        lin = self._lineage.get(str(name))
        if lin is not None and endpoint not in lin["reused_in"]:
            lin["reused_in"].append(endpoint)

    def inject(self, text: str, endpoint: str = "") -> str:
        """Replace {{var}} / {var} with stored values, recording the reuse."""
        def repl(m: re.Match) -> str:
            name = m.group(1) or m.group(2)
            if self.has(name):
                if endpoint:
                    self.mark_reuse(name, endpoint)
                return str(self.get(name))
            return m.group(0)
        return _PLACEHOLDER_RE.sub(repl, str(text or ""))

    def inject_obj(self, obj: Any, endpoint: str = "") -> Any:
        if isinstance(obj, str):
            return self.inject(obj, endpoint)
        if isinstance(obj, dict):
            return {k: self.inject_obj(v, endpoint) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.inject_obj(v, endpoint) for v in obj]
        return obj

    def lineage(self) -> list[dict[str, Any]]:
        return list(self._lineage.values())


def extract_ids_from_response(body: Any, store: VariableStore, source_endpoint: str) -> list[str]:
    """Harvest id-like fields from a JSON response body into the store.
    Returns the names captured. Scans top-level and one level of nesting."""
    captured: list[str] = []

    def consider(key: str, val: Any) -> None:
        if not isinstance(val, (str, int)) or isinstance(val, bool):
            return
        kl = str(key).lower()
        if kl in _ID_FIELDS or kl.endswith("id"):
            store.put(key, val, source_endpoint, key)
            captured.append(str(key))

    if isinstance(body, dict):
        for k, v in body.items():
            consider(k, v)
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    consider(k2, v2)
    return captured


def _path_of(url: str) -> str:
    try:
        return urlparse(url).path or url
    except Exception:
        return url


def _json_body(result: dict[str, Any]) -> Any:
    """Best-effort JSON parse of a request_fn result's response body."""
    import json
    txt = result.get("response_body")
    if txt is None:
        resp = result.get("response")
        txt = getattr(resp, "text", None) if resp is not None else None
    if not txt:
        return None
    try:
        return json.loads(txt)
    except Exception:
        return None


def _status(result: dict[str, Any]) -> int:
    if result.get("response_status") is not None:
        try:
            return int(result["response_status"])
        except Exception:
            return 0
    resp = result.get("response")
    return int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0


# --------------------------------------------------------------------------- #
# endpoint role selection (from the flow graph / paths)
# --------------------------------------------------------------------------- #
def _find(endpoints: list[Any], method: str, must_contain: list[str], must_not: list[str] | None = None) -> Any:
    must_not = must_not or []
    for ep in endpoints:
        m = str(getattr(ep, "method", "") or "").upper()
        p = _path_of(str(getattr(ep, "url", "") or "")).lower()
        if m != method.upper():
            continue
        if all(tok in p for tok in must_contain) and not any(tok in p for tok in must_not):
            return ep
    return None


def run_business_flow(
    endpoints: list[Any],
    identities: list[Any],
    request_fn: Callable[..., dict[str, Any]],
    store: VariableStore,
    *,
    allow_mutations: bool,
    skill: dict[str, Any] | None = None,
    make_finding: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run the onboarding business-logic sequence via ``request_fn``.

    Returns ``{findings, variables, steps, dynamic_executed}``. Needs a reachable
    target; mutating requests require ``allow_mutations``. Findings keep the hard
    rule: a BAC positive requires a 2xx/3xx with the owner's data; 401/403/404 is
    advisory.
    """
    findings: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    primary = identities[0] if identities else None

    def fin(url: str, msg: str, sev: str, owasp: str, *, confirmed: bool, http: int, extra: dict | None = None) -> dict[str, Any]:
        if make_finding is not None:
            return make_finding(skill or {}, url, msg, getattr(primary, "key", "anonymous"),
                                severity=sev,
                                verification_status="confirmed" if confirmed else "advisory",
                                evidence_extra={**(extra or {}), "owasp": owasp, "http_status": http,
                                                "business_flow": True})
        return {"url": url, "title": msg, "severity": sev, "owasp": owasp,
                "verification_status": "confirmed" if confirmed else "advisory",
                "http_status": http, "method": "POST"}

    if not allow_mutations:
        return {"findings": [], "variables": store.lineage(), "steps": [],
                "dynamic_executed": False, "skipped": "allow_mutations_required"}

    # 1) Create a flow to obtain a real requestId (unless one was seeded).
    create_ep = _find(endpoints, "POST", ["steps/flow"]) or _find(endpoints, "POST", ["steps"], ["result", "fraud", "liveness", "mfa", "upload", "signer"])
    if create_ep is not None and not store.has("requestId"):
        r = request_fn("POST", str(create_ep.url), primary, json_body={})
        sc = _status(r)
        captured = extract_ids_from_response(_json_body(r), store, _path_of(str(create_ep.url)))
        steps.append({"step": "create_flow", "url": str(create_ep.url), "status": sc, "captured": captured})

    request_id = store.get("requestId") or store.get("id")

    # 2) Business-logic bypass: fraud step with optIn:true and NO image.
    fraud_ep = _find(endpoints, "POST", ["steps/fraud"]) or _find(endpoints, "POST", ["fraud"])
    if fraud_ep is not None:
        body = {"optIn": True}
        if request_id:
            body["requestId"] = request_id
            store.mark_reuse("requestId", _path_of(str(fraud_ep.url)))
        r = request_fn("POST", str(fraud_ep.url), primary, json_body=store.inject_obj(body, _path_of(str(fraud_ep.url))))
        sc = _status(r)
        steps.append({"step": "fraud_optin_no_image", "url": str(fraud_ep.url), "status": sc})
        if 200 <= sc < 300:
            findings.append(fin(str(fraud_ep.url),
                                "Step de fraude ACEITOU optIn:true SEM imagem/documento (HTTP %d) — bypass de regra de negócio (OWASP API6/API3)." % sc,
                                "high", "API6:2023", confirmed=True, http=sc,
                                extra={"request_body": '{"optIn": true}', "response_status": sc, "curl": r.get("curl", "")}))

    # 3) BOLA: read the result with a second identity (or anonymous).
    result_ep = _find(endpoints, "GET", ["steps/result"], ["external"]) or _find(endpoints, "GET", ["result"])
    if result_ep is not None and request_id:
        attacker = identities[1] if len(identities) > 1 else primary
        url = store.inject(str(result_ep.url).replace("{requestId}", str(request_id)).replace("{id}", str(request_id)), _path_of(str(result_ep.url)))
        store.mark_reuse("requestId", _path_of(str(result_ep.url)))
        r = request_fn("GET", url, attacker)
        sc = _status(r)
        steps.append({"step": "bola_cross_identity_result", "url": url, "status": sc,
                      "identity": getattr(attacker, "key", "")})
        if 200 <= sc < 400:
            findings.append(fin(url,
                                "Resultado da transação de OUTRO dono acessível por identidade/sem autorização adequada (HTTP %d) — BOLA (OWASP API1)." % sc,
                                "high", "API1:2023", confirmed=True, http=sc,
                                extra={"response_status": sc, "curl": r.get("curl", "")}))
        else:
            findings.append(fin(url,
                                "Tentativa de BOLA em resultado retornou HTTP %d — negado (advisório; revisar se o id é adivinhável)." % sc,
                                "info", "API1:2023", confirmed=False, http=sc))

    return {"findings": findings, "variables": store.lineage(), "steps": steps, "dynamic_executed": True}
