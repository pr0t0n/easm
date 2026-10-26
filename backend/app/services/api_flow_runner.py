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
# Token/auth-handshake substrings so the store captures undocumented chain values
# like intentToken/platformId/accessToken (user: platformID -> intentToken -> requestID).
_TOKEN_SUBSTR = ("token", "intent", "platform", "session", "secret")
_SKIP_SUFFIX = ("url", "data", "name", "status", "date", "type", "message", "description")
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


_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)


def extract_urls_from_response(body: Any, *, in_scope_hosts: set[str] | None = None) -> list[str]:
    """Feedback-driven discovery (Schemathesis/RESTler-style): harvest URLs the
    API returns in its own response (HATEOAS links, requestProcessUrl, callbacks,
    webhooks) so they can be probed as newly-discovered surface — autonomously,
    no spec or credential needed. Optionally filtered to in-scope hosts."""
    text = body if isinstance(body, str) else None
    if text is None:
        import json as _json
        try:
            text = _json.dumps(body)
        except Exception:
            return []
    seen: dict[str, None] = {}
    for m in _URL_RE.finditer(text or ""):
        url = m.group(0).rstrip(".,);")
        if in_scope_hosts:
            try:
                host = urlparse(url).hostname or ""
            except Exception:
                host = ""
            if host and not any(host == h or host.endswith("." + h) for h in in_scope_hosts):
                continue
        seen.setdefault(url, None)
        if len(seen) >= 50:
            break
    return list(seen.keys())


def extract_ids_from_response(body: Any, store: VariableStore, source_endpoint: str) -> list[str]:
    """Harvest id-like fields from a JSON response body into the store.
    Returns the names captured. Scans top-level and one level of nesting."""
    captured: list[str] = []

    def consider(key: str, val: Any) -> None:
        if not isinstance(val, (str, int)) or isinstance(val, bool):
            return
        kl = str(key).lower()
        if any(kl.endswith(suf) for suf in _SKIP_SUFFIX):
            return
        if kl in _ID_FIELDS or kl.endswith("id") or any(tok in kl for tok in _TOKEN_SUBSTR):
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


def run_generic_flow(
    endpoints: list[Any],
    identities: list[Any],
    request_fn: Callable[..., dict[str, Any]],
    store: "VariableStore",
    *,
    allow_mutations: bool,
    skill: dict[str, Any] | None = None,
    make_finding: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """GENERIC stateful flow for ANY API (no hardcoded paths): drive the
    producer->consumer graph — run creators to harvest REAL ids, exercise each
    consumer as the owner AND as a second identity (cross-identity BOLA, API1),
    and inject generic bypass flags on state-changing steps (API6/API3). Uses
    real harvested ids (stronger than fuzzed ids). Needs a reachable target;
    creation/mutation gated by allow_mutations."""
    from app.services.api_flow_graph import _node_id, build_flow_graph
    skill = skill or {}
    findings: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    primary = identities[0] if identities else None
    attacker = identities[1] if len(identities) > 1 else None

    def fin(url: str, msg: str, sev: str, owasp: str, confirmed: bool, http: int, extra: dict | None = None) -> dict[str, Any]:
        if make_finding is not None:
            return make_finding(skill, url, msg, getattr(primary, "key", "anonymous"), severity=sev,
                                verification_status="confirmed" if confirmed else "advisory",
                                evidence_extra={**(extra or {}), "owasp": owasp, "http_status": http, "generic_flow": True})
        return {"url": url, "title": msg, "severity": sev, "owasp": owasp, "method": "GET",
                "verification_status": "confirmed" if confirmed else "advisory", "http_status": http}

    def m_of(ep: Any) -> str:
        return str(getattr(ep, "method", "GET") or "GET").upper()

    def u_of(ep: Any) -> str:
        return str(getattr(ep, "url", "") or "")

    graph = build_flow_graph(endpoints)
    ep_by_id: dict[str, Any] = {}
    for ep in endpoints:
        ep_by_id.setdefault(_node_id(ep), ep)

    discovered_urls: dict[str, None] = {}
    scope_hosts: set[str] = set()
    for ep in endpoints:
        h = urlparse(u_of(ep)).hostname
        if h:
            scope_hosts.add(h)

    # 1) Creators: harvest REAL ids + URLs (POST/PUT creation gated by allow_mutations).
    for n in graph.get("nodes", []):
        if not (n.get("produces") or n.get("stage") == "create"):
            continue
        ep = ep_by_id.get(n["id"])
        if ep is None:
            continue
        m = str(n.get("method") or "GET").upper()
        if m in ("POST", "PUT", "PATCH") and not allow_mutations:
            continue
        r = request_fn(m, u_of(ep), primary, json_body=({} if m in ("POST", "PUT", "PATCH") else None))
        jb = _json_body(r)
        caps = extract_ids_from_response(jb, store, _path_of(u_of(ep)))
        for u in extract_urls_from_response(jb if jb is not None else (r.get("response_body") or ""), in_scope_hosts=scope_hosts):
            discovered_urls.setdefault(u, None)
        steps.append({"step": "create", "node": n["id"], "status": _status(r), "captured": caps})

    # 2) Consumers: cross-identity BOLA using harvested/seeded ids (read endpoints).
    seen: set[str] = set()
    for e in graph.get("edges", []):
        cid, var = e["to"], e["variable"]
        if cid in seen or not store.has(var):
            continue
        ep = ep_by_id.get(cid)
        if ep is None or m_of(ep) not in ("GET", "HEAD"):
            continue
        seen.add(cid)
        url = store.inject(u_of(ep), _path_of(u_of(ep)))
        owner = request_fn(m_of(ep), url, primary)
        osc = _status(owner)
        steps.append({"step": "consume_read", "node": cid, "variable": var, "owner_status": osc})
        if attacker is not None and 200 <= osc < 400:
            atk = request_fn(m_of(ep), url, attacker)
            asc = _status(atk)
            if 200 <= asc < 400:
                findings.append(fin(url, f"BOLA (genérico, id real): identidade '{getattr(attacker,'key','')}' acessou objeto de '{getattr(primary,'key','')}' via {var}={_mask(store.get(var))} — HTTP {asc} (OWASP API1).",
                                     "high", "API1:2023", True, asc, {"variable": var, "owner_status": osc, "curl": atk.get("curl", "")}))

    # 3) Generic bypass-flag injection on state-changing steps (any API).
    if allow_mutations:
        for ep in endpoints:
            if m_of(ep) not in ("POST", "PUT", "PATCH"):
                continue
            consumes = [e["variable"] for e in graph.get("edges", []) if e["to"] == _node_id(ep)]
            if not consumes:
                continue  # only steps that act on an existing object
            body: dict[str, Any] = {k: v for k, v in _BYPASS_FLAGS.items()}
            for v in consumes:
                if store.has(v):
                    body[v] = store.get(v)
            r = request_fn(m_of(ep), store.inject(u_of(ep), _path_of(u_of(ep))), primary, json_body=body)
            sc = _status(r)
            steps.append({"step": "bypass_flags", "node": _node_id(ep), "status": sc})
            if 200 <= sc < 300:
                findings.append(fin(u_of(ep), f"Step state-changing aceitou corpo mínimo + flags de bypass ({list(_BYPASS_FLAGS)[:5]}) — HTTP {sc}: possível bypass de validação/regra de negócio (OWASP API6/API3).",
                                     "high", "API6:2023", True, sc, {"curl": r.get("curl", "")}))

    # 4) Feedback-driven discovery: probe URLs the API returned in its own bodies
    #    (requestProcessUrl/HATEOAS/callbacks). A 2xx on such a URL — especially as
    #    a second identity — is undocumented/accessible surface worth flagging.
    for url in list(discovered_urls)[:20]:
        probe = request_fn("GET", url, primary)
        psc = _status(probe)
        steps.append({"step": "feedback_discovery", "url": url, "status": psc})
        if 200 <= psc < 300:
            try:
                from app.services.api_sensitive_data import classify as _cls_fn
                cls = _cls_fn(probe.get("response_body") or "")
            except Exception:
                cls = {"types": {}, "worst_severity": ""}
            if cls.get("types"):
                findings.append(fin(url, f"URL retornada pela API (feedback) acessível e expõe dados sensíveis ({', '.join(cls['types'])}) — HTTP {psc} (OWASP API3/API9).",
                                     cls.get("worst_severity") or "medium", "API3:2023", True, psc, {"discovered_via": "response_feedback"}))
            else:
                findings.append(fin(url, f"URL retornada pela API (feedback) acessível sem controle aparente — HTTP {psc}; superfície não documentada (OWASP API9).",
                                     "low", "API9:2023", True, psc, {"discovered_via": "response_feedback"}))

    return {"findings": findings, "variables": store.lineage(), "steps": steps, "dynamic_executed": bool(steps)}
