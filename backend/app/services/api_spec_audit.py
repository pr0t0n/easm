"""Static OpenAPI security audit (vacuum/Spectral-OWASP style).

Design-time, 100% autonomous (reads only the spec — no network, no credentials).
Flags OWASP API Top 10 weaknesses in the contract itself: unauthenticated
operations, undefined responses, mass-assignment-prone schemas, missing
input/size constraints (resource consumption), weak transport, etc.

Mirrors the key rules of daveshanley/vacuum (MIT) `--hard-mode` OWASP ruleset,
reimplemented in Python to avoid a Go binary dependency.
"""

from __future__ import annotations

from typing import Any


def _deref(spec: dict, s: Any, depth: int = 0) -> Any:
    comps = ((spec.get("components") or {}).get("schemas") or {})
    if not isinstance(s, dict) or depth > 8:
        return s if isinstance(s, dict) else {}
    if "$ref" in s:
        return _deref(spec, comps.get(str(s["$ref"]).split("/")[-1], {}), depth + 1)
    return s


def audit_spec(spec: Any) -> list[dict[str, Any]]:
    """Return a list of audit findings: {type, severity, owasp, location, detail}."""
    issues: list[dict[str, Any]] = []
    if not isinstance(spec, dict):
        return issues

    def add(t: str, sev: str, owasp: str, loc: str, detail: str) -> None:
        issues.append({"type": t, "severity": sev, "owasp": owasp, "location": loc, "detail": detail})

    # --- global security schemes ---
    comps = spec.get("components") or {}
    schemes = (comps.get("securitySchemes") or {})
    global_security = spec.get("security")
    if not schemes:
        add("no_security_scheme", "high", "API2:2023", "components.securitySchemes",
            "Nenhum securityScheme definido no contrato — a API não modela autenticação.")
    for name, sc in schemes.items():
        sc = sc if isinstance(sc, dict) else {}
        t = str(sc.get("type") or "").lower()
        if t == "http" and str(sc.get("scheme") or "").lower() == "basic":
            add("weak_auth_basic", "medium", "API2:2023", f"securitySchemes.{name}", "HTTP Basic auth — credenciais em base64 reversível; preferir token/OAuth2.")
        if t == "apikey" and str(sc.get("in") or "").lower() == "query":
            add("apikey_in_query", "medium", "API2:2023", f"securitySchemes.{name}", "API key em QUERY string — vaza em logs/histórico; usar header.")

    # --- transport ---
    for srv in (spec.get("servers") or []):
        if isinstance(srv, dict) and str(srv.get("url") or "").startswith("http://"):
            add("insecure_transport", "medium", "API8:2023", "servers", f"Servidor em HTTP sem TLS: {srv.get('url')}.")

    # --- per operation ---
    paths = spec.get("paths") or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch") or not isinstance(op, dict):
                continue
            loc = f"{method.upper()} {path}"
            op_sec = op.get("security")
            # unauthenticated operation (no op-level and no global security)
            if op_sec == [] or (op_sec is None and not global_security and schemes):
                add("unauthenticated_operation", "high", "API2:2023", loc,
                    "Operação sem 'security' (e sem security global) — potencialmente acessível sem auth.")
            # parameters without constraints (resource consumption / injection surface)
            for pr in (op.get("parameters") or []):
                pr = _deref(spec, pr) if isinstance(pr, dict) and "$ref" in pr else pr
                if not isinstance(pr, dict):
                    continue
                sch = _deref(spec, pr.get("schema") or {})
                pname = pr.get("name")
                ptype = str(sch.get("type") or "")
                if ptype == "string" and "maxLength" not in sch and not sch.get("enum") and not sch.get("format"):
                    add("param_no_maxlength", "low", "API4:2023", loc, f"Parâmetro '{pname}' (string) sem maxLength/enum — risco de consumo de recurso.")
                if ptype == "integer" and "maximum" not in sch and "minimum" not in sch:
                    add("param_no_bounds", "low", "API4:2023", loc, f"Parâmetro '{pname}' (integer) sem minimum/maximum.")
                if ptype == "array" and "maxItems" not in sch:
                    add("param_no_maxitems", "low", "API4:2023", loc, f"Parâmetro '{pname}' (array) sem maxItems — DoS por payload grande.")
            # request body schema: additionalProperties / mass assignment
            rb = ((op.get("requestBody") or {}).get("content") or {})
            for _ct, media in rb.items():
                sch = _deref(spec, (media or {}).get("schema") or {})
                if sch.get("type") == "object" and sch.get("additionalProperties", True) is not False:
                    add("mass_assignment_risk", "medium", "API3:2023", loc,
                        "requestBody com additionalProperties não-restrito (!= false) — superfície de mass assignment/BOPLA.")
            # responses: undefined schema + missing auth/rate-limit responses
            responses = op.get("responses") or {}
            has_401 = any(str(c) in ("401", "403") for c in responses)
            has_429 = any(str(c) == "429" for c in responses)
            for code, r in responses.items():
                if not str(code).startswith("2"):
                    continue
                content = (_deref(spec, r).get("content") or {}) if isinstance(r, dict) else {}
                if content and not any((m or {}).get("schema") for m in content.values()):
                    add("response_no_schema", "medium", "API3:2023", loc, f"Resposta {code} sem schema definido — over-exposure não controlada.")
            if schemes and not has_401:
                add("no_auth_response_defined", "low", "API2:2023", loc, "Operação não declara resposta 401/403 — controle de auth não modelado.")
            if not has_429:
                add("no_ratelimit_response", "low", "API4:2023", loc, "Operação não declara resposta 429 — rate limiting não modelado no contrato.")

    # Deduplicate identical (type, location) to keep it clean.
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for i in issues:
        k = (i["type"], i["location"])
        if k in seen:
            continue
        seen.add(k)
        out.append(i)
    return out
