"""Contract conformance checking (autonomous, no credentials).

Compares a live response against the OpenAPI contract: undocumented status codes,
response fields NOT declared in the schema (silent data over-exposure / drift),
and declared-required fields missing. Complements shadow discovery with "the
implementation diverges from its own contract". Uses only the spec + observed
responses — runs fully on its own.
"""

from __future__ import annotations

import re
from typing import Any

_PLACEHOLDER_RE = re.compile(r"\{([^/{}]+)\}|:([^/{}]+)")
_UUID_SEG_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _template_key(path: str) -> str:
    segs: list[str] = []
    for s in str(path or "").strip("/").split("/"):
        if not s:
            continue
        if ("{" in s and "}" in s) or s.startswith(":") or s.isdigit() or _UUID_SEG_RE.match(s):
            segs.append("{}")
        else:
            segs.append(s.lower())
    return "/" + "/".join(segs)


def build_conformance_index(spec: Any) -> dict[str, dict[str, Any]]:
    """Per operation (``METHOD /template``): declared 2xx/other status codes and
    the top-level fields + required fields of each response schema."""
    try:
        if not isinstance(spec, dict):
            return {}
        comps = ((spec.get("components") or {}).get("schemas") or {})

        def deref(s: Any, d: int = 0) -> Any:
            if not isinstance(s, dict) or d > 8:
                return s if isinstance(s, dict) else {}
            if "$ref" in s:
                return deref(comps.get(str(s["$ref"]).split("/")[-1], {}), d + 1)
            return s

        def schema_fields(schema: Any, d: int = 0) -> tuple[set[str], set[str]]:
            schema = deref(schema, d)
            props: set[str] = set()
            required: set[str] = set()
            if not isinstance(schema, dict) or d > 8:
                return props, required
            for comb in ("allOf", "oneOf", "anyOf"):
                for sub in (schema.get(comb) or []):
                    p, r = schema_fields(sub, d + 1)
                    props |= p
                    required |= r
            if isinstance(schema.get("properties"), dict):
                props |= set(schema["properties"].keys())
            if isinstance(schema.get("required"), list):
                required |= {str(x) for x in schema["required"]}
            # unwrap common envelope
            for wrap in ("data", "result", "content"):
                if wrap in (schema.get("properties") or {}):
                    p, r = schema_fields(schema["properties"][wrap], d + 1)
                    props |= p
            if "items" in schema:
                p, r = schema_fields(schema["items"], d + 1)
                props |= p
            return props, required

        index: dict[str, dict[str, Any]] = {}
        for path, methods in (spec.get("paths") or {}).items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch") or not isinstance(op, dict):
                    continue
                statuses: set[str] = set()
                by_status: dict[str, tuple[set[str], set[str]]] = {}
                for code, r in (op.get("responses") or {}).items():
                    statuses.add(str(code))
                    fields: set[str] = set()
                    reqd: set[str] = set()
                    for _ct, media in ((deref(r).get("content") or {}) if isinstance(r, dict) else {}).items():
                        p, rq = schema_fields((media or {}).get("schema", {}))
                        fields |= p
                        reqd |= rq
                    by_status[str(code)] = (fields, reqd)
                index[f"{method.upper()} {_template_key(path)}"] = {
                    "statuses": statuses,
                    "by_status": by_status,
                }
        return index
    except Exception:
        return {}


def _top_level_keys(body: Any) -> set[str]:
    import json
    try:
        obj = json.loads(body) if isinstance(body, (str, bytes)) else body
    except Exception:
        return set()
    if isinstance(obj, dict):
        keys = set(obj.keys())
        # unwrap envelope one level for comparison
        for wrap in ("data", "result", "content"):
            if isinstance(obj.get(wrap), dict):
                keys |= set(obj[wrap].keys())
            if isinstance(obj.get(wrap), list) and obj[wrap] and isinstance(obj[wrap][0], dict):
                keys |= set(obj[wrap][0].keys())
        return {str(k) for k in keys}
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        return {str(k) for k in obj[0].keys()}
    return set()


def check_response(entry: dict[str, Any], status: int, body: str) -> list[dict[str, Any]]:
    """Return conformance issues for one live response vs its contract entry."""
    issues: list[dict[str, Any]] = []
    if not entry:
        return issues
    statuses = entry.get("statuses") or set()
    scode = str(int(status))
    # 1) undocumented status code (ignore auth/not-found which are implicit)
    if statuses and scode not in statuses and not any(scode.startswith(p) for p in ("401", "403", "404")):
        # allow a documented "default" or class match (2XX)
        klass = scode[0] + "XX"
        if klass not in {str(s).upper() for s in statuses} and "default" not in {str(s).lower() for s in statuses}:
            issues.append({"type": "undocumented_status", "severity": "low", "detail": f"HTTP {scode} não está declarado no contrato (declarados: {sorted(statuses)})."})
    # 2) response fields vs declared schema (only for 2xx with a declared schema)
    if 200 <= status < 300:
        declared = (entry.get("by_status") or {}).get(scode)
        if declared is None:
            declared = (entry.get("by_status") or {}).get(scode[0] + "XX") or (entry.get("by_status") or {}).get("default")
        if declared:
            decl_fields, required = declared
            actual = _top_level_keys(body)
            if decl_fields:
                extra = sorted(actual - decl_fields)
                if extra:
                    issues.append({"type": "undocumented_response_field", "severity": "medium", "detail": f"Campos retornados fora do contrato (possível over-exposure): {extra[:15]}."})
                missing = sorted(required - actual)
                if missing:
                    issues.append({"type": "missing_required_field", "severity": "low", "detail": f"Campos obrigatórios do contrato ausentes na resposta: {missing[:15]}."})
    return issues
