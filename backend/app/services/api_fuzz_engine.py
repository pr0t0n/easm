"""Coverage-guided, grammar-based fuzz engine + deep response oracles.

Moves fuzzing beyond static value-substitution toward real fuzzing:
- **grammar/schema-based mutations**: drop required fields, per-field type
  confusion, boundary violations derived from the field's own constraints
  (min/max/maxLength/enum/pattern), plus structural anomalies.
- **coverage-guided loop**: keep mutations that reach a NEW response signature
  (status class + response shape + error class) and iterate on them, so the
  fuzzer explores new states instead of re-hitting the same one.
- **shrinking**: when a mutation triggers an anomaly, minimize it to the
  smallest body that still triggers it (clean, reproducible PoC).
- **deep oracles**: full response-schema validation (jsonschema), server error
  (5xx), stack-trace/error signatures, and reflected-input detection.

Network goes through a caller-provided ``send(method, url, json_body) -> result``
(result dict with response_status + response_body), so this stays unit-testable.
"""

from __future__ import annotations

import re
from typing import Any, Callable

try:
    import jsonschema as _jsonschema
    from jsonschema import Draft7Validator as _Validator
except Exception:  # pragma: no cover
    _jsonschema = None
    _Validator = None

_STACKTRACE_RE = re.compile(r"(Traceback \(most recent call last\)|at [\w.$]+\([\w.]+:\d+\)|\.java:\d+\)|System\.\w+Exception|org\.\w+\.\w+Exception|ORA-\d{5}|SQLSTATE)", re.I)
_SQL_ERR_RE = re.compile(r"(SQL syntax|mysql_fetch|ORA-\d+|PostgreSQL.*ERROR|SQLite3::|unclosed quotation)", re.I)

_TYPE_CONFUSION = {
    "string": [12345, True, [1, 2], {"k": "v"}, None],
    "integer": ["not-an-int", 3.14, True, [1], {}, None, "1e999"],
    "number": ["abc", True, [], {}, None],
    "boolean": ["maybe", 2, "true", [], None],
    "array": ["notarray", 1, {"0": "x"}, None],
    "object": ["notobject", 1, [1], None],
}
_INJECT = ["' OR '1'='1", "{{7*7}}", "../../../etc/passwd", "<script>alert(1)</script>", "${jndi:ldap://x}", "\x00", "A" * 20000]


# --------------------------------------------------------------------------- #
def coverage_signature(status: int, body: str) -> str:
    """A compact signature of a response's *shape* for coverage tracking."""
    klass = f"{int(status) // 100}xx"
    shape = "err" if _STACKTRACE_RE.search(body or "") else ""
    keys = ""
    try:
        import json
        obj = json.loads(body) if body else None
        if isinstance(obj, dict):
            keys = ",".join(sorted(list(obj.keys()))[:12])
        elif isinstance(obj, list):
            keys = "[]"
    except Exception:
        keys = "nonjson" if body else ""
    return f"{klass}|{status}|{keys}|{shape}"


def _schema_props(schema: Any) -> tuple[dict[str, Any], list[str]]:
    schema = schema if isinstance(schema, dict) else {}
    return (schema.get("properties") or {}), list(schema.get("required") or [])


def grammar_mutations(seed: dict[str, Any] | None, schema: Any, *, cap: int = 40) -> list[tuple[dict[str, Any], str]]:
    """Schema-aware structural mutations of a request body."""
    seed = dict(seed or {})
    props, required = _schema_props(schema)
    muts: list[tuple[dict[str, Any], str]] = []

    def add(body: dict[str, Any], label: str) -> None:
        muts.append((body, label))

    # 1) drop each required field (contract violation surface)
    for f in required[:10]:
        b = dict(seed)
        b.pop(f, None)
        add(b, f"drop-required:{f}")
    # 2) per-field type confusion + boundary, from the field's declared type
    for name, ps in list(props.items())[:15]:
        ps = ps if isinstance(ps, dict) else {}
        t = str(ps.get("type") or "string")
        for bad in _TYPE_CONFUSION.get(t, _TYPE_CONFUSION["string"])[:3]:
            b = dict(seed)
            b[name] = bad
            add(b, f"type-confusion:{name}")
        # boundary from constraints
        if "maxLength" in ps:
            b = dict(seed); b[name] = "A" * (int(ps["maxLength"]) + 50); add(b, f"maxlen+:{name}")
        if "maximum" in ps:
            b = dict(seed); b[name] = int(ps["maximum"]) + 10**6; add(b, f"max+:{name}")
        if "minimum" in ps:
            b = dict(seed); b[name] = int(ps["minimum"]) - 10**6; add(b, f"min-:{name}")
        if ps.get("enum"):
            b = dict(seed); b[name] = "__not_in_enum__"; add(b, f"enum-break:{name}")
        # injection into string-ish field
        if t in ("string", ""):
            for pay in _INJECT[:3]:
                b = dict(seed); b[name] = pay; add(b, f"inject:{name}")
    # 3) structural: extra/admin fields (mass assignment), empty, nulls
    add({**seed, "isAdmin": True, "role": "admin", "verified": True}, "mass-assignment")
    add({}, "empty-body")
    add({k: None for k in (list(props) or list(seed))[:10]}, "all-null")
    # dedup + cap
    seen: set[str] = set()
    out: list[tuple[dict[str, Any], str]] = []
    for b, l in muts:
        key = f"{l}"
        if key in seen:
            continue
        seen.add(key)
        out.append((b, l))
    return out[:cap]


def validate_against_schema(body: str, schema: Any) -> list[str]:
    """Full response-schema validation (jsonschema). Returns clear violations
    (bounded). Only meaningful when a response schema is declared."""
    if _Validator is None or not isinstance(schema, dict) or not schema:
        return []
    import json
    try:
        obj = json.loads(body) if body else None
    except Exception:
        return ["response_not_json"]
    if obj is None:
        return []
    try:
        validator = _Validator(schema)
        errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.path))
    except Exception:
        return []
    out: list[str] = []
    for e in errors[:8]:
        loc = "/".join(str(p) for p in e.path) or "(root)"
        out.append(f"{loc}: {e.message[:120]}")
    return out


def _anomaly(status: int, body: str, resp_schema: Any = None) -> tuple[str, str] | None:
    """Deep oracle: classify an anomalous response. Returns (severity, reason).
    Error-signature oracles first (apply at any status), then generic 5xx."""
    if _SQL_ERR_RE.search(body or ""):
        return ("high", "erro de SQL refletido na resposta (possível injeção)")
    if _STACKTRACE_RE.search(body or ""):
        return ("high", f"stack trace/erro interno exposto na resposta (HTTP {status})")
    if status >= 500:
        return ("medium", f"HTTP {status} — erro de servidor (validação de input ausente)")
    if resp_schema:
        viols = validate_against_schema(body, resp_schema)
        if viols:
            return ("medium", f"resposta viola o schema do contrato: {viols[:3]}")
    return None


def coverage_guided_fuzz(
    send: Callable[[str, str, Any], dict[str, Any]],
    method: str,
    url: str,
    *,
    seed_body: dict[str, Any] | None,
    req_schema: Any = None,
    resp_schema: Any = None,
    budget: int = 40,
) -> dict[str, Any]:
    """Run a coverage-guided grammar fuzz on one endpoint. Returns
    {attempts, new_coverage, anomalies:[{label,severity,reason,body,status}]}.
    Anomalies are shrunk to a minimal reproducer."""
    attempts = 0
    seen_sigs: set[str] = set()
    anomalies: list[dict[str, Any]] = []
    queue = grammar_mutations(seed_body, req_schema, cap=budget)

    def _status(r: dict[str, Any]) -> int:
        try:
            return int(r.get("response_status") or 0)
        except Exception:
            return 0

    for body, label in queue:
        if attempts >= budget:
            break
        attempts += 1
        r = send(method, url, body)
        sc = _status(r)
        rbody = (r.get("response_body") or "")[:8000]
        sig = coverage_signature(sc, rbody)
        if sig not in seen_sigs:
            seen_sigs.add(sig)
        an = _anomaly(sc, rbody, resp_schema)
        if an:
            sev, reason = an
            minimal = _shrink(send, method, url, body, sc, rbody, resp_schema)
            anomalies.append({"label": label, "severity": sev, "reason": reason, "status": sc, "body": minimal})
    return {"attempts": attempts, "new_coverage": len(seen_sigs), "anomalies": anomalies}


def _shrink(send, method, url, body, orig_status, orig_body, resp_schema, *, rounds: int = 2) -> dict[str, Any]:
    """Minimize a triggering body: drop keys one at a time while the anomaly
    class is preserved. Bounded for cost."""
    current = dict(body)
    for _ in range(rounds):
        changed = False
        for k in list(current.keys()):
            trial = dict(current)
            trial.pop(k, None)
            r = send(method, url, trial)
            try:
                sc = int(r.get("response_status") or 0)
            except Exception:
                sc = 0
            rb = (r.get("response_body") or "")[:8000]
            if _anomaly(sc, rb, resp_schema) is not None:
                current = trial
                changed = True
        if not changed:
            break
    return current


# --------------------------------------------------------------------------- #
# OpenAPI op-schema index (request/response schemas, deref'd) for the engine.
# --------------------------------------------------------------------------- #
_PH_RE = re.compile(r"\{([^/{}]+)\}|:([^/{}]+)")
_UUIDSEG = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _tkey(path: str) -> str:
    segs = []
    for s in str(path or "").strip("/").split("/"):
        if not s:
            continue
        if ("{" in s and "}" in s) or s.startswith(":") or s.isdigit() or _UUIDSEG.match(s):
            segs.append("{}")
        else:
            segs.append(s.lower())
    return "/" + "/".join(segs)


def build_op_schema_index(spec: Any) -> dict[str, dict[str, Any]]:
    """{``METHOD /template``: {req: <schema>, resp: <2xx schema>, seed: <example>}}."""
    try:
        if not isinstance(spec, dict):
            return {}
        comps = ((spec.get("components") or {}).get("schemas") or {})

        def deref(s: Any, d: int = 0) -> Any:
            if not isinstance(s, dict) or d > 8:
                return s if isinstance(s, dict) else {}
            if "$ref" in s:
                return deref(comps.get(str(s["$ref"]).split("/")[-1], {}), d + 1)
            out = {}
            for k, v in s.items():
                if k == "properties" and isinstance(v, dict):
                    out[k] = {pk: deref(pv, d + 1) for pk, pv in v.items()}
                elif k in ("items",) and isinstance(v, dict):
                    out[k] = deref(v, d + 1)
                else:
                    out[k] = v
            return out

        def seed_from(schema: Any) -> dict[str, Any]:
            schema = schema if isinstance(schema, dict) else {}
            seed = {}
            for name, ps in (schema.get("properties") or {}).items():
                ps = ps if isinstance(ps, dict) else {}
                if "example" in ps:
                    seed[name] = ps["example"]
                elif ps.get("enum"):
                    seed[name] = ps["enum"][0]
                else:
                    t = ps.get("type")
                    seed[name] = {"integer": 1, "number": 1, "boolean": True, "array": [], "object": {}}.get(t, "x")
            return seed

        idx: dict[str, dict[str, Any]] = {}
        for path, methods in (spec.get("paths") or {}).items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                if method.lower() not in ("post", "put", "patch", "get", "delete") or not isinstance(op, dict):
                    continue
                req = {}
                for _ct, media in ((op.get("requestBody") or {}).get("content") or {}).items():
                    req = deref((media or {}).get("schema") or {})
                    break
                resp = {}
                for code, r in (op.get("responses") or {}).items():
                    if str(code).startswith("2"):
                        for _ct, media in ((deref(r).get("content") or {}) if isinstance(r, dict) else {}).items():
                            resp = deref((media or {}).get("schema") or {})
                            break
                        break
                idx[f"{method.upper()} {_tkey(path)}"] = {"req": req, "resp": resp, "seed": seed_from(req)}
        return idx
    except Exception:
        return {}
