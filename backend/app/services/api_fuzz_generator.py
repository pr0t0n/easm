"""Schema-driven fuzz value generator.

Replaces the thin hand-rolled candidate set (~6 values/param) with a real,
schema-aware generator: it reads each variable's OpenAPI/JSON-Schema shape
(type, format, enum, min/max, pattern) and emits a rich set of values —
format-valid samples, boundary values, malformed/type-confusion inputs, common
injection payloads, and id-enumeration candidates for BOLA/IDOR.

No heavy dependency: uses ``jsonschema`` (already present) only for light schema
inspection. This is the data/volume layer the previous fuzzer lacked.

Each generator returns ``(value, label)`` tuples so the runner can tag findings
with the fuzz class that triggered them.
"""

from __future__ import annotations

import uuid as _uuidlib
from typing import Any

# --------------------------------------------------------------------------- #
# Value pools (the "how many informations" — real volume, not 6 hand values)
# --------------------------------------------------------------------------- #
_SAMPLE_UUIDS = [
    "05be75cc-8f8a-414a-891f-434aa9b4e7a5",
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "11111111-1111-1111-1111-111111111111",
]
# Object-id enumeration for BOLA/IDOR (cross-owner access attempts).
_ID_ENUM = [
    "1", "2", "3", "4", "5", "10", "42", "100", "1000", "99999", "0", "-1",
    "9999999999", "admin", "test", "null", "undefined",
]
_EMAILS = ["test@example.com", "admin@example.com", "a@a.co", "victim@valid.com"]
_CPFS = ["11144477735", "00000000191", "12345678909"]
_DATES = ["2020-01-01", "1970-01-01", "2999-12-31", "0001-01-01"]
_DATETIMES = ["2020-01-01T00:00:00Z", "1970-01-01T00:00:00Z", "2999-12-31T23:59:59Z"]
_URIS = ["http://example.com", "https://169.254.169.254/latest/meta-data/", "file:///etc/passwd"]

# Malformed / boundary / attack payloads (type confusion, overflow, injection).
_STRING_ATTACKS = [
    "", " ", "A" * 5000, "A" * 100000,                      # empty / oversized
    "' OR '1'='1", "\" OR \"1\"=\"1", "1; DROP TABLE users--",  # SQLi
    "{\"$gt\": \"\"}", "{\"$ne\": null}",                   # NoSQLi
    "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",  # path traversal
    "${7*7}", "{{7*7}}", "#{7*7}",                          # SSTI
    "<script>alert(1)</script>", "javascript:alert(1)",     # XSS
    "; cat /etc/passwd", "| id", "$(id)", "`id`",          # command injection
    "%00", "\x00", "\n\r", "٠١٢٣", "😀", "‮",           # null/encoding/unicode
    "-1", "0", "true", "false", "null", "[]", "{}", "NaN", "Infinity",
]
_NUMBER_ATTACKS = [0, -1, 1, 2147483647, 2147483648, -2147483648,
                   9223372036854775807, 9999999999999999999, 1.7976931348623157e308,
                   -0.0, 0.1 + 0.2]
# Type-confusion: send a value whose JSON type differs from the schema's.
_TYPE_CONFUSION = {
    "string": [123, True, ["x"], {"k": "v"}, None],
    "integer": ["not-a-number", "1e9", "0x10", True, [1], {"n": 1}, None, 3.14],
    "number": ["abc", True, [1.0], {}, None],
    "boolean": ["yes", 1, 0, "true", [], None],
    "array": ["notarray", 1, {"0": "x"}, None],
    "object": ["notobject", 1, ["x"], None],
}


def _rand_uuid() -> str:
    return str(_uuidlib.uuid4())


# --------------------------------------------------------------------------- #
def _format_valid_values(fmt: str, name: str) -> list[str]:
    fmt = (fmt or "").lower()
    n = (name or "").lower()
    if fmt == "uuid" or "uuid" in n or "requestid" in n or "projectid" in n:
        return _SAMPLE_UUIDS + [_rand_uuid()]
    if fmt == "email" or "email" in n:
        return list(_EMAILS)
    if fmt in ("date-time", "datetime"):
        return list(_DATETIMES)
    if fmt == "date":
        return list(_DATES)
    if fmt in ("uri", "url") or "url" in n:
        return list(_URIS)
    if "cpf" in n:
        return list(_CPFS)
    return []


def fuzz_values_for_param(param: dict[str, Any], *, aggressive: bool = False, cap: int = 24) -> list[tuple[Any, str]]:
    """Return ``(value, label)`` fuzz candidates for one parameter/field.

    ``param`` carries at least ``name`` and optionally ``type_hint``/``schema``/
    ``format``/``enum``/``sample_value``. Produces format-valid samples, enum
    values, boundary values, type-confusion and injection payloads, plus id
    enumeration for id-like names. ``cap`` bounds the count (safe default);
    ``aggressive`` lifts it and adds the heavy payloads.
    """
    name = str(param.get("name") or "")
    schema = param.get("schema") if isinstance(param.get("schema"), dict) else {}
    type_hint = str(param.get("type_hint") or schema.get("type") or "").lower()
    fmt = str(param.get("format") or schema.get("format") or "")
    enum = param.get("enum") or schema.get("enum") or []
    sample = str(param.get("sample_value") or "").strip()
    nlow = name.lower()

    out: list[tuple[Any, str]] = []
    seen: set[str] = set()

    def add(v: Any, label: str) -> None:
        key = f"{label}:{v!r}"[:200]
        if key in seen:
            return
        seen.add(key)
        out.append((v, label))

    # 1) valid-ish values (so a well-formed request can reach the object layer)
    if sample and "{" not in sample:
        add(sample, "valid:spec-example")
    for v in _format_valid_values(fmt, name):
        add(v, f"valid:{fmt or 'fmt'}")
    for v in list(enum)[:8]:
        add(v, "valid:enum")
    # 2) id enumeration (BOLA/IDOR: other owners' objects)
    if nlow.endswith("id") or any(t in nlow for t in ("id", "request", "external", "order", "account", "customer", "tenant", "file", "project")):
        for v in _ID_ENUM:
            add(v, "idor:enum")
        for v in _SAMPLE_UUIDS:
            add(v, "idor:uuid")
    # 3) boundary / type-confusion / injection by declared type
    base_type = type_hint or ("integer" if nlow.endswith("id") and not fmt else "string")
    if base_type in ("integer", "number"):
        for v in _NUMBER_ATTACKS:
            add(v, "boundary:number")
    else:
        for v in _STRING_ATTACKS[: (len(_STRING_ATTACKS) if aggressive else 14)]:
            add(v, "malformed:string")
    for v in _TYPE_CONFUSION.get(base_type, _TYPE_CONFUSION["string"]):
        add(v, "type-confusion")

    # Keep valid + idor first (most useful), then the rest, bounded by cap.
    priority = {"valid": 0, "idor": 1}
    out.sort(key=lambda t: priority.get(t[1].split(":")[0], 2))
    limit = cap * 3 if aggressive else cap
    return out[:limit]


def discover_variables(spec: Any) -> dict[str, list[dict[str, Any]]]:
    """Identify EVERY variable of an OpenAPI spec, keyed by ``METHOD /path``:
    path/query/header params + request-body leaf fields, each with name,
    location, type, format and enum — so the fuzzer can test them all."""
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

        def leaves(schema: Any, prefix: str = "", d: int = 0) -> list[dict[str, Any]]:
            schema = deref(schema, d)
            found: list[dict[str, Any]] = []
            if not isinstance(schema, dict) or d > 8:
                return found
            for comb in ("allOf", "oneOf", "anyOf"):
                for sub in (schema.get(comb) or []):
                    found += leaves(sub, prefix, d + 1)
            props = schema.get("properties") or {}
            for k, v in props.items():
                vd = deref(v, d + 1)
                nm = f"{prefix}{k}"
                if (vd.get("type") == "object" or vd.get("properties")) and d < 6:
                    found += leaves(vd, f"{nm}.", d + 1)
                else:
                    found.append({"name": nm, "location": "body", "type_hint": str(vd.get("type") or ""),
                                  "format": str(vd.get("format") or ""), "enum": vd.get("enum") or []})
            if "items" in schema:
                found += leaves(schema["items"], prefix, d + 1)
            return found

        out: dict[str, list[dict[str, Any]]] = {}
        for path, methods in (spec.get("paths") or {}).items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch") or not isinstance(op, dict):
                    continue
                vrs: list[dict[str, Any]] = []
                for pr in (op.get("parameters") or []):
                    pr = deref(pr) if isinstance(pr, dict) and "$ref" in pr else pr
                    if isinstance(pr, dict) and pr.get("name"):
                        sc = deref(pr.get("schema") or {})
                        vrs.append({"name": str(pr["name"]), "location": str(pr.get("in") or "query"),
                                    "type_hint": str(sc.get("type") or ""), "format": str(sc.get("format") or ""),
                                    "enum": sc.get("enum") or []})
                rb = ((op.get("requestBody") or {}).get("content") or {})
                for _ct, media in rb.items():
                    vrs += leaves((media or {}).get("schema", {}))
                out[f"{method.upper()} {path}"] = vrs
        return out
    except Exception:
        return {}
