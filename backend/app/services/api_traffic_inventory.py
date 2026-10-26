"""Derive a testable API inventory from observed TRAFFIC (no spec required).

Technique from mitmproxy2swagger (MIT): when the user provides NO OpenAPI spec,
reverse-engineer one from captured requests/responses (Caido replay history,
crawler, browser traffic). This makes the platform test ANY API autonomously —
point it at a host, let it observe/crawl, and derive the surface to fuzz.

Output shapes match what the skills already consume:
  endpoints:   [{method, path(template), url, parameters:[{name,location,type_hint,sample_value}]}]
  conformance: {METHOD /template: {statuses:set, by_status:{code:(fields,required)}}}

Pure/stdlib — no network, unit-testable.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_NUM_RE = re.compile(r"^\d+$")
_HEXID_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)


def _seg_is_id(seg: str) -> bool:
    return bool(_UUID_RE.match(seg) or _NUM_RE.match(seg) or _HEXID_RE.match(seg))


def _templatize(path: str) -> tuple[str, list[tuple[int, str]]]:
    """Collapse id-like segments to {id}/{id2}/... Returns (template, [(idx,name)])."""
    segs = [s for s in str(path or "").strip("/").split("/") if s]
    out: list[str] = []
    ids: list[tuple[int, str]] = []
    counter = 0
    for i, s in enumerate(segs):
        if _seg_is_id(s):
            prev = segs[i - 1].rstrip("s") if i > 0 else "id"
            name = f"{prev}Id" if prev.isalpha() else "id"
            if any(n == name for _, n in ids):
                counter += 1
                name = f"{name}{counter}"
            out.append("{" + name + "}")
            ids.append((i, name))
        else:
            out.append(s)
    return "/" + "/".join(out), ids


def _type_of(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _leaf_fields(obj: Any, prefix: str = "", depth: int = 0) -> dict[str, str]:
    """Flatten a JSON object into {field: type}, one level of nesting for data/result."""
    out: dict[str, str] = {}
    if depth > 4:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out[str(k)] = _type_of(v)
            if str(k).lower() in ("data", "result", "content", "items") and isinstance(v, (dict, list)):
                out.update(_leaf_fields(v, f"{k}.", depth + 1))
    elif isinstance(obj, list) and obj:
        out.update(_leaf_fields(obj[0], prefix, depth + 1))
    return out


def _parse_json(body: Any) -> Any:
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return body
    try:
        return json.loads(body)
    except Exception:
        return None


def derive_inventory_from_traffic(observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Build an endpoint inventory + conformance index from observed requests.

    ``observations``: list of dicts with any of: method, url, query (dict/str),
    request_headers (dict), request_body (str/obj), response_status (int),
    response_body (str/obj). Only url+method are required.
    """
    endpoints: dict[str, dict[str, Any]] = {}
    conformance: dict[str, dict[str, Any]] = {}

    for obs in observations or []:
        url = str(obs.get("url") or "")
        if not url:
            continue
        method = str(obs.get("method") or "GET").upper()
        parsed = urlparse(url)
        template, _ids = _templatize(parsed.path)
        key = f"{method} {template}"
        ep = endpoints.setdefault(key, {
            "method": method,
            "path": template,
            "url": f"{parsed.scheme}://{parsed.netloc}{template}" if parsed.scheme else template,
            "_params": {},
        })
        params: dict[str, dict[str, Any]] = ep["_params"]

        # path params
        for _idx, name in _ids:
            params.setdefault(name, {"name": name, "location": "path", "type_hint": "string", "sample_value": ""})
        # query params
        q = obs.get("query")
        pairs = list(q.items()) if isinstance(q, dict) else parse_qsl(q if isinstance(q, str) else parsed.query, keep_blank_values=True)
        for k, v in pairs:
            params.setdefault(str(k), {"name": str(k), "location": "query", "type_hint": "string", "sample_value": str(v)[:40]})
        # header params (only custom x-* / auth-ish, skip standard)
        for hk in (obs.get("request_headers") or {}):
            hl = str(hk).lower()
            if hl.startswith("x-") or hl in ("authorization", "api-key"):
                params.setdefault(str(hk), {"name": str(hk), "location": "header", "type_hint": "string", "sample_value": ""})
        # body fields
        rb = _parse_json(obs.get("request_body"))
        for f, t in _leaf_fields(rb).items():
            params.setdefault(f, {"name": f, "location": "json", "type_hint": t, "sample_value": ""})

        # conformance: observed status + response fields
        sc = obs.get("response_status")
        if sc is not None:
            ce = conformance.setdefault(key, {"statuses": set(), "by_status": {}})
            ce["statuses"].add(str(int(sc)))
            resp = _parse_json(obs.get("response_body"))
            if resp is not None and 200 <= int(sc) < 300:
                fields = set(_leaf_fields(resp).keys())
                prev = ce["by_status"].get(str(int(sc)))
                merged = (prev[0] | fields) if prev else fields
                ce["by_status"][str(int(sc))] = (merged, set())

    out_eps = []
    for ep in endpoints.values():
        ep["parameters"] = list(ep.pop("_params").values())
        out_eps.append(ep)
    return {
        "endpoints": out_eps,
        "conformance": conformance,
        "stats": {
            "endpoints": len(out_eps),
            "parameters": sum(len(e["parameters"]) for e in out_eps),
            "from_observations": len(observations or []),
        },
    }
