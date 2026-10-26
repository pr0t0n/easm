"""Generate an OpenAPI 3.0 document from DISCOVERED/observed endpoints.

When the user provides no Swagger, the platform discovers the surface (route
brute-force, crawl, observed traffic) and this module turns that surface into a
real, downloadable OpenAPI 3.0 spec: path templates, methods, inferred
parameters (path/query/header), request-body schema inferred from observed
bodies, and responses inferred from observed status codes + bodies.

Technique inspired by mitmproxy2swagger (MIT), but emitting a full OpenAPI doc
(not just an inventory) so the user can download and reuse the JSON.

Pure/stdlib — unit-testable.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlparse

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_NUM_RE = re.compile(r"^\d+$")
_HEXID_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)


def _seg_is_id(seg: str) -> bool:
    return bool(_UUID_RE.match(seg) or _NUM_RE.match(seg) or _HEXID_RE.match(seg))


def _templatize(path: str) -> tuple[str, list[str]]:
    segs = [s for s in str(path or "").strip("/").split("/") if s]
    out: list[str] = []
    ids: list[str] = []
    n = 0
    for i, s in enumerate(segs):
        if _seg_is_id(s):
            prev = segs[i - 1].rstrip("s") if i > 0 else "id"
            name = f"{prev}Id" if prev.isalpha() else "id"
            if name in ids:
                n += 1
                name = f"{name}{n}"
            out.append("{" + name + "}")
            ids.append(name)
        else:
            out.append(s)
    return "/" + "/".join(out), ids


def _parse_json(body: Any) -> Any:
    if body is None or isinstance(body, (dict, list)):
        return body
    try:
        return json.loads(body)
    except Exception:
        return None


def infer_schema(value: Any, depth: int = 0) -> dict[str, Any]:
    """JSON value -> OpenAPI schema (recursive, bounded)."""
    if depth > 6:
        return {}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        fmt = _str_format(value)
        return {"type": "string", **({"format": fmt} if fmt else {})}
    if isinstance(value, list):
        return {"type": "array", "items": infer_schema(value[0], depth + 1) if value else {}}
    if isinstance(value, dict):
        props = {k: infer_schema(v, depth + 1) for k, v in list(value.items())[:50]}
        return {"type": "object", "properties": props}
    return {}


def _str_format(s: str) -> str:
    if _UUID_RE.match(s):
        return "uuid"
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", s):
        return "email"
    if re.match(r"^\d{4}-\d{2}-\d{2}T", s):
        return "date-time"
    if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
        return "date"
    if re.match(r"^https?://", s):
        return "uri"
    return ""


def _merge_schema(a: dict, b: dict) -> dict:
    """Merge two object schemas (union of properties)."""
    if not a:
        return b
    if not b:
        return a
    if a.get("type") == "object" and b.get("type") == "object":
        props = {**(a.get("properties") or {})}
        for k, v in (b.get("properties") or {}).items():
            props.setdefault(k, v)
        return {"type": "object", "properties": props}
    return a


def build_openapi_spec(rows: list[dict[str, Any]], *, title: str = "Discovered API", base_url: str = "") -> dict[str, Any]:
    """Build an OpenAPI 3.0 doc from discovered rows.

    Each row: {method, url, request_body?, request_headers?, query?, status_code?,
    response_body?}. Only method+url are required (discovered-only endpoints still
    appear, with a minimal operation).
    """
    paths: dict[str, dict[str, Any]] = {}
    servers: dict[str, None] = {}
    op_count = 0

    for row in rows or []:
        url = str(row.get("url") or "")
        if not url:
            continue
        method = str(row.get("method") or "GET").lower()
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            servers.setdefault(f"{parsed.scheme}://{parsed.netloc}", None)
        template, path_ids = _templatize(parsed.path)
        pitem = paths.setdefault(template, {})
        op = pitem.get(method)
        if op is None:
            op = {
                "summary": f"{method.upper()} {template} (descoberto)",
                "parameters": [],
                "responses": {},
                "x-discovered": True,
            }
            pitem[method] = op
            op_count += 1

        existing_params = {(p["in"], p["name"]) for p in op["parameters"]}

        def add_param(name: str, loc: str, example: Any = None, fmt: str = "") -> None:
            if (loc, name) in existing_params:
                return
            existing_params.add((loc, name))
            sch = {"type": "string", **({"format": fmt} if fmt else {})}
            p = {"name": name, "in": loc, "required": loc == "path", "schema": sch}
            if example not in (None, ""):
                p["example"] = str(example)[:80]
            op["parameters"].append(p)

        for pid in path_ids:
            add_param(pid, "path", fmt="uuid" if "Id" in pid else "")
        q = row.get("query")
        pairs = list(q.items()) if isinstance(q, dict) else parse_qsl(q if isinstance(q, str) else parsed.query, keep_blank_values=True)
        for k, v in pairs:
            add_param(str(k), "query", v)
        for hk in (row.get("request_headers") or {}):
            hl = str(hk).lower()
            if hl.startswith("x-") or hl in ("authorization", "api-key"):
                add_param(str(hk), "header")

        # request body schema (merged across observations)
        rb = _parse_json(row.get("request_body"))
        if rb is not None and method in ("post", "put", "patch"):
            new_schema = infer_schema(rb)
            cur = (((op.get("requestBody") or {}).get("content") or {}).get("application/json") or {}).get("schema") or {}
            op["requestBody"] = {"content": {"application/json": {"schema": _merge_schema(cur, new_schema)}}}

        # response
        sc = row.get("status_code")
        if sc is not None:
            code = str(int(sc))
            resp = op["responses"].setdefault(code, {"description": "Observado"})
            rbody = _parse_json(row.get("response_body"))
            if rbody is not None and 200 <= int(sc) < 300:
                new_schema = infer_schema(rbody)
                cur = (((resp.get("content") or {}).get("application/json") or {}).get("schema") or {})
                resp["content"] = {"application/json": {"schema": _merge_schema(cur, new_schema)}}
        if not op["responses"]:
            op["responses"]["default"] = {"description": "Descoberto (sem resposta observada)"}

    server_list = [{"url": base_url}] if base_url else [{"url": u} for u in servers] or [{"url": "/"}]
    return {
        "openapi": "3.0.3",
        "info": {
            "title": title,
            "version": "0.1.0-discovered",
            "description": (
                "Spec OpenAPI gerado AUTONOMAMENTE a partir da descoberta de endpoints "
                "(brute de rotas, crawl e tráfego observado) — ScriptKidd.o API module. "
                f"Gerado em {datetime.now(timezone.utc).isoformat()}. Schemas inferidos das amostras."
            ),
        },
        "servers": server_list,
        "paths": paths,
        "x-generated": {"by": "scriptkiddo-api-openapi-builder", "operations": op_count, "paths": len(paths)},
    }
