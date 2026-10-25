"""API flow graph + attack-path inference (static, no network).

Turns a flat list of API endpoints (from the ingested spec/crawl) into a
*flow model*: producer -> consumer edges, an operation lifecycle, the set of
variables that must be seeded externally, and ordered attack-paths that chain
endpoints through shared variables up to an observed finding.

Design goals:
- Pure and dependency-free (unit-testable in isolation, deterministic).
- Duck-typed input: each endpoint may be the runner's ``Endpoint`` dataclass or
  a plain ``dict`` with the same field names (method, url, parameters, tags,
  documented, metadata). This keeps tests trivial and avoids importing the heavy
  runner module (circular-import safe).

This answers "observe o fluxo, compreenda as variáveis, reutilize no processo":
the graph is what the platform *understands* about the operation, and the
attack-paths are how an attacker would chain it — rendered below the OWASP table.
"""

from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlparse

_PLACEHOLDER_RE = re.compile(r"\{([^/{}]+)\}")
_UUID_SEG_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

# Tokens that mark a variable/param as an object identifier (the BOLA surface).
_ID_TOKENS = ("id", "uuid", "request", "external", "order", "account", "customer", "tenant", "file", "project", "invoice", "transaction")
_CREATE_METHODS = {"POST", "PUT"}
_READ_METHODS = {"GET", "HEAD"}


# --------------------------------------------------------------------------- #
# small duck-typed accessors
# --------------------------------------------------------------------------- #
def _get(ep: Any, field: str, default: Any = None) -> Any:
    if isinstance(ep, dict):
        return ep.get(field, default)
    return getattr(ep, field, default)


def _method(ep: Any) -> str:
    return str(_get(ep, "method", "GET") or "GET").upper()


def _path(ep: Any) -> str:
    url = str(_get(ep, "url", "") or "")
    try:
        p = urlparse(url).path
    except Exception:
        p = url
    return p or url


def _template_key(path: str) -> str:
    """Collapse concrete/placeholder segments so variants share one key."""
    segs: list[str] = []
    for s in str(path or "").strip("/").split("/"):
        if not s:
            continue
        if ("{" in s and "}" in s) or s.isdigit() or _UUID_SEG_RE.match(s):
            segs.append("{}")
        else:
            segs.append(s.lower())
    return "/" + "/".join(segs)


def _is_id_name(name: str) -> bool:
    n = str(name or "").lower()
    return any(tok in n for tok in _ID_TOKENS)


def _placeholders(path: str) -> list[str]:
    return _PLACEHOLDER_RE.findall(path or "")


def _id_placeholders(path: str) -> list[str]:
    return [ph for ph in _placeholders(path) if _is_id_name(ph)]


def _param_names(ep: Any) -> list[str]:
    out: list[str] = []
    for p in list(_get(ep, "parameters", []) or []):
        name = p.get("name") if isinstance(p, dict) else getattr(p, "name", None)
        if name:
            out.append(str(name))
    return out


def _consumed_vars(ep: Any) -> list[str]:
    """Variables this endpoint needs as input: id-like path placeholders plus
    id-like parameter names (body/query) when the schema is available."""
    seen: dict[str, None] = {}
    for ph in _id_placeholders(_path(ep)):
        seen.setdefault(ph, None)
    for name in _param_names(ep):
        if _is_id_name(name):
            seen.setdefault(name, None)
    return list(seen.keys())


def _static_segments(path: str) -> list[str]:
    return [s.lower() for s in str(path or "").strip("/").split("/") if s and "{" not in s]


_VERSION_SEG_RE = re.compile(r"^v\d+$")


def _resource_root(path: str) -> str:
    """First meaningful resource segment, ignoring an api/version prefix.
    /api/v1/steps/result/{} -> 'steps'; /api/v1/know/customer -> 'know'."""
    for s in _static_segments(path):
        if s in ("api", "apis") or _VERSION_SEG_RE.match(s):
            continue
        return s
    return ""


def _common_prefix_len(a: list[str], b: list[str]) -> int:
    n = 0
    for x, y in zip(a, b):
        if x == y:
            n += 1
        else:
            break
    return n


def _stage(ep: Any) -> str:
    path = _path(ep).lower()
    method = _method(ep)
    if "/admin/" in path or path.endswith("/admin"):
        return "admin"
    if "/settings/" in path or "/config" in path:
        return "setup"
    if method == "DELETE":
        return "delete"
    if method in _READ_METHODS:
        return "read"
    if _consumed_vars(ep):
        return "step"          # state-changing action on an existing object
    if method in _CREATE_METHODS:
        return "create"        # creates a new object (produces an id)
    return "other"


_STAGE_ORDER = {"setup": 0, "create": 1, "step": 2, "read": 3, "admin": 4, "delete": 5, "other": 6}
_OWASP_BY_STAGE = {"admin": "API5:2023", "read": "API1:2023", "step": "API6:2023", "create": "API3:2023"}


def _node_id(ep: Any) -> str:
    return f"{_method(ep)} {_template_key(_path(ep))}"


# --------------------------------------------------------------------------- #
# graph
# --------------------------------------------------------------------------- #
def build_flow_graph(endpoints: Iterable[Any]) -> dict[str, Any]:
    """Infer producer->consumer edges and the operation lifecycle.

    Returns ``{nodes, edges, lifecycle, external_variables, stats}``.
    - A ``create`` endpoint (POST/PUT with no id consumed) *produces* the
      id-variable(s) of its resource group.
    - A ``step``/``read``/``admin`` endpoint *consumes* id-variables. We link it
      to the best-matching producer (exact resource base > longest static path
      prefix). Variables with no producer are reported as ``external_variables``
      (must be seeded via test_variables, e.g. a real requestId/projectId).
    """
    eps = [ep for ep in endpoints if ep is not None]
    # Deduplicate by node id, keep first.
    nodes_by_id: dict[str, dict[str, Any]] = {}
    raw_by_id: dict[str, Any] = {}
    for ep in eps:
        nid = _node_id(ep)
        if nid in nodes_by_id:
            continue
        raw_by_id[nid] = ep
        nodes_by_id[nid] = {
            "id": nid,
            "method": _method(ep),
            "path": _template_key(_path(ep)),
            "url": str(_get(ep, "url", "") or ""),
            "stage": _stage(ep),
            "consumes": _consumed_vars(ep),
            "produces": [],  # filled below
            "documented": bool(_get(ep, "documented", True)),
            "tags": [str(t).lower() for t in list(_get(ep, "tags", []) or [])],
            "owasp": _OWASP_BY_STAGE.get(_stage(ep), ""),
        }

    # Producers: create endpoints. Each is a candidate producer of the id-vars
    # consumed elsewhere in its resource group. We attribute a produced var name
    # to a creator by matching the consumer's var to a creator in the same group.
    creators = [n for n in nodes_by_id.values() if n["stage"] in ("create", "setup") and _method_of(n) in _CREATE_METHODS]

    # All id-vars consumed anywhere.
    consumed_vars: set[str] = set()
    for n in nodes_by_id.values():
        consumed_vars.update(n["consumes"])

    edges: list[dict[str, Any]] = []
    external_variables: set[str] = set()

    for consumer in nodes_by_id.values():
        for var in consumer["consumes"]:
            producer = _best_producer(var, consumer, creators)
            if producer is None:
                external_variables.add(var)
                continue
            if var not in producer["produces"]:
                producer["produces"].append(var)
            edges.append({
                "from": producer["id"],
                "to": consumer["id"],
                "variable": var,
                "kind": "produces",
            })

    # Lifecycle: stable order by stage then path, giving the operation timeline.
    lifecycle = [
        n["id"]
        for n in sorted(nodes_by_id.values(), key=lambda n: (_STAGE_ORDER.get(n["stage"], 9), n["path"], n["method"]))
    ]

    stats = {
        "nodes_total": len(nodes_by_id),
        "edges_total": len(edges),
        "by_stage": _count_by(nodes_by_id.values(), "stage"),
        "external_variables_total": len(external_variables),
    }
    return {
        "nodes": list(nodes_by_id.values()),
        "edges": edges,
        "lifecycle": lifecycle,
        "external_variables": sorted(external_variables),
        "stats": stats,
    }


def _method_of(node: dict[str, Any]) -> str:
    return str(node.get("method") or "GET").upper()


def _best_producer(var: str, consumer: dict[str, Any], creators: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick the creator most likely to produce ``var`` consumed by ``consumer``.

    Attribution is scoped to the resource group to avoid cross-group noise
    (``requestId`` and ``id`` are generic names shared by unrelated resources):

    - Tier 1 (same resource root): the creator under the same top-level resource
      as the consumer (e.g. ``POST /steps/flow`` for ``GET /steps/result/{id}``).
      Scored by longest static-path prefix; the exact resource base wins.
    - Tier 2 (cross-group reuse): only when NO same-root creator exists AND the
      creator's resource root appears as a segment of the consumer path (e.g.
      ``POST /steps/flow`` for ``POST /admin/steps/{requestId}/reprocess``).
    - Otherwise the variable has no producer -> reported as external (must be
      seeded via test_variables).

    A creator that itself consumes ``var`` is excluded (can't be its origin).
    """
    c_segs = _static_segments(consumer["path"])
    c_root = _resource_root(consumer["path"])
    c_seg_set = set(c_segs)

    def score_of(cr: dict[str, Any]) -> int:
        cr_segs = _static_segments(cr["path"])
        exact = len(cr_segs) > 0 and c_segs[: len(cr_segs)] == cr_segs
        score = _common_prefix_len(c_segs, cr_segs)
        if exact:
            score += 100
        # shorter (more "create-like") creators break ties upward
        score = score * 10 - len(cr_segs)
        return score

    def eligible(cr: dict[str, Any]) -> bool:
        return cr["id"] != consumer["id"] and var not in cr["consumes"]

    tier1 = [cr for cr in creators if eligible(cr) and _resource_root(cr["path"]) == c_root and c_root]
    if tier1:
        return max(tier1, key=score_of)
    tier2 = [cr for cr in creators if eligible(cr) and _resource_root(cr["path"]) in c_seg_set and _resource_root(cr["path"])]
    if tier2:
        return max(tier2, key=score_of)
    return None


def _count_by(nodes: Iterable[dict[str, Any]], field: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for n in nodes:
        out[str(n.get(field))] = out.get(str(n.get(field)), 0) + 1
    return out


# --------------------------------------------------------------------------- #
# attack paths
# --------------------------------------------------------------------------- #
def build_attack_paths(
    graph: dict[str, Any],
    findings: list[dict[str, Any]] | None = None,
    variables: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Chain graph nodes through shared variables into ordered attack-paths.

    A path ends at (or passes through) an endpoint with a finding when findings
    are supplied; otherwise at least one *potential* path is derived from the
    graph so the report always shows how the operation could be abused.

    Each path: ``{name, description, severity, owasp, confirmed, steps:[...]}``
    with steps ``{order, method, path, produces, consumes, result, owasp, severity, finding}``.
    """
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    edges = graph.get("edges", [])
    findings = findings or []

    # Index findings by node id (method+template) and by path template.
    find_by_node: dict[str, list[dict[str, Any]]] = {}
    find_by_path: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        path = _template_key(urlparse(str(f.get("url") or f.get("matched_at") or "")).path)
        method = str(f.get("method") or "").upper()
        if method:
            find_by_node.setdefault(f"{method} {path}", []).append(f)
        find_by_path.setdefault(path, []).append(f)

    def node_findings(nid: str) -> list[dict[str, Any]]:
        if nid in find_by_node:
            return find_by_node[nid]
        path = nodes.get(nid, {}).get("path", "")
        return find_by_path.get(path, [])

    # Direct edge maps (specific to the actual producer/consumer pair, so a
    # generic variable name does not drag in unrelated producers).
    producers_into: dict[str, list[tuple[str, str]]] = {}   # node id -> [(producer id, var)]
    consumers_from: dict[str, list[tuple[str, str]]] = {}    # node id -> [(consumer id, var)]
    for e in edges:
        producers_into.setdefault(e["to"], [])
        if (e["from"], e["variable"]) not in producers_into[e["to"]]:
            producers_into[e["to"]].append((e["from"], e["variable"]))
        consumers_from.setdefault(e["from"], [])
        if (e["to"], e["variable"]) not in consumers_from[e["from"]]:
            consumers_from[e["from"]].append((e["to"], e["variable"]))

    paths: list[dict[str, Any]] = []
    seen_chains: set[tuple[str, ...]] = set()

    def emit(chain_ids: list[str], reason: str) -> None:
        key = tuple(chain_ids)
        if not chain_ids or key in seen_chains:
            return
        seen_chains.add(key)
        steps = []
        worst = "info"
        confirmed = False
        owasps: list[str] = []
        for i, nid in enumerate(chain_ids, start=1):
            n = nodes.get(nid, {})
            fs = node_findings(nid)
            sev = _worst_sev([_sev(f) for f in fs]) if fs else ""
            if fs:
                worst = _worst_sev([worst, sev])
                if any(_is_confirmed(f) for f in fs):
                    confirmed = True
            owasp = (fs[0].get("owasp") if fs else "") or n.get("owasp") or ""
            if owasp:
                owasps.append(owasp)
            steps.append({
                "order": i,
                "method": n.get("method", ""),
                "path": n.get("path", ""),
                "produces": n.get("produces", []),
                "consumes": n.get("consumes", []),
                "result": (fs[0].get("title") or fs[0].get("summary") or "achado") if fs else _stage_hint(n.get("stage", "")),
                "owasp": owasp,
                "severity": sev or ("info" if not fs else sev),
                "finding": bool(fs),
            })
        names = " → ".join(f"{s['method']} {s['path']}" for s in steps)
        paths.append({
            "name": reason,
            "description": names,
            "severity": worst,
            "owasp": sorted(set(o for o in owasps if o)),
            "confirmed": confirmed,
            "steps": steps,
        })

    # 1) Paths that terminate on a finding: creator(s) of the finding's consumed
    #    vars -> finding node -> any admin consumer that reuses a produced var.
    finding_nodes = [nid for nid in nodes if node_findings(nid)]
    for nid in finding_nodes:
        n = nodes[nid]
        chain: list[str] = []
        # prepend the DIRECT producer(s) that feed this node (one per variable)
        for pid, _var in producers_into.get(nid, []):
            if pid not in chain:
                chain.append(pid)
        chain.append(nid)
        # extend to an admin/step node that reuses the SAME identifier — either a
        # var this node produces, or a sibling consumer of this node's producer
        # (e.g. result[BOLA] + admin/steps/reprocess[BFLA] both reuse requestId).
        extend_from = [nid] + [pid for pid, _v in producers_into.get(nid, [])]
        extended = False
        for src in extend_from:
            if extended:
                break
            for cid, _var in consumers_from.get(src, []):
                cnode = nodes.get(cid, {})
                if cid not in chain and cnode.get("stage") in ("admin", "step"):
                    chain.append(cid)
                    extended = True
                    break
        emit(chain, f"Cadeia até achado: {n.get('method')} {n.get('path')}")

    # 2) Always-on potential path: longest create -> step -> read -> admin chain
    #    linked by a shared variable, even with no findings yet.
    potential = _longest_potential_chain(nodes, edges)
    if potential:
        emit(potential, "Attack-path potencial (derivado do fluxo)")

    # Sort: confirmed first, then by severity.
    paths.sort(key=lambda p: (0 if p["confirmed"] else 1, -_SEV_RANK.get(p["severity"], 0)))
    return paths


def _stage_hint(stage: str) -> str:
    return {
        "create": "cria objeto / retorna identificador",
        "step": "ação sobre objeto existente (reusa identificador)",
        "read": "lê objeto por identificador (superfície BOLA)",
        "admin": "função administrativa (superfície BFLA)",
        "setup": "configura o projeto",
        "delete": "remove objeto por identificador",
    }.get(stage, "")


def _longest_potential_chain(nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]]) -> list[str]:
    """Find a representative create->...->read/admin chain following edges."""
    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e["from"], []).append(e["to"])
    best: list[str] = []
    starts = [nid for nid, n in nodes.items() if n.get("stage") in ("create", "setup")] or list(nodes.keys())

    def walk(nid: str, acc: list[str], visited: set[str]) -> None:
        nonlocal best
        acc = acc + [nid]
        if len(acc) > len(best):
            best = acc
        for nxt in adj.get(nid, []):
            if nxt not in visited and len(acc) < 6:
                walk(nxt, acc, visited | {nxt})

    for s in starts:
        walk(s, [], {s})
    return best if len(best) >= 2 else []


# --------------------------------------------------------------------------- #
# severity helpers
# --------------------------------------------------------------------------- #
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "": 0}


def _sev(f: dict[str, Any]) -> str:
    return str(f.get("severity") or "info").lower()


def _worst_sev(sevs: list[str]) -> str:
    best = ""
    for s in sevs:
        if _SEV_RANK.get(s, 0) > _SEV_RANK.get(best, 0):
            best = s
    return best or "info"


def _is_confirmed(f: dict[str, Any]) -> bool:
    vs = str(f.get("verification") or f.get("verification_status") or "").lower()
    if vs == "confirmed":
        return True
    try:
        sc = int(f.get("http_status") or 0)
    except Exception:
        sc = 0
    return 200 <= sc < 400
