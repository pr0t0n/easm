"""Per-endpoint API security report — the "forest" view.

Aggregates, for a given API test (ScanJob mode=api), every documented endpoint
and validates the QUALITY of testing PER ENDPOINT: which OWASP API skills hit
it, with which identities, what HTTP responses came back, and what findings
were produced. Also surfaces the full OWASP API Top 20 test catalog (which
tests exist, which ran) and a Broken Access Control (BOLA/BFLA/BOPLA) focus.

Data sources (all already produced by the existing engine):
  - OffensiveEndpoint (source api-spec/openapi/...) = the documented surface.
  - api-skill-top20 work items -> result.parsed_result.response_observations
    ({method, endpoint, skill_id, http_status, identity_key, ok}) and
    skill_results.
  - Finding rows (tool=api-skill-top20/zap-api, url + details.api_skill_id).
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.models import Finding, OffensiveEndpoint, ScanJob, ScanWorkItem
from app.services.api_flow_graph import build_attack_paths, build_flow_graph, parse_spec_flow_hints
from app.services.api_skill_coverage import API_SPEC_SOURCES, _is_api_skill_item, _parsed_result
from app.services.api_skill_top20_runner import load_api_top20_skills

# Broken Access Control family (the user's primary focus): object-level (BOLA),
# function-level (BFLA) and property-level (BOPLA / mass assignment).
BAC_SKILL_IDS = {
    "skill.api.bola_idor",
    "skill.api.bfla_privilege_escalation",
    "skill.api.bopla",
    "skill.api.mass_assignment",
}
API_FINDING_TOOLS = {"api-skill-top20", "zap-api"}


def _path_of(url: Any) -> str:
    try:
        p = urlparse(str(url or "")).path or "/"
    except Exception:
        p = "/"
    return p.rstrip("/") or "/"


def _template_regex(path_template: str) -> re.Pattern[str]:
    # /api/orders/{id} -> ^/api/orders/[^/]+$  (match concrete values)
    norm = _path_of(path_template)
    escaped = re.escape(norm)
    # un-escape the {param} placeholders re.escape turned into \{param\}
    escaped = re.sub(r"\\\{[^/}]+\\\}", r"[^/]+", escaped)
    return re.compile("^" + escaped + "$")


def _skill_catalog() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for s in load_api_top20_skills().get("skills", []):
        sid = str(s.get("id") or "")
        if not sid:
            continue
        out[sid] = {
            "id": sid,
            "name": s.get("name") or sid,
            "owasp": s.get("owasp") or s.get("category") or "",
            "priority": int(s.get("priority") or 999),
            "is_bac": sid in BAC_SKILL_IDS,
        }
    return out


def _quality(tested: bool, skills: set[str], real_responses: int, bac_tested: bool, findings: int) -> dict[str, Any]:
    if not tested:
        return {"score": 0, "label": "não testado", "level": "none"}
    score = 0
    score += min(60, len(skills) * 6)          # breadth of skills (cap 60)
    score += 20 if real_responses > 0 else 0   # got real HTTP responses
    score += 20 if bac_tested else 0           # BAC coverage (user focus)
    score = min(100, score)
    if score >= 75:
        level = "good"
    elif score >= 40:
        level = "partial"
    else:
        level = "weak"
    label = {"good": "completo", "partial": "parcial", "weak": "superficial"}[level]
    return {"score": score, "label": label, "level": level}


def build_api_endpoint_report(db: Session, job: ScanJob) -> dict[str, Any]:
    catalog = _skill_catalog()

    # 1) The forest: BOTH spec-documented AND crawler-discovered endpoints.
    # Do not trust only the Swagger — active discovery (P03/P04/P08 crawlers)
    # populates OffensiveEndpoint with other source_tools; include them all and
    # tag the origin (spec vs crawled) so undocumented/shadow endpoints surface.
    endpoints = (
        db.query(OffensiveEndpoint)
        .filter(OffensiveEndpoint.scan_job_id == int(job.id))
        .all()
    )
    docs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for ep in endpoints:
        method = str(getattr(ep, "method", "") or "GET").upper()
        url = str(getattr(ep, "normalized_url", None) or getattr(ep, "url", "") or "")
        path = _path_of(url)
        key = (method, path)
        if not url or key in seen:
            continue
        seen.add(key)
        src = str(getattr(ep, "source_tool", "") or "").lower()
        origin = "spec" if src in API_SPEC_SOURCES else "crawled"
        docs.append({"method": method, "url": url, "path": path, "regex": _template_regex(path), "source": origin})

    # 2) Observations + skill_results from api-skill-top20 items.
    items = (
        db.query(ScanWorkItem)
        .filter(ScanWorkItem.scan_job_id == int(job.id))
        .all()
    )
    observations: list[dict[str, Any]] = []
    executed_skills: set[str] = set()
    dynamic_flow: dict[str, Any] = {}
    for item in items:
        if not _is_api_skill_item(item):
            continue
        parsed = _parsed_result(item)
        if isinstance(parsed.get("api_flow"), dict) and parsed["api_flow"]:
            dynamic_flow = parsed["api_flow"]
        sid = str(parsed.get("api_skill_id") or parsed.get("skill_id") or "")
        status = str(getattr(item, "status", "") or "").lower()
        if sid and status in {"completed", "done"}:
            executed_skills.add(sid)
        obs = [o for o in list(parsed.get("response_observations") or []) if isinstance(o, dict)]
        for sr in list(parsed.get("skill_results") or []):
            if isinstance(sr, dict):
                srid = str(sr.get("skill_id") or sid or "")
                if srid and status in {"completed", "done"}:
                    executed_skills.add(srid)
                for o in list(sr.get("observations") or []):
                    if isinstance(o, dict):
                        o = {**o, "skill_id": o.get("skill_id") or srid}
                        obs.append(o)
        observations.extend(obs)

    # 3) API findings.
    findings = (
        db.query(Finding)
        .filter(Finding.scan_job_id == int(job.id), Finding.is_false_positive.is_(False))
        .all()
    )
    api_findings = []
    for f in findings:
        det = dict(getattr(f, "details", None) or {})
        tool = str(getattr(f, "tool", "") or "").lower()
        sid = str(det.get("api_skill_id") or "")
        if tool in API_FINDING_TOOLS or sid.startswith("skill.api."):
            _vs = str(det.get("verification_status") or "candidate")
            _http = det.get("http_status") or (det.get("response_fingerprint") or {}).get("status_code")
            _advisory = bool(det.get("advisory")) or _vs == "advisory"
            # Regra dura: achado de BAC/BOLA só é "positivo" com acesso real
            # (resposta 2xx/3xx) ou confirmado. 401/403/404 => advisory (design),
            # nunca positivo — exatamente o ponto levantado.
            if (sid in BAC_SKILL_IDS) and _vs != "confirmed":
                if not (isinstance(_http, int) and 200 <= _http < 400):
                    _advisory = True
            api_findings.append({
                "url": str(getattr(f, "url", "") or det.get("url") or det.get("matched_at") or ""),
                "path": _path_of(getattr(f, "url", "") or det.get("url") or det.get("matched_at") or ""),
                "severity": str(getattr(f, "severity", "") or "low").lower(),
                "title": str(getattr(f, "title", "") or ""),
                "skill_id": sid,
                "owasp": catalog.get(sid, {}).get("owasp", ""),
                "is_bac": sid in BAC_SKILL_IDS,
                # advisory = risco de design (não confirma acesso indevido);
                # separado dos achados para não inflar "positivos".
                "verification": _vs,
                "advisory": _advisory,
                "http_status": _http,
            })

    # 4) Per-endpoint aggregation.
    def match_path(path: str, method: str | None = None) -> dict[str, Any] | None:
        m = str(method or "").upper()
        fallback = None
        for d in docs:
            if d["regex"].match(path):
                if m and d["method"] == m:
                    return d
                fallback = fallback or d
        return fallback

    _EVIDENCE_PER_EP = 10
    obs_by_ep: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"skills": set(), "identities": set(), "statuses": defaultdict(int), "real": 0, "count": 0, "evidence": []}
    )
    shadow_paths: set[str] = set()
    for o in observations:
        opath = _path_of(o.get("endpoint") or o.get("url"))
        d = match_path(opath, o.get("method"))
        if not d:
            shadow_paths.add(opath)
            continue
        agg = obs_by_ep[(d["method"], d["path"])]
        if o.get("skill_id"):
            agg["skills"].add(str(o["skill_id"]))
        if o.get("identity_key"):
            agg["identities"].add(str(o["identity_key"]))
        st = o.get("http_status")
        if st is not None:
            agg["statuses"][str(st)] += 1
            if isinstance(st, int) and st > 0:
                agg["real"] += 1
        agg["count"] += 1
        # cURL + request body + response as evidence for the drill-down.
        if o.get("curl") and len(agg["evidence"]) < _EVIDENCE_PER_EP:
            agg["evidence"].append({
                "skill_id": str(o.get("skill_id") or ""),
                "method": str(o.get("method") or ""),
                "url": str(o.get("endpoint") or o.get("url") or ""),
                "identity_key": str(o.get("identity_key") or ""),
                "curl": str(o.get("curl") or ""),
                "request_body": str(o.get("request_body") or ""),
                "response_status": o.get("response_status") if o.get("response_status") is not None else o.get("http_status"),
                "response_body": str(o.get("response_body") or ""),
                "response_truncated": bool(o.get("response_truncated")),
            })

    # Separate confirmed/candidate findings (real signals) from advisories
    # (design-risk notes that do NOT confirm a vuln) so advisories never inflate
    # the positive counts.
    real_findings = [f for f in api_findings if not f["advisory"]]
    advisory_findings = [f for f in api_findings if f["advisory"]]
    find_by_ep: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    adv_by_ep: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for f in real_findings:
        d = match_path(f["path"])
        if d:
            find_by_ep[(d["method"], d["path"])].append(f)
    for f in advisory_findings:
        d = match_path(f["path"])
        if d:
            adv_by_ep[(d["method"], d["path"])].append(f)

    endpoint_rows: list[dict[str, Any]] = []
    for d in docs:
        key = (d["method"], d["path"])
        agg = obs_by_ep.get(key)
        fs = find_by_ep.get(key, [])
        skills = set(agg["skills"]) if agg else set()
        bac_tested = bool(skills & BAC_SKILL_IDS)
        real = int(agg["real"]) if agg else 0
        tested = bool(agg and agg["count"] > 0)
        sev_counts: dict[str, int] = defaultdict(int)
        for f in fs:
            sev_counts[f["severity"]] += 1
        endpoint_rows.append({
            "method": d["method"],
            "url": d["url"],
            "path": d["path"],
            "source": d.get("source", "spec"),
            "tested": tested,
            "skills_tested": sorted(skills),
            "skills_tested_count": len(skills),
            "bac_tested": bac_tested,
            "identities": sorted(agg["identities"]) if agg else [],
            "http_status_counts": dict(agg["statuses"]) if agg else {},
            "observation_count": int(agg["count"]) if agg else 0,
            "findings": [{"severity": f["severity"], "title": f["title"], "owasp": f["owasp"], "skill_id": f["skill_id"], "is_bac": f["is_bac"], "verification": f["verification"], "http_status": f.get("http_status")} for f in fs],
            "findings_by_severity": dict(sev_counts),
            "advisories": [{"title": f["title"], "owasp": f["owasp"], "skill_id": f["skill_id"], "is_bac": f["is_bac"]} for f in adv_by_ep.get(key, [])],
            "evidence": list(agg["evidence"]) if agg else [],
            "quality": _quality(tested, skills, real, bac_tested, len(fs)),
        })

    # Sort: worst quality first (so gaps surface), then by findings.
    level_order = {"none": 0, "weak": 1, "partial": 2, "good": 3}
    endpoint_rows.sort(key=lambda r: (level_order.get(r["quality"]["level"], 0), -len(r["findings"])))

    # 5) Catalog view (which tests exist / ran) + per-skill endpoint coverage.
    skill_ep_cov: dict[str, int] = defaultdict(int)
    skill_find: dict[str, int] = defaultdict(int)
    for r in endpoint_rows:
        for sid in r["skills_tested"]:
            skill_ep_cov[sid] += 1
    for f in real_findings:
        if f["skill_id"]:
            skill_find[f["skill_id"]] += 1
    catalog_rows = []
    for sid, meta in sorted(catalog.items(), key=lambda kv: kv[1]["priority"]):
        catalog_rows.append({
            **meta,
            "executed": sid in executed_skills,
            "endpoints_covered": skill_ep_cov.get(sid, 0),
            "findings": skill_find.get(sid, 0),
        })

    # 6) Summary (forest overview). Advisories NÃO contam como achados/positivos.
    sev_total: dict[str, int] = defaultdict(int)
    for f in real_findings:
        sev_total[f["severity"]] += 1
    tested_count = sum(1 for r in endpoint_rows if r["tested"])
    bac_tested_count = sum(1 for r in endpoint_rows if r["bac_tested"])
    bac_findings = sum(1 for f in real_findings if f["is_bac"])
    bac_confirmed = sum(1 for f in real_findings if f["is_bac"] and f["verification"] == "confirmed")
    owasp_counts: dict[str, int] = defaultdict(int)
    for f in real_findings:
        if f["owasp"]:
            owasp_counts[f["owasp"]] += 1

    # 7) Flow model + attack-paths. The STATIC graph is derived here from the
    # endpoint forest + findings, so the depth (operation flow, how variables are
    # reused, and the attack-path below the OWASP table) shows up even when the
    # dynamic Caido-backed flow runner has not executed. When the runner DID run,
    # its richer output (variable lineage + executed attack-paths) is preferred.
    # Schema-driven flow: parse the ingested OpenAPI spec (request/response field
    # names) so the graph captures real token chains (e.g. platformId -> requestId),
    # not just path-parameter matches. Falls back to the create-heuristic if absent.
    spec_hints: dict[str, Any] = {}
    try:
        import json
        import os
        cfg = dict((getattr(job, "state_data", None) or {}).get("api_scan_config") or {})
        spec_path = str(cfg.get("inline_spec_file") or "")
        if spec_path and os.path.exists(spec_path):
            with open(spec_path) as _fh:
                spec_hints = parse_spec_flow_hints(json.load(_fh))
    except Exception:
        spec_hints = {}
    flow_graph = build_flow_graph(docs, schema_hints=spec_hints)
    attack_paths = build_attack_paths(flow_graph, real_findings + advisory_findings)
    variables: list[dict[str, Any]] = []
    dynamic_executed = False
    caido_project = ""
    if dynamic_flow:
        variables = list(dynamic_flow.get("variables") or [])
        if dynamic_flow.get("attack_paths"):
            attack_paths = list(dynamic_flow["attack_paths"])
        dynamic_executed = bool(dynamic_flow.get("dynamic_executed"))
        caido_project = str(dynamic_flow.get("caido_project") or "")

    return {
        "version": "api-endpoint-report-v1",
        "scan_id": int(job.id),
        "target": str(job.target_query or ""),
        "status": str(job.status or ""),
        "summary": {
            "endpoints_total": len(docs),
            "endpoints_from_spec": sum(1 for d in docs if d.get("source") == "spec"),
            "endpoints_discovered": sum(1 for d in docs if d.get("source") == "crawled"),
            "endpoints_tested": tested_count,
            "endpoints_untested": len(docs) - tested_count,
            "coverage_pct": round(tested_count / len(docs) * 100) if docs else 0,
            "bac_endpoints_tested": bac_tested_count,
            "shadow_paths_observed": len(shadow_paths),
            "findings_total": len(real_findings),
            "findings_by_severity": dict(sev_total),
            "findings_by_owasp": dict(sorted(owasp_counts.items())),
            "advisories_total": len(advisory_findings),
            "bac_findings": bac_findings,
            "bac_confirmed": bac_confirmed,
            "bac_advisories": sum(1 for f in advisory_findings if f["is_bac"]),
            "skills_catalog_total": len(catalog),
            "skills_executed": len(executed_skills & set(catalog)),
            "attack_paths_total": len(attack_paths),
            "attack_paths_confirmed": sum(1 for p in attack_paths if p.get("confirmed")),
            "flow_edges": flow_graph.get("stats", {}).get("edges_total", 0),
            "flow_dynamic": dynamic_executed,
        },
        "skills_catalog": catalog_rows,
        "endpoints": endpoint_rows,
        "shadow_paths": sorted(shadow_paths)[:50],
        "flow": flow_graph,
        "variables": variables,
        "attack_paths": attack_paths,
        "caido_project": caido_project,
    }
