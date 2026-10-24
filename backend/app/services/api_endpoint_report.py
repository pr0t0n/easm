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
    for item in items:
        if not _is_api_skill_item(item):
            continue
        parsed = _parsed_result(item)
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
            api_findings.append({
                "url": str(getattr(f, "url", "") or det.get("url") or det.get("matched_at") or ""),
                "path": _path_of(getattr(f, "url", "") or det.get("url") or det.get("matched_at") or ""),
                "severity": str(getattr(f, "severity", "") or "low").lower(),
                "title": str(getattr(f, "title", "") or ""),
                "skill_id": sid,
                "owasp": catalog.get(sid, {}).get("owasp", ""),
                "is_bac": sid in BAC_SKILL_IDS,
            })

    # 4) Per-endpoint aggregation.
    def match_path(path: str) -> dict[str, Any] | None:
        for d in docs:
            if d["regex"].match(path):
                return d
        return None

    obs_by_ep: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"skills": set(), "identities": set(), "statuses": defaultdict(int), "real": 0, "count": 0}
    )
    shadow_paths: set[str] = set()
    for o in observations:
        opath = _path_of(o.get("endpoint") or o.get("url"))
        d = match_path(opath)
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

    find_by_ep: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for f in api_findings:
        d = match_path(f["path"])
        if d:
            find_by_ep[(d["method"], d["path"])].append(f)

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
            "findings": [{"severity": f["severity"], "title": f["title"], "owasp": f["owasp"], "skill_id": f["skill_id"], "is_bac": f["is_bac"]} for f in fs],
            "findings_by_severity": dict(sev_counts),
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
    for f in api_findings:
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

    # 6) Summary (forest overview).
    sev_total: dict[str, int] = defaultdict(int)
    for f in api_findings:
        sev_total[f["severity"]] += 1
    tested_count = sum(1 for r in endpoint_rows if r["tested"])
    bac_tested_count = sum(1 for r in endpoint_rows if r["bac_tested"])
    bac_findings = sum(1 for f in api_findings if f["is_bac"])
    owasp_counts: dict[str, int] = defaultdict(int)
    for f in api_findings:
        if f["owasp"]:
            owasp_counts[f["owasp"]] += 1

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
            "findings_total": len(api_findings),
            "findings_by_severity": dict(sev_total),
            "findings_by_owasp": dict(sorted(owasp_counts.items())),
            "bac_findings": bac_findings,
            "skills_catalog_total": len(catalog),
            "skills_executed": len(executed_skills & set(catalog)),
        },
        "skills_catalog": catalog_rows,
        "endpoints": endpoint_rows,
        "shadow_paths": sorted(shadow_paths)[:50],
    }
