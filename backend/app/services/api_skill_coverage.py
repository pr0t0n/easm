from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.models import OffensiveEndpoint, ScanJob, ScanWorkItem
from app.services.api_skill_top20_runner import load_api_top20_skills


API_SPEC_SOURCES = {"api-spec", "openapi", "swagger", "graphql-spec"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
TERMINAL_SUCCESS_STATUSES = {"completed", "done"}


def build_api_skill_coverage(
    db: Session,
    job: ScanJob,
    *,
    work_items: list[ScanWorkItem] | None = None,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    items = list(work_items) if work_items is not None else (
        db.query(ScanWorkItem)
        .filter(ScanWorkItem.scan_job_id == job.id)
        .all()
    )
    api_items = [item for item in items if _is_api_skill_item(item)]
    scan_ids = {int(job.id)}
    for item in api_items:
        for reused_id in _parsed_result(item).get("reused_inventory_scan_ids") or []:
            try:
                scan_ids.add(int(reused_id))
            except (TypeError, ValueError):
                continue
    swagger_endpoints = (
        db.query(OffensiveEndpoint)
        .filter(
            OffensiveEndpoint.scan_job_id.in_(scan_ids),
            OffensiveEndpoint.source_tool.in_(API_SPEC_SOURCES),
        )
        .all()
    )
    return build_api_skill_coverage_snapshot(
        work_items=api_items,
        swagger_endpoints=swagger_endpoints,
        state=state if state is not None else dict(job.state_data or {}),
    )


def build_api_skill_coverage_snapshot(
    *,
    work_items: list[Any],
    swagger_endpoints: list[Any],
    state: dict[str, Any] | None = None,
    expected_skill_ids: list[str] | None = None,
) -> dict[str, Any]:
    state = dict(state or {})
    expected_ids = list(expected_skill_ids or _expected_api_skill_ids())
    expected_set = set(expected_ids)
    rows: list[dict[str, Any]] = []
    completed_ids: set[str] = set()
    completed_mcp_ids: set[str] = set()
    skills_total_zero_items: list[int] = []
    response_observations: list[dict[str, Any]] = []
    findings_by_skill: Counter[str] = Counter()
    api_items = [item for item in work_items if _is_api_skill_item(item)]

    for item in api_items:
        parsed = _parsed_result(item)
        status = str(getattr(item, "status", "") or "").lower()
        skill_id = _skill_id(item, parsed)
        mcp_used = bool(parsed.get("mcp_used"))
        execution_path = str(parsed.get("execution_path") or "")
        skill_results = [row for row in list(parsed.get("skill_results") or []) if isinstance(row, dict)]
        observations = [row for row in list(parsed.get("response_observations") or []) if isinstance(row, dict)]
        if not observations:
            for skill_result in skill_results:
                observations.extend([
                    row for row in list(skill_result.get("observations") or []) if isinstance(row, dict)
                ])
        response_observations.extend(observations)
        skills_total = int(parsed.get("skills_total") or len(skill_results) or (1 if skill_id else 0))
        if status in TERMINAL_SUCCESS_STATUSES and skills_total == 0:
            item_id = getattr(item, "id", None)
            if item_id is not None:
                skills_total_zero_items.append(int(item_id))
        parsed_finding_count = parsed.get("finding_count")
        row_findings = int(parsed_finding_count or 0)
        skill_result_findings: Counter[str] = Counter()
        for skill_result in skill_results:
            result_skill_id = str(skill_result.get("skill_id") or skill_id or "unknown")
            count = _count_findings(skill_result)
            skill_result_findings[result_skill_id] += count
        if parsed_finding_count is None:
            row_findings = sum(skill_result_findings.values())
        findings_by_skill.update(skill_result_findings)
        if skill_id and status in TERMINAL_SUCCESS_STATUSES:
            completed_ids.add(skill_id)
            if mcp_used:
                completed_mcp_ids.add(skill_id)
            if row_findings and not skill_result_findings:
                findings_by_skill[skill_id] += row_findings
        rows.append({
            "work_item_id": getattr(item, "id", None),
            "skill_id": skill_id,
            "status": status,
            "target": getattr(item, "target", None),
            "mcp_used": mcp_used,
            "execution_path": execution_path,
            "skills_total": skills_total,
            "selected_endpoint_count": int(parsed.get("selected_endpoint_count") or 0),
            "matched_endpoint_count": int(parsed.get("matched_endpoint_count") or 0),
            "skipped_endpoint_count": int(parsed.get("skipped_endpoint_count") or 0),
            "attempts": int(parsed.get("attempts") or getattr(item, "attempts", 0) or 0),
            "findings": row_findings,
            "response_observations": len(observations),
            "http_status_counts": dict(parsed.get("http_status_counts") or {}),
            "observation_error_counts": dict(parsed.get("observation_error_counts") or {}),
            "coverage_complete": bool(parsed.get("endpoint_coverage_complete", parsed.get("coverage_complete", False))),
            "blocked_reason": parsed.get("blocked_reason"),
        })

    swagger_rows = _swagger_rows(swagger_endpoints)
    swagger_method_keys = {row["method_key"] for row in swagger_rows}
    swagger_path_keys = {row["path_key"] for row in swagger_rows}
    observed_method_keys = {_endpoint_key(obs.get("method"), obs.get("url"), method_sensitive=True) for obs in response_observations}
    observed_path_keys = {_endpoint_key(obs.get("method"), obs.get("url"), method_sensitive=False) for obs in response_observations}
    observed_method_keys.discard(None)
    observed_path_keys.discard(None)
    method_gaps = [
        {"method": row["method"], "url": row["url"]}
        for row in swagger_rows
        if row["method_key"] not in observed_method_keys
    ]
    path_gaps = [
        {"method": row["method"], "url": row["url"]}
        for row in swagger_rows
        if row["path_key"] not in observed_path_keys
    ]
    mutation_skipped = [
        row for row in method_gaps
        if str(row.get("method") or "").upper() in MUTATING_METHODS
        and _endpoint_key(row.get("method"), row.get("url"), method_sensitive=False) in observed_path_keys
    ]
    api_evidence_present = bool(api_items or swagger_rows or state.get("api_scan_observability_runs"))
    missing_ids = sorted(expected_set - completed_ids)
    missing_mcp_ids = sorted(expected_set - completed_mcp_ids)
    rag_warmup = dict(state.get("rag_warmup") or {})
    rag_used = bool(rag_warmup.get("ok") or rag_warmup.get("skills_indexed") or state.get("skill_rag_index"))
    gaps = _coverage_gaps(
        api_evidence_present=api_evidence_present,
        expected_count=len(expected_ids),
        missing_ids=missing_ids,
        missing_mcp_ids=missing_mcp_ids,
        skills_total_zero_items=skills_total_zero_items,
        path_gaps=path_gaps,
        rows=rows,
    )
    swagger = {
        "endpoints_total": len(swagger_method_keys),
        "paths_total": len(swagger_path_keys),
        "paths_observed": len(swagger_path_keys & observed_path_keys),
        "methods_observed": len(swagger_method_keys & observed_method_keys),
        "path_coverage_complete": not path_gaps if swagger_rows else None,
        "method_coverage_complete": not method_gaps if swagger_rows else None,
        "path_gaps": path_gaps,
        "method_gaps": method_gaps,
        "mutation_skipped_by_policy": mutation_skipped,
    }
    return {
        "version": "api-skill-coverage-v1",
        "api_evidence_present": api_evidence_present,
        "expected_skills": len(expected_ids),
        "skills_expected_ids": expected_ids,
        "skills_completed_ids": sorted(completed_ids),
        "skills_completed_via_mcp_ids": sorted(completed_mcp_ids),
        "skills_missing_ids": missing_ids,
        "skills_missing_mcp_ids": missing_mcp_ids,
        "skills_total_zero_items": skills_total_zero_items,
        "work_items": len(api_items),
        "completed_work_items": len([row for row in rows if row["status"] in TERMINAL_SUCCESS_STATUSES]),
        "mcp_work_items": len([row for row in rows if row["mcp_used"]]),
        "rag_used": rag_used,
        "response_observation_count": len(response_observations),
        "findings_by_skill": dict(sorted(findings_by_skill.items())),
        "swagger": swagger,
        "matrix": rows,
        "gaps": gaps,
        "complete": api_evidence_present and not gaps,
    }


def _coverage_gaps(
    *,
    api_evidence_present: bool,
    expected_count: int,
    missing_ids: list[str],
    missing_mcp_ids: list[str],
    skills_total_zero_items: list[int],
    path_gaps: list[dict[str, Any]],
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not api_evidence_present:
        return []
    gaps: list[dict[str, Any]] = []
    if not rows:
        gaps.append({
            "severity": "high",
            "area": "api_skill_coverage",
            "title": "Inventário API sem execução das skills Top20",
            "detail": "Há evidência de API, mas nenhum item api-skill-top20 foi executado.",
            "action": "Executar o catálogo API Top20 via MCP/RAG antes de aceitar o scan como completo.",
        })
    if missing_ids:
        gaps.append({
            "severity": "high",
            "area": "api_skill_coverage",
            "title": "Catálogo API Top20 incompleto",
            "detail": f"{len(missing_ids)} de {expected_count} skills não concluíram: {', '.join(missing_ids[:8])}.",
            "action": "Drenar todos os work items api-skill-top20 e registrar resultado por skill.",
        })
    if missing_mcp_ids:
        gaps.append({
            "severity": "high",
            "area": "api_skill_mcp",
            "title": "Skills API sem confirmação de execução via MCP",
            "detail": f"{len(missing_mcp_ids)} de {expected_count} skills não têm mcp_used=true: {', '.join(missing_mcp_ids[:8])}.",
            "action": "Executar as skills API pelo adaptador MCP/RAG e persistir mcp_used no resultado.",
        })
    if skills_total_zero_items:
        gaps.append({
            "severity": "high",
            "area": "api_skill_dispatch",
            "title": "Execução API concluída sem skill materializada",
            "detail": f"Itens concluídos com skills_total=0: {', '.join(str(item_id) for item_id in skills_total_zero_items[:8])}.",
            "action": "Bloquear conclusão quando o dispatcher cair em skill genérica ou perder o catálogo API.",
        })
    if path_gaps:
        gaps.append({
            "severity": "medium",
            "area": "api_endpoint_coverage",
            "title": "Endpoints Swagger sem observação de skill API",
            "detail": f"{len(path_gaps)} endpoints documentados não têm observação de request/response por skill.",
            "action": "Executar as skills contra todo o inventário documentado ou registrar pré-condição objetiva.",
        })
    return gaps


def _expected_api_skill_ids() -> list[str]:
    return [str(skill["id"]) for skill in load_api_top20_skills().get("skills", [])]


def _is_api_skill_item(item: Any) -> bool:
    metadata = dict(getattr(item, "item_metadata", None) or {})
    parsed = _parsed_result(item)
    return (
        str(getattr(item, "tool_name", "") or "").lower() == "api-skill-top20"
        or str(metadata.get("api_skill_id") or "").startswith("skill.api.")
        or str(parsed.get("tool") or "").lower() == "api-skill-top20"
    )


def _parsed_result(item: Any) -> dict[str, Any]:
    result = getattr(item, "result", None)
    if not isinstance(result, dict):
        return {}
    parsed = result.get("parsed_result")
    if isinstance(parsed, dict):
        return parsed
    return result


def _skill_id(item: Any, parsed: dict[str, Any]) -> str | None:
    metadata = dict(getattr(item, "item_metadata", None) or {})
    for value in (
        metadata.get("api_skill_id"),
        parsed.get("api_skill_id"),
        parsed.get("skill_id"),
        metadata.get("skill_id"),
    ):
        text = str(value or "")
        if text.startswith("skill.api."):
            return text
    for row in list(parsed.get("skill_results") or []):
        if not isinstance(row, dict):
            continue
        text = str(row.get("skill_id") or "")
        if text.startswith("skill.api."):
            return text
    return None


def _count_findings(row: dict[str, Any]) -> int:
    findings = row.get("findings")
    if isinstance(findings, list):
        return len(findings)
    try:
        return int(findings or 0)
    except (TypeError, ValueError):
        return 0


def _swagger_rows(endpoints: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for endpoint in endpoints:
        url = _attr(endpoint, "url") or _attr(endpoint, "normalized_url")
        method = str(_attr(endpoint, "method") or "GET").upper()
        method_key = _endpoint_key(method, url, method_sensitive=True)
        path_key = _endpoint_key(method, url, method_sensitive=False)
        if method_key is None or path_key is None or method_key in seen:
            continue
        seen.add(method_key)
        rows.append({
            "method": method,
            "url": str(url),
            "method_key": method_key,
            "path_key": path_key,
        })
    return rows


def _endpoint_key(method: Any, url: Any, *, method_sensitive: bool) -> tuple[str, str, str, str] | tuple[str, str, str] | None:
    if not url:
        return None
    parsed = urlparse(str(url))
    host = (parsed.netloc or parsed.hostname or "").lower()
    path = parsed.path or "/"
    query = parsed.query or ""
    if method_sensitive:
        return (str(method or "GET").upper(), host, path, query)
    return (host, path, query)


def _attr(row: Any, name: str) -> Any:
    if isinstance(row, dict):
        return row.get(name)
    return getattr(row, name, None)
