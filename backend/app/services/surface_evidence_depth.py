from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.models import (
    EndpointObservation,
    ObservedRequest,
    OffensiveEndpoint,
    OffensiveJsAsset,
    OffensiveParameter,
    OffensiveService,
    ScanJob,
)
from app.services.offensive_inventory_service import normalize_url
from app.services.skill_activity_materializer import summarize_skill_activity_execution


def _target_keys(value: Any) -> set[str]:
    raw = str(value or "").strip()
    if not raw or raw.startswith("__batch__"):
        return set()
    keys = {raw, normalize_url(raw)}
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        if parsed.hostname:
            keys.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}")
            keys.add(f"{parsed.netloc}{parsed.path or '/'}")
    except Exception:
        pass
    return {item for item in keys if item}


def build_surface_evidence_snapshot(
    db: Session,
    job: ScanJob,
    *,
    work_items: list[Any] | None = None,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    endpoints = db.query(OffensiveEndpoint).filter(OffensiveEndpoint.scan_job_id == job.id).all()
    parameters = db.query(OffensiveParameter).filter(OffensiveParameter.scan_job_id == job.id).all()
    js_assets = db.query(OffensiveJsAsset).filter(OffensiveJsAsset.scan_job_id == job.id).all()
    services = db.query(OffensiveService).filter(OffensiveService.scan_job_id == job.id).all()
    observations = db.query(EndpointObservation).filter(EndpointObservation.scan_job_id == job.id).all()
    requests = db.query(ObservedRequest).filter(ObservedRequest.scan_job_id == job.id).all()
    items = list(work_items or [])
    if work_items is None:
        from app.models.models import ScanWorkItem

        items = db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == job.id).all()
    endpoint_keys = {int(row.id): _target_keys(row.url) | _target_keys(row.normalized_url) for row in endpoints}
    executed_keys: set[str] = set()
    analyzed_keys: set[str] = set()
    for item in items:
        status = str(getattr(item, "status", "") or "").lower()
        if status not in {"completed", "done", "confirmed", "validated", "refuted"}:
            continue
        metadata = dict(getattr(item, "item_metadata", None) or {})
        for value in (metadata.get("surface_target"), metadata.get("execution_target"), getattr(item, "target", "")):
            executed_keys.update(_target_keys(value))
        result = dict(getattr(item, "result", None) or {})
        parsed = result.get("parsed_result") if isinstance(result.get("parsed_result"), dict) else result
        for row in list(parsed.get("response_observations") or []):
            if isinstance(row, dict):
                executed_keys.update(_target_keys(row.get("url") or row.get("target")))
        for value in list(metadata.get("surface_ids") or []):
            analyzed_keys.add(str(value))
    endpoint_activity = {
        int(endpoint_id): bool(keys & executed_keys)
        for endpoint_id, keys in endpoint_keys.items()
    }
    endpoint_headers = {
        int(row.endpoint_id)
        for row in requests
        if row.endpoint_id is not None and bool(dict(row.request_headers or {}))
    }
    endpoint_headers.update(
        int(row.endpoint_id)
        for row in observations
        if row.endpoint_id is not None and bool(dict(row.observation_metadata or {}).get("response_headers"))
    )
    js_downloaded = [row for row in js_assets if str(row.download_status or "").lower() in {"downloaded", "complete", "completed", "ok"}]
    js_analyzed = [row for row in js_assets if str(row.analysis_status or "").lower() in {"analyzed", "parsed", "complete", "completed", "ok"}]
    method_counts = Counter(str(row.method or "GET").upper() for row in endpoints)
    missing_endpoint_ids = [int(row.id) for row in endpoints if not endpoint_activity.get(int(row.id), False)]
    missing_header_endpoint_ids = [int(row.id) for row in endpoints if int(row.id) not in endpoint_headers]
    missing_js_ids = [int(row.id) for row in js_assets if int(row.id) not in {int(item.id) for item in js_analyzed}]
    activity_metrics = summarize_skill_activity_execution(items)
    gaps: list[dict[str, Any]] = []
    if endpoints and missing_endpoint_ids:
        gaps.append({
            "severity": "medium",
            "area": "surface_endpoint_execution",
            "title": "Endpoints descobertos sem atividade executada",
            "detail": f"{len(missing_endpoint_ids)} de {len(endpoints)} endpoints não têm execução associada.",
            "action": "Materializar atividade por endpoint, método e parâmetro e drenar a fila.",
            "endpoint_ids": missing_endpoint_ids[:50],
        })
    if endpoints and missing_header_endpoint_ids:
        gaps.append({
            "severity": "medium",
            "area": "surface_header_analysis",
            "title": "Rotas sem análise de headers",
            "detail": f"{len(missing_header_endpoint_ids)} de {len(endpoints)} endpoints não têm headers observados.",
            "action": "Persistir response headers por rota e método e executar o analisador de headers.",
            "endpoint_ids": missing_header_endpoint_ids[:50],
        })
    if js_assets and missing_js_ids:
        gaps.append({
            "severity": "medium",
            "area": "surface_js_analysis",
            "title": "Bundles JavaScript sem análise concluída",
            "detail": f"{len(missing_js_ids)} de {len(js_assets)} bundles não foram analisados.",
            "action": "Baixar, extrair endpoints/parâmetros e executar análise de secrets e dependências.",
            "js_asset_ids": missing_js_ids[:50],
        })
    if activity_metrics["selected"] and activity_metrics["generic_only_items"]:
        gaps.append({
            "severity": "high",
            "area": "skill_activity_materialization",
            "title": "Skills selecionadas sem atividades materializadas",
            "detail": f"{activity_metrics['generic_only_items']} item(ns) carregam skill sem playbook de atividades.",
            "action": "Materializar baseline, coleta de evidência, validação e follow-up antes de concluir o scan.",
        })
    return {
        "version": "surface-to-evidence-v1",
        "endpoints": len(endpoints),
        "endpoint_methods": dict(sorted(method_counts.items())),
        "endpoint_parameters": len(parameters),
        "endpoint_observations": len(observations),
        "observed_requests": len(requests),
        "routes_with_headers": len(endpoint_headers),
        "services": len(services),
        "js_assets": len(js_assets),
        "js_downloaded": len(js_downloaded),
        "js_analyzed": len(js_analyzed),
        "executed_endpoints": sum(1 for value in endpoint_activity.values() if value),
        "unexecuted_endpoint_ids": missing_endpoint_ids[:100],
        "unreviewed_header_endpoint_ids": missing_header_endpoint_ids[:100],
        "unanalyzed_js_asset_ids": missing_js_ids[:100],
        "activity_metrics": activity_metrics,
        "gaps": gaps,
        "complete": not any(str(gap.get("severity") or "").lower() == "high" for gap in gaps),
    }
