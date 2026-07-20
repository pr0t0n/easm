"""Inventário ofensivo persistente.

Este módulo é a fonte oficial para transformar saída de ferramentas em artefatos
consultáveis por endpoint, parâmetro, JS, hipótese, validação e cobertura.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from sqlalchemy.orm import Session

from app.models.models import (
    CoverageItem,
    OffensiveApiSpec,
    OffensiveAsset,
    OffensiveEndpoint,
    OffensiveHypothesis,
    OffensiveJsAsset,
    OffensiveParameter,
    OffensiveService,
    ScanJob,
    ValidationRun,
)


_JS_RE = re.compile(r"\.(?:js|mjs|cjs)(?:\?|$)", re.I)
_PATH_PARAM_RE = re.compile(r"/(?:[^/?#&=]+/)*(?:[^/?#&=]*?(?:id|uuid|guid|user|account|basket|order)[^/?#&=]*)(?:/|$)", re.I)
_ROUTE_ID_RE = re.compile(r"(?<=/)(?:\d{1,12}|[0-9a-f]{8}-[0-9a-f-]{27,})(?=/|$)", re.I)
_COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.br", "net.br", "org.br", "gov.br",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.za", "com.mx",
}


def root_domain(host: str) -> str:
    parts = [part for part in (host or "").split(".") if part]
    if len(parts) >= 3 and ".".join(parts[-2:]) in _COMMON_SECOND_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def host_of(value: str) -> str:
    parsed = urlparse(str(value or ""))
    return (parsed.hostname or parsed.path.split("/")[0] or "").lower()


def normalize_url(url: str, base: str | None = None) -> str:
    raw = str(url or "").strip()
    if base and raw.startswith("/"):
        raw = urljoin(base, raw)
    parsed = urlparse(raw)
    if not parsed.scheme and parsed.netloc == "":
        return raw.split("#", 1)[0]
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.netloc or "").lower()
    path = _ROUTE_ID_RE.sub("{id}", parsed.path or "/")
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = "&".join(f"{k}=" for k, _ in sorted(pairs))
    return urlunparse((scheme, netloc, path, "", query, ""))


def parameter_risk_hint(name: str, url: str = "") -> str:
    n = str(name or "").lower()
    if n in {"id", "user_id", "userid", "account", "account_id", "basket", "basketid", "order", "order_id", "invoice", "tenant", "tenant_id"}:
        return "idor_bola"
    if n in {"role", "isadmin", "admin", "price", "quantity", "discount", "coupon", "plan", "owner", "owner_id"}:
        return "business_logic_mass_assignment"
    if n in {"url", "uri", "redirect", "next", "return", "return_to", "callback", "continue"}:
        return "ssrf_open_redirect"
    if n in {"file", "path", "include", "template", "view", "page", "lang"}:
        return "lfi_ssti_path_traversal"
    if n in {"q", "query", "search", "name", "message", "comment"}:
        return "xss_sqli"
    if n in {"cmd", "command", "exec"}:
        return "rce"
    if _PATH_PARAM_RE.search(url or ""):
        return "object_reference"
    return ""


class OffensiveInventoryService:
    def __init__(self, db: Session, scan: ScanJob):
        self.db = db
        self.scan = scan

    def upsert_asset(
        self,
        target: str,
        *,
        asset_type: str = "web",
        source_tool: str = "",
        confidence: int = 60,
        metadata: dict[str, Any] | None = None,
    ) -> OffensiveAsset:
        host = host_of(target)
        from app.services.scan_scope import authorized_scope_from_target_query, is_host_in_scope
        authorized_scope = authorized_scope_from_target_query(str(self.scan.target_query or ""))
        if not authorized_scope or not is_host_in_scope(host, authorized_scope):
            raise ValueError(f"out_of_scope_inventory_target:{host or target}")
        parsed = urlparse(str(target or ""))
        # Assets represent hosts/origins; paths belong to OffensiveEndpoint.
        # Keeping the full URL here created one asset per crawled path and made
        # both coverage and dashboard cardinality meaningless.
        if parsed.scheme and parsed.netloc:
            url = urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), "", "", "", ""))
        else:
            url = ""
        asset = (
            self.db.query(OffensiveAsset)
            .filter(
                OffensiveAsset.scan_job_id == self.scan.id,
                OffensiveAsset.asset_type == asset_type,
                OffensiveAsset.host == host,
                OffensiveAsset.url == url,
            )
            .first()
        )
        if asset is None:
            asset = OffensiveAsset(
                scan_job_id=self.scan.id,
                asset_type=asset_type,
                host=host,
                url=url,
                root_domain=root_domain(host),
            )
        asset.source_tool = source_tool or asset.source_tool
        asset.confidence = max(int(asset.confidence or 0), int(confidence or 0))
        asset.asset_metadata = _merge(asset.asset_metadata, metadata)
        asset.last_seen = datetime.now()
        self.db.add(asset)
        self.db.flush()
        return asset

    def upsert_service(
        self,
        *,
        asset: OffensiveAsset | None,
        port: int | None,
        protocol: str = "tcp",
        service_name: str = "",
        product: str = "",
        version: str = "",
        tls: bool = False,
        banner: str = "",
        source_tool: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> OffensiveService:
        svc = (
            self.db.query(OffensiveService)
            .filter(
                OffensiveService.asset_id == (asset.id if asset else None),
                OffensiveService.port == port,
                OffensiveService.protocol == protocol,
            )
            .first()
        )
        if svc is None:
            svc = OffensiveService(scan_job_id=self.scan.id, asset_id=asset.id if asset else None, port=port, protocol=protocol)
        svc.service_name = service_name or svc.service_name
        svc.product = product or svc.product
        svc.version = version or svc.version
        svc.tls = bool(tls or svc.tls)
        svc.banner = banner or svc.banner
        svc.source_tool = source_tool or svc.source_tool
        svc.service_metadata = _merge(svc.service_metadata, metadata)
        svc.last_seen = datetime.now()
        self.db.add(svc)
        self.db.flush()
        return svc

    def upsert_endpoint(
        self,
        url: str,
        *,
        method: str = "GET",
        source_tool: str = "",
        status_code: int | None = None,
        content_type: str = "",
        auth_context: str = "anonymous",
        role_observed: str = "",
        auth_required: bool | None = None,
        source_artifact_id: int | None = None,
        discovered_from: str = "",
        confidence: int = 60,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> OffensiveEndpoint:
        normalized = normalize_url(url)[:1000]
        asset = self.upsert_asset(url, asset_type="web", source_tool=source_tool, confidence=confidence)
        parsed = urlparse(str(url or ""))
        if parsed.hostname:
            tls = parsed.scheme.lower() == "https"
            port = parsed.port or (443 if tls else 80)
            self.upsert_service(
                asset=asset,
                port=port,
                protocol="tcp",
                service_name="https" if tls else "http",
                tls=tls,
                source_tool=source_tool,
                metadata={"inferred_from_endpoint": True},
            )
        endpoint = (
            self.db.query(OffensiveEndpoint)
            .filter(
                OffensiveEndpoint.scan_job_id == self.scan.id,
                OffensiveEndpoint.method == str(method or "GET").upper(),
                OffensiveEndpoint.normalized_url == normalized,
                OffensiveEndpoint.auth_context == (auth_context or "anonymous"),
            )
            .first()
        )
        if endpoint is None:
            endpoint = OffensiveEndpoint(
                scan_job_id=self.scan.id,
                asset_id=asset.id,
                url=url,
                normalized_url=normalized,
                method=str(method or "GET").upper(),
                auth_context=auth_context or "anonymous",
            )
        endpoint.url = url
        endpoint.asset_id = asset.id
        endpoint.status_code = status_code if status_code is not None else endpoint.status_code
        endpoint.content_type = content_type or endpoint.content_type
        endpoint.auth_required = auth_required if auth_required is not None else endpoint.auth_required
        endpoint.role_observed = role_observed or endpoint.role_observed
        endpoint.source_tool = source_tool or endpoint.source_tool
        endpoint.source_artifact_id = source_artifact_id or endpoint.source_artifact_id
        endpoint.discovered_from = discovered_from or endpoint.discovered_from
        endpoint.confidence = max(int(endpoint.confidence or 0), int(confidence or 0))
        endpoint.tags = sorted(set(list(endpoint.tags or []) + list(tags or []) + _auto_tags(url)))
        endpoint.endpoint_metadata = _merge(endpoint.endpoint_metadata, metadata)
        samples = list((endpoint.endpoint_metadata or {}).get("sample_urls") or [])
        if url not in samples:
            samples.append(url)
        endpoint.endpoint_metadata = _merge(endpoint.endpoint_metadata, {"sample_urls": samples[-12:]})
        endpoint.last_seen = datetime.now()
        self.db.add(endpoint)
        self.db.flush()
        self._sync_state_endpoint(url)
        for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
            self.upsert_parameter(endpoint, name, location="query", sample_value=value, source_tool=source_tool)
        return endpoint

    def upsert_parameter(
        self,
        endpoint: OffensiveEndpoint,
        name: str,
        *,
        location: str = "query",
        type_hint: str = "",
        risk_hint: str = "",
        sample_value: str = "",
        source_tool: str = "",
        source_js_asset_id: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> OffensiveParameter:
        clean = str(name or "").strip()[:160]
        if not clean:
            raise ValueError("parameter name is required")
        param = (
            self.db.query(OffensiveParameter)
            .filter(
                OffensiveParameter.endpoint_id == endpoint.id,
                OffensiveParameter.name == clean,
                OffensiveParameter.location == location,
            )
            .first()
        )
        if param is None:
            param = OffensiveParameter(scan_job_id=self.scan.id, endpoint_id=endpoint.id, name=clean, location=location)
        param.type_hint = type_hint or param.type_hint
        param.risk_hint = risk_hint or parameter_risk_hint(clean, endpoint.url) or param.risk_hint
        param.sample_value = sample_value or param.sample_value
        param.source_tool = source_tool or param.source_tool
        param.source_js_asset_id = source_js_asset_id or param.source_js_asset_id
        param.parameter_metadata = _merge(param.parameter_metadata, metadata)
        param.last_seen = datetime.now()
        self.db.add(param)
        self.db.flush()
        return param

    def upsert_js_asset(
        self,
        url: str,
        *,
        endpoint: OffensiveEndpoint | None = None,
        sha256: str = "",
        size: int | None = None,
        download_status: str = "pending",
        analysis_status: str = "pending",
        framework_hint: str = "",
        source_tool: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> OffensiveJsAsset:
        js = self.db.query(OffensiveJsAsset).filter(OffensiveJsAsset.scan_job_id == self.scan.id, OffensiveJsAsset.url == url).first()
        if js is None:
            js = OffensiveJsAsset(scan_job_id=self.scan.id, url=url)
        js.endpoint_id = endpoint.id if endpoint else js.endpoint_id
        js.sha256 = sha256 or js.sha256
        js.size = size if size is not None else js.size
        js.is_sourcemap = url.lower().split("?", 1)[0].endswith(".map")
        js.bundle_name = urlparse(url).path.rsplit("/", 1)[-1] or js.bundle_name
        js.framework_hint = framework_hint or js.framework_hint
        js.download_status = download_status or js.download_status
        js.analysis_status = analysis_status or js.analysis_status
        js.js_metadata = _merge(js.js_metadata, {"source_tool": source_tool} if source_tool else {}, metadata)
        js.last_seen = datetime.now()
        self.db.add(js)
        self.db.flush()
        return js

    def upsert_api_spec(
        self,
        url: str,
        *,
        spec_type: str = "openapi",
        version: str = "",
        parsed_status: str = "pending",
        endpoint_count: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> OffensiveApiSpec:
        target_ref = str(target_ref or "")[:1000]
        row = (
            self.db.query(OffensiveApiSpec)
            .filter(OffensiveApiSpec.scan_job_id == self.scan.id, OffensiveApiSpec.url == url, OffensiveApiSpec.spec_type == spec_type)
            .first()
        )
        if row is None:
            row = OffensiveApiSpec(scan_job_id=self.scan.id, url=url, spec_type=spec_type)
        row.version = version or row.version
        row.parsed_status = parsed_status or row.parsed_status
        row.endpoint_count = max(int(row.endpoint_count or 0), int(endpoint_count or 0))
        row.spec_metadata = _merge(row.spec_metadata, metadata)
        row.updated_at = datetime.now()
        self.db.add(row)
        self.db.flush()
        return row

    def upsert_hypothesis(
        self,
        *,
        hypothesis_type: str,
        title: str,
        target_ref: str,
        source_signal: str,
        confidence: int = 50,
        recommended_tools: list[str] | None = None,
        required_identities: list[str] | None = None,
        evidence_requirements: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> OffensiveHypothesis:
        target_ref = str(target_ref or "")[:1000]
        row = (
            self.db.query(OffensiveHypothesis)
            .filter(
                OffensiveHypothesis.scan_job_id == self.scan.id,
                OffensiveHypothesis.hypothesis_type == hypothesis_type,
                OffensiveHypothesis.target_ref == target_ref,
                OffensiveHypothesis.source_signal == source_signal,
            )
            .first()
        )
        if row is None:
            row = OffensiveHypothesis(
                scan_job_id=self.scan.id,
                hypothesis_type=hypothesis_type,
                target_ref=target_ref,
                source_signal=source_signal,
                title=title[:255],
            )
        row.title = title[:255]
        row.confidence = max(int(row.confidence or 0), int(confidence or 0))
        row.recommended_tools = list(dict.fromkeys((row.recommended_tools or []) + list(recommended_tools or [])))
        row.required_identities = list(dict.fromkeys((row.required_identities or []) + list(required_identities or [])))
        row.evidence_requirements = list(dict.fromkeys((row.evidence_requirements or []) + list(evidence_requirements or [])))
        row.hypothesis_metadata = _merge(row.hypothesis_metadata, metadata)
        row.updated_at = datetime.now()
        self.db.add(row)
        self.db.flush()
        return row

    def record_validation(
        self,
        *,
        validator_name: str,
        result: str,
        hypothesis: OffensiveHypothesis | None = None,
        finding_id: int | None = None,
        identity_key: str = "",
        baseline_artifact_id: int | None = None,
        attempt_artifact_id: int | None = None,
        negative_control_artifact_id: int | None = None,
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> ValidationRun:
        row = ValidationRun(
            scan_job_id=self.scan.id,
            hypothesis_id=hypothesis.id if hypothesis else None,
            finding_id=finding_id,
            validator_name=validator_name,
            identity_key=identity_key or None,
            baseline_artifact_id=baseline_artifact_id,
            attempt_artifact_id=attempt_artifact_id,
            negative_control_artifact_id=negative_control_artifact_id,
            result=result,
            reason=reason or None,
            run_metadata=metadata or {},
        )
        self.db.add(row)
        if hypothesis:
            hypothesis.status = {
                "confirmed": "validated",
                "candidate": "tested_candidate",
                "refuted": "refuted",
                "skipped": "blocked_precondition",
            }.get(str(result or "").lower(), str(result or "tested"))
            hypothesis.updated_at = datetime.now()
            self.db.add(hypothesis)
        self.db.flush()
        return row

    def upsert_coverage(
        self,
        *,
        coverage_type: str,
        target_ref: str,
        test_class: str,
        status: str,
        endpoint_id: int | None = None,
        hypothesis_id: int | None = None,
        finding_id: int | None = None,
        blocking_reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> CoverageItem:
        row = (
            self.db.query(CoverageItem)
            .filter(
                CoverageItem.scan_job_id == self.scan.id,
                CoverageItem.coverage_type == coverage_type,
                CoverageItem.target_ref == target_ref,
                CoverageItem.test_class == test_class,
            )
            .first()
        )
        if row is None:
            row = CoverageItem(scan_job_id=self.scan.id, coverage_type=coverage_type, target_ref=target_ref, test_class=test_class)
        row.status = status
        row.endpoint_id = endpoint_id or row.endpoint_id
        row.hypothesis_id = hypothesis_id or row.hypothesis_id
        row.finding_id = finding_id or row.finding_id
        row.blocking_reason = blocking_reason or row.blocking_reason
        row.coverage_metadata = _merge(row.coverage_metadata, metadata)
        row.updated_at = datetime.now()
        self.db.add(row)
        self.db.flush()
        return row

    def ingest_url(self, url: str, *, source_tool: str, discovered_from: str = "", auth_context: str = "anonymous", metadata: dict[str, Any] | None = None) -> OffensiveEndpoint:
        tags = ["js"] if _JS_RE.search(url) else []
        ep = self.upsert_endpoint(url, source_tool=source_tool, discovered_from=discovered_from, auth_context=auth_context, tags=tags, metadata=metadata)
        if _JS_RE.search(url):
            self.upsert_js_asset(url, endpoint=ep, source_tool=source_tool)
        return ep

    def _sync_state_endpoint(self, url: str) -> None:
        state = dict(self.scan.state_data or {})
        seen = list(state.get("discovered_endpoints") or [])
        if url not in seen:
            seen.append(url)
        state["discovered_endpoints"] = seen[:5000]
        self.scan.state_data = state
        self.db.add(self.scan)


def sha256_text(value: str | bytes) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(raw or b"").hexdigest()


def _auto_tags(url: str) -> list[str]:
    lower = str(url or "").lower()
    tags = []
    for key in ("admin", "api", "graphql", "login", "auth", "token", "upload", "debug", "internal", "swagger", "openapi"):
        if key in lower:
            tags.append(key)
    if _JS_RE.search(lower):
        tags.append("js")
    return tags


def _merge(*items: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items:
        if isinstance(item, dict):
            out.update(item)
    return out
