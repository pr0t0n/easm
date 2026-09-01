"""Frente E — expansão de superfície que REALIMENTA o pentest.

Fecha o loop que faltava: quando um tool de crawl/fuzz (ffuf/feroxbuster/
katana/gospider/hakrawler/gobuster/dirsearch) descobre páginas, este motor:
  1. extrai os endpoints descobertos do resultado bruto (independente de o
     parser de findings ter funcionado);
  2. abre as páginas de alto valor (page_analyzer) → novos endpoints + segredos
     hardcoded + scripts de domínio externo;
  3. REINJETA apenas probes amplos aplicáveis; validadores ativos são escolhidos
     depois pela matriz persistida do endpoint;
  4. gera findings para segredos expostos e para referência cross-domain
     (possível script injection).

Tudo somente-leitura — respeita o guardrail (nenhum efeito destrutivo).
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.models import ScanJob

logger = logging.getLogger("endpoint_discovery")

# Caps por scan (anti-explosão de fila), guardados no state_data.
_MAX_FETCH_PER_SCAN = 120
_MAX_RESEED_PER_SCAN = 250
_MAX_PER_EVENT_FETCH = 10
_MAX_PER_EVENT_RESEED = 12

_DISCOVERY_TOOLS = {
    "ffuf", "ffuf-content", "ffuf-params", "ffuf-values", "ffuf-post",
    "feroxbuster", "gobuster", "dirsearch", "katana", "gospider",
    "hakrawler", "gau", "waybackurls", "linkfinder", "paramspider",
}

_HIGH_VALUE = re.compile(
    r"(?i)(admin|api|graphql|login|signin|auth|oauth|token|upload|config|"
    r"debug|internal|backup|swagger|openapi|actuator|\.json|\.js$|\.env|\.git|"
    r"account|user|profile|dashboard|console|manage|setting|secret|key)"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+")
_EXECUTION_STATE_KEYS = {
    "execution_plan",
    "execution_plan_stage",
    "current_surface",
    "g0_status",
    "g1_status",
    "internal_execution_status",
    "external_execution_status",
    "external_release_pending",
    "external_released_after_internal",
    "execution_tracks",
}


def _preserve_runtime_execution_state(db: Session, job: ScanJob, state: dict) -> dict:
    """Merge endpoint-discovery state without resurrecting stale G0/G1 fields.

    Surface expansion may run for minutes from a state_data snapshot captured at
    task start. During that window the execution-context reconciler can move a
    scan from waiting_for_auth to G1 running. Writing the old JSON wholesale at
    the end makes the UI/backend jump backwards. Preserve the fresh runtime
    execution keys and let this service patch only discovery/inventory fields.
    """
    merged = dict(state or {})
    try:
        db.refresh(job)
        fresh = dict(job.state_data or {})
        for key in _EXECUTION_STATE_KEYS:
            if key in fresh:
                merged[key] = fresh.get(key)
    except Exception:
        pass
    return merged


def _emit_surface_progress(scan_id: int, message: str) -> None:
    """Write progress from a separate transaction.

    Surface expansion can spend minutes normalizing/fetching thousands of
    archived URLs. A separate short-lived session keeps that work visible
    without committing or holding locks from the caller's transaction.
    """
    try:
        from app.db.session import SessionLocal
        from app.models.models import ScanLog

        progress_db = SessionLocal()
        try:
            progress_db.add(ScanLog(
                scan_job_id=scan_id,
                source="endpoint-discovery",
                level="INFO",
                message=message[:4000],
            ))
            progress_db.commit()
        finally:
            progress_db.close()
    except Exception:
        pass


def _acquire_expansion_lock(db: Session, scan_id: int) -> bool:
    try:
        row = db.execute(
            text("SELECT pg_try_advisory_xact_lock(:lock_key)"),
            {"lock_key": 734200000 + int(scan_id)},
        ).first()
        return bool(row and row[0])
    except Exception:
        return True


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url or "")
    return m.group(1).lower() if m else ""


def discovered_in_scope_hosts_for_testing(
    endpoints: set[str] | list[str],
    authorized_scope: list[str],
    known_hosts: set[str] | list[str] | None = None,
) -> list[str]:
    """Return every newly observed endpoint host that must enter the test queue."""
    from app.services.scan_scope import is_host_in_scope

    known = {str(host or "").strip().lower() for host in (known_hosts or []) if str(host or "").strip()}
    discovered = {
        _host_of(url)
        for url in endpoints
        if _host_of(url) and is_host_in_scope(_host_of(url), authorized_scope)
    }
    return sorted(discovered - known)


def httpx_in_scope_endpoint_urls(parsed_result: object, authorized_scope: list[str]) -> list[str]:
    """Return only reachable HTTPX endpoints whose host is authorized."""
    from app.services.scan_scope import host_from_scope_reference, is_host_in_scope

    if isinstance(parsed_result, dict):
        rows = [parsed_result]
    elif isinstance(parsed_result, list):
        rows = [row for row in parsed_result if isinstance(row, dict)]
    else:
        rows = []
    urls: set[str] = set()
    for row in rows:
        if row.get("failed") is True:
            continue
        value = str(row.get("url") or row.get("final_url") or row.get("final-url") or row.get("input") or "").strip()
        if not value:
            continue
        host = host_from_scope_reference(value)
        if not host or not is_host_in_scope(host, authorized_scope):
            continue
        if "://" not in value:
            scheme = str(row.get("scheme") or "https").strip().lower()
            scheme = scheme if scheme in {"http", "https"} else "https"
            value = f"{scheme}://{value}/"
        urls.add(value)
    return sorted(urls)


def promote_httpx_results_to_test_queue(
    db: Session,
    job,
    source_item,
    parsed_result: object,
) -> dict[str, object]:
    """Promote only scope-filtered HTTPX endpoints into inventory/tests."""
    from app.services.hypothesis_rules import generate_hypotheses_for_scan
    from app.services.offensive_inventory_service import OffensiveInventoryService
    from app.services.scan_scope import authorized_scope_for_scan
    from app.services.scan_work_queue import enqueue_scan_work_items

    authorized_scope = authorized_scope_for_scan(db, job.id)
    urls = httpx_in_scope_endpoint_urls(parsed_result, authorized_scope)
    inventory = OffensiveInventoryService(db, job)
    for url in urls:
        inventory.ingest_url(
            url,
            source_tool="httpx",
            discovered_from=str(source_item.target or job.target_query),
            metadata={"source_work_item_id": source_item.id, "scope_validated": True},
        )

    state = dict(job.state_data or {})
    expanded = {
        _host_of(str(value)) or str(value or "").strip().lower()
        for value in (state.get("expanded_targets") or [])
        if str(value or "").strip()
    }
    confirmed_hosts = sorted({_host_of(url) for url in urls if _host_of(url)})
    new_hosts = [host for host in confirmed_hosts if host not in expanded]
    seed = {"created": 0, "existing": 0, "skipped": 0}
    if new_hosts:
        seed = enqueue_scan_work_items(db, job, new_hosts, source="httpx_scope_validated_endpoint")
        expanded.update(new_hosts)
        state = dict(job.state_data or state)
        state["expanded_targets"] = sorted(expanded)
        pending = [
            str(host) for host in (state.get("httpx_candidate_hosts") or [])
            if str(host) not in set(new_hosts)
        ]
        state["httpx_candidate_hosts"] = pending
        promotions = list(state.get("httpx_endpoint_promotions") or [])
        promotions.append({
            "source_item_id": source_item.id,
            "hosts": new_hosts,
            "endpoint_count": len(urls),
            "created_at": datetime.now().isoformat(),
        })
        state["httpx_endpoint_promotions"] = promotions[-100:]
        job.state_data = _preserve_runtime_execution_state(db, job, state)
        db.flush()
    if urls:
        generate_hypotheses_for_scan(db, job)
    return {
        "endpoints": len(urls),
        "confirmed_hosts": confirmed_hosts,
        "promoted_hosts": new_hosts,
        "work_items_created": int(seed.get("created") or 0),
    }


def _extract_endpoints_from_result(tool_name: str, result: dict, base_target: str) -> set[str]:
    """Extrai URLs descobertas do resultado bruto do tool (robusto a parser)."""
    urls: set[str] = set()
    if not isinstance(result, dict):
        return urls
    base_host = _host_of(base_target) or base_target

    # 1) campos já parseados, se existirem
    parsed = result.get("parsed_result") or {}
    if isinstance(parsed, dict):
        for key in ("discovered_urls", "urls", "endpoints"):
            for u in (parsed.get(key) or []):
                if isinstance(u, str) and u.startswith("http"):
                    urls.add(u.split("#")[0])
        for key in ("discovered_paths", "paths"):
            for p in (parsed.get(key) or []):
                path = p.get("url") if isinstance(p, dict) else p
                if isinstance(path, str):
                    if path.startswith("http"):
                        urls.add(path.split("#")[0])
                    elif path.startswith("/"):
                        urls.add(f"https://{base_host}{path.split('#')[0]}")

    # 2) varredura do stdout (cobre tools cujo parser não captura nada)
    stdout = str(result.get("stdout_full") or result.get("stdout_preview") or result.get("stdout") or "")
    if stdout:
        for m in _URL_RE.finditer(stdout):
            urls.add(m.group(0).split("#")[0])
        # ffuf/gobuster/feroxbuster: linhas com path e status
        for m in re.finditer(r"^\s*(/[^\s\"']{1,200})\s", stdout, re.M):
            urls.add(f"https://{base_host}{m.group(1).split('#')[0]}")

    # This extractor feeds discovery/surface expansion.  Do not apply the
    # active-test endpoint filter here: short semantic routes such as /aa or
    # /bb are still valid discovered surface, and the later work-item
    # applicability layer decides whether they deserve active testing.
    return {u for u in urls if u.startswith("http")}


def _seed_test_item(db, scan_id, phase_id, target, tool_name, metadata, *, execution_context: str = "external") -> bool:
    from app.models.models import ScanWorkItem
    from app.services.scan_work_queue import apply_phase_tool_metadata, resource_class_for_tool, PHASE_PRIORITY
    from app.services.scan_scope import authorized_scope_for_scan, is_host_in_scope

    authorized_scope = authorized_scope_for_scan(db, scan_id)
    if authorized_scope and not is_host_in_scope(_host_of(target), authorized_scope):
        return False

    already = db.query(ScanWorkItem.id).filter(
        ScanWorkItem.scan_job_id == scan_id,
        ScanWorkItem.execution_context == execution_context,
        ScanWorkItem.phase_id == phase_id,
        ScanWorkItem.tool_name == tool_name,
        ScanWorkItem.target == target[:500],
    ).first()
    if already:
        return False
    rc = resource_class_for_tool(tool_name)
    pri = PHASE_PRIORITY.get(phase_id, 100) + {"light": 0, "medium": 5, "heavy": 12}.get(rc, 0)
    item_metadata = apply_phase_tool_metadata(metadata, phase_id, tool_name, source=str((metadata or {}).get("source") or "endpoint_discovery"))
    item_metadata["execution_context"] = execution_context
    auth_session_revision = 0
    if execution_context == "internal":
        try:
            from app.services.execution_context_service import get_context

            internal = get_context(db, scan_id, "internal")
            auth_session_revision = int(internal.session_revision or 0) if internal else 0
            if internal and internal.identity_key:
                item_metadata["identity_key"] = internal.identity_key
        except Exception:
            pass
    item_metadata["queue_ready_at"] = datetime.now().isoformat()
    db.add(ScanWorkItem(
        scan_job_id=scan_id, execution_context=execution_context,
        auth_session_revision=auth_session_revision,
        phase_id=phase_id, target=target[:500],
        tool_name=tool_name, profile=tool_name, resource_class=rc,
        priority=pri - 10, status="queued", max_attempts=2,
        item_metadata=item_metadata,
        created_at=datetime.now(), updated_at=datetime.now(),
    ))
    try:
        db.flush()
        return True
    except Exception:
        db.rollback()
        return False


def _internal_endpoint_analysis_matrix(url: str, analysis: dict) -> list[tuple[str, str]]:
    """Context-safe fan-out for an endpoint discovered only after login."""
    lower = str(url or "").lower()
    classifications = dict(analysis.get("classification") or {})
    matrix: list[tuple[str, str]] = []
    is_js = re.search(r"\.(?:js|mjs|cjs)(?:\?|$)", lower) is not None
    is_api = bool(classifications.get("api") or any(token in lower for token in ("/api/", "/rest/", "/graphql")))
    is_input = bool("?" in url or classifications.get("input_surface") or is_api)
    parsed = urlparse(url)
    leaf = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    directory_like = parsed.path.endswith("/") or "." not in leaf
    if directory_like:
        matrix.extend([("P03", "katana"), ("P03", "ffuf"), ("P03", "feroxbuster")])
    if is_api:
        matrix.extend([("P03", "dirsearch-api"), ("P03", "dirsearch-api-post")])
    if is_js:
        matrix.extend([
            ("P08", "linkfinder"),
            ("P08", "nuclei-js-analysis"),
            ("P08", "nuclei-js-secrets"),
        ])
    if is_input:
        matrix.extend([("P04", "arjun"), ("P04", "ffuf-params")])
    if is_api:
        matrix.extend([("P16", "nuclei"), ("P16", "wapiti")])
    if classifications.get("sensitive_function") or is_api:
        matrix.append(("P13", "bl-test"))
    matrix.append(("P09", "nuclei"))
    return list(dict.fromkeys(matrix))


def expand_attack_surface(db: Session, scan_id: int, source_target: str,
                          tool_name: str, result: dict, job,
                          *, execution_context: str = "external") -> dict:
    """Ponto de entrada — chamado quando um tool de discovery completa."""
    from app.services.execution_context_service import normalize_execution_context

    execution_context = normalize_execution_context(execution_context)
    if str(tool_name or "").lower() not in _DISCOVERY_TOOLS:
        return {"skipped": "not_discovery_tool"}
    if not _acquire_expansion_lock(db, scan_id):
        return {"skipped": "surface_expansion_already_running"}

    state = dict(job.state_data or {})
    seen: set[str] = set(state.get("discovered_endpoints") or [])
    try:
        from app.models.models import EndpointObservation, OffensiveEndpoint

        context_seen = {
            str(row[0])
            for row in (
                db.query(OffensiveEndpoint.url)
                .join(EndpointObservation, EndpointObservation.endpoint_id == OffensiveEndpoint.id)
                .filter(
                    OffensiveEndpoint.scan_job_id == scan_id,
                    EndpointObservation.execution_context == execution_context,
                )
                .all()
            )
        }
    except Exception:
        context_seen = set(seen) if execution_context == "external" else set()
    fetched_count = int(state.get("se_fetched_count") or 0)
    reseeded_count = int(state.get("se_reseeded_count") or 0)

    from app.services.scan_scope import authorized_scope_for_scan, is_host_in_scope

    authorized_scope = authorized_scope_for_scan(db, scan_id)
    found = _extract_endpoints_from_result(tool_name, result, source_target)
    # Escopo estrito: alvo autorizado exato ou subdomínio dele — NÃO o
    # domínio registrável inteiro. O incidente que isto corrige: waybackurls
    # devolveu uma URL arquivada em ri.valid.com a partir de um crawl de
    # www.valid.com; o filtro antigo (_root_domain, "mesmo domínio
    # registrável") tratava os dois como equivalentes e reinjetava
    # ri.valid.com como alvo de teste ativo sem nenhuma checagem real de
    # escopo. Um scan autorizado para www.valid.com não autoriza nada em
    # outro host do mesmo domínio pai.
    out_of_scope: list[str] = []
    new_eps = []
    for u in found:
        if u in context_seen:
            continue
        host = _host_of(u)
        if authorized_scope and not is_host_in_scope(host, authorized_scope):
            out_of_scope.append(u)
            continue
        new_eps.append(u)
    if out_of_scope:
        state["out_of_scope_endpoints_skipped"] = sorted(
            set(state.get("out_of_scope_endpoints_skipped") or []) | set(out_of_scope)
        )[:200]
        job.state_data = _preserve_runtime_execution_state(db, job, state)
        logger.info(
            "surface_expansion scan=%d fora_do_escopo=%d exemplos=%s",
            scan_id, len(out_of_scope), out_of_scope[:5],
        )
    if not new_eps:
        return {"new_endpoints": 0, "out_of_scope_skipped": len(out_of_scope)}

    new_eps.sort(key=lambda u: (0 if _HIGH_VALUE.search(u) else 1, len(u), u))
    _surface_started = time.monotonic()
    _surface_last_progress = _surface_started
    _emit_surface_progress(
        scan_id,
        (
            f"surface_expansion_started tool={tool_name} target={source_target} "
            f"candidates={len(found)} new_in_scope={len(new_eps)}"
        ),
    )
    try:
        from app.services.crawler_result_normalizer import normalize_crawler_result
        from app.services.hypothesis_rules import generate_hypotheses_for_scan
        from app.models.models import OffensiveEndpoint

        from app.services.execution_context_service import inventory_auth_context

        normalize_crawler_result(
            db,
            job,
            target=source_target,
            tool_name=tool_name,
            result=result,
            auth_context=inventory_auth_context(execution_context),
            execution_context=execution_context,
        )
        generate_hypotheses_for_scan(db, job)
        # The normalizer understands additional tool-specific formats. Merge
        # its in-scope inventory back into the candidate set so a URL found
        # there cannot remain invisible to HTTPX promotion.
        normalized_urls = (
            db.query(OffensiveEndpoint.normalized_url)
            .filter(OffensiveEndpoint.scan_job_id == scan_id)
            .order_by(OffensiveEndpoint.id.asc())
            .limit(10_000)
            .all()
        )
        for (normalized_url,) in normalized_urls:
            value = str(normalized_url or "").strip()
            if value and value not in seen and value not in new_eps and is_host_in_scope(_host_of(value), authorized_scope):
                new_eps.append(value)
    except Exception as exc:
        logger.debug("offensive inventory normalization falhou: %s", exc)

    # A newly observed host is a candidate, not yet a broad test target. Send
    # it through HTTPX. Only HTTPX's post-filtered in-scope output is allowed
    # to promote it into the full test matrix.
    known_test_hosts = {
        _host_of(str(value)) or str(value or "").strip().lower()
        for value in (
            list(state.get("expanded_targets") or [])
            + list(state.get("parallel_delegated_targets") or [])
            + list(state.get("httpx_candidate_hosts") or [])
            + [source_target]
        )
        if str(value or "").strip()
    }
    new_test_hosts = discovered_in_scope_hosts_for_testing(
        new_eps,
        authorized_scope,
        known_test_hosts,
    )
    host_seed = {"created": 0, "existing": 0, "skipped": 0}
    if new_test_hosts:
        candidate_hosts = list(state.get("httpx_candidate_hosts") or [])
        for host in new_test_hosts:
            if host not in candidate_hosts:
                candidate_hosts.append(host)
        state["httpx_candidate_hosts"] = candidate_hosts
        host_events = list(state.get("discovered_host_test_queue") or [])
        host_events.append({
            "source": "endpoint_discovery_pending_httpx",
            "tool": tool_name,
            "source_target": source_target,
            "hosts": new_test_hosts,
            "created_at": datetime.now().isoformat(),
        })
        state["discovered_host_test_queue"] = host_events[-100:]
        job.state_data = _preserve_runtime_execution_state(db, job, state)
        db.flush()
        try:
            from app.services.scan_work_queue import enqueue_httpx_scope_candidates

            host_seed = enqueue_httpx_scope_candidates(
                db,
                job,
                new_test_hosts,
                source="endpoint_host_discovery_pending_httpx",
            )
            state = dict(job.state_data or state)
        except Exception as exc:
            logger.warning("endpoint host test seeding failed scan=%d hosts=%s: %s", scan_id, new_test_hosts, exc)
    for u in new_eps:
        seen.add(u)

    state["discovered_endpoints"] = list(seen)[:5000]
    if execution_context == "internal":
        state["internal_discovered_endpoints"] = sorted(
            set(state.get("internal_discovered_endpoints") or []) | set(new_eps)
        )[:5000]
    state["endpoint_test_targets"] = list(seen)[:10000]
    job.state_data = _preserve_runtime_execution_state(db, job, state)
    db.flush()

    findings: list[dict] = []
    reseeded = 0
    fetched = 0
    request_headers: dict[str, str] = {}
    request_cookies: dict[str, str] = {}
    if execution_context == "internal":
        try:
            from app.services.auth_session_manager import AuthSessionManager

            material = AuthSessionManager(db, job).get_material()
            if material and material.valid:
                request_headers = dict(material.headers or {})
                request_cookies = dict(material.cookies or {})
        except Exception:
            logger.warning("internal page analysis has no valid auth material scan=%d", scan_id)
        finally:
            db.flush()

    for url_index, url in enumerate(new_eps, start=1):
        hv = bool(_HIGH_VALUE.search(url))
        has_param = "?" in url and "=" in url

        # (a) Abrir páginas de alto valor → segredos + endpoints + scripts externos
        if hv and fetched < _MAX_PER_EVENT_FETCH and fetched_count < _MAX_FETCH_PER_SCAN:
            try:
                from app.services.page_analyzer import fetch_and_extract
                info = fetch_and_extract(
                    url,
                    headers=request_headers,
                    cookies=request_cookies,
                )
                fetched += 1
                fetched_count += 1
                if info.get("ok"):
                    # endpoints novos do corpo realimentam o conjunto — mesma
                    # checagem estrita de escopo do filtro inicial (não
                    # _root_domain/mesmo-domínio-registrável).
                    for e in info.get("endpoints_same_domain", []):
                        if e not in seen and is_host_in_scope(_host_of(e), authorized_scope):
                            new_eps.append(e) if len(new_eps) < 400 else None
                            seen.add(e)
                    # segredos hardcoded → finding
                    for sec in info.get("secrets", []):
                        findings.append({
                            "title": f"Segredo hardcoded exposto ({sec['type']}) em página",
                            "severity": "high", "risk_score": 8,
                            "details": {
                                "tool": "page_analyzer", "asset": url, "matched_at": url,
                                "evidence": f"{sec['type']}: {sec['match']}",
                                "owasp_category": "A05:2021 Security Misconfiguration",
                                "verification_status": "candidate",
                                "discovery_method": "page fetch (GET) + regex de segredos",
                            },
                        })
                    # scripts de domínio externo → possível script injection
                    for ext in info.get("external_scripts", []):
                        findings.append({
                            "title": f"Script de domínio externo carregado ({_host_of(ext)}) — possível Script Injection",
                            "severity": "medium", "risk_score": 5,
                            "details": {
                                "tool": "page_analyzer", "asset": url, "matched_at": url,
                                "evidence": f"<script src=\"{ext}\"> em {url}",
                                "owasp_category": "A08:2021 Software and Data Integrity Failures",
                                "verification_status": "candidate",
                                "external_domain": _host_of(ext),
                                "discovery_method": "page fetch (GET) + análise de <script src>",
                            },
                        })
            except Exception as exc:
                logger.debug("page fetch falhou %s: %s", url, exc)

        # (b) Reinjetar como ALVO DE TESTE (fecha o loop)
        if (execution_context == "internal" or hv or has_param) and reseeded < _MAX_PER_EVENT_RESEED and reseeded_count < _MAX_RESEED_PER_SCAN:
            meta = {
                "source": "surface_expansion", "engine": "endpoint_discovery",
                "discovered_by": tool_name, "discovered_from": source_target,
                "rationale": f"Endpoint descoberto por {tool_name} → reinjetado para teste ativo.",
            }
            # Active validators are selected later from the persisted endpoint
            # test matrix. Discovery only seeds context-safe broad probes.
            from app.services.endpoint_analysis_pipeline import analyze_endpoint_contract, recommended_execution_tools

            analysis = analyze_endpoint_contract(
                url,
                auth_required=True if execution_context == "internal" else None,
            )
            tools = recommended_execution_tools(analysis)
            phase_tools = [("P09", tool) for tool in tools]
            if execution_context == "internal":
                phase_tools.extend(_internal_endpoint_analysis_matrix(url, analysis))
            seeded_this_url = 0
            for phase_id, tn in list(dict.fromkeys(phase_tools)):
                if _seed_test_item(db, scan_id, phase_id, url, tn, meta, execution_context=execution_context):
                    reseeded += 1
                    reseeded_count += 1
                    seeded_this_url += 1
                if reseeded >= _MAX_PER_EVENT_RESEED:
                    break
            if seeded_this_url:
                db.flush()

        _surface_now = time.monotonic()
        if _surface_now - _surface_last_progress >= 30:
            _emit_surface_progress(
                scan_id,
                (
                    f"surface_expansion_progress tool={tool_name} "
                    f"processed={url_index}/{len(new_eps)} fetched={fetched} "
                    f"reseeded={reseeded} elapsed={int(_surface_now - _surface_started)}s"
                ),
            )
            _surface_last_progress = _surface_now

    # Persistir contadores e conjunto (cap p/ não inchar state)
    state["discovered_endpoints"] = list(seen)[:5000]
    if execution_context == "internal":
        state["internal_discovered_endpoints"] = sorted(
            set(state.get("internal_discovered_endpoints") or []) | set(new_eps)
        )[:5000]
    state["endpoint_test_targets"] = list(seen)[:10000]
    state["se_fetched_count"] = fetched_count
    state["se_reseeded_count"] = reseeded_count
    job.state_data = _preserve_runtime_execution_state(db, job, state)

    if findings:
        try:
            from app.services.findings_extractor import persist_finding_dicts
            persist_finding_dicts(db, job, findings,
                                  default_tool="page_analyzer", default_target=source_target,
                                  source_item=None)
        except Exception as exc:
            logger.debug("persist surface findings falhou: %s", exc)

    if execution_context == "internal":
        try:
            from app.services.endpoint_analysis_pipeline import analyze_endpoints_for_scan
            from app.services.hypothesis_rules import generate_hypotheses_for_scan
            from app.services.execution_context_service import (
                compute_external_internal_diff,
                reopen_auth_blocked_hypotheses,
            )

            analyze_endpoints_for_scan(db, job)
            generate_hypotheses_for_scan(db, job)
            reopen_auth_blocked_hypotheses(db, job)
            compute_external_internal_diff(db, job)
        except Exception as exc:
            logger.warning("internal endpoint analysis fan-out failed scan=%d: %s", scan_id, exc)

    db.flush()

    logger.info(
        "surface_expansion scan=%d tool=%s novos=%d novos_hosts=%d host_items=%d abertos=%d reinjetados=%d segredos+scripts=%d fora_do_escopo=%d",
        scan_id, tool_name, len(new_eps), len(new_test_hosts), int(host_seed.get("created") or 0), fetched, reseeded, len(findings), len(out_of_scope),
    )
    _emit_surface_progress(
        scan_id,
        (
            f"surface_expansion_finished tool={tool_name} target={source_target} "
            f"new={len(new_eps)} fetched={fetched} reseeded={reseeded} "
            f"findings={len(findings)} elapsed={int(time.monotonic() - _surface_started)}s"
        ),
    )
    return {
        "new_endpoints": len(new_eps), "fetched": fetched,
        "reseeded": reseeded, "findings": len(findings),
        "new_test_hosts": len(new_test_hosts),
        "host_work_items_created": int(host_seed.get("created") or 0),
        "out_of_scope_skipped": len(out_of_scope),
    }
