"""Frente E — expansão de superfície que REALIMENTA o pentest.

Fecha o loop que faltava: quando um tool de crawl/fuzz (ffuf/feroxbuster/
katana/gospider/hakrawler/gobuster/dirsearch) descobre páginas, este motor:
  1. extrai os endpoints descobertos do resultado bruto (independente de o
     parser de findings ter funcionado);
  2. abre as páginas de alto valor (page_analyzer) → novos endpoints + segredos
     hardcoded + scripts de domínio externo;
  3. REINJETA os endpoints in-scope como novos alvos de teste (nuclei/dalfox/
     sqlmap por endpoint com parâmetro);
  4. gera findings para segredos expostos e para referência cross-domain
     (possível script injection).

Tudo somente-leitura — respeita o guardrail (nenhum efeito destrutivo).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime

from sqlalchemy.orm import Session

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


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url or "")
    return m.group(1).lower() if m else ""


def _root_domain(host: str) -> str:
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


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

    return {u for u in urls if u.startswith("http")}


def _seed_test_item(db, scan_id, phase_id, target, tool_name, metadata) -> bool:
    from app.models.models import ScanWorkItem
    from app.services.scan_work_queue import apply_phase_tool_metadata, resource_class_for_tool, PHASE_PRIORITY

    already = db.query(ScanWorkItem.id).filter(
        ScanWorkItem.scan_job_id == scan_id,
        ScanWorkItem.phase_id == phase_id,
        ScanWorkItem.tool_name == tool_name,
        ScanWorkItem.target == target[:500],
    ).first()
    if already:
        return False
    rc = resource_class_for_tool(tool_name)
    pri = PHASE_PRIORITY.get(phase_id, 100) + {"light": 0, "medium": 5, "heavy": 12}.get(rc, 0)
    db.add(ScanWorkItem(
        scan_job_id=scan_id, phase_id=phase_id, target=target[:500],
        tool_name=tool_name, profile=tool_name, resource_class=rc,
        priority=pri - 10, status="queued", max_attempts=2,
        item_metadata=apply_phase_tool_metadata(metadata, phase_id, tool_name, source=str((metadata or {}).get("source") or "endpoint_discovery")),
        created_at=datetime.now(), updated_at=datetime.now(),
    ))
    try:
        db.flush()
        return True
    except Exception:
        db.rollback()
        return False


def expand_attack_surface(db: Session, scan_id: int, source_target: str,
                          tool_name: str, result: dict, job) -> dict:
    """Ponto de entrada — chamado quando um tool de discovery completa."""
    if str(tool_name or "").lower() not in _DISCOVERY_TOOLS:
        return {"skipped": "not_discovery_tool"}

    state = dict(job.state_data or {})
    seen: set[str] = set(state.get("discovered_endpoints") or [])
    fetched_count = int(state.get("se_fetched_count") or 0)
    reseeded_count = int(state.get("se_reseeded_count") or 0)

    root = _root_domain(_host_of(source_target) or source_target)
    found = _extract_endpoints_from_result(tool_name, result, source_target)
    # Novos, in-scope (mesmo domínio registrável)
    new_eps = [
        u for u in found
        if u not in seen and _root_domain(_host_of(u)) == root
    ]
    if not new_eps:
        return {"new_endpoints": 0}

    new_eps.sort(key=lambda u: (0 if _HIGH_VALUE.search(u) else 1, len(u)))
    try:
        from app.services.crawler_result_normalizer import normalize_crawler_result
        from app.services.hypothesis_rules import generate_hypotheses_for_scan

        normalize_crawler_result(
            db,
            job,
            target=source_target,
            tool_name=tool_name,
            result=result,
            auth_context="anonymous",
        )
        generate_hypotheses_for_scan(db, job)
    except Exception as exc:
        logger.debug("offensive inventory normalization falhou: %s", exc)
    for u in new_eps:
        seen.add(u)

    findings: list[dict] = []
    reseeded = 0
    fetched = 0

    for url in new_eps:
        hv = bool(_HIGH_VALUE.search(url))
        has_param = "?" in url and "=" in url

        # (a) Abrir páginas de alto valor → segredos + endpoints + scripts externos
        if hv and fetched < _MAX_PER_EVENT_FETCH and fetched_count < _MAX_FETCH_PER_SCAN:
            try:
                from app.services.page_analyzer import fetch_and_extract
                info = fetch_and_extract(url, scope_root=root)
                fetched += 1
                fetched_count += 1
                if info.get("ok"):
                    # endpoints novos do corpo realimentam o conjunto
                    for e in info.get("endpoints_same_domain", []):
                        if e not in seen and _root_domain(_host_of(e)) == root:
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
                                "verification_status": "confirmed",
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
                                "verification_status": "confirmed",
                                "external_domain": _host_of(ext),
                                "discovery_method": "page fetch (GET) + análise de <script src>",
                            },
                        })
            except Exception as exc:
                logger.debug("page fetch falhou %s: %s", url, exc)

        # (b) Reinjetar como ALVO DE TESTE (fecha o loop)
        if (hv or has_param) and reseeded < _MAX_PER_EVENT_RESEED and reseeded_count < _MAX_RESEED_PER_SCAN:
            meta = {
                "source": "surface_expansion", "engine": "endpoint_discovery",
                "discovered_by": tool_name, "discovered_from": source_target,
                "rationale": f"Endpoint descoberto por {tool_name} → reinjetado para teste ativo.",
            }
            # endpoint com parâmetro → injeção; senão → nuclei genérico
            tools = ["nuclei"]
            if has_param:
                tools = ["nuclei-sqli", "dalfox", "nuclei-xss"]
            for tn in tools:
                if _seed_test_item(db, scan_id, "P09", url, tn, meta):
                    reseeded += 1
                    reseeded_count += 1
                if reseeded >= _MAX_PER_EVENT_RESEED:
                    break

    # Persistir contadores e conjunto (cap p/ não inchar state)
    state["discovered_endpoints"] = list(seen)[:5000]
    state["se_fetched_count"] = fetched_count
    state["se_reseeded_count"] = reseeded_count
    job.state_data = state

    if findings:
        try:
            from app.services.findings_extractor import persist_finding_dicts
            persist_finding_dicts(db, job, findings,
                                  default_tool="page_analyzer", default_target=source_target,
                                  source_item=None)
        except Exception as exc:
            logger.debug("persist surface findings falhou: %s", exc)

    try:
        db.commit()
    except Exception:
        db.rollback()

    logger.info(
        "surface_expansion scan=%d tool=%s novos=%d abertos=%d reinjetados=%d segredos+scripts=%d",
        scan_id, tool_name, len(new_eps), fetched, reseeded, len(findings),
    )
    return {
        "new_endpoints": len(new_eps), "fetched": fetched,
        "reseeded": reseeded, "findings": len(findings),
    }
