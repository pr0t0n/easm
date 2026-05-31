"""
zap_scanner.py — Integração com OWASP ZAP via REST API.

Fluxo para cada tipo de scan:
  zap-baseline → passive scan + quick spider (≤ 2 min, sem ataques)
  zap-ajax     → AJAX spider com headless browser (SPAs React/Vue/Angular)
  zap-active   → active scan completo OWASP Top 10 (fuzz params/headers)
  zap-api      → scan orientado a OpenAPI/Swagger (testa todos os endpoints)

ZAP corre como serviço Docker separado (scriptkiddo_zap, porta 8090).
Backend chama esta API; nenhuma dependência do kali_runner.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

_ZAP_BASE = os.getenv("ZAP_URL", "http://zap:8090").rstrip("/")
_ZAP_API_KEY = os.getenv("ZAP_API_KEY", "scriptkiddo-zap-key")

# Timeouts (segundos)
_SPIDER_MAX_WAIT = 120      # spider passivo/ativo
_AJAX_MAX_WAIT = 180        # AJAX spider (mais lento — usa browser)
_ACTIVE_MAX_WAIT = 1800     # active scan completo (30 min)
_API_SCAN_MAX_WAIT = 900    # API scan (15 min)

# Severidade ZAP → plataforma
_ZAP_RISK_MAP = {
    "3": "high",     # High
    "2": "medium",   # Medium
    "1": "low",      # Low
    "0": "info",     # Informational
}
# ZAP confidence
_ZAP_CONFIDENCE_MAP = {
    "3": "confirmed",
    "2": "likely",
    "1": "hypothesis",
    "0": "hypothesis",
}


def _zap(path: str, params: dict | None = None) -> dict:
    """Chama um endpoint GET da API ZAP."""
    p = {"apikey": _ZAP_API_KEY, **(params or {})}
    url = f"{_ZAP_BASE}{path}"
    resp = requests.get(url, params=p, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _zap_post(path: str, data: dict | None = None) -> dict:
    """Chama um endpoint POST/ACTION da API ZAP."""
    d = {"apikey": _ZAP_API_KEY, **(data or {})}
    url = f"{_ZAP_BASE}{path}"
    resp = requests.post(url, data=d, timeout=30)
    resp.raise_for_status()
    return resp.json()


def is_zap_available() -> bool:
    """Verifica se o ZAP está rodando e acessível."""
    try:
        data = _zap("/JSON/core/view/version/")
        return bool(data.get("version"))
    except Exception:
        return False


def _apply_auth_headers(auth_headers: dict[str, str] | None) -> list[str]:
    """Configura scan autenticado: injeta cabeçalhos em TODA requisição do ZAP.

    Usa a extensão Replacer do ZAP (regras REQ_HEADER) — funciona para spider,
    AJAX e active scan. Retorna a lista de descrições de regra criadas (para
    posterior limpeza). Falha graciosamente.
    """
    created: list[str] = []
    if not auth_headers:
        return created
    for name, value in auth_headers.items():
        if not name or value is None:
            continue
        desc = f"easm-auth-{name}"
        try:
            # matchType REQ_HEADER + matchString=<header> + replacement=<value>
            _zap_post("/JSON/replacer/action/addRule/", {
                "description": desc,
                "enabled": "true",
                "matchType": "REQ_HEADER",
                "matchString": str(name),
                "matchRegex": "false",
                "replacement": str(value),
            })
            created.append(desc)
        except Exception as exc:
            logger.debug("ZAP replacer addRule falhou para %s: %s", name, exc)
    return created


def _clear_auth_headers(descriptions: list[str]) -> None:
    """Remove as regras de auth criadas (evita vazar credenciais entre alvos)."""
    for desc in descriptions or []:
        try:
            _zap_post("/JSON/replacer/action/removeRule/", {"description": desc})
        except Exception:
            pass


def _wait_for_spider(scan_id: str, max_wait: int = _SPIDER_MAX_WAIT) -> None:
    """Aguarda o spider ZAP completar."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            status = _zap("/JSON/spider/view/status/", {"scanId": scan_id})
            pct = int(status.get("status") or 0)
            if pct >= 100:
                return
        except Exception:
            pass
        time.sleep(3)
    logger.warning("ZAP spider timeout after %ds", max_wait)


def _wait_for_ajax_spider(max_wait: int = _AJAX_MAX_WAIT) -> None:
    """Aguarda o AJAX spider ZAP completar (não tem scanId como o spider)."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            status = _zap("/JSON/ajaxSpider/view/status/")
            if status.get("status") == "stopped":
                return
        except Exception:
            pass
        time.sleep(5)
    logger.warning("ZAP AJAX spider timeout after %ds", max_wait)


def _wait_for_active_scan(scan_id: str, max_wait: int = _ACTIVE_MAX_WAIT) -> None:
    """Aguarda o active scan ZAP completar."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            status = _zap("/JSON/ascan/view/status/", {"scanId": scan_id})
            pct = int(status.get("status") or 0)
            if pct >= 100:
                return
        except Exception:
            pass
        time.sleep(10)
    logger.warning("ZAP active scan timeout after %ds", max_wait)


def _get_alerts(target: str) -> list[dict]:
    """Obtém todos os alertas ZAP para o target."""
    try:
        data = _zap("/JSON/alert/view/alertsByRisk/", {
            "url": target,
            "recurse": "true",
        })
        # alertsByRisk returns {High: [...], Medium: [...], Low: [...], Informational: [...]}
        alerts = []
        for level_name, items in (data or {}).items():
            if isinstance(items, list):
                for item in items:
                    item["_risk_name"] = level_name.lower()
                    alerts.append(item)
        return alerts
    except Exception:
        # Fallback: get all alerts
        try:
            data = _zap("/JSON/core/view/alerts/", {"baseurl": target})
            return list(data.get("alerts") or [])
        except Exception as exc:
            logger.debug("ZAP get alerts error: %s", exc)
            return []


def _alerts_to_findings(alerts: list[dict], target: str) -> list[dict]:
    """Converte alertas ZAP para o formato de findings da plataforma."""
    findings = []
    for alert in alerts:
        risk = str(alert.get("risk") or alert.get("_risk_name") or "0")
        confidence = str(alert.get("confidence") or "1")

        # severity
        if risk.isdigit():
            severity = _ZAP_RISK_MAP.get(risk, "info")
        else:
            severity = risk.lower() if risk.lower() in ("high", "medium", "low", "info") else "info"

        # confidence/validation
        if confidence.isdigit():
            val_status = _ZAP_CONFIDENCE_MAP.get(confidence, "hypothesis")
        else:
            val_status = "hypothesis"

        cwe_id = str(alert.get("cweid") or "")
        wasc_id = str(alert.get("wascid") or "")
        plugin_id = str(alert.get("pluginId") or alert.get("id") or "")
        name = str(alert.get("name") or alert.get("alert") or "ZAP Finding")
        description = str(alert.get("desc") or alert.get("description") or "")
        solution = str(alert.get("solution") or "")
        reference = str(alert.get("reference") or "")
        url = str(alert.get("url") or target)
        evidence = str(alert.get("evidence") or "")
        param = str(alert.get("param") or "")
        attack = str(alert.get("attack") or "")
        other_info = str(alert.get("other") or "")

        # Build evidence string
        evidence_parts = []
        if url:
            evidence_parts.append(f"URL: {url}")
        if param:
            evidence_parts.append(f"Parâmetro: {param}")
        if evidence:
            evidence_parts.append(f"Evidência: {evidence[:300]}")
        if attack:
            evidence_parts.append(f"Ataque: {attack[:200]}")

        findings.append({
            "title": name,
            "description": description[:2000] if description else name,
            "severity": severity,
            "validation_status": val_status,
            "source_tool": "zap",
            "evidence": " | ".join(evidence_parts)[:1000],
            "details": {
                "source": "owasp_zap",
                "plugin_id": plugin_id,
                "cwe_id": cwe_id,
                "wasc_id": wasc_id,
                "solution": solution[:1000] if solution else "",
                "reference": reference[:500] if reference else "",
                "other_info": other_info[:500] if other_info else "",
                "confidence": confidence,
                "url": url,
                "param": param,
                "attack": attack[:300] if attack else "",
                "zap_scan_type": "passive",  # updated per scan type
            },
        })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Scan entry points
# ─────────────────────────────────────────────────────────────────────────────

def run_zap_baseline(target: str, auth_headers: dict[str, str] | None = None) -> dict[str, Any]:
    """
    ZAP Baseline: passive scan + quick spider.
    Não faz ataques ativos. Baixo ruído, rápido (1-2 min).
    Ideal para: todos os alvos HTTP/HTTPS descobertos.

    auth_headers: se fornecido, faz scan AUTENTICADO (injeta os cabeçalhos em
    toda requisição do ZAP, alcançando endpoints pós-login).
    """
    if not is_zap_available():
        return {"error": "ZAP service unavailable", "findings": []}

    _auth_rules = _apply_auth_headers(auth_headers)
    try:
        # Access target to populate ZAP proxy (baseline access)
        try:
            _zap_post("/JSON/core/action/accessUrl/", {"url": target, "followRedirects": "true"})
        except Exception as exc:
            logger.debug("ZAP accessUrl error: %s", exc)

        # Start passive spider
        try:
            spider_data = _zap_post("/JSON/spider/action/scan/", {
                "url": target,
                "maxChildren": "0",
                "recurse": "true",
                "contextName": "",
                "subtreeOnly": "false",
            })
            scan_id = str(spider_data.get("scan") or "0")
            _wait_for_spider(scan_id, max_wait=_SPIDER_MAX_WAIT)
        except Exception as exc:
            logger.warning("ZAP spider error: %s", exc)

        alerts = _get_alerts(target)
    finally:
        _clear_auth_headers(_auth_rules)

    findings = _alerts_to_findings(alerts, target)
    for f in findings:
        f["details"]["zap_scan_type"] = "baseline"
        if auth_headers:
            f["details"]["authenticated_scan"] = True

    return {
        "scan_type": "zap-baseline",
        "target": target,
        "alert_count": len(alerts),
        "authenticated": bool(auth_headers),
        "findings": findings,
    }


def run_zap_ajax_spider(target: str, max_duration_mins: int = 3) -> dict[str, Any]:
    """
    ZAP AJAX Spider: usa headless browser para navegar SPAs.
    Descobre rotas dinâmicas que katana/gospider não encontram.
    Ideal para: targets com React/Vue/Angular confirmado.
    """
    if not is_zap_available():
        return {"error": "ZAP service unavailable", "findings": []}

    try:
        _zap_post("/JSON/ajaxSpider/action/scan/", {
            "url": target,
            "inScope": "false",
            "contextName": "",
            "subtreeOnly": "false",
        })
        _wait_for_ajax_spider(max_wait=max_duration_mins * 60)
    except Exception as exc:
        logger.warning("ZAP AJAX spider error: %s", exc)

    # Get discovered URLs
    try:
        results_data = _zap("/JSON/ajaxSpider/view/results/")
        discovered_urls = [
            str(r.get("requestHeader", "").split("\n")[0]).replace("GET ", "").split(" HTTP")[0]
            for r in (results_data.get("results") or [])
        ]
    except Exception:
        discovered_urls = []

    alerts = _get_alerts(target)
    findings = _alerts_to_findings(alerts, target)
    for f in findings:
        f["details"]["zap_scan_type"] = "ajax_spider"

    return {
        "scan_type": "zap-ajax",
        "target": target,
        "discovered_urls": discovered_urls[:100],
        "discovered_url_count": len(discovered_urls),
        "alert_count": len(alerts),
        "findings": findings,
    }


def run_zap_active_scan(target: str, auth_headers: dict[str, str] | None = None) -> dict[str, Any]:
    """
    ZAP Active Scan: fuzzing ativo para OWASP Top 10.
    Detecta: SQLi, XSS, SSRF, Path Traversal, Command Injection, etc.
    Pode ser lento (até 30 min para targets grandes).

    auth_headers: scan autenticado (alcança endpoints pós-login).
    """
    if not is_zap_available():
        return {"error": "ZAP service unavailable", "findings": []}

    _auth_rules = _apply_auth_headers(auth_headers)
    try:
        # Spider first to populate sitemap
        try:
            spider_data = _zap_post("/JSON/spider/action/scan/", {
                "url": target, "recurse": "true", "subtreeOnly": "false",
            })
            scan_id = str(spider_data.get("scan") or "0")
            _wait_for_spider(scan_id, max_wait=120)
        except Exception:
            pass

        # Active scan
        try:
            ascan_data = _zap_post("/JSON/ascan/action/scan/", {
                "url": target,
                "recurse": "true",
                "inScopeOnly": "false",
                "scanPolicyName": "",
                "method": "",
                "postData": "",
            })
            ascan_id = str(ascan_data.get("scan") or "0")
            _wait_for_active_scan(ascan_id, max_wait=_ACTIVE_MAX_WAIT)
        except Exception as exc:
            logger.warning("ZAP active scan error: %s", exc)

        alerts = _get_alerts(target)
    finally:
        _clear_auth_headers(_auth_rules)

    findings = _alerts_to_findings(alerts, target)
    for f in findings:
        f["details"]["zap_scan_type"] = "active"
        if auth_headers:
            f["details"]["authenticated_scan"] = True

    return {
        "scan_type": "zap-active",
        "target": target,
        "alert_count": len(alerts),
        "authenticated": bool(auth_headers),
        "findings": findings,
    }


def run_zap_api_scan(target: str, openapi_url: str | None = None) -> dict[str, Any]:
    """
    ZAP API Scan: scan orientado a OpenAPI/Swagger.
    Testa automaticamente todos os endpoints do schema.
    openapi_url: URL do swagger.json/openapi.json. Se None, tenta /swagger.json e /openapi.json.
    """
    if not is_zap_available():
        return {"error": "ZAP service unavailable", "findings": []}

    # Auto-discover OpenAPI URL if not provided
    if not openapi_url:
        from urllib.parse import urljoin
        for path in ("/swagger.json", "/openapi.json", "/api-docs", "/api/swagger.json", "/v2/api-docs"):
            candidate = urljoin(target, path)
            try:
                r = requests.get(candidate, timeout=10, verify=False, allow_redirects=True)
                if r.status_code == 200 and ("swagger" in r.text.lower() or "openapi" in r.text.lower()):
                    openapi_url = candidate
                    logger.info("ZAP API scan: discovered OpenAPI at %s", openapi_url)
                    break
            except Exception:
                continue

    if openapi_url:
        # Import OpenAPI definition into ZAP
        try:
            _zap_post("/JSON/openapi/action/importUrl/", {
                "url": openapi_url,
                "hostOverride": "",
            })
        except Exception as exc:
            logger.warning("ZAP OpenAPI import error: %s", exc)

    # Active scan against discovered endpoints
    try:
        ascan_data = _zap_post("/JSON/ascan/action/scan/", {
            "url": target, "recurse": "true",
        })
        ascan_id = str(ascan_data.get("scan") or "0")
        _wait_for_active_scan(ascan_id, max_wait=_API_SCAN_MAX_WAIT)
    except Exception as exc:
        logger.warning("ZAP API active scan error: %s", exc)

    alerts = _get_alerts(target)
    findings = _alerts_to_findings(alerts, target)
    for f in findings:
        f["details"]["zap_scan_type"] = "api_scan"
        if openapi_url:
            f["details"]["openapi_url"] = openapi_url

    return {
        "scan_type": "zap-api",
        "target": target,
        "openapi_url": openapi_url,
        "alert_count": len(alerts),
        "findings": findings,
    }


def run_zap_scan(tool_name: str, target: str, item_metadata: dict | None = None,
                 auth_headers: dict[str, str] | None = None) -> dict[str, Any]:
    """
    Entry point principal — roteador de scan ZAP baseado no tool_name.
    Chamado pelo poll_scan_work_item quando tool_name começa com 'zap-'.

    auth_headers pode vir explícito ou dentro de item_metadata['auth_headers'].
    """
    tool = tool_name.lower().strip()
    meta = item_metadata or {}
    auth = auth_headers or meta.get("auth_headers") or None

    if tool == "zap-baseline":
        return run_zap_baseline(target, auth_headers=auth)
    elif tool == "zap-ajax":
        return run_zap_ajax_spider(target)
    elif tool == "zap-active":
        return run_zap_active_scan(target, auth_headers=auth)
    elif tool == "zap-api":
        openapi_url = meta.get("openapi_url") or meta.get("swagger_url")
        return run_zap_api_scan(target, openapi_url=openapi_url)
    else:
        return {"error": f"Unknown ZAP tool: {tool_name}", "findings": []}
