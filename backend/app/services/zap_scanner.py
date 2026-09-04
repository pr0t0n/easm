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
import json
import time
import uuid
from contextlib import contextmanager
from typing import Any, Callable
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_ZAP_BASE = os.getenv("ZAP_URL", "http://zap:8090").rstrip("/")
_ZAP_API_KEY = os.getenv("ZAP_API_KEY", "scriptkiddo-zap-key")

# Timeouts (segundos)
_SPIDER_MAX_WAIT = 120      # spider passivo/ativo
_AJAX_MAX_WAIT = 180        # AJAX spider (mais lento — usa browser)
_ACTIVE_MAX_WAIT = 1800     # active scan completo (30 min)
_API_SCAN_MAX_WAIT = int(os.getenv("ZAP_API_SCAN_MAX_WAIT", "1200"))

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


def _zap(path: str, params: dict | None = None, *, timeout: int = 30) -> dict:
    """Chama um endpoint GET da API ZAP."""
    p = {"apikey": _ZAP_API_KEY, **(params or {})}
    url = f"{_ZAP_BASE}{path}"
    resp = requests.get(url, params=p, timeout=timeout)
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


def _wait_for_zap_available(max_wait: int = 180) -> bool:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        if is_zap_available():
            return True
        time.sleep(5)
    return False


def _prepare_api_scan_options() -> None:
    option_calls = [
        ("/JSON/ascan/action/setOptionThreadPerHost/", {"Integer": os.getenv("ZAP_API_THREAD_PER_HOST", "1")}),
        ("/JSON/ascan/action/setOptionMaxScanDurationInMins/", {"Integer": os.getenv("ZAP_API_MAX_SCAN_DURATION_MINS", "20")}),
        ("/JSON/ascan/action/setOptionDelayInMs/", {"Integer": os.getenv("ZAP_API_DELAY_MS", "25")}),
    ]
    for path, data in option_calls:
        try:
            _zap_post(path, data)
        except Exception as exc:
            logger.debug("ZAP API option %s failed: %s", path, exc)


def _apply_auth_headers(auth_headers: dict[str, str] | None, *, scan_id: int | None = None) -> list[str]:
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
        desc = f"easm-auth-{scan_id or 'adhoc'}-{uuid.uuid4().hex[:8]}-{name}"
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


@contextmanager
def _exclusive_zap_session(scan_id: int | None):
    """Serialize ZAP sessions because Replacer rules are process-global."""
    token = uuid.uuid4().hex
    client = None
    acquired = False
    try:
        from app.services.scan_work_queue import _redis_client

        client = _redis_client()
        acquired = bool(client.set("zap:exclusive-session", f"{scan_id}:{token}", nx=True, ex=3600))
    except Exception:
        # Without the distributed lock, authenticated ZAP cannot safely run.
        acquired = not bool(scan_id)
    if not acquired:
        raise RuntimeError("zap_session_busy")
    try:
        yield
    finally:
        if client is not None:
            try:
                current = client.get("zap:exclusive-session")
                if current and token in (current.decode() if isinstance(current, bytes) else str(current)):
                    client.delete("zap:exclusive-session")
            except Exception:
                pass


def _same_target_host(url: str, target: str) -> bool:
    try:
        return bool(urlparse(url).hostname and urlparse(url).hostname == urlparse(target).hostname)
    except Exception:
        return False


def _zap_target_url(target: str) -> str:
    value = str(target or "").strip()
    if value.startswith(("http://", "https://")):
        return value.rstrip("/")
    return f"https://{value}".rstrip("/")


def _rewritten_openapi_file_for_target(
    openapi_url: str,
    target_url: str,
    auth_headers: dict[str, str] | None,
    scan_id: int | None,
) -> tuple[str, dict[str, Any]]:
    if not scan_id:
        return "", {}
    base_dir = os.getenv("ZAP_OPENAPI_SHARED_DIR", "/evidence/zap-openapi")
    os.makedirs(base_dir, exist_ok=True)
    response = requests.get(openapi_url, timeout=30, verify=False, allow_redirects=True, headers=auth_headers or None)
    response.raise_for_status()
    spec = response.json()
    parsed_target = urlparse(target_url)
    if str(spec.get("openapi") or "").startswith("3"):
        spec["servers"] = [{"url": target_url}]
    elif spec.get("swagger"):
        spec["schemes"] = [parsed_target.scheme or "https"]
        spec["host"] = parsed_target.netloc
        spec["basePath"] = str(spec.get("basePath") or "/")
    path = os.path.join(base_dir, f"scan-{scan_id}-{uuid.uuid4().hex[:12]}.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(spec, handle, ensure_ascii=False)
    return path, {
        "rewritten": True,
        "path": path,
        "target_url": target_url,
        "paths": len(spec.get("paths") or {}),
        "servers": spec.get("servers") or [],
        "schemes": spec.get("schemes") or [],
        "host": spec.get("host") or "",
    }


def _is_zap_does_not_exist(exc: Exception) -> bool:
    """True when ZAP rejected the scanId itself (never started) — retrying for
    the full timeout in this case only wastes time, it will never succeed."""
    response = getattr(exc, "response", None)
    if response is None or response.status_code != 400:
        return False
    try:
        return str(response.json().get("code") or "") == "does_not_exist"
    except Exception:
        return False


def _wait_for_spider(scan_id: str, max_wait: int = _SPIDER_MAX_WAIT) -> None:
    """Aguarda o spider ZAP completar."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            status = _zap("/JSON/spider/view/status/", {"scanId": scan_id})
            pct = int(status.get("status") or 0)
            if pct >= 100:
                return
        except Exception as exc:
            if _is_zap_does_not_exist(exc):
                logger.warning("ZAP spider scanId=%s never registered — aborting wait early", scan_id)
                return
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


def _wait_for_active_scan(scan_id: str, max_wait: int = _ACTIVE_MAX_WAIT, on_progress: Callable[[], None] | None = None) -> bool:
    """Aguarda o active scan ZAP completar."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            status = _zap("/JSON/ascan/view/status/", {"scanId": scan_id})
            pct = int(status.get("status") or 0)
            if on_progress:
                on_progress()
            if pct >= 100:
                return True
            scans = list((_zap("/JSON/ascan/view/scans/") or {}).get("scans") or [])
            for scan in scans:
                if str(scan.get("id") or "") == str(scan_id):
                    state = str(scan.get("state") or "").upper()
                    if state in {"FINISHED", "STOPPED"}:
                        return True
        except Exception as exc:
            if _is_zap_does_not_exist(exc):
                logger.warning("ZAP active scan scanId=%s never registered — aborting wait early", scan_id)
                return False
        time.sleep(10)
    logger.warning("ZAP active scan timeout after %ds", max_wait)
    return False


def _get_alerts(target: str) -> list[dict]:
    """Obtém todos os alertas ZAP para o target.

    alertsByRisk's actual response shape is
    {"alertsByRisk": [{risk_name: {alert_name: [instance, ...]}}, ...]} —
    triple-nested, and instances lack desc/solution/reference/cweid/etc.
    A flat-dict read of data.items() here silently absorbed the single
    "alertsByRisk" wrapper key as if it were itself a real alert, so every
    ZAP run "succeeded" with zero usable findings regardless of what ZAP
    actually found. /JSON/core/view/alerts/ returns properly flat, fully
    detailed alert dicts, so it is the primary path, not a fallback.
    """
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


def resolve_zap_auth_headers(db: Any, job: Any, state: dict[str, Any] | None = None) -> dict[str, str]:
    """Prefer a real captured session (AuthSessionManager/ScanAuthSession) over
    the legacy static auth_config mechanism.

    auth_headers_from_state(state) only ever reads state["auth_config"] — a
    single, static identity supplied at scan-creation time. It's still a
    legitimate fallback for scans that never had a live credential capture,
    so it's not removed — but a real captured session (from the CDP capture
    flow, confirm_identity_capture) should always take priority when one
    exists, since it's an actual live session rather than a static config.
    """
    try:
        from app.services.auth_session_manager import AuthSessionManager

        material = AuthSessionManager(db, job).get_material()
        if material and material.valid:
            headers = dict(material.headers or {})
            if material.cookies and "Cookie" not in headers and "cookie" not in headers:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in material.cookies.items())
            if headers:
                return headers
    except Exception:
        logger.debug("resolve_zap_auth_headers: AuthSessionManager lookup failed", exc_info=True)

    try:
        from app.services.scan_intelligence import auth_headers_from_state

        return auth_headers_from_state(state or dict(getattr(job, "state_data", None) or {})) or {}
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Scan entry points
# ─────────────────────────────────────────────────────────────────────────────

def run_zap_baseline(target: str, auth_headers: dict[str, str] | None = None, *, scan_id: int | None = None) -> dict[str, Any]:
    """
    ZAP Baseline: passive scan + quick spider.
    Não faz ataques ativos. Baixo ruído, rápido (1-2 min).
    Ideal para: todos os alvos HTTP/HTTPS descobertos.

    auth_headers: se fornecido, faz scan AUTENTICADO (injeta os cabeçalhos em
    toda requisição do ZAP, alcançando endpoints pós-login).
    """
    if not is_zap_available():
        return {"error": "ZAP service unavailable", "findings": []}

    alerts: list[dict] = []
    try:
        with _exclusive_zap_session(scan_id):
            auth_rules = _apply_auth_headers(auth_headers, scan_id=scan_id)
            try:
                try:
                    _zap_post("/JSON/core/action/accessUrl/", {"url": target, "followRedirects": "false"})
                except Exception as exc:
                    logger.debug("ZAP accessUrl error: %s", exc)
                try:
                    spider_data = _zap_post("/JSON/spider/action/scan/", {
                        "url": target,
                        "maxChildren": "0",
                        "recurse": "true",
                        "contextName": "",
                        "subtreeOnly": "true",
                    })
                    spider_scan_id = str(spider_data.get("scan") or "0")
                    _wait_for_spider(spider_scan_id, max_wait=_SPIDER_MAX_WAIT)
                except Exception as exc:
                    logger.warning("ZAP spider error: %s", exc)
                alerts = _get_alerts(target)
            finally:
                _clear_auth_headers(auth_rules)
    except RuntimeError as exc:
        return {"status": "skipped", "reason": str(exc), "findings": []}

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


def run_zap_ajax_spider(
    target: str, max_duration_mins: int = 3, auth_headers: dict[str, str] | None = None,
    *, scan_id: int | None = None,
) -> dict[str, Any]:
    """
    ZAP AJAX Spider: usa headless browser para navegar SPAs.
    Descobre rotas dinâmicas que katana/gospider não encontram.
    Ideal para: targets com React/Vue/Angular confirmado.

    auth_headers: se fornecido, o headless browser navega autenticado — sem
    isso, uma SPA atrás de login nunca sai da tela de login e o spider não
    descobre nada além dela.
    """
    if not is_zap_available():
        return {"error": "ZAP service unavailable", "findings": []}

    try:
        with _exclusive_zap_session(scan_id):
            auth_rules = _apply_auth_headers(auth_headers, scan_id=scan_id)
            try:
                _zap_post("/JSON/ajaxSpider/action/scan/", {
                    "url": target,
                    "inScope": "true",
                    "contextName": "",
                    "subtreeOnly": "true",
                })
                _wait_for_ajax_spider(max_wait=max_duration_mins * 60)
            except Exception as exc:
                logger.warning("ZAP AJAX spider error: %s", exc)
            finally:
                _clear_auth_headers(auth_rules)
    except RuntimeError as exc:
        return {"status": "skipped", "reason": str(exc), "findings": []}

    # Get discovered URLs
    try:
        results_data = _zap("/JSON/ajaxSpider/view/results/")
        discovered_urls = [
            str(r.get("requestHeader", "").split("\n")[0]).replace("GET ", "").split(" HTTP")[0]
            for r in (results_data.get("results") or [])
            if _same_target_host(str(r.get("requestHeader", "").split("\n")[0]).replace("GET ", "").split(" HTTP")[0], target)
        ]
    except Exception:
        discovered_urls = []

    alerts = _get_alerts(target)
    findings = _alerts_to_findings(alerts, target)
    for f in findings:
        f["details"]["zap_scan_type"] = "ajax_spider"
        if auth_headers:
            f["details"]["authenticated_scan"] = True

    return {
        "scan_type": "zap-ajax",
        "target": target,
        "discovered_urls": discovered_urls[:100],
        "discovered_url_count": len(discovered_urls),
        "alert_count": len(alerts),
        "authenticated": bool(auth_headers),
        "findings": findings,
    }


def run_zap_active_scan(target: str, auth_headers: dict[str, str] | None = None, *, scan_id: int | None = None) -> dict[str, Any]:
    """
    ZAP Active Scan: fuzzing ativo para OWASP Top 10.
    Detecta: SQLi, XSS, SSRF, Path Traversal, Command Injection, etc.
    Pode ser lento (até 30 min para targets grandes).

    auth_headers: scan autenticado (alcança endpoints pós-login).
    """
    if not is_zap_available():
        return {"error": "ZAP service unavailable", "findings": []}

    alerts: list[dict] = []
    try:
        with _exclusive_zap_session(scan_id):
            auth_rules = _apply_auth_headers(auth_headers, scan_id=scan_id)
            try:
                try:
                    _zap_post("/JSON/core/action/accessUrl/", {"url": target, "followRedirects": "false"})
                except Exception as exc:
                    logger.debug("ZAP accessUrl error: %s", exc)
                try:
                    spider_data = _zap_post("/JSON/spider/action/scan/", {
                        "url": target, "recurse": "true", "subtreeOnly": "true",
                    })
                    spider_scan_id = str(spider_data.get("scan") or "0")
                    _wait_for_spider(spider_scan_id, max_wait=120)
                except Exception:
                    pass
                try:
                    ascan_data = _zap_post("/JSON/ascan/action/scan/", {
                        "url": target,
                        "recurse": "true",
                        "inScopeOnly": "true",
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
                _clear_auth_headers(auth_rules)
    except RuntimeError as exc:
        return {"status": "skipped", "reason": str(exc), "findings": []}

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


def run_zap_api_scan(
    target: str,
    openapi_url: str | None = None,
    auth_headers: dict[str, str] | None = None,
    *,
    scan_id: int | None = None,
) -> dict[str, Any]:
    """
    ZAP API Scan: scan orientado a OpenAPI/Swagger.
    Testa automaticamente todos os endpoints do schema.
    openapi_url: URL do swagger.json/openapi.json. Se None, tenta /swagger.json e /openapi.json.
    auth_headers: scan autenticado — também usado na descoberta do spec, caso o
    próprio arquivo openapi.json exija sessão.
    """
    if not _wait_for_zap_available():
        return {"error": "ZAP service unavailable", "findings": []}

    target_url = _zap_target_url(target)
    _prepare_api_scan_options()
    import_result: dict[str, Any] = {}
    import_errors: list[str] = []
    active_error = ""
    imported_urls: list[str] = []
    alerts: list[dict] = []
    import_source = "url"
    rewritten_spec: dict[str, Any] = {}

    def refresh_snapshot() -> None:
        nonlocal imported_urls, alerts
        try:
            current_urls = list((_zap("/JSON/core/view/urls/", {"baseurl": target_url}) or {}).get("urls") or [])
            if current_urls:
                imported_urls = current_urls
        except Exception as exc:
            logger.debug("ZAP API URL snapshot error: %s", exc)
        try:
            current_alerts = _get_alerts(target_url)
            if current_alerts or not alerts:
                alerts = current_alerts
        except Exception as exc:
            logger.debug("ZAP API alert snapshot error: %s", exc)

    # Auto-discover OpenAPI URL if not provided
    if not openapi_url:
        from urllib.parse import urljoin
        for path in ("/swagger.json", "/openapi.json", "/api-docs", "/api/swagger.json", "/v2/api-docs"):
            candidate = urljoin(target_url + "/", path.lstrip("/"))
            try:
                r = requests.get(candidate, timeout=10, verify=False, allow_redirects=True, headers=auth_headers or None)
                if r.status_code == 200 and ("swagger" in r.text.lower() or "openapi" in r.text.lower()):
                    openapi_url = candidate
                    logger.info("ZAP API scan: discovered OpenAPI at %s", openapi_url)
                    break
            except Exception:
                continue

    if openapi_url:
        try:
            rewritten_file, rewritten_spec = _rewritten_openapi_file_for_target(
                openapi_url,
                target_url,
                auth_headers,
                scan_id,
            )
            if rewritten_file:
                import_source = "rewritten_file"
                import_result = _zap("/JSON/openapi/action/importFile/", {
                    "file": rewritten_file,
                    "target": target_url,
                    "maxMessages": "0",
                }, timeout=int(os.getenv("ZAP_OPENAPI_IMPORT_TIMEOUT", "300")))
            else:
                import_result = _zap("/JSON/openapi/action/importUrl/", {
                    "url": openapi_url,
                    "hostOverride": target_url,
                    "maxMessages": "0",
                }, timeout=int(os.getenv("ZAP_OPENAPI_IMPORT_TIMEOUT", "300")))
            import_errors = [str(item) for item in import_result.get("importUrl") or [] if str(item)]
            import_errors.extend(str(item) for item in import_result.get("importFile") or [] if str(item))
        except Exception as exc:
            active_error = str(exc)
            logger.warning("ZAP OpenAPI import error: %s", exc)

    refresh_snapshot()
    effective_scan_policy = os.getenv("ZAP_API_SCAN_POLICY", "API").strip()
    _auth_rules = _apply_auth_headers(auth_headers)
    try:
        if not imported_urls:
            raise RuntimeError("openapi_import_produced_no_target_urls")
        if not _wait_for_zap_available():
            raise RuntimeError("zap_unavailable_before_active_scan")
        scan_policy = effective_scan_policy
        scan_payload = {"url": target_url, "recurse": "true"}
        if scan_policy:
            scan_payload["scanPolicyName"] = scan_policy
        try:
            ascan_data = _zap_post("/JSON/ascan/action/scan/", scan_payload)
        except requests.HTTPError as exc:
            if not scan_policy or getattr(exc.response, "status_code", None) != 400:
                raise
            scan_payload.pop("scanPolicyName", None)
            effective_scan_policy = ""
            ascan_data = _zap_post("/JSON/ascan/action/scan/", scan_payload)
        ascan_id = str(ascan_data.get("scan") or "0")
        finished = _wait_for_active_scan(ascan_id, max_wait=_API_SCAN_MAX_WAIT, on_progress=refresh_snapshot)
        if not finished and not active_error:
            active_error = "zap_active_scan_incomplete_or_lost"
    except Exception as exc:
        active_error = str(exc)
        logger.warning("ZAP API active scan error: %s", exc)
    finally:
        _clear_auth_headers(_auth_rules)

    refresh_snapshot()
    findings = _alerts_to_findings(alerts, target_url)
    for f in findings:
        f["source_tool"] = "zap-api"
        f["details"]["zap_scan_type"] = "api_scan"
        f["details"]["tool"] = "zap-api"
        f["details"]["source_agent_name"] = "Backend ZAP API Scanner"
        f["details"]["api_tested_via"] = "openapi_dast"
        f["details"]["imported_url_count"] = len(imported_urls)
        f["details"]["alert_count"] = len(alerts)
        if openapi_url:
            f["details"]["openapi_url"] = openapi_url
        if auth_headers:
            f["details"]["authenticated_scan"] = True

    return {
        "scan_type": "zap-api",
        "target": target_url,
        "openapi_url": openapi_url,
        "scan_policy": effective_scan_policy,
        "import_source": import_source,
        "rewritten_spec": rewritten_spec,
        "import_errors": import_errors[:25],
        "imported_url_count": len(imported_urls),
        "active_error": active_error,
        "alert_count": len(alerts),
        "finding_count": len(findings),
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
        return run_zap_ajax_spider(target, auth_headers=auth)
    elif tool == "zap-active":
        return run_zap_active_scan(target, auth_headers=auth)
    elif tool == "zap-api":
        openapi_url = meta.get("openapi_url") or meta.get("swagger_url")
        return run_zap_api_scan(target, openapi_url=openapi_url, auth_headers=auth, scan_id=meta.get("scan_id"))
    else:
        return {"error": f"Unknown ZAP tool: {tool_name}", "findings": []}
